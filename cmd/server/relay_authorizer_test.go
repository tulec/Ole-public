package main

import (
	"Ole/internal/app"
	"Ole/internal/domain"
	"Ole/internal/relay"
	"Ole/internal/store/memory"
	"Ole/internal/transportauth"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"
)

type relayFixture struct {
	app                        *app.App
	token                      string
	source, target             *domain.Peer
	network                    *domain.Network
	sourceDevice, targetDevice *domain.Device
	tunnel                     *domain.Tunnel
}

func TestRelayWireRejectsCrossNetworkAndLiveDeviceRevocation(t *testing.T) {
	f := newRelayFixture(t)
	server, err := relay.ListenWithConfig("127.0.0.1:0", appRelayAuthorizer{f.app}, relay.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	openSocket := func() *net.UDPConn {
		t.Helper()
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	source, target := openSocket(), openSocket()
	write := func(conn *net.UDPConn, message string) {
		t.Helper()
		encoded, err := transportauth.EncodeRelay(message)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.WriteTo(encoded, server.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	targetSession, err := f.app.AuthService.Login("target@example.com", "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	write(target, "OLER2|bind|"+targetSession.AccessToken+"|target|bind-nonce")
	bound, err := relay.WaitForPacket(target, time.Second)
	if err != nil || !strings.HasPrefix(bound, "OLER2|bound|") {
		t.Fatalf("bind failed: %v", err)
	}
	payload := hex.EncodeToString([]byte("test payload"))
	send := func() { write(source, "OLER2|send|"+f.token+"|source|target|"+payload) }
	expectDenied := func() {
		t.Helper()
		response, err := relay.WaitForPacket(source, time.Second)
		if err != nil || !strings.HasPrefix(response, "OLER2|error|send_denied|") {
			t.Fatalf("send was not denied: %q, %v", response, err)
		}
		if _, err := relay.WaitForPacket(target, 100*time.Millisecond); err == nil {
			t.Fatal("forbidden packet reached target")
		} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatalf("unexpected target read failure: %v", err)
		}
	}
	f.target.NetworkID = domain.NetworkID{Value: "network-b"}
	if err := f.app.PeerRepo.Save(f.target); err != nil {
		t.Fatal(err)
	}
	send()
	expectDenied()
	f.target.NetworkID = f.network.ID
	if err := f.app.PeerRepo.Save(f.target); err != nil {
		t.Fatal(err)
	}
	send()
	delivered, err := relay.WaitForPacket(target, time.Second)
	if err != nil || delivered != "OLER2|deliver|source|"+payload {
		t.Fatalf("valid packet was not delivered: %q, %v", delivered, err)
	}
	f.targetDevice.Status = domain.DeviceStatusRevoked
	if err := f.app.DeviceRepo.Save(f.targetDevice); err != nil {
		t.Fatal(err)
	}
	send()
	expectDenied()
	snapshot := server.Snapshot()
	if snapshot.ForwardedPackets != 1 || snapshot.SendDenials != 2 {
		t.Fatalf("forwarded=%d denied=%d", snapshot.ForwardedPackets, snapshot.SendDenials)
	}
	t.Log("wire requests=3 forwarded=1 forbidden_deliveries=0 denied=2")
}

func newRelayFixture(t *testing.T) *relayFixture {
	t.Helper()
	users := memory.NewUserRepo()
	devices := memory.NewDeviceRepo()
	networks := memory.NewNetworkRepo()
	peers := memory.NewPeerRepo()
	tunnels := memory.NewTunnelRepo()
	auth := domain.NewAuthService(users, nil, memory.NewSessionRepo(), "test-secret", "ole-test")
	owner, err := auth.Register("source@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	targetUser, err := auth.Register("target@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.Login(owner.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	network := domain.NewNetwork(domain.NetworkID{Value: "network-a"}, owner.ID, "private", domain.NetworkAccessInviteOnly, true)
	if err := network.AddMember(targetUser.ID); err != nil {
		t.Fatal(err)
	}
	sourceDevice := domain.NewDevice(domain.DeviceID{Value: "source-device"}, owner.ID, "source", "source-key", 100)
	targetDevice := domain.NewDevice(domain.DeviceID{Value: "target-device"}, targetUser.ID, "target", "target-key", 100)
	network.ApproveDevice(targetDevice.ID)
	if err := networks.Save(network); err != nil {
		t.Fatal(err)
	}
	for _, d := range []*domain.Device{sourceDevice, targetDevice} {
		if err := devices.Save(d); err != nil {
			t.Fatal(err)
		}
	}
	source := &domain.Peer{ID: domain.PeerID{Value: "source"}, UserID: owner.ID, DeviceID: sourceDevice.ID, NetworkID: network.ID, Status: domain.PeerStatusOnline}
	target := &domain.Peer{ID: domain.PeerID{Value: "target"}, UserID: targetUser.ID, DeviceID: targetDevice.ID, NetworkID: network.ID, Status: domain.PeerStatusOnline}
	for _, p := range []*domain.Peer{source, target} {
		if err := peers.Save(p); err != nil {
			t.Fatal(err)
		}
	}
	tunnel := &domain.Tunnel{ID: domain.TunnelID{Value: "tunnel"}, NetworkID: network.ID, A: source.ID, B: target.ID, Mode: domain.TunnelModeRelay, State: domain.TunnelStateOpen}
	if err := tunnels.Save(tunnel); err != nil {
		t.Fatal(err)
	}
	return &relayFixture{app: &app.App{AuthService: auth, UserRepo: users, DeviceRepo: devices, NetworkRepo: networks, PeerRepo: peers, TunnelRepo: tunnels}, token: session.AccessToken, source: source, target: target, network: network, sourceDevice: sourceDevice, targetDevice: targetDevice, tunnel: tunnel}
}

func TestRelayAuthorizerRejectsCrossNetworkAndRevokedAccess(t *testing.T) {
	for _, tc := range []struct {
		name     string
		change   func(*relayFixture)
		denyBind bool
	}{
		{"cross-network legacy tunnel", func(f *relayFixture) { f.target.NetworkID = domain.NetworkID{Value: "network-b"} }, false},
		{"source offline", func(f *relayFixture) { f.source.Status = domain.PeerStatusOffline }, true},
		{"target offline", func(f *relayFixture) { f.target.Status = domain.PeerStatusOffline }, false},
		{"source device revoked", func(f *relayFixture) { f.sourceDevice.Status = domain.DeviceStatusRevoked }, true},
		{"target device revoked", func(f *relayFixture) { f.targetDevice.Status = domain.DeviceStatusRevoked }, false},
		{"source device wrong owner", func(f *relayFixture) { f.sourceDevice.UserID = f.target.UserID }, true},
		{"target device wrong owner", func(f *relayFixture) { f.targetDevice.UserID = f.source.UserID }, false},
		{"source read-only", func(f *relayFixture) { f.network.Members[f.source.UserID.String()] = domain.NetworkRoleReadOnly }, true},
		{"target read-only", func(f *relayFixture) { f.network.Members[f.target.UserID.String()] = domain.NetworkRoleReadOnly }, false},
		{"target removed", func(f *relayFixture) { delete(f.network.Members, f.target.UserID.String()) }, false},
		{"target approval revoked", func(f *relayFixture) { f.network.RevokeDeviceApproval(f.targetDevice.ID) }, false},
		{"source approval revoked", func(f *relayFixture) {
			f.network.OwnerID = domain.UserID{Value: "new-owner"}
			f.network.Members[f.source.UserID.String()] = domain.NetworkRoleMember
		}, true},
		{"tunnel closed", func(f *relayFixture) { f.tunnel.State = domain.TunnelStateClosed }, false},
		{"wrong tunnel mode", func(f *relayFixture) { f.tunnel.Mode = domain.TunnelModeP2P }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRelayFixture(t)
			tc.change(f)
			for _, p := range []*domain.Peer{f.source, f.target} {
				if err := f.app.PeerRepo.Save(p); err != nil {
					t.Fatal(err)
				}
			}
			for _, d := range []*domain.Device{f.sourceDevice, f.targetDevice} {
				if err := f.app.DeviceRepo.Save(d); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.app.NetworkRepo.Save(f.network); err != nil {
				t.Fatal(err)
			}
			if err := f.app.TunnelRepo.Save(f.tunnel); err != nil {
				t.Fatal(err)
			}
			authorizer := appRelayAuthorizer{f.app}
			if err := authorizer.AuthorizeSend(f.token, f.source.ID.String(), f.target.ID.String()); err == nil {
				t.Error("forbidden relay send was accepted")
			}
			if tc.denyBind && authorizer.AuthorizeBind(f.token, f.source.ID.String()) == nil {
				t.Error("forbidden relay bind was accepted")
			}
		})
	}
}

func TestRelayAuthorizerAllowsValidOpenAndNegotiatingPairs(t *testing.T) {
	f := newRelayFixture(t)
	authorizer := appRelayAuthorizer{f.app}
	if err := authorizer.AuthorizeBind(f.token, f.source.ID.String()); err != nil {
		t.Fatal(err)
	}
	for _, state := range []domain.TunnelState{domain.TunnelStateOpen, domain.TunnelStateNegotiating} {
		f.tunnel.State = state
		if err := f.app.TunnelRepo.Save(f.tunnel); err != nil {
			t.Fatal(err)
		}
		if err := authorizer.AuthorizeSend(f.token, f.source.ID.String(), f.target.ID.String()); err != nil {
			t.Fatalf("valid %s send rejected: %v", state, err)
		}
	}
}
