package clientagent

import (
	"Ole/internal/app"
	"Ole/internal/controlclient"
	"Ole/internal/directprobe"
	"Ole/internal/domain"
	"Ole/internal/httpapi"
	"Ole/internal/relay"
	"Ole/internal/relaytransport"
	"Ole/internal/store/memory"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAgentUsesServerDeviceKeysForBothTransportsAndRevocation(t *testing.T) {
	users, devices, networks, peers, pools := memory.NewUserRepo(), memory.NewDeviceRepo(), memory.NewNetworkRepo(), memory.NewPeerRepo(), memory.NewVirtualIPPoolRepo()
	auth := domain.NewAuthService(users, nil, memory.NewSessionRepo(), "test-secret", "ole-test")
	directory := domain.NewPeerDirectory(peers, networks, pools, devices, nil, users)
	server := httptest.NewServer(httpapi.NewRouter(&app.App{AuthService: auth, PeerDirectory: directory}))
	defer server.Close()
	relayServer, err := relay.Listen("127.0.0.1:0", relay.StaticAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	defer relayServer.Close()
	var agents []*Agent
	var registered []*domain.Peer
	var network *domain.Network
	for _, name := range []string{"left", "right"} {
		user, err := auth.Register(name+"-identity@example.com", "secret")
		if err != nil {
			t.Fatal(err)
		}
		session, err := auth.Login(user.Email, "secret", domain.SessionMetadata{})
		if err != nil {
			t.Fatal(err)
		}
		if network == nil {
			network = domain.NewNetwork(domain.NetworkID{Value: "agent-identity-net"}, user.ID, "identity", domain.NetworkAccessInviteOnly, false)
		} else if err := network.AddMember(user.ID); err != nil {
			t.Fatal(err)
		}
		if err := networks.Save(network); err != nil {
			t.Fatal(err)
		}
		state := defaultPersistentState()
		if _, err := state.EnsureKeyPair(); err != nil {
			t.Fatal(err)
		}
		device := domain.NewDevice(domain.DeviceID{Value: "device-" + name}, user.ID, name, state.PublicKey, time.Now().Unix())
		if err := devices.Save(device); err != nil {
			t.Fatal(err)
		}
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		addr := conn.LocalAddr().String()
		conn.Close()
		peer, err := directory.RegisterPeer(user.ID, device.ID, network.ID, addr, time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		state.SetEnrollment(server.URL, user.ID.String(), device.ID.String())
		state.SetManagedPeer(server.URL, user.ID.String(), network.ID.String(), peer.ID.String(), addr, "", peer.VirtualIP)
		remote := controlclient.New(server.URL)
		remote.SetAccessToken(session.AccessToken)
		a := &Agent{remote: remote, currentUser: &controlclient.User{ID: user.ID.String()}, currentSession: &controlclient.Session{AccessToken: session.AccessToken}, deviceState: state, directManager: directprobe.New(), relayManager: relaytransport.New(), runtime: RuntimeConfig{RelayServerAddress: relayServer.LocalAddr().String()}}
		t.Cleanup(func() { a.directManager.Close(); a.relayManager.Close() })
		agents = append(agents, a)
		registered = append(registered, peer)
	}
	for _, a := range agents {
		if err := a.reconcileManagedRuntimeLocked(); err != nil {
			t.Fatal(err)
		}
	}
	left, right := registered[0].ID.String(), registered[1].ID.String()
	assertExchanges := func() {
		t.Helper()
		if _, err := agents[0].directManager.Establish(left, right, []string{registered[1].Endpoint}, time.Second); err != nil {
			t.Fatal(err)
		}
		if response, err := agents[0].directManager.Exchange(left, right, []byte("direct"), time.Second); err != nil || string(response) != "ack:direct" {
			t.Fatal("direct key-bound exchange failed", err)
		}
		if _, err := agents[0].relayManager.Establish(left, right, time.Second); err != nil {
			t.Fatal(err)
		}
		if response, err := agents[0].relayManager.Exchange(left, right, []byte("relay"), time.Second); err != nil || string(response) != "ack:relay" {
			t.Fatal("relay key-bound exchange failed", err)
		}
	}
	assertExchanges()
	for _, a := range agents {
		metrics := a.transportDataPlaneMetricsLocked()
		if len(metrics) != 1 || metrics[0].Direct == nil || metrics[0].Relay == nil || metrics[0].Direct.Records.Accepted == 0 || metrics[0].Relay.Records.Accepted == 0 {
			t.Fatal("diagnostics lost transport record counters")
		}
	}
	// Rotate through the authoritative device record and refresh both snapshots.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := devices.FindByID(domain.DeviceID{Value: "device-right"})
	if err != nil {
		t.Fatal(err)
	}
	device.SetPublicKey(base64.StdEncoding.EncodeToString(public))
	if err := devices.Save(device); err != nil {
		t.Fatal(err)
	}
	agents[1].deviceState.PrivateKey = base64.StdEncoding.EncodeToString(private)
	agents[1].deviceState.PublicKey = device.PublicKey
	for _, a := range agents {
		a.transportCredentials = nil
		a.refreshTransportCredentialsLocked()
	}
	if err := agents[0].directManager.SendPacket(left, right, []byte("old")); err == nil {
		t.Fatal("DIRECT retained old key after rotation")
	}
	if err := agents[0].relayManager.SendPacket(left, right, []byte("old")); err == nil {
		t.Fatal("RELAY retained old key after rotation")
	}
	assertExchanges()
	if err := device.Revoke(time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := devices.Save(device); err != nil {
		t.Fatal(err)
	}
	for _, a := range agents {
		a.transportCredentials = nil
		a.refreshTransportCredentialsLocked()
	}
	if err := agents[0].directManager.SendPacket(left, right, []byte("revoked")); err == nil {
		t.Fatal("DIRECT retained revoked remote identity")
	}
	if err := agents[0].relayManager.SendPacket(left, right, []byte("revoked")); err == nil {
		t.Fatal("RELAY retained revoked remote identity")
	}
	if err := agents[1].directManager.SendPacket(right, left, []byte("revoked")); err == nil {
		t.Fatal("DIRECT retained revoked local identity")
	}
	if err := agents[1].relayManager.SendPacket(right, left, []byte("revoked")); err == nil {
		t.Fatal("RELAY retained revoked local identity")
	}
}
