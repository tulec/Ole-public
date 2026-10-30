package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/directprobe"
	"Ole/internal/overlaydns"
	"Ole/internal/relay"
	"Ole/internal/relaytransport"
	"Ole/internal/transportauth"
	"Ole/internal/virtualadapter"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type gatedRecoveryDirect struct {
	directprobe.Manager
	wait func()
	fail bool
}

func TestRecoveryGlobalReconcileInvalidatesRouting(t *testing.T) {
	for _, kind := range []string{"runtime", "relay"} {
		t.Run(kind, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var armed atomic.Bool
			var enterOnce, releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if armed.Load() {
					enterOnce.Do(func() { close(entered) })
					<-release
					http.Error(w, "unavailable", http.StatusServiceUnavailable)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": []controlclient.Network{{ID: "network", RoutingPolicy: "SPLIT"}}})
			}))
			defer server.Close()
			defer unblock()
			a, adapter, _ := newForwardingAgent(t, "DIRECT", server.URL)
			adapter.outbound = nil
			a.runtime = DefaultRuntimeConfig()
			a.runtime.RelayServerAddress = "127.0.0.1:1"
			a.overlayDNS = overlaydns.New("", "ole.test")
			if kind == "relay" {
				manager := relaytransport.New()
				a.relayManager = manager
				t.Cleanup(func() { _ = manager.Close() })
			}
			if _, err := a.forwardingNetworksLocked(); err != nil {
				t.Fatal(err)
			}
			held := a.publishForwardingRoutesLocked(a.forwardingPolicy.networks)
			a.startOutboundPacketPump()
			defer a.outboundPump.stop()
			armed.Store(true)
			done := make(chan struct{})
			go func() {
				defer close(done)
				a.mu.Lock()
				defer a.mu.Unlock()
				_ = a.outboundControlLocked(func() error {
					return a.withRecoveryPauseLocked(outboundReport{route: a.connections[0], scope: a.forwardingScopeLocked(), expires: held.expires}, func() error {
						if kind == "runtime" {
							return a.reconcileManagedRuntimeLocked()
						}
						return a.reconcileRelayBindingsLocked()
					})
				})
			}()
			defer func() {
				unblock()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Error("global reconcile did not return")
				}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("global reconcile read did not start")
			}
			if held.valid.Load() || a.forwardingRoutes.Load() != nil {
				t.Fatal("global listener/relay reconcile exposed the old routing snapshot")
			}
		})
	}
}

func (m gatedRecoveryDirect) Establish(local, remote string, candidates []string, timeout time.Duration) (directprobe.Session, error) {
	session, err := m.Manager.Establish(local, remote, candidates, timeout)
	if err == nil && local == "local" && remote == "remote" {
		m.wait() // The native new session exists, but the owner has not committed it.
		if m.fail {
			return directprobe.Session{}, fmt.Errorf("injected recovery validation failure")
		}
	}
	return session, err
}

func TestDirectRecoveryIsolatesHealthySession(t *testing.T) {
	for _, scenario := range []string{"DIRECT", "RELAY", "fanout", "full-paused-batch", "failure", "expiry"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": []controlclient.Network{{ID: "network", RoutingPolicy: "SPLIT", GroupTrafficPolicy: "FLOOD"}}})
			}))
			defer server.Close()
			a, adapter, badTransport := newForwardingAgent(t, "DIRECT", server.URL)
			sessionID, remoteAddress := forwardingSession(t, a, "DIRECT")
			reverse, err := a.directManager.Establish("remote", "local", nil, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			keys, identities := map[string]ed25519.PrivateKey{}, map[string]transportauth.Identity{}
			for _, peer := range []string{"local", "remote", "healthy"} {
				seed := sha256.Sum256([]byte("packet-forwarding-test-" + peer))
				keys[peer] = ed25519.NewKeyFromSeed(seed[:])
				identities[peer] = transportauth.Identity{DeviceID: "device-" + peer, PublicKey: keys[peer].Public().(ed25519.PublicKey)}
			}
			credentials := func(peer string) *transportauth.Credentials {
				return &transportauth.Credentials{NetworkID: "network", PeerID: peer, DeviceID: "device-" + peer, PrivateKey: keys[peer], Peers: identities, ExpiresAt: time.Now().Add(transportauth.SnapshotTTL)}
			}
			healthyAddress := fileTransferUDPAddress(t)
			if err := a.directManager.Reconcile([]directprobe.Binding{{PeerID: "local", ListenAddress: reverse.RemoteAddress, Credentials: credentials("local")}, {PeerID: "remote", ListenAddress: remoteAddress, Credentials: credentials("remote")}, {PeerID: "healthy", ListenAddress: healthyAddress, Credentials: credentials("healthy")}}); err != nil {
				t.Fatal(err)
			}
			a.runtime = DefaultRuntimeConfig()
			healthyMode, healthyID := "DIRECT", ""
			var healthyTransport transportManagerForPackets = directPacketAdapter{a.directManager}
			if scenario == "RELAY" {
				healthyMode = "RELAY"
				relayServer, err := relay.Listen("127.0.0.1:0", relay.StaticAuthorizer{})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = relayServer.Close() })
				manager := relaytransport.New()
				t.Cleanup(func() { _ = manager.Close() })
				a.runtime.RelayServerAddress = relayServer.LocalAddr().String()
				if err := manager.Reconcile([]relaytransport.Binding{{PeerID: "local", RelayAddress: a.runtime.RelayServerAddress, AccessToken: "local", Credentials: credentials("local")}, {PeerID: "healthy", RelayAddress: a.runtime.RelayServerAddress, AccessToken: "healthy", Credentials: credentials("healthy")}}); err != nil {
					t.Fatal(err)
				}
				session, err := manager.Establish("local", "healthy", time.Second)
				if err != nil {
					t.Fatal(err)
				}
				healthyID = session.SessionID
				a.relayManager, healthyTransport = manager, relayPacketAdapter{manager}
			} else {
				session, err := a.directManager.Establish("local", "healthy", []string{healthyAddress}, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				healthyID = session.SessionID
			}
			badKey, healthyKey := connectionKey("network", "local", "remote"), connectionKey("network", "local", "healthy")
			a.connections[0].RemoteCandidates = []string{remoteAddress}
			a.connections = append(a.connections, ConnectionStatus{NetworkID: "network", LocalPeerID: "local", RemotePeerID: "healthy", RemoteVirtualIP: "10.0.0.4", State: "CONNECTED", TransportMode: healthyMode, TransportReady: true})
			for index, entry := range []struct{ key, mode, id string }{{badKey, "DIRECT", sessionID}, {healthyKey, healthyMode, healthyID}} {
				attempt := DirectAttemptState{DirectReady: true, TransportMode: entry.mode, TransportSessionID: entry.id, TransportStartedAt: time.Now()}
				a.directAttempts[entry.key] = attempt
				a.applyAttemptStateToConnection(&a.connections[index], attempt)
			}
			if _, err := a.forwardingNetworksLocked(); err != nil {
				t.Fatal(err)
			}
			if scenario == "expiry" {
				a.forwardingPolicy.expires = time.Now().Add(700 * time.Millisecond)
			}
			a.refreshForwardingRoutesLocked()
			originalDeadline := a.forwardingRoutes.Load().expires
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			a.directManager = gatedRecoveryDirect{a.directManager, func() { close(entered); <-release }, scenario == "failure"}
			a.directManager.DropSession("local", "remote")
			adapter.outbound = adapter.outbound[:1]
			a.startInboundPacketPump()
			a.startOutboundPacketPump()
			defer a.inboundPump.stop()
			defer a.outboundPump.stop()
			deadline := time.Now().Add(time.Second)
			for len(a.outboundPump.reports) == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if len(a.outboundPump.reports) != 1 {
				t.Fatal("missing failed packet for recovery")
			}
			done := make(chan struct{})
			go func() { defer close(done); a.mu.Lock(); defer a.mu.Unlock(); a.mergeOutboundReportsLocked(true) }()
			var finishOnce sync.Once
			finish := func() {
				unblock()
				finishOnce.Do(func() {
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Error("recovery did not finish")
					}
				})
			}
			defer finish()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("recovery handshake did not start")
			}
			var healthyWant [][]byte
			badCount := 16
			if scenario == "full-paused-batch" {
				badCount = 32
			}
			adapter.mu.Lock()
			for sequence := 1; sequence <= badCount; sequence++ {
				adapter.outbound = append(adapter.outbound, virtualadapter.Packet{Data: forwardingIPv4Packet("10.0.0.2", "10.0.0.3", sequence)})
			}
			if scenario == "fanout" {
				packet := forwardingIPv4Packet("10.0.0.2", "10.0.0.255", 17)
				adapter.outbound = append(adapter.outbound, virtualadapter.Packet{Data: packet})
				healthyWant = append(healthyWant, packet)
			}
			for sequence := range 48 {
				packet := forwardingIPv4Packet("10.0.0.2", "10.0.0.4", sequence)
				adapter.outbound = append(adapter.outbound, virtualadapter.Packet{Data: packet})
				healthyWant = append(healthyWant, packet)
			}
			adapter.mu.Unlock()
			// New-session traffic must not be accepted under old session metadata.
			if err := badTransport.SendPacket("remote", "local", forwardingIPv4Packet("10.0.0.3", "10.0.0.2", 999)); err != nil {
				t.Fatal(err)
			}
			for sequence := range 64 {
				if err := healthyTransport.SendPacket("healthy", "local", forwardingIPv4Packet("10.0.0.4", "10.0.0.2", sequence)); err != nil {
					t.Fatal(err)
				}
			}
			var sent []transportInboundPacket
			wantBefore := len(healthyWant)
			if scenario == "full-paused-batch" {
				wantBefore = 0 // A full retained batch cannot dequeue later traffic.
			}
			deadline = time.Now().Add(300 * time.Millisecond)
			for (len(sent) < wantBefore || inboundWritten(adapter) < 64) && time.Now().Before(deadline) {
				sent = append(sent, healthyTransport.DrainInbound("healthy", 256)...)
				time.Sleep(time.Millisecond)
			}
			if len(sent) != wantBefore || inboundWritten(adapter) != 64 {
				t.Fatalf("healthy during recovery: TX=%d/%d RX=%d/64", len(sent), wantBefore, inboundWritten(adapter))
			}
			for index, packet := range sent {
				if !bytes.Equal(packet.Payload, healthyWant[index]) {
					t.Fatal("healthy flow reordered or duplicated during recovery")
				}
			}
			if got := badTransport.DrainInbound("remote", 256); len(got) != 0 {
				t.Fatal("uncommitted session sent application data")
			}
			if scenario == "expiry" {
				if delay := time.Until(originalDeadline); delay > 0 {
					time.Sleep(delay + 10*time.Millisecond)
				}
			}
			finish()
			wantBad := badCount + 1
			if scenario == "fanout" {
				wantBad++
			}
			if scenario == "failure" || scenario == "expiry" {
				wantBad = 0
			}
			var recovered []transportInboundPacket
			deadline = time.Now().Add(500 * time.Millisecond)
			for time.Now().Before(deadline) && (len(recovered) < wantBad || len(sent) < len(healthyWant) || wantBad == 0) {
				recovered = append(recovered, badTransport.DrainInbound("remote", 256)...)
				sent = append(sent, healthyTransport.DrainInbound("healthy", 256)...)
				time.Sleep(time.Millisecond)
			}
			a.outboundPump.stop()
			a.inboundPump.stop()
			a.mergeInboundReportsLocked()
			a.mergeOutboundReportsLocked(false)
			if len(recovered) != wantBad || len(sent) != len(healthyWant) || a.directAttempts[badKey].TransportPacketCount != wantBad || a.directAttempts[healthyKey].TransportPacketCount != len(healthyWant)+64 {
				t.Fatalf("recovery counters: badPackets=%d/%d badCount=%d healthyCount=%d", len(recovered), wantBad, a.directAttempts[badKey].TransportPacketCount, a.directAttempts[healthyKey].TransportPacketCount)
			}
			if a.recoveryPaused.Load() != nil || a.outboundPump.reportLoad() != 0 {
				t.Fatal("completed/failed/expired recovery retained pause or report slots")
			}
			for index, packet := range sent {
				if !bytes.Equal(packet.Payload, healthyWant[index]) {
					t.Fatal("healthy flow changed order/content after recovery")
				}
			}
			for index, packet := range recovered {
				destination := "10.0.0.3"
				if scenario == "fanout" && index == 17 {
					destination = "10.0.0.255"
				}
				if !bytes.Equal(packet.Payload, forwardingIPv4Packet("10.0.0.2", destination, index)) {
					t.Fatal("recovery changed packet order/content")
				}
			}
			if scenario == "fanout" {
				diag := a.groupTrafficDiagnostics["network"]
				if diag.FloodPacketCount != 1 || diag.FanoutCopyCount != 2 {
					t.Fatalf("fanout repeated or lost copies: %+v", diag)
				}
			}
		})
	}
}
