package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/directprobe"
	"Ole/internal/relay"
	"Ole/internal/relaytransport"
	"Ole/internal/transportauth"
	"Ole/internal/virtualadapter"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This adapter models a destructive Wintun read: a packet cannot be recovered
// after ReadPackets removes it. Accessors also allow observing a blocked HTTP call.
type forwardingAdapter struct {
	virtualadapter.Manager
	mu       sync.Mutex
	reads    int
	outbound []virtualadapter.Packet
	written  []virtualadapter.Packet
}

func (m *forwardingAdapter) ReadPackets(limit int) ([]virtualadapter.Packet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	if limit > len(m.outbound) {
		limit = len(m.outbound)
	}
	packets := append([]virtualadapter.Packet(nil), m.outbound[:limit]...)
	m.outbound = m.outbound[limit:]
	return packets, nil
}

func (m *forwardingAdapter) WritePackets(packets []virtualadapter.Packet) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.written = append(m.written, packets...)
	return nil
}

func (m *forwardingAdapter) pending() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reads, len(m.outbound)
}

func forwardingIPv4Packet(source, destination string, sequence int) []byte {
	packet := make([]byte, 24)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], net.ParseIP(source).To4())
	copy(packet[16:20], net.ParseIP(destination).To4())
	binary.BigEndian.PutUint32(packet[20:], uint32(sequence))
	return packet
}

func newForwardingAgent(t *testing.T, mode, baseURL string) (*Agent, *forwardingAdapter, transportManagerForPackets) {
	t.Helper()
	adapter := &forwardingAdapter{}
	for sequence := range 64 {
		adapter.outbound = append(adapter.outbound, virtualadapter.Packet{Data: forwardingIPv4Packet("10.0.0.2", "10.0.0.3", sequence)})
	}
	state := defaultPersistentState()
	if _, err := state.EnsureKeyPair(); err != nil {
		t.Fatal(err)
	}
	state.SetManagedPeer(baseURL, "user", "network", "local", "127.0.0.1:0", "10.0.0.0/24", "10.0.0.2")
	a := &Agent{
		remote: controlclient.New(baseURL), currentUser: &controlclient.User{ID: "user"},
		currentSession: &controlclient.Session{AccessToken: "forwarding-test", ExpiresAtUnix: time.Now().Add(time.Hour).Unix()},
		deviceState:    state, adapterManager: adapter,
		directAttempts: map[string]DirectAttemptState{connectionKey("network", "local", "remote"): {DirectReady: true, TransportMode: mode}},
		connections:    []ConnectionStatus{{NetworkID: "network", LocalPeerID: "local", RemotePeerID: "remote", RemoteVirtualIP: "10.0.0.3", TransportReady: true, TransportMode: mode, State: "CONNECTED"}},
	}
	identities := map[string]transportauth.Identity{}
	keys := map[string]ed25519.PrivateKey{}
	for _, peer := range []string{"local", "remote"} {
		seed := sha256.Sum256([]byte("packet-forwarding-test-" + peer))
		keys[peer] = ed25519.NewKeyFromSeed(seed[:])
		identities[peer] = transportauth.Identity{DeviceID: "device-" + peer, PublicKey: keys[peer].Public().(ed25519.PublicKey)}
	}
	credentials := func(peer string) *transportauth.Credentials {
		return &transportauth.Credentials{NetworkID: "network", PeerID: peer, DeviceID: identities[peer].DeviceID, PrivateKey: keys[peer], Peers: identities, ExpiresAt: time.Now().Add(transportauth.SnapshotTTL)}
	}
	var transport transportManagerForPackets
	if mode == "DIRECT" {
		manager := directprobe.New()
		t.Cleanup(func() { _ = manager.Close() })
		local, remote := fileTransferUDPAddress(t), fileTransferUDPAddress(t)
		if err := manager.Reconcile([]directprobe.Binding{{PeerID: "local", ListenAddress: local, Credentials: credentials("local")}, {PeerID: "remote", ListenAddress: remote, Credentials: credentials("remote")}}); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Establish("local", "remote", []string{remote}, time.Second); err != nil {
			t.Fatal(err)
		}
		a.directManager, transport = manager, directPacketAdapter{manager}
	} else {
		server, err := relay.Listen("127.0.0.1:0", relay.StaticAuthorizer{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = server.Close() })
		manager := relaytransport.New()
		t.Cleanup(func() { _ = manager.Close() })
		if err := manager.Reconcile([]relaytransport.Binding{{PeerID: "local", RelayAddress: server.LocalAddr().String(), AccessToken: "local-test", Credentials: credentials("local")}, {PeerID: "remote", RelayAddress: server.LocalAddr().String(), AccessToken: "remote-test", Credentials: credentials("remote")}}); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Establish("local", "remote", time.Second); err != nil {
			t.Fatal(err)
		}
		a.relayManager, transport = manager, relayPacketAdapter{manager}
	}
	return a, adapter, transport
}

func TestForwardingPreservesAdapterBatchOnPolicyFailure(t *testing.T) {
	for _, mode := range []string{"DIRECT", "RELAY"} {
		for _, failure := range []string{"unavailable", "unauthorized", "invalid-json"} {
			t.Run(mode+"/"+failure, func(t *testing.T) {
				var healthy atomic.Bool
				var requests atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.URL.Path != "/api/v1/networks" || r.Method != http.MethodGet {
						t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					if !healthy.Load() {
						switch failure {
						case "unavailable":
							http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
						case "unauthorized":
							http.Error(w, "revoked", http.StatusUnauthorized)
						default:
							_, _ = w.Write([]byte(`{"data":`))
						}
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": []controlclient.Network{{ID: "network", RoutingPolicy: "SPLIT", GroupTrafficPolicy: "BLOCKED"}}})
				}))
				defer server.Close()
				a, adapter, transport := newForwardingAgent(t, mode, server.URL)
				for range 3 {
					if err := a.forwardTransportPacketsLocked(time.Now()); err == nil {
						t.Error("expected policy failure")
					}
				}
				if reads, pending := adapter.pending(); reads != 0 || pending != 64 {
					t.Errorf("policy failure consumed adapter packets: reads=%d, pending=%d; want 0,64", reads, pending)
				}
				if packets := transport.DrainInbound("remote", 256); len(packets) != 0 {
					t.Errorf("forwarded %d packets without current policy", len(packets))
				}
				healthy.Store(true)
				var received []transportInboundPacket
				for batch := 0; batch < 2; batch++ {
					if err := a.forwardTransportPacketsLocked(time.Now()); err != nil {
						t.Fatal(err)
					}
					deadline := time.Now().Add(time.Second)
					for len(received) < (batch+1)*32 && time.Now().Before(deadline) {
						received = append(received, transport.DrainInbound("remote", 256)...)
						time.Sleep(time.Millisecond)
					}
				}
				if len(received) != 64 {
					t.Fatalf("after policy recovery delivered %d/64 packets", len(received))
				}
				for sequence, packet := range received {
					if packet.RemotePeerID != "local" || !bytes.Equal(packet.Payload, forwardingIPv4Packet("10.0.0.2", "10.0.0.3", sequence)) {
						t.Fatalf("incorrect packet/sequence at %d", sequence)
					}
				}
				if requests.Load() != 4 {
					t.Errorf("want three failures and one shared policy refresh, got %d", requests.Load())
				}
			})
		}
	}
}

func TestForwardingWaitsForPolicyBeforeAdapterRead(t *testing.T) {
	for _, mode := range []string{"DIRECT", "RELAY"} {
		t.Run(mode, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				<-release
				http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			}))
			defer server.Close()
			defer unblock()
			a, adapter, _ := newForwardingAgent(t, mode, server.URL)
			done := make(chan error, 1)
			go func() { done <- a.forwardTransportPacketsLocked(time.Now()) }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("policy request did not arrive")
			}
			if reads, pending := adapter.pending(); reads != 0 || pending != 64 {
				t.Errorf("slow policy consumed batch: reads=%d, pending=%d; want 0,64", reads, pending)
			}
			unblock()
			select {
			case err := <-done:
				if err == nil {
					t.Error("expected policy failure")
				}
			case <-time.After(time.Second):
				t.Fatal("forwarder did not return after HTTP response")
			}
		})
	}
}
