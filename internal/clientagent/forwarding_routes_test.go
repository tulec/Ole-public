package clientagent

import (
	"Ole/internal/controlclient"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func routingFixture(t testing.TB) *Agent {
	t.Helper()
	base := "http://127.0.0.1:1"
	state := &PersistentState{ManagedPeers: []ManagedPeerState{{ServerBaseURL: base, UserID: "user", NetworkID: "network", PeerID: "local", VirtualIP: "10.0.0.2", OverlayCIDR: "10.0.0.0/24"}}}
	a := &Agent{remote: controlclient.New(base), currentUser: &controlclient.User{ID: "user"}, currentSession: &controlclient.Session{AccessToken: "private-token", ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}, deviceState: state,
		connections:     []ConnectionStatus{{NetworkID: "network", LocalPeerID: "local", RemotePeerID: "remote", RemoteCandidates: []string{"127.0.0.1:1234"}, TransportReady: true, TransportMode: "DIRECT"}},
		discoveredPeers: map[string][]controlclient.Peer{"network": {{ID: "remote", VirtualIP: "10.0.0.3"}}},
	}
	a.publishForwardingPolicyLocked(map[string]controlclient.Network{"network": {ID: "network", RoutingPolicy: "SPLIT", GroupTrafficPolicy: "BLOCKED"}}, time.Now())
	return a
}

func TestForwardingRoutesOwnTheirData(t *testing.T) {
	a := routingFixture(t)
	routes := a.publishForwardingRoutesLocked(a.forwardingPolicy.networks)
	if routes == nil {
		t.Fatal("missing routing snapshot")
	}
	first := routes.routes("10.0.0.2", "10.0.0.3")
	if len(first) != 1 {
		t.Fatal("missing route", first)
	}
	first[0].RemoteCandidates[0] = "changed-output"
	a.connections[0].RemoteCandidates[0] = "changed-source"
	a.connections = nil
	a.discoveredPeers["network"][0].VirtualIP = "10.0.0.99"
	a.deviceState.ManagedPeers[0].VirtualIP = "10.0.0.99"
	a.currentUser.ID = "other"
	second := routes.routes("10.0.0.2", "10.0.0.3")
	if len(second) != 1 || second[0].RemotePeerID != "remote" || second[0].RemoteCandidates[0] != "127.0.0.1:1234" {
		t.Fatal("routing snapshot shares mutable data", second)
	}
	if routes.view.currentSession != nil || routes.view.remote.AccessToken() != "" || routes.view.deviceState.PrivateKey != "" || routes.view.directManager != nil || routes.view.adapterManager != nil || routes.view.relayManager != nil {
		t.Fatal("routing view retains credentials or I/O managers")
	}
}

func TestForwardingRoutesStopAfterInvalidation(t *testing.T) {
	for _, reason := range []string{"expiry", "logout", "server", "user", "token", "replacement", "close"} {
		t.Run(reason, func(t *testing.T) {
			a := routingFixture(t)
			routes := a.publishForwardingRoutesLocked(a.forwardingPolicy.networks)
			switch reason {
			case "expiry":
				routes.expires = time.Now().Add(-time.Second)
			case "logout":
				a.clearInMemorySessionLocked()
			case "server":
				a.remote.SetBaseURL("http://127.0.0.1:2")
				a.publishForwardingRoutesLocked(a.forwardingPolicy.networks)
			case "user":
				a.currentUser.ID = "other"
				a.publishForwardingRoutesLocked(a.forwardingPolicy.networks)
			case "token":
				a.currentSession.AccessToken = "other"
				a.publishForwardingRoutesLocked(a.forwardingPolicy.networks)
			case "replacement":
				a.publishForwardingRoutesLocked(a.forwardingPolicy.networks)
			case "close":
				a.packetPumpsClosed.Store(true)
				a.refreshForwardingRoutesLocked()
			}
			if selected := routes.routes("10.0.0.2", "10.0.0.3"); len(selected) != 0 {
				t.Fatal("retired snapshot retained a route")
			}
		})
	}
}

func TestForwardingRouteSelectionWhileControlPlaneHoldsMutex(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		close(entered)
		<-release
		http.Error(w, "offline", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	defer unblock()
	a := routingFixture(t)
	a.remote.SetBaseURL(server.URL)
	a.deviceState.ManagedPeers[0].ServerBaseURL = server.URL
	a.publishForwardingPolicyLocked(a.forwardingPolicy.networks, time.Now())
	routes := a.publishForwardingRoutesLocked(a.forwardingPolicy.networks)
	done := make(chan struct{})
	go func() { a.mu.Lock(); defer a.mu.Unlock(); defer close(done); _, _ = a.listNetworksByIDLocked() }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP request did not start")
	}
	var workers sync.WaitGroup
	var successes atomic.Int32
	workers.Add(16)
	for range 16 {
		go func() {
			defer workers.Done()
			for range 100 {
				if len(routes.routes("10.0.0.2", "10.0.0.3")) == 1 {
					successes.Add(1)
				}
			}
		}()
	}
	selected := make(chan struct{})
	go func() { workers.Wait(); close(selected) }()
	select {
	case <-selected:
	case <-time.After(2 * time.Second):
		t.Fatal("route selection waited for Agent.mu")
	}
	if successes.Load() != 1600 || requests.Load() != 1 {
		t.Fatal("routing requires control-plane I/O", successes.Load(), requests.Load())
	}
	unblock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh did not return")
	}
	if len(routes.routes("10.0.0.2", "10.0.0.3")) != 0 || a.forwardingRoutes.Load() != nil {
		t.Fatal("refresh error did not invalidate held routing snapshot")
	}
}

func BenchmarkForwardingRoutes(b *testing.B) {
	a := routingFixture(b)
	routes := a.publishForwardingRoutesLocked(a.forwardingPolicy.networks)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if len(routes.routes("10.0.0.2", "10.0.0.3")) != 1 {
			b.Fatal("route missing")
		}
	}
}
