package clientagent

import (
	"Ole/internal/controlclient"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type tunnelSweepUpstream struct {
	mu              sync.Mutex
	tunnels         map[string]controlclient.Tunnel
	nextTunnelID    int
	listCalls       map[string]int
	disconnectCalls []string
}

func newTunnelSweepUpstream(tunnels ...controlclient.Tunnel) *tunnelSweepUpstream {
	store := make(map[string]controlclient.Tunnel, len(tunnels))
	nextTunnelID := 1
	for _, tunnel := range tunnels {
		store[tunnel.ID] = tunnel
		if strings.TrimSpace(tunnel.ID) != "" {
			nextTunnelID++
		}
	}
	return &tunnelSweepUpstream{
		tunnels:      store,
		nextTunnelID: nextTunnelID,
		listCalls:    map[string]int{},
	}
}

func (s *tunnelSweepUpstream) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/networks/", s.handleNetworkChildren)
	mux.HandleFunc("/api/v1/tunnels/", s.handleTunnelByID)
	mux.HandleFunc("/api/v1/peers/", s.handlePeerByID)
	return mux
}

func (s *tunnelSweepUpstream) handleNetworkChildren(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/networks/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 2 || parts[1] != "tunnels" {
		http.NotFound(w, r)
		return
	}
	networkID := parts[0]
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		s.listCalls[networkID]++
		tunnels := make([]controlclient.Tunnel, 0, len(s.tunnels))
		for _, tunnel := range s.tunnels {
			if strings.EqualFold(strings.TrimSpace(tunnel.NetworkID), strings.TrimSpace(networkID)) {
				tunnels = append(tunnels, tunnel)
			}
		}
		s.mu.Unlock()
		writeTunnelSweepJSON(w, http.StatusOK, map[string]any{"data": tunnels})
	case http.MethodPost:
		var req struct {
			PeerAID string `json:"peerAId"`
			PeerBID string `json:"peerBId"`
			Mode    string `json:"mode"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		defer s.mu.Unlock()
		for id, tunnel := range s.tunnels {
			if !strings.EqualFold(strings.TrimSpace(tunnel.NetworkID), strings.TrimSpace(networkID)) {
				continue
			}
			if samePeerPair(tunnel.PeerAID, tunnel.PeerBID, req.PeerAID, req.PeerBID) {
				tunnel.Mode = firstNonEmptyString(strings.ToUpper(strings.TrimSpace(req.Mode)), tunnel.Mode, "P2P")
				tunnel.State = "NEGOTIATING"
				s.tunnels[id] = tunnel
				writeTunnelSweepJSON(w, http.StatusCreated, map[string]any{"data": tunnel})
				return
			}
		}
		tunnel := controlclient.Tunnel{
			ID:        "tun-" + strconv.Itoa(s.nextTunnelID),
			NetworkID: networkID,
			PeerAID:   strings.TrimSpace(req.PeerAID),
			PeerBID:   strings.TrimSpace(req.PeerBID),
			Mode:      firstNonEmptyString(strings.ToUpper(strings.TrimSpace(req.Mode)), "P2P"),
			State:     "NEGOTIATING",
		}
		s.nextTunnelID++
		s.tunnels[tunnel.ID] = tunnel
		writeTunnelSweepJSON(w, http.StatusCreated, map[string]any{"data": tunnel})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *tunnelSweepUpstream) handleTunnelByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tunnelID := strings.TrimPrefix(r.URL.Path, "/api/v1/tunnels/")
	var req struct {
		State string `json:"state"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	defer s.mu.Unlock()
	tunnel, ok := s.tunnels[tunnelID]
	if !ok {
		writeTunnelSweepJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	tunnel.State = strings.ToUpper(strings.TrimSpace(req.State))
	s.tunnels[tunnelID] = tunnel
	writeTunnelSweepJSON(w, http.StatusOK, map[string]any{"data": tunnel})
}

func (s *tunnelSweepUpstream) handlePeerByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	peerID := strings.TrimPrefix(r.URL.Path, "/api/v1/peers/")
	s.mu.Lock()
	s.disconnectCalls = append(s.disconnectCalls, peerID)
	s.mu.Unlock()
	writeTunnelSweepJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"id": peerID}})
}

func (s *tunnelSweepUpstream) listCallsForNetwork(networkID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listCalls[networkID]
}

func (s *tunnelSweepUpstream) disconnectCallCount(peerID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, item := range s.disconnectCalls {
		if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(peerID)) {
			count++
		}
	}
	return count
}

func (s *tunnelSweepUpstream) tunnelStateForPair(peerAID, peerBID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tunnel := range s.tunnels {
		if samePeerPair(tunnel.PeerAID, tunnel.PeerBID, peerAID, peerBID) {
			return tunnel.State
		}
	}
	return ""
}

func writeTunnelSweepJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func TestReconcileNegotiationTunnelsListsEachManagedNetworkOnceAcrossReplacementPeers(t *testing.T) {
	upstream := newTunnelSweepUpstream(
		controlclient.Tunnel{ID: "tun-old", NetworkID: "net-1", PeerAID: "peer-local-old", PeerBID: "peer-remote", Mode: "P2P", State: "OPEN"},
		controlclient.Tunnel{ID: "tun-new", NetworkID: "net-1", PeerAID: "peer-local-new", PeerBID: "peer-remote", Mode: "P2P", State: "OPEN"},
	)
	server := httptest.NewServer(upstream.Handler())
	defer server.Close()

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(
		controlclient.New(server.URL),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\managed-peer-tunnel-reconcile-state.json"),
		RuntimeConfig{},
		nil,
		nil,
		nil,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()
	agent.overlayDNS = nil
	agent.adapterManager = nil
	agent.directManager = nil
	agent.relayManager = nil
	agent.currentUser = &controlclient.User{ID: "user-1", Email: "owner@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.ManagedPeers = []ManagedPeerState{
		{
			ServerBaseURL: agent.remote.BaseURL(),
			UserID:        agent.currentUser.ID,
			NetworkID:     "net-1",
			PeerID:        "peer-local-old",
			Endpoint:      "127.0.0.1:4000",
			OverlayCIDR:   "10.10.0.0/24",
			VirtualIP:     "10.10.0.2",
		},
		{
			ServerBaseURL: agent.remote.BaseURL(),
			UserID:        agent.currentUser.ID,
			NetworkID:     "net-1",
			PeerID:        "peer-local-new",
			Endpoint:      "127.0.0.1:4001",
			OverlayCIDR:   "10.10.0.0/24",
			VirtualIP:     "10.10.0.2",
		},
	}
	agent.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-local-new",
		RemotePeerID:   "peer-remote",
		Reachability:   "DIRECT",
		State:          "CONNECTED",
		TransportReady: true,
		TransportMode:  "DIRECT",
	}}

	if err := agent.reconcileNegotiationTunnelsLocked(); err != nil {
		t.Fatalf("reconcile negotiation tunnels: %v", err)
	}
	if upstream.listCallsForNetwork("net-1") != 1 {
		t.Fatalf("expected a single tunnel listing for replacement-managed network, got %d", upstream.listCallsForNetwork("net-1"))
	}
	if upstream.tunnelStateForPair("peer-local-old", "peer-remote") != "CLOSED" {
		t.Fatalf("expected stale replacement tunnel to close, got %q", upstream.tunnelStateForPair("peer-local-old", "peer-remote"))
	}
	if upstream.tunnelStateForPair("peer-local-new", "peer-remote") != "OPEN" {
		t.Fatalf("expected active replacement tunnel to stay open, got %q", upstream.tunnelStateForPair("peer-local-new", "peer-remote"))
	}
}

func TestReconcileNegotiationTunnelsClosesStaleReplacedTunnelAfterManagedPeerHandoff(t *testing.T) {
	upstream := newTunnelSweepUpstream(
		controlclient.Tunnel{ID: "tun-old", NetworkID: "net-1", PeerAID: "peer-local-old", PeerBID: "peer-remote", Mode: "P2P", State: "OPEN"},
	)
	server := httptest.NewServer(upstream.Handler())
	defer server.Close()

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(
		controlclient.New(server.URL),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\managed-peer-tunnel-handoff-state.json"),
		RuntimeConfig{},
		nil,
		nil,
		nil,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()
	agent.overlayDNS = nil
	agent.adapterManager = nil
	agent.directManager = nil
	agent.relayManager = nil
	agent.currentUser = &controlclient.User{ID: "user-1", Email: "owner@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.ManagedPeers = []ManagedPeerState{{
		ServerBaseURL: agent.remote.BaseURL(),
		UserID:        agent.currentUser.ID,
		NetworkID:     "net-1",
		PeerID:        "peer-local-new",
		Endpoint:      "127.0.0.1:4001",
		OverlayCIDR:   "10.10.0.0/24",
		VirtualIP:     "10.10.0.2",
	}}
	agent.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-local-new",
		RemotePeerID:   "peer-remote",
		Reachability:   "DIRECT",
		State:          "CONNECTED",
		TransportReady: true,
		TransportMode:  "DIRECT",
	}}

	if err := agent.reconcileNegotiationTunnelsLocked(); err != nil {
		t.Fatalf("reconcile negotiation tunnels after managed peer handoff: %v", err)
	}
	if upstream.tunnelStateForPair("peer-local-old", "peer-remote") != "CLOSED" {
		t.Fatalf("expected stale pre-handoff tunnel to close after managed peer handoff, got %q", upstream.tunnelStateForPair("peer-local-old", "peer-remote"))
	}
	if upstream.tunnelStateForPair("peer-local-new", "peer-remote") != "OPEN" {
		t.Fatalf("expected replacement managed-peer tunnel to open after handoff, got %q", upstream.tunnelStateForPair("peer-local-new", "peer-remote"))
	}
}

func TestDisconnectManagedPeersClosesStaleReplacementTunnelsBeforeDedupe(t *testing.T) {
	upstream := newTunnelSweepUpstream(
		controlclient.Tunnel{ID: "tun-old", NetworkID: "net-1", PeerAID: "peer-local-old", PeerBID: "peer-remote", Mode: "P2P", State: "OPEN"},
		controlclient.Tunnel{ID: "tun-new", NetworkID: "net-1", PeerAID: "peer-local-new", PeerBID: "peer-remote", Mode: "P2P", State: "OPEN"},
	)
	server := httptest.NewServer(upstream.Handler())
	defer server.Close()

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(
		controlclient.New(server.URL),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\managed-peer-tunnel-disconnect-state.json"),
		RuntimeConfig{},
		nil,
		nil,
		nil,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()
	agent.overlayDNS = nil
	agent.adapterManager = nil
	agent.directManager = nil
	agent.relayManager = nil
	agent.currentUser = &controlclient.User{ID: "user-1", Email: "owner@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.ManagedPeers = []ManagedPeerState{
		{
			ServerBaseURL: agent.remote.BaseURL(),
			UserID:        agent.currentUser.ID,
			NetworkID:     "net-1",
			PeerID:        "peer-local-old",
			Endpoint:      "127.0.0.1:4000",
			OverlayCIDR:   "10.10.0.0/24",
			VirtualIP:     "10.10.0.2",
		},
		{
			ServerBaseURL: agent.remote.BaseURL(),
			UserID:        agent.currentUser.ID,
			NetworkID:     "net-1",
			PeerID:        "peer-local-new",
			Endpoint:      "127.0.0.1:4001",
			OverlayCIDR:   "10.10.0.0/24",
			VirtualIP:     "10.10.0.2",
		},
	}
	agent.connections = []ConnectionStatus{{
		NetworkID:    "net-1",
		LocalPeerID:  "peer-local-new",
		RemotePeerID: "peer-remote",
		State:        "CONNECTED",
	}}

	if err := agent.disconnectManagedPeersLocked(false); err != nil {
		t.Fatalf("disconnect managed peers: %v", err)
	}
	if upstream.tunnelStateForPair("peer-local-old", "peer-remote") != "CLOSED" {
		t.Fatalf("expected stale replacement tunnel to close on disconnect, got %q", upstream.tunnelStateForPair("peer-local-old", "peer-remote"))
	}
	if upstream.tunnelStateForPair("peer-local-new", "peer-remote") != "CLOSED" {
		t.Fatalf("expected active managed-peer tunnel to close on disconnect, got %q", upstream.tunnelStateForPair("peer-local-new", "peer-remote"))
	}
	if upstream.disconnectCallCount("peer-local-old") != 0 {
		t.Fatalf("expected stale replacement peer not to receive duplicate disconnect, got %d", upstream.disconnectCallCount("peer-local-old"))
	}
	if upstream.disconnectCallCount("peer-local-new") != 1 {
		t.Fatalf("expected deduped live peer disconnect, got %d", upstream.disconnectCallCount("peer-local-new"))
	}
}
