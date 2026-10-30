package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/directprobe"
	"Ole/internal/stun"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type lifecycleDirectManager struct {
	exchanges []string
	drops     []string
}

func (m *lifecycleDirectManager) Reconcile(_ []directprobe.Binding) error {
	return nil
}

func (m *lifecycleDirectManager) Attempt(_, _ string, _ []string, _ time.Duration) (directprobe.Result, error) {
	return directprobe.Result{}, nil
}

func (m *lifecycleDirectManager) Establish(localPeerID, remotePeerID string, _ []string, _ time.Duration) (directprobe.Session, error) {
	return directprobe.Session{SessionID: localPeerID + "|" + remotePeerID}, nil
}

func (m *lifecycleDirectManager) Exchange(localPeerID, remotePeerID string, payload []byte, _ time.Duration) ([]byte, error) {
	m.exchanges = append(m.exchanges, localPeerID+"|"+remotePeerID+"|"+string(payload))
	if string(payload) == "ole-keepalive" {
		return []byte("ack:ole-keepalive"), nil
	}
	return []byte("ack:ole-handshake"), nil
}

func (m *lifecycleDirectManager) SetExchangeHandler(_ string, _ directprobe.ExchangeHandler) error {
	return nil
}

func (m *lifecycleDirectManager) SendPacket(_, _ string, _ []byte) error {
	return nil
}

func (m *lifecycleDirectManager) DrainInbound(_ string, _ int) []directprobe.Packet {
	return nil
}

func (m *lifecycleDirectManager) DropSession(localPeerID, remotePeerID string) {
	m.drops = append(m.drops, localPeerID+"|"+remotePeerID)
}

func (m *lifecycleDirectManager) Close() error {
	return nil
}

func (m *lifecycleDirectManager) ProbeSTUN(_, _ string, _ time.Duration) (stun.ProbeResult, error) {
	return stun.ProbeResult{}, nil
}

func TestMaintainTransportQualityPrefersReplacementSessionDuringMetadataGap(t *testing.T) {
	directManager := &lifecycleDirectManager{}
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New("http://example.invalid"),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\transport-quality-replacement-state.json"),
		RuntimeConfig{
			LifecycleInterval:   time.Hour,
			HeartbeatInterval:   time.Hour,
			PeerDiscoveryPeriod: time.Hour,
			STUNProbePeriod:     time.Hour,
			TransportKeepalive:  5 * time.Second,
		},
		nil,
		directManager,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	now := time.Unix(500, 0)
	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local",
			RemotePeerID:             "peer-remote-old",
			RemoteUserID:             "user-remote",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-old",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 100,
			LastTransportUnix:        now.Add(-10 * time.Second).Unix(),
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local",
			RemotePeerID:             "peer-remote-new",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-new",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 200,
			LastTransportUnix:        now.Add(-10 * time.Second).Unix(),
		},
	}
	agent.directAttempts[connectionKey("net-1", "peer-local", "peer-remote-old")] = DirectAttemptState{
		DirectReady:          true,
		TransportMode:        "DIRECT",
		TransportSessionID:   "sess-old",
		TransportStartedAt:   time.Unix(100, 0),
		LastTransportAt:      now.Add(-10 * time.Second),
		LastKeepaliveAt:      now.Add(-10 * time.Second),
		AverageRTT:           10 * time.Millisecond,
		LastRTT:              10 * time.Millisecond,
		SelectedCandidate:    "198.51.100.10:5000",
		RemoteEndpointKey:    "198.51.100.10:5000",
		TransportPacketCount: 1,
	}
	agent.directAttempts[connectionKey("net-1", "peer-local", "peer-remote-new")] = DirectAttemptState{
		DirectReady:          true,
		TransportMode:        "DIRECT",
		TransportSessionID:   "sess-new",
		TransportStartedAt:   time.Unix(200, 0),
		LastTransportAt:      now.Add(-10 * time.Second),
		LastKeepaliveAt:      now.Add(-10 * time.Second),
		AverageRTT:           10 * time.Millisecond,
		LastRTT:              10 * time.Millisecond,
		SelectedCandidate:    "198.51.100.11:5001",
		RemoteEndpointKey:    "198.51.100.11:5001",
		TransportPacketCount: 1,
	}

	if err := agent.maintainTransportQualityLocked(now); err != nil {
		t.Fatalf("maintain transport quality: %v", err)
	}
	if len(directManager.exchanges) != 1 {
		t.Fatalf("expected only one keepalive exchange for replacement target, got %#v", directManager.exchanges)
	}
	if !strings.Contains(directManager.exchanges[0], "peer-remote-new|ole-keepalive") {
		t.Fatalf("expected keepalive to prefer replacement peer during metadata gap, got %#v", directManager.exchanges)
	}
}

func TestReplacementConnectionForPeerRefreshUsesUniqueEndpointContinuityWhenPeerMetadataIsMissing(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New("http://example.invalid"),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\peer-refresh-endpoint-continuity-state.json"),
		RuntimeConfig{},
		nil,
		&dataplaneExchangeManager{},
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.connections = []ConnectionStatus{{
		NetworkID:        "net-1",
		LocalPeerID:      "peer-local",
		RemotePeerID:     "peer-remote-old",
		RemoteUserID:     "user-remote",
		RemoteVirtualIP:  "10.10.0.3",
		RemoteEndpoint:   "198.51.100.10:5000",
		RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
		TransportReady:   true,
		TransportMode:    "DIRECT",
		State:            "CONNECTED",
		Reachability:     "DIRECT",
	}}

	remotePeer := controlclient.Peer{
		ID:        "peer-remote-new",
		NetworkID: "net-1",
		Status:    "ONLINE",
		Endpoint:  "198.51.100.10:5000",
	}
	candidates := []controlclient.SignalCandidate{
		{Type: "HOST", Protocol: "UDP", Address: "198.51.100.10:5000"},
		{Type: "SRFLX", Protocol: "UDP", Address: "203.0.113.10:6000"},
	}

	previous := agent.replacementConnectionForPeerRefreshLocked("net-1", "peer-local", remotePeer, candidates)
	if previous == nil || previous.RemotePeerID != "peer-remote-old" {
		t.Fatalf("expected peer refresh to recover the previous connection through unique endpoint continuity, got %#v", previous)
	}

	connection := buildConnectionStatus("net-1", "peer-local", remotePeer, candidates, previous)
	if connection.RemoteUserID != "user-remote" || connection.RemoteVirtualIP != "10.10.0.3" {
		t.Fatalf("expected peer refresh endpoint continuity to preserve prior remote identity, got %#v", connection)
	}
	if len(connection.RemoteCandidates) != 2 || connection.RemoteCandidates[0] != "198.51.100.10:5000" || connection.RemoteCandidates[1] != "203.0.113.10:6000" {
		t.Fatalf("expected peer refresh endpoint continuity to keep the live candidate set, got %#v", connection.RemoteCandidates)
	}
}

func TestReplacementConnectionForPeerRefreshUsesPartialEndpointContinuityWhenPeerMetadataIsMissing(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New("http://example.invalid"),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\peer-refresh-endpoint-partial-continuity-state.json"),
		RuntimeConfig{},
		nil,
		&dataplaneExchangeManager{},
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.connections = []ConnectionStatus{{
		NetworkID:        "net-1",
		LocalPeerID:      "peer-local",
		RemotePeerID:     "peer-remote-old",
		RemoteUserID:     "user-remote",
		RemoteVirtualIP:  "10.10.0.3",
		RemoteEndpoint:   "198.51.100.10:5000",
		RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
		TransportReady:   true,
		TransportMode:    "DIRECT",
		State:            "CONNECTED",
		Reachability:     "DIRECT",
	}}

	remotePeer := controlclient.Peer{
		ID:        "peer-remote-new",
		NetworkID: "net-1",
		Status:    "ONLINE",
		Endpoint:  "198.51.100.10:5000",
	}
	candidates := []controlclient.SignalCandidate{
		{Type: "HOST", Protocol: "UDP", Address: "198.51.100.10:5000"},
	}

	previous := agent.replacementConnectionForPeerRefreshLocked("net-1", "peer-local", remotePeer, candidates)
	if previous == nil || previous.RemotePeerID != "peer-remote-old" {
		t.Fatalf("expected peer refresh to recover the previous connection through partial endpoint continuity, got %#v", previous)
	}

	connection := buildConnectionStatus("net-1", "peer-local", remotePeer, candidates, previous)
	if connection.RemoteUserID != "user-remote" || connection.RemoteVirtualIP != "10.10.0.3" {
		t.Fatalf("expected partial endpoint continuity to preserve prior remote identity, got %#v", connection)
	}
	if len(connection.RemoteCandidates) != 1 || connection.RemoteCandidates[0] != "198.51.100.10:5000" {
		t.Fatalf("expected peer refresh partial endpoint continuity to keep the live partial candidate set, got %#v", connection.RemoteCandidates)
	}
}

func TestReplacementConnectionForPeerRefreshFailsClosedForAmbiguousEndpointContinuity(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New("http://example.invalid"),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\peer-refresh-endpoint-ambiguous-state.json"),
		RuntimeConfig{},
		nil,
		&dataplaneExchangeManager{},
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-a",
			RemoteUserID:     "user-a",
			RemoteVirtualIP:  "10.10.0.3",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
			TransportReady:   true,
			TransportMode:    "DIRECT",
			State:            "CONNECTED",
			Reachability:     "DIRECT",
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-b",
			RemoteUserID:     "user-b",
			RemoteVirtualIP:  "10.10.0.4",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
			TransportReady:   true,
			TransportMode:    "DIRECT",
			State:            "CONNECTED",
			Reachability:     "DIRECT",
		},
	}

	remotePeer := controlclient.Peer{
		ID:        "peer-remote-new",
		NetworkID: "net-1",
		Status:    "ONLINE",
		Endpoint:  "198.51.100.10:5000",
	}
	candidates := []controlclient.SignalCandidate{
		{Type: "HOST", Protocol: "UDP", Address: "198.51.100.10:5000"},
		{Type: "SRFLX", Protocol: "UDP", Address: "203.0.113.10:6000"},
	}

	if previous := agent.replacementConnectionForPeerRefreshLocked("net-1", "peer-local", remotePeer, candidates); previous != nil {
		t.Fatalf("expected ambiguous endpoint continuity to fail closed instead of guessing a prior peer, got %#v", previous)
	}
}

func TestNegotiateDirectConnectionsDropsSupersededReplacementSessionDuringMetadataGap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || !strings.HasPrefix(r.URL.Path, "/api/v1/peers/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"peer-local"}}`))
	}))
	defer server.Close()

	directManager := &lifecycleDirectManager{}
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New(server.URL),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\transport-negotiate-replacement-state.json"),
		RuntimeConfig{
			LifecycleInterval:   time.Hour,
			HeartbeatInterval:   time.Hour,
			PeerDiscoveryPeriod: time.Hour,
			STUNProbePeriod:     time.Hour,
			TransportKeepalive:  time.Hour,
		},
		nil,
		directManager,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.adapterManager = nil
	agent.overlayDNS = nil
	agent.relayManager = nil
	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local",
			RemotePeerID:             "peer-remote-old",
			RemoteUserID:             "user-remote",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-old",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 100,
			LastTransportUnix:        150,
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local",
			RemotePeerID:             "peer-remote-new",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-new",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
	}
	agent.directAttempts[connectionKey("net-1", "peer-local", "peer-remote-old")] = DirectAttemptState{
		DirectReady:          true,
		TransportMode:        "DIRECT",
		TransportSessionID:   "sess-old",
		TransportStartedAt:   time.Unix(100, 0),
		LastTransportAt:      time.Unix(150, 0),
		LastKeepaliveAt:      time.Unix(150, 0),
		AverageRTT:           10 * time.Millisecond,
		LastRTT:              10 * time.Millisecond,
		SelectedCandidate:    "198.51.100.10:5000",
		RemoteEndpointKey:    "198.51.100.10:5000",
		TransportPacketCount: 1,
	}
	agent.directAttempts[connectionKey("net-1", "peer-local", "peer-remote-new")] = DirectAttemptState{
		DirectReady:          true,
		TransportMode:        "DIRECT",
		TransportSessionID:   "sess-new",
		TransportStartedAt:   time.Unix(200, 0),
		LastTransportAt:      time.Unix(250, 0),
		LastKeepaliveAt:      time.Unix(250, 0),
		AverageRTT:           10 * time.Millisecond,
		LastRTT:              10 * time.Millisecond,
		SelectedCandidate:    "198.51.100.11:5001",
		RemoteEndpointKey:    "198.51.100.11:5001",
		TransportPacketCount: 1,
	}

	if err := agent.negotiateDirectConnectionsLocked(time.Unix(500, 0)); err != nil {
		t.Fatalf("negotiate direct connections: %v", err)
	}
	if len(directManager.drops) != 1 || directManager.drops[0] != "peer-local|peer-remote-old" {
		t.Fatalf("expected stale replacement session to be dropped, got %#v", directManager.drops)
	}
	if _, ok := agent.directAttempts[connectionKey("net-1", "peer-local", "peer-remote-old")]; ok {
		t.Fatalf("expected stale replacement attempt to be removed, got %#v", agent.directAttempts)
	}
	replacement := agent.directAttempts[connectionKey("net-1", "peer-local", "peer-remote-new")]
	if !replacement.DirectReady || replacement.TransportSessionID != "sess-new" {
		t.Fatalf("expected replacement attempt to stay active, got %#v", replacement)
	}
	if agent.connections[0].TransportReady || agent.connections[0].TransportSessionID != "" {
		t.Fatalf("expected stale connection transport state to clear after replacement cleanup, got %#v", agent.connections[0])
	}
	if !strings.Contains(agent.connections[0].LastError, "superseded by replacement transport") {
		t.Fatalf("expected stale connection to record replacement cleanup reason, got %#v", agent.connections[0])
	}
}

func TestNegotiateDirectConnectionsKeepsDistinctSameOverlaySessionsForDifferentUsers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || !strings.HasPrefix(r.URL.Path, "/api/v1/peers/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"peer-local"}}`))
	}))
	defer server.Close()

	directManager := &lifecycleDirectManager{}
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New(server.URL),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\transport-negotiate-distinct-target-state.json"),
		RuntimeConfig{
			LifecycleInterval:   time.Hour,
			HeartbeatInterval:   time.Hour,
			PeerDiscoveryPeriod: time.Hour,
			STUNProbePeriod:     time.Hour,
			TransportKeepalive:  time.Hour,
		},
		nil,
		directManager,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.adapterManager = nil
	agent.overlayDNS = nil
	agent.relayManager = nil
	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local",
			RemotePeerID:             "peer-remote-a",
			RemoteUserID:             "user-a",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-a",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			TransportEstablishedUnix: 100,
			LastTransportUnix:        150,
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local",
			RemotePeerID:             "peer-remote-b",
			RemoteUserID:             "user-b",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-b",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
	}
	agent.directAttempts[connectionKey("net-1", "peer-local", "peer-remote-a")] = DirectAttemptState{
		DirectReady:        true,
		TransportMode:      "DIRECT",
		TransportSessionID: "sess-a",
	}
	agent.directAttempts[connectionKey("net-1", "peer-local", "peer-remote-b")] = DirectAttemptState{
		DirectReady:        true,
		TransportMode:      "DIRECT",
		TransportSessionID: "sess-b",
	}

	if err := agent.negotiateDirectConnectionsLocked(time.Unix(500, 0)); err != nil {
		t.Fatalf("negotiate direct connections: %v", err)
	}
	if len(directManager.drops) != 0 {
		t.Fatalf("expected known-distinct users with same overlay IP to stay separate, got %#v", directManager.drops)
	}
	if len(agent.directAttempts) != 2 {
		t.Fatalf("expected both distinct overlay sessions to remain active, got %#v", agent.directAttempts)
	}
}

func TestMaintainTransportQualityPrefersActiveLocalPeerSessionDuringSameDeviceOverlap(t *testing.T) {
	directManager := &lifecycleDirectManager{}
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New("http://example.invalid"),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\transport-quality-local-peer-overlap-state.json"),
		RuntimeConfig{
			LifecycleInterval:   time.Hour,
			HeartbeatInterval:   time.Hour,
			PeerDiscoveryPeriod: time.Hour,
			STUNProbePeriod:     time.Hour,
			TransportKeepalive:  5 * time.Second,
		},
		nil,
		directManager,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	now := time.Unix(500, 0)
	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:5000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local-old",
			RemotePeerID:             "peer-remote-old",
			RemoteUserID:             "user-remote",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-old",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 100,
			LastTransportUnix:        now.Add(-10 * time.Second).Unix(),
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local-new",
			RemotePeerID:             "peer-remote-new",
			RemoteUserID:             "user-remote",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-new",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         20,
			LastRTTMillis:            20,
			TransportEstablishedUnix: 200,
			LastTransportUnix:        now.Add(-10 * time.Second).Unix(),
		},
	}
	agent.directAttempts[connectionKey("net-1", "peer-local-old", "peer-remote-old")] = DirectAttemptState{
		DirectReady:          true,
		TransportMode:        "DIRECT",
		TransportSessionID:   "sess-old",
		TransportStartedAt:   time.Unix(100, 0),
		LastTransportAt:      now.Add(-10 * time.Second),
		LastKeepaliveAt:      now.Add(-10 * time.Second),
		AverageRTT:           10 * time.Millisecond,
		LastRTT:              10 * time.Millisecond,
		SelectedCandidate:    "198.51.100.10:5000",
		RemoteEndpointKey:    "198.51.100.10:5000",
		TransportPacketCount: 1,
	}
	agent.directAttempts[connectionKey("net-1", "peer-local-new", "peer-remote-new")] = DirectAttemptState{
		DirectReady:          true,
		TransportMode:        "DIRECT",
		TransportSessionID:   "sess-new",
		TransportStartedAt:   time.Unix(200, 0),
		LastTransportAt:      now.Add(-10 * time.Second),
		LastKeepaliveAt:      now.Add(-10 * time.Second),
		AverageRTT:           20 * time.Millisecond,
		LastRTT:              20 * time.Millisecond,
		SelectedCandidate:    "198.51.100.11:5001",
		RemoteEndpointKey:    "198.51.100.11:5001",
		TransportPacketCount: 1,
	}

	if err := agent.maintainTransportQualityLocked(now); err != nil {
		t.Fatalf("maintain transport quality: %v", err)
	}
	if len(directManager.exchanges) != 1 {
		t.Fatalf("expected only the active local-peer session to receive keepalive maintenance, got %#v", directManager.exchanges)
	}
	if !strings.Contains(directManager.exchanges[0], "peer-local-new|peer-remote-new|ole-keepalive") {
		t.Fatalf("expected keepalive maintenance to prefer the active local peer during overlap, got %#v", directManager.exchanges)
	}
	if agent.connections[0].LastKeepaliveUnix != 0 || agent.connections[0].LastRTTMillis != 10 {
		t.Fatalf("expected stale local connection metrics to stay untouched, got %#v", agent.connections[0])
	}
}

func TestMaintainTransportQualityPrefersActiveLocalPeerSessionDuringSameDeviceOverlapWithMetadataGap(t *testing.T) {
	directManager := &lifecycleDirectManager{}
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New("http://example.invalid"),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\transport-quality-local-peer-overlap-metadata-gap-state.json"),
		RuntimeConfig{
			LifecycleInterval:   time.Hour,
			HeartbeatInterval:   time.Hour,
			PeerDiscoveryPeriod: time.Hour,
			STUNProbePeriod:     time.Hour,
			TransportKeepalive:  5 * time.Second,
		},
		nil,
		directManager,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	now := time.Unix(500, 0)
	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:5000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local-old",
			RemotePeerID:             "peer-remote-old",
			RemoteUserID:             "user-remote",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-old",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 100,
			LastTransportUnix:        now.Add(-10 * time.Second).Unix(),
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local-new",
			RemotePeerID:             "peer-remote-new",
			RemoteUserID:             "user-remote",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-new",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         20,
			LastRTTMillis:            20,
			TransportEstablishedUnix: 200,
			LastTransportUnix:        now.Add(-10 * time.Second).Unix(),
		},
	}
	agent.directAttempts[connectionKey("net-1", "peer-local-old", "peer-remote-old")] = DirectAttemptState{
		DirectReady:          true,
		TransportMode:        "DIRECT",
		TransportSessionID:   "sess-old",
		TransportStartedAt:   time.Unix(100, 0),
		LastTransportAt:      now.Add(-10 * time.Second),
		LastKeepaliveAt:      now.Add(-10 * time.Second),
		AverageRTT:           10 * time.Millisecond,
		LastRTT:              10 * time.Millisecond,
		SelectedCandidate:    "198.51.100.10:5000",
		RemoteEndpointKey:    "198.51.100.10:5000",
		TransportPacketCount: 1,
	}
	agent.directAttempts[connectionKey("net-1", "peer-local-new", "peer-remote-new")] = DirectAttemptState{
		DirectReady:          true,
		TransportMode:        "DIRECT",
		TransportSessionID:   "sess-new",
		TransportStartedAt:   time.Unix(200, 0),
		LastTransportAt:      now.Add(-10 * time.Second),
		LastKeepaliveAt:      now.Add(-10 * time.Second),
		AverageRTT:           20 * time.Millisecond,
		LastRTT:              20 * time.Millisecond,
		SelectedCandidate:    "198.51.100.11:5001",
		RemoteEndpointKey:    "198.51.100.11:5001",
		TransportPacketCount: 1,
	}

	if err := agent.maintainTransportQualityLocked(now); err != nil {
		t.Fatalf("maintain transport quality: %v", err)
	}
	if len(directManager.exchanges) != 1 {
		t.Fatalf("expected only the active replacement session to receive keepalive maintenance during metadata gap overlap, got %#v", directManager.exchanges)
	}
	if !strings.Contains(directManager.exchanges[0], "peer-local-new|peer-remote-new|ole-keepalive") {
		t.Fatalf("expected keepalive maintenance to prefer the active replacement session during local-peer metadata gap overlap, got %#v", directManager.exchanges)
	}
	if agent.connections[0].LastKeepaliveUnix != 0 || agent.connections[0].LastRTTMillis != 10 {
		t.Fatalf("expected stale local connection metrics to stay untouched during metadata gap overlap, got %#v", agent.connections[0])
	}
}

func TestMaintainTransportQualityUsesEndpointContinuityDuringLocalPeerMetadataGap(t *testing.T) {
	directManager := &lifecycleDirectManager{}
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New("http://example.invalid"),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\transport-quality-local-peer-endpoint-gap-state.json"),
		RuntimeConfig{
			LifecycleInterval:   time.Hour,
			HeartbeatInterval:   time.Hour,
			PeerDiscoveryPeriod: time.Hour,
			STUNProbePeriod:     time.Hour,
			TransportKeepalive:  5 * time.Second,
		},
		nil,
		directManager,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	now := time.Unix(500, 0)
	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:5000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local-old",
			RemotePeerID:             "peer-remote-old",
			RemoteUserID:             "user-remote",
			RemoteVirtualIP:          "10.10.0.3",
			RemoteEndpoint:           "198.51.100.10:5000",
			RemoteCandidates:         []string{"198.51.100.10:5000", "203.0.113.10:6000"},
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-old",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 100,
			LastTransportUnix:        now.Add(-10 * time.Second).Unix(),
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local-new",
			RemotePeerID:             "peer-remote-new",
			RemoteEndpoint:           "198.51.100.10:5000",
			RemoteCandidates:         []string{"198.51.100.10:5000"},
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-new",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         20,
			LastRTTMillis:            20,
			TransportEstablishedUnix: 200,
			LastTransportUnix:        now.Add(-10 * time.Second).Unix(),
		},
	}
	agent.directAttempts[connectionKey("net-1", "peer-local-old", "peer-remote-old")] = DirectAttemptState{
		DirectReady:          true,
		TransportMode:        "DIRECT",
		TransportSessionID:   "sess-old",
		TransportStartedAt:   time.Unix(100, 0),
		LastTransportAt:      now.Add(-10 * time.Second),
		LastKeepaliveAt:      now.Add(-10 * time.Second),
		AverageRTT:           10 * time.Millisecond,
		LastRTT:              10 * time.Millisecond,
		SelectedCandidate:    "198.51.100.10:5000",
		RemoteEndpointKey:    "198.51.100.10:5000|203.0.113.10:6000",
		TransportPacketCount: 1,
	}
	agent.directAttempts[connectionKey("net-1", "peer-local-new", "peer-remote-new")] = DirectAttemptState{
		DirectReady:          true,
		TransportMode:        "DIRECT",
		TransportSessionID:   "sess-new",
		TransportStartedAt:   time.Unix(200, 0),
		LastTransportAt:      now.Add(-10 * time.Second),
		LastKeepaliveAt:      now.Add(-10 * time.Second),
		AverageRTT:           20 * time.Millisecond,
		LastRTT:              20 * time.Millisecond,
		SelectedCandidate:    "198.51.100.10:5000",
		RemoteEndpointKey:    "198.51.100.10:5000",
		TransportPacketCount: 1,
	}

	if err := agent.maintainTransportQualityLocked(now); err != nil {
		t.Fatalf("maintain transport quality: %v", err)
	}
	if len(directManager.exchanges) != 1 {
		t.Fatalf("expected only the active endpoint-continuity replacement session to receive keepalive maintenance, got %#v", directManager.exchanges)
	}
	if !strings.Contains(directManager.exchanges[0], "peer-local-new|peer-remote-new|ole-keepalive") {
		t.Fatalf("expected keepalive maintenance to follow endpoint-continuity replacement during local-peer metadata gap, got %#v", directManager.exchanges)
	}
	if agent.connections[0].LastKeepaliveUnix != 0 || agent.connections[0].LastRTTMillis != 10 {
		t.Fatalf("expected stale endpoint-continuity connection metrics to stay untouched, got %#v", agent.connections[0])
	}
}

func TestNegotiateDirectConnectionsDropsSupersededLocalPeerSessionDuringSameDeviceOverlap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || !strings.HasPrefix(r.URL.Path, "/api/v1/peers/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"peer-local-new"}}`))
	}))
	defer server.Close()

	directManager := &lifecycleDirectManager{}
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New(server.URL),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\transport-negotiate-local-peer-overlap-state.json"),
		RuntimeConfig{
			LifecycleInterval:   time.Hour,
			HeartbeatInterval:   time.Hour,
			PeerDiscoveryPeriod: time.Hour,
			STUNProbePeriod:     time.Hour,
			TransportKeepalive:  time.Hour,
		},
		nil,
		directManager,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.adapterManager = nil
	agent.overlayDNS = nil
	agent.relayManager = nil
	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:5000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local-old",
			RemotePeerID:             "peer-remote-old",
			RemoteUserID:             "user-remote",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-old",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 100,
			LastTransportUnix:        150,
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local-new",
			RemotePeerID:             "peer-remote-new",
			RemoteUserID:             "user-remote",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-new",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
	}
	agent.directAttempts[connectionKey("net-1", "peer-local-old", "peer-remote-old")] = DirectAttemptState{
		DirectReady:          true,
		TransportMode:        "DIRECT",
		TransportSessionID:   "sess-old",
		TransportStartedAt:   time.Unix(100, 0),
		LastTransportAt:      time.Unix(150, 0),
		LastKeepaliveAt:      time.Unix(150, 0),
		AverageRTT:           10 * time.Millisecond,
		LastRTT:              10 * time.Millisecond,
		SelectedCandidate:    "198.51.100.10:5000",
		RemoteEndpointKey:    "198.51.100.10:5000",
		TransportPacketCount: 1,
	}
	agent.directAttempts[connectionKey("net-1", "peer-local-new", "peer-remote-new")] = DirectAttemptState{
		DirectReady:          true,
		TransportMode:        "DIRECT",
		TransportSessionID:   "sess-new",
		TransportStartedAt:   time.Unix(200, 0),
		LastTransportAt:      time.Unix(250, 0),
		LastKeepaliveAt:      time.Unix(250, 0),
		AverageRTT:           10 * time.Millisecond,
		LastRTT:              10 * time.Millisecond,
		SelectedCandidate:    "198.51.100.11:5001",
		RemoteEndpointKey:    "198.51.100.11:5001",
		TransportPacketCount: 1,
	}

	if err := agent.negotiateDirectConnectionsLocked(time.Unix(500, 0)); err != nil {
		t.Fatalf("negotiate direct connections: %v", err)
	}
	if len(directManager.drops) != 1 || directManager.drops[0] != "peer-local-old|peer-remote-old" {
		t.Fatalf("expected stale local-peer session to be dropped, got %#v", directManager.drops)
	}
	if _, ok := agent.directAttempts[connectionKey("net-1", "peer-local-old", "peer-remote-old")]; ok {
		t.Fatalf("expected stale local-peer attempt to be removed, got %#v", agent.directAttempts)
	}
	replacement := agent.directAttempts[connectionKey("net-1", "peer-local-new", "peer-remote-new")]
	if !replacement.DirectReady || replacement.TransportSessionID != "sess-new" {
		t.Fatalf("expected active local-peer attempt to stay active, got %#v", replacement)
	}
	if agent.connections[0].TransportReady || agent.connections[0].TransportSessionID != "" {
		t.Fatalf("expected stale local-peer connection transport state to clear after overlap cleanup, got %#v", agent.connections[0])
	}
	if !strings.Contains(agent.connections[0].LastError, "superseded by replacement transport") {
		t.Fatalf("expected stale local-peer connection to record overlap cleanup reason, got %#v", agent.connections[0])
	}
}

func TestNegotiateDirectConnectionsDropsSupersededLocalPeerSessionDuringMetadataGapOverlap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || !strings.HasPrefix(r.URL.Path, "/api/v1/peers/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"peer-local-new"}}`))
	}))
	defer server.Close()

	directManager := &lifecycleDirectManager{}
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New(server.URL),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\transport-negotiate-local-peer-overlap-metadata-gap-state.json"),
		RuntimeConfig{
			LifecycleInterval:   time.Hour,
			HeartbeatInterval:   time.Hour,
			PeerDiscoveryPeriod: time.Hour,
			STUNProbePeriod:     time.Hour,
			TransportKeepalive:  time.Hour,
		},
		nil,
		directManager,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.adapterManager = nil
	agent.overlayDNS = nil
	agent.relayManager = nil
	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:5000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local-old",
			RemotePeerID:             "peer-remote-old",
			RemoteUserID:             "user-remote",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-old",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 100,
			LastTransportUnix:        150,
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local-new",
			RemotePeerID:             "peer-remote-new",
			RemoteUserID:             "user-remote",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-new",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
	}
	agent.directAttempts[connectionKey("net-1", "peer-local-old", "peer-remote-old")] = DirectAttemptState{
		DirectReady:          true,
		TransportMode:        "DIRECT",
		TransportSessionID:   "sess-old",
		TransportStartedAt:   time.Unix(100, 0),
		LastTransportAt:      time.Unix(150, 0),
		LastKeepaliveAt:      time.Unix(150, 0),
		AverageRTT:           10 * time.Millisecond,
		LastRTT:              10 * time.Millisecond,
		SelectedCandidate:    "198.51.100.10:5000",
		RemoteEndpointKey:    "198.51.100.10:5000",
		TransportPacketCount: 1,
	}
	agent.directAttempts[connectionKey("net-1", "peer-local-new", "peer-remote-new")] = DirectAttemptState{
		DirectReady:          true,
		TransportMode:        "DIRECT",
		TransportSessionID:   "sess-new",
		TransportStartedAt:   time.Unix(200, 0),
		LastTransportAt:      time.Unix(250, 0),
		LastKeepaliveAt:      time.Unix(250, 0),
		AverageRTT:           10 * time.Millisecond,
		LastRTT:              10 * time.Millisecond,
		SelectedCandidate:    "198.51.100.11:5001",
		RemoteEndpointKey:    "198.51.100.11:5001",
		TransportPacketCount: 1,
	}

	if err := agent.negotiateDirectConnectionsLocked(time.Unix(500, 0)); err != nil {
		t.Fatalf("negotiate direct connections: %v", err)
	}
	if len(directManager.drops) != 1 || directManager.drops[0] != "peer-local-old|peer-remote-old" {
		t.Fatalf("expected stale local-peer session to be dropped during metadata gap overlap, got %#v", directManager.drops)
	}
	if _, ok := agent.directAttempts[connectionKey("net-1", "peer-local-old", "peer-remote-old")]; ok {
		t.Fatalf("expected stale local-peer attempt to be removed during metadata gap overlap, got %#v", agent.directAttempts)
	}
	replacement := agent.directAttempts[connectionKey("net-1", "peer-local-new", "peer-remote-new")]
	if !replacement.DirectReady || replacement.TransportSessionID != "sess-new" {
		t.Fatalf("expected active local-peer attempt to stay active during metadata gap overlap, got %#v", replacement)
	}
	if agent.connections[0].TransportReady || agent.connections[0].TransportSessionID != "" {
		t.Fatalf("expected stale local-peer connection transport state to clear after metadata gap overlap cleanup, got %#v", agent.connections[0])
	}
	if !strings.Contains(agent.connections[0].LastError, "superseded by replacement transport") {
		t.Fatalf("expected stale local-peer connection to record metadata gap overlap cleanup reason, got %#v", agent.connections[0])
	}
}

func TestHandleManagedPeerRoamingDoesNotRecreateSupersededReplacementAttempt(t *testing.T) {
	directManager := &lifecycleDirectManager{}
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New("http://example.invalid"),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\transport-roam-replacement-state.json"),
		RuntimeConfig{
			LifecycleInterval:   time.Hour,
			HeartbeatInterval:   time.Hour,
			PeerDiscoveryPeriod: time.Hour,
			STUNProbePeriod:     time.Hour,
			TransportKeepalive:  time.Hour,
		},
		nil,
		directManager,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	managedPeer := managedPeerByNetwork(agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID), "net-1")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local",
			RemotePeerID:             "peer-remote-old",
			RemoteUserID:             "user-remote",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-old",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 100,
			LastTransportUnix:        150,
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local",
			RemotePeerID:             "peer-remote-new",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			TransportSessionID:       "sess-new",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
	}
	replacementKey := connectionKey("net-1", "peer-local", "peer-remote-new")
	agent.directAttempts[replacementKey] = DirectAttemptState{
		DirectReady:        true,
		TransportMode:      "DIRECT",
		TransportSessionID: "sess-new",
		LocalEndpoint:      "127.0.0.1:4000",
		RemoteEndpointKey:  "198.51.100.11:5001",
		TransportStartedAt: time.Unix(200, 0),
		LastTransportAt:    time.Unix(250, 0),
		LastKeepaliveAt:    time.Unix(250, 0),
		AverageRTT:         10 * time.Millisecond,
		LastRTT:            10 * time.Millisecond,
	}

	if err := agent.handleManagedPeerRoamingLocked(managedPeer, "127.0.0.1:5000", time.Unix(500, 0)); err != nil {
		t.Fatalf("handle managed peer roaming: %v", err)
	}

	staleKey := connectionKey("net-1", "peer-local", "peer-remote-old")
	if _, ok := agent.directAttempts[staleKey]; ok {
		t.Fatalf("expected stale replacement attempt to stay absent after roam reset, got %#v", agent.directAttempts)
	}
	replacement := agent.directAttempts[replacementKey]
	if !strings.EqualFold(replacement.LocalEndpoint, "127.0.0.1:5000") {
		t.Fatalf("expected active replacement attempt to rebind onto new local endpoint, got %#v", replacement)
	}
	if !strings.Contains(replacement.LastError, "local endpoint changed") {
		t.Fatalf("expected active replacement attempt to record roam reset reason, got %#v", replacement)
	}
}
