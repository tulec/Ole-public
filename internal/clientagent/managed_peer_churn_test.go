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

type recordingDirectManager struct {
	probedPeerIDs []string
	inbound       map[string][]directprobe.Packet
}

func (m *recordingDirectManager) Reconcile(_ []directprobe.Binding) error {
	return nil
}

func (m *recordingDirectManager) Attempt(_, _ string, _ []string, _ time.Duration) (directprobe.Result, error) {
	return directprobe.Result{}, nil
}

func (m *recordingDirectManager) Establish(_, _ string, _ []string, _ time.Duration) (directprobe.Session, error) {
	return directprobe.Session{}, nil
}

func (m *recordingDirectManager) Exchange(_, _ string, _ []byte, _ time.Duration) ([]byte, error) {
	return nil, nil
}

func (m *recordingDirectManager) SetExchangeHandler(_ string, _ directprobe.ExchangeHandler) error {
	return nil
}

func (m *recordingDirectManager) SendPacket(_, _ string, _ []byte) error {
	return nil
}

func (m *recordingDirectManager) DrainInbound(localPeerID string, limit int) []directprobe.Packet {
	packets := m.inbound[localPeerID]
	if limit <= 0 || limit > len(packets) {
		limit = len(packets)
	}
	if limit == 0 {
		return nil
	}
	out := append([]directprobe.Packet(nil), packets[:limit]...)
	m.inbound[localPeerID] = append([]directprobe.Packet(nil), packets[limit:]...)
	return out
}

func (m *recordingDirectManager) DropSession(_, _ string) {}

func (m *recordingDirectManager) Close() error {
	return nil
}

func (m *recordingDirectManager) ProbeSTUN(localPeerID, _ string, _ time.Duration) (stun.ProbeResult, error) {
	m.probedPeerIDs = append(m.probedPeerIDs, localPeerID)
	return stun.ProbeResult{
		NATType:       stun.NATTypeNAT,
		MappedAddress: "203.0.113.20:50000",
	}, nil
}

func (m *recordingDirectManager) InjectInbound(localPeerID string, packet directprobe.Packet) {
	if m.inbound == nil {
		m.inbound = map[string][]directprobe.Packet{}
	}
	m.inbound[localPeerID] = append(m.inbound[localPeerID], packet)
}

func TestRefreshSTUNDedupesReplacementManagedPeer(t *testing.T) {
	directManager := &recordingDirectManager{}
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New("http://example.invalid"),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\managed-peer-stun-state.json"),
		RuntimeConfig{STUNServerAddress: "stun.example.invalid:3478"},
		nil,
		directManager,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-1", Email: "owner@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-old", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{{
		NetworkID:    "net-1",
		LocalPeerID:  "peer-local-new",
		RemotePeerID: "peer-remote",
		State:        "CONNECTED",
	}}

	if err := agent.refreshSTUNLocked(time.Now()); err != nil {
		t.Fatalf("refresh stun: %v", err)
	}
	if len(directManager.probedPeerIDs) != 1 || directManager.probedPeerIDs[0] != "peer-local-new" {
		t.Fatalf("expected stun refresh to probe replacement managed peer, got %#v", directManager.probedPeerIDs)
	}
	if agent.localSTUNEndpoint != "127.0.0.1:4001" {
		t.Fatalf("expected stun refresh to keep replacement endpoint, got %q", agent.localSTUNEndpoint)
	}
	if agent.publicEndpoint != "203.0.113.20:50000" {
		t.Fatalf("expected stun refresh to store mapped endpoint, got %q", agent.publicEndpoint)
	}
}

func TestRefreshSTUNPrefersFresherEqualQualityReplacementManagedPeer(t *testing.T) {
	directManager := &recordingDirectManager{}
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New("http://example.invalid"),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\managed-peer-stun-freshness-state.json"),
		RuntimeConfig{STUNServerAddress: "stun.example.invalid:3478"},
		nil,
		directManager,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-1", Email: "owner@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-old", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local-old",
			RemotePeerID:             "peer-remote-old",
			RemoteUserID:             "user-remote",
			State:                    "CONNECTED",
			TransportReady:           true,
			TransportMode:            "DIRECT",
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
			State:                    "CONNECTED",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			Reachability:             "DIRECT",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
	}

	if err := agent.refreshSTUNLocked(time.Now()); err != nil {
		t.Fatalf("refresh stun: %v", err)
	}
	if len(directManager.probedPeerIDs) != 1 || directManager.probedPeerIDs[0] != "peer-local-new" {
		t.Fatalf("expected stun refresh to prefer fresher equal-quality replacement peer, got %#v", directManager.probedPeerIDs)
	}
	if agent.localSTUNEndpoint != "127.0.0.1:4001" {
		t.Fatalf("expected stun refresh to keep fresher replacement endpoint, got %q", agent.localSTUNEndpoint)
	}
}

func TestNegotiateDirectConnectionsPersistsReplacementManagedPeerEndpointReset(t *testing.T) {
	signaledPeerIDs := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || !strings.HasPrefix(r.URL.Path, "/api/v1/peers/") {
			http.NotFound(w, r)
			return
		}
		peerID := strings.TrimPrefix(r.URL.Path, "/api/v1/peers/")
		signaledPeerIDs = append(signaledPeerIDs, peerID)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"` + peerID + `"}}`))
	}))
	defer server.Close()

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(
		controlclient.New(server.URL),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\managed-peer-negotiate-state.json"),
		RuntimeConfig{DirectMaxAttempts: 1},
		nil,
		nil,
		nil,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.directManager = nil
	agent.relayManager = nil
	agent.adapterManager = nil
	agent.overlayDNS = nil
	agent.currentUser = &controlclient.User{ID: "user-1", Email: "owner@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-old", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{{
		NetworkID:          "net-1",
		LocalPeerID:        "peer-local-new",
		RemotePeerID:       "peer-remote",
		RemoteEndpoint:     "198.51.100.10:5000",
		Reachability:       "DIRECT",
		State:              "CONNECTED",
		TransportReady:     true,
		TransportMode:      "DIRECT",
		TransportSessionID: "sess-direct",
	}}
	key := connectionKey("net-1", "peer-local-new", "peer-remote")
	agent.directAttempts[key] = DirectAttemptState{
		DirectReady:        true,
		TransportMode:      "DIRECT",
		TransportSessionID: "sess-direct",
		LocalEndpoint:      "127.0.0.1:4000",
		RemoteEndpointKey:  "198.51.100.10:5000",
	}

	if err := agent.negotiateDirectConnectionsLocked(time.Now()); err != nil {
		t.Fatalf("negotiate direct connections: %v", err)
	}

	attempt := agent.directAttempts[key]
	if attempt.LocalEndpoint != "127.0.0.1:4001" {
		t.Fatalf("expected direct-attempt local endpoint to move to replacement peer, got %#v", attempt)
	}
	if attempt.DirectReady || attempt.TransportMode != "" || attempt.TransportSessionID != "" {
		t.Fatalf("expected replacement endpoint change to reset direct attempt state, got %#v", attempt)
	}
	if !strings.Contains(attempt.LastError, "local endpoint changed") {
		t.Fatalf("expected replacement endpoint change error to be preserved, got %#v", attempt)
	}
	if len(signaledPeerIDs) != 1 || signaledPeerIDs[0] != "peer-local-new" {
		t.Fatalf("expected signaling update only for replacement managed peer, got %#v", signaledPeerIDs)
	}
	if agent.connections[0].TransportSessionID != "" || agent.connections[0].TransportReady {
		t.Fatalf("expected live connection to reflect reset transport state, got %#v", agent.connections[0])
	}
}

func TestCollectInboundTransportPacketsAcceptsSupersededLocalPeerPacketViaActiveReplacement(t *testing.T) {
	directManager := &recordingDirectManager{}
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New("http://example.invalid"),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\managed-peer-inbound-overlap-state.json"),
		RuntimeConfig{},
		nil,
		directManager,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	now := time.Unix(500, 0)
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
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    90,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-remote-new",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 10,
			LastRTTMillis:    12,
		},
	}

	packet := buildIPv4PacketForChurnTest(t, "10.10.0.3", "10.10.0.2", []byte{1, 2, 3, 4})
	directManager.InjectInbound("peer-local-old", directprobe.Packet{
		RemotePeerID:   "peer-remote-old",
		Payload:        packet,
		ReceivedAtUnix: now.Unix(),
	})

	managedPeers := agent.dedupeManagedPeersForRuntime(agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID))
	managedPeer := managedPeerByNetwork(managedPeers, "net-1")
	drainLocalPeerIDs := agent.inboundDrainLocalPeerIDsForManagedPeerLocked(managedPeer)
	if len(drainLocalPeerIDs) != 2 || drainLocalPeerIDs[0] != "peer-local-new" || drainLocalPeerIDs[1] != "peer-local-old" {
		t.Fatalf("expected inbound drain to include active and superseded local peers, got %#v", drainLocalPeerIDs)
	}
	if connection := agent.inboundTransportConnectionLocked(managedPeer, "peer-local-old", "peer-remote-old"); connection == nil || connection.LocalPeerID != "peer-local-new" || connection.RemotePeerID != "peer-remote-new" {
		t.Fatalf("expected stale local inbound packet to map onto active replacement connection, got %#v", connection)
	}
	networksByID := map[string]controlclient.Network{
		"net-1": {
			ID: "net-1",
			MemberRoles: map[string]string{
				"user-1":      "MEMBER",
				"user-remote": "MEMBER",
			},
		},
	}

	inbound := agent.collectInboundTransportPacketsLocked(nil, managedPeer, managedPeers, networksByID, now)
	if len(inbound) != 1 || !strings.EqualFold(string(inbound[0].Data), string(packet)) {
		t.Fatalf("expected superseded local-peer inbound packet to survive handoff via active replacement, got %#v", inbound)
	}
	if agent.connections[1].LastTransportUnix != now.Unix() {
		t.Fatalf("expected active replacement connection to absorb inbound packet metrics, got %#v", agent.connections[1])
	}
	if agent.connections[0].LastTransportUnix != 0 {
		t.Fatalf("expected stale local-peer connection metrics to stay untouched, got %#v", agent.connections[0])
	}
}

func TestCollectInboundTransportPacketsAcceptsSupersededLocalPeerPacketViaActiveReplacementAcrossVirtualIPMetadataGap(t *testing.T) {
	directManager := &recordingDirectManager{}
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New("http://example.invalid"),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\managed-peer-inbound-overlap-metadata-gap-state.json"),
		RuntimeConfig{},
		nil,
		directManager,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	now := time.Unix(500, 0)
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
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    90,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-remote-new",
			RemoteUserID:     "user-remote",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 10,
			LastRTTMillis:    12,
		},
	}

	packet := buildIPv4PacketForChurnTest(t, "10.10.0.3", "10.10.0.2", []byte{1, 2, 3, 4})
	directManager.InjectInbound("peer-local-old", directprobe.Packet{
		RemotePeerID:   "peer-remote-old",
		Payload:        packet,
		ReceivedAtUnix: now.Unix(),
	})

	managedPeers := agent.dedupeManagedPeersForRuntime(agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID))
	managedPeer := managedPeerByNetwork(managedPeers, "net-1")
	if connection := agent.inboundTransportConnectionLocked(managedPeer, "peer-local-old", "peer-remote-old"); connection == nil || connection.LocalPeerID != "peer-local-new" || connection.RemotePeerID != "peer-remote-new" {
		t.Fatalf("expected stale local inbound packet to map onto active replacement connection across metadata gap, got %#v", connection)
	}
	networksByID := map[string]controlclient.Network{
		"net-1": {
			ID: "net-1",
			MemberRoles: map[string]string{
				"user-1":      "MEMBER",
				"user-remote": "MEMBER",
			},
		},
	}

	inbound := agent.collectInboundTransportPacketsLocked(nil, managedPeer, managedPeers, networksByID, now)
	if len(inbound) != 1 || !strings.EqualFold(string(inbound[0].Data), string(packet)) {
		t.Fatalf("expected superseded local-peer inbound packet to survive handoff via active replacement across metadata gap, got %#v", inbound)
	}
	if agent.connections[1].LastTransportUnix != now.Unix() {
		t.Fatalf("expected active replacement connection to absorb inbound packet metrics across metadata gap, got %#v", agent.connections[1])
	}
	if agent.connections[0].LastTransportUnix != 0 {
		t.Fatalf("expected stale local-peer connection metrics to stay untouched across metadata gap, got %#v", agent.connections[0])
	}
}

func TestCollectInboundFloodPacketAcceptsSupersededLocalPeerViaActiveReplacementAcrossVirtualIPMetadataGap(t *testing.T) {
	directManager := &recordingDirectManager{}
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New("http://example.invalid"),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\managed-peer-inbound-flood-overlap-metadata-gap-state.json"),
		RuntimeConfig{},
		nil,
		directManager,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	now := time.Unix(500, 0)
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
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    90,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-remote-new",
			RemoteUserID:     "user-remote",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 10,
			LastRTTMillis:    12,
		},
	}

	packet := buildIPv4PacketForChurnTest(t, "10.10.0.3", "10.10.0.255", []byte{5, 6, 7, 8})
	directManager.InjectInbound("peer-local-old", directprobe.Packet{
		RemotePeerID:   "peer-remote-old",
		Payload:        packet,
		ReceivedAtUnix: now.Unix(),
	})

	managedPeers := agent.dedupeManagedPeersForRuntime(agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID))
	managedPeer := managedPeerByNetwork(managedPeers, "net-1")
	networksByID := map[string]controlclient.Network{
		"net-1": {
			ID:                 "net-1",
			GroupTrafficPolicy: "FLOOD",
			MemberRoles: map[string]string{
				"user-1":      "MEMBER",
				"user-remote": "MEMBER",
			},
		},
	}

	inbound := agent.collectInboundTransportPacketsLocked(nil, managedPeer, managedPeers, networksByID, now)
	if len(inbound) != 1 || !strings.EqualFold(string(inbound[0].Data), string(packet)) {
		t.Fatalf("expected superseded local-peer inbound flood packet to survive handoff via active replacement across metadata gap, got %#v", inbound)
	}
	if agent.connections[1].LastTransportUnix != now.Unix() {
		t.Fatalf("expected active replacement connection to absorb inbound flood metrics across metadata gap, got %#v", agent.connections[1])
	}
	if agent.connections[0].LastTransportUnix != 0 {
		t.Fatalf("expected stale local-peer flood metrics to stay untouched across metadata gap, got %#v", agent.connections[0])
	}
}

func TestCollectInboundGatewayReturnPacketAcceptsSupersededLocalPeerViaActiveReplacementAcrossVirtualIPMetadataGap(t *testing.T) {
	directManager := &recordingDirectManager{}
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New("http://example.invalid"),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\managed-peer-inbound-gateway-overlap-gap-state.json"),
		RuntimeConfig{},
		nil,
		directManager,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	now := time.Unix(500, 0)
	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
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
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-gateway-old",
			RemoteUserID:     "user-owner",
			RemoteVirtualIP:  "10.10.0.1",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    90,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-gateway-new",
			RemoteUserID:     "user-owner",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 10,
			LastRTTMillis:    12,
		},
	}

	packet := buildIPv4PacketForChurnTest(t, "8.8.8.8", "10.10.0.2", []byte{1, 2, 3, 4})
	directManager.InjectInbound("peer-local-old", directprobe.Packet{
		RemotePeerID:   "peer-gateway-old",
		Payload:        packet,
		ReceivedAtUnix: now.Unix(),
	})

	managedPeers := agent.dedupeManagedPeersForRuntime(agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID))
	managedPeer := managedPeerByNetwork(managedPeers, "net-1")
	if connection := agent.inboundTransportConnectionLocked(managedPeer, "peer-local-old", "peer-gateway-old"); connection == nil || connection.LocalPeerID != "peer-local-new" || connection.RemotePeerID != "peer-gateway-new" {
		t.Fatalf("expected stale local full-gateway return packet to map onto active replacement connection across metadata gap, got %#v", connection)
	}
	networksByID := map[string]controlclient.Network{
		"net-1": {
			ID:            "net-1",
			OwnerID:       "user-owner",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
			},
		},
	}

	inbound := agent.collectInboundTransportPacketsLocked(nil, managedPeer, managedPeers, networksByID, now)
	if len(inbound) != 1 || !strings.EqualFold(string(inbound[0].Data), string(packet)) {
		t.Fatalf("expected superseded local full-gateway return packet to survive handoff via active replacement across metadata gap, got %#v", inbound)
	}
	if agent.connections[1].LastTransportUnix != now.Unix() {
		t.Fatalf("expected active replacement gateway connection to absorb inbound packet metrics, got %#v", agent.connections[1])
	}
	if agent.connections[0].LastTransportUnix != 0 {
		t.Fatalf("expected stale local gateway connection metrics to stay untouched, got %#v", agent.connections[0])
	}
}

func TestCollectInboundGatewayReturnPacketUsesEndpointContinuityForActiveReplacementDuringMetadataGap(t *testing.T) {
	directManager := &recordingDirectManager{}
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New("http://example.invalid"),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\managed-peer-inbound-gateway-endpoint-gap-state.json"),
		RuntimeConfig{},
		nil,
		directManager,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	now := time.Unix(500, 0)
	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
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
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-1": {
			NetworkID:          "net-1",
			GatewayRole:        "CLIENT",
			GatewayPeerID:      "peer-gateway-old",
			GatewayUserID:      "user-owner",
			GatewayVirtualIP:   "10.10.0.1",
			GatewayEndpointKey: normalizedEndpointContinuityKey("198.51.100.10:5000", []string{"198.51.100.10:5000", "203.0.113.10:6000"}),
			GatewayTargetRole:  "OWNER",
			PolicyStatus:       "ACTIVE",
			Path:               "RELAY",
		},
	}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-gateway-old",
			RemoteUserID:     "user-owner",
			RemoteVirtualIP:  "10.10.0.1",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    90,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-gateway-new",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000"},
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 10,
			LastRTTMillis:    12,
		},
	}

	packet := buildIPv4PacketForChurnTest(t, "8.8.8.8", "10.10.0.2", []byte{1, 2, 3, 4})
	directManager.InjectInbound("peer-local-old", directprobe.Packet{
		RemotePeerID:   "peer-gateway-old",
		Payload:        packet,
		ReceivedAtUnix: now.Unix(),
	})

	managedPeers := agent.dedupeManagedPeersForRuntime(agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID))
	managedPeer := managedPeerByNetwork(managedPeers, "net-1")
	if connection := agent.inboundTransportConnectionLocked(managedPeer, "peer-local-old", "peer-gateway-old"); connection == nil || connection.LocalPeerID != "peer-local-new" || connection.RemotePeerID != "peer-gateway-new" {
		t.Fatalf("expected stale local full-gateway return packet to map onto endpoint-continuity replacement connection, got %#v", connection)
	}
	networksByID := map[string]controlclient.Network{
		"net-1": {
			ID:            "net-1",
			OwnerID:       "user-owner",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
			},
		},
	}

	inbound := agent.collectInboundTransportPacketsLocked(nil, managedPeer, managedPeers, networksByID, now)
	if len(inbound) != 1 || !strings.EqualFold(string(inbound[0].Data), string(packet)) {
		t.Fatalf("expected endpoint-continuity full-gateway return packet to survive handoff, got %#v", inbound)
	}
	if agent.connections[1].LastTransportUnix != now.Unix() {
		t.Fatalf("expected active endpoint-continuity replacement gateway connection to absorb inbound packet metrics, got %#v", agent.connections[1])
	}
	if agent.connections[0].LastTransportUnix != 0 {
		t.Fatalf("expected stale endpoint-continuity gateway connection metrics to stay untouched, got %#v", agent.connections[0])
	}
}

func TestCollectInboundTransportPacketsRejectsSupersededLocalPeerPacketWithoutActiveReplacement(t *testing.T) {
	directManager := &recordingDirectManager{}
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(
		controlclient.New("http://example.invalid"),
		"127.0.0.1:0",
		NewStateStore(t.TempDir()+"\\managed-peer-inbound-stale-only-state.json"),
		RuntimeConfig{},
		nil,
		directManager,
	)
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	now := time.Unix(500, 0)
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
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    90,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-remote-other",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.4",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 10,
			LastRTTMillis:    12,
		},
	}

	packet := buildIPv4PacketForChurnTest(t, "10.10.0.3", "10.10.0.2", []byte{9, 8, 7, 6})
	directManager.InjectInbound("peer-local-old", directprobe.Packet{
		RemotePeerID:   "peer-remote-old",
		Payload:        packet,
		ReceivedAtUnix: now.Unix(),
	})

	managedPeers := agent.dedupeManagedPeersForRuntime(agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID))
	managedPeer := managedPeerByNetwork(managedPeers, "net-1")
	networksByID := map[string]controlclient.Network{
		"net-1": {
			ID: "net-1",
			MemberRoles: map[string]string{
				"user-1":      "MEMBER",
				"user-remote": "MEMBER",
			},
		},
	}

	inbound := agent.collectInboundTransportPacketsLocked(nil, managedPeer, managedPeers, networksByID, now)
	if len(inbound) != 0 {
		t.Fatalf("expected stale-only superseded local-peer inbound packet to fail closed, got %#v", inbound)
	}
	if agent.connections[0].LastTransportUnix != 0 {
		t.Fatalf("expected stale-only local-peer metrics to stay untouched, got %#v", agent.connections[0])
	}
}
