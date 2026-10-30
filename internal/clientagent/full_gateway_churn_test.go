package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/virtualadapter"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFullTunnelGatewaySelectionSurvivesMissingDiscoveryPeerRecord(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\agent-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.discoveredPeers["net-full"] = nil
	agent.connections = []ConnectionStatus{{
		NetworkID:        "net-full",
		LocalPeerID:      "peer-local",
		RemotePeerID:     "peer-owner",
		RemoteUserID:     "user-owner",
		TransportReady:   true,
		TransportMode:    "DIRECT",
		Reachability:     "DIRECT",
		State:            "CONNECTED",
		AverageRTTMillis: 12,
		LastRTTMillis:    10,
	}}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-member": "MEMBER",
		},
	}
	networksByID := map[string]controlclient.Network{
		"net-full": network,
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	localPeer := managedPeerByNetwork(managedPeers, "net-full")

	gateway := agent.gatewayConnectionForNetworkLocked(network, localPeer.PeerID)
	if gateway == nil || gateway.RemotePeerID != "peer-owner" {
		t.Fatalf("expected full-tunnel gateway selection to use live connection user metadata, got %#v", gateway)
	}

	primary := agent.primaryFullTunnelClientNetworkLocked(managedPeers, networksByID)
	if primary != "net-full" {
		t.Fatalf("expected live owner gateway to keep full-tunnel network active, got %q", primary)
	}

	config, err := agent.adapterConfigForManagedPeerLocked(localPeer, network, primary)
	if err != nil {
		t.Fatalf("build full-tunnel adapter config with missing discovery peer record: %v", err)
	}
	if config.GatewayRole != "CLIENT" || config.GatewayPeerID != "peer-owner" || config.RoutePrefix != "0.0.0.0/0" {
		t.Fatalf("expected full-tunnel adapter config to stay bound to live owner gateway, got %#v", config)
	}

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, primary, "10.10.0.2", "8.8.8.8")
	if len(routed) != 1 || routed[0].RemotePeerID != "peer-owner" {
		t.Fatalf("expected internet packet to keep routing through live owner gateway, got %#v", routed)
	}
}

func TestFullTunnelGatewaySelectionSurvivesReplacementPeerWithMissingGatewayMetadata(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-metadata-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:         "net-full",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-owner-old",
			GatewayUserID:     "user-owner",
			GatewayVirtualIP:  "10.10.0.3",
			GatewayTargetRole: "OWNER",
			Path:              "DIRECT",
			PolicyStatus:      "ACTIVE",
		},
	}
	agent.connections = []ConnectionStatus{{
		NetworkID:        "net-full",
		LocalPeerID:      "peer-local",
		RemotePeerID:     "peer-owner-new",
		RemoteVirtualIP:  "10.10.0.3",
		TransportReady:   true,
		TransportMode:    "DIRECT",
		Reachability:     "DIRECT",
		State:            "CONNECTED",
		AverageRTTMillis: 12,
		LastRTTMillis:    10,
	}}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-member": "MEMBER",
		},
	}
	networksByID := map[string]controlclient.Network{
		"net-full": network,
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	localPeer := managedPeerByNetwork(managedPeers, "net-full")

	gateway := agent.gatewayConnectionForNetworkLocked(network, localPeer.PeerID)
	if gateway == nil || gateway.RemotePeerID != "peer-owner-new" {
		t.Fatalf("expected full-tunnel gateway selection to keep the live replacement peer during a metadata gap, got %#v", gateway)
	}
	if role := agent.remotePeerGatewayRoleForConnectionLocked(network, gateway.RemotePeerID); role != "OWNER" {
		t.Fatalf("expected gateway role fallback to preserve owner eligibility for replacement peer, got %q", role)
	}

	primary := agent.primaryFullTunnelClientNetworkLocked(managedPeers, networksByID)
	if primary != "net-full" {
		t.Fatalf("expected active full-tunnel network to stay selected during replacement metadata gap, got %q", primary)
	}

	config, err := agent.adapterConfigForManagedPeerLocked(localPeer, network, primary)
	if err != nil {
		t.Fatalf("build full-tunnel adapter config with replacement metadata gap: %v", err)
	}
	if config.GatewayRole != "CLIENT" || config.GatewayPeerID != "peer-owner-new" || config.GatewayUserID != "user-owner" || config.GatewayVirtualIP != "10.10.0.3" || config.GatewayTargetRole != "OWNER" || config.RoutePrefix != "0.0.0.0/0" {
		t.Fatalf("expected full-tunnel adapter config to stay bound to replacement gateway during metadata gap, got %#v", config)
	}

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, primary, "10.10.0.2", "8.8.8.8")
	if len(routed) != 1 || routed[0].RemotePeerID != "peer-owner-new" {
		t.Fatalf("expected internet packet to keep routing through replacement gateway during metadata gap, got %#v", routed)
	}
}

func TestFullTunnelGatewaySelectionSurvivesReplacementPeerAfterOldGatewayDisappearsUsingStoredEndpointContinuity(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-endpoint-continuity-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	endpointKey := normalizedEndpointContinuityKey("198.51.100.10:5000", []string{"198.51.100.10:5000", "203.0.113.10:6000"})
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:          "net-full",
			GatewayRole:        "CLIENT",
			GatewayPeerID:      "peer-owner-old",
			GatewayUserID:      "user-owner",
			GatewayVirtualIP:   "10.10.0.3",
			GatewayEndpointKey: endpointKey,
			GatewayTargetRole:  "OWNER",
			Path:               "DIRECT",
			PolicyStatus:       "ACTIVE",
		},
	}
	agent.connections = []ConnectionStatus{{
		NetworkID:        "net-full",
		LocalPeerID:      "peer-local",
		RemotePeerID:     "peer-owner-new",
		RemoteEndpoint:   "198.51.100.10:5000",
		RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
		TransportReady:   true,
		TransportMode:    "RELAY",
		Reachability:     "RELAY",
		State:            "CONNECTED",
		AverageRTTMillis: 52,
		LastRTTMillis:    50,
	}}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-member": "MEMBER",
		},
	}
	networksByID := map[string]controlclient.Network{
		"net-full": network,
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	localPeer := managedPeerByNetwork(managedPeers, "net-full")

	gateway := agent.gatewayConnectionForNetworkLocked(network, localPeer.PeerID)
	if gateway == nil || gateway.RemotePeerID != "peer-owner-new" {
		t.Fatalf("expected full-tunnel gateway selection to keep the live replacement peer after the stale gateway disappeared, got %#v", gateway)
	}
	if role := agent.remotePeerGatewayRoleForConnectionLocked(network, gateway.RemotePeerID); role != "OWNER" {
		t.Fatalf("expected stored endpoint continuity to preserve owner eligibility for replacement peer after stale gateway disappearance, got %q", role)
	}

	primary := agent.primaryFullTunnelClientNetworkLocked(managedPeers, networksByID)
	if primary != "net-full" {
		t.Fatalf("expected active full-tunnel network to stay selected when only stored endpoint continuity still identifies the gateway target, got %q", primary)
	}

	config, err := agent.adapterConfigForManagedPeerLocked(localPeer, network, primary)
	if err != nil {
		t.Fatalf("build full-tunnel adapter config with stored endpoint continuity: %v", err)
	}
	if config.GatewayRole != "CLIENT" || config.GatewayPeerID != "peer-owner-new" || config.GatewayUserID != "user-owner" || config.GatewayVirtualIP != "10.10.0.3" || config.GatewayTargetRole != "OWNER" || config.RoutePrefix != "0.0.0.0/0" {
		t.Fatalf("expected full-tunnel adapter config to stay bound to replacement gateway after stale gateway disappearance, got %#v", config)
	}

	agent.observeGatewaySelectionsLocked([]virtualadapter.NetworkConfig{config})
	selection := agent.gatewaySelections["net-full"]
	if selection.GatewayPeerID != "peer-owner-new" || selection.GatewayUserID != "user-owner" || selection.GatewayVirtualIP != "10.10.0.3" || selection.GatewayEndpointKey != endpointKey || selection.Path != "RELAY" {
		t.Fatalf("expected stored gateway selection to rebind onto the replacement peer while preserving target metadata and endpoint continuity, got %#v", selection)
	}

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, primary, "10.10.0.2", "8.8.8.8")
	if len(routed) != 1 || routed[0].RemotePeerID != "peer-owner-new" {
		t.Fatalf("expected internet packet to keep routing through replacement gateway after stale gateway disappearance, got %#v", routed)
	}
}

func TestFullTunnelGatewaySelectionSurvivesReplacementPeerAfterOldGatewayDisappearsUsingPartialStoredEndpointContinuity(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-partial-endpoint-continuity-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	endpointKey := normalizedEndpointContinuityKey("198.51.100.10:5000", []string{"198.51.100.10:5000", "203.0.113.10:6000"})
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:          "net-full",
			GatewayRole:        "CLIENT",
			GatewayPeerID:      "peer-owner-old",
			GatewayUserID:      "user-owner",
			GatewayVirtualIP:   "10.10.0.3",
			GatewayEndpointKey: endpointKey,
			GatewayTargetRole:  "OWNER",
			Path:               "DIRECT",
			PolicyStatus:       "ACTIVE",
		},
	}
	agent.connections = []ConnectionStatus{{
		NetworkID:        "net-full",
		LocalPeerID:      "peer-local",
		RemotePeerID:     "peer-owner-new",
		RemoteEndpoint:   "198.51.100.10:5000",
		RemoteCandidates: []string{"198.51.100.10:5000"},
		TransportReady:   true,
		TransportMode:    "RELAY",
		Reachability:     "RELAY",
		State:            "CONNECTED",
		AverageRTTMillis: 52,
		LastRTTMillis:    50,
	}}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-member": "MEMBER",
		},
	}
	networksByID := map[string]controlclient.Network{
		"net-full": network,
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	localPeer := managedPeerByNetwork(managedPeers, "net-full")

	gateway := agent.gatewayConnectionForNetworkLocked(network, localPeer.PeerID)
	if gateway == nil || gateway.RemotePeerID != "peer-owner-new" {
		t.Fatalf("expected full-tunnel gateway selection to keep the live replacement peer after stale gateway disappearance with only partial endpoint continuity, got %#v", gateway)
	}
	if role := agent.remotePeerGatewayRoleForConnectionLocked(network, gateway.RemotePeerID); role != "OWNER" {
		t.Fatalf("expected partial stored endpoint continuity to preserve owner eligibility for replacement peer after stale gateway disappearance, got %q", role)
	}

	primary := agent.primaryFullTunnelClientNetworkLocked(managedPeers, networksByID)
	if primary != "net-full" {
		t.Fatalf("expected active full-tunnel network to stay selected when only partial stored endpoint continuity still identifies the gateway target, got %q", primary)
	}

	config, err := agent.adapterConfigForManagedPeerLocked(localPeer, network, primary)
	if err != nil {
		t.Fatalf("build full-tunnel adapter config with partial stored endpoint continuity: %v", err)
	}
	if config.GatewayRole != "CLIENT" || config.GatewayPeerID != "peer-owner-new" || config.GatewayUserID != "user-owner" || config.GatewayVirtualIP != "10.10.0.3" || config.GatewayTargetRole != "OWNER" || config.RoutePrefix != "0.0.0.0/0" {
		t.Fatalf("expected full-tunnel adapter config to stay bound to replacement gateway after stale gateway disappearance with partial continuity, got %#v", config)
	}

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, primary, "10.10.0.2", "8.8.8.8")
	if len(routed) != 1 || routed[0].RemotePeerID != "peer-owner-new" {
		t.Fatalf("expected internet packet to keep routing through replacement gateway after stale gateway disappearance with partial continuity, got %#v", routed)
	}
}

func TestFullTunnelGatewaySelectionPrefersDirectAdminOverRelayOwner(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-direct-admin-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-owner",
			RemoteUserID:     "user-owner",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 85,
			LastRTTMillis:    90,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-admin",
			RemoteUserID:     "user-admin",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
	}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-member": "MEMBER",
			"user-admin":  "ADMIN",
		},
	}
	networksByID := map[string]controlclient.Network{
		"net-full": network,
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	localPeer := managedPeerByNetwork(managedPeers, "net-full")

	gateway := agent.gatewayConnectionForNetworkLocked(network, localPeer.PeerID)
	if gateway == nil || gateway.RemotePeerID != "peer-admin" || gateway.TransportMode != "DIRECT" {
		t.Fatalf("expected direct admin gateway to outrank relay owner for full-tunnel exit routing, got %#v", gateway)
	}

	primary := agent.primaryFullTunnelClientNetworkLocked(managedPeers, networksByID)
	if primary != "net-full" {
		t.Fatalf("expected full-tunnel network with direct admin gateway to stay active, got %q", primary)
	}

	config, err := agent.adapterConfigForManagedPeerLocked(localPeer, network, primary)
	if err != nil {
		t.Fatalf("build full-tunnel adapter config with direct admin gateway: %v", err)
	}
	if config.GatewayPeerID != "peer-admin" || config.RoutePrefix != "0.0.0.0/0" {
		t.Fatalf("expected adapter config to bind default route to direct admin gateway, got %#v", config)
	}

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, primary, "10.10.0.2", "8.8.8.8")
	if len(routed) != 1 || routed[0].RemotePeerID != "peer-admin" {
		t.Fatalf("expected internet packet to use direct admin gateway over relay owner, got %#v", routed)
	}
}

func TestFullTunnelGatewaySelectionKeepsDirectOwnerOverMinorRTTDirectAdmin(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-direct-owner-rtt-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-owner",
			RemoteUserID:     "user-owner",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-admin",
			RemoteUserID:     "user-admin",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 9,
			LastRTTMillis:    8,
		},
	}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-member": "MEMBER",
			"user-admin":  "ADMIN",
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	localPeer := managedPeerByNetwork(managedPeers, "net-full")

	gateway := agent.gatewayConnectionForNetworkLocked(network, localPeer.PeerID)
	if gateway == nil || gateway.RemotePeerID != "peer-owner" {
		t.Fatalf("expected owner gateway to stay preferred over admin on minor RTT advantage, got %#v", gateway)
	}
}

func TestFullTunnelGatewaySelectionPrefersDirectAdminOverMateriallyDegradedDirectOwner(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-direct-admin-quality-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:         "net-full",
			LocalPeerID:       "peer-local",
			RemotePeerID:      "peer-owner",
			RemoteUserID:      "user-owner",
			TransportReady:    true,
			TransportMode:     "DIRECT",
			Reachability:      "DIRECT",
			State:             "CONNECTED",
			ConsecutiveLosses: 2,
			AverageRTTMillis:  46,
			LastRTTMillis:     44,
		},
		{
			NetworkID:         "net-full",
			LocalPeerID:       "peer-local",
			RemotePeerID:      "peer-admin",
			RemoteUserID:      "user-admin",
			TransportReady:    true,
			TransportMode:     "DIRECT",
			Reachability:      "DIRECT",
			State:             "CONNECTED",
			ConsecutiveLosses: 0,
			AverageRTTMillis:  8,
			LastRTTMillis:     7,
		},
	}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-member": "MEMBER",
			"user-admin":  "ADMIN",
		},
	}
	networksByID := map[string]controlclient.Network{
		"net-full": network,
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	localPeer := managedPeerByNetwork(managedPeers, "net-full")

	gateway := agent.gatewayConnectionForNetworkLocked(network, localPeer.PeerID)
	if gateway == nil || gateway.RemotePeerID != "peer-admin" || gateway.TransportMode != "DIRECT" {
		t.Fatalf("expected materially healthier direct admin gateway to outrank degraded direct owner, got %#v", gateway)
	}

	primary := agent.primaryFullTunnelClientNetworkLocked(managedPeers, networksByID)
	if primary != "net-full" {
		t.Fatalf("expected materially healthier admin-backed path to keep full-tunnel network active, got %q", primary)
	}

	config, err := agent.adapterConfigForManagedPeerLocked(localPeer, network, primary)
	if err != nil {
		t.Fatalf("build full-tunnel adapter config with materially healthier admin gateway: %v", err)
	}
	if config.GatewayPeerID != "peer-admin" || config.RoutePrefix != "0.0.0.0/0" {
		t.Fatalf("expected adapter config to bind default route to materially healthier admin gateway, got %#v", config)
	}
}

func TestFullTunnelGatewaySelectionKeepsCurrentAdminOnMinorRTTImprovement(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-admin-rtt-stickiness-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-admin-z",
			RemoteUserID:     "user-admin-z",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 10,
			LastRTTMillis:    10,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-admin-a",
			RemoteUserID:     "user-admin-a",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 8,
			LastRTTMillis:    8,
		},
	}
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:         "net-full",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-admin-z",
			GatewayUserID:     "user-admin-z",
			GatewayTargetRole: "ADMIN",
			Path:              "DIRECT",
			PolicyStatus:      "ACTIVE",
		},
	}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-member":  "MEMBER",
			"user-admin-z": "ADMIN",
			"user-admin-a": "ADMIN",
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	localPeer := managedPeerByNetwork(managedPeers, "net-full")

	gateway := agent.gatewayConnectionForNetworkLocked(network, localPeer.PeerID)
	if gateway == nil || gateway.RemotePeerID != "peer-admin-z" {
		t.Fatalf("expected current admin gateway to stay selected on minor RTT improvement, got %#v", gateway)
	}
}

func TestFullTunnelGatewaySelectionKeepsReplacementOfCurrentAdminOnMinorRTTImprovement(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-admin-replacement-rtt-stickiness-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:                "net-full",
			LocalPeerID:              "peer-local",
			RemotePeerID:             "peer-admin-z-new",
			RemoteUserID:             "user-admin-z",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			Reachability:             "DIRECT",
			State:                    "CONNECTED",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-admin-a",
			RemoteUserID:     "user-admin-a",
			RemoteVirtualIP:  "10.10.0.4",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 8,
			LastRTTMillis:    8,
		},
	}
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:         "net-full",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-admin-z-old",
			GatewayUserID:     "user-admin-z",
			GatewayVirtualIP:  "10.10.0.3",
			GatewayTargetRole: "ADMIN",
			Path:              "DIRECT",
			PolicyStatus:      "ACTIVE",
		},
	}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-member":  "MEMBER",
			"user-admin-z": "ADMIN",
			"user-admin-a": "ADMIN",
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	localPeer := managedPeerByNetwork(managedPeers, "net-full")

	gateway := agent.gatewayConnectionForNetworkLocked(network, localPeer.PeerID)
	if gateway == nil || gateway.RemotePeerID != "peer-admin-z-new" {
		t.Fatalf("expected replacement of current admin gateway to stay selected on minor RTT improvement, got %#v", gateway)
	}
}

func TestFullTunnelGatewaySelectionDoesNotTreatSameUserWithoutOverlayIPAsCurrentReplacement(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-admin-replacement-no-overlay-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-admin-z-old",
			RemoteUserID:     "user-admin-z",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 10,
			LastRTTMillis:    10,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-admin-z-new",
			RemoteUserID:     "user-admin-z",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 8,
			LastRTTMillis:    8,
		},
	}
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:         "net-full",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-admin-z-old",
			GatewayUserID:     "user-admin-z",
			GatewayTargetRole: "ADMIN",
			Path:              "DIRECT",
			PolicyStatus:      "ACTIVE",
		},
	}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-member":  "MEMBER",
			"user-admin-z": "ADMIN",
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	localPeer := managedPeerByNetwork(managedPeers, "net-full")

	gateway := agent.gatewayConnectionForNetworkLocked(network, localPeer.PeerID)
	if gateway == nil || gateway.RemotePeerID != "peer-admin-z-old" {
		t.Fatalf("expected current admin gateway to stay selected when same-user replacement lacks overlay IP continuity, got %#v", gateway)
	}
}

func TestFullTunnelGatewaySelectionKeepsCurrentAdminOnSingleLossDelta(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-admin-loss-stickiness-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:         "net-full",
			LocalPeerID:       "peer-local",
			RemotePeerID:      "peer-admin-z",
			RemoteUserID:      "user-admin-z",
			TransportReady:    true,
			TransportMode:     "DIRECT",
			Reachability:      "DIRECT",
			State:             "CONNECTED",
			ConsecutiveLosses: 1,
			AverageRTTMillis:  10,
			LastRTTMillis:     10,
		},
		{
			NetworkID:         "net-full",
			LocalPeerID:       "peer-local",
			RemotePeerID:      "peer-admin-a",
			RemoteUserID:      "user-admin-a",
			TransportReady:    true,
			TransportMode:     "DIRECT",
			Reachability:      "DIRECT",
			State:             "CONNECTED",
			ConsecutiveLosses: 0,
			AverageRTTMillis:  10,
			LastRTTMillis:     10,
		},
	}
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:         "net-full",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-admin-z",
			GatewayUserID:     "user-admin-z",
			GatewayTargetRole: "ADMIN",
			Path:              "DIRECT",
			PolicyStatus:      "ACTIVE",
		},
	}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-member":  "MEMBER",
			"user-admin-z": "ADMIN",
			"user-admin-a": "ADMIN",
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	localPeer := managedPeerByNetwork(managedPeers, "net-full")

	gateway := agent.gatewayConnectionForNetworkLocked(network, localPeer.PeerID)
	if gateway == nil || gateway.RemotePeerID != "peer-admin-z" {
		t.Fatalf("expected current admin gateway to stay selected on single-loss jitter, got %#v", gateway)
	}
}

func TestFullTunnelGatewaySelectionKeepsReplacementOfCurrentAdminOnSingleLossDelta(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-admin-replacement-loss-stickiness-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:                "net-full",
			LocalPeerID:              "peer-local",
			RemotePeerID:             "peer-admin-z-new",
			RemoteUserID:             "user-admin-z",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			Reachability:             "DIRECT",
			State:                    "CONNECTED",
			ConsecutiveLosses:        1,
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
		{
			NetworkID:         "net-full",
			LocalPeerID:       "peer-local",
			RemotePeerID:      "peer-admin-a",
			RemoteUserID:      "user-admin-a",
			RemoteVirtualIP:   "10.10.0.4",
			TransportReady:    true,
			TransportMode:     "DIRECT",
			Reachability:      "DIRECT",
			State:             "CONNECTED",
			ConsecutiveLosses: 0,
			AverageRTTMillis:  10,
			LastRTTMillis:     10,
		},
	}
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:         "net-full",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-admin-z-old",
			GatewayUserID:     "user-admin-z",
			GatewayVirtualIP:  "10.10.0.3",
			GatewayTargetRole: "ADMIN",
			Path:              "DIRECT",
			PolicyStatus:      "ACTIVE",
		},
	}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-member":  "MEMBER",
			"user-admin-z": "ADMIN",
			"user-admin-a": "ADMIN",
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	localPeer := managedPeerByNetwork(managedPeers, "net-full")

	gateway := agent.gatewayConnectionForNetworkLocked(network, localPeer.PeerID)
	if gateway == nil || gateway.RemotePeerID != "peer-admin-z-new" {
		t.Fatalf("expected replacement of current admin gateway to stay selected on single-loss jitter, got %#v", gateway)
	}
}

func TestFullTunnelGatewaySelectionDoesNotTreatKnownDistinctUserAsCurrentReplacement(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-admin-distinct-overlay-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-admin-z-new",
			RemoteUserID:     "user-admin-z-other",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 10,
			LastRTTMillis:    10,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-admin-a",
			RemoteUserID:     "user-admin-a",
			RemoteVirtualIP:  "10.10.0.4",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 8,
			LastRTTMillis:    8,
		},
	}
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:         "net-full",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-admin-z-old",
			GatewayUserID:     "user-admin-z",
			GatewayVirtualIP:  "10.10.0.3",
			GatewayTargetRole: "ADMIN",
			Path:              "DIRECT",
			PolicyStatus:      "ACTIVE",
		},
	}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-member":        "MEMBER",
			"user-admin-z":       "ADMIN",
			"user-admin-z-other": "ADMIN",
			"user-admin-a":       "ADMIN",
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	localPeer := managedPeerByNetwork(managedPeers, "net-full")

	gateway := agent.gatewayConnectionForNetworkLocked(network, localPeer.PeerID)
	if gateway == nil || gateway.RemotePeerID != "peer-admin-a" {
		t.Fatalf("expected known-distinct user on same claimed overlay IP not to inherit current gateway stickiness, got %#v", gateway)
	}
}

func TestFullTunnelGatewaySelectionPromotesMateriallyBetterAdminOverCurrentAdmin(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-admin-promotion-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-admin-z",
			RemoteUserID:     "user-admin-z",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 17,
			LastRTTMillis:    17,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-admin-a",
			RemoteUserID:     "user-admin-a",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 8,
			LastRTTMillis:    8,
		},
	}
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:         "net-full",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-admin-z",
			GatewayUserID:     "user-admin-z",
			GatewayTargetRole: "ADMIN",
			Path:              "DIRECT",
			PolicyStatus:      "ACTIVE",
		},
	}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-member":  "MEMBER",
			"user-admin-z": "ADMIN",
			"user-admin-a": "ADMIN",
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	localPeer := managedPeerByNetwork(managedPeers, "net-full")

	gateway := agent.gatewayConnectionForNetworkLocked(network, localPeer.PeerID)
	if gateway == nil || gateway.RemotePeerID != "peer-admin-a" {
		t.Fatalf("expected materially better admin gateway to replace current admin, got %#v", gateway)
	}
}

func TestFullTunnelGatewaySelectionPrefersFresherReplacementPeerOnEqualQuality(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-replacement-freshness-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:                "net-full",
			LocalPeerID:              "peer-local",
			RemotePeerID:             "peer-owner-old",
			RemoteUserID:             "user-owner",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			Reachability:             "DIRECT",
			State:                    "CONNECTED",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 100,
			LastTransportUnix:        150,
		},
		{
			NetworkID:                "net-full",
			LocalPeerID:              "peer-local",
			RemotePeerID:             "peer-owner-new",
			RemoteUserID:             "user-owner",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			Reachability:             "DIRECT",
			State:                    "CONNECTED",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
	}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-member": "MEMBER",
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	localPeer := managedPeerByNetwork(managedPeers, "net-full")

	gateway := agent.gatewayConnectionForNetworkLocked(network, localPeer.PeerID)
	if gateway == nil || gateway.RemotePeerID != "peer-owner-new" {
		t.Fatalf("expected fresher equal-quality replacement peer to win gateway selection, got %#v", gateway)
	}
}

func TestPrimaryFullTunnelNetworkPrefersDirectAdminGatewayOverRelayOwnerGateway(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\primary-gateway-quality-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-owner", "peer-local-owner", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-admin", "peer-local-admin", "127.0.0.1:4001", "10.20.0.0/24", "10.20.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-owner",
			LocalPeerID:      "peer-local-owner",
			RemotePeerID:     "peer-owner",
			RemoteUserID:     "user-owner",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:        "net-admin",
			LocalPeerID:      "peer-local-admin",
			RemotePeerID:     "peer-admin",
			RemoteUserID:     "user-admin",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 14,
			LastRTTMillis:    12,
		},
	}

	networksByID := map[string]controlclient.Network{
		"net-owner": {
			ID:            "net-owner",
			OwnerID:       "user-owner",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
			},
		},
		"net-admin": {
			ID:            "net-admin",
			OwnerID:       "user-other",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
				"user-admin":  "ADMIN",
			},
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)

	primary := agent.primaryFullTunnelClientNetworkLocked(managedPeers, networksByID)
	if primary != "net-admin" {
		t.Fatalf("expected direct admin-backed full network to own default route over relay owner-backed network, got %q", primary)
	}

	ownerPeer := managedPeerByNetwork(managedPeers, "net-owner")
	ownerConfig, err := agent.adapterConfigForManagedPeerLocked(ownerPeer, networksByID["net-owner"], primary)
	if err != nil {
		t.Fatalf("build owner-backed standby config: %v", err)
	}
	if ownerConfig.GatewayPeerID != "peer-owner" || ownerConfig.PolicyStatusHint != "STANDBY_GATEWAY" || ownerConfig.RoutePrefix != "10.10.0.0/24" {
		t.Fatalf("expected relay owner-backed network to stay standby, got %#v", ownerConfig)
	}

	adminPeer := managedPeerByNetwork(managedPeers, "net-admin")
	adminConfig, err := agent.adapterConfigForManagedPeerLocked(adminPeer, networksByID["net-admin"], primary)
	if err != nil {
		t.Fatalf("build admin-backed active config: %v", err)
	}
	if adminConfig.GatewayPeerID != "peer-admin" || adminConfig.RoutePrefix != "0.0.0.0/0" {
		t.Fatalf("expected direct admin-backed network to own default route, got %#v", adminConfig)
	}
}

func TestPrimaryFullTunnelNetworkPrefersDirectAdminGatewayOverMateriallyDegradedDirectOwnerGateway(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\primary-gateway-owner-quality-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-owner", "peer-local-owner", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-admin", "peer-local-admin", "127.0.0.1:4001", "10.20.0.0/24", "10.20.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:         "net-owner",
			LocalPeerID:       "peer-local-owner",
			RemotePeerID:      "peer-owner",
			RemoteUserID:      "user-owner",
			TransportReady:    true,
			TransportMode:     "DIRECT",
			Reachability:      "DIRECT",
			State:             "CONNECTED",
			ConsecutiveLosses: 2,
			AverageRTTMillis:  48,
			LastRTTMillis:     46,
		},
		{
			NetworkID:         "net-admin",
			LocalPeerID:       "peer-local-admin",
			RemotePeerID:      "peer-admin",
			RemoteUserID:      "user-admin",
			TransportReady:    true,
			TransportMode:     "DIRECT",
			Reachability:      "DIRECT",
			State:             "CONNECTED",
			ConsecutiveLosses: 0,
			AverageRTTMillis:  8,
			LastRTTMillis:     7,
		},
	}
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-owner": {
			NetworkID:         "net-owner",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-owner",
			GatewayUserID:     "user-owner",
			GatewayTargetRole: "OWNER",
			Path:              "DIRECT",
			PolicyStatus:      "ACTIVE",
		},
		"net-admin": {
			NetworkID:         "net-admin",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-admin",
			GatewayUserID:     "user-admin",
			GatewayTargetRole: "ADMIN",
			Path:              "DIRECT",
			PolicyStatus:      "STANDBY_GATEWAY",
		},
	}

	networksByID := map[string]controlclient.Network{
		"net-owner": {
			ID:            "net-owner",
			OwnerID:       "user-owner",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
			},
		},
		"net-admin": {
			ID:            "net-admin",
			OwnerID:       "user-other",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
				"user-admin":  "ADMIN",
			},
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)

	primary := agent.primaryFullTunnelClientNetworkLocked(managedPeers, networksByID)
	if primary != "net-admin" {
		t.Fatalf("expected materially healthier direct admin-backed full network to own default route over degraded direct owner-backed network, got %q", primary)
	}

	ownerPeer := managedPeerByNetwork(managedPeers, "net-owner")
	ownerConfig, err := agent.adapterConfigForManagedPeerLocked(ownerPeer, networksByID["net-owner"], primary)
	if err != nil {
		t.Fatalf("build degraded owner-backed standby config: %v", err)
	}
	if ownerConfig.GatewayPeerID != "peer-owner" || ownerConfig.PolicyStatusHint != "STANDBY_GATEWAY" || ownerConfig.RoutePrefix != "10.10.0.0/24" {
		t.Fatalf("expected degraded owner-backed network to fall back to standby, got %#v", ownerConfig)
	}

	adminPeer := managedPeerByNetwork(managedPeers, "net-admin")
	adminConfig, err := agent.adapterConfigForManagedPeerLocked(adminPeer, networksByID["net-admin"], primary)
	if err != nil {
		t.Fatalf("build materially healthier admin-backed active config: %v", err)
	}
	if adminConfig.GatewayPeerID != "peer-admin" || adminConfig.RoutePrefix != "0.0.0.0/0" {
		t.Fatalf("expected materially healthier admin-backed network to own default route, got %#v", adminConfig)
	}
}

func TestPrimaryFullTunnelNetworkKeepsCurrentActiveNetworkOnEqualGatewayQuality(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\primary-gateway-continuity-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-z", "peer-local-z", "127.0.0.1:4000", "10.30.0.0/24", "10.30.0.2")
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-a", "peer-local-a", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-z",
			LocalPeerID:      "peer-local-z",
			RemotePeerID:     "peer-owner-z",
			RemoteUserID:     "user-owner-z",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
		{
			NetworkID:        "net-a",
			LocalPeerID:      "peer-local-a",
			RemotePeerID:     "peer-owner-a",
			RemoteUserID:     "user-owner-a",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
	}
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-z": {
			NetworkID:         "net-z",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-owner-z",
			GatewayUserID:     "user-owner-z",
			GatewayTargetRole: "OWNER",
			Path:              "DIRECT",
			PolicyStatus:      "ACTIVE",
		},
		"net-a": {
			NetworkID:         "net-a",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-owner-a",
			GatewayUserID:     "user-owner-a",
			GatewayTargetRole: "OWNER",
			Path:              "DIRECT",
			PolicyStatus:      "STANDBY_GATEWAY",
		},
	}

	networksByID := map[string]controlclient.Network{
		"net-z": {
			ID:            "net-z",
			OwnerID:       "user-owner-z",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
			},
		},
		"net-a": {
			ID:            "net-a",
			OwnerID:       "user-owner-a",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
			},
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)

	primary := agent.primaryFullTunnelClientNetworkLocked(managedPeers, networksByID)
	if primary != "net-z" {
		t.Fatalf("expected equal-quality full-tunnel election to keep current active network instead of lower network ID, got %q", primary)
	}

	peerZ := managedPeerByNetwork(managedPeers, "net-z")
	configZ, err := agent.adapterConfigForManagedPeerLocked(peerZ, networksByID["net-z"], primary)
	if err != nil {
		t.Fatalf("build equal-quality active config: %v", err)
	}
	if configZ.RoutePrefix != "0.0.0.0/0" || strings.TrimSpace(configZ.PolicyStatusHint) != "" {
		t.Fatalf("expected current active full network to keep default route, got %#v", configZ)
	}

	peerA := managedPeerByNetwork(managedPeers, "net-a")
	configA, err := agent.adapterConfigForManagedPeerLocked(peerA, networksByID["net-a"], primary)
	if err != nil {
		t.Fatalf("build equal-quality standby config: %v", err)
	}
	if configA.RoutePrefix != "10.10.0.0/24" || configA.PolicyStatusHint != "STANDBY_GATEWAY" {
		t.Fatalf("expected equal-quality standby network to stay on overlay route, got %#v", configA)
	}

	agent.observeGatewaySelectionsLocked([]virtualadapter.NetworkConfig{configZ, configA})
	if len(agent.gatewayHistory) != 0 {
		t.Fatalf("expected equal-quality election continuity to avoid noisy gateway history, got %#v", agent.gatewayHistory)
	}
}

func TestPrimaryFullTunnelNetworkKeepsCurrentActiveNetworkOnMinorRTTImprovement(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\primary-gateway-rtt-hysteresis-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-z", "peer-local-z", "127.0.0.1:4000", "10.30.0.0/24", "10.30.0.2")
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-a", "peer-local-a", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-z",
			LocalPeerID:      "peer-local-z",
			RemotePeerID:     "peer-owner-z",
			RemoteUserID:     "user-owner-z",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    11,
		},
		{
			NetworkID:        "net-a",
			LocalPeerID:      "peer-local-a",
			RemotePeerID:     "peer-owner-a",
			RemoteUserID:     "user-owner-a",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 9,
			LastRTTMillis:    8,
		},
	}
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-z": {
			NetworkID:         "net-z",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-owner-z",
			GatewayUserID:     "user-owner-z",
			GatewayTargetRole: "OWNER",
			Path:              "DIRECT",
			PolicyStatus:      "ACTIVE",
		},
		"net-a": {
			NetworkID:         "net-a",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-owner-a",
			GatewayUserID:     "user-owner-a",
			GatewayTargetRole: "OWNER",
			Path:              "DIRECT",
			PolicyStatus:      "STANDBY_GATEWAY",
		},
	}

	networksByID := map[string]controlclient.Network{
		"net-z": {
			ID:            "net-z",
			OwnerID:       "user-owner-z",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
			},
		},
		"net-a": {
			ID:            "net-a",
			OwnerID:       "user-owner-a",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
			},
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)

	primary := agent.primaryFullTunnelClientNetworkLocked(managedPeers, networksByID)
	if primary != "net-z" {
		t.Fatalf("expected minor RTT improvement to stay below full-tunnel hysteresis and keep current active network, got %q", primary)
	}
}

func TestPrimaryFullTunnelNetworkPromotesStandbyOnMaterialRTTImprovement(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\primary-gateway-rtt-promotion-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-z", "peer-local-z", "127.0.0.1:4000", "10.30.0.0/24", "10.30.0.2")
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-a", "peer-local-a", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-z",
			LocalPeerID:      "peer-local-z",
			RemotePeerID:     "peer-owner-z",
			RemoteUserID:     "user-owner-z",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 16,
			LastRTTMillis:    15,
		},
		{
			NetworkID:        "net-a",
			LocalPeerID:      "peer-local-a",
			RemotePeerID:     "peer-owner-a",
			RemoteUserID:     "user-owner-a",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 8,
			LastRTTMillis:    7,
		},
	}
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-z": {
			NetworkID:         "net-z",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-owner-z",
			GatewayUserID:     "user-owner-z",
			GatewayTargetRole: "OWNER",
			Path:              "DIRECT",
			PolicyStatus:      "ACTIVE",
		},
		"net-a": {
			NetworkID:         "net-a",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-owner-a",
			GatewayUserID:     "user-owner-a",
			GatewayTargetRole: "OWNER",
			Path:              "DIRECT",
			PolicyStatus:      "STANDBY_GATEWAY",
		},
	}

	networksByID := map[string]controlclient.Network{
		"net-z": {
			ID:            "net-z",
			OwnerID:       "user-owner-z",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
			},
		},
		"net-a": {
			ID:            "net-a",
			OwnerID:       "user-owner-a",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
			},
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)

	primary := agent.primaryFullTunnelClientNetworkLocked(managedPeers, networksByID)
	if primary != "net-a" {
		t.Fatalf("expected material RTT improvement to promote standby full-tunnel network, got %q", primary)
	}
}

func TestPrimaryFullTunnelNetworkKeepsCurrentActiveNetworkOnSingleLossDelta(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\primary-gateway-loss-hysteresis-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-z", "peer-local-z", "127.0.0.1:4000", "10.30.0.0/24", "10.30.0.2")
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-a", "peer-local-a", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:         "net-z",
			LocalPeerID:       "peer-local-z",
			RemotePeerID:      "peer-owner-z",
			RemoteUserID:      "user-owner-z",
			TransportReady:    true,
			TransportMode:     "DIRECT",
			Reachability:      "DIRECT",
			State:             "CONNECTED",
			ConsecutiveLosses: 1,
			AverageRTTMillis:  12,
			LastRTTMillis:     11,
		},
		{
			NetworkID:         "net-a",
			LocalPeerID:       "peer-local-a",
			RemotePeerID:      "peer-owner-a",
			RemoteUserID:      "user-owner-a",
			TransportReady:    true,
			TransportMode:     "DIRECT",
			Reachability:      "DIRECT",
			State:             "CONNECTED",
			ConsecutiveLosses: 0,
			AverageRTTMillis:  12,
			LastRTTMillis:     11,
		},
	}
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-z": {
			NetworkID:         "net-z",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-owner-z",
			GatewayUserID:     "user-owner-z",
			GatewayTargetRole: "OWNER",
			Path:              "DIRECT",
			PolicyStatus:      "ACTIVE",
		},
		"net-a": {
			NetworkID:         "net-a",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-owner-a",
			GatewayUserID:     "user-owner-a",
			GatewayTargetRole: "OWNER",
			Path:              "DIRECT",
			PolicyStatus:      "STANDBY_GATEWAY",
		},
	}

	networksByID := map[string]controlclient.Network{
		"net-z": {
			ID:            "net-z",
			OwnerID:       "user-owner-z",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
			},
		},
		"net-a": {
			ID:            "net-a",
			OwnerID:       "user-owner-a",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
			},
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)

	primary := agent.primaryFullTunnelClientNetworkLocked(managedPeers, networksByID)
	if primary != "net-z" {
		t.Fatalf("expected single loss delta to keep current active full-tunnel network, got %q", primary)
	}
}

func TestPrimaryFullTunnelNetworkPromotesStandbyOnMaterialLossImprovement(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\primary-gateway-loss-promotion-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-z", "peer-local-z", "127.0.0.1:4000", "10.30.0.0/24", "10.30.0.2")
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-a", "peer-local-a", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:         "net-z",
			LocalPeerID:       "peer-local-z",
			RemotePeerID:      "peer-owner-z",
			RemoteUserID:      "user-owner-z",
			TransportReady:    true,
			TransportMode:     "DIRECT",
			Reachability:      "DIRECT",
			State:             "CONNECTED",
			ConsecutiveLosses: 2,
			AverageRTTMillis:  12,
			LastRTTMillis:     11,
		},
		{
			NetworkID:         "net-a",
			LocalPeerID:       "peer-local-a",
			RemotePeerID:      "peer-owner-a",
			RemoteUserID:      "user-owner-a",
			TransportReady:    true,
			TransportMode:     "DIRECT",
			Reachability:      "DIRECT",
			State:             "CONNECTED",
			ConsecutiveLosses: 0,
			AverageRTTMillis:  12,
			LastRTTMillis:     11,
		},
	}
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-z": {
			NetworkID:         "net-z",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-owner-z",
			GatewayUserID:     "user-owner-z",
			GatewayTargetRole: "OWNER",
			Path:              "DIRECT",
			PolicyStatus:      "ACTIVE",
		},
		"net-a": {
			NetworkID:         "net-a",
			GatewayRole:       "CLIENT",
			GatewayPeerID:     "peer-owner-a",
			GatewayUserID:     "user-owner-a",
			GatewayTargetRole: "OWNER",
			Path:              "DIRECT",
			PolicyStatus:      "STANDBY_GATEWAY",
		},
	}

	networksByID := map[string]controlclient.Network{
		"net-z": {
			ID:            "net-z",
			OwnerID:       "user-owner-z",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
			},
		},
		"net-a": {
			ID:            "net-a",
			OwnerID:       "user-owner-a",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
			},
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)

	primary := agent.primaryFullTunnelClientNetworkLocked(managedPeers, networksByID)
	if primary != "net-a" {
		t.Fatalf("expected material loss improvement to promote standby full-tunnel network, got %q", primary)
	}
}

func TestFullTunnelGatewayHostReturnPathSurvivesSamePeerReplacement(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-host-churn-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-owner", Email: "owner@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.1")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-client-old",
			RemoteUserID:     "user-client",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    82,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-client-new",
			RemoteUserID:     "user-client",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
	}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-client": "MEMBER",
		},
	}
	networksByID := map[string]controlclient.Network{
		"net-full": network,
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)

	selected := agent.gatewayHostConnectionForDestinationLocked(managedPeers, networksByID, "8.8.8.8", "10.10.0.3")
	if selected == nil || selected.RemotePeerID != "peer-client-new" {
		t.Fatalf("expected gateway-host return path to keep routing through replacement peer, got %#v", selected)
	}

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, "", "8.8.8.8", "10.10.0.3")
	if len(routed) != 1 || routed[0].RemotePeerID != "peer-client-new" {
		t.Fatalf("expected gateway-host internet return packet to use replacement peer, got %#v", routed)
	}
}

func TestFullTunnelGatewayHostReturnPathSurvivesReplacementPeerWithMissingConnectionVirtualIP(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-host-virtualip-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-owner", Email: "owner@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.1")
	agent.discoveredPeers["net-full"] = []controlclient.Peer{{
		ID:        "peer-client-new",
		NetworkID: "net-full",
		UserID:    "user-client",
		VirtualIP: "10.10.0.3",
		Status:    "ONLINE",
	}}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-client-old",
			RemoteUserID:     "user-client",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    82,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-client-new",
			RemoteUserID:     "user-client",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
	}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-client": "MEMBER",
		},
	}
	networksByID := map[string]controlclient.Network{
		"net-full": network,
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)

	selected := agent.gatewayHostConnectionForDestinationLocked(managedPeers, networksByID, "8.8.8.8", "10.10.0.3")
	if selected == nil || selected.RemotePeerID != "peer-client-new" {
		t.Fatalf("expected gateway-host return path to keep the replacement peer when connection virtual IP metadata is missing, got %#v", selected)
	}

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, "", "8.8.8.8", "10.10.0.3")
	if len(routed) != 1 || routed[0].RemotePeerID != "peer-client-new" {
		t.Fatalf("expected gateway-host internet return packet to keep the replacement peer when connection virtual IP metadata is missing, got %#v", routed)
	}
}

func TestFullTunnelGatewayHostReturnPathKeepsReplacementPeerAcrossVirtualIPMetadataGapWithoutDiscovery(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-host-virtualip-no-discovery-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-owner", Email: "owner@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.1")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-client-old",
			RemoteUserID:     "user-client",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    82,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-client-new",
			RemoteUserID:     "user-client",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
	}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-client": "MEMBER",
		},
	}
	networksByID := map[string]controlclient.Network{
		"net-full": network,
	}
	managedPeers := agent.dedupeManagedPeersForRuntime(agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID))

	selected := agent.gatewayHostConnectionForDestinationLocked(managedPeers, networksByID, "8.8.8.8", "10.10.0.3")
	if selected == nil || selected.RemotePeerID != "peer-client-new" {
		t.Fatalf("expected gateway-host return path to keep the live replacement peer across a no-discovery virtual IP metadata gap, got %#v", selected)
	}

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, "", "8.8.8.8", "10.10.0.3")
	if len(routed) != 1 || routed[0].RemotePeerID != "peer-client-new" {
		t.Fatalf("expected gateway-host internet return packet to keep the live replacement peer across a no-discovery virtual IP metadata gap, got %#v", routed)
	}
}

func TestFullTunnelGatewayHostReturnPathPrefersActiveLocalPeerAcrossVirtualIPMetadataGap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-host-local-peer-virtualip-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-owner", Email: "owner@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.ManagedPeers = []ManagedPeerState{
		{
			ServerBaseURL: agent.remote.BaseURL(),
			UserID:        agent.currentUser.ID,
			NetworkID:     "net-full",
			PeerID:        "peer-local-old",
			Endpoint:      "127.0.0.1:4000",
			OverlayCIDR:   "10.10.0.0/24",
			VirtualIP:     "10.10.0.1",
		},
		{
			ServerBaseURL: agent.remote.BaseURL(),
			UserID:        agent.currentUser.ID,
			NetworkID:     "net-full",
			PeerID:        "peer-local-new",
			Endpoint:      "127.0.0.1:4001",
			OverlayCIDR:   "10.10.0.0/24",
			VirtualIP:     "10.10.0.1",
		},
	}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-client-old",
			RemoteUserID:     "user-client",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    82,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-client-new",
			RemoteUserID:     "user-client",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
	}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-client": "MEMBER",
		},
	}
	networksByID := map[string]controlclient.Network{
		"net-full": network,
	}
	managedPeers := agent.dedupeManagedPeersForRuntime(agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID))

	selected := agent.gatewayHostConnectionForDestinationLocked(managedPeers, networksByID, "8.8.8.8", "10.10.0.3")
	if selected == nil || selected.LocalPeerID != "peer-local-new" || selected.RemotePeerID != "peer-client-new" {
		t.Fatalf("expected gateway-host return path to prefer the active local-peer replacement across a virtual IP metadata gap, got %#v", selected)
	}

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, "", "8.8.8.8", "10.10.0.3")
	if len(routed) != 1 || routed[0].LocalPeerID != "peer-local-new" || routed[0].RemotePeerID != "peer-client-new" {
		t.Fatalf("expected gateway-host internet return packet to prefer the active local-peer replacement across a virtual IP metadata gap, got %#v", routed)
	}
}

func TestFullTunnelGatewayHostReturnPathUsesEndpointContinuityForActiveReplacementDuringMetadataGap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-host-endpoint-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-owner", Email: "owner@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.ManagedPeers = []ManagedPeerState{
		{
			ServerBaseURL: agent.remote.BaseURL(),
			UserID:        agent.currentUser.ID,
			NetworkID:     "net-full",
			PeerID:        "peer-local-old",
			Endpoint:      "127.0.0.1:4000",
			OverlayCIDR:   "10.10.0.0/24",
			VirtualIP:     "10.10.0.1",
		},
		{
			ServerBaseURL: agent.remote.BaseURL(),
			UserID:        agent.currentUser.ID,
			NetworkID:     "net-full",
			PeerID:        "peer-local-new",
			Endpoint:      "127.0.0.1:4001",
			OverlayCIDR:   "10.10.0.0/24",
			VirtualIP:     "10.10.0.1",
		},
	}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-client-old",
			RemoteUserID:     "user-client",
			RemoteVirtualIP:  "10.10.0.3",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    82,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-client-new",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000"},
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
	}

	network := controlclient.Network{
		ID:            "net-full",
		OwnerID:       "user-owner",
		RoutingPolicy: "FULL",
		MemberRoles: map[string]string{
			"user-client": "MEMBER",
		},
	}
	networksByID := map[string]controlclient.Network{
		"net-full": network,
	}
	managedPeers := agent.dedupeManagedPeersForRuntime(agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID))

	selected := agent.gatewayHostConnectionForDestinationLocked(managedPeers, networksByID, "8.8.8.8", "10.10.0.3")
	if selected == nil || selected.LocalPeerID != "peer-local-new" || selected.RemotePeerID != "peer-client-new" {
		t.Fatalf("expected gateway-host return path to follow the active replacement through endpoint continuity while remote metadata is blank, got %#v", selected)
	}

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, "", "8.8.8.8", "10.10.0.3")
	if len(routed) != 1 || routed[0].LocalPeerID != "peer-local-new" || routed[0].RemotePeerID != "peer-client-new" {
		t.Fatalf("expected gateway-host internet return packet to follow the active replacement through endpoint continuity while remote metadata is blank, got %#v", routed)
	}
}

func TestOverlayDNSDeduplicationPrefersReplacementConnectionWithMissingConnectionVirtualIP(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\overlay-dns-virtualip-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.connections = []ConnectionStatus{{
		NetworkID:        "net-1",
		LocalPeerID:      "peer-local",
		RemotePeerID:     "peer-remote-new",
		RemoteUserID:     "user-remote",
		TransportReady:   true,
		TransportMode:    "DIRECT",
		Reachability:     "DIRECT",
		State:            "CONNECTED",
		AverageRTTMillis: 12,
		LastRTTMillis:    10,
	}}
	peers := []controlclient.Peer{
		{
			ID:                 "peer-remote-old",
			NetworkID:          "net-1",
			UserID:             "user-remote",
			VirtualIP:          "10.10.0.3",
			Status:             "ONLINE",
			ConnectionState:    "CONNECTED",
			LastSignaledAtUnix: 200,
			LastSeenUnix:       200,
		},
		{
			ID:                 "peer-remote-new",
			NetworkID:          "net-1",
			UserID:             "user-remote",
			VirtualIP:          "10.10.0.3",
			Status:             "ONLINE",
			ConnectionState:    "DISCOVERING",
			LastSignaledAtUnix: 100,
			LastSeenUnix:       100,
		},
	}

	preferred := agent.overlayDNSPreferredRemotePeerByID("net-1", peers)
	deduped := agent.dedupeDiscoveredPeersForOverlayDNS("net-1", peers)

	if preferred["peer-remote-old"] != "peer-remote-new" || preferred["peer-remote-new"] != "peer-remote-new" {
		t.Fatalf("expected overlay dns peer matching to follow the live replacement connection via discovery virtual IP fallback, got %#v", preferred)
	}
	if len(deduped) != 1 || deduped[0].ID != "peer-remote-new" {
		t.Fatalf("expected overlay dns dedupe to keep the connected replacement peer when its connection virtual IP metadata is missing, got %#v", deduped)
	}
}

func TestOverlayDNSDeduplicationPrefersActiveLocalPeerDuringSameDeviceOverlap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\overlay-dns-local-peer-overlap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 8,
			LastRTTMillis:    7,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-remote-new",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    78,
		},
	}
	peers := []controlclient.Peer{
		{
			ID:                 "peer-remote-old",
			NetworkID:          "net-1",
			UserID:             "user-remote",
			VirtualIP:          "10.10.0.3",
			Status:             "ONLINE",
			ConnectionState:    "CONNECTED",
			LastSignaledAtUnix: 200,
			LastSeenUnix:       200,
		},
		{
			ID:                 "peer-remote-new",
			NetworkID:          "net-1",
			UserID:             "user-remote",
			VirtualIP:          "10.10.0.3",
			Status:             "ONLINE",
			ConnectionState:    "CONNECTED",
			LastSignaledAtUnix: 100,
			LastSeenUnix:       100,
		},
	}

	preferred := agent.overlayDNSPreferredRemotePeerByID("net-1", peers)
	deduped := agent.dedupeDiscoveredPeersForOverlayDNS("net-1", peers)

	if preferred["peer-remote-old"] != "peer-remote-new" || preferred["peer-remote-new"] != "peer-remote-new" {
		t.Fatalf("expected overlay dns peer matching to follow the active managed local peer during overlap, got %#v", preferred)
	}
	if len(deduped) != 1 || deduped[0].ID != "peer-remote-new" {
		t.Fatalf("expected overlay dns dedupe to keep the active local peer replacement during overlap, got %#v", deduped)
	}
}

func TestStatusConnectionsBackfillReplacementVirtualIPMetadata(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\status-virtualip-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.discoveredPeers["net-1"] = []controlclient.Peer{{
		ID:        "peer-remote-new",
		NetworkID: "net-1",
		UserID:    "user-remote",
		VirtualIP: "10.10.0.3",
		Status:    "ONLINE",
	}}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-new",
			RemoteUserID:     "user-remote",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
	}
	agent.mu.Unlock()

	status := agent.Status()
	if len(status.Connections) != 1 {
		t.Fatalf("expected status to keep only the replacement connection, got %#v", status.Connections)
	}
	if status.Connections[0].RemotePeerID != "peer-remote-new" || status.Connections[0].RemoteVirtualIP != "10.10.0.3" {
		t.Fatalf("expected status to backfill replacement virtual IP metadata from discovery, got %#v", status.Connections[0])
	}
}

func TestBuildConnectionStatusPreservesPreviousMetadataWhenPeerRefreshDropsIt(t *testing.T) {
	connection := buildConnectionStatus(
		"net-1",
		"peer-local",
		controlclient.Peer{
			ID:        "peer-remote",
			NetworkID: "net-1",
			Status:    "ONLINE",
			Endpoint:  "127.0.0.1:42000",
		},
		nil,
		&ConnectionStatus{
			NetworkID:       "net-1",
			LocalPeerID:     "peer-local",
			RemotePeerID:    "peer-remote",
			RemoteUserID:    "user-remote",
			RemoteVirtualIP: "10.10.0.3",
		},
	)

	if connection.RemoteUserID != "user-remote" || connection.RemoteVirtualIP != "10.10.0.3" {
		t.Fatalf("expected connection rebuild to preserve previous remote metadata when peer refresh drops it, got %#v", connection)
	}
}

func TestBuildNeighborStatusPreservesConnectionMetadataWhenPeerRefreshDropsIt(t *testing.T) {
	neighbor := buildNeighborStatus(
		"net-1",
		"peer-local",
		controlclient.Peer{
			ID:        "peer-remote",
			NetworkID: "net-1",
			Status:    "ONLINE",
			Endpoint:  "127.0.0.1:42000",
		},
		nil,
		ConnectionStatus{
			NetworkID:       "net-1",
			LocalPeerID:     "peer-local",
			RemotePeerID:    "peer-remote",
			RemoteUserID:    "user-remote",
			RemoteVirtualIP: "10.10.0.3",
			State:           "CONNECTED",
			Reachability:    "DIRECT",
			TransportReady:  true,
			TransportMode:   "DIRECT",
		},
	)

	if neighbor.RemoteUserID != "user-remote" || neighbor.RemoteVirtualIP != "10.10.0.3" {
		t.Fatalf("expected neighbor rebuild to preserve connection metadata when peer refresh drops it, got %#v", neighbor)
	}
}

func TestOverlayPacketRoutingSurvivesSamePeerReplacement(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\overlay-routing-churn-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-new",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
	}

	networksByID := map[string]controlclient.Network{
		"net-1": {
			ID:            "net-1",
			OwnerID:       "user-owner",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
				"user-remote": "MEMBER",
			},
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, "", "10.10.0.2", "10.10.0.3")
	if len(routed) != 1 || routed[0].RemotePeerID != "peer-remote-new" {
		t.Fatalf("expected overlay packet routing to use replacement peer, got %#v", routed)
	}
}

func TestOverlayPacketRoutingSurvivesSamePeerReplacementWithoutUserMetadata(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\overlay-routing-metadata-churn-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-old",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-new",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
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
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, "", "10.10.0.2", "10.10.0.3")
	if len(routed) != 1 || routed[0].RemotePeerID != "peer-remote-new" {
		t.Fatalf("expected overlay packet routing to keep the replacement peer when only overlay IP continuity is known, got %#v", routed)
	}
}

func TestOverlayPacketRoutingSurvivesReplacementPeerWithMissingConnectionVirtualIP(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\overlay-routing-virtualip-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.discoveredPeers["net-1"] = []controlclient.Peer{{
		ID:        "peer-remote-new",
		NetworkID: "net-1",
		UserID:    "user-remote",
		VirtualIP: "10.10.0.3",
		Status:    "ONLINE",
	}}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-new",
			RemoteUserID:     "user-remote",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
	}

	networksByID := map[string]controlclient.Network{
		"net-1": {
			ID:            "net-1",
			OwnerID:       "user-owner",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
				"user-remote": "MEMBER",
			},
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, "", "10.10.0.2", "10.10.0.3")
	if len(routed) != 1 || routed[0].RemotePeerID != "peer-remote-new" {
		t.Fatalf("expected overlay packet routing to keep the replacement peer when connection virtual IP metadata is missing, got %#v", routed)
	}
}

func TestOverlayPacketRoutingKeepsReplacementPeerAcrossVirtualIPMetadataGapWithoutDiscovery(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\overlay-routing-no-discovery-virtualip-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-new",
			RemoteUserID:     "user-remote",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
	}

	networksByID := map[string]controlclient.Network{
		"net-1": {
			ID:            "net-1",
			OwnerID:       "user-owner",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
				"user-remote": "MEMBER",
			},
		},
	}
	managedPeers := agent.dedupeManagedPeersForRuntime(agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID))

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, "", "10.10.0.2", "10.10.0.3")
	if len(routed) != 1 || routed[0].RemotePeerID != "peer-remote-new" {
		t.Fatalf("expected overlay packet routing to keep the live replacement peer across a no-discovery virtual IP metadata gap, got %#v", routed)
	}
}

func TestOverlayPacketRoutingUsesEndpointContinuityForReplacementDuringMetadataGap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\overlay-routing-endpoint-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-new",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000"},
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
	}

	networksByID := map[string]controlclient.Network{
		"net-1": {
			ID:            "net-1",
			OwnerID:       "user-owner",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
				"user-remote": "MEMBER",
			},
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, "", "10.10.0.2", "10.10.0.3")
	if len(routed) != 1 || routed[0].RemotePeerID != "peer-remote-new" {
		t.Fatalf("expected overlay packet routing to follow the replacement through endpoint continuity while remote metadata is blank, got %#v", routed)
	}
}

func TestOverlayPacketRoutingPrefersActiveLocalPeerAcrossVirtualIPMetadataGap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\overlay-routing-local-peer-virtualip-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

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
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    82,
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
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
	}

	networksByID := map[string]controlclient.Network{
		"net-1": {
			ID:            "net-1",
			OwnerID:       "user-owner",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
				"user-remote": "MEMBER",
			},
		},
	}
	managedPeers := agent.dedupeManagedPeersForRuntime(agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID))

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, "", "10.10.0.2", "10.10.0.3")
	if len(routed) != 1 || routed[0].LocalPeerID != "peer-local-new" || routed[0].RemotePeerID != "peer-remote-new" {
		t.Fatalf("expected overlay packet routing to prefer the active local-peer replacement across a virtual IP metadata gap, got %#v", routed)
	}
}

func TestDestinationRoutingPrefersActiveLocalPeerAcrossEndpointMetadataGap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\overlay-routing-local-peer-endpoint-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 8,
			LastRTTMillis:    8,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-remote-new",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000"},
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    82,
		},
	}

	routed := agent.preferredDestinationConnectionLocked(connectionStatusPointers(agent.connections), "10.10.0.3")
	if routed == nil || routed.LocalPeerID != "peer-local-new" || routed.RemotePeerID != "peer-remote-new" {
		t.Fatalf("expected destination routing to prefer active local-peer replacement through endpoint continuity despite stale direct quality, got %#v", routed)
	}
}

func TestOverlayPacketRoutingPrefersFresherReplacementPeerOnEqualQuality(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\overlay-routing-freshness-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
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
			Reachability:             "DIRECT",
			State:                    "CONNECTED",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 100,
			LastTransportUnix:        150,
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local",
			RemotePeerID:             "peer-remote-new",
			RemoteUserID:             "user-remote",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			Reachability:             "DIRECT",
			State:                    "CONNECTED",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
	}

	networksByID := map[string]controlclient.Network{
		"net-1": {
			ID:            "net-1",
			OwnerID:       "user-owner",
			RoutingPolicy: "FULL",
			MemberRoles: map[string]string{
				"user-member": "MEMBER",
				"user-remote": "MEMBER",
			},
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, "", "10.10.0.2", "10.10.0.3")
	if len(routed) != 1 || routed[0].RemotePeerID != "peer-remote-new" {
		t.Fatalf("expected overlay packet routing to prefer fresher equal-quality replacement peer, got %#v", routed)
	}
}

func TestFloodGroupRoutingDeduplicatesSamePeerReplacement(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\group-flood-churn-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote-a",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-new",
			RemoteUserID:     "user-remote-a",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-other",
			RemoteUserID:     "user-remote-b",
			RemoteVirtualIP:  "10.10.0.4",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 15,
			LastRTTMillis:    14,
		},
	}

	networksByID := map[string]controlclient.Network{
		"net-1": {
			ID:                 "net-1",
			OwnerID:            "user-owner",
			GroupTrafficPolicy: "FLOOD",
			MemberRoles: map[string]string{
				"user-member":   "MEMBER",
				"user-remote-a": "MEMBER",
				"user-remote-b": "MEMBER",
			},
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, "", "10.10.0.2", "10.10.0.255")
	if len(routed) != 2 {
		t.Fatalf("expected flooded routing to deduplicate replacement peer and keep distinct peer, got %#v", routed)
	}
	seen := map[string]bool{}
	for _, connection := range routed {
		seen[connection.RemotePeerID] = true
	}
	if !seen["peer-remote-new"] || !seen["peer-other"] || seen["peer-remote-old"] {
		t.Fatalf("expected flooded routing to keep replacement and distinct peer only, got %#v", routed)
	}
}

func TestFloodGroupRoutingDeduplicatesReplacementPeerAcrossVirtualIPMetadataGapWithoutDiscovery(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\group-flood-no-discovery-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote-a",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-new",
			RemoteUserID:     "user-remote-a",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-other",
			RemoteUserID:     "user-remote-b",
			RemoteVirtualIP:  "10.10.0.4",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 15,
			LastRTTMillis:    14,
		},
	}

	networksByID := map[string]controlclient.Network{
		"net-1": {
			ID:                 "net-1",
			OwnerID:            "user-owner",
			GroupTrafficPolicy: "FLOOD",
			MemberRoles: map[string]string{
				"user-member":   "MEMBER",
				"user-remote-a": "MEMBER",
				"user-remote-b": "MEMBER",
			},
		},
	}
	managedPeers := agent.dedupeManagedPeersForRuntime(agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID))

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, "", "10.10.0.2", "10.10.0.255")
	if len(routed) != 2 {
		t.Fatalf("expected flooded routing to deduplicate a no-discovery replacement peer metadata gap and keep the distinct peer, got %#v", routed)
	}
	seen := map[string]bool{}
	for _, connection := range routed {
		seen[connection.RemotePeerID] = true
	}
	if !seen["peer-remote-new"] || !seen["peer-other"] || seen["peer-remote-old"] {
		t.Fatalf("expected flooded routing to keep the live replacement and distinct peer only across a no-discovery metadata gap, got %#v", routed)
	}
}

func TestFloodGroupRoutingKeepsDistinctStaleLocalPeerDuringActiveReplacementMetadataGap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\group-flood-local-peer-metadata-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

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
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote-a",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-remote-new",
			RemoteUserID:     "user-remote-a",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-other-stale-local",
			RemoteUserID:     "user-remote-b",
			RemoteVirtualIP:  "10.10.0.4",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 15,
			LastRTTMillis:    14,
		},
	}

	networksByID := map[string]controlclient.Network{
		"net-1": {
			ID:                 "net-1",
			OwnerID:            "user-owner",
			GroupTrafficPolicy: "FLOOD",
			MemberRoles: map[string]string{
				"user-member":   "MEMBER",
				"user-remote-a": "MEMBER",
				"user-remote-b": "MEMBER",
			},
		},
	}
	managedPeers := agent.dedupeManagedPeersForRuntime(agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID))

	routed := agent.connectionsForPacketLocked(managedPeers, networksByID, "", "10.10.0.2", "10.10.0.255")
	if len(routed) != 2 {
		t.Fatalf("expected flooded routing to keep the active replacement plus a distinct peer still on the stale local peer during overlap, got %#v", routed)
	}
	seen := map[string]bool{}
	for _, connection := range routed {
		seen[connection.RemotePeerID] = true
	}
	if !seen["peer-remote-new"] || !seen["peer-other-stale-local"] || seen["peer-remote-old"] {
		t.Fatalf("expected flooded routing to keep the active replacement and the distinct stale-local peer only during overlap, got %#v", routed)
	}
}

func TestInboundTransportValidationPrefersReplacementPeer(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\inbound-routing-churn-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-new",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
	}

	network := controlclient.Network{
		ID:                 "net-1",
		GroupTrafficPolicy: "FLOOD",
		MemberRoles: map[string]string{
			"user-member": "MEMBER",
			"user-remote": "MEMBER",
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	managedPeer := managedPeerByNetwork(managedPeers, "net-1")

	unicast := buildIPv4PacketForChurnTest(t, "10.10.0.3", "10.10.0.2", []byte{1, 2, 3, 4})
	if agent.shouldAcceptInboundTransportPacketLocked(managedPeer, managedPeers, network, "", "peer-remote-old", unicast, time.Time{}) {
		t.Fatalf("expected stale peer inbound unicast to be rejected when replacement transport is live")
	}
	if !agent.shouldAcceptInboundTransportPacketLocked(managedPeer, managedPeers, network, "", "peer-remote-new", unicast, time.Time{}) {
		t.Fatalf("expected replacement peer inbound unicast to be accepted")
	}

	broadcast := buildIPv4PacketForChurnTest(t, "10.10.0.3", "10.10.0.255", []byte{5, 6, 7, 8})
	if agent.shouldAcceptInboundTransportPacketLocked(managedPeer, managedPeers, network, "", "peer-remote-old", broadcast, time.Time{}) {
		t.Fatalf("expected stale peer inbound flood packet to be rejected when replacement transport is live")
	}
	if !agent.shouldAcceptInboundTransportPacketLocked(managedPeer, managedPeers, network, "", "peer-remote-new", broadcast, time.Time{}) {
		t.Fatalf("expected replacement peer inbound flood packet to be accepted")
	}
}

func TestInboundTransportValidationPrefersReplacementPeerWithMissingConnectionVirtualIP(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\inbound-routing-virtualip-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.discoveredPeers["net-1"] = []controlclient.Peer{{
		ID:        "peer-remote-new",
		NetworkID: "net-1",
		UserID:    "user-remote",
		VirtualIP: "10.10.0.3",
		Status:    "ONLINE",
	}}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-new",
			RemoteUserID:     "user-remote",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
	}

	network := controlclient.Network{
		ID:                 "net-1",
		GroupTrafficPolicy: "FLOOD",
		MemberRoles: map[string]string{
			"user-member": "MEMBER",
			"user-remote": "MEMBER",
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	managedPeer := managedPeerByNetwork(managedPeers, "net-1")

	unicast := buildIPv4PacketForChurnTest(t, "10.10.0.3", "10.10.0.2", []byte{1, 2, 3, 4})
	if agent.shouldAcceptInboundTransportPacketLocked(managedPeer, managedPeers, network, "", "peer-remote-old", unicast, time.Time{}) {
		t.Fatalf("expected stale peer inbound unicast to be rejected when replacement transport is live even if the replacement connection is missing virtual IP metadata")
	}
	if !agent.shouldAcceptInboundTransportPacketLocked(managedPeer, managedPeers, network, "", "peer-remote-new", unicast, time.Time{}) {
		t.Fatalf("expected replacement peer inbound unicast to be accepted when connection virtual IP metadata is missing")
	}
}

func TestInboundTransportValidationPrefersReplacementPeerAcrossVirtualIPMetadataGapWithoutDiscovery(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\inbound-routing-no-discovery-virtualip-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-member", Email: "member@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-new",
			RemoteUserID:     "user-remote",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
	}

	network := controlclient.Network{
		ID:                 "net-1",
		GroupTrafficPolicy: "FLOOD",
		MemberRoles: map[string]string{
			"user-member": "MEMBER",
			"user-remote": "MEMBER",
		},
	}
	managedPeers := agent.deviceState.ManagedPeersFor(agent.remote.BaseURL(), agent.currentUser.ID)
	managedPeer := managedPeerByNetwork(managedPeers, "net-1")

	unicast := buildIPv4PacketForChurnTest(t, "10.10.0.3", "10.10.0.2", []byte{1, 2, 3, 4})
	if agent.shouldAcceptInboundTransportPacketLocked(managedPeer, managedPeers, network, "", "peer-remote-old", unicast, time.Time{}) {
		t.Fatalf("expected stale peer inbound unicast to be rejected across a no-discovery virtual IP metadata gap")
	}
	if !agent.shouldAcceptInboundTransportPacketLocked(managedPeer, managedPeers, network, "", "peer-remote-new", unicast, time.Time{}) {
		t.Fatalf("expected replacement peer inbound unicast to be accepted across a no-discovery virtual IP metadata gap")
	}

	broadcast := buildIPv4PacketForChurnTest(t, "10.10.0.3", "10.10.0.255", []byte{5, 6, 7, 8})
	if agent.shouldAcceptInboundTransportPacketLocked(managedPeer, managedPeers, network, "", "peer-remote-old", broadcast, time.Time{}) {
		t.Fatalf("expected stale peer inbound flood packet to be rejected across a no-discovery virtual IP metadata gap")
	}
	if !agent.shouldAcceptInboundTransportPacketLocked(managedPeer, managedPeers, network, "", "peer-remote-new", broadcast, time.Time{}) {
		t.Fatalf("expected replacement peer inbound flood packet to be accepted across a no-discovery virtual IP metadata gap")
	}
}

func TestNetworkSignalingPrefersReplacementDirectTransport(t *testing.T) {
	reachability, connectionState := summarizeNetworkSignaling("peer-local", "net-1", []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-new",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
		{
			NetworkID:    "net-1",
			LocalPeerID:  "peer-other-local",
			RemotePeerID: "peer-unrelated",
			Reachability: "DIRECT",
			State:        "CONNECTED",
		},
	})
	if reachability != "DIRECT" || connectionState != "CONNECTED" {
		t.Fatalf("expected signaling summary to prefer replacement direct transport, got reachability=%q state=%q", reachability, connectionState)
	}
}

func TestTunnelNegotiationDeduplicatesSamePeerReplacement(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\tunnel-churn-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote-a",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-new",
			RemoteUserID:     "user-remote-a",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-other",
			RemoteUserID:     "user-remote-b",
			RemoteVirtualIP:  "10.10.0.4",
			TransportReady:   false,
			TransportMode:    "",
			Reachability:     "RELAY",
			State:            "RELAY_READY",
			AverageRTTMillis: 50,
			LastRTTMillis:    48,
		},
	}

	connections := agent.tunnelNegotiationConnectionsLocked()
	if len(connections) != 2 {
		t.Fatalf("expected tunnel negotiation set to deduplicate replacement peer and keep distinct target, got %#v", connections)
	}
	seen := map[string]bool{}
	for _, connection := range connections {
		seen[connection.RemotePeerID] = true
	}
	if !seen["peer-remote-new"] || !seen["peer-other"] || seen["peer-remote-old"] {
		t.Fatalf("expected tunnel negotiation to keep replacement and distinct peer only, got %#v", connections)
	}
}

func TestTunnelNegotiationDeduplicatesSamePeerReplacementWithoutUserMetadata(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\tunnel-metadata-churn-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-old",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-new",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-other",
			RemoteUserID:     "user-remote-b",
			RemoteVirtualIP:  "10.10.0.4",
			TransportReady:   false,
			TransportMode:    "",
			Reachability:     "RELAY",
			State:            "RELAY_READY",
			AverageRTTMillis: 50,
			LastRTTMillis:    48,
		},
	}

	connections := agent.tunnelNegotiationConnectionsLocked()
	if len(connections) != 2 {
		t.Fatalf("expected tunnel negotiation set to deduplicate same-overlay replacement without user metadata and keep distinct target, got %#v", connections)
	}
	seen := map[string]bool{}
	for _, connection := range connections {
		seen[connection.RemotePeerID] = true
	}
	if !seen["peer-remote-new"] || !seen["peer-other"] || seen["peer-remote-old"] {
		t.Fatalf("expected tunnel negotiation to keep replacement and distinct peer only when overlay IP continuity is the remaining identity, got %#v", connections)
	}
}

func TestAttachTunnelToConnectionsPropagatesMetadataToPreferredReplacementConnection(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\tunnel-attach-churn-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

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
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local-new",
			RemotePeerID:             "peer-remote-new",
			RemoteVirtualIP:          "10.10.0.3",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			Reachability:             "DIRECT",
			State:                    "CONNECTED",
			AverageRTTMillis:         12,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
	}

	agent.attachTunnelToConnections(controlclient.Tunnel{
		ID:        "tun-old",
		NetworkID: "net-1",
		PeerAID:   "peer-local-old",
		PeerBID:   "peer-remote-old",
		Mode:      "P2P",
		State:     "OPEN",
	})

	if agent.connections[1].TunnelID != "tun-old" || agent.connections[1].TunnelMode != "P2P" || agent.connections[1].TunnelState != "OPEN" {
		t.Fatalf("expected preferred replacement connection to inherit tunnel metadata during overlap, got %#v", agent.connections[1])
	}
	if agent.connections[0].TunnelID != "tun-old" || agent.connections[0].TunnelState != "OPEN" {
		t.Fatalf("expected exact stale pair to keep tunnel metadata while overlap is still present, got %#v", agent.connections[0])
	}
}

func TestAttachTunnelToConnectionsUsesEndpointContinuityForActiveReplacement(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\tunnel-attach-endpoint-continuity-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-local-new",
			RemotePeerID:             "peer-remote-new",
			RemoteEndpoint:           "198.51.100.10:5000",
			RemoteCandidates:         []string{"198.51.100.10:5000"},
			TransportReady:           true,
			TransportMode:            "DIRECT",
			Reachability:             "DIRECT",
			State:                    "CONNECTED",
			AverageRTTMillis:         12,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
	}

	agent.attachTunnelToConnections(controlclient.Tunnel{
		ID:        "tun-old",
		NetworkID: "net-1",
		PeerAID:   "peer-local-old",
		PeerBID:   "peer-remote-old",
		Mode:      "P2P",
		State:     "OPEN",
	})

	if agent.connections[1].TunnelID != "tun-old" || agent.connections[1].TunnelMode != "P2P" || agent.connections[1].TunnelState != "OPEN" {
		t.Fatalf("expected endpoint-continuity replacement connection to inherit tunnel metadata, got %#v", agent.connections[1])
	}
	if agent.connections[0].TunnelID != "tun-old" || agent.connections[0].TunnelState != "OPEN" {
		t.Fatalf("expected exact stale pair to keep tunnel metadata while endpoint-continuity overlap is still present, got %#v", agent.connections[0])
	}
}

func TestAttachTunnelToConnectionsFailsClosedForAmbiguousEndpointContinuity(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\tunnel-attach-endpoint-ambiguous-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 90,
			LastRTTMillis:    95,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-remote-new-a",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000"},
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-remote-new-b",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000"},
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 11,
			LastRTTMillis:    9,
		},
	}

	agent.attachTunnelToConnections(controlclient.Tunnel{
		ID:        "tun-old",
		NetworkID: "net-1",
		PeerAID:   "peer-local-old",
		PeerBID:   "peer-remote-old",
		Mode:      "P2P",
		State:     "OPEN",
	})

	if agent.connections[0].TunnelID != "tun-old" || agent.connections[0].TunnelState != "OPEN" {
		t.Fatalf("expected exact stale pair to keep tunnel metadata, got %#v", agent.connections[0])
	}
	for idx := 1; idx < len(agent.connections); idx++ {
		if agent.connections[idx].TunnelID != "" || agent.connections[idx].TunnelState != "" {
			t.Fatalf("expected ambiguous endpoint-continuity replacement %d to fail closed without tunnel metadata, got %#v", idx, agent.connections[idx])
		}
	}
}

func TestAttachTunnelToConnectionsDoesNotPropagateMetadataAcrossKnownDistinctUsers(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\tunnel-attach-distinct-users-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-a",
			RemoteUserID:     "user-remote-a",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-b",
			RemoteUserID:     "user-remote-b",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 11,
			LastRTTMillis:    9,
		},
	}

	agent.attachTunnelToConnections(controlclient.Tunnel{
		ID:        "tun-a",
		NetworkID: "net-1",
		PeerAID:   "peer-local",
		PeerBID:   "peer-remote-a",
		Mode:      "P2P",
		State:     "OPEN",
	})

	if agent.connections[0].TunnelID != "tun-a" || agent.connections[0].TunnelState != "OPEN" {
		t.Fatalf("expected exact tunnel pair to keep its metadata, got %#v", agent.connections[0])
	}
	if agent.connections[1].TunnelID != "" || agent.connections[1].TunnelState != "" {
		t.Fatalf("expected tunnel metadata to fail closed across known-distinct users sharing a claimed overlay IP, got %#v", agent.connections[1])
	}
}

func TestCleanupRemovedConnectionsKeepsReplacementTunnelMetadataAcrossPeerDisappearance(t *testing.T) {
	closeCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v1/tunnels/tun-old" {
			http.NotFound(w, r)
			return
		}
		closeCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"tun-old","networkId":"net-1","peerAId":"peer-local","peerBId":"peer-remote-old","mode":"P2P","state":"CLOSED"}}`))
	}))
	defer server.Close()

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(server.URL), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\cleanup-removed-tunnel-continuity-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.discoveredPeers["net-1"] = []controlclient.Peer{{
		ID:        "peer-remote-new",
		NetworkID: "net-1",
		UserID:    "user-remote",
		VirtualIP: "10.10.0.3",
		Status:    "ONLINE",
	}}

	previous := []ConnectionStatus{{
		NetworkID:       "net-1",
		LocalPeerID:     "peer-local",
		RemotePeerID:    "peer-remote-old",
		RemoteUserID:    "user-remote",
		RemoteVirtualIP: "10.10.0.3",
		TunnelID:        "tun-old",
		TunnelMode:      "P2P",
		TunnelState:     "OPEN",
	}}
	current := []ConnectionStatus{{
		NetworkID:    "net-1",
		LocalPeerID:  "peer-local",
		RemotePeerID: "peer-remote-new",
		State:        "CONNECTED",
		Reachability: "DIRECT",
	}}

	agent.cleanupRemovedConnectionsLocked(previous, current)

	if closeCalls != 0 {
		t.Fatalf("expected removed stale tunnel to stay open while a same-target replacement peer is already live, got closeCalls=%d", closeCalls)
	}
	if current[0].TunnelID != "tun-old" || current[0].TunnelMode != "P2P" || current[0].TunnelState != "OPEN" {
		t.Fatalf("expected replacement connection to inherit stale tunnel metadata after peer disappearance, got %#v", current[0])
	}
	if current[0].RemoteUserID != "user-remote" || current[0].RemoteVirtualIP != "10.10.0.3" {
		t.Fatalf("expected replacement connection to keep prior remote metadata after peer disappearance, got %#v", current[0])
	}
}

func TestCleanupRemovedConnectionsClosesTunnelForDistinctUserOverlayCollision(t *testing.T) {
	closeCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v1/tunnels/tun-old" {
			http.NotFound(w, r)
			return
		}
		closeCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"tun-old","networkId":"net-1","peerAId":"peer-local","peerBId":"peer-remote-old","mode":"P2P","state":"CLOSED"}}`))
	}))
	defer server.Close()

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(server.URL), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\cleanup-removed-tunnel-distinct-user-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.discoveredPeers["net-1"] = []controlclient.Peer{{
		ID:        "peer-remote-new",
		NetworkID: "net-1",
		UserID:    "user-other",
		VirtualIP: "10.10.0.3",
		Status:    "ONLINE",
	}}

	previous := []ConnectionStatus{{
		NetworkID:       "net-1",
		LocalPeerID:     "peer-local",
		RemotePeerID:    "peer-remote-old",
		RemoteUserID:    "user-remote",
		RemoteVirtualIP: "10.10.0.3",
		TunnelID:        "tun-old",
		TunnelMode:      "P2P",
		TunnelState:     "OPEN",
	}}
	current := []ConnectionStatus{{
		NetworkID:    "net-1",
		LocalPeerID:  "peer-local",
		RemotePeerID: "peer-remote-new",
		State:        "CONNECTED",
		Reachability: "DIRECT",
	}}

	agent.cleanupRemovedConnectionsLocked(previous, current)

	if closeCalls != 1 {
		t.Fatalf("expected stale tunnel to close when only a distinct-user overlay collision remains, got closeCalls=%d", closeCalls)
	}
	if current[0].TunnelID != "" || current[0].TunnelState != "" || current[0].RemoteUserID != "" {
		t.Fatalf("expected distinct-user collision to fail closed without inheriting stale tunnel metadata, got %#v", current[0])
	}
}

func TestCleanupRemovedConnectionsKeepsReplacementTunnelMetadataAcrossLocalPeerOverlap(t *testing.T) {
	closeCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v1/tunnels/tun-old" {
			http.NotFound(w, r)
			return
		}
		closeCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"tun-old","networkId":"net-1","peerAId":"peer-local-old","peerBId":"peer-remote-old","mode":"P2P","state":"CLOSED"}}`))
	}))
	defer server.Close()

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(server.URL), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\cleanup-removed-tunnel-local-peer-overlap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.discoveredPeers["net-1"] = []controlclient.Peer{{
		ID:        "peer-remote-new",
		NetworkID: "net-1",
		UserID:    "user-remote",
		VirtualIP: "10.10.0.3",
		Status:    "ONLINE",
	}}

	previous := []ConnectionStatus{{
		NetworkID:       "net-1",
		LocalPeerID:     "peer-local-old",
		RemotePeerID:    "peer-remote-old",
		RemoteUserID:    "user-remote",
		RemoteVirtualIP: "10.10.0.3",
		TunnelID:        "tun-old",
		TunnelMode:      "P2P",
		TunnelState:     "OPEN",
	}}
	current := []ConnectionStatus{{
		NetworkID:       "net-1",
		LocalPeerID:     "peer-local-new",
		RemotePeerID:    "peer-remote-new",
		State:           "CONNECTED",
		Reachability:    "DIRECT",
		TransportReady:  true,
		TransportMode:   "DIRECT",
		RemoteUserID:    "",
		RemoteVirtualIP: "",
	}}

	agent.cleanupRemovedConnectionsLocked(previous, current)

	if closeCalls != 0 {
		t.Fatalf("expected removed stale tunnel to stay open while an active local-peer replacement is already live, got closeCalls=%d", closeCalls)
	}
	if current[0].TunnelID != "tun-old" || current[0].TunnelMode != "P2P" || current[0].TunnelState != "OPEN" {
		t.Fatalf("expected active local-peer replacement to inherit stale tunnel metadata after overlap cleanup, got %#v", current[0])
	}
	if current[0].RemoteUserID != "user-remote" || current[0].RemoteVirtualIP != "10.10.0.3" {
		t.Fatalf("expected active local-peer replacement to keep prior remote metadata after overlap cleanup, got %#v", current[0])
	}
}

func TestCleanupRemovedConnectionsKeepsReplacementTunnelMetadataAcrossLocalPeerEndpointContinuity(t *testing.T) {
	closeCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v1/tunnels/tun-old" {
			http.NotFound(w, r)
			return
		}
		closeCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"tun-old","networkId":"net-1","peerAId":"peer-local-old","peerBId":"peer-remote-old","mode":"P2P","state":"CLOSED"}}`))
	}))
	defer server.Close()

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(server.URL), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\cleanup-removed-tunnel-local-peer-endpoint-continuity-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")

	previous := []ConnectionStatus{{
		NetworkID:        "net-1",
		LocalPeerID:      "peer-local-old",
		RemotePeerID:     "peer-remote-old",
		RemoteUserID:     "user-remote",
		RemoteVirtualIP:  "10.10.0.3",
		RemoteEndpoint:   "198.51.100.10:5000",
		RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
		TunnelID:         "tun-old",
		TunnelMode:       "P2P",
		TunnelState:      "OPEN",
	}}
	current := []ConnectionStatus{{
		NetworkID:        "net-1",
		LocalPeerID:      "peer-local-new",
		RemotePeerID:     "peer-remote-new",
		RemoteEndpoint:   "198.51.100.10:5000",
		RemoteCandidates: []string{"198.51.100.10:5000"},
		State:            "CONNECTED",
		Reachability:     "DIRECT",
		TransportReady:   true,
		TransportMode:    "DIRECT",
	}}

	agent.cleanupRemovedConnectionsLocked(previous, current)

	if closeCalls != 0 {
		t.Fatalf("expected removed stale tunnel to stay open while endpoint continuity identifies the active replacement, got closeCalls=%d", closeCalls)
	}
	if current[0].TunnelID != "tun-old" || current[0].TunnelMode != "P2P" || current[0].TunnelState != "OPEN" {
		t.Fatalf("expected endpoint-continuity replacement to inherit stale tunnel metadata after overlap cleanup, got %#v", current[0])
	}
	if current[0].RemoteUserID != "user-remote" || current[0].RemoteVirtualIP != "10.10.0.3" {
		t.Fatalf("expected endpoint-continuity replacement to keep prior remote metadata after overlap cleanup, got %#v", current[0])
	}
}

func TestCleanupRemovedConnectionsClosesTunnelWhenEndpointContinuityIsAmbiguousAcrossLocalPeerOverlap(t *testing.T) {
	closeCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v1/tunnels/tun-old" {
			http.NotFound(w, r)
			return
		}
		closeCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"tun-old","networkId":"net-1","peerAId":"peer-local-old","peerBId":"peer-remote-old","mode":"P2P","state":"CLOSED"}}`))
	}))
	defer server.Close()

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(server.URL), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\cleanup-removed-tunnel-local-peer-endpoint-ambiguous-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")

	previous := []ConnectionStatus{{
		NetworkID:        "net-1",
		LocalPeerID:      "peer-local-old",
		RemotePeerID:     "peer-remote-old",
		RemoteUserID:     "user-remote",
		RemoteVirtualIP:  "10.10.0.3",
		RemoteEndpoint:   "198.51.100.10:5000",
		RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
		TunnelID:         "tun-old",
		TunnelMode:       "P2P",
		TunnelState:      "OPEN",
	}}
	current := []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-remote-new-a",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000"},
			State:            "CONNECTED",
			Reachability:     "DIRECT",
			TransportReady:   true,
			TransportMode:    "DIRECT",
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-remote-new-b",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000"},
			State:            "CONNECTED",
			Reachability:     "DIRECT",
			TransportReady:   true,
			TransportMode:    "DIRECT",
		},
	}

	agent.cleanupRemovedConnectionsLocked(previous, current)

	if closeCalls != 1 {
		t.Fatalf("expected stale tunnel to close when endpoint continuity is ambiguous across replacements, got closeCalls=%d", closeCalls)
	}
	for _, connection := range current {
		if connection.TunnelID != "" || connection.TunnelState != "" || connection.RemoteUserID != "" || connection.RemoteVirtualIP != "" {
			t.Fatalf("expected ambiguous endpoint-continuity replacements to fail closed without inheriting stale metadata, got %#v", current)
		}
	}
}

func TestCleanupRemovedConnectionsClosesTunnelForDistinctUserCollisionAcrossLocalPeerOverlap(t *testing.T) {
	closeCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v1/tunnels/tun-old" {
			http.NotFound(w, r)
			return
		}
		closeCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"tun-old","networkId":"net-1","peerAId":"peer-local-old","peerBId":"peer-remote-old","mode":"P2P","state":"CLOSED"}}`))
	}))
	defer server.Close()

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(server.URL), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\cleanup-removed-tunnel-local-peer-overlap-distinct-user-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.discoveredPeers["net-1"] = []controlclient.Peer{{
		ID:        "peer-remote-new",
		NetworkID: "net-1",
		UserID:    "user-other",
		VirtualIP: "10.10.0.3",
		Status:    "ONLINE",
	}}

	previous := []ConnectionStatus{{
		NetworkID:       "net-1",
		LocalPeerID:     "peer-local-old",
		RemotePeerID:    "peer-remote-old",
		RemoteUserID:    "user-remote",
		RemoteVirtualIP: "10.10.0.3",
		TunnelID:        "tun-old",
		TunnelMode:      "P2P",
		TunnelState:     "OPEN",
	}}
	current := []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-local-new",
		RemotePeerID:   "peer-remote-new",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
		TransportReady: true,
		TransportMode:  "DIRECT",
	}}

	agent.cleanupRemovedConnectionsLocked(previous, current)

	if closeCalls != 1 {
		t.Fatalf("expected stale tunnel to close when local-peer overlap only leaves a distinct-user overlay collision, got closeCalls=%d", closeCalls)
	}
	if current[0].TunnelID != "" || current[0].TunnelState != "" || current[0].RemoteUserID != "" || current[0].RemoteVirtualIP != "" {
		t.Fatalf("expected local-peer overlap distinct-user collision to fail closed without inheriting stale tunnel metadata, got %#v", current[0])
	}
}

func TestReconcileNegotiationTunnelsKeepsProjectedReplacementTunnelDuringCreateLag(t *testing.T) {
	createCalls := 0
	closeCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/networks/net-1/tunnels":
			var req struct {
				PeerAID string `json:"peerAId"`
				PeerBID string `json:"peerBId"`
				Mode    string `json:"mode"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.PeerAID == "peer-local" && req.PeerBID == "peer-remote-new" {
				createCalls++
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"not found"}`))
				return
			}
			http.NotFound(w, r)
			return
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/networks/net-1/tunnels":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"tun-old","networkId":"net-1","peerAId":"peer-local","peerBId":"peer-remote-old","mode":"P2P","state":"OPEN"}]}`))
			return
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/tunnels/tun-old":
			closeCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"id":"tun-old","networkId":"net-1","peerAId":"peer-local","peerBId":"peer-remote-old","mode":"P2P","state":"CLOSED"}}`))
			return
		default:
			http.NotFound(w, r)
			return
		}
	}))
	defer server.Close()

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(server.URL), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\tunnel-create-lag-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{{
		NetworkID:       "net-1",
		LocalPeerID:     "peer-local",
		RemotePeerID:    "peer-remote-new",
		RemoteUserID:    "user-remote",
		RemoteVirtualIP: "10.10.0.3",
		State:           "CONNECTED",
		Reachability:    "DIRECT",
		TransportReady:  true,
		TransportMode:   "DIRECT",
		TunnelID:        "tun-old",
		TunnelMode:      "P2P",
		TunnelState:     "OPEN",
	}}

	if err := agent.reconcileNegotiationTunnelsLocked(); err != nil {
		t.Fatalf("reconcile negotiation tunnels during replacement create lag: %v", err)
	}
	if createCalls != 1 {
		t.Fatalf("expected replacement tunnel create to be attempted once before falling back to projected tunnel metadata, got %d", createCalls)
	}
	if closeCalls != 0 {
		t.Fatalf("expected stale projected tunnel to stay open during create lag, got closeCalls=%d", closeCalls)
	}
	if agent.connections[0].TunnelID != "tun-old" || agent.connections[0].TunnelMode != "P2P" || agent.connections[0].TunnelState != "OPEN" {
		t.Fatalf("expected replacement connection to keep projected stale tunnel metadata during create lag, got %#v", agent.connections[0])
	}
}

func TestGatewayHistoryIgnoresSameUserPeerReplacement(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-history-churn-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:        "net-full",
			GatewayRole:      "CLIENT",
			GatewayPeerID:    "peer-gateway-old",
			GatewayUserID:    "user-owner",
			GatewayVirtualIP: "10.10.0.3",
			Path:             "DIRECT",
			PolicyStatus:     "ACTIVE",
		},
	}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-gateway-new",
			RemoteUserID:     "user-owner",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 10,
			LastRTTMillis:    9,
		},
	}

	agent.observeGatewaySelectionsLocked([]virtualadapter.NetworkConfig{{
		NetworkID:        "net-full",
		RoutingPolicy:    "FULL",
		GatewayRole:      "CLIENT",
		GatewayPeerID:    "peer-gateway-new",
		PolicyStatusHint: "ACTIVE",
	}})

	if len(agent.gatewayHistory) != 0 {
		t.Fatalf("expected same-user gateway peer replacement to avoid false failover history, got %#v", agent.gatewayHistory)
	}
	selection := agent.gatewaySelections["net-full"]
	if selection.GatewayPeerID != "peer-gateway-new" || selection.GatewayUserID != "user-owner" || selection.Path != "DIRECT" {
		t.Fatalf("expected stored gateway selection to update to replacement peer without history noise, got %#v", selection)
	}
}

func TestGatewayHistoryIgnoresSamePeerReplacementWithoutUserMetadata(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-history-metadata-churn-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:        "net-full",
			GatewayRole:      "CLIENT",
			GatewayPeerID:    "peer-gateway-old",
			GatewayUserID:    "user-owner",
			GatewayVirtualIP: "10.10.0.3",
			Path:             "DIRECT",
			PolicyStatus:     "ACTIVE",
		},
	}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-gateway-new",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 10,
			LastRTTMillis:    9,
		},
	}

	agent.observeGatewaySelectionsLocked([]virtualadapter.NetworkConfig{{
		NetworkID:        "net-full",
		RoutingPolicy:    "FULL",
		GatewayRole:      "CLIENT",
		GatewayPeerID:    "peer-gateway-new",
		PolicyStatusHint: "ACTIVE",
	}})

	if len(agent.gatewayHistory) != 0 {
		t.Fatalf("expected same-overlay gateway peer replacement to avoid false failover history when replacement user metadata is temporarily missing, got %#v", agent.gatewayHistory)
	}
	selection := agent.gatewaySelections["net-full"]
	if selection.GatewayPeerID != "peer-gateway-new" || selection.GatewayVirtualIP != "10.10.0.3" || selection.Path != "DIRECT" {
		t.Fatalf("expected stored gateway selection to update to replacement peer without history noise when only overlay IP continuity is known, got %#v", selection)
	}
}

func TestGatewaySelectionKeepsPathWhenBindingStillPointsAtStalePeerDuringReplacementHandoff(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-binding-stale-peer-path-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:        "net-full",
			GatewayRole:      "CLIENT",
			GatewayPeerID:    "peer-gateway-old",
			GatewayUserID:    "user-owner",
			GatewayVirtualIP: "10.10.0.3",
			Path:             "DIRECT",
			PolicyStatus:     "ACTIVE",
		},
	}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-gateway-new",
			RemoteUserID:     "user-owner",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 10,
			LastRTTMillis:    9,
		},
	}

	agent.observeGatewaySelectionsLocked([]virtualadapter.NetworkConfig{{
		NetworkID:        "net-full",
		RoutingPolicy:    "FULL",
		GatewayRole:      "CLIENT",
		GatewayPeerID:    "peer-gateway-old",
		PolicyStatusHint: "ACTIVE",
	}})

	if len(agent.gatewayHistory) != 0 {
		t.Fatalf("expected stale binding handoff to keep current gateway path without noisy history, got %#v", agent.gatewayHistory)
	}
	selection := agent.gatewaySelections["net-full"]
	if selection.GatewayPeerID != "peer-gateway-old" || selection.GatewayUserID != "user-owner" || selection.GatewayVirtualIP != "10.10.0.3" || selection.Path != "DIRECT" {
		t.Fatalf("expected stored gateway selection to keep active path while binding still points at stale peer, got %#v", selection)
	}
}

func TestGatewaySelectionFailsClosedForDistinctUserOnStaleBindingHandoff(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-binding-stale-peer-distinct-user-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:        "net-full",
			GatewayRole:      "CLIENT",
			GatewayPeerID:    "peer-gateway-old",
			GatewayUserID:    "user-owner",
			GatewayVirtualIP: "10.10.0.3",
			Path:             "DIRECT",
			PolicyStatus:     "ACTIVE",
		},
	}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-gateway-other",
			RemoteUserID:     "user-other",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 10,
			LastRTTMillis:    9,
		},
	}

	agent.observeGatewaySelectionsLocked([]virtualadapter.NetworkConfig{{
		NetworkID:        "net-full",
		RoutingPolicy:    "FULL",
		GatewayRole:      "CLIENT",
		GatewayPeerID:    "peer-gateway-old",
		PolicyStatusHint: "ACTIVE",
	}})

	if len(agent.gatewayHistory) != 1 || agent.gatewayHistory[0].Event != "PATH_CHANGED" || agent.gatewayHistory[0].CurrentPath != "PENDING" {
		t.Fatalf("expected stale binding handoff to fail closed for a distinct user sharing the overlay IP, got %#v", agent.gatewayHistory)
	}
	selection := agent.gatewaySelections["net-full"]
	if selection.Path != "PENDING" {
		t.Fatalf("expected stored gateway selection to drop to pending for distinct-user overlay collision, got %#v", selection)
	}
}

func TestGatewaySelectionUsesPersistedConfigMetadataToFollowReplacementAfterRestart(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-binding-config-metadata-restart-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-gateway-new",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 10,
			LastRTTMillis:    9,
		},
	}

	agent.observeGatewaySelectionsLocked([]virtualadapter.NetworkConfig{{
		NetworkID:        "net-full",
		RoutingPolicy:    "FULL",
		GatewayRole:      "CLIENT",
		GatewayPeerID:    "peer-gateway-old",
		GatewayUserID:    "user-owner",
		GatewayVirtualIP: "10.10.0.3",
		PolicyStatusHint: "ACTIVE",
	}})

	if len(agent.gatewayHistory) != 1 || agent.gatewayHistory[0].Event != "SELECTED" || agent.gatewayHistory[0].CurrentPath != "DIRECT" {
		t.Fatalf("expected persisted gateway metadata to restore replacement path as an initial direct selection after restart, got %#v", agent.gatewayHistory)
	}
	selection := agent.gatewaySelections["net-full"]
	if selection.GatewayPeerID != "peer-gateway-old" || selection.GatewayUserID != "user-owner" || selection.GatewayVirtualIP != "10.10.0.3" || selection.Path != "DIRECT" {
		t.Fatalf("expected persisted gateway metadata to keep direct replacement path after restart, got %#v", selection)
	}
}

func TestGatewaySelectionKeepsPathWhenReplacementLacksVirtualIPAndDiscoveryMetadata(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-binding-metadata-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:        "net-full",
			GatewayRole:      "CLIENT",
			GatewayPeerID:    "peer-gateway-old",
			GatewayUserID:    "user-owner",
			GatewayVirtualIP: "10.10.0.3",
			Path:             "DIRECT",
			PolicyStatus:     "ACTIVE",
		},
	}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-gateway-new",
			RemoteUserID:     "user-owner",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 10,
			LastRTTMillis:    9,
		},
	}

	agent.observeGatewaySelectionsLocked([]virtualadapter.NetworkConfig{{
		NetworkID:        "net-full",
		RoutingPolicy:    "FULL",
		GatewayRole:      "CLIENT",
		GatewayPeerID:    "peer-gateway-old",
		PolicyStatusHint: "ACTIVE",
	}})

	if len(agent.gatewayHistory) != 0 {
		t.Fatalf("expected stale gateway binding to keep direct path when the only same-user replacement temporarily lacks virtual IP discovery metadata, got %#v", agent.gatewayHistory)
	}
	selection := agent.gatewaySelections["net-full"]
	if selection.GatewayPeerID != "peer-gateway-old" || selection.GatewayUserID != "user-owner" || selection.GatewayVirtualIP != "10.10.0.3" || selection.Path != "DIRECT" {
		t.Fatalf("expected stored gateway selection to keep direct replacement path through a temporary virtual IP metadata gap, got %#v", selection)
	}
}

func TestGatewaySelectionFailsClosedWhenMetadataGapMakesSameUserReplacementAmbiguous(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-binding-metadata-gap-ambiguous-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:        "net-full",
			GatewayRole:      "CLIENT",
			GatewayPeerID:    "peer-gateway-old",
			GatewayUserID:    "user-owner",
			GatewayVirtualIP: "10.10.0.3",
			Path:             "DIRECT",
			PolicyStatus:     "ACTIVE",
		},
	}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-gateway-new-a",
			RemoteUserID:     "user-owner",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 10,
			LastRTTMillis:    9,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-gateway-new-b",
			RemoteUserID:     "user-owner",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 11,
			LastRTTMillis:    10,
		},
	}

	agent.observeGatewaySelectionsLocked([]virtualadapter.NetworkConfig{{
		NetworkID:        "net-full",
		RoutingPolicy:    "FULL",
		GatewayRole:      "CLIENT",
		GatewayPeerID:    "peer-gateway-old",
		PolicyStatusHint: "ACTIVE",
	}})

	if len(agent.gatewayHistory) != 1 || agent.gatewayHistory[0].Event != "PATH_CHANGED" || agent.gatewayHistory[0].CurrentPath != "PENDING" {
		t.Fatalf("expected ambiguous same-user virtual IP metadata gap to fail closed instead of guessing a replacement gateway, got %#v", agent.gatewayHistory)
	}
	selection := agent.gatewaySelections["net-full"]
	if selection.Path != "PENDING" {
		t.Fatalf("expected stored gateway selection to drop to pending when the replacement target is ambiguous, got %#v", selection)
	}
}

func TestGatewaySelectionPrefersActiveLocalManagedPeerDuringOverlap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-local-peer-overlap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:        "net-full",
			GatewayRole:      "CLIENT",
			GatewayPeerID:    "peer-gateway",
			GatewayUserID:    "user-owner",
			GatewayVirtualIP: "10.10.0.3",
			Path:             "DIRECT",
			PolicyStatus:     "ACTIVE",
		},
	}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-gateway",
			RemoteUserID:     "user-owner",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 8,
			LastRTTMillis:    7,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-gateway",
			RemoteUserID:     "user-owner",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    78,
		},
	}

	agent.observeGatewaySelectionsLocked([]virtualadapter.NetworkConfig{{
		NetworkID:        "net-full",
		RoutingPolicy:    "FULL",
		GatewayRole:      "CLIENT",
		GatewayPeerID:    "peer-gateway",
		PolicyStatusHint: "ACTIVE",
	}})

	if len(agent.gatewayHistory) != 1 || agent.gatewayHistory[0].Event != "PATH_CHANGED" || agent.gatewayHistory[0].CurrentPath != "RELAY" {
		t.Fatalf("expected gateway selection to follow the active local managed peer path during overlap instead of stale local direct state, got %#v", agent.gatewayHistory)
	}
	selection := agent.gatewaySelections["net-full"]
	if selection.Path != "RELAY" || selection.GatewayPeerID != "peer-gateway" {
		t.Fatalf("expected stored gateway selection to keep the gateway target but follow the active local managed peer path, got %#v", selection)
	}
}

func TestGatewaySelectionDropsStaleLocalPeerPathWhenActiveLocalPeerHasNoConnection(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-local-peer-stale-only-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:        "net-full",
			GatewayRole:      "CLIENT",
			GatewayPeerID:    "peer-gateway",
			GatewayUserID:    "user-owner",
			GatewayVirtualIP: "10.10.0.3",
			Path:             "DIRECT",
			PolicyStatus:     "ACTIVE",
		},
	}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-gateway",
			RemoteUserID:     "user-owner",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 8,
			LastRTTMillis:    7,
		},
	}

	agent.observeGatewaySelectionsLocked([]virtualadapter.NetworkConfig{{
		NetworkID:        "net-full",
		RoutingPolicy:    "FULL",
		GatewayRole:      "CLIENT",
		GatewayPeerID:    "peer-gateway",
		PolicyStatusHint: "ACTIVE",
	}})

	if len(agent.gatewayHistory) != 1 || agent.gatewayHistory[0].Event != "PATH_CHANGED" || agent.gatewayHistory[0].CurrentPath != "PENDING" {
		t.Fatalf("expected gateway selection to stop reporting stale local direct path once only the superseded local peer remains, got %#v", agent.gatewayHistory)
	}
	selection := agent.gatewaySelections["net-full"]
	if selection.Path != "PENDING" || selection.GatewayPeerID != "peer-gateway" {
		t.Fatalf("expected stored gateway selection to keep the gateway target but drop stale local path visibility, got %#v", selection)
	}
}

func TestGatewaySelectionIgnoresStaleLocalPeerWhenMetadataGapOnlyAffectsActiveReplacement(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-local-peer-metadata-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:        "net-full",
			GatewayRole:      "CLIENT",
			GatewayPeerID:    "peer-gateway-old",
			GatewayUserID:    "user-owner",
			GatewayVirtualIP: "10.10.0.3",
			Path:             "DIRECT",
			PolicyStatus:     "ACTIVE",
		},
	}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-gateway-old",
			RemoteUserID:     "user-owner",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 8,
			LastRTTMillis:    7,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-gateway-new",
			RemoteUserID:     "user-owner",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    78,
		},
	}

	agent.observeGatewaySelectionsLocked([]virtualadapter.NetworkConfig{{
		NetworkID:        "net-full",
		RoutingPolicy:    "FULL",
		GatewayRole:      "CLIENT",
		GatewayPeerID:    "peer-gateway-old",
		PolicyStatusHint: "ACTIVE",
	}})

	if len(agent.gatewayHistory) != 1 || agent.gatewayHistory[0].Event != "PATH_CHANGED" || agent.gatewayHistory[0].CurrentPath != "RELAY" {
		t.Fatalf("expected gateway selection to ignore stale local-peer ambiguity and follow the active replacement path through a metadata gap, got %#v", agent.gatewayHistory)
	}
	selection := agent.gatewaySelections["net-full"]
	if selection.Path != "RELAY" || selection.GatewayPeerID != "peer-gateway-old" || selection.GatewayVirtualIP != "10.10.0.3" {
		t.Fatalf("expected stored gateway selection to keep the gateway target metadata while following the active replacement path through a metadata gap, got %#v", selection)
	}
}

func TestGatewaySelectionUsesEndpointContinuityForActiveReplacementDuringMetadataGap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-local-peer-endpoint-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:        "net-full",
			GatewayRole:      "CLIENT",
			GatewayPeerID:    "peer-gateway-old",
			GatewayUserID:    "user-owner",
			GatewayVirtualIP: "10.10.0.3",
			Path:             "DIRECT",
			PolicyStatus:     "ACTIVE",
		},
	}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-gateway-old",
			RemoteUserID:     "user-owner",
			RemoteVirtualIP:  "10.10.0.3",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 8,
			LastRTTMillis:    7,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-gateway-new",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    78,
		},
	}

	agent.observeGatewaySelectionsLocked([]virtualadapter.NetworkConfig{{
		NetworkID:        "net-full",
		RoutingPolicy:    "FULL",
		GatewayRole:      "CLIENT",
		GatewayPeerID:    "peer-gateway-old",
		PolicyStatusHint: "ACTIVE",
	}})

	if len(agent.gatewayHistory) != 1 || agent.gatewayHistory[0].Event != "PATH_CHANGED" || agent.gatewayHistory[0].CurrentPath != "RELAY" {
		t.Fatalf("expected gateway selection to follow the active replacement path through endpoint continuity when remote metadata is blank, got %#v", agent.gatewayHistory)
	}
	selection := agent.gatewaySelections["net-full"]
	if selection.Path != "RELAY" || selection.GatewayPeerID != "peer-gateway-old" || selection.GatewayUserID != "user-owner" || selection.GatewayVirtualIP != "10.10.0.3" {
		t.Fatalf("expected stored gateway selection to preserve gateway target metadata while following endpoint-continuity replacement path, got %#v", selection)
	}
}

func TestGatewaySelectionEndpointContinuityFailsClosedForDistinctKnownTargetCollision(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\gateway-local-peer-endpoint-gap-ambiguous-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-full", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.gatewaySelections = map[string]gatewaySelectionState{
		"net-full": {
			NetworkID:        "net-full",
			GatewayRole:      "CLIENT",
			GatewayPeerID:    "peer-gateway-old",
			GatewayUserID:    "user-owner",
			GatewayVirtualIP: "10.10.0.3",
			Path:             "DIRECT",
			PolicyStatus:     "ACTIVE",
		},
	}
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-gateway-old",
			RemoteUserID:     "user-owner",
			RemoteVirtualIP:  "10.10.0.3",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 8,
			LastRTTMillis:    7,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-gateway-new",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    78,
		},
		{
			NetworkID:        "net-full",
			LocalPeerID:      "peer-local-shadow",
			RemotePeerID:     "peer-collision",
			RemoteUserID:     "user-other",
			RemoteVirtualIP:  "10.10.0.44",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    11,
		},
	}

	agent.observeGatewaySelectionsLocked([]virtualadapter.NetworkConfig{{
		NetworkID:        "net-full",
		RoutingPolicy:    "FULL",
		GatewayRole:      "CLIENT",
		GatewayPeerID:    "peer-gateway-old",
		PolicyStatusHint: "ACTIVE",
	}})

	if len(agent.gatewayHistory) != 1 || agent.gatewayHistory[0].Event != "PATH_CHANGED" || agent.gatewayHistory[0].CurrentPath != "PENDING" {
		t.Fatalf("expected gateway endpoint continuity to fail closed when a distinct known target collides on the same endpoint key, got %#v", agent.gatewayHistory)
	}
	selection := agent.gatewaySelections["net-full"]
	if selection.Path != "PENDING" || selection.GatewayPeerID != "peer-gateway-old" {
		t.Fatalf("expected stored gateway selection to drop to pending on endpoint-continuity ambiguity, got %#v", selection)
	}
}

func TestStatusDeduplicatesSamePeerReplacementNeighbors(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\status-neighbor-churn-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	agent.neighbors = []NeighborStatus{
		{
			NetworkID:          "net-1",
			LocalPeerID:        "peer-local",
			RemotePeerID:       "peer-remote-old",
			RemoteUserID:       "user-remote",
			RemoteVirtualIP:    "10.10.0.3",
			Presence:           "online",
			NeighborState:      "CONNECTED",
			Reachability:       "RELAY",
			CandidateCount:     1,
			TransportReady:     true,
			TransportMode:      "RELAY",
			LastSeenUnix:       100,
			LastSignaledAtUnix: 101,
		},
		{
			NetworkID:          "net-1",
			LocalPeerID:        "peer-local",
			RemotePeerID:       "peer-remote-new",
			RemoteUserID:       "user-remote",
			RemoteVirtualIP:    "10.10.0.3",
			Presence:           "online",
			NeighborState:      "CONNECTED",
			Reachability:       "DIRECT",
			CandidateCount:     2,
			TransportReady:     true,
			TransportMode:      "DIRECT",
			LastSeenUnix:       120,
			LastSignaledAtUnix: 121,
		},
	}
	agent.mu.Unlock()

	status := agent.Status()
	if len(status.Neighbors) != 1 {
		t.Fatalf("expected status neighbor snapshot to deduplicate same-peer replacement, got %#v", status.Neighbors)
	}
	if status.Neighbors[0].RemotePeerID != "peer-remote-new" || status.Neighbors[0].TransportMode != "DIRECT" || status.Neighbors[0].CandidateCount != 2 {
		t.Fatalf("expected status neighbor snapshot to keep replacement direct peer, got %#v", status.Neighbors[0])
	}
}

func TestStatusDeduplicatesSamePeerReplacementNeighborsWithMissingVirtualIPMetadata(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\status-neighbor-virtualip-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	agent.discoveredPeers["net-1"] = []controlclient.Peer{{
		ID:        "peer-remote-new",
		NetworkID: "net-1",
		UserID:    "user-remote",
		VirtualIP: "10.10.0.3",
		Status:    "ONLINE",
	}}
	agent.neighbors = []NeighborStatus{
		{
			NetworkID:          "net-1",
			LocalPeerID:        "peer-local",
			RemotePeerID:       "peer-remote-old",
			RemoteUserID:       "user-remote",
			RemoteVirtualIP:    "10.10.0.3",
			Presence:           "online",
			NeighborState:      "CONNECTED",
			Reachability:       "RELAY",
			CandidateCount:     1,
			TransportReady:     true,
			TransportMode:      "RELAY",
			LastSeenUnix:       100,
			LastSignaledAtUnix: 101,
		},
		{
			NetworkID:          "net-1",
			LocalPeerID:        "peer-local",
			RemotePeerID:       "peer-remote-new",
			Presence:           "online",
			NeighborState:      "CONNECTED",
			Reachability:       "DIRECT",
			CandidateCount:     2,
			TransportReady:     true,
			TransportMode:      "DIRECT",
			LastSeenUnix:       120,
			LastSignaledAtUnix: 121,
		},
	}
	agent.mu.Unlock()

	status := agent.Status()
	if len(status.Neighbors) != 1 {
		t.Fatalf("expected status neighbor snapshot to deduplicate same-peer replacement when replacement metadata is missing, got %#v", status.Neighbors)
	}
	if status.Neighbors[0].RemotePeerID != "peer-remote-new" || status.Neighbors[0].TransportMode != "DIRECT" || status.Neighbors[0].CandidateCount != 2 || status.Neighbors[0].RemoteVirtualIP != "10.10.0.3" {
		t.Fatalf("expected status neighbor snapshot to keep replacement direct peer and backfill metadata, got %#v", status.Neighbors[0])
	}
}

func TestStatusKeepsDistinctUsersOnNeighborOverlayCollision(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\status-neighbor-distinct-user-collision-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	agent.neighbors = []NeighborStatus{
		{
			NetworkID:          "net-1",
			LocalPeerID:        "peer-local",
			RemotePeerID:       "peer-owner",
			RemoteUserID:       "user-owner",
			RemoteVirtualIP:    "10.10.0.3",
			Presence:           "online",
			NeighborState:      "CONNECTED",
			Reachability:       "DIRECT",
			CandidateCount:     2,
			TransportReady:     true,
			TransportMode:      "DIRECT",
			LastSeenUnix:       120,
			LastSignaledAtUnix: 121,
		},
		{
			NetworkID:          "net-1",
			LocalPeerID:        "peer-local",
			RemotePeerID:       "peer-other",
			RemoteUserID:       "user-other",
			RemoteVirtualIP:    "10.10.0.3",
			Presence:           "online",
			NeighborState:      "CONNECTED",
			Reachability:       "RELAY",
			CandidateCount:     1,
			TransportReady:     true,
			TransportMode:      "RELAY",
			LastSeenUnix:       100,
			LastSignaledAtUnix: 101,
		},
	}
	agent.mu.Unlock()

	status := agent.Status()
	if len(status.Neighbors) != 2 {
		t.Fatalf("expected status neighbor snapshot to fail closed on distinct-user overlay collision, got %#v", status.Neighbors)
	}
}

func TestStatusDeduplicatesSamePeerReplacementConnections(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\status-connection-churn-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    85,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local",
			RemotePeerID:     "peer-remote-new",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 12,
			LastRTTMillis:    10,
		},
	}
	agent.mu.Unlock()

	status := agent.Status()
	if len(status.Connections) != 1 {
		t.Fatalf("expected status connection snapshot to deduplicate same-peer replacement, got %#v", status.Connections)
	}
	if status.Connections[0].RemotePeerID != "peer-remote-new" || status.Connections[0].TransportMode != "DIRECT" || status.Connections[0].Reachability != "DIRECT" {
		t.Fatalf("expected status connection snapshot to keep replacement direct peer, got %#v", status.Connections[0])
	}
}

func TestStatusPrefersActiveLocalPeerConnectionDuringSameDeviceOverlap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\status-local-peer-overlap-connection-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-remote",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 8,
			LastRTTMillis:    7,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-remote",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    78,
		},
	}
	agent.mu.Unlock()

	status := agent.Status()
	if len(status.Connections) != 1 {
		t.Fatalf("expected status connection snapshot to collapse stale-vs-active local-peer overlap, got %#v", status.Connections)
	}
	if status.Connections[0].LocalPeerID != "peer-local-new" || status.Connections[0].TransportMode != "RELAY" {
		t.Fatalf("expected status connection snapshot to follow the active managed local peer during overlap, got %#v", status.Connections[0])
	}
}

func TestStatusPrefersActiveLocalPeerConnectionAcrossEndpointMetadataGap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\status-local-peer-endpoint-gap-connection-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-old",
			RemotePeerID:     "peer-remote-old",
			RemoteUserID:     "user-remote",
			RemoteVirtualIP:  "10.10.0.3",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000", "203.0.113.10:6000"},
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 8,
			LastRTTMillis:    7,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-local-new",
			RemotePeerID:     "peer-remote-new",
			RemoteEndpoint:   "198.51.100.10:5000",
			RemoteCandidates: []string{"198.51.100.10:5000"},
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    78,
		},
	}
	agent.mu.Unlock()

	status := agent.Status()
	if len(status.Connections) != 1 {
		t.Fatalf("expected status connection snapshot to collapse endpoint-continuity local-peer overlap, got %#v", status.Connections)
	}
	if status.Connections[0].LocalPeerID != "peer-local-new" || status.Connections[0].RemotePeerID != "peer-remote-new" || status.Connections[0].TransportMode != "RELAY" {
		t.Fatalf("expected status connection snapshot to follow active endpoint-continuity replacement, got %#v", status.Connections[0])
	}
}

func TestStatusDeduplicatesDiscoveredPeerCountForSameUserReplacement(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\status-discovered-churn-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	agent.discoveredPeers = map[string][]controlclient.Peer{
		"net-1": {
			{ID: "peer-old", UserID: "user-remote", VirtualIP: "10.10.0.3"},
			{ID: "peer-new", UserID: "user-remote", VirtualIP: "10.10.0.3"},
			{ID: "peer-other", UserID: "user-other", VirtualIP: "10.10.0.4"},
		},
	}
	agent.mu.Unlock()

	status := agent.Status()
	if status.DiscoveredPeerCount != 2 {
		t.Fatalf("expected discovered peer count to deduplicate same-user replacement, got %d", status.DiscoveredPeerCount)
	}
}

func TestStatusDeduplicatesDiscoveredPeerCountForReplacementWithoutUserMetadata(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\status-discovered-metadata-gap-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	agent.discoveredPeers = map[string][]controlclient.Peer{
		"net-1": {
			{ID: "peer-old", VirtualIP: "10.10.0.3"},
			{ID: "peer-new", VirtualIP: "10.10.0.3"},
			{ID: "peer-other", UserID: "user-other", VirtualIP: "10.10.0.4"},
		},
	}
	agent.mu.Unlock()

	status := agent.Status()
	if status.DiscoveredPeerCount != 2 {
		t.Fatalf("expected discovered peer count to deduplicate replacement peer even without user metadata, got %d", status.DiscoveredPeerCount)
	}
}

func TestStatusPrefersActiveLocalPeerNeighborDuringSameDeviceOverlap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(t.TempDir()+"\\status-local-peer-overlap-neighbor-state.json"), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	agent.currentUser = &controlclient.User{ID: "user-local", Email: "local@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-local-new", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.2")
	agent.neighbors = []NeighborStatus{
		{
			NetworkID:          "net-1",
			LocalPeerID:        "peer-local-old",
			RemotePeerID:       "peer-remote",
			RemoteUserID:       "user-remote",
			RemoteVirtualIP:    "10.10.0.3",
			Presence:           "online",
			NeighborState:      "CONNECTED",
			Reachability:       "DIRECT",
			CandidateCount:     2,
			TransportReady:     true,
			TransportMode:      "DIRECT",
			LastSeenUnix:       120,
			LastSignaledAtUnix: 121,
		},
		{
			NetworkID:          "net-1",
			LocalPeerID:        "peer-local-new",
			RemotePeerID:       "peer-remote",
			RemoteUserID:       "user-remote",
			RemoteVirtualIP:    "10.10.0.3",
			Presence:           "online",
			NeighborState:      "CONNECTED",
			Reachability:       "RELAY",
			CandidateCount:     1,
			TransportReady:     true,
			TransportMode:      "RELAY",
			LastSeenUnix:       100,
			LastSignaledAtUnix: 101,
		},
	}
	agent.mu.Unlock()

	status := agent.Status()
	if len(status.Neighbors) != 1 {
		t.Fatalf("expected status neighbor snapshot to collapse stale-vs-active local-peer overlap, got %#v", status.Neighbors)
	}
	if status.Neighbors[0].LocalPeerID != "peer-local-new" || status.Neighbors[0].TransportMode != "RELAY" {
		t.Fatalf("expected status neighbor snapshot to follow the active managed local peer during overlap, got %#v", status.Neighbors[0])
	}
}

func buildIPv4PacketForChurnTest(t *testing.T, sourceIP, destinationIP string, payload []byte) []byte {
	t.Helper()
	source := net.ParseIP(sourceIP).To4()
	destination := net.ParseIP(destinationIP).To4()
	if source == nil || destination == nil {
		t.Fatalf("parse IPv4 packet endpoints: %q -> %q", sourceIP, destinationIP)
	}
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], source)
	copy(packet[16:20], destination)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[20:], payload)
	return packet
}
