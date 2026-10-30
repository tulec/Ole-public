package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/virtualadapter"
	"strings"
	"testing"
	"time"
)

func TestSummarizeDiagnosticsUsageCountsDirectAndRelayConnections(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{
			Enabled:         true,
			Available:       true,
			SessionActive:   true,
			ConnectionState: "UP",
			DesiredMTU:      1380,
			MTU:             1380,
			DNSServers:      []string{"127.0.0.1"},
			DNSSuffix:       "ole",
		},
		[]NeighborStatus{
			{
				NetworkID:          "net-1",
				Presence:           "online",
				NeighborState:      "CONNECTED",
				Reachability:       "DIRECT",
				CandidateCount:     2,
				TransportReady:     true,
				TransportMode:      "DIRECT",
				LastSeenUnix:       205,
				LastSignaledAtUnix: 206,
			},
			{
				NetworkID:          "net-1",
				Presence:           "offline",
				NeighborState:      "NEGOTIATING",
				Reachability:       "RELAY",
				CandidateCount:     1,
				TransportReady:     false,
				TransportMode:      "",
				LastSeenUnix:       180,
				LastSignaledAtUnix: 190,
			},
			{
				NetworkID:          "net-1",
				Presence:           "recent",
				NeighborState:      "RELAY_READY",
				Reachability:       "RELAY",
				CandidateCount:     3,
				TransportReady:     true,
				TransportMode:      "RELAY",
				LastSeenUnix:       210,
				LastSignaledAtUnix: 215,
			},
		},
		[]ConnectionStatus{
			{
				NetworkID:            "net-1",
				RemotePeerID:         "peer-2",
				Reachability:         "DIRECT",
				State:                "CONNECTED",
				TransportReady:       true,
				TransportMode:        "DIRECT",
				TransportPacketCount: 5,
				LastTransportUnix:    100,
				LastRTTMillis:        18,
				AverageRTTMillis:     20,
			},
			{
				NetworkID:            "net-1",
				Reachability:         "RELAY",
				State:                "CONNECTED",
				TransportReady:       true,
				TransportMode:        "RELAY",
				TransportPacketCount: 7,
				LastTransportUnix:    200,
				LastRTTMillis:        42,
				AverageRTTMillis:     40,
				ConsecutiveLosses:    2,
			},
			{
				NetworkID:         "net-1",
				Reachability:      "DIRECT",
				State:             "DIRECT_CANDIDATE",
				TransportMode:     "",
				LastRTTMillis:     0,
				AverageRTTMillis:  0,
				ConsecutiveLosses: 1,
			},
			{
				NetworkID:     "net-1",
				Reachability:  "RELAY",
				State:         "RELAY_READY",
				TunnelMode:    "RELAY",
				TunnelState:   "NEGOTIATING",
				TransportMode: "",
			},
		},
		[]virtualadapter.NetworkBinding{
			{
				NetworkID:        "net-1",
				RoutingPolicy:    "FULL",
				PolicyStatus:     "ACTIVE",
				GatewayRole:      "CLIENT",
				GatewayPeerID:    "peer-2",
				IPAddressVisible: true,
				RouteVisible:     true,
			},
		},
		[]controlclient.Peer{
			{ID: "peer-1", Status: "ONLINE"},
			{ID: "peer-2", Status: "ONLINE"},
			{ID: "peer-3", Status: "OFFLINE"},
		},
		[]controlclient.Tunnel{
			{ID: "tun-1", State: "OPEN", Mode: "P2P"},
			{ID: "tun-2", State: "OPEN", Mode: "RELAY"},
			{ID: "tun-3", State: "NEGOTIATING", Mode: "RELAY"},
		},
		[]GatewayChangeEvent{
			{NetworkID: "net-1", Event: "SELECTED", ChangedAtUnix: 50},
			{NetworkID: "net-1", Event: "FAILOVER", ChangedAtUnix: 75},
		},
		[]GroupTrafficDiagnostics{
			{
				NetworkID:            "net-1",
				Policy:               "FLOOD",
				BlockedPacketCount:   1,
				FloodPacketCount:     2,
				FanoutCopyCount:      4,
				BroadcastPacketCount: 3,
				MulticastPacketCount: 1,
				LastAction:           "FLOOD",
				LastPacketUnix:       210,
			},
		},
		1,
	)

	if summary.NetworkCount != 1 || summary.PeerCount != 3 || summary.OnlinePeerCount != 2 {
		t.Fatalf("expected network and peer counts in summary, got %#v", summary)
	}
	if summary.ConnectionCount != 4 || summary.ConnectedCount != 2 {
		t.Fatalf("expected connection counts in summary, got %#v", summary)
	}
	if summary.DirectConnectedCount != 1 || summary.RelayConnectedCount != 1 {
		t.Fatalf("expected direct/relay connected counts in summary, got %#v", summary)
	}
	if summary.DirectCandidateCount != 1 || summary.RelayReadyCount != 1 {
		t.Fatalf("expected candidate/relay-ready counts in summary, got %#v", summary)
	}
	if summary.TransportReadyCount != 2 || summary.DirectTransportCount != 1 || summary.RelayTransportCount != 1 {
		t.Fatalf("expected transport counts in summary, got %#v", summary)
	}
	if summary.TotalTransportPacketCount != 12 || summary.DirectTransportPacketCount != 5 || summary.RelayTransportPacketCount != 7 {
		t.Fatalf("expected transport packet counters in summary, got %#v", summary)
	}
	if summary.OpenTunnelCount != 2 || summary.OpenP2PTunnelCount != 1 || summary.OpenRelayTunnelCount != 1 {
		t.Fatalf("expected open tunnel counts in summary, got %#v", summary)
	}
	if summary.AverageRTTMillis != 30 || summary.MaxRTTMillis != 42 || summary.MaxConsecutiveLosses != 2 {
		t.Fatalf("expected RTT/loss summary in summary, got %#v", summary)
	}
	if summary.Neighbors == nil {
		t.Fatalf("expected explicit neighbor rollup in summary, got %#v", summary)
	}
	if summary.Neighbors.NeighborCount != 3 ||
		summary.Neighbors.OnlineCount != 1 ||
		summary.Neighbors.RecentCount != 1 ||
		summary.Neighbors.OfflineCount != 1 ||
		summary.Neighbors.TransportReadyCount != 2 ||
		summary.Neighbors.ConnectedCount != 1 ||
		summary.Neighbors.PendingCount != 2 ||
		summary.Neighbors.DirectReachabilityCount != 1 ||
		summary.Neighbors.RelayReachabilityCount != 2 ||
		summary.Neighbors.DirectTransportCount != 1 ||
		summary.Neighbors.RelayTransportCount != 1 ||
		summary.Neighbors.MaxCandidateCount != 3 ||
		summary.Neighbors.LastSeenUnix != 210 ||
		summary.Neighbors.LastSignaledAtUnix != 215 {
		t.Fatalf("expected neighbor rollup in summary, got %#v", summary.Neighbors)
	}
	if summary.AdapterNeighbor == nil {
		t.Fatalf("expected explicit adapter-neighbor correlation in summary, got %#v", summary)
	}
	if summary.AdapterNeighbor.NetworkCount != 1 ||
		summary.AdapterNeighbor.AlignedCount != 1 ||
		summary.AdapterNeighbor.ReadyNeighborCount != 2 ||
		summary.AdapterNeighbor.HealthyBindingCount != 1 ||
		summary.AdapterNeighbor.MostSevereState != "ALIGNED" ||
		summary.AdapterNeighbor.AffectedNetworkID != "net-1" {
		t.Fatalf("expected aligned adapter-neighbor correlation in summary, got %#v", summary.AdapterNeighbor)
	}
	if summary.ConnectionState == nil {
		t.Fatalf("expected explicit connection-state rollup in summary, got %#v", summary)
	}
	if summary.ConnectionState.ConnectionCount != 4 ||
		summary.ConnectionState.ConnectedCount != 2 ||
		summary.ConnectionState.DirectCandidateCount != 1 ||
		summary.ConnectionState.RelayReadyCount != 1 ||
		summary.ConnectionState.ErrorCount != 0 ||
		summary.ConnectionState.SelectedCandidateCount != 0 ||
		summary.ConnectionState.TunnelOpenCount != 0 ||
		summary.ConnectionState.TunnelNegotiatingCount != 1 ||
		summary.ConnectionState.TransportReadyCount != 2 ||
		summary.ConnectionState.DirectPathCount != 2 ||
		summary.ConnectionState.RelayPathCount != 2 ||
		summary.ConnectionState.LastAttemptUnix != 0 ||
		summary.ConnectionState.NextRetryUnix != 0 ||
		summary.ConnectionState.MostSevereState != "MIXED" ||
		!strings.Contains(summary.ConnectionState.Hint, "established") {
		t.Fatalf("expected connection-state rollup in summary, got %#v", summary.ConnectionState)
	}
	if summary.Adapter == nil {
		t.Fatalf("expected explicit adapter rollup in summary, got %#v", summary)
	}
	if !summary.Adapter.Enabled ||
		!summary.Adapter.Available ||
		!summary.Adapter.SessionActive ||
		summary.Adapter.ConnectionState != "UP" ||
		summary.Adapter.BindingCount != 1 ||
		summary.Adapter.FullBindingCount != 1 ||
		summary.Adapter.ActivePolicyCount != 1 ||
		summary.Adapter.VisibleIPCount != 1 ||
		summary.Adapter.VisibleRouteCount != 1 ||
		summary.Adapter.HealthyBindingCount != 1 ||
		summary.Adapter.DesiredMTU != 1380 ||
		summary.Adapter.CurrentMTU != 1380 ||
		summary.Adapter.DNSServerCount != 1 ||
		!summary.Adapter.HasDNSSuffix ||
		summary.Adapter.HasError {
		t.Fatalf("expected adapter rollup in summary, got %#v", summary.Adapter)
	}
	if summary.Transport == nil {
		t.Fatalf("expected explicit transport rollup in summary, got %#v", summary)
	}
	if summary.Transport.Quality != "degraded" ||
		summary.Transport.HealthyConnectionCount != 1 ||
		summary.Transport.DegradedConnectionCount != 1 ||
		summary.Transport.PendingConnectionCount != 1 ||
		summary.Transport.FallbackReadyCount != 1 ||
		summary.Transport.ConnectedDirectCount != 1 ||
		summary.Transport.ConnectedRelayCount != 1 ||
		summary.Transport.TotalTransportPacketCount != 12 ||
		summary.Transport.LastTransportUnix != 200 {
		t.Fatalf("expected transport rollup in summary, got %#v", summary.Transport)
	}
	if summary.Gateway == nil {
		t.Fatalf("expected explicit gateway rollup in summary, got %#v", summary)
	}
	if summary.Gateway.ChangeCount != 2 || summary.Gateway.SelectionCount != 1 || summary.Gateway.FailoverCount != 1 || summary.Gateway.LastChangeUnix != 75 || summary.Gateway.LastEvent != "FAILOVER" {
		t.Fatalf("expected gateway rollup in summary, got %#v", summary.Gateway)
	}
	if summary.GroupTraffic == nil {
		t.Fatalf("expected explicit group-traffic rollup in summary, got %#v", summary)
	}
	if summary.GroupTraffic.Policy != "FLOOD" ||
		summary.GroupTraffic.BlockedPacketCount != 1 ||
		summary.GroupTraffic.FloodEventCount != 2 ||
		summary.GroupTraffic.FanoutCopyCount != 4 ||
		summary.GroupTraffic.BroadcastPacketCount != 3 ||
		summary.GroupTraffic.MulticastPacketCount != 1 ||
		summary.GroupTraffic.LastAction != "FLOOD" ||
		summary.GroupTraffic.LastPacketUnix != 210 {
		t.Fatalf("expected group-traffic rollup in summary, got %#v", summary.GroupTraffic)
	}
	if summary.GatewayCurrent == nil {
		t.Fatalf("expected explicit current gateway rollup in summary, got %#v", summary)
	}
	if summary.GatewayCurrent.FullNetworkCount != 1 ||
		summary.GatewayCurrent.ActiveNetworkCount != 1 ||
		summary.GatewayCurrent.ClientGatewayCount != 1 ||
		summary.GatewayCurrent.DirectPathCount != 1 ||
		summary.GatewayCurrent.CurrentNetworkID != "net-1" ||
		summary.GatewayCurrent.CurrentGatewayRole != "CLIENT" ||
		summary.GatewayCurrent.CurrentGatewayPeerID != "peer-2" ||
		summary.GatewayCurrent.CurrentPath != "DIRECT" ||
		summary.GatewayCurrent.CurrentPolicyStatus != "ACTIVE" ||
		summary.GatewayCurrent.CurrentConnectionState != "CONNECTED" {
		t.Fatalf("expected current gateway rollup in summary, got %#v", summary.GatewayCurrent)
	}
	if summary.RecentErrors != nil {
		t.Fatalf("expected recent-error rollup to stay empty when no connection errors exist, got %#v", summary.RecentErrors)
	}
	if summary.TransportSessions == nil {
		t.Fatalf("expected transport-session rollup in summary, got %#v", summary)
	}
	if summary.TransportSessions.SessionCount != 2 ||
		summary.TransportSessions.DirectSessionCount != 1 ||
		summary.TransportSessions.RelaySessionCount != 1 ||
		summary.TransportSessions.RekeyScheduledCount != 0 ||
		summary.TransportSessions.MostSevereState != "ACTIVE" {
		t.Fatalf("expected active transport-session rollup in summary, got %#v", summary.TransportSessions)
	}
}

func TestApplyDirectMetricsToUsageSummary(t *testing.T) {
	summary := applyDirectMetricsToUsageSummary(DiagnosticsUsageSummary{}, DirectConnectMetrics{
		AttemptCount:         5,
		SuccessCount:         3,
		FailureCount:         2,
		SuccessRatePct:       60,
		RelayFallbackCount:   2,
		FailbackSuccessCount: 1,
	})

	if summary.DirectAttemptCount != 5 || summary.DirectSuccessCount != 3 || summary.DirectFailureCount != 2 {
		t.Fatalf("expected direct attempt counters in usage summary, got %#v", summary)
	}
	if summary.DirectSuccessRatePct != 60 || summary.RelayFallbackCount != 2 || summary.DirectFailbackSuccessCount != 1 {
		t.Fatalf("expected direct success/fallback counters in usage summary, got %#v", summary)
	}
}

func TestSummarizeDiagnosticsUsageCountsGatewayFailback(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{},
		nil,
		nil,
		nil,
		nil,
		nil,
		[]GatewayChangeEvent{
			{NetworkID: "net-1", Event: "FAILOVER", ChangedAtUnix: 50},
			{NetworkID: "net-1", Event: "FAILBACK", ChangedAtUnix: 75},
		},
		nil,
		1,
	)

	if summary.Gateway == nil {
		t.Fatalf("expected explicit gateway rollup in summary, got %#v", summary)
	}
	if summary.Gateway.ChangeCount != 2 || summary.Gateway.FailoverCount != 1 || summary.Gateway.FailbackCount != 1 || summary.Gateway.LastEvent != "FAILBACK" {
		t.Fatalf("expected gateway rollup to count failback events, got %#v", summary.Gateway)
	}
}

func TestSummarizeDiagnosticsUsageCountsGatewayPromotionAndDemotion(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{},
		nil,
		nil,
		nil,
		nil,
		nil,
		[]GatewayChangeEvent{
			{NetworkID: "net-1", Event: "PROMOTED", ChangedAtUnix: 50},
			{NetworkID: "net-1", Event: "DEMOTED", ChangedAtUnix: 75},
		},
		nil,
		1,
	)

	if summary.Gateway == nil {
		t.Fatalf("expected explicit gateway rollup in summary, got %#v", summary)
	}
	if summary.Gateway.ChangeCount != 2 || summary.Gateway.PromotedCount != 1 || summary.Gateway.DemotedCount != 1 || summary.Gateway.LastEvent != "DEMOTED" {
		t.Fatalf("expected gateway rollup to count promotion and demotion events, got %#v", summary.Gateway)
	}
}

func TestSummarizeDiagnosticsUsageDeduplicatesSameConnectionReplacement(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{},
		nil,
		[]ConnectionStatus{
			{
				NetworkID:            "net-1",
				LocalPeerID:          "peer-local",
				RemotePeerID:         "peer-remote-old",
				RemoteUserID:         "user-remote",
				RemoteVirtualIP:      "10.10.0.3",
				State:                "CONNECTED",
				Reachability:         "RELAY",
				TransportReady:       true,
				TransportMode:        "RELAY",
				TransportPacketCount: 4,
				LastTransportUnix:    100,
				AverageRTTMillis:     80,
				LastRTTMillis:        82,
				TunnelState:          "OPEN",
			},
			{
				NetworkID:            "net-1",
				LocalPeerID:          "peer-local",
				RemotePeerID:         "peer-remote-new",
				RemoteUserID:         "user-remote",
				RemoteVirtualIP:      "10.10.0.3",
				State:                "CONNECTED",
				Reachability:         "DIRECT",
				TransportReady:       true,
				TransportMode:        "DIRECT",
				TransportPacketCount: 7,
				LastTransportUnix:    120,
				AverageRTTMillis:     12,
				LastRTTMillis:        10,
				TunnelState:          "OPEN",
			},
		},
		[]virtualadapter.NetworkBinding{
			{
				NetworkID:     "net-1",
				RoutingPolicy: "FULL",
				PolicyStatus:  "ACTIVE",
				GatewayRole:   "CLIENT",
				GatewayPeerID: "peer-remote-new",
			},
		},
		nil,
		nil,
		nil,
		nil,
		1,
	)

	if summary.ConnectionCount != 1 || summary.ConnectedCount != 1 {
		t.Fatalf("expected diagnostics summary to deduplicate same-peer replacement connection counts, got %#v", summary)
	}
	if summary.DirectConnectedCount != 1 || summary.RelayConnectedCount != 0 {
		t.Fatalf("expected replacement direct path to win connected rollup, got %#v", summary)
	}
	if summary.TransportReadyCount != 1 || summary.DirectTransportCount != 1 || summary.RelayTransportCount != 0 {
		t.Fatalf("expected replacement direct transport to win transport rollup, got %#v", summary)
	}
	if summary.TotalTransportPacketCount != 7 || summary.DirectTransportPacketCount != 7 || summary.RelayTransportPacketCount != 0 {
		t.Fatalf("expected transport packet counts to keep replacement direct path only, got %#v", summary)
	}
	if summary.ConnectionState == nil || summary.ConnectionState.ConnectionCount != 1 || summary.ConnectionState.DirectPathCount != 1 || summary.ConnectionState.RelayPathCount != 0 {
		t.Fatalf("expected connection-state rollup to deduplicate same-peer replacement, got %#v", summary.ConnectionState)
	}
	if summary.Transport == nil || summary.Transport.ConnectedDirectCount != 1 || summary.Transport.ConnectedRelayCount != 0 || summary.Transport.TotalTransportPacketCount != 7 {
		t.Fatalf("expected transport rollup to keep replacement direct path only, got %#v", summary.Transport)
	}
	if summary.GatewayCurrent == nil || summary.GatewayCurrent.DirectPathCount != 1 || summary.GatewayCurrent.CurrentPath != "DIRECT" || summary.GatewayCurrent.CurrentConnectionState != "CONNECTED" {
		t.Fatalf("expected current gateway rollup to stay on replacement direct path, got %#v", summary.GatewayCurrent)
	}
}

func TestSummarizeDiagnosticsUsageDeduplicatesSamePeerReplacementWithoutUserMetadata(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{},
		nil,
		[]ConnectionStatus{
			{
				NetworkID:            "net-1",
				LocalPeerID:          "peer-local",
				RemotePeerID:         "peer-remote-old",
				RemoteUserID:         "user-remote",
				RemoteVirtualIP:      "10.10.0.3",
				State:                "CONNECTED",
				Reachability:         "RELAY",
				TransportReady:       true,
				TransportMode:        "RELAY",
				TransportPacketCount: 2,
				LastTransportUnix:    80,
				AverageRTTMillis:     50,
				LastRTTMillis:        45,
			},
			{
				NetworkID:            "net-1",
				LocalPeerID:          "peer-local",
				RemotePeerID:         "peer-remote-new",
				RemoteVirtualIP:      "10.10.0.3",
				State:                "CONNECTED",
				Reachability:         "DIRECT",
				TransportReady:       true,
				TransportMode:        "DIRECT",
				TransportPacketCount: 7,
				LastTransportUnix:    120,
				AverageRTTMillis:     12,
				LastRTTMillis:        10,
				TunnelState:          "OPEN",
			},
		},
		[]virtualadapter.NetworkBinding{
			{
				NetworkID:     "net-1",
				RoutingPolicy: "FULL",
				PolicyStatus:  "ACTIVE",
				GatewayRole:   "CLIENT",
				GatewayPeerID: "peer-remote-new",
			},
		},
		nil,
		nil,
		nil,
		nil,
		1,
	)

	if summary.ConnectionCount != 1 || summary.ConnectedCount != 1 {
		t.Fatalf("expected diagnostics summary to deduplicate same-peer replacement without user metadata, got %#v", summary)
	}
	if summary.DirectConnectedCount != 1 || summary.RelayConnectedCount != 0 {
		t.Fatalf("expected replacement direct path to win connected rollup when metadata is missing, got %#v", summary)
	}
	if summary.TransportReadyCount != 1 || summary.DirectTransportCount != 1 || summary.RelayTransportCount != 0 {
		t.Fatalf("expected replacement direct transport to win transport rollup without user metadata, got %#v", summary)
	}
	if summary.TotalTransportPacketCount != 7 || summary.DirectTransportPacketCount != 7 || summary.RelayTransportPacketCount != 0 {
		t.Fatalf("expected transport packet counts to keep replacement direct path only without user metadata, got %#v", summary)
	}
	if summary.ConnectionState == nil || summary.ConnectionState.ConnectionCount != 1 || summary.ConnectionState.DirectPathCount != 1 || summary.ConnectionState.RelayPathCount != 0 {
		t.Fatalf("expected connection-state rollup to deduplicate same-peer replacement without user metadata, got %#v", summary.ConnectionState)
	}
	if summary.Transport == nil || summary.Transport.ConnectedDirectCount != 1 || summary.Transport.ConnectedRelayCount != 0 || summary.Transport.TotalTransportPacketCount != 7 {
		t.Fatalf("expected transport rollup to keep replacement direct path only without user metadata, got %#v", summary.Transport)
	}
	if summary.GatewayCurrent == nil || summary.GatewayCurrent.DirectPathCount != 1 || summary.GatewayCurrent.CurrentPath != "DIRECT" || summary.GatewayCurrent.CurrentConnectionState != "CONNECTED" {
		t.Fatalf("expected current gateway rollup to stay on replacement direct path without user metadata, got %#v", summary.GatewayCurrent)
	}
}

func TestSummarizeDiagnosticsUsageDeduplicatesSameConnectionReplacementWithMissingVirtualIPMetadata(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{},
		nil,
		[]ConnectionStatus{
			{
				NetworkID:            "net-1",
				LocalPeerID:          "peer-local",
				RemotePeerID:         "peer-remote-old",
				RemoteUserID:         "user-remote",
				RemoteVirtualIP:      "10.10.0.3",
				State:                "CONNECTED",
				Reachability:         "RELAY",
				TransportReady:       true,
				TransportMode:        "RELAY",
				TransportPacketCount: 2,
				LastTransportUnix:    80,
				AverageRTTMillis:     50,
				LastRTTMillis:        45,
			},
			{
				NetworkID:            "net-1",
				LocalPeerID:          "peer-local",
				RemotePeerID:         "peer-remote-new",
				RemoteUserID:         "user-remote",
				State:                "CONNECTED",
				Reachability:         "DIRECT",
				TransportReady:       true,
				TransportMode:        "DIRECT",
				TransportPacketCount: 7,
				LastTransportUnix:    120,
				AverageRTTMillis:     12,
				LastRTTMillis:        10,
				TunnelState:          "OPEN",
			},
		},
		[]virtualadapter.NetworkBinding{
			{
				NetworkID:     "net-1",
				RoutingPolicy: "FULL",
				PolicyStatus:  "ACTIVE",
				GatewayRole:   "CLIENT",
				GatewayPeerID: "peer-remote-new",
			},
		},
		[]controlclient.Peer{
			{
				ID:        "peer-remote-old",
				NetworkID: "net-1",
				UserID:    "user-remote",
				VirtualIP: "10.10.0.3",
				Status:    "OFFLINE",
			},
			{
				ID:        "peer-remote-new",
				NetworkID: "net-1",
				UserID:    "user-remote",
				VirtualIP: "10.10.0.3",
				Status:    "ONLINE",
			},
		},
		nil,
		nil,
		nil,
		1,
	)

	if summary.ConnectionCount != 1 || summary.ConnectedCount != 1 {
		t.Fatalf("expected diagnostics summary to deduplicate replacement connection when live virtual IP metadata is missing, got %#v", summary)
	}
	if summary.DirectConnectedCount != 1 || summary.RelayConnectedCount != 0 {
		t.Fatalf("expected replacement direct path to win connected rollup when live virtual IP metadata is missing, got %#v", summary)
	}
	if summary.ConnectionState == nil || summary.ConnectionState.ConnectionCount != 1 || summary.ConnectionState.DirectPathCount != 1 || summary.ConnectionState.RelayPathCount != 0 {
		t.Fatalf("expected connection-state rollup to deduplicate replacement connection when live virtual IP metadata is missing, got %#v", summary.ConnectionState)
	}
}

func TestSummarizeDiagnosticsUsageKeepsCurrentGatewayRollupOnStaleBindingReplacementPeer(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{},
		nil,
		[]ConnectionStatus{
			{
				NetworkID:            "net-1",
				LocalPeerID:          "peer-local",
				RemotePeerID:         "peer-remote-new",
				RemoteUserID:         "user-remote",
				RemoteVirtualIP:      "10.10.0.3",
				State:                "CONNECTED",
				Reachability:         "DIRECT",
				TransportReady:       true,
				TransportMode:        "DIRECT",
				TransportPacketCount: 9,
				LastTransportUnix:    140,
				AverageRTTMillis:     11,
				LastRTTMillis:        10,
				TunnelState:          "OPEN",
			},
		},
		[]virtualadapter.NetworkBinding{
			{
				NetworkID:     "net-1",
				RoutingPolicy: "FULL",
				PolicyStatus:  "ACTIVE",
				GatewayRole:   "CLIENT",
				GatewayPeerID: "peer-remote-old",
			},
		},
		[]controlclient.Peer{
			{
				ID:        "peer-remote-old",
				NetworkID: "net-1",
				UserID:    "user-remote",
				VirtualIP: "10.10.0.3",
				Status:    "OFFLINE",
			},
			{
				ID:        "peer-remote-new",
				NetworkID: "net-1",
				UserID:    "user-remote",
				VirtualIP: "10.10.0.3",
				Status:    "ONLINE",
			},
		},
		nil,
		nil,
		nil,
		1,
	)

	if summary.GatewayCurrent == nil || summary.GatewayCurrent.DirectPathCount != 1 || summary.GatewayCurrent.CurrentPath != "DIRECT" || summary.GatewayCurrent.CurrentConnectionState != "CONNECTED" {
		t.Fatalf("expected stale binding current gateway rollup to stay on replacement direct path, got %#v", summary.GatewayCurrent)
	}
	if summary.GatewayCurrent.CurrentGatewayPeerID != "peer-remote-old" {
		t.Fatalf("expected stale binding current gateway rollup to preserve bound gateway peer id while borrowing replacement path, got %#v", summary.GatewayCurrent)
	}
}

func TestSummarizeDiagnosticsUsageKeepsCurrentGatewayRollupWhenReplacementConnectionLacksVirtualIPMetadata(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{},
		nil,
		[]ConnectionStatus{
			{
				NetworkID:            "net-1",
				LocalPeerID:          "peer-local",
				RemotePeerID:         "peer-remote-new",
				RemoteUserID:         "user-remote",
				State:                "CONNECTED",
				Reachability:         "DIRECT",
				TransportReady:       true,
				TransportMode:        "DIRECT",
				TransportPacketCount: 9,
				LastTransportUnix:    140,
				AverageRTTMillis:     11,
				LastRTTMillis:        10,
				TunnelState:          "OPEN",
			},
		},
		[]virtualadapter.NetworkBinding{
			{
				NetworkID:        "net-1",
				RoutingPolicy:    "FULL",
				PolicyStatus:     "ACTIVE",
				GatewayRole:      "CLIENT",
				GatewayPeerID:    "peer-remote-old",
				GatewayUserID:    "user-remote",
				GatewayVirtualIP: "10.10.0.3",
			},
		},
		[]controlclient.Peer{
			{
				ID:        "peer-remote-old",
				NetworkID: "net-1",
				UserID:    "user-remote",
				VirtualIP: "10.10.0.3",
				Status:    "OFFLINE",
			},
			{
				ID:        "peer-remote-new",
				NetworkID: "net-1",
				UserID:    "user-remote",
				VirtualIP: "10.10.0.3",
				Status:    "ONLINE",
			},
		},
		nil,
		nil,
		nil,
		1,
	)

	if summary.GatewayCurrent == nil || summary.GatewayCurrent.DirectPathCount != 1 || summary.GatewayCurrent.CurrentPath != "DIRECT" || summary.GatewayCurrent.CurrentConnectionState != "CONNECTED" {
		t.Fatalf("expected stale binding current gateway rollup to stay on replacement direct path when the replacement connection is missing virtual IP metadata, got %#v", summary.GatewayCurrent)
	}
	if summary.GatewayCurrent.CurrentGatewayPeerID != "peer-remote-old" {
		t.Fatalf("expected stale binding current gateway rollup to preserve bound gateway peer id when the replacement connection is missing virtual IP metadata, got %#v", summary.GatewayCurrent)
	}
}

func TestSummarizeDiagnosticsUsageKeepsCurrentGatewayRollupWhenStaleBindingPeerRecordDisappears(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{},
		nil,
		[]ConnectionStatus{
			{
				NetworkID:            "net-1",
				LocalPeerID:          "peer-local",
				RemotePeerID:         "peer-remote-new",
				RemoteUserID:         "user-remote",
				RemoteVirtualIP:      "10.10.0.3",
				State:                "CONNECTED",
				Reachability:         "DIRECT",
				TransportReady:       true,
				TransportMode:        "DIRECT",
				TransportPacketCount: 9,
				LastTransportUnix:    140,
				AverageRTTMillis:     11,
				LastRTTMillis:        10,
				TunnelState:          "OPEN",
			},
		},
		[]virtualadapter.NetworkBinding{
			{
				NetworkID:        "net-1",
				RoutingPolicy:    "FULL",
				PolicyStatus:     "ACTIVE",
				GatewayRole:      "CLIENT",
				GatewayPeerID:    "peer-remote-old",
				GatewayUserID:    "user-remote",
				GatewayVirtualIP: "10.10.0.3",
			},
		},
		[]controlclient.Peer{
			{
				ID:        "peer-remote-new",
				NetworkID: "net-1",
				UserID:    "user-remote",
				VirtualIP: "10.10.0.3",
				Status:    "ONLINE",
			},
		},
		nil,
		nil,
		nil,
		1,
	)

	if summary.GatewayCurrent == nil || summary.GatewayCurrent.DirectPathCount != 1 || summary.GatewayCurrent.CurrentPath != "DIRECT" || summary.GatewayCurrent.CurrentConnectionState != "CONNECTED" {
		t.Fatalf("expected metadata-backed stale binding current gateway rollup to stay on replacement direct path after the old peer record disappears, got %#v", summary.GatewayCurrent)
	}
	if summary.GatewayCurrent.CurrentGatewayPeerID != "peer-remote-old" {
		t.Fatalf("expected metadata-backed stale binding current gateway rollup to preserve bound gateway peer id while borrowing replacement path, got %#v", summary.GatewayCurrent)
	}
}

func TestSummarizeDiagnosticsUsageFailsClosedForDistinctUserWhenStaleBindingPeerRecordDisappears(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{},
		nil,
		[]ConnectionStatus{
			{
				NetworkID:            "net-1",
				LocalPeerID:          "peer-local",
				RemotePeerID:         "peer-remote-other",
				RemoteUserID:         "user-other",
				RemoteVirtualIP:      "10.10.0.3",
				State:                "CONNECTED",
				Reachability:         "DIRECT",
				TransportReady:       true,
				TransportMode:        "DIRECT",
				TransportPacketCount: 9,
				LastTransportUnix:    140,
				AverageRTTMillis:     11,
				LastRTTMillis:        10,
				TunnelState:          "OPEN",
			},
		},
		[]virtualadapter.NetworkBinding{
			{
				NetworkID:        "net-1",
				RoutingPolicy:    "FULL",
				PolicyStatus:     "ACTIVE",
				GatewayRole:      "CLIENT",
				GatewayPeerID:    "peer-remote-old",
				GatewayUserID:    "user-remote",
				GatewayVirtualIP: "10.10.0.3",
			},
		},
		[]controlclient.Peer{
			{
				ID:        "peer-remote-other",
				NetworkID: "net-1",
				UserID:    "user-other",
				VirtualIP: "10.10.0.3",
				Status:    "ONLINE",
			},
		},
		nil,
		nil,
		nil,
		1,
	)

	if summary.GatewayCurrent == nil || summary.GatewayCurrent.CurrentPath != "PENDING" || summary.GatewayCurrent.CurrentConnectionState != "ACTIVE" {
		t.Fatalf("expected metadata-backed stale binding current gateway rollup to fail closed on a distinct-user overlay collision after the old peer record disappears, got %#v", summary.GatewayCurrent)
	}
	if summary.GatewayCurrent.CurrentGatewayPeerID != "peer-remote-old" {
		t.Fatalf("expected metadata-backed stale binding current gateway rollup to preserve bound gateway peer id on a distinct-user collision, got %#v", summary.GatewayCurrent)
	}
}

func TestSummarizeDiagnosticsUsageFailsClosedForDistinctUserOnStaleGatewayBinding(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{},
		nil,
		[]ConnectionStatus{
			{
				NetworkID:            "net-1",
				LocalPeerID:          "peer-local",
				RemotePeerID:         "peer-remote-other",
				RemoteUserID:         "user-other",
				RemoteVirtualIP:      "10.10.0.3",
				State:                "CONNECTED",
				Reachability:         "DIRECT",
				TransportReady:       true,
				TransportMode:        "DIRECT",
				TransportPacketCount: 9,
				LastTransportUnix:    140,
				AverageRTTMillis:     11,
				LastRTTMillis:        10,
				TunnelState:          "OPEN",
			},
		},
		[]virtualadapter.NetworkBinding{
			{
				NetworkID:     "net-1",
				RoutingPolicy: "FULL",
				PolicyStatus:  "ACTIVE",
				GatewayRole:   "CLIENT",
				GatewayPeerID: "peer-remote-old",
			},
		},
		[]controlclient.Peer{
			{
				ID:        "peer-remote-old",
				NetworkID: "net-1",
				UserID:    "user-remote",
				VirtualIP: "10.10.0.3",
				Status:    "OFFLINE",
			},
			{
				ID:        "peer-remote-other",
				NetworkID: "net-1",
				UserID:    "user-other",
				VirtualIP: "10.10.0.3",
				Status:    "ONLINE",
			},
		},
		nil,
		nil,
		nil,
		1,
	)

	if summary.GatewayCurrent == nil || summary.GatewayCurrent.DirectPathCount != 0 || summary.GatewayCurrent.CurrentPath != "PENDING" {
		t.Fatalf("expected stale binding current gateway rollup to fail closed for distinct-user overlay collision, got %#v", summary.GatewayCurrent)
	}
}

func TestSummarizeDiagnosticsUsageDeduplicatesSameNeighborReplacement(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{},
		[]NeighborStatus{
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
		},
		nil,
		[]virtualadapter.NetworkBinding{{
			NetworkID:        "net-1",
			RoutingPolicy:    "PEER",
			PolicyStatus:     "ACTIVE",
			IPAddressVisible: true,
			RouteVisible:     true,
		}},
		nil,
		nil,
		nil,
		nil,
		1,
	)

	if summary.Neighbors == nil || summary.Neighbors.NeighborCount != 1 || summary.Neighbors.TransportReadyCount != 1 || summary.Neighbors.ConnectedCount != 1 {
		t.Fatalf("expected neighbor rollup to deduplicate same-peer replacement, got %#v", summary.Neighbors)
	}
	if summary.Neighbors.DirectReachabilityCount != 1 || summary.Neighbors.RelayReachabilityCount != 0 || summary.Neighbors.DirectTransportCount != 1 || summary.Neighbors.RelayTransportCount != 0 {
		t.Fatalf("expected replacement direct neighbor to win reachability/transport rollup, got %#v", summary.Neighbors)
	}
	if summary.AdapterNeighbor == nil || summary.AdapterNeighbor.ReadyNeighborCount != 1 || summary.AdapterNeighbor.HealthyBindingCount != 1 {
		t.Fatalf("expected adapter-neighbor correlation to deduplicate same-peer replacement, got %#v", summary.AdapterNeighbor)
	}
}

func TestSummarizeDiagnosticsUsageDeduplicatesSameNeighborReplacementWithMissingVirtualIPMetadata(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{},
		[]NeighborStatus{
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
		},
		nil,
		[]virtualadapter.NetworkBinding{{
			NetworkID:        "net-1",
			RoutingPolicy:    "PEER",
			PolicyStatus:     "ACTIVE",
			IPAddressVisible: true,
			RouteVisible:     true,
		}},
		[]controlclient.Peer{
			{
				ID:        "peer-remote-old",
				NetworkID: "net-1",
				UserID:    "user-remote",
				VirtualIP: "10.10.0.3",
				Status:    "OFFLINE",
			},
			{
				ID:        "peer-remote-new",
				NetworkID: "net-1",
				UserID:    "user-remote",
				VirtualIP: "10.10.0.3",
				Status:    "ONLINE",
			},
		},
		nil,
		nil,
		nil,
		1,
	)

	if summary.Neighbors == nil || summary.Neighbors.NeighborCount != 1 || summary.Neighbors.TransportReadyCount != 1 || summary.Neighbors.ConnectedCount != 1 {
		t.Fatalf("expected neighbor rollup to deduplicate same-peer replacement when replacement metadata is missing, got %#v", summary.Neighbors)
	}
	if summary.Neighbors.DirectReachabilityCount != 1 || summary.Neighbors.RelayReachabilityCount != 0 || summary.Neighbors.DirectTransportCount != 1 || summary.Neighbors.RelayTransportCount != 0 {
		t.Fatalf("expected replacement direct neighbor to win reachability/transport rollup when replacement metadata is missing, got %#v", summary.Neighbors)
	}
	if summary.AdapterNeighbor == nil || summary.AdapterNeighbor.ReadyNeighborCount != 1 || summary.AdapterNeighbor.HealthyBindingCount != 1 {
		t.Fatalf("expected adapter-neighbor correlation to deduplicate same-peer replacement when replacement metadata is missing, got %#v", summary.AdapterNeighbor)
	}
}

func TestSummarizeDiagnosticsUsageKeepsDistinctNeighborsOnOverlayCollision(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{},
		[]NeighborStatus{
			{
				NetworkID:          "net-1",
				LocalPeerID:        "peer-local",
				RemotePeerID:       "peer-remote-owner",
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
				RemotePeerID:       "peer-remote-other",
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
		},
		nil,
		[]virtualadapter.NetworkBinding{{
			NetworkID:        "net-1",
			RoutingPolicy:    "PEER",
			PolicyStatus:     "ACTIVE",
			IPAddressVisible: true,
			RouteVisible:     true,
		}},
		nil,
		nil,
		nil,
		nil,
		1,
	)

	if summary.Neighbors == nil || summary.Neighbors.NeighborCount != 2 || summary.Neighbors.TransportReadyCount != 2 || summary.Neighbors.ConnectedCount != 2 {
		t.Fatalf("expected neighbor rollup to keep distinct-user overlay collision visible, got %#v", summary.Neighbors)
	}
	if summary.Neighbors.DirectReachabilityCount != 1 || summary.Neighbors.RelayReachabilityCount != 1 || summary.Neighbors.DirectTransportCount != 1 || summary.Neighbors.RelayTransportCount != 1 {
		t.Fatalf("expected neighbor rollup to keep both direct and relay collision paths visible, got %#v", summary.Neighbors)
	}
	if summary.AdapterNeighbor == nil || summary.AdapterNeighbor.ReadyNeighborCount != 2 {
		t.Fatalf("expected adapter-neighbor correlation to fail closed on distinct-user overlay collision, got %#v", summary.AdapterNeighbor)
	}
}

func TestSummarizeDiagnosticsUsageDeduplicatesSamePeerReplacement(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{},
		nil,
		nil,
		nil,
		[]controlclient.Peer{
			{
				ID:              "peer-old",
				NetworkID:       "net-1",
				UserID:          "user-remote",
				VirtualIP:       "10.10.0.3",
				Status:          "OFFLINE",
				ConnectionState: "IDLE",
				LastSeenUnix:    100,
			},
			{
				ID:              "peer-new",
				NetworkID:       "net-1",
				UserID:          "user-remote",
				VirtualIP:       "10.10.0.3",
				Status:          "ONLINE",
				ConnectionState: "CONNECTED",
				LastSeenUnix:    120,
			},
			{
				ID:              "peer-other",
				NetworkID:       "net-1",
				UserID:          "user-other",
				VirtualIP:       "10.10.0.4",
				Status:          "ONLINE",
				ConnectionState: "CONNECTED",
				LastSeenUnix:    130,
			},
		},
		nil,
		nil,
		nil,
		1,
	)

	if summary.PeerCount != 2 || summary.OnlinePeerCount != 2 {
		t.Fatalf("expected peer rollup to deduplicate same-user replacement, got %#v", summary)
	}
}

func TestSummarizeDiagnosticsUsageDeduplicatesPeerReplacementWithoutUserMetadata(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{},
		nil,
		nil,
		nil,
		[]controlclient.Peer{
			{
				ID:              "peer-old",
				NetworkID:       "net-1",
				VirtualIP:       "10.10.0.3",
				Status:          "OFFLINE",
				ConnectionState: "IDLE",
				LastSeenUnix:    100,
			},
			{
				ID:              "peer-new",
				NetworkID:       "net-1",
				VirtualIP:       "10.10.0.3",
				Status:          "ONLINE",
				ConnectionState: "CONNECTED",
				LastSeenUnix:    120,
			},
			{
				ID:              "peer-other",
				NetworkID:       "net-1",
				UserID:          "user-other",
				VirtualIP:       "10.10.0.4",
				Status:          "ONLINE",
				ConnectionState: "CONNECTED",
				LastSeenUnix:    130,
			},
		},
		nil,
		nil,
		nil,
		1,
	)

	if summary.PeerCount != 2 || summary.OnlinePeerCount != 2 {
		t.Fatalf("expected peer rollup to deduplicate replacement peer even without user metadata, got %#v", summary)
	}
}

func TestFilterNeighborsByNetworkDeduplicatesSamePeerReplacement(t *testing.T) {
	neighbors := filterNeighborsByNetwork([]NeighborStatus{
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
		{
			NetworkID:          "net-2",
			LocalPeerID:        "peer-local",
			RemotePeerID:       "peer-other",
			RemoteVirtualIP:    "10.20.0.3",
			Presence:           "online",
			NeighborState:      "CONNECTED",
			Reachability:       "DIRECT",
			CandidateCount:     1,
			TransportReady:     true,
			TransportMode:      "DIRECT",
			LastSeenUnix:       130,
			LastSignaledAtUnix: 131,
		},
	}, "net-1")

	if len(neighbors) != 1 {
		t.Fatalf("expected network neighbor snapshot to deduplicate same-peer replacement, got %#v", neighbors)
	}
	if neighbors[0].RemotePeerID != "peer-remote-new" || neighbors[0].TransportMode != "DIRECT" || neighbors[0].CandidateCount != 2 {
		t.Fatalf("expected replacement direct neighbor to win filtered network snapshot, got %#v", neighbors[0])
	}
}

func TestFilterNeighborsByNetworkKeepsDistinctUsersOnOverlayCollision(t *testing.T) {
	neighbors := filterNeighborsByNetwork([]NeighborStatus{
		{
			NetworkID:          "net-1",
			LocalPeerID:        "peer-local",
			RemotePeerID:       "peer-remote-owner",
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
			RemotePeerID:       "peer-remote-other",
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
	}, "net-1")

	if len(neighbors) != 2 {
		t.Fatalf("expected filtered network snapshot to keep distinct-user overlay collision visible, got %#v", neighbors)
	}
}

func TestSummarizeDiagnosticsUsageTracksPendingCurrentGatewayState(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{
			Enabled:         true,
			Available:       true,
			ConnectionState: "PENDING",
			LastError:       "gateway pending",
		},
		nil,
		nil,
		[]virtualadapter.NetworkBinding{
			{
				NetworkID:     "net-2",
				RoutingPolicy: "FULL",
				PolicyStatus:  "PENDING_GATEWAY",
			},
		},
		nil,
		nil,
		nil,
		nil,
		1,
	)

	if summary.GatewayCurrent == nil {
		t.Fatalf("expected pending current gateway rollup, got %#v", summary)
	}
	if summary.GatewayCurrent.FullNetworkCount != 1 ||
		summary.GatewayCurrent.PendingNetworkCount != 1 ||
		summary.GatewayCurrent.CurrentNetworkID != "net-2" ||
		summary.GatewayCurrent.CurrentPath != "PENDING" ||
		summary.GatewayCurrent.CurrentPolicyStatus != "PENDING_GATEWAY" ||
		summary.GatewayCurrent.CurrentConnectionState != "PENDING_GATEWAY" {
		t.Fatalf("expected pending current gateway details, got %#v", summary.GatewayCurrent)
	}
	if summary.Adapter == nil ||
		summary.Adapter.BindingCount != 1 ||
		summary.Adapter.FullBindingCount != 1 ||
		summary.Adapter.PendingPolicyCount != 1 ||
		summary.Adapter.ConnectionState != "PENDING" ||
		!summary.Adapter.HasError {
		t.Fatalf("expected pending adapter rollup details, got %#v", summary.Adapter)
	}
	if summary.ConnectionState != nil {
		t.Fatalf("expected empty connection-state rollup when no connections exist, got %#v", summary.ConnectionState)
	}
	if summary.AdapterNeighbor == nil ||
		summary.AdapterNeighbor.NetworkCount != 1 ||
		summary.AdapterNeighbor.PendingCount != 1 ||
		summary.AdapterNeighbor.PendingGatewayCount != 1 ||
		summary.AdapterNeighbor.MostSevereState != "PENDING" ||
		summary.AdapterNeighbor.AffectedNetworkID != "net-2" {
		t.Fatalf("expected pending adapter-neighbor correlation details, got %#v", summary.AdapterNeighbor)
	}
}

func TestSummarizeDiagnosticsUsagePrefersActiveFullTunnelOverStandby(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{
			Enabled:         true,
			Available:       true,
			ConnectionState: "Connected",
			Networks: []virtualadapter.NetworkBinding{
				{
					NetworkID:        "net-standby",
					RoutingPolicy:    "FULL",
					PolicyStatus:     "STANDBY_GATEWAY",
					GatewayRole:      "CLIENT",
					GatewayPeerID:    "peer-admin",
					IPAddressVisible: true,
					RouteVisible:     true,
				},
				{
					NetworkID:        "net-active",
					RoutingPolicy:    "FULL",
					PolicyStatus:     "ACTIVE",
					GatewayRole:      "CLIENT",
					GatewayPeerID:    "peer-owner",
					IPAddressVisible: true,
					RouteVisible:     true,
				},
			},
		},
		[]NeighborStatus{
			{NetworkID: "net-standby", RemotePeerID: "peer-admin", TransportReady: true, NeighborState: "CONNECTED"},
			{NetworkID: "net-active", RemotePeerID: "peer-owner", TransportReady: true, NeighborState: "CONNECTED"},
		},
		[]ConnectionStatus{
			{NetworkID: "net-standby", RemotePeerID: "peer-admin", State: "CONNECTED", TransportMode: "RELAY", Reachability: "RELAY", TransportReady: true},
			{NetworkID: "net-active", RemotePeerID: "peer-owner", State: "CONNECTED", TransportMode: "DIRECT", Reachability: "DIRECT", TransportReady: true},
		},
		[]virtualadapter.NetworkBinding{
			{
				NetworkID:        "net-standby",
				RoutingPolicy:    "FULL",
				PolicyStatus:     "STANDBY_GATEWAY",
				GatewayRole:      "CLIENT",
				GatewayPeerID:    "peer-admin",
				IPAddressVisible: true,
				RouteVisible:     true,
			},
			{
				NetworkID:        "net-active",
				RoutingPolicy:    "FULL",
				PolicyStatus:     "ACTIVE",
				GatewayRole:      "CLIENT",
				GatewayPeerID:    "peer-owner",
				IPAddressVisible: true,
				RouteVisible:     true,
			},
		},
		nil,
		nil,
		nil,
		nil,
		2,
	)

	if summary.GatewayCurrent == nil ||
		summary.GatewayCurrent.FullNetworkCount != 2 ||
		summary.GatewayCurrent.ActiveNetworkCount != 1 ||
		summary.GatewayCurrent.PendingNetworkCount != 1 ||
		summary.GatewayCurrent.CurrentNetworkID != "net-active" ||
		summary.GatewayCurrent.CurrentGatewayPeerID != "peer-owner" ||
		summary.GatewayCurrent.CurrentPolicyStatus != "ACTIVE" {
		t.Fatalf("expected active full network to win current gateway rollup, got %#v", summary.GatewayCurrent)
	}
	if summary.AdapterNeighbor == nil ||
		summary.AdapterNeighbor.NetworkCount != 2 ||
		summary.AdapterNeighbor.MostSevereState != "STANDBY" ||
		summary.AdapterNeighbor.AffectedNetworkID != "net-standby" ||
		summary.AdapterNeighbor.Hint == "" {
		t.Fatalf("expected standby adapter-neighbor hint, got %#v", summary.AdapterNeighbor)
	}
}

func TestSummarizeDiagnosticsUsageDetectsAdapterLaggingBehindReadyNeighbors(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{
			Enabled:         true,
			Available:       true,
			ConnectionState: "UP",
		},
		[]NeighborStatus{
			{
				NetworkID:      "net-3",
				Presence:       "online",
				NeighborState:  "CONNECTED",
				Reachability:   "DIRECT",
				CandidateCount: 2,
				TransportReady: true,
				TransportMode:  "DIRECT",
			},
		},
		nil,
		[]virtualadapter.NetworkBinding{
			{
				NetworkID:        "net-3",
				RoutingPolicy:    "SPLIT",
				PolicyStatus:     "ACTIVE",
				IPAddressVisible: true,
				RouteVisible:     false,
			},
		},
		nil,
		nil,
		nil,
		nil,
		1,
	)

	if summary.AdapterNeighbor == nil ||
		summary.AdapterNeighbor.NetworkCount != 1 ||
		summary.AdapterNeighbor.AdapterLaggingCount != 1 ||
		summary.AdapterNeighbor.MissingRouteVisibilityCount != 1 ||
		summary.AdapterNeighbor.ReadyNeighborCount != 1 ||
		summary.AdapterNeighbor.MostSevereState != "ADAPTER_LAGGING" ||
		summary.AdapterNeighbor.AffectedNetworkID != "net-3" ||
		!strings.Contains(summary.AdapterNeighbor.Hint, "route") {
		t.Fatalf("expected adapter-lagging correlation details, got %#v", summary.AdapterNeighbor)
	}
}

func TestSummarizeDiagnosticsUsageSeparatesTransientAndPersistentRecentErrors(t *testing.T) {
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{},
		nil,
		[]ConnectionStatus{
			{
				NetworkID:       "net-4",
				RemotePeerID:    "peer-retry",
				State:           "DIRECT_CANDIDATE",
				LastAttemptUnix: 220,
				NextRetryUnix:   240,
				LastError:       "probe timeout",
			},
			{
				NetworkID:       "net-4",
				RemotePeerID:    "peer-stuck",
				State:           "RELAY_READY",
				LastAttemptUnix: 260,
				LastError:       "relay path unavailable",
			},
		},
		nil,
		nil,
		nil,
		nil,
		nil,
		1,
	)

	if summary.RecentErrors == nil {
		t.Fatalf("expected recent-error rollup in summary, got %#v", summary)
	}
	if summary.RecentErrors.ErrorCount != 2 ||
		summary.RecentErrors.TransientRetryCount != 1 ||
		summary.RecentErrors.PersistentFailureCount != 1 ||
		summary.RecentErrors.ConnectedErrorCount != 0 ||
		summary.RecentErrors.LastErrorUnix != 260 ||
		summary.RecentErrors.NextRetryUnix != 240 ||
		summary.RecentErrors.LastErrorPeerID != "peer-stuck" ||
		summary.RecentErrors.LastErrorState != "RELAY_READY" ||
		summary.RecentErrors.MostRecentError != "relay path unavailable" ||
		summary.RecentErrors.MostSevereState != "MIXED" ||
		!strings.Contains(summary.RecentErrors.Hint, "mixed") {
		t.Fatalf("expected recent-error rollup to separate transient and persistent failures, got %#v", summary.RecentErrors)
	}
}

func TestSummarizeDiagnosticsUsageTracksTransportSessionAgeAndRekey(t *testing.T) {
	nowUnix := time.Now().Unix()
	summary := summarizeDiagnosticsUsage(
		virtualadapter.Status{},
		nil,
		[]ConnectionStatus{
			{
				NetworkID:                "net-5",
				RemotePeerID:             "peer-direct",
				State:                    "CONNECTED",
				TransportReady:           true,
				TransportMode:            "DIRECT",
				TransportSessionID:       "sess-direct",
				TransportEstablishedUnix: nowUnix - 7200,
				TransportRekeyDueUnix:    nowUnix + 120,
				LastTransportUnix:        nowUnix - 45,
			},
			{
				NetworkID:                "net-5",
				RemotePeerID:             "peer-relay",
				State:                    "CONNECTED",
				TransportReady:           true,
				TransportMode:            "RELAY",
				TransportSessionID:       "sess-relay",
				TransportEstablishedUnix: nowUnix - 1800,
				TransportRekeyDueUnix:    nowUnix - 10,
				LastTransportUnix:        nowUnix - 600,
			},
		},
		nil,
		nil,
		nil,
		nil,
		nil,
		1,
	)

	if summary.TransportSessions == nil {
		t.Fatalf("expected transport-session rollup in summary, got %#v", summary)
	}
	if summary.TransportSessions.SessionCount != 2 ||
		summary.TransportSessions.DirectSessionCount != 1 ||
		summary.TransportSessions.RelaySessionCount != 1 ||
		summary.TransportSessions.OldestSessionID != "sess-direct" ||
		summary.TransportSessions.NextRekeySessionID != "sess-relay" ||
		summary.TransportSessions.RekeyScheduledCount != 2 ||
		summary.TransportSessions.RekeyDueSoonCount != 1 ||
		summary.TransportSessions.RekeyOverdueCount != 1 ||
		summary.TransportSessions.MostSevereState != "OVERDUE_REKEY" ||
		!strings.Contains(summary.TransportSessions.Hint, "rekey deadline") {
		t.Fatalf("expected transport-session age/rekey rollup details, got %#v", summary.TransportSessions)
	}
	if summary.TransportSessions.OldestSessionUnix > nowUnix-7000 ||
		summary.TransportSessions.NewestSessionUnix < nowUnix-2000 ||
		summary.TransportSessions.MaxSessionAgeSec < 7000 ||
		summary.TransportSessions.MaxIdleSec < 500 ||
		summary.TransportSessions.NextRekeyUnix > nowUnix {
		t.Fatalf("expected transport-session timing values to reflect oldest age, idle, and earliest due rekey, got %#v", summary.TransportSessions)
	}
}

func TestSummarizeCrossNetworkHealthDistinguishesIsolatedAndWidespreadIssues(t *testing.T) {
	isolated := summarizeCrossNetworkHealth([]DiagnosticsNetwork{
		{
			Network: controlclient.Network{ID: "net-healthy"},
			UsageSummary: DiagnosticsUsageSummary{
				ConnectionState: &DiagnosticsConnectionStateRollup{MostSevereState: "CONNECTED"},
				Transport:       &DiagnosticsTransportRollup{Quality: "healthy"},
			},
		},
		{
			Network: controlclient.Network{ID: "net-bad"},
			UsageSummary: DiagnosticsUsageSummary{
				AdapterNeighbor: &DiagnosticsAdapterNeighborRollup{MostSevereState: "ADAPTER_LAGGING", AdapterLaggingCount: 1},
				ConnectionState: &DiagnosticsConnectionStateRollup{MostSevereState: "MIXED"},
			},
		},
	})
	if isolated == nil ||
		isolated.NetworkCount != 2 ||
		isolated.HealthyCount != 1 ||
		isolated.DegradedCount != 1 ||
		isolated.AffectedCount != 1 ||
		isolated.IsolatedIssueCount != 1 ||
		isolated.WidespreadIssueCount != 0 ||
		isolated.MostSevereState != "ISOLATED_DEGRADATION" ||
		isolated.AffectedNetworkID != "net-bad" ||
		!strings.Contains(isolated.Hint, "Only one network") {
		t.Fatalf("expected isolated cross-network degradation summary, got %#v", isolated)
	}

	widespread := summarizeCrossNetworkHealth([]DiagnosticsNetwork{
		{
			Network: controlclient.Network{ID: "net-1"},
			UsageSummary: DiagnosticsUsageSummary{
				Transport: &DiagnosticsTransportRollup{Quality: "degraded"},
			},
		},
		{
			Network: controlclient.Network{ID: "net-2"},
			UsageSummary: DiagnosticsUsageSummary{
				ConnectionState: &DiagnosticsConnectionStateRollup{MostSevereState: "ERROR"},
				Adapter:         &DiagnosticsAdapterRollup{HasError: true},
			},
		},
		{
			Network: controlclient.Network{ID: "net-3"},
			UsageSummary: DiagnosticsUsageSummary{
				ConnectionCount: 1,
				ConnectionState: &DiagnosticsConnectionStateRollup{MostSevereState: "CONNECTED"},
				Transport:       &DiagnosticsTransportRollup{Quality: "healthy"},
			},
		},
	})
	if widespread == nil ||
		widespread.NetworkCount != 3 ||
		widespread.HealthyCount != 1 ||
		widespread.DegradedCount != 2 ||
		widespread.AffectedCount != 2 ||
		widespread.WidespreadIssueCount != 2 ||
		widespread.MostSevereState != "WIDESPREAD_DEGRADATION" ||
		!strings.Contains(widespread.Hint, "Multiple networks") {
		t.Fatalf("expected widespread cross-network degradation summary, got %#v", widespread)
	}

	if value := summarizeCrossNetworkHealth([]DiagnosticsNetwork{{Network: controlclient.Network{ID: "solo"}}}); value != nil {
		t.Fatalf("expected no cross-network summary for a single network, got %#v", value)
	}
}
