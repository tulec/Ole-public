//go:build windows

package clientgui

import (
	"Ole/internal/clientagent"
	"Ole/internal/domain"
	"Ole/internal/virtualadapter"
	"strings"
	"testing"
	"time"
)

func TestFormatPeerLineShowsDirectHealthyLatencyHint(t *testing.T) {
	peer := Peer{
		ID:              "peer-b",
		VirtualIP:       "10.77.1.2",
		Endpoint:        "198.51.100.10:5000",
		Status:          "ONLINE",
		ConnectionState: "CONNECTED",
		LastSeenUnix:    time.Now().Unix(),
	}
	status := &clientagent.Status{
		Connections: []clientagent.ConnectionStatus{
			{
				NetworkID:         "net-1",
				RemotePeerID:      "peer-b",
				Reachability:      "DIRECT",
				State:             "CONNECTED",
				TransportReady:    true,
				TransportMode:     "DIRECT",
				AverageRTTMillis:  24,
				ConsecutiveLosses: 0,
			},
		},
	}

	line := formatPeerLine(peer, status, &Network{ID: "net-1"})
	assertContains(t, line, "online")
	assertContains(t, line, "quality=healthy")
	assertContains(t, line, "latency=24 ms")
	assertContains(t, line, "path=direct")
}

func TestFormatPeerLineShowsRelayDegradedHint(t *testing.T) {
	peer := Peer{
		ID:           "peer-c",
		VirtualIP:    "10.88.1.3",
		Status:       "ONLINE",
		LastSeenUnix: time.Now().Unix(),
	}
	status := &clientagent.Status{
		Connections: []clientagent.ConnectionStatus{
			{
				NetworkID:         "net-1",
				RemotePeerID:      "peer-c",
				Reachability:      "RELAY",
				State:             "CONNECTED",
				TransportReady:    true,
				TransportMode:     "RELAY",
				LastRTTMillis:     95,
				ConsecutiveLosses: 2,
			},
		},
	}

	line := formatPeerLine(peer, status, &Network{ID: "net-1"})
	assertContains(t, line, "quality=degraded")
	assertContains(t, line, "latency=95 ms")
	assertContains(t, line, "path=relay")
}

func TestFormatPeerLineShowsOfflineHintWithoutConnection(t *testing.T) {
	peer := Peer{
		ID:           "peer-d",
		VirtualIP:    "10.99.1.4",
		Status:       "OFFLINE",
		LastSeenUnix: time.Now().Add(-10 * time.Minute).Unix(),
	}

	line := formatPeerLine(peer, nil, &Network{ID: "net-1"})
	assertContains(t, line, "offline")
	assertContains(t, line, "quality=offline")
	assertContains(t, line, "latency=-")
	assertContains(t, line, "path=offline")
}

func TestFormatAgentStatusShowsDesiredMTU(t *testing.T) {
	status := &clientagent.Status{
		ServiceName: "Ole Agent",
		Adapter:     clientagent.Status{}.Adapter,
	}
	status.Adapter.DesiredMTU = 1360
	status.Adapter.MTU = 1380

	value := formatAgentStatus(status)
	assertContains(t, value, "Desired MTU: 1360")
	assertContains(t, value, "MTU: 1380")
}

func TestFormatAgentStatusShowsUpdaterState(t *testing.T) {
	status := &clientagent.Status{
		ServiceName: "Ole Agent",
		Update: clientagent.UpdateStatus{
			Channel:                "beta",
			AvailableChannels:      []string{"stable", "beta"},
			ManifestURL:            "https://updates.example.com/ole-update.json",
			CheckPeriodSec:         21600,
			CurrentVersion:         "0.1.0",
			LatestVersion:          "0.2.0",
			Available:              true,
			PolicyStatus:           "COMPATIBLE",
			PolicyMessage:          "current server version is compatible with this update",
			Downloaded:             true,
			DownloadedPath:         `C:\Ole\updates\Ole-Setup-0.2.0.exe`,
			ReleaseNotesURL:        "https://updates.example.com/release-notes",
			RollbackAvailable:      true,
			RollbackVersion:        "0.1.0",
			RollbackReason:         "Use this rollback if needed",
			RollbackDownloaded:     true,
			RollbackDownloadedPath: `C:\Ole\updates\Ole-Setup-0.1.0.exe`,
		},
	}

	value := formatAgentStatus(status)
	assertContains(t, value, "Updater")
	assertContains(t, value, "Channel: beta")
	assertContains(t, value, "Available Channels: stable, beta")
	assertContains(t, value, "State: downloaded")
	assertContains(t, value, "Policy: COMPATIBLE")
	assertContains(t, value, "Rollback Available: yes")
	assertContains(t, value, `Rollback Downloaded Path: C:\Ole\updates\Ole-Setup-0.1.0.exe`)
	assertContains(t, value, "Latest Version: 0.2.0")
	assertContains(t, value, `Downloaded Path: C:\Ole\updates\Ole-Setup-0.2.0.exe`)
}

func TestFormatAgentStatusShowsSecurityAlerts(t *testing.T) {
	status := &clientagent.Status{
		ServiceName: "Ole Agent",
		Security: clientagent.SecurityDiagnostics{
			LastCheckedUnix:     time.Now().Unix(),
			ReuseDetectedCount:  1,
			RevokedDeviceCount:  1,
			CurrentDeviceStatus: "REVOKED",
			EnrollmentStatus:    "REVOKED",
			Alerts: []clientagent.SecurityAlert{
				{
					Code:           "SESSION_REUSE_DETECTED",
					Severity:       "error",
					Summary:        "Current session family reported token reuse",
					Detail:         "Ole Desktop",
					DetectedAtUnix: time.Now().Unix(),
				},
			},
		},
	}

	value := formatAgentStatus(status)
	assertContains(t, value, "Current Device Status: REVOKED")
	assertContains(t, value, "Enrollment Status: REVOKED")
	assertContains(t, value, "Security Alerts:")
	assertContains(t, value, "SESSION_REUSE_DETECTED")
}

func TestFormatAgentStatusShowsIncidentSummary(t *testing.T) {
	status := &clientagent.Status{
		ServiceName: "Ole Agent",
		Incidents: clientagent.IncidentSummary{
			ActiveCount:      2,
			TokenReuseCount:  1,
			MostSevere:       "critical",
			LastCheckedUnix:  time.Now().Unix(),
			LastRefreshError: "incident feed timeout",
		},
	}

	value := formatAgentStatus(status)
	assertContains(t, value, "Active Incidents: 2")
	assertContains(t, value, "Token Reuse Incidents: 1")
	assertContains(t, value, "Incident Severity: critical")
	assertContains(t, value, "Incident Refresh Error: incident feed timeout")
}

func TestFormatAgentStatusShowsDirectConnectMetrics(t *testing.T) {
	status := &clientagent.Status{
		ServiceName: "Ole Agent",
		DirectMetrics: clientagent.DirectConnectMetrics{
			AttemptCount:         5,
			SuccessCount:         3,
			FailureCount:         2,
			SuccessRatePct:       60,
			RelayFallbackCount:   2,
			FailbackSuccessCount: 1,
			LastSuccessCandidate: "198.51.100.20:5000",
		},
	}

	value := formatAgentStatus(status)
	assertContains(t, value, "Direct Connect Metrics")
	assertContains(t, value, "Attempts: 5")
	assertContains(t, value, "Success Rate: 60%")
	assertContains(t, value, "Relay Fallbacks: 2")
	assertContains(t, value, "Last Success Candidate: 198.51.100.20:5000")
}

func TestFormatAgentStatusShowsReconnectBackoffDiagnostics(t *testing.T) {
	status := &clientagent.Status{
		ServiceName:            "Ole Agent",
		ReconnectState:         "BACKOFF",
		ReconnectBackoffActive: true,
		ReconnectAttemptCount:  3,
		LastReconnectAttemptMs: time.Unix(1_710_000_000, 0).UnixMilli(),
		NextReconnectAttemptMs: time.Unix(1_710_000_030, 0).UnixMilli(),
		ReconnectRemainingMs:   int64((30 * time.Second) / time.Millisecond),
		LastReconnectError:     "temporary control-plane failure",
	}

	value := formatAgentStatus(status)
	assertContains(t, value, "Reconnect State: waiting 30s")
	assertContains(t, value, "Reconnect Attempts: 3")
	assertContains(t, value, "Last Reconnect Error: temporary control-plane failure")
}

func TestFormatAgentStatusShowsNeighborSummaries(t *testing.T) {
	status := &clientagent.Status{
		ServiceName: "Ole Agent",
		Neighbors: []clientagent.NeighborStatus{
			{
				NetworkID:      "net-1",
				RemotePeerID:   "peer-2",
				Presence:       "online",
				NeighborState:  "DIRECT_CANDIDATE",
				CandidateCount: 2,
				Reachability:   "DIRECT",
				LastSeenUnix:   1710000000,
			},
		},
	}

	value := formatAgentStatus(status)
	assertContains(t, value, "Neighbors:")
	assertContains(t, value, "peer-2")
	assertContains(t, value, "DIRECT_CANDIDATE")
}

func TestFormatAgentStatusShowsGroupTrafficDiagnostics(t *testing.T) {
	status := &clientagent.Status{
		ServiceName: "Ole Agent",
		GroupTraffic: []clientagent.GroupTrafficDiagnostics{
			{
				NetworkID:            "net-1",
				Policy:               "FLOOD",
				BlockedPacketCount:   1,
				FloodPacketCount:     2,
				FanoutCopyCount:      4,
				BroadcastPacketCount: 2,
				MulticastPacketCount: 1,
				LastAction:           "FLOOD",
				LastPacketUnix:       1710000000,
			},
		},
	}

	value := formatAgentStatus(status)
	assertContains(t, value, "Group Traffic:")
	assertContains(t, value, "policy=flood")
	assertContains(t, value, "blocked=1")
	assertContains(t, value, "copies=4")
}

func TestFormatServiceHealthStatusShowsUpgradeBlock(t *testing.T) {
	now := time.Unix(1_710_000_600, 0)
	status := &clientagent.Status{
		ServiceName:          "Ole Agent",
		ListenAddress:        "127.0.0.1:5858",
		ServerBaseURL:        "http://localhost:8080",
		StartedAtUnix:        now.Add(-10 * time.Minute).Unix(),
		Connected:            true,
		ClientVersion:        "0.8.0",
		ServerVersion:        "1.2.0",
		MinClientVersion:     "1.0.0",
		CompatibilityStatus:  "UPGRADE_REQUIRED",
		CompatibilityMessage: "client is older than the minimum supported version",
		CurrentSession:       &Session{ID: "ses-1"},
		CurrentUser:          &User{ID: "usr-1", Email: "user@example.com"},
		CurrentDevice:        &Device{ID: "dev-1", Name: "Ole Desktop"},
		Security: clientagent.SecurityDiagnostics{
			EnrollmentStatus: "ACTIVE",
		},
	}

	value := formatServiceHealthStatusAt(status, now)
	assertContains(t, value, "Overall: blocked")
	assertContains(t, value, "Version Pairing: UPGRADE_REQUIRED")
	assertContains(t, value, "Minimum Client: 1.0.0")
	assertContains(t, value, "Next Action: Upgrade Ole Desktop")
}

func TestFormatServiceHealthStatusShowsLifecycleDegradation(t *testing.T) {
	now := time.Unix(1_710_001_200, 0)
	status := &clientagent.Status{
		ServiceName:            "Ole Agent",
		ListenAddress:          "127.0.0.1:5858",
		ServerBaseURL:          "http://localhost:8080",
		StartedAtUnix:          now.Add(-2 * time.Hour).Unix(),
		Connected:              true,
		CompatibilityStatus:    "COMPATIBLE",
		CompatibilityMessage:   "compatible",
		LastLifecycleError:     "heartbeat failed",
		LastSessionRefreshUnix: now.Add(-3 * time.Minute).Unix(),
		LastHeartbeatUnix:      now.Add(-2 * time.Minute).Unix(),
		LastPeerDiscoveryUnix:  now.Add(-1 * time.Minute).Unix(),
		ManagedPeerCount:       2,
		DiscoveredPeerCount:    4,
		Security: clientagent.SecurityDiagnostics{
			EnrollmentStatus: "ACTIVE",
			Alerts: []clientagent.SecurityAlert{
				{Code: "DEVICE_REVOKED"},
			},
		},
	}

	value := formatServiceHealthStatusAt(status, now)
	assertContains(t, value, "Overall: degraded")
	assertContains(t, value, "Service Uptime: 2h 0m")
	assertContains(t, value, "Last Lifecycle Error: heartbeat failed")
	assertContains(t, value, "Security Alerts: 1")
	assertContains(t, value, "Next Action: Review the lifecycle error")
}

func TestFormatServiceHealthStatusShowsReconnectBackoff(t *testing.T) {
	now := time.Unix(1_710_001_200, 0)
	status := &clientagent.Status{
		ServiceName:            "Ole Agent",
		ListenAddress:          "127.0.0.1:5858",
		ServerBaseURL:          "http://localhost:8080",
		StartedAtUnix:          now.Add(-30 * time.Minute).Unix(),
		Connected:              false,
		PersistedSession:       true,
		CompatibilityStatus:    "COMPATIBLE",
		ReconnectState:         "BACKOFF",
		ReconnectBackoffActive: true,
		ReconnectAttemptCount:  2,
		LastReconnectAttemptMs: now.Add(-10 * time.Second).UnixMilli(),
		NextReconnectAttemptMs: now.Add(20 * time.Second).UnixMilli(),
		ReconnectRemainingMs:   int64((20 * time.Second) / time.Millisecond),
		LastReconnectError:     "server unavailable",
	}

	value := formatServiceHealthStatusAt(status, now)
	assertContains(t, value, "Overall: recovering")
	assertContains(t, value, "Persisted Session: yes")
	assertContains(t, value, "Reconnect State: waiting 20s")
	assertContains(t, value, "Reconnect Attempts: 2")
	assertContains(t, value, "Reconnect Error: server unavailable")
	assertContains(t, value, "Next Action: Wait for the scheduled auto-reconnect retry")
}

func TestFormatServiceHealthStatusShowsDownloadedUpdate(t *testing.T) {
	now := time.Unix(1_710_001_200, 0)
	status := &clientagent.Status{
		ServiceName:   "Ole Agent",
		ListenAddress: "127.0.0.1:5858",
		ServerBaseURL: "http://localhost:8080",
		StartedAtUnix: now.Add(-time.Hour).Unix(),
		Update: clientagent.UpdateStatus{
			Channel:            "stable",
			ManifestURL:        "https://updates.example.com/ole-update.json",
			CurrentVersion:     "0.1.0",
			LatestVersion:      "0.2.0",
			Downloaded:         true,
			DownloadedPath:     `C:\Ole\updates\Ole-Setup-0.2.0.exe`,
			LastDownloadedUnix: now.Add(-5 * time.Minute).Unix(),
		},
	}

	value := formatServiceHealthStatusAt(status, now)
	assertContains(t, value, "Overall: ready-to-upgrade")
	assertContains(t, value, "Update Channel: stable")
	assertContains(t, value, "Update State: downloaded")
	assertContains(t, value, `Downloaded Installer: C:\Ole\updates\Ole-Setup-0.2.0.exe`)
	assertContains(t, value, "Next Action: Run `Install Update`")
}

func TestFormatServiceHealthStatusShowsSessionReuseRecovery(t *testing.T) {
	now := time.Unix(1_710_001_200, 0)
	status := &clientagent.Status{
		ServiceName:   "Ole Agent",
		ListenAddress: "127.0.0.1:5858",
		ServerBaseURL: "http://localhost:8080",
		StartedAtUnix: now.Add(-time.Hour).Unix(),
		Connected:     true,
		CurrentSession: &Session{
			ID: "ses-1",
		},
		Security: clientagent.SecurityDiagnostics{
			ReuseDetectedCount:          1,
			CurrentSessionReuseDetected: true,
			Alerts: []clientagent.SecurityAlert{
				{Code: "SESSION_REUSE_DETECTED"},
			},
		},
	}

	value := formatServiceHealthStatusAt(status, now)
	assertContains(t, value, "Overall: security-alert")
	assertContains(t, value, "Security Alerts: 1")
	assertContains(t, value, "Next Action: Use `Revoke All Sessions` and sign in again because token reuse was detected for this account.")
}

func TestFormatServiceHealthStatusShowsIncidentSummaryForTokenReuse(t *testing.T) {
	now := time.Unix(1_710_001_200, 0)
	status := &clientagent.Status{
		ServiceName:   "Ole Agent",
		ListenAddress: "127.0.0.1:5858",
		ServerBaseURL: "http://localhost:8080",
		StartedAtUnix: now.Add(-time.Hour).Unix(),
		Connected:     true,
		CurrentSession: &Session{
			ID: "ses-1",
		},
		Incidents: clientagent.IncidentSummary{
			ActiveCount:       1,
			TokenReuseCount:   1,
			MostSevere:        "elevated",
			LastCheckedUnix:   now.Unix(),
			RecommendedAction: "Use `Revoke All Sessions`, sign in again, and review the trusted-device list if you do not recognize the affected device.",
		},
	}

	value := formatServiceHealthStatusAt(status, now)
	assertContains(t, value, "Overall: security-alert")
	assertContains(t, value, "Active Incidents: 1")
	assertContains(t, value, "Token Reuse Incidents: 1")
	assertContains(t, value, "Incident Severity: elevated")
	assertContains(t, value, "Next Action: Use `Revoke All Sessions`, sign in again, and review the trusted-device list if you do not recognize the affected device.")
}

func TestFormatServiceHealthStatusShowsRollbackRecommendation(t *testing.T) {
	now := time.Unix(1_710_001_200, 0)
	status := &clientagent.Status{
		ServiceName:   "Ole Agent",
		ListenAddress: "127.0.0.1:5858",
		ServerBaseURL: "http://localhost:8080",
		StartedAtUnix: now.Add(-time.Hour).Unix(),
		ClientVersion: "0.2.0",
		ServerVersion: "0.1.0",
		Update: clientagent.UpdateStatus{
			Channel:                "stable",
			ManifestURL:            "https://updates.example.com/ole-update-stable.json",
			CurrentVersion:         "0.2.0",
			LatestVersion:          "0.2.0",
			PolicyStatus:           "BLOCKED_SERVER_TOO_OLD",
			PolicyMessage:          "server 0.1.0 is below the minimum supported version 0.2.0 for this update",
			MinimumServerVersion:   "0.2.0",
			RollbackAvailable:      true,
			RollbackVersion:        "0.1.0",
			RollbackReason:         "Use the previous installer while the server stays on 0.1.x",
			RollbackDownloaded:     true,
			RollbackDownloadedPath: `C:\Ole\updates\Ole-Setup-0.1.0.exe`,
		},
	}

	value := formatServiceHealthStatusAt(status, now)
	assertContains(t, value, "Overall: rollback-recommended")
	assertContains(t, value, "Update Policy: BLOCKED_SERVER_TOO_OLD")
	assertContains(t, value, "Rollback Available: yes")
	assertContains(t, value, "Rollback Downloaded: yes")
	assertContains(t, value, "Update Policy Message: server 0.1.0 is below the minimum supported version 0.2.0 for this update")
	assertContains(t, value, `Rollback Installer: C:\Ole\updates\Ole-Setup-0.1.0.exe`)
	assertContains(t, value, "Next Action: This update channel is not compatible with the current server. Use `Download Rollback` if you need to revert to the recommended rollback build.")
}

func TestFormatOnboardingGuideShowsFirstRunInstructions(t *testing.T) {
	value := formatOnboardingGuide(nil, 0, nil, 0, 0)
	assertContains(t, value, "Current Step: bring the local Ole Agent online.")
	assertContains(t, value, "Start `cmd/agent` or the Windows service.")
	assertContains(t, value, "Use `Create Account` for a new account or `Sign In` for an existing one.")
}

func TestFormatOnboardingGuideShowsCreateNetworkStep(t *testing.T) {
	value := formatOnboardingGuide(&clientagent.Status{
		ServiceName: "Ole Agent",
		Connected:   true,
		CurrentSession: &Session{
			ID: "ses-1",
		},
	}, 0, nil, 0, 0)
	assertContains(t, value, "Current Step: create or join your first network.")
	assertContains(t, value, "Use `Create Network`")
	assertContains(t, value, "Join By Invite")
}

func TestFormatOnboardingGuideShowsRecoveryForPendingTransport(t *testing.T) {
	value := formatOnboardingGuide(&clientagent.Status{
		ServiceName: "Ole Agent",
		Connected:   true,
		Connections: []clientagent.ConnectionStatus{
			{
				NetworkID:         "net-1",
				State:             "NEGOTIATING",
				TransportReady:    false,
				RemotePeerID:      "peer-2",
				TransportMode:     "",
				Reachability:      "DIRECT",
				AttemptCount:      1,
				SelectedCandidate: "198.51.100.4:5000",
			},
		},
	}, 1, &Network{ID: "net-1", Name: "friends"}, 1, 1)
	assertContains(t, value, "Current Step: wait for transport to finish negotiating.")
	assertContains(t, value, "Connection Diagnostics")
	assertContains(t, value, "Reconnect")
	assertContains(t, value, "Reconnect This PC")
}

func TestFormatOnboardingGuideShowsSensitiveNetworkApprovalStep(t *testing.T) {
	value := formatOnboardingGuide(&clientagent.Status{
		ServiceName: "Ole Agent",
		Connected:   true,
		CurrentSession: &Session{
			ID: "ses-1",
		},
		CurrentDevice: &Device{ID: "dev-2", Name: "Laptop"},
		Security: clientagent.SecurityDiagnostics{
			CurrentDeviceID: "dev-2",
		},
	}, 1, &Network{
		ID:                     "net-1",
		Name:                   "sensitive",
		DeviceApprovalRequired: true,
		ApprovedDeviceIDs:      []string{},
	}, 0, 0)
	assertContains(t, value, "Current Step: approve the current device for the selected sensitive network.")
	assertContains(t, value, "Approve For Network")
	assertContains(t, value, "Connect This PC")
}

func TestFormatOnboardingGuideShowsSessionReuseRecoveryStep(t *testing.T) {
	value := formatOnboardingGuide(&clientagent.Status{
		ServiceName: "Ole Agent",
		Connected:   true,
		CurrentSession: &Session{
			ID: "ses-1",
		},
		Security: clientagent.SecurityDiagnostics{
			ReuseDetectedCount:          1,
			CurrentSessionReuseDetected: true,
		},
	}, 1, &Network{ID: "net-1", Name: "friends"}, 1, 1)
	assertContains(t, value, "Current Step: secure the account before continuing network setup.")
	assertContains(t, value, "Revoke All Sessions")
	assertContains(t, value, "Sign in again")
}

func TestFormatSessionDetailsShowsReuseRecoveryAction(t *testing.T) {
	value := formatSessionDetails(Session{
		ID:                  "ses-1",
		FamilyID:            "fam-1",
		DeviceName:          "Laptop",
		ReuseDetectedAtUnix: 1710000000,
	}, &Session{ID: "ses-1", FamilyID: "fam-1"})
	assertContains(t, value, "Security Alert: token reuse detected for this session family")
	assertContains(t, value, "Recommended Action: Use `Revoke All Sessions` and sign in again.")
}

func TestFormatNetworkSummaryLineShowsNameResolutionPolicy(t *testing.T) {
	line := formatNetworkSummaryLine(Network{
		ID:                 "net-1",
		Name:               "friends",
		Access:             "INVITE_ONLY",
		RoutingPolicy:      "FULL",
		GroupTrafficPolicy: "FLOOD",
		NameResolutionMode: "NETWORK_ONLY",
		DNSLabel:           "friends-lan",
		Members:            []string{"usr-1"},
	}, &clientagent.Status{
		Adapter: virtualadapter.Status{
			Networks: []virtualadapter.NetworkBinding{
				{
					NetworkID:     "net-1",
					RoutingPolicy: "FULL",
					PolicyStatus:  "ACTIVE",
					GatewayRole:   "CLIENT",
					GatewayPeerID: "peer-gw",
				},
			},
		},
		Connections: []clientagent.ConnectionStatus{
			{
				NetworkID:      "net-1",
				RemotePeerID:   "peer-gw",
				State:          "CONNECTED",
				TransportReady: true,
				TransportMode:  "DIRECT",
			},
		},
	})
	assertContains(t, line, "routing=full")
	assertContains(t, line, "transport=healthy")
	assertContains(t, line, "via peer-gw direct")
	assertContains(t, line, "group=flood")
	assertContains(t, line, "dns=network-only (friends-lan)")
}

func TestFormatNetworkSummaryLineShowsCurrentRole(t *testing.T) {
	line := formatNetworkSummaryLine(Network{
		ID:          "net-1",
		Name:        "friends",
		Access:      "INVITE_ONLY",
		OwnerID:     "usr-owner",
		Members:     []string{"usr-owner", "usr-admin"},
		MemberRoles: map[string]string{"usr-owner": "OWNER", "usr-admin": "ADMIN"},
	}, &clientagent.Status{
		CurrentUser: &User{ID: "usr-admin"},
	})

	assertContains(t, line, "role=admin")
}

func TestFormatDeviceDetailsForNetworkShowsGroupTrafficPolicy(t *testing.T) {
	value := formatDeviceDetailsForNetwork([]Device{
		{
			ID:          "dev-1",
			UserID:      "usr-1",
			Name:        "Laptop",
			Status:      "ACTIVE",
			Fingerprint: "abcd1234efgh5678",
		},
	}, &Device{
		ID:          "dev-1",
		UserID:      "usr-1",
		Name:        "Laptop",
		Status:      "ACTIVE",
		Fingerprint: "abcd1234efgh5678",
	}, &Network{
		ID:                 "net-1",
		Name:               "friends",
		GroupTrafficPolicy: "FLOOD",
		RoutingPolicy:      "FULL",
	}, &clientagent.Status{
		CurrentSession: &Session{ID: "ses-1"},
		Security: clientagent.SecurityDiagnostics{
			CurrentDeviceID: "dev-1",
		},
	})

	assertContains(t, value, "Group Traffic: flood")
	assertContains(t, value, "Group Traffic Note: FLOOD fans out IPv4 broadcast and multicast packets")
	assertContains(t, value, "Routing Note: FULL sends non-overlay IPv4 through an OWNER or ADMIN gateway")
	assertContains(t, value, "Gateway Status: pending gateway")
	assertContains(t, value, "Gateway Next Action: Wait for an OWNER or ADMIN peer to become transport-ready")
	assertContains(t, value, "Transport Summary: idle")
	assertContains(t, value, "Transport Next Action: No live transport paths are ready for this network yet.")
}

func TestFormatDeviceDetailsForNetworkShowsPermissionMatrix(t *testing.T) {
	value := formatDeviceDetailsForNetwork([]Device{
		{
			ID:          "dev-1",
			UserID:      "usr-admin",
			Name:        "Laptop",
			Status:      "ACTIVE",
			Fingerprint: "abcd1234efgh5678",
		},
	}, &Device{
		ID:          "dev-1",
		UserID:      "usr-admin",
		Name:        "Laptop",
		Status:      "ACTIVE",
		Fingerprint: "abcd1234efgh5678",
	}, &Network{
		ID:          "net-1",
		Name:        "friends",
		OwnerID:     "usr-owner",
		Members:     []string{"usr-owner", "usr-admin", "usr-read"},
		MemberRoles: map[string]string{"usr-owner": "OWNER", "usr-admin": "ADMIN", "usr-read": "READ_ONLY"},
	}, &clientagent.Status{
		CurrentUser:    &User{ID: "usr-admin"},
		CurrentSession: &Session{ID: "ses-1", UserID: "usr-admin"},
		Security: clientagent.SecurityDiagnostics{
			CurrentDeviceID: "dev-1",
		},
	})

	assertContains(t, value, "Current Role: admin")
	assertContains(t, value, "Current Permissions: view, use, settings, invites, members, files")
	assertContains(t, value, "Role Matrix:")
	assertContains(t, value, "owner: view, use, settings, invites, members, files, moderate, delete")
	assertContains(t, value, "read-only: view")
	assertContains(t, value, "Owner-only Note: deleting the network and changing member roles stay owner-only.")
}

func TestFormatAgentStatusShowsAdapterRoutingPolicyStatus(t *testing.T) {
	status := &clientagent.Status{
		ServiceName: "Ole Agent",
		Adapter: virtualadapter.Status{
			Networks: []virtualadapter.NetworkBinding{
				{
					NetworkID:        "net-1",
					VirtualIP:        "10.0.0.2",
					PrefixLength:     24,
					RoutePrefix:      "10.0.0.0/24",
					RoutingPolicy:    "FULL",
					PolicyStatus:     "PENDING_GATEWAY",
					IPAddressVisible: true,
					RouteVisible:     true,
					RouteMetric:      5,
				},
			},
		},
	}

	value := formatAgentStatus(status)
	assertContains(t, value, "routing=full")
	assertContains(t, value, "policy=pending_gateway")
}

func TestFormatConnectionDiagnosticsShowsGatewayPathForFullNetwork(t *testing.T) {
	status := &clientagent.Status{
		Adapter: virtualadapter.Status{
			Networks: []virtualadapter.NetworkBinding{
				{
					NetworkID:     "net-1",
					RoutingPolicy: "FULL",
					PolicyStatus:  "ACTIVE",
					GatewayRole:   "CLIENT",
					GatewayPeerID: "peer-gw",
				},
			},
		},
		Connections: []clientagent.ConnectionStatus{
			{
				NetworkID:         "net-1",
				LocalPeerID:       "peer-local",
				RemotePeerID:      "peer-gw",
				State:             "CONNECTED",
				TransportReady:    true,
				TransportMode:     "RELAY",
				Reachability:      "RELAY",
				AverageRTTMillis:  82,
				ConsecutiveLosses: 1,
			},
		},
	}

	value := formatConnectionDiagnostics(status, &Network{ID: "net-1", RoutingPolicy: "FULL"})
	assertContains(t, value, "Gateway Path")
	assertContains(t, value, "Gateway Status: active")
	assertContains(t, value, "Gateway Role: client")
	assertContains(t, value, "Gateway Peer: peer-gw")
	assertContains(t, value, "Gateway Path: relay")
	assertContains(t, value, "Gateway RTT: 82 ms")
}

func TestFormatConnectionDiagnosticsShowsPendingGatewayAction(t *testing.T) {
	status := &clientagent.Status{
		Adapter: virtualadapter.Status{
			Networks: []virtualadapter.NetworkBinding{
				{
					NetworkID:     "net-1",
					RoutingPolicy: "FULL",
					PolicyStatus:  "PENDING_GATEWAY",
				},
			},
		},
	}

	value := formatConnectionDiagnostics(status, &Network{ID: "net-1", RoutingPolicy: "FULL"})
	assertContains(t, value, "Gateway Status: pending gateway")
	assertContains(t, value, "Gateway Path: pending")
	assertContains(t, value, "Gateway Next Action: Wait for an OWNER or ADMIN peer to become transport-ready")
}

func TestFormatConnectionDiagnosticsShowsStandbyGatewayAction(t *testing.T) {
	status := &clientagent.Status{
		Adapter: virtualadapter.Status{
			Networks: []virtualadapter.NetworkBinding{
				{
					NetworkID:     "net-1",
					RoutingPolicy: "FULL",
					PolicyStatus:  "STANDBY_GATEWAY",
					GatewayRole:   "CLIENT",
					GatewayPeerID: "peer-owner",
				},
			},
		},
		Connections: []clientagent.ConnectionStatus{
			{
				NetworkID:      "net-1",
				RemotePeerID:   "peer-owner",
				State:          "CONNECTED",
				TransportMode:  "DIRECT",
				Reachability:   "DIRECT",
				TransportReady: true,
			},
		},
	}

	value := formatConnectionDiagnostics(status, &Network{ID: "net-1", RoutingPolicy: "FULL"})
	assertContains(t, value, "Gateway Status: standby gateway")
	assertContains(t, value, "Gateway Path: direct")
	assertContains(t, value, "Gateway Next Action: Another FULL network currently owns the default route")
}

func TestGatewayDiagnosticsPrefersReplacementGatewayConnection(t *testing.T) {
	status := &clientagent.Status{
		Adapter: virtualadapter.Status{
			Networks: []virtualadapter.NetworkBinding{
				{
					NetworkID:     "net-1",
					RoutingPolicy: "FULL",
					PolicyStatus:  "ACTIVE",
					GatewayRole:   "CLIENT",
					GatewayPeerID: "peer-old",
				},
			},
		},
		Connections: []clientagent.ConnectionStatus{
			{
				NetworkID:        "net-1",
				LocalPeerID:      "peer-local",
				RemotePeerID:     "peer-new",
				RemoteUserID:     "user-owner",
				State:            "CONNECTED",
				TransportReady:   true,
				TransportMode:    "DIRECT",
				Reachability:     "DIRECT",
				AverageRTTMillis: 12,
			},
		},
	}

	diag := gatewayDiagnosticsForNetwork(status, &Network{
		ID:            "net-1",
		RoutingPolicy: "FULL",
		OwnerID:       "user-owner",
	})

	if diag == nil {
		t.Fatalf("expected gateway diagnostics to be present")
	}
	if diag.GatewayPeerID != "peer-new" || diag.TransportMode != "DIRECT" || diag.ConnectionState != "CONNECTED" {
		t.Fatalf("expected gateway diagnostics to prefer replacement owner connection, got %#v", diag)
	}
}

func TestGatewayDiagnosticsPrefersReplacementGatewayConnectionWithoutUserMetadata(t *testing.T) {
	status := &clientagent.Status{
		Adapter: virtualadapter.Status{
			Networks: []virtualadapter.NetworkBinding{
				{
					NetworkID:        "net-1",
					RoutingPolicy:    "FULL",
					PolicyStatus:     "ACTIVE",
					GatewayRole:      "CLIENT",
					GatewayPeerID:    "peer-old",
					GatewayUserID:    "user-owner",
					GatewayVirtualIP: "10.10.0.3",
				},
			},
		},
		Connections: []clientagent.ConnectionStatus{
			{
				NetworkID:        "net-1",
				LocalPeerID:      "peer-local",
				RemotePeerID:     "peer-new",
				RemoteVirtualIP:  "10.10.0.3",
				State:            "CONNECTED",
				TransportReady:   true,
				TransportMode:    "DIRECT",
				Reachability:     "DIRECT",
				AverageRTTMillis: 12,
			},
		},
	}

	diag := gatewayDiagnosticsForNetwork(status, &Network{
		ID:            "net-1",
		RoutingPolicy: "FULL",
		OwnerID:       "user-owner",
	})

	if diag == nil {
		t.Fatalf("expected gateway diagnostics to be present")
	}
	if diag.GatewayPeerID != "peer-new" || diag.TransportMode != "DIRECT" || diag.ConnectionState != "CONNECTED" {
		t.Fatalf("expected gateway diagnostics to preserve replacement owner connection during metadata gap, got %#v", diag)
	}
}

func TestGatewayDiagnosticsFailsClosedForDistinctUserOnReplacementGatewayCollision(t *testing.T) {
	status := &clientagent.Status{
		Adapter: virtualadapter.Status{
			Networks: []virtualadapter.NetworkBinding{
				{
					NetworkID:        "net-1",
					RoutingPolicy:    "FULL",
					PolicyStatus:     "ACTIVE",
					GatewayRole:      "CLIENT",
					GatewayPeerID:    "peer-old",
					GatewayUserID:    "user-owner",
					GatewayVirtualIP: "10.10.0.3",
				},
			},
		},
		Connections: []clientagent.ConnectionStatus{
			{
				NetworkID:        "net-1",
				LocalPeerID:      "peer-local",
				RemotePeerID:     "peer-other",
				RemoteUserID:     "user-other",
				RemoteVirtualIP:  "10.10.0.3",
				State:            "CONNECTED",
				TransportReady:   true,
				TransportMode:    "DIRECT",
				Reachability:     "DIRECT",
				AverageRTTMillis: 12,
			},
		},
	}

	diag := gatewayDiagnosticsForNetwork(status, &Network{
		ID:            "net-1",
		RoutingPolicy: "FULL",
		OwnerID:       "user-owner",
		MemberRoles: map[string]string{
			"user-owner": "OWNER",
			"user-other": "ADMIN",
		},
	})

	if diag == nil {
		t.Fatalf("expected gateway diagnostics to be present")
	}
	if diag.GatewayPeerID != "peer-old" {
		t.Fatalf("expected gateway diagnostics to keep stale bound peer id on distinct-user collision, got %#v", diag)
	}
}

func TestBestPeerConnectionPrefersSameUserReplacement(t *testing.T) {
	status := &clientagent.Status{
		Connections: []clientagent.ConnectionStatus{
			{
				NetworkID:        "net-1",
				LocalPeerID:      "peer-local",
				RemotePeerID:     "peer-new",
				RemoteUserID:     "user-remote",
				RemoteVirtualIP:  "10.10.0.3",
				State:            "CONNECTED",
				TransportReady:   true,
				TransportMode:    "DIRECT",
				Reachability:     "DIRECT",
				AverageRTTMillis: 12,
			},
		},
	}

	connection := bestPeerConnection(status, Peer{
		ID:        "peer-old",
		NetworkID: "net-1",
		UserID:    "user-remote",
		VirtualIP: "10.10.0.3",
	}, &Network{ID: "net-1"})

	if connection == nil || connection.RemotePeerID != "peer-new" {
		t.Fatalf("expected peer connection to fall back to same-user replacement, got %#v", connection)
	}
}

func TestBestPeerConnectionPrefersReplacementWhenPeerUserMetadataIsMissing(t *testing.T) {
	status := &clientagent.Status{
		Connections: []clientagent.ConnectionStatus{
			{
				NetworkID:        "net-1",
				LocalPeerID:      "peer-local",
				RemotePeerID:     "peer-new",
				RemoteUserID:     "user-remote",
				RemoteVirtualIP:  "10.10.0.3",
				State:            "CONNECTED",
				TransportReady:   true,
				TransportMode:    "DIRECT",
				Reachability:     "DIRECT",
				AverageRTTMillis: 12,
			},
		},
	}

	connection := bestPeerConnection(status, Peer{
		ID:        "peer-old",
		NetworkID: "net-1",
		VirtualIP: "10.10.0.3",
	}, &Network{ID: "net-1"})

	if connection == nil || connection.RemotePeerID != "peer-new" {
		t.Fatalf("expected peer connection to survive missing peer user metadata, got %#v", connection)
	}
}

func TestBestPeerConnectionPrefersReplacementWhenConnectionUserMetadataIsMissing(t *testing.T) {
	status := &clientagent.Status{
		Connections: []clientagent.ConnectionStatus{
			{
				NetworkID:        "net-1",
				LocalPeerID:      "peer-local",
				RemotePeerID:     "peer-new",
				RemoteVirtualIP:  "10.10.0.3",
				State:            "CONNECTED",
				TransportReady:   true,
				TransportMode:    "DIRECT",
				Reachability:     "DIRECT",
				AverageRTTMillis: 12,
			},
		},
	}

	connection := bestPeerConnection(status, Peer{
		ID:        "peer-old",
		NetworkID: "net-1",
		UserID:    "user-remote",
		VirtualIP: "10.10.0.3",
	}, &Network{ID: "net-1"})

	if connection == nil || connection.RemotePeerID != "peer-new" {
		t.Fatalf("expected peer connection to survive missing connection user metadata, got %#v", connection)
	}
}

func TestBestPeerConnectionFailsClosedForDistinctUserOnSameVirtualIP(t *testing.T) {
	status := &clientagent.Status{
		Connections: []clientagent.ConnectionStatus{
			{
				NetworkID:        "net-1",
				LocalPeerID:      "peer-local",
				RemotePeerID:     "peer-other",
				RemoteUserID:     "user-other",
				RemoteVirtualIP:  "10.10.0.3",
				State:            "CONNECTED",
				TransportReady:   true,
				TransportMode:    "DIRECT",
				Reachability:     "DIRECT",
				AverageRTTMillis: 12,
			},
		},
	}

	connection := bestPeerConnection(status, Peer{
		ID:        "peer-old",
		NetworkID: "net-1",
		UserID:    "user-remote",
		VirtualIP: "10.10.0.3",
	}, &Network{ID: "net-1"})

	if connection != nil {
		t.Fatalf("expected peer connection fallback to fail closed for a distinct user sharing the same virtual ip, got %#v", connection)
	}
}

func TestFormatConnectionDiagnosticsShowsGatewayHistory(t *testing.T) {
	status := &clientagent.Status{
		GatewayHistory: []clientagent.GatewayChangeEvent{
			{
				NetworkID:             "net-1",
				Event:                 "FAILOVER",
				PreviousGatewayPeerID: "peer-owner",
				PreviousPath:          "DIRECT",
				PreviousPolicyStatus:  "ACTIVE",
				CurrentGatewayPeerID:  "peer-admin",
				CurrentPath:           "RELAY",
				CurrentPolicyStatus:   "ACTIVE",
				ChangedAtUnix:         1710000200,
			},
		},
	}

	value := formatConnectionDiagnostics(status, &Network{ID: "net-1", RoutingPolicy: "FULL"})
	assertContains(t, value, "Gateway History")
	assertContains(t, value, "failover | net-1 | peer-owner -> peer-admin | direct -> relay")
}

func TestFormatConnectionDiagnosticsShowsGatewayFailbackHistory(t *testing.T) {
	status := &clientagent.Status{
		GatewayHistory: []clientagent.GatewayChangeEvent{
			{
				NetworkID:             "net-1",
				Event:                 "FAILBACK",
				PreviousGatewayPeerID: "peer-admin",
				PreviousPath:          "DIRECT",
				PreviousPolicyStatus:  "ACTIVE",
				CurrentGatewayPeerID:  "peer-owner",
				CurrentPath:           "DIRECT",
				CurrentPolicyStatus:   "ACTIVE",
				ChangedAtUnix:         1710000300,
			},
		},
	}

	value := formatConnectionDiagnostics(status, &Network{ID: "net-1", RoutingPolicy: "FULL"})
	assertContains(t, value, "Gateway History")
	assertContains(t, value, "failback | net-1 | peer-admin -> peer-owner | direct -> direct")
}

func TestFormatConnectionDiagnosticsShowsGatewayPromotionAndDemotionHistory(t *testing.T) {
	status := &clientagent.Status{
		GatewayHistory: []clientagent.GatewayChangeEvent{
			{
				NetworkID:             "net-1",
				Event:                 "PROMOTED",
				PreviousGatewayPeerID: "peer-admin",
				PreviousPath:          "DIRECT",
				PreviousPolicyStatus:  "STANDBY_GATEWAY",
				CurrentGatewayPeerID:  "peer-admin",
				CurrentPath:           "DIRECT",
				CurrentPolicyStatus:   "ACTIVE",
				ChangedAtUnix:         1710000400,
			},
			{
				NetworkID:             "net-1",
				Event:                 "DEMOTED",
				PreviousGatewayPeerID: "peer-admin",
				PreviousPath:          "DIRECT",
				PreviousPolicyStatus:  "ACTIVE",
				CurrentGatewayPeerID:  "peer-admin",
				CurrentPath:           "DIRECT",
				CurrentPolicyStatus:   "STANDBY_GATEWAY",
				ChangedAtUnix:         1710000500,
			},
		},
	}

	value := formatConnectionDiagnostics(status, &Network{ID: "net-1", RoutingPolicy: "FULL"})
	assertContains(t, value, "Gateway History")
	assertContains(t, value, "promoted | net-1 | peer-admin -> peer-admin | direct -> direct")
	assertContains(t, value, "demoted | net-1 | peer-admin -> peer-admin | direct -> direct")
}

func TestFormatDeviceDetailsForNetworkShowsGatewayLastChange(t *testing.T) {
	value := formatDeviceDetailsForNetwork([]Device{
		{
			ID:          "dev-1",
			UserID:      "usr-1",
			Name:        "Laptop",
			Status:      "ACTIVE",
			Fingerprint: "abcd1234efgh5678",
		},
	}, &Device{
		ID:          "dev-1",
		UserID:      "usr-1",
		Name:        "Laptop",
		Status:      "ACTIVE",
		Fingerprint: "abcd1234efgh5678",
	}, &Network{
		ID:            "net-1",
		Name:          "friends",
		RoutingPolicy: "FULL",
	}, &clientagent.Status{
		CurrentSession: &Session{ID: "ses-1"},
		Security: clientagent.SecurityDiagnostics{
			CurrentDeviceID: "dev-1",
		},
		GatewayHistory: []clientagent.GatewayChangeEvent{
			{
				NetworkID:            "net-1",
				Event:                "SELECTED",
				PreviousPath:         "PENDING",
				PreviousPolicyStatus: "PENDING_GATEWAY",
				CurrentGatewayPeerID: "peer-owner",
				CurrentPath:          "DIRECT",
				CurrentPolicyStatus:  "ACTIVE",
				ChangedAtUnix:        1710000100,
			},
		},
	})

	assertContains(t, value, "Gateway Last Change: selected | net-1 | pending gateway -> peer-owner | pending -> direct")
	assertContains(t, value, "Gateway Recent Changes: 1")
}

func TestFormatConnectionDiagnosticsShowsOverlayNeighbors(t *testing.T) {
	status := &clientagent.Status{
		Neighbors: []clientagent.NeighborStatus{
			{
				NetworkID:          "net-1",
				LocalPeerID:        "peer-1",
				RemotePeerID:       "peer-2",
				RemoteVirtualIP:    "10.0.0.3",
				RemoteEndpoint:     "198.51.100.10:5000",
				OverlayCIDR:        "10.0.0.0/24",
				Presence:           "online",
				NeighborState:      "CONNECTED",
				Reachability:       "DIRECT",
				CandidateCount:     2,
				TransportReady:     true,
				TransportMode:      "DIRECT",
				LastSeenUnix:       1710000000,
				LastSignaledAtUnix: 1710000010,
			},
		},
		GroupTraffic: []clientagent.GroupTrafficDiagnostics{
			{
				NetworkID:            "net-1",
				Policy:               "FLOOD",
				BlockedPacketCount:   0,
				FloodPacketCount:     1,
				FanoutCopyCount:      2,
				BroadcastPacketCount: 1,
				LastAction:           "FLOOD",
				LastPacketUnix:       1710000020,
			},
		},
		Connections: []clientagent.ConnectionStatus{
			{
				NetworkID:                "net-1",
				LocalPeerID:              "peer-1",
				RemotePeerID:             "peer-2",
				State:                    "CONNECTED",
				TransportReady:           true,
				TransportMode:            "DIRECT",
				AverageRTTMillis:         24,
				GroupTrafficPacketCopies: 2,
				GroupBroadcastCopies:     1,
				GroupMulticastCopies:     1,
				LastGroupTrafficUnix:     1710000020,
				TransportPacketCount:     7,
				LastTransportUnix:        1710000025,
			},
		},
	}

	value := formatConnectionDiagnostics(status, &Network{ID: "net-1"})
	assertContains(t, value, "Network Transport Summary")
	assertContains(t, value, "Quality: healthy")
	assertContains(t, value, "Connections: total=1 | connected=1 | pending=0 | fallback-ready=0")
	assertContains(t, value, "Connected Modes: direct=1 | relay=0")
	assertContains(t, value, "Average RTT: 24 ms")
	assertContains(t, value, "Transport Packets: 7")
	assertContains(t, value, "Overlay Neighbors")
	assertContains(t, value, "Group Traffic")
	assertContains(t, value, "Fanout Copies: 2")
	assertContains(t, value, "Group Traffic Copies: 2")
	assertContains(t, value, "Neighbor State: CONNECTED")
	assertContains(t, value, "Overlay CIDR: 10.0.0.0/24")
}

func TestFormatConnectionDiagnosticsShowsDegradedNetworkTransportSummary(t *testing.T) {
	status := &clientagent.Status{
		Connections: []clientagent.ConnectionStatus{
			{
				NetworkID:            "net-1",
				LocalPeerID:          "peer-1",
				RemotePeerID:         "peer-2",
				State:                "CONNECTED",
				TransportReady:       true,
				TransportMode:        "DIRECT",
				AverageRTTMillis:     48,
				ConsecutiveLosses:    2,
				TransportPacketCount: 10,
				LastTransportUnix:    1710000100,
			},
			{
				NetworkID:            "net-1",
				LocalPeerID:          "peer-1",
				RemotePeerID:         "peer-3",
				State:                "NEGOTIATING",
				TransportReady:       false,
				TransportPacketCount: 1,
			},
			{
				NetworkID:            "net-1",
				LocalPeerID:          "peer-1",
				RemotePeerID:         "peer-4",
				State:                "CONNECTED",
				TransportReady:       true,
				TransportMode:        "RELAY",
				Reachability:         "RELAY",
				AverageRTTMillis:     92,
				TransportPacketCount: 4,
				LastTransportUnix:    1710000110,
			},
		},
	}

	value := formatConnectionDiagnostics(status, &Network{ID: "net-1"})
	assertContains(t, value, "Quality: degraded")
	assertContains(t, value, "Connections: total=3 | connected=2 | pending=1 | fallback-ready=0")
	assertContains(t, value, "Connected Modes: direct=1 | relay=1")
	assertContains(t, value, "Connection Quality: healthy=0 | degraded=1")
	assertContains(t, value, "Average RTT: 70 ms")
	assertContains(t, value, "Worst Losses: 2")
	assertContains(t, value, "Transport Packets: 15")
	assertContains(t, value, "Next Action: Watch RTT and loss telemetry; use `Reconnect` if the degraded path does not recover.")
}

func TestFormatOnboardingGuideShowsReconnectBackoffRecovery(t *testing.T) {
	value := formatOnboardingGuide(&clientagent.Status{
		ServiceName:            "Ole Agent",
		PersistedSession:       true,
		ReconnectState:         "BACKOFF",
		ReconnectBackoffActive: true,
		ReconnectAttemptCount:  1,
		NextReconnectAttemptMs: time.Now().Add(15 * time.Second).UnixMilli(),
		ReconnectRemainingMs:   int64((15 * time.Second) / time.Millisecond),
		LastReconnectError:     "server unavailable",
	}, 0, nil, 0, 0)
	assertContains(t, value, "Current Step: wait for the local agent to retry the persisted session restore.")
	assertContains(t, value, "Use `Reconnect` to bypass the backoff window")
	assertContains(t, value, "Next reconnect:")
}

func TestFormatDevicesShowsTrustLabels(t *testing.T) {
	status := &clientagent.Status{
		CurrentSession: &Session{ID: "ses-1"},
		Security: clientagent.SecurityDiagnostics{
			CurrentDeviceID:  "dev-1",
			EnrollmentStatus: "ACTIVE",
		},
	}
	devices := []Device{
		{ID: "dev-1", Name: "Current Desktop", Status: "ACTIVE", CreatedAtUnix: 1710000000},
		{ID: "dev-2", Name: "Old Laptop", Status: "REVOKED", CreatedAtUnix: 1710000100, RevokedAtUnix: 1710000200},
	}

	value := formatDeviceDetails(devices, &devices[0], status)
	assertContains(t, value, "Summary: total=2 | trusted=1 | revoked=1")
	assertContains(t, value, "Selected Device")
	assertContains(t, value, "Name: Current Desktop")
	assertContains(t, value, "Trust: current-trusted")
}

func TestFormatDevicesRequiresSession(t *testing.T) {
	value := formatDeviceDetails([]Device{{ID: "dev-1", Name: "Desktop", Status: "ACTIVE"}}, nil, nil)
	assertContains(t, value, "Sign in to inspect trusted devices.")
}

func TestFormatDeviceSummaryLineShowsFingerprintPreview(t *testing.T) {
	status := &clientagent.Status{
		Security: clientagent.SecurityDiagnostics{
			CurrentDeviceID: "dev-1",
		},
	}
	line := formatDeviceSummaryLine(Device{
		ID:          "dev-1",
		Name:        "Desktop",
		Status:      "ACTIVE",
		Fingerprint: "abcdef0123456789fedcba9876543210",
	}, status)
	assertContains(t, line, "Desktop")
	assertContains(t, line, "trust=current-trusted")
	assertContains(t, line, "fingerprint=abcdef01...76543210")
}

func TestFormatDeviceDetailsShowsFingerprint(t *testing.T) {
	status := &clientagent.Status{
		CurrentSession: &Session{ID: "ses-1"},
		Security: clientagent.SecurityDiagnostics{
			CurrentDeviceID:  "dev-2",
			EnrollmentStatus: "ACTIVE",
		},
	}
	devices := []Device{
		{
			ID:            "dev-2",
			UserID:        "usr-1",
			Name:          "Laptop",
			Fingerprint:   "fp-dev-2",
			Status:        "ACTIVE",
			CreatedAtUnix: 1710000100,
		},
	}
	value := formatDeviceDetails(devices, &devices[0], status)
	assertContains(t, value, "Fingerprint: fp-dev-2")
	assertContains(t, value, "ID: dev-2")
	assertContains(t, value, "User ID: usr-1")
}

func TestFormatDeviceDetailsShowsSelectedNetworkApprovalState(t *testing.T) {
	status := &clientagent.Status{
		CurrentSession: &Session{ID: "ses-1"},
		Security: clientagent.SecurityDiagnostics{
			CurrentDeviceID:  "dev-2",
			EnrollmentStatus: "ACTIVE",
		},
	}
	devices := []Device{
		{
			ID:            "dev-2",
			UserID:        "usr-1",
			Name:          "Laptop",
			Fingerprint:   "fp-dev-2",
			Status:        "ACTIVE",
			CreatedAtUnix: 1710000100,
		},
	}
	network := &Network{
		ID:                     "net-1",
		Name:                   "sensitive",
		DeviceApprovalRequired: true,
		ApprovedDeviceIDs:      []string{"dev-2"},
	}
	value := formatDeviceDetailsForNetwork(devices, &devices[0], network, status)
	assertContains(t, value, "Selected Network")
	assertContains(t, value, "Sensitive: yes")
	assertContains(t, value, "Selected Device Approval: approved")
}

func TestFormatDeviceDetailsShowsPendingApprovalAction(t *testing.T) {
	status := &clientagent.Status{
		CurrentSession: &Session{ID: "ses-1"},
		CurrentDevice:  &Device{ID: "dev-2", Name: "Laptop"},
		Security: clientagent.SecurityDiagnostics{
			CurrentDeviceID:  "dev-2",
			EnrollmentStatus: "ACTIVE",
		},
	}
	devices := []Device{
		{
			ID:            "dev-2",
			UserID:        "usr-1",
			Name:          "Laptop",
			Fingerprint:   "fp-dev-2",
			Status:        "ACTIVE",
			CreatedAtUnix: 1710000100,
		},
	}
	network := &Network{
		ID:                     "net-1",
		Name:                   "sensitive",
		DeviceApprovalRequired: true,
	}
	value := formatDeviceDetailsForNetwork(devices, &devices[0], network, status)
	assertContains(t, value, "Selected Device Approval: pending approval")
	assertContains(t, value, "Next Action: Press `Approve For Network` before `Connect This PC` or `Reconnect This PC`.")
}

func TestFormatQuickStartGuideShowsSignInPath(t *testing.T) {
	value := formatQuickStartGuide(nil, 0, nil, 0, 0)
	assertContains(t, value, "Start the Ole Agent service.")
	assertContains(t, value, "Refresh Ole Agent")
	assertContains(t, value, "Create Account")
	assertContains(t, value, "Sign In")
}

func TestFormatQuickStartGuideShowsCreateOrJoinPath(t *testing.T) {
	value := formatQuickStartGuide(&clientagent.Status{
		ServiceName: "Ole Agent",
		Connected:   true,
		CurrentSession: &Session{
			ID: "ses-1",
		},
	}, 0, nil, 0, 0)
	assertContains(t, value, "create or join a network")
	assertContains(t, value, "2A. Create Your Network")
	assertContains(t, value, "2B. Join By Invite")
}

func TestFormatQuickStartGuideShowsConnectThisPCPath(t *testing.T) {
	value := formatQuickStartGuide(&clientagent.Status{
		ServiceName: "Ole Agent",
		Connected:   true,
		CurrentSession: &Session{
			ID: "ses-1",
		},
	}, 1, &Network{ID: "net-1", Name: "friends"}, 0, 0)
	assertContains(t, value, "connect this PC")
	assertContains(t, value, "Connect This PC")
}

func TestFormatNetworkSummaryLineShowsCurrentDeviceApprovalState(t *testing.T) {
	status := &clientagent.Status{
		CurrentDevice: &Device{ID: "dev-2"},
		Security: clientagent.SecurityDiagnostics{
			CurrentDeviceID: "dev-2",
		},
	}
	line := formatNetworkSummaryLine(Network{
		ID:                     "net-1",
		Name:                   "sensitive",
		Access:                 "INVITE_ONLY",
		DeviceApprovalRequired: true,
	}, status)
	assertContains(t, line, "device-approval current-pending")

	line = formatNetworkSummaryLine(Network{
		ID:                     "net-1",
		Name:                   "sensitive",
		Access:                 "INVITE_ONLY",
		DeviceApprovalRequired: true,
		ApprovedDeviceIDs:      []string{"dev-2"},
	}, status)
	assertContains(t, line, "device-approval current-approved")
}

func TestFormatSessionSummaryAndDetailsShowReuseDetection(t *testing.T) {
	session := Session{
		ID:                  "ses-1",
		FamilyID:            "fam-1",
		DeviceName:          "Ole Desktop",
		LastUsedAtUnix:      time.Now().Unix(),
		ReuseDetectedAtUnix: time.Now().Unix(),
	}

	summary := formatSessionSummary(session, &session)
	details := formatSessionDetails(session, &session)
	assertContains(t, summary, "reuse detected")
	assertContains(t, details, "Security Alert: token reuse detected for this session family")
}

func TestFormatAuditEventsShowsFilteredLines(t *testing.T) {
	events := []AuditEvent{
		{ID: "aud-1", ActorUserID: "usr-1", Type: "device.revoked", Details: "dev-1", CreatedAtUnix: 1710000000},
		{ID: "aud-2", ActorUserID: "usr-2", Type: "network.created", Details: "net-1", CreatedAtUnix: 1710000100},
	}

	value := formatAuditEvents(events)
	assertContains(t, value, "usr-1")
	assertContains(t, value, "device.revoked")
	assertContains(t, value, "net-1")
}

func TestFormatIncidentReportsShowsSeverityAndRecovery(t *testing.T) {
	value := formatIncidentReports([]IncidentReport{
		{
			ID:                "auth-abuse",
			Category:          "AUTH_ABUSE",
			Severity:          "warning",
			Status:            "ACTIVE",
			Source:            "server.auth_abuse",
			Summary:           "Authentication abuse alerts are active.",
			Detail:            "1 login alert, 1 blocked key",
			RecommendedAction: "Review blocked login sources.",
			EventCount:        1,
			DetectedAtUnix:    1710000000,
			UpdatedAtUnix:     1710000300,
		},
	})
	assertContains(t, value, "warning | AUTH_ABUSE | server.auth_abuse")
	assertContains(t, value, "detail: 1 login alert, 1 blocked key")
	assertContains(t, value, "next action: Review blocked login sources.")
}

func TestFormatAuditPresetLabelShowsNamedFilter(t *testing.T) {
	value := formatAuditPresetLabel(AuditPreset{
		Name:        "Device Revokes",
		ActorUserID: "usr-1",
		Type:        "device.revoked",
		Query:       "desktop",
		FromUnix:    100,
		ToUnix:      200,
	})
	assertContains(t, value, "Device Revokes")
	assertContains(t, value, "actor=usr-1")
	assertContains(t, value, "type=device.revoked")
	assertContains(t, value, "query=desktop")
	assertContains(t, value, "from=100 to=200")
}

func TestFormatAuditPresetLabelOmitsEmptyFields(t *testing.T) {
	value := formatAuditPresetLabel(AuditPreset{Name: "Recent Events"})
	assertContains(t, value, "Recent Events")
	if strings.Contains(value, "actor=") || strings.Contains(value, "type=") || strings.Contains(value, "query=") {
		t.Fatalf("expected empty audit preset fields to be omitted, got %q", value)
	}
}

func TestFormatMessagesShowsEntries(t *testing.T) {
	value := formatMessages([]Message{
		{ID: "msg-1", FromPeerID: "peer-1", Text: "hello overlay", SentAtUnix: 1710000000},
	})
	assertContains(t, value, "from=peer-1")
	assertContains(t, value, "hello overlay")
}

func TestFormatMessagesWithPeersShowsFriendlyPeerLabel(t *testing.T) {
	value := formatMessagesWithPeers([]Message{
		{ID: "msg-1", FromPeerID: "peer-1", Text: "hello overlay", SentAtUnix: 1710000000},
	}, []Peer{
		{ID: "peer-1", VirtualIP: "10.77.1.2"},
	})
	assertContains(t, value, "from=peer-1 (10.77.1.2)")
}

func TestFormatMessagesWithPeersShowsReplacementPeerLabel(t *testing.T) {
	value := formatMessagesWithPeers([]Message{
		{ID: "msg-1", NetworkID: "net-1", FromPeerID: "peer-old", Text: "hello overlay", SentAtUnix: 1710000000},
	}, []Peer{
		{ID: "peer-old", NetworkID: "net-1", UserID: "usr-remote", VirtualIP: "10.77.1.2", Status: "OFFLINE", ConnectionState: "IDLE"},
		{ID: "peer-new", NetworkID: "net-1", UserID: "usr-remote", VirtualIP: "10.77.1.2", Status: "ONLINE", ConnectionState: "CONNECTED"},
	})
	assertContains(t, value, "from=peer-old -> peer-new (10.77.1.2)")
}

func TestFilterMessagesAppliesPeerAndQuery(t *testing.T) {
	filtered := filterMessages([]Message{
		{ID: "msg-1", FromPeerID: "peer-1", Text: "hello overlay"},
		{ID: "msg-2", FromPeerID: "peer-2", Text: "goodbye"},
		{ID: "msg-3", FromPeerID: "peer-1", Text: "status update"},
	}, "status", "peer-1", nil)
	if len(filtered) != 1 || filtered[0].ID != "msg-3" {
		t.Fatalf("expected peer/query filter to keep only msg-3, got %#v", filtered)
	}
}

func TestFilterMessagesSupportsPeerReplacementByUserID(t *testing.T) {
	filtered := filterMessages([]Message{
		{ID: "msg-1", NetworkID: "net-1", FromPeerID: "peer-old", Text: "hello overlay"},
		{ID: "msg-2", NetworkID: "net-1", FromPeerID: "peer-other", Text: "goodbye"},
	}, "", "peer-new", []Peer{
		{ID: "peer-new", NetworkID: "net-1", UserID: "usr-remote"},
		{ID: "peer-old", NetworkID: "net-1", UserID: "usr-remote"},
		{ID: "peer-other", NetworkID: "net-1", UserID: "usr-other"},
	})
	if len(filtered) != 1 || filtered[0].ID != "msg-1" {
		t.Fatalf("expected peer-replacement filter to keep msg-1, got %#v", filtered)
	}
}

func TestFilterFileTransfersAppliesStatusPeerAndQuery(t *testing.T) {
	filtered := filterFileTransfers([]FileTransfer{
		{ID: "xfer-1", FromPeerID: "peer-1", ToPeerID: "peer-2", FileName: "notes.txt", Status: "PENDING"},
		{ID: "xfer-2", FromPeerID: "peer-1", ToPeerID: "peer-3", FileName: "photo.jpg", Status: "DONE"},
		{ID: "xfer-3", FromPeerID: "peer-4", ToPeerID: "peer-2", FileName: "draft-notes.md", Status: "DONE"},
	}, "notes", "All Transfers", "DONE", "peer-2", nil, nil)
	if len(filtered) != 1 || filtered[0].ID != "xfer-3" {
		t.Fatalf("expected combined transfer filter to keep only xfer-3, got %#v", filtered)
	}
}

func TestFilterFileTransfersSupportsInboxMailbox(t *testing.T) {
	filtered := filterFileTransfers([]FileTransfer{
		{ID: "xfer-1", FromPeerID: "peer-remote", ToPeerID: "peer-local", FileName: "notes.txt", Status: "INIT"},
		{ID: "xfer-2", FromPeerID: "peer-local", ToPeerID: "peer-remote", FileName: "photo.jpg", Status: "DONE"},
	}, "", "Inbox", "PENDING", "", []Peer{
		{ID: "peer-local", DeviceID: "dev-local", UserID: "usr-1"},
		{ID: "peer-remote", DeviceID: "dev-remote", UserID: "usr-2"},
	}, &clientagent.Status{
		CurrentUser:   &User{ID: "usr-1"},
		CurrentDevice: &Device{ID: "dev-local"},
	})
	if len(filtered) != 1 || filtered[0].ID != "xfer-1" {
		t.Fatalf("expected inbox filter to keep only xfer-1, got %#v", filtered)
	}
}

func TestFilterFileTransfersSupportsPeerReplacementByUserID(t *testing.T) {
	filtered := filterFileTransfers([]FileTransfer{
		{ID: "xfer-1", NetworkID: "net-1", FromPeerID: "peer-old", FromUserID: "usr-remote", ToPeerID: "peer-local", ToUserID: "usr-local", FileName: "notes.txt", Status: "DONE"},
	}, "", "All Transfers", "ALL STATUSES", "peer-new", []Peer{
		{ID: "peer-new", NetworkID: "net-1", UserID: "usr-remote", VirtualIP: "10.77.1.9"},
	}, nil)
	if len(filtered) != 1 || filtered[0].ID != "xfer-1" {
		t.Fatalf("expected peer replacement filter to keep xfer-1, got %#v", filtered)
	}
}

func TestFilterFileTransfersSupportsInboxMailboxByUserID(t *testing.T) {
	filtered := filterFileTransfers([]FileTransfer{
		{ID: "xfer-1", NetworkID: "net-1", FromPeerID: "peer-remote-old", FromUserID: "usr-2", ToPeerID: "peer-local-old", ToUserID: "usr-1", FileName: "notes.txt", Status: "INIT"},
	}, "", "Inbox", "PENDING", "", []Peer{
		{ID: "peer-remote-new", NetworkID: "net-1", UserID: "usr-2"},
	}, &clientagent.Status{
		CurrentUser: &User{ID: "usr-1"},
	})
	if len(filtered) != 1 || filtered[0].ID != "xfer-1" {
		t.Fatalf("expected inbox filter to keep xfer-1 by user ID, got %#v", filtered)
	}
}

func TestFormatFileTransferSummaryLineWithPeersShowsFriendlyLabels(t *testing.T) {
	value := formatFileTransferSummaryLineWithPeers(FileTransfer{
		ID:              "xfer-1",
		FromPeerID:      "peer-1",
		ToPeerID:        "peer-2",
		FileName:        "notes.txt",
		Status:          "INIT",
		ProgressPercent: 50,
		PayloadReady:    true,
	}, []Peer{
		{ID: "peer-1", VirtualIP: "10.77.1.2"},
		{ID: "peer-2", VirtualIP: "10.77.1.3"},
	})
	assertContains(t, value, "from=peer-1 (10.77.1.2)")
	assertContains(t, value, "to=peer-2 (10.77.1.3)")
	assertContains(t, value, "status=pending")
	assertContains(t, value, "payload=ready")
}

func TestFormatFileTransferSummaryLineWithPeersShowsReplacementPeer(t *testing.T) {
	value := formatFileTransferSummaryLineWithPeers(FileTransfer{
		ID:         "xfer-1",
		NetworkID:  "net-1",
		FromPeerID: "peer-old",
		FromUserID: "usr-remote",
		ToPeerID:   "peer-local",
		FileName:   "notes.txt",
		Status:     "INIT",
	}, []Peer{
		{ID: "peer-new", NetworkID: "net-1", UserID: "usr-remote", VirtualIP: "10.77.1.9"},
		{ID: "peer-local", NetworkID: "net-1", UserID: "usr-local", VirtualIP: "10.77.1.2"},
	})
	assertContains(t, value, "from=peer-old -> peer-new (10.77.1.9)")
}

func TestFormatFileTransferDetailsShowsCancelReason(t *testing.T) {
	value := formatFileTransferDetails(&FileTransfer{
		ID:               "xfer-1",
		NetworkID:        "net-1",
		FromPeerID:       "peer-1",
		ToPeerID:         "peer-2",
		FileName:         "notes.txt",
		SizeBytes:        64,
		Status:           "CANCELED",
		ProgressPercent:  50,
		CancelReason:     "receiver busy",
		ContentType:      "text/plain",
		PayloadSHA256:    "abc123",
		PayloadReady:     true,
		UploadedAtUnix:   1710000000,
		DownloadedAtUnix: 1710000100,
	})
	assertContains(t, value, "ID: xfer-1")
	assertContains(t, value, "Status: CANCELED")
	assertContains(t, value, "Cancel Reason: receiver busy")
	assertContains(t, value, "Payload Ready: yes")
	assertContains(t, value, "Content Type: text/plain")
	assertContains(t, value, "Payload SHA256: abc123")
}

func TestFormatFileTransferDetailsShowsLocalState(t *testing.T) {
	value := formatFileTransferDetailsWithPeersAndLocalState(&FileTransfer{
		ID:          "xfer-2",
		NetworkID:   "net-1",
		FromPeerID:  "peer-1",
		ToPeerID:    "peer-2",
		FileName:    "archive.bin",
		SizeBytes:   128,
		Status:      "IN_PROGRESS",
		ContentType: "application/octet-stream",
	}, nil, &clientagent.FileTransferLocalState{
		TransferID:             "xfer-2",
		SenderSourceRegistered: true,
		SenderSourceAvailable:  true,
		SenderSourcePath:       `C:\source\archive.bin`,
		SenderSourceSizeBytes:  128,
		ReceiverCacheAvailable: true,
		ReceiverCachePath:      `C:\cache\xfer-2.part`,
		ReceiverCachedBytes:    64,
		ReceiverCacheSizeBytes: 128,
		ReceiverCacheComplete:  false,
	})
	assertContains(t, value, "Sender Source Registered: yes")
	assertContains(t, value, `Sender Source Path: C:\source\archive.bin`)
	assertContains(t, value, "Receiver Cache Available: yes")
	assertContains(t, value, `Receiver Cache Path: C:\cache\xfer-2.part`)
	assertContains(t, value, "Receiver Cache Bytes: 64/128")
	assertContains(t, value, "Receiver Cache Complete: no")
}

func TestDefaultNetworkFileTransferMaxBytesUsesDomainDefault(t *testing.T) {
	if got := defaultNetworkFileTransferMaxBytes(); got != domain.DefaultNetworkFileTransferMaxBytes {
		t.Fatalf("expected GUI default file transfer max bytes %d, got %d", domain.DefaultNetworkFileTransferMaxBytes, got)
	}
}

func TestValidateTransferUploadSourceRejectsMismatchedSize(t *testing.T) {
	err := validateTransferUploadSource(FileTransfer{
		ID:                   "xfer-1",
		FileName:             "notes.txt",
		SizeBytes:            64,
		PayloadUploadedBytes: 16,
	}, 32)
	if err == nil {
		t.Fatal("expected mismatched upload source size to fail")
	}
	assertContains(t, err.Error(), "local file size 32 does not match transfer size 64")
}

func TestInspectTransferDownloadTargetClassifiesExistingFileState(t *testing.T) {
	tests := []struct {
		name         string
		existingSize int64
		totalSize    int64
		want         transferDownloadTargetState
		wantErr      string
	}{
		{name: "empty", existingSize: 0, totalSize: 64, want: transferDownloadTargetEmpty},
		{name: "partial", existingSize: 32, totalSize: 64, want: transferDownloadTargetPartial},
		{name: "complete", existingSize: 64, totalSize: 64, want: transferDownloadTargetComplete},
		{name: "oversized", existingSize: 96, totalSize: 64, wantErr: "existing file size 96 exceeds transfer size 64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := inspectTransferDownloadTarget(tt.existingSize, tt.totalSize)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantErr)
				}
				assertContains(t, err.Error(), tt.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected state %v, got %v", tt.want, got)
			}
		})
	}
}

func TestPreferredOperatorPeerIDUsesCurrentDevicePeer(t *testing.T) {
	peers := []Peer{
		{ID: "peer-1", DeviceID: "dev-remote", UserID: "usr-1", VirtualIP: "10.77.1.3", Status: "ONLINE"},
		{ID: "peer-2", DeviceID: "dev-local", UserID: "usr-1", VirtualIP: "10.77.1.2", Status: "ONLINE"},
	}
	status := &clientagent.Status{
		CurrentUser:   &User{ID: "usr-1"},
		CurrentDevice: &Device{ID: "dev-local"},
	}
	if preferred := preferredOperatorPeerID(peers, status); preferred != "peer-2" {
		t.Fatalf("expected current device peer to be preferred, got %q", preferred)
	}
	choices := buildOperatorPeerChoices(peers, status, true)
	if len(choices) != 2 {
		t.Fatalf("expected both owned peers to be selectable, got %#v", choices)
	}
	if choices[0].ID != "peer-1" || choices[1].ID != "peer-2" {
		t.Fatalf("expected owned peers to stay in peer order, got %#v", choices)
	}
}

func TestPreferredOperatorPeerIDPrefersActiveReplacementPeer(t *testing.T) {
	now := time.Now().Unix()
	peers := []Peer{
		{ID: "peer-old", DeviceID: "dev-local", UserID: "usr-1", VirtualIP: "10.77.1.2", Status: "OFFLINE", ConnectionState: "IDLE", LastSeenUnix: now - 300},
		{ID: "peer-new", DeviceID: "dev-local", UserID: "usr-1", VirtualIP: "10.77.1.2", Status: "ONLINE", ConnectionState: "CONNECTED", LastSeenUnix: now},
	}
	status := &clientagent.Status{
		CurrentUser:   &User{ID: "usr-1"},
		CurrentDevice: &Device{ID: "dev-local"},
	}
	if preferred := preferredOperatorPeerID(peers, status); preferred != "peer-new" {
		t.Fatalf("expected replacement peer to be preferred, got %q", preferred)
	}
}

func TestBuildRecipientPeerChoicesDeduplicatesSameUserVirtualIP(t *testing.T) {
	now := time.Now().Unix()
	choices := buildRecipientPeerChoices([]Peer{
		{ID: "peer-old", NetworkID: "net-1", UserID: "usr-1", VirtualIP: "10.77.1.2", Status: "OFFLINE", ConnectionState: "IDLE", LastSeenUnix: now - 600},
		{ID: "peer-new", NetworkID: "net-1", UserID: "usr-1", VirtualIP: "10.77.1.2", Status: "ONLINE", ConnectionState: "CONNECTED", LastSeenUnix: now},
		{ID: "peer-other", NetworkID: "net-1", UserID: "usr-2", VirtualIP: "10.77.1.3", Status: "ONLINE", ConnectionState: "CONNECTED", LastSeenUnix: now},
	}, "")
	if len(choices) != 2 {
		t.Fatalf("expected recipient choices to deduplicate replacements, got %#v", choices)
	}
	if choices[0].ID != "peer-new" && choices[1].ID != "peer-new" {
		t.Fatalf("expected replacement peer to be present, got %#v", choices)
	}
}

func TestBuildFilterPeerChoicesDeduplicatesSameUserVirtualIP(t *testing.T) {
	now := time.Now().Unix()
	choices := buildFilterPeerChoices([]Peer{
		{ID: "peer-old", NetworkID: "net-1", UserID: "usr-1", VirtualIP: "10.77.1.2", Status: "OFFLINE", ConnectionState: "IDLE", LastSeenUnix: now - 600},
		{ID: "peer-new", NetworkID: "net-1", UserID: "usr-1", VirtualIP: "10.77.1.2", Status: "ONLINE", ConnectionState: "CONNECTED", LastSeenUnix: now},
	})
	if len(choices) != 2 {
		t.Fatalf("expected filter choices to include All Peers plus one deduped peer, got %#v", choices)
	}
	if choices[1].ID != "peer-new" {
		t.Fatalf("expected filter choice to keep replacement peer, got %#v", choices)
	}
}

func assertContains(t *testing.T, value, expected string) {
	t.Helper()
	if !strings.Contains(value, expected) {
		t.Fatalf("expected %q to contain %q", value, expected)
	}
}
