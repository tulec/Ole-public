package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/structuredlog"
	"Ole/internal/virtualadapter"
	"fmt"
	"sort"
	"strings"
	"time"
)

const defaultLogCapacity = 200

type LogEntry struct {
	CreatedAtUnix int64             `json:"createdAtUnix"`
	Level         string            `json:"level"`
	Component     string            `json:"component,omitempty"`
	Event         string            `json:"event,omitempty"`
	Message       string            `json:"message"`
	Fields        map[string]string `json:"fields,omitempty"`
}

type SecurityAlert struct {
	Code            string `json:"code"`
	Severity        string `json:"severity"`
	Summary         string `json:"summary"`
	Detail          string `json:"detail,omitempty"`
	DetectedAtUnix  int64  `json:"detectedAtUnix,omitempty"`
	SessionID       string `json:"sessionId,omitempty"`
	SessionFamilyID string `json:"sessionFamilyId,omitempty"`
	DeviceID        string `json:"deviceId,omitempty"`
}

type SecurityDiagnostics struct {
	LastCheckedUnix             int64           `json:"lastCheckedUnix,omitempty"`
	SessionCount                int             `json:"sessionCount,omitempty"`
	DeviceCount                 int             `json:"deviceCount,omitempty"`
	ReuseDetectedCount          int             `json:"reuseDetectedCount,omitempty"`
	RevokedDeviceCount          int             `json:"revokedDeviceCount,omitempty"`
	CurrentSessionFamilyID      string          `json:"currentSessionFamilyId,omitempty"`
	CurrentSessionReuseDetected bool            `json:"currentSessionReuseDetected,omitempty"`
	CurrentDeviceID             string          `json:"currentDeviceId,omitempty"`
	CurrentDeviceStatus         string          `json:"currentDeviceStatus,omitempty"`
	CurrentDeviceRevokedAtUnix  int64           `json:"currentDeviceRevokedAtUnix,omitempty"`
	EnrollmentStatus            string          `json:"enrollmentStatus,omitempty"`
	Alerts                      []SecurityAlert `json:"alerts,omitempty"`
}

type DiagnosticsUsageSummary struct {
	NetworkCount               int                                `json:"networkCount,omitempty"`
	PeerCount                  int                                `json:"peerCount,omitempty"`
	OnlinePeerCount            int                                `json:"onlinePeerCount,omitempty"`
	TunnelCount                int                                `json:"tunnelCount,omitempty"`
	OpenTunnelCount            int                                `json:"openTunnelCount,omitempty"`
	ConnectionCount            int                                `json:"connectionCount,omitempty"`
	ConnectedCount             int                                `json:"connectedCount,omitempty"`
	DirectConnectedCount       int                                `json:"directConnectedCount,omitempty"`
	RelayConnectedCount        int                                `json:"relayConnectedCount,omitempty"`
	DirectCandidateCount       int                                `json:"directCandidateCount,omitempty"`
	NegotiatingCount           int                                `json:"negotiatingCount,omitempty"`
	RelayReadyCount            int                                `json:"relayReadyCount,omitempty"`
	TransportReadyCount        int                                `json:"transportReadyCount,omitempty"`
	DirectTransportCount       int                                `json:"directTransportCount,omitempty"`
	RelayTransportCount        int                                `json:"relayTransportCount,omitempty"`
	OpenP2PTunnelCount         int                                `json:"openP2pTunnelCount,omitempty"`
	OpenRelayTunnelCount       int                                `json:"openRelayTunnelCount,omitempty"`
	TotalTransportPacketCount  int                                `json:"totalTransportPacketCount,omitempty"`
	DirectTransportPacketCount int                                `json:"directTransportPacketCount,omitempty"`
	RelayTransportPacketCount  int                                `json:"relayTransportPacketCount,omitempty"`
	AverageRTTMillis           int64                              `json:"averageRttMillis,omitempty"`
	MaxRTTMillis               int64                              `json:"maxRttMillis,omitempty"`
	MaxConsecutiveLosses       int                                `json:"maxConsecutiveLosses,omitempty"`
	DirectAttemptCount         int                                `json:"directAttemptCount,omitempty"`
	DirectSuccessCount         int                                `json:"directSuccessCount,omitempty"`
	DirectFailureCount         int                                `json:"directFailureCount,omitempty"`
	DirectSuccessRatePct       int                                `json:"directSuccessRatePct,omitempty"`
	RelayFallbackCount         int                                `json:"relayFallbackCount,omitempty"`
	DirectFailbackSuccessCount int                                `json:"directFailbackSuccessCount,omitempty"`
	CrossNetwork               *DiagnosticsCrossNetworkRollup     `json:"crossNetwork,omitempty"`
	AdapterNeighbor            *DiagnosticsAdapterNeighborRollup  `json:"adapterNeighbor,omitempty"`
	ConnectionState            *DiagnosticsConnectionStateRollup  `json:"connectionState,omitempty"`
	Neighbors                  *DiagnosticsNeighborRollup         `json:"neighbors,omitempty"`
	Adapter                    *DiagnosticsAdapterRollup          `json:"adapter,omitempty"`
	Transport                  *DiagnosticsTransportRollup        `json:"transport,omitempty"`
	TransportSessions          *DiagnosticsTransportSessionRollup `json:"transportSessions,omitempty"`
	RecentErrors               *DiagnosticsRecentErrorRollup      `json:"recentErrors,omitempty"`
	Gateway                    *DiagnosticsGatewayRollup          `json:"gateway,omitempty"`
	GroupTraffic               *DiagnosticsGroupTrafficRollup     `json:"groupTraffic,omitempty"`
	GatewayCurrent             *DiagnosticsGatewayCurrentRollup   `json:"gatewayCurrent,omitempty"`
}

type DiagnosticsAdapterNeighborRollup struct {
	NetworkCount                int    `json:"networkCount,omitempty"`
	AlignedCount                int    `json:"alignedCount,omitempty"`
	AdapterLaggingCount         int    `json:"adapterLaggingCount,omitempty"`
	TransportLaggingCount       int    `json:"transportLaggingCount,omitempty"`
	PendingCount                int    `json:"pendingCount,omitempty"`
	ReadyNeighborCount          int    `json:"readyNeighborCount,omitempty"`
	HealthyBindingCount         int    `json:"healthyBindingCount,omitempty"`
	MissingIPVisibilityCount    int    `json:"missingIpVisibilityCount,omitempty"`
	MissingRouteVisibilityCount int    `json:"missingRouteVisibilityCount,omitempty"`
	PendingGatewayCount         int    `json:"pendingGatewayCount,omitempty"`
	MostSevereState             string `json:"mostSevereState,omitempty"`
	AffectedNetworkID           string `json:"affectedNetworkId,omitempty"`
	Hint                        string `json:"hint,omitempty"`
}

type DiagnosticsCrossNetworkRollup struct {
	NetworkCount         int    `json:"networkCount,omitempty"`
	HealthyCount         int    `json:"healthyCount,omitempty"`
	DegradedCount        int    `json:"degradedCount,omitempty"`
	PendingCount         int    `json:"pendingCount,omitempty"`
	IdleCount            int    `json:"idleCount,omitempty"`
	AffectedCount        int    `json:"affectedCount,omitempty"`
	IsolatedIssueCount   int    `json:"isolatedIssueCount,omitempty"`
	WidespreadIssueCount int    `json:"widespreadIssueCount,omitempty"`
	MostSevereState      string `json:"mostSevereState,omitempty"`
	AffectedNetworkID    string `json:"affectedNetworkId,omitempty"`
	Hint                 string `json:"hint,omitempty"`
}

type DiagnosticsConnectionStateRollup struct {
	ConnectionCount        int    `json:"connectionCount,omitempty"`
	ConnectedCount         int    `json:"connectedCount,omitempty"`
	DirectCandidateCount   int    `json:"directCandidateCount,omitempty"`
	NegotiatingCount       int    `json:"negotiatingCount,omitempty"`
	RelayReadyCount        int    `json:"relayReadyCount,omitempty"`
	IdleCount              int    `json:"idleCount,omitempty"`
	ErrorCount             int    `json:"errorCount,omitempty"`
	RetryScheduledCount    int    `json:"retryScheduledCount,omitempty"`
	SelectedCandidateCount int    `json:"selectedCandidateCount,omitempty"`
	TunnelOpenCount        int    `json:"tunnelOpenCount,omitempty"`
	TunnelNegotiatingCount int    `json:"tunnelNegotiatingCount,omitempty"`
	TransportReadyCount    int    `json:"transportReadyCount,omitempty"`
	DirectPathCount        int    `json:"directPathCount,omitempty"`
	RelayPathCount         int    `json:"relayPathCount,omitempty"`
	LastAttemptUnix        int64  `json:"lastAttemptUnix,omitempty"`
	NextRetryUnix          int64  `json:"nextRetryUnix,omitempty"`
	MostSevereState        string `json:"mostSevereState,omitempty"`
	Hint                   string `json:"hint,omitempty"`
}

type DiagnosticsNeighborRollup struct {
	NeighborCount           int   `json:"neighborCount,omitempty"`
	OnlineCount             int   `json:"onlineCount,omitempty"`
	RecentCount             int   `json:"recentCount,omitempty"`
	OfflineCount            int   `json:"offlineCount,omitempty"`
	TransportReadyCount     int   `json:"transportReadyCount,omitempty"`
	ConnectedCount          int   `json:"connectedCount,omitempty"`
	PendingCount            int   `json:"pendingCount,omitempty"`
	DirectReachabilityCount int   `json:"directReachabilityCount,omitempty"`
	RelayReachabilityCount  int   `json:"relayReachabilityCount,omitempty"`
	DirectTransportCount    int   `json:"directTransportCount,omitempty"`
	RelayTransportCount     int   `json:"relayTransportCount,omitempty"`
	MaxCandidateCount       int   `json:"maxCandidateCount,omitempty"`
	LastSeenUnix            int64 `json:"lastSeenUnix,omitempty"`
	LastSignaledAtUnix      int64 `json:"lastSignaledAtUnix,omitempty"`
}

type DiagnosticsAdapterRollup struct {
	Enabled             bool   `json:"enabled,omitempty"`
	Available           bool   `json:"available,omitempty"`
	SessionActive       bool   `json:"sessionActive,omitempty"`
	ConnectionState     string `json:"connectionState,omitempty"`
	BindingCount        int    `json:"bindingCount,omitempty"`
	FullBindingCount    int    `json:"fullBindingCount,omitempty"`
	SplitBindingCount   int    `json:"splitBindingCount,omitempty"`
	ActivePolicyCount   int    `json:"activePolicyCount,omitempty"`
	PendingPolicyCount  int    `json:"pendingPolicyCount,omitempty"`
	VisibleIPCount      int    `json:"visibleIpCount,omitempty"`
	VisibleRouteCount   int    `json:"visibleRouteCount,omitempty"`
	HealthyBindingCount int    `json:"healthyBindingCount,omitempty"`
	DesiredMTU          int    `json:"desiredMtu,omitempty"`
	CurrentMTU          int    `json:"currentMtu,omitempty"`
	DNSServerCount      int    `json:"dnsServerCount,omitempty"`
	HasDNSSuffix        bool   `json:"hasDnsSuffix,omitempty"`
	HasError            bool   `json:"hasError,omitempty"`
}

type DiagnosticsTransportRollup struct {
	Quality                   string `json:"quality,omitempty"`
	HealthyConnectionCount    int    `json:"healthyConnectionCount,omitempty"`
	DegradedConnectionCount   int    `json:"degradedConnectionCount,omitempty"`
	PendingConnectionCount    int    `json:"pendingConnectionCount,omitempty"`
	FallbackReadyCount        int    `json:"fallbackReadyCount,omitempty"`
	ConnectedDirectCount      int    `json:"connectedDirectCount,omitempty"`
	ConnectedRelayCount       int    `json:"connectedRelayCount,omitempty"`
	TotalTransportPacketCount int    `json:"totalTransportPacketCount,omitempty"`
	LastTransportUnix         int64  `json:"lastTransportUnix,omitempty"`
}

type DiagnosticsTransportSessionRollup struct {
	SessionCount        int    `json:"sessionCount,omitempty"`
	DirectSessionCount  int    `json:"directSessionCount,omitempty"`
	RelaySessionCount   int    `json:"relaySessionCount,omitempty"`
	OldestSessionUnix   int64  `json:"oldestSessionUnix,omitempty"`
	NewestSessionUnix   int64  `json:"newestSessionUnix,omitempty"`
	MaxSessionAgeSec    int64  `json:"maxSessionAgeSec,omitempty"`
	MaxIdleSec          int64  `json:"maxIdleSec,omitempty"`
	RekeyScheduledCount int    `json:"rekeyScheduledCount,omitempty"`
	RekeyDueSoonCount   int    `json:"rekeyDueSoonCount,omitempty"`
	RekeyOverdueCount   int    `json:"rekeyOverdueCount,omitempty"`
	NextRekeyUnix       int64  `json:"nextRekeyUnix,omitempty"`
	OldestSessionID     string `json:"oldestSessionId,omitempty"`
	NextRekeySessionID  string `json:"nextRekeySessionId,omitempty"`
	MostSevereState     string `json:"mostSevereState,omitempty"`
	Hint                string `json:"hint,omitempty"`
}

type DiagnosticsRecentErrorRollup struct {
	ErrorCount             int    `json:"errorCount,omitempty"`
	TransientRetryCount    int    `json:"transientRetryCount,omitempty"`
	PersistentFailureCount int    `json:"persistentFailureCount,omitempty"`
	ConnectedErrorCount    int    `json:"connectedErrorCount,omitempty"`
	LastErrorUnix          int64  `json:"lastErrorUnix,omitempty"`
	NextRetryUnix          int64  `json:"nextRetryUnix,omitempty"`
	LastErrorPeerID        string `json:"lastErrorPeerId,omitempty"`
	LastErrorState         string `json:"lastErrorState,omitempty"`
	MostRecentError        string `json:"mostRecentError,omitempty"`
	MostSevereState        string `json:"mostSevereState,omitempty"`
	Hint                   string `json:"hint,omitempty"`
}

type DiagnosticsGatewayRollup struct {
	ChangeCount               int    `json:"changeCount,omitempty"`
	SelectionCount            int    `json:"selectionCount,omitempty"`
	FailoverCount             int    `json:"failoverCount,omitempty"`
	FailbackCount             int    `json:"failbackCount,omitempty"`
	PromotedCount             int    `json:"promotedCount,omitempty"`
	DemotedCount              int    `json:"demotedCount,omitempty"`
	LostCount                 int    `json:"lostCount,omitempty"`
	PathChangeCount           int    `json:"pathChangeCount,omitempty"`
	StatusChangeCount         int    `json:"statusChangeCount,omitempty"`
	LocalGatewayActiveCount   int    `json:"localGatewayActiveCount,omitempty"`
	LocalGatewayReleasedCount int    `json:"localGatewayReleasedCount,omitempty"`
	RemovedCount              int    `json:"removedCount,omitempty"`
	LastChangeUnix            int64  `json:"lastChangeUnix,omitempty"`
	LastEvent                 string `json:"lastEvent,omitempty"`
}

type DiagnosticsGroupTrafficRollup struct {
	Policy               string `json:"policy,omitempty"`
	BlockedPacketCount   int    `json:"blockedPacketCount,omitempty"`
	FloodEventCount      int    `json:"floodEventCount,omitempty"`
	FanoutCopyCount      int    `json:"fanoutCopyCount,omitempty"`
	BroadcastPacketCount int    `json:"broadcastPacketCount,omitempty"`
	MulticastPacketCount int    `json:"multicastPacketCount,omitempty"`
	LastAction           string `json:"lastAction,omitempty"`
	LastPacketUnix       int64  `json:"lastPacketUnix,omitempty"`
}

type DiagnosticsGatewayCurrentRollup struct {
	FullNetworkCount       int    `json:"fullNetworkCount,omitempty"`
	ActiveNetworkCount     int    `json:"activeNetworkCount,omitempty"`
	PendingNetworkCount    int    `json:"pendingNetworkCount,omitempty"`
	LocalGatewayCount      int    `json:"localGatewayCount,omitempty"`
	ClientGatewayCount     int    `json:"clientGatewayCount,omitempty"`
	DirectPathCount        int    `json:"directPathCount,omitempty"`
	RelayPathCount         int    `json:"relayPathCount,omitempty"`
	CurrentNetworkID       string `json:"currentNetworkId,omitempty"`
	CurrentGatewayRole     string `json:"currentGatewayRole,omitempty"`
	CurrentGatewayPeerID   string `json:"currentGatewayPeerId,omitempty"`
	CurrentPath            string `json:"currentPath,omitempty"`
	CurrentPolicyStatus    string `json:"currentPolicyStatus,omitempty"`
	CurrentConnectionState string `json:"currentConnectionState,omitempty"`
}

type DiagnosticsNetwork struct {
	Network        controlclient.Network   `json:"network"`
	UsageSummary   DiagnosticsUsageSummary `json:"usageSummary"`
	GatewayHistory []GatewayChangeEvent    `json:"gatewayHistory,omitempty"`
	Neighbors      []NeighborStatus        `json:"neighbors,omitempty"`
	Peers          []controlclient.Peer    `json:"peers,omitempty"`
	Tunnels        []controlclient.Tunnel  `json:"tunnels,omitempty"`
}

type DiagnosticsBundle struct {
	TransportDataPlane []TransportDataPlaneMetrics `json:"transportDataPlane,omitempty"`
	GeneratedAtUnix    int64                       `json:"generatedAtUnix"`
	Status             Status                      `json:"status"`
	Security           SecurityDiagnostics         `json:"security"`
	UsageSummary       DiagnosticsUsageSummary     `json:"usageSummary"`
	GatewayHistory     []GatewayChangeEvent        `json:"gatewayHistory,omitempty"`
	RecentLogs         []LogEntry                  `json:"recentLogs,omitempty"`
	Sessions           []controlclient.Session     `json:"sessions,omitempty"`
	Devices            []controlclient.Device      `json:"devices,omitempty"`
	Networks           []DiagnosticsNetwork        `json:"networks,omitempty"`
	CollectionErrors   []string                    `json:"collectionErrors,omitempty"`
}

func (a *Agent) DiagnosticsBundle() DiagnosticsBundle {
	a.mu.Lock()
	defer a.mu.Unlock()

	bundle := DiagnosticsBundle{
		TransportDataPlane: a.transportDataPlaneMetricsLocked(),
		GeneratedAtUnix:    time.Now().Unix(),
		Status:             redactStatusTokens(a.snapshotLocked()),
		Security:           cloneSecurityDiagnostics(a.securityDiagnostics),
		GatewayHistory:     cloneGatewayHistory(a.gatewayHistory),
		RecentLogs:         a.recentLogsSnapshot(),
	}
	if a.currentSession == nil || a.currentUser == nil {
		return bundle
	}

	sessions, err := a.remote.ListSessions()
	if err != nil {
		bundle.CollectionErrors = append(bundle.CollectionErrors, "list sessions: "+err.Error())
	} else {
		bundle.Sessions = redactSessions(sessions)
	}
	devices, err := a.remote.ListDevices()
	if err != nil {
		bundle.CollectionErrors = append(bundle.CollectionErrors, "list devices: "+err.Error())
	} else {
		bundle.Devices = cloneDevices(devices)
	}
	if len(sessions) > 0 || len(devices) > 0 {
		enrollmentDeviceID := a.currentEnrolledDeviceIDLocked()
		bundle.Security = deriveSecurityDiagnostics(sessions, devices, bundle.Status.CurrentSession, bundle.Status.CurrentDevice, enrollmentDeviceID, time.Now())
		bundle.Status.Security = cloneSecurityDiagnostics(bundle.Security)
	}

	networks, err := a.remote.ListNetworks()
	if err != nil {
		bundle.CollectionErrors = append(bundle.CollectionErrors, "list networks: "+err.Error())
		return bundle
	}

	bundle.Networks = make([]DiagnosticsNetwork, 0, len(networks))
	for _, network := range networks {
		item := DiagnosticsNetwork{Network: network}
		peers, peersErr := a.remote.ListPeers(network.ID)
		if peersErr != nil {
			bundle.CollectionErrors = append(bundle.CollectionErrors, fmt.Sprintf("list peers for %s: %v", network.ID, peersErr))
		} else {
			item.Peers = dedupeDiagnosticsPeers(peers)
		}
		tunnels, tunnelsErr := a.remote.ListTunnels(network.ID)
		if tunnelsErr != nil {
			bundle.CollectionErrors = append(bundle.CollectionErrors, fmt.Sprintf("list tunnels for %s: %v", network.ID, tunnelsErr))
		} else {
			item.Tunnels = tunnels
		}
		item.GatewayHistory = filterGatewayHistoryByNetwork(bundle.GatewayHistory, network.ID)
		item.Neighbors = filterNeighborsByNetwork(bundle.Status.Neighbors, network.ID)
		item.UsageSummary = summarizeDiagnosticsUsage(
			bundle.Status.Adapter,
			item.Neighbors,
			filterConnectionsByNetwork(bundle.Status.Connections, network.ID),
			filterAdapterBindingsByNetwork(bundle.Status.Adapter.Networks, network.ID),
			item.Peers,
			item.Tunnels,
			item.GatewayHistory,
			filterGroupTrafficByNetwork(bundle.Status.GroupTraffic, network.ID),
			1,
		)
		bundle.Networks = append(bundle.Networks, item)
	}
	bundle.UsageSummary = summarizeDiagnosticsUsage(
		bundle.Status.Adapter,
		bundle.Status.Neighbors,
		bundle.Status.Connections,
		bundle.Status.Adapter.Networks,
		flattenDiagnosticsPeers(bundle.Networks),
		flattenDiagnosticsTunnels(bundle.Networks),
		bundle.GatewayHistory,
		bundle.Status.GroupTraffic,
		len(bundle.Networks),
	)
	bundle.UsageSummary = applyDirectMetricsToUsageSummary(bundle.UsageSummary, bundle.Status.DirectMetrics)
	bundle.UsageSummary.CrossNetwork = summarizeCrossNetworkHealth(bundle.Networks)

	return bundle
}

func (a *Agent) logInfof(format string, args ...any) {
	a.appendLogLocked("INFO", format, args...)
}

func (a *Agent) logErrorf(format string, args ...any) {
	a.appendLogLocked("ERROR", format, args...)
}

func (a *Agent) logInfow(event, message string, keyvals ...any) {
	a.appendStructuredLogLocked("INFO", "clientagent", event, message, keyvals...)
}

func (a *Agent) logErrorw(event, message string, keyvals ...any) {
	a.appendStructuredLogLocked("ERROR", "clientagent", event, message, keyvals...)
}

func (a *Agent) appendLogLocked(level, format string, args ...any) {
	a.appendStructuredLogLocked(level, "clientagent", "", fmt.Sprintf(format, args...))
}

func (a *Agent) appendStructuredLogLocked(level, component, event, message string, keyvals ...any) {
	if a == nil {
		return
	}
	a.logsMu.Lock()
	defer a.logsMu.Unlock()
	if a.logCapacity <= 0 {
		a.logCapacity = defaultLogCapacity
	}
	entry := LogEntry{
		CreatedAtUnix: time.Now().Unix(),
		Level:         level,
		Component:     strings.TrimSpace(component),
		Event:         strings.TrimSpace(event),
		Message:       strings.TrimSpace(message),
		Fields:        structuredlog.FieldsMap(keyvals...),
	}
	a.logs = append(a.logs, entry)
	if len(a.logs) > a.logCapacity {
		a.logs = append([]LogEntry(nil), a.logs[len(a.logs)-a.logCapacity:]...)
	}
}

func (a *Agent) recentLogsSnapshot() []LogEntry {
	if a == nil {
		return nil
	}
	a.logsMu.Lock()
	defer a.logsMu.Unlock()
	return cloneLogEntries(a.logs)
}

func (a *Agent) observeControlPlaneTrace(trace controlclient.RequestTrace) {
	if a == nil {
		return
	}
	keyvals := []any{
		"method", trace.Method,
		"path", trace.Path,
		"traceId", trace.TraceID,
		"spanId", trace.SpanID,
		"serverSpanId", trace.ServerSpanID,
		"responseTraceId", trace.ResponseTrace,
		"statusCode", trace.StatusCode,
		"durationMs", trace.DurationMs,
	}
	level := "INFO"
	message := "control plane request completed"
	if strings.TrimSpace(trace.Error) != "" {
		level = "ERROR"
		message = "control plane request failed"
		keyvals = append(keyvals, "error", trace.Error)
	}
	a.appendStructuredLogLocked(level, "controlclient", "controlplane.request.completed", message, keyvals...)
}

func cloneLogEntries(entries []LogEntry) []LogEntry {
	if len(entries) == 0 {
		return nil
	}
	out := make([]LogEntry, len(entries))
	copy(out, entries)
	return out
}

func redactStatusTokens(status Status) Status {
	status.CurrentSession = redactSession(status.CurrentSession)
	return status
}

func redactSession(session *controlclient.Session) *controlclient.Session {
	if session == nil {
		return nil
	}
	copy := *session
	copy.AccessToken = ""
	copy.RefreshToken = ""
	return &copy
}

func redactSessions(sessions []controlclient.Session) []controlclient.Session {
	if len(sessions) == 0 {
		return nil
	}
	out := make([]controlclient.Session, len(sessions))
	for idx := range sessions {
		out[idx] = sessions[idx]
		out[idx].AccessToken = ""
		out[idx].RefreshToken = ""
	}
	return out
}

func cloneDevices(devices []controlclient.Device) []controlclient.Device {
	if len(devices) == 0 {
		return nil
	}
	out := make([]controlclient.Device, len(devices))
	copy(out, devices)
	return out
}

func cloneSecurityDiagnostics(value SecurityDiagnostics) SecurityDiagnostics {
	value.Alerts = cloneSecurityAlerts(value.Alerts)
	return value
}

func cloneSecurityAlerts(alerts []SecurityAlert) []SecurityAlert {
	if len(alerts) == 0 {
		return nil
	}
	out := make([]SecurityAlert, len(alerts))
	copy(out, alerts)
	return out
}

func deriveSecurityDiagnostics(sessions []controlclient.Session, devices []controlclient.Device, currentSession *controlclient.Session, currentDevice *controlclient.Device, enrollmentDeviceID string, now time.Time) SecurityDiagnostics {
	diagnostics := SecurityDiagnostics{
		LastCheckedUnix:  now.Unix(),
		SessionCount:     len(sessions),
		DeviceCount:      len(devices),
		EnrollmentStatus: "NONE",
	}
	if currentSession != nil {
		diagnostics.CurrentSessionFamilyID = currentSession.FamilyID
	}
	targetDeviceID := strings.TrimSpace(enrollmentDeviceID)
	if targetDeviceID == "" && currentDevice != nil {
		targetDeviceID = currentDevice.ID
	}
	diagnostics.CurrentDeviceID = targetDeviceID

	for _, session := range sessions {
		if session.ReuseDetectedAtUnix <= 0 {
			continue
		}
		diagnostics.ReuseDetectedCount++
		alert := SecurityAlert{
			Code:            "SESSION_REUSE_DETECTED",
			Severity:        "warning",
			Summary:         "Session reuse detected",
			Detail:          firstNonEmptyString(session.DeviceName, session.ID),
			DetectedAtUnix:  session.ReuseDetectedAtUnix,
			SessionID:       session.ID,
			SessionFamilyID: session.FamilyID,
		}
		if currentSession != nil && session.FamilyID == currentSession.FamilyID {
			diagnostics.CurrentSessionReuseDetected = true
			alert.Severity = "error"
			alert.Summary = "Current session family reported token reuse"
		}
		diagnostics.Alerts = append(diagnostics.Alerts, alert)
	}

	targetFound := false
	for _, device := range devices {
		if strings.EqualFold(device.Status, "REVOKED") || device.RevokedAtUnix > 0 || !strings.EqualFold(device.Status, "ACTIVE") {
			diagnostics.RevokedDeviceCount++
		}
		if targetDeviceID == "" || device.ID != targetDeviceID {
			continue
		}
		targetFound = true
		diagnostics.CurrentDeviceStatus = firstNonEmptyString(device.Status, "UNKNOWN")
		diagnostics.CurrentDeviceRevokedAtUnix = device.RevokedAtUnix
		diagnostics.EnrollmentStatus = enrollmentStatusFromDevice(device)
		if !strings.EqualFold(device.Status, "ACTIVE") || device.RevokedAtUnix > 0 {
			diagnostics.Alerts = append(diagnostics.Alerts, SecurityAlert{
				Code:           "DEVICE_REVOKED",
				Severity:       "error",
				Summary:        "Current enrolled device is no longer active",
				Detail:         firstNonEmptyString(device.Name, device.ID),
				DetectedAtUnix: maxInt64(device.RevokedAtUnix, now.Unix()),
				DeviceID:       device.ID,
			})
		}
	}
	if targetDeviceID != "" && !targetFound {
		diagnostics.CurrentDeviceStatus = "MISSING"
		diagnostics.EnrollmentStatus = "MISSING"
		diagnostics.Alerts = append(diagnostics.Alerts, SecurityAlert{
			Code:           "DEVICE_MISSING",
			Severity:       "warning",
			Summary:        "Current enrolled device was not found on the server",
			Detail:         targetDeviceID,
			DetectedAtUnix: now.Unix(),
			DeviceID:       targetDeviceID,
		})
	}
	if targetDeviceID != "" && diagnostics.EnrollmentStatus == "NONE" {
		diagnostics.EnrollmentStatus = "UNKNOWN"
	}
	return diagnostics
}

func enrollmentStatusFromDevice(device controlclient.Device) string {
	if strings.EqualFold(device.Status, "ACTIVE") && device.RevokedAtUnix <= 0 {
		return "ACTIVE"
	}
	if strings.EqualFold(device.Status, "REVOKED") || device.RevokedAtUnix > 0 {
		return "REVOKED"
	}
	if strings.TrimSpace(device.Status) != "" {
		return strings.ToUpper(strings.TrimSpace(device.Status))
	}
	return "UNKNOWN"
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

func summarizeDiagnosticsUsage(adapter virtualadapter.Status, neighbors []NeighborStatus, connections []ConnectionStatus, bindings []virtualadapter.NetworkBinding, peers []controlclient.Peer, tunnels []controlclient.Tunnel, gatewayHistory []GatewayChangeEvent, groupTraffic []GroupTrafficDiagnostics, networkCount int) DiagnosticsUsageSummary {
	rawPeers := peers
	peers = dedupeDiagnosticsPeers(peers)
	neighbors = normalizeDiagnosticsNeighbors(neighbors, rawPeers)
	connections = normalizeDiagnosticsConnections(connections, rawPeers)
	summary := DiagnosticsUsageSummary{
		NetworkCount: networkCount,
		PeerCount:    len(peers),
		TunnelCount:  len(tunnels),
	}
	neighbors = dedupeDiagnosticsNeighbors(neighbors)
	connections = dedupeDiagnosticsConnections(connections)
	nowUnix := time.Now().Unix()
	var rttSamples int64
	transport := &DiagnosticsTransportRollup{}
	transportSessions := &DiagnosticsTransportSessionRollup{}
	gateway := &DiagnosticsGatewayRollup{}
	group := &DiagnosticsGroupTrafficRollup{}
	gatewayCurrent := &DiagnosticsGatewayCurrentRollup{}
	neighbor := &DiagnosticsNeighborRollup{}
	connectionState := &DiagnosticsConnectionStateRollup{}
	recentErrors := &DiagnosticsRecentErrorRollup{}

	for _, peer := range peers {
		if strings.EqualFold(peer.Status, "ONLINE") {
			summary.OnlinePeerCount++
		}
	}

	for _, item := range neighbors {
		neighbor.NeighborCount++
		switch strings.ToUpper(strings.TrimSpace(item.Presence)) {
		case "ONLINE":
			neighbor.OnlineCount++
		case "OFFLINE":
			neighbor.OfflineCount++
		default:
			neighbor.RecentCount++
		}
		if item.TransportReady {
			neighbor.TransportReadyCount++
		}
		switch strings.ToUpper(strings.TrimSpace(item.NeighborState)) {
		case "CONNECTED":
			neighbor.ConnectedCount++
		case "NEGOTIATING", "DIRECT_CANDIDATE", "DISCOVERING", "RELAY_READY":
			neighbor.PendingCount++
		}
		switch strings.ToUpper(strings.TrimSpace(item.Reachability)) {
		case "DIRECT":
			neighbor.DirectReachabilityCount++
		case "RELAY":
			neighbor.RelayReachabilityCount++
		}
		switch strings.ToUpper(strings.TrimSpace(item.TransportMode)) {
		case "DIRECT":
			neighbor.DirectTransportCount++
		case "RELAY":
			neighbor.RelayTransportCount++
		}
		if item.CandidateCount > neighbor.MaxCandidateCount {
			neighbor.MaxCandidateCount = item.CandidateCount
		}
		if item.LastSeenUnix > neighbor.LastSeenUnix {
			neighbor.LastSeenUnix = item.LastSeenUnix
		}
		if item.LastSignaledAtUnix > neighbor.LastSignaledAtUnix {
			neighbor.LastSignaledAtUnix = item.LastSignaledAtUnix
		}
	}

	for _, tunnel := range tunnels {
		if strings.EqualFold(tunnel.State, "OPEN") {
			summary.OpenTunnelCount++
		}
		if strings.EqualFold(tunnel.State, "OPEN") && strings.EqualFold(tunnel.Mode, "P2P") {
			summary.OpenP2PTunnelCount++
		}
		if strings.EqualFold(tunnel.State, "OPEN") && strings.EqualFold(tunnel.Mode, "RELAY") {
			summary.OpenRelayTunnelCount++
		}
	}

	for _, binding := range bindings {
		if !strings.EqualFold(strings.TrimSpace(binding.RoutingPolicy), "FULL") {
			continue
		}
		gatewayCurrent.FullNetworkCount++
		if strings.EqualFold(binding.PolicyStatus, "ACTIVE") {
			gatewayCurrent.ActiveNetworkCount++
		} else {
			gatewayCurrent.PendingNetworkCount++
		}
		switch strings.ToUpper(strings.TrimSpace(binding.GatewayRole)) {
		case "GATEWAY":
			gatewayCurrent.LocalGatewayCount++
		case "CLIENT":
			gatewayCurrent.ClientGatewayCount++
		}
		path, state := diagnosticsGatewayCurrentPathAndState(binding, connections, rawPeers)
		switch path {
		case "DIRECT":
			gatewayCurrent.DirectPathCount++
		case "RELAY":
			gatewayCurrent.RelayPathCount++
		}
		if gatewayCurrent.CurrentNetworkID == "" || diagnosticsGatewayCurrentBindingRank(binding) > diagnosticsGatewayCurrentBindingRank(virtualadapter.NetworkBinding{
			PolicyStatus:  gatewayCurrent.CurrentPolicyStatus,
			GatewayRole:   gatewayCurrent.CurrentGatewayRole,
			GatewayPeerID: gatewayCurrent.CurrentGatewayPeerID,
		}) || (diagnosticsGatewayCurrentBindingRank(binding) == diagnosticsGatewayCurrentBindingRank(virtualadapter.NetworkBinding{
			PolicyStatus:  gatewayCurrent.CurrentPolicyStatus,
			GatewayRole:   gatewayCurrent.CurrentGatewayRole,
			GatewayPeerID: gatewayCurrent.CurrentGatewayPeerID,
		}) && strings.Compare(strings.TrimSpace(binding.NetworkID), strings.TrimSpace(gatewayCurrent.CurrentNetworkID)) < 0) {
			gatewayCurrent.CurrentNetworkID = binding.NetworkID
			gatewayCurrent.CurrentGatewayRole = strings.ToUpper(strings.TrimSpace(binding.GatewayRole))
			gatewayCurrent.CurrentGatewayPeerID = strings.TrimSpace(binding.GatewayPeerID)
			gatewayCurrent.CurrentPath = path
			gatewayCurrent.CurrentPolicyStatus = strings.ToUpper(strings.TrimSpace(binding.PolicyStatus))
			gatewayCurrent.CurrentConnectionState = state
		}
	}

	for _, event := range gatewayHistory {
		gateway.ChangeCount++
		if event.ChangedAtUnix > gateway.LastChangeUnix {
			gateway.LastChangeUnix = event.ChangedAtUnix
			gateway.LastEvent = event.Event
		}
		switch strings.ToUpper(strings.TrimSpace(event.Event)) {
		case "SELECTED":
			gateway.SelectionCount++
		case "FAILOVER":
			gateway.FailoverCount++
		case "FAILBACK":
			gateway.FailbackCount++
		case "PROMOTED":
			gateway.PromotedCount++
		case "DEMOTED":
			gateway.DemotedCount++
		case "LOST":
			gateway.LostCount++
		case "PATH_CHANGED":
			gateway.PathChangeCount++
		case "STATUS_CHANGED":
			gateway.StatusChangeCount++
		case "LOCAL_GATEWAY_ACTIVE":
			gateway.LocalGatewayActiveCount++
		case "LOCAL_GATEWAY_RELEASED":
			gateway.LocalGatewayReleasedCount++
		case "REMOVED":
			gateway.RemovedCount++
		}
	}

	for _, item := range groupTraffic {
		group.BlockedPacketCount += item.BlockedPacketCount
		group.FloodEventCount += item.FloodPacketCount
		group.FanoutCopyCount += item.FanoutCopyCount
		group.BroadcastPacketCount += item.BroadcastPacketCount
		group.MulticastPacketCount += item.MulticastPacketCount
		switch {
		case strings.TrimSpace(group.Policy) == "":
			group.Policy = strings.ToUpper(strings.TrimSpace(item.Policy))
		case !strings.EqualFold(group.Policy, strings.TrimSpace(item.Policy)):
			group.Policy = "MIXED"
		}
		if item.LastPacketUnix >= group.LastPacketUnix {
			group.LastPacketUnix = item.LastPacketUnix
			group.LastAction = item.LastAction
		}
	}

	for _, connection := range connections {
		summary.ConnectionCount++
		connectionState.ConnectionCount++
		if strings.TrimSpace(connection.SelectedCandidate) != "" {
			connectionState.SelectedCandidateCount++
		}
		if strings.TrimSpace(connection.LastError) != "" {
			connectionState.ErrorCount++
			recentErrors.ErrorCount++
			if connection.NextRetryUnix > 0 {
				recentErrors.TransientRetryCount++
				if recentErrors.NextRetryUnix == 0 || connection.NextRetryUnix < recentErrors.NextRetryUnix {
					recentErrors.NextRetryUnix = connection.NextRetryUnix
				}
			}
			if strings.EqualFold(strings.TrimSpace(connection.State), "CONNECTED") {
				recentErrors.ConnectedErrorCount++
			}
			if connection.NextRetryUnix == 0 && !strings.EqualFold(strings.TrimSpace(connection.State), "CONNECTED") {
				recentErrors.PersistentFailureCount++
			}
			if recentErrors.MostRecentError == "" || connection.LastAttemptUnix >= recentErrors.LastErrorUnix {
				recentErrors.LastErrorUnix = connection.LastAttemptUnix
				recentErrors.LastErrorPeerID = strings.TrimSpace(connection.RemotePeerID)
				recentErrors.LastErrorState = strings.ToUpper(strings.TrimSpace(connection.State))
				recentErrors.MostRecentError = strings.TrimSpace(connection.LastError)
			}
		}
		if connection.LastAttemptUnix > connectionState.LastAttemptUnix {
			connectionState.LastAttemptUnix = connection.LastAttemptUnix
		}
		if connection.NextRetryUnix > 0 {
			connectionState.RetryScheduledCount++
			if connectionState.NextRetryUnix == 0 || connection.NextRetryUnix < connectionState.NextRetryUnix {
				connectionState.NextRetryUnix = connection.NextRetryUnix
			}
		}
		if strings.EqualFold(connection.TunnelState, "OPEN") {
			connectionState.TunnelOpenCount++
		}
		if strings.EqualFold(connection.TunnelState, "NEGOTIATING") {
			connectionState.TunnelNegotiatingCount++
		}
		if connection.TransportReady {
			connectionState.TransportReadyCount++
		}
		switch strings.ToUpper(strings.TrimSpace(connection.State)) {
		case "CONNECTED":
			connectionState.ConnectedCount++
		case "DIRECT_CANDIDATE":
			connectionState.DirectCandidateCount++
		case "NEGOTIATING":
			connectionState.NegotiatingCount++
		case "RELAY_READY":
			connectionState.RelayReadyCount++
		default:
			connectionState.IdleCount++
		}
		switch {
		case strings.EqualFold(connection.TransportMode, "DIRECT"), strings.EqualFold(connection.Reachability, "DIRECT"):
			connectionState.DirectPathCount++
		case strings.EqualFold(connection.TransportMode, "RELAY"), strings.EqualFold(connection.Reachability, "RELAY"):
			connectionState.RelayPathCount++
		}
		switch diagnosticsConnectionQuality(connection) {
		case "healthy":
			transport.HealthyConnectionCount++
		case "degraded":
			transport.DegradedConnectionCount++
		case "pending":
			transport.PendingConnectionCount++
		case "fallback-ready":
			transport.FallbackReadyCount++
		}
		if strings.EqualFold(connection.State, "CONNECTED") {
			summary.ConnectedCount++
			if strings.EqualFold(connection.Reachability, "DIRECT") {
				summary.DirectConnectedCount++
				transport.ConnectedDirectCount++
			}
			if strings.EqualFold(connection.Reachability, "RELAY") {
				summary.RelayConnectedCount++
				transport.ConnectedRelayCount++
			}
		}
		if strings.EqualFold(connection.State, "DIRECT_CANDIDATE") {
			summary.DirectCandidateCount++
		}
		if strings.EqualFold(connection.State, "NEGOTIATING") {
			summary.NegotiatingCount++
		}
		if strings.EqualFold(connection.State, "RELAY_READY") {
			summary.RelayReadyCount++
		}
		if connection.TransportReady {
			summary.TransportReadyCount++
		}
		if strings.EqualFold(connection.TransportMode, "DIRECT") {
			summary.DirectTransportCount++
			summary.DirectTransportPacketCount += connection.TransportPacketCount
		}
		if strings.EqualFold(connection.TransportMode, "RELAY") {
			summary.RelayTransportCount++
			summary.RelayTransportPacketCount += connection.TransportPacketCount
		}
		summary.TotalTransportPacketCount += connection.TransportPacketCount
		transport.TotalTransportPacketCount += connection.TransportPacketCount
		if connection.LastTransportUnix > transport.LastTransportUnix {
			transport.LastTransportUnix = connection.LastTransportUnix
		}
		if connection.AverageRTTMillis > 0 {
			summary.AverageRTTMillis += connection.AverageRTTMillis
			rttSamples++
		}
		if connection.LastRTTMillis > summary.MaxRTTMillis {
			summary.MaxRTTMillis = connection.LastRTTMillis
		}
		if connection.ConsecutiveLosses > summary.MaxConsecutiveLosses {
			summary.MaxConsecutiveLosses = connection.ConsecutiveLosses
		}
		if connection.TransportReady {
			transportSessions.SessionCount++
			switch strings.ToUpper(strings.TrimSpace(connection.TransportMode)) {
			case "DIRECT":
				transportSessions.DirectSessionCount++
			case "RELAY":
				transportSessions.RelaySessionCount++
			}
			if connection.TransportEstablishedUnix > 0 {
				if transportSessions.OldestSessionUnix == 0 || connection.TransportEstablishedUnix < transportSessions.OldestSessionUnix {
					transportSessions.OldestSessionUnix = connection.TransportEstablishedUnix
					transportSessions.OldestSessionID = strings.TrimSpace(connection.TransportSessionID)
				}
				if connection.TransportEstablishedUnix > transportSessions.NewestSessionUnix {
					transportSessions.NewestSessionUnix = connection.TransportEstablishedUnix
				}
				ageSec := nowUnix - connection.TransportEstablishedUnix
				if ageSec > transportSessions.MaxSessionAgeSec {
					transportSessions.MaxSessionAgeSec = ageSec
				}
			}
			if connection.LastTransportUnix > 0 {
				idleSec := nowUnix - connection.LastTransportUnix
				if idleSec > transportSessions.MaxIdleSec {
					transportSessions.MaxIdleSec = idleSec
				}
			}
			if connection.TransportRekeyDueUnix > 0 {
				transportSessions.RekeyScheduledCount++
				if transportSessions.NextRekeyUnix == 0 || connection.TransportRekeyDueUnix < transportSessions.NextRekeyUnix {
					transportSessions.NextRekeyUnix = connection.TransportRekeyDueUnix
					transportSessions.NextRekeySessionID = strings.TrimSpace(connection.TransportSessionID)
				}
				if connection.TransportRekeyDueUnix <= nowUnix {
					transportSessions.RekeyOverdueCount++
				} else if connection.TransportRekeyDueUnix-nowUnix <= 300 {
					transportSessions.RekeyDueSoonCount++
				}
			}
		}
	}

	if rttSamples > 0 {
		summary.AverageRTTMillis /= rttSamples
	}
	if rollup := summarizeAdapterRollup(adapter, bindings); rollup != nil {
		summary.Adapter = rollup
	}
	if rollup := summarizeAdapterNeighborCorrelation(bindings, neighbors); rollup != nil {
		summary.AdapterNeighbor = rollup
	}
	if len(connections) > 0 {
		connectionState.MostSevereState = diagnosticsConnectionRollupState(*connectionState)
		connectionState.Hint = diagnosticsConnectionRollupHint(*connectionState)
		summary.ConnectionState = connectionState
	}
	if len(neighbors) > 0 {
		summary.Neighbors = neighbor
	}
	if len(connections) > 0 {
		transport.Quality = diagnosticsTransportQuality(*transport)
		summary.Transport = transport
	}
	if transportSessions.SessionCount > 0 {
		transportSessions.MostSevereState = diagnosticsTransportSessionState(*transportSessions)
		transportSessions.Hint = diagnosticsTransportSessionHint(*transportSessions)
		summary.TransportSessions = transportSessions
	}
	if recentErrors.ErrorCount > 0 {
		recentErrors.MostSevereState = diagnosticsRecentErrorState(*recentErrors)
		recentErrors.Hint = diagnosticsRecentErrorHint(*recentErrors)
		summary.RecentErrors = recentErrors
	}
	if len(gatewayHistory) > 0 {
		summary.Gateway = gateway
	}
	if len(groupTraffic) > 0 {
		summary.GroupTraffic = group
	}
	if len(bindings) > 0 && gatewayCurrent.FullNetworkCount > 0 {
		summary.GatewayCurrent = gatewayCurrent
	}

	return summary
}

func summarizeAdapterNeighborCorrelation(bindings []virtualadapter.NetworkBinding, neighbors []NeighborStatus) *DiagnosticsAdapterNeighborRollup {
	if len(bindings) == 0 && len(neighbors) == 0 {
		return nil
	}
	bindingsByNetwork := map[string]virtualadapter.NetworkBinding{}
	for _, binding := range bindings {
		if strings.TrimSpace(binding.NetworkID) == "" {
			continue
		}
		if _, exists := bindingsByNetwork[binding.NetworkID]; !exists {
			bindingsByNetwork[binding.NetworkID] = binding
		}
	}
	neighborsByNetwork := map[string][]NeighborStatus{}
	for _, neighbor := range neighbors {
		if strings.TrimSpace(neighbor.NetworkID) == "" {
			continue
		}
		neighborsByNetwork[neighbor.NetworkID] = append(neighborsByNetwork[neighbor.NetworkID], neighbor)
	}
	networkIDs := make([]string, 0, len(bindingsByNetwork)+len(neighborsByNetwork))
	for networkID := range bindingsByNetwork {
		networkIDs = append(networkIDs, networkID)
	}
	for networkID := range neighborsByNetwork {
		if _, exists := bindingsByNetwork[networkID]; !exists {
			networkIDs = append(networkIDs, networkID)
		}
	}
	sort.Strings(networkIDs)
	if len(networkIDs) == 0 {
		return nil
	}
	rollup := &DiagnosticsAdapterNeighborRollup{NetworkCount: len(networkIDs)}
	mostSevereRank := -1
	for _, networkID := range networkIDs {
		binding, hasBinding := bindingsByNetwork[networkID]
		networkNeighbors := neighborsByNetwork[networkID]
		readyNeighbors := 0
		for _, neighbor := range networkNeighbors {
			if neighbor.TransportReady || strings.EqualFold(strings.TrimSpace(neighbor.NeighborState), "CONNECTED") {
				readyNeighbors++
			}
		}
		rollup.ReadyNeighborCount += readyNeighbors

		bindingHealthy := false
		if hasBinding {
			if binding.IPAddressVisible && binding.RouteVisible && strings.EqualFold(strings.TrimSpace(binding.PolicyStatus), "ACTIVE") {
				bindingHealthy = true
				rollup.HealthyBindingCount++
			}
			if !binding.IPAddressVisible {
				rollup.MissingIPVisibilityCount++
			}
			if !binding.RouteVisible {
				rollup.MissingRouteVisibilityCount++
			}
			if strings.EqualFold(strings.TrimSpace(binding.PolicyStatus), "PENDING_GATEWAY") {
				rollup.PendingGatewayCount++
			}
		}

		state := "PENDING"
		switch {
		case hasBinding && strings.EqualFold(strings.TrimSpace(binding.PolicyStatus), "STANDBY_GATEWAY"):
			state = "STANDBY"
		case readyNeighbors > 0 && !bindingHealthy:
			state = "ADAPTER_LAGGING"
			rollup.AdapterLaggingCount++
		case bindingHealthy && readyNeighbors == 0:
			state = "TRANSPORT_LAGGING"
			rollup.TransportLaggingCount++
		case bindingHealthy && readyNeighbors > 0:
			state = "ALIGNED"
			rollup.AlignedCount++
		default:
			rollup.PendingCount++
		}

		rank := diagnosticsAdapterNeighborStateRank(state)
		if rank > mostSevereRank {
			mostSevereRank = rank
			rollup.MostSevereState = state
			rollup.AffectedNetworkID = networkID
			rollup.Hint = diagnosticsAdapterNeighborHint(state, hasBinding, binding, readyNeighbors)
		}
	}
	return rollup
}

func diagnosticsAdapterNeighborStateRank(state string) int {
	switch strings.ToUpper(strings.TrimSpace(state)) {
	case "ADAPTER_LAGGING":
		return 4
	case "TRANSPORT_LAGGING":
		return 3
	case "STANDBY":
		return 2
	case "PENDING":
		return 2
	case "ALIGNED":
		return 1
	default:
		return 0
	}
}

func diagnosticsAdapterNeighborHint(state string, hasBinding bool, binding virtualadapter.NetworkBinding, readyNeighbors int) string {
	switch strings.ToUpper(strings.TrimSpace(state)) {
	case "ADAPTER_LAGGING":
		switch {
		case hasBinding && !binding.IPAddressVisible && !binding.RouteVisible:
			return "Neighbor transport is ready, but the adapter still lacks both IP and route visibility."
		case hasBinding && !binding.IPAddressVisible:
			return "Neighbor transport is ready, but the adapter IP is not visible yet."
		case hasBinding && !binding.RouteVisible:
			return "Neighbor transport is ready, but the adapter route is not visible yet."
		case hasBinding && strings.EqualFold(strings.TrimSpace(binding.PolicyStatus), "PENDING_GATEWAY"):
			return "Neighbor transport is ready, but the adapter is still waiting for gateway policy activation."
		default:
			return "Neighbor transport is ready, but adapter visibility or policy state is still lagging."
		}
	case "STANDBY":
		return "Neighbor transport is ready, but another FULL network currently owns the default route for this client."
	case "TRANSPORT_LAGGING":
		if readyNeighbors == 0 {
			return "Adapter visibility looks healthy, but no transport-ready neighbors are currently available."
		}
		return "Adapter visibility looks healthy, but neighbor transport has not reached ready state yet."
	case "ALIGNED":
		return "Adapter visibility and neighbor transport readiness are aligned."
	default:
		return "Adapter visibility and neighbor readiness are still converging."
	}
}

func diagnosticsConnectionRollupState(rollup DiagnosticsConnectionStateRollup) string {
	switch {
	case rollup.ConnectionCount == 0:
		return "IDLE"
	case rollup.ConnectedCount > 0 && (rollup.DirectCandidateCount > 0 || rollup.NegotiatingCount > 0 || rollup.RelayReadyCount > 0 || rollup.ErrorCount > 0):
		return "MIXED"
	case rollup.ConnectedCount > 0:
		return "CONNECTED"
	case rollup.NegotiatingCount > 0:
		return "NEGOTIATING"
	case rollup.DirectCandidateCount > 0:
		return "DIRECT_CANDIDATE"
	case rollup.RelayReadyCount > 0:
		return "RELAY_READY"
	case rollup.ErrorCount > 0:
		return "ERROR"
	default:
		return "IDLE"
	}
}

func diagnosticsConnectionRollupHint(rollup DiagnosticsConnectionStateRollup) string {
	switch rollup.MostSevereState {
	case "MIXED":
		return "Some connections are already established while others are still retrying or degrading."
	case "CONNECTED":
		return "Connection lifecycle is stable: at least one path is connected without pending fallback work."
	case "NEGOTIATING":
		return "Connections are negotiating transport and tunnel state but have not fully settled yet."
	case "DIRECT_CANDIDATE":
		return "Connections have direct candidates and are waiting for negotiation or retry windows."
	case "RELAY_READY":
		return "Connections are ready to fall back to relay, but a fully connected path is not open yet."
	case "ERROR":
		if rollup.RetryScheduledCount > 0 {
			return "Connection errors are present, but retries are already scheduled."
		}
		return "Connection errors are present without any fully connected path yet."
	default:
		return "No active connection lifecycle is currently in progress."
	}
}

func summarizeCrossNetworkHealth(networks []DiagnosticsNetwork) *DiagnosticsCrossNetworkRollup {
	if len(networks) <= 1 {
		return nil
	}
	rollup := &DiagnosticsCrossNetworkRollup{NetworkCount: len(networks)}
	mostSevereRank := -1
	for _, network := range networks {
		state := diagnosticsNetworkHealthState(network.UsageSummary)
		switch state {
		case "HEALTHY":
			rollup.HealthyCount++
		case "DEGRADED":
			rollup.DegradedCount++
			rollup.AffectedCount++
		case "PENDING":
			rollup.PendingCount++
			rollup.AffectedCount++
		default:
			rollup.IdleCount++
		}
		rank := diagnosticsCrossNetworkStateRank(state)
		if rank > mostSevereRank {
			mostSevereRank = rank
			rollup.AffectedNetworkID = network.Network.ID
		}
	}
	if rollup.AffectedCount == 1 {
		rollup.IsolatedIssueCount = 1
	}
	if rollup.AffectedCount > 1 {
		rollup.WidespreadIssueCount = rollup.AffectedCount
	}
	rollup.MostSevereState = diagnosticsCrossNetworkOverallState(*rollup)
	rollup.Hint = diagnosticsCrossNetworkHint(*rollup)
	return rollup
}

func diagnosticsNetworkHealthState(summary DiagnosticsUsageSummary) string {
	switch {
	case summary.AdapterNeighbor != nil && (summary.AdapterNeighbor.AdapterLaggingCount > 0 || summary.AdapterNeighbor.TransportLaggingCount > 0):
		return "DEGRADED"
	case summary.Transport != nil && strings.EqualFold(strings.TrimSpace(summary.Transport.Quality), "degraded"):
		return "DEGRADED"
	case summary.ConnectionState != nil && (strings.EqualFold(strings.TrimSpace(summary.ConnectionState.MostSevereState), "MIXED") || strings.EqualFold(strings.TrimSpace(summary.ConnectionState.MostSevereState), "ERROR")):
		return "DEGRADED"
	case summary.Adapter != nil && summary.Adapter.HasError:
		return "DEGRADED"
	case summary.ConnectionState != nil && strings.TrimSpace(summary.ConnectionState.MostSevereState) != "" && !strings.EqualFold(strings.TrimSpace(summary.ConnectionState.MostSevereState), "CONNECTED") && !strings.EqualFold(strings.TrimSpace(summary.ConnectionState.MostSevereState), "IDLE"):
		return "PENDING"
	case summary.AdapterNeighbor != nil && strings.EqualFold(strings.TrimSpace(summary.AdapterNeighbor.MostSevereState), "PENDING"):
		return "PENDING"
	case summary.GatewayCurrent != nil && strings.EqualFold(strings.TrimSpace(summary.GatewayCurrent.CurrentPolicyStatus), "PENDING_GATEWAY"):
		return "PENDING"
	case summary.ConnectionCount == 0 && summary.Neighbors == nil && summary.Transport == nil:
		return "IDLE"
	default:
		return "HEALTHY"
	}
}

func diagnosticsCrossNetworkStateRank(state string) int {
	switch state {
	case "DEGRADED":
		return 3
	case "PENDING":
		return 2
	case "IDLE":
		return 1
	default:
		return 0
	}
}

func diagnosticsCrossNetworkOverallState(rollup DiagnosticsCrossNetworkRollup) string {
	switch {
	case rollup.DegradedCount > 1:
		return "WIDESPREAD_DEGRADATION"
	case rollup.DegradedCount == 1:
		return "ISOLATED_DEGRADATION"
	case rollup.PendingCount > 1:
		return "WIDESPREAD_PENDING"
	case rollup.PendingCount == 1:
		return "ISOLATED_PENDING"
	case rollup.HealthyCount == rollup.NetworkCount:
		return "HEALTHY"
	case rollup.IdleCount == rollup.NetworkCount:
		return "IDLE"
	default:
		return "MIXED"
	}
}

func diagnosticsCrossNetworkHint(rollup DiagnosticsCrossNetworkRollup) string {
	switch rollup.MostSevereState {
	case "WIDESPREAD_DEGRADATION":
		return "Multiple networks are degraded, which points to service-wide transport or adapter trouble rather than a single-network issue."
	case "ISOLATED_DEGRADATION":
		return "Only one network is degraded, so support work can stay focused on that specific overlay."
	case "WIDESPREAD_PENDING":
		return "Multiple networks are still pending convergence, which suggests a shared startup, signaling, or reconnect phase."
	case "ISOLATED_PENDING":
		return "Only one network is still pending while the others look healthy."
	case "HEALTHY":
		return "All exported networks currently look healthy at the rollup level."
	case "IDLE":
		return "All exported networks are idle right now, so there is no active cross-network issue to compare."
	default:
		return "Network health is mixed across the export; compare the affected network with the healthier ones first."
	}
}

func summarizeAdapterRollup(adapter virtualadapter.Status, bindings []virtualadapter.NetworkBinding) *DiagnosticsAdapterRollup {
	if !adapterRollupPresent(adapter, bindings) {
		return nil
	}
	rollup := &DiagnosticsAdapterRollup{
		Enabled:         adapter.Enabled,
		Available:       adapter.Available,
		SessionActive:   adapter.SessionActive,
		ConnectionState: strings.ToUpper(strings.TrimSpace(adapter.ConnectionState)),
		BindingCount:    len(bindings),
		DesiredMTU:      adapter.DesiredMTU,
		CurrentMTU:      adapter.MTU,
		DNSServerCount:  len(adapter.DNSServers),
		HasDNSSuffix:    strings.TrimSpace(adapter.DNSSuffix) != "",
		HasError:        strings.TrimSpace(adapter.LastError) != "",
	}
	for _, binding := range bindings {
		if strings.EqualFold(strings.TrimSpace(binding.RoutingPolicy), "FULL") {
			rollup.FullBindingCount++
		} else {
			rollup.SplitBindingCount++
		}
		if strings.EqualFold(strings.TrimSpace(binding.PolicyStatus), "ACTIVE") {
			rollup.ActivePolicyCount++
		} else {
			rollup.PendingPolicyCount++
		}
		if binding.IPAddressVisible {
			rollup.VisibleIPCount++
		}
		if binding.RouteVisible {
			rollup.VisibleRouteCount++
		}
		if binding.IPAddressVisible && binding.RouteVisible {
			rollup.HealthyBindingCount++
		}
	}
	return rollup
}

func adapterRollupPresent(adapter virtualadapter.Status, bindings []virtualadapter.NetworkBinding) bool {
	return len(bindings) > 0 ||
		adapter.Enabled ||
		adapter.Available ||
		adapter.SessionActive ||
		strings.TrimSpace(adapter.ConnectionState) != "" ||
		adapter.DesiredMTU > 0 ||
		adapter.MTU > 0 ||
		len(adapter.DNSServers) > 0 ||
		strings.TrimSpace(adapter.DNSSuffix) != ""
}

func diagnosticsConnectionQuality(connection ConnectionStatus) string {
	if strings.EqualFold(connection.State, "CONNECTED") {
		if connection.ConsecutiveLosses > 0 {
			return "degraded"
		}
		if strings.EqualFold(connection.TransportMode, "RELAY") || strings.EqualFold(connection.Reachability, "RELAY") {
			return "relay"
		}
		return "healthy"
	}
	switch strings.ToUpper(strings.TrimSpace(connection.State)) {
	case "NEGOTIATING", "DIRECT_CANDIDATE", "DISCOVERING":
		return "pending"
	case "RELAY_READY":
		return "fallback-ready"
	default:
		return "idle"
	}
}

func diagnosticsTransportQuality(rollup DiagnosticsTransportRollup) string {
	switch {
	case rollup.HealthyConnectionCount == 0 && rollup.DegradedConnectionCount == 0 && rollup.PendingConnectionCount == 0 && rollup.FallbackReadyCount == 0:
		return "idle"
	case rollup.HealthyConnectionCount == 0 && rollup.DegradedConnectionCount == 0 && rollup.PendingConnectionCount > 0:
		return "pending"
	case rollup.HealthyConnectionCount == 0 && rollup.DegradedConnectionCount == 0 && rollup.FallbackReadyCount > 0:
		return "fallback-ready"
	case rollup.DegradedConnectionCount > 0:
		return "degraded"
	case rollup.ConnectedRelayCount > 0 && rollup.ConnectedDirectCount > 0:
		return "mixed"
	case rollup.ConnectedRelayCount > 0:
		return "relay"
	default:
		return "healthy"
	}
}

func diagnosticsTransportSessionState(rollup DiagnosticsTransportSessionRollup) string {
	switch {
	case rollup.RekeyOverdueCount > 0:
		return "OVERDUE_REKEY"
	case rollup.RekeyDueSoonCount > 0:
		return "REKEY_DUE_SOON"
	case rollup.MaxSessionAgeSec >= 3600:
		return "LONG_LIVED"
	default:
		return "ACTIVE"
	}
}

func diagnosticsTransportSessionHint(rollup DiagnosticsTransportSessionRollup) string {
	switch rollup.MostSevereState {
	case "OVERDUE_REKEY":
		return "At least one live transport session is already past its rekey deadline, so support should inspect long-lived session rollover first."
	case "REKEY_DUE_SOON":
		return "Live transport sessions are healthy, but at least one rekey deadline is approaching soon."
	case "LONG_LIVED":
		return "Live transport sessions are long-lived; compare the oldest session age and idle time with any reported path degradation."
	default:
		return "Live transport sessions are active and within their current rekey window."
	}
}

func diagnosticsRecentErrorState(rollup DiagnosticsRecentErrorRollup) string {
	switch {
	case rollup.PersistentFailureCount > 0 && (rollup.TransientRetryCount > 0 || rollup.ConnectedErrorCount > 0):
		return "MIXED"
	case rollup.PersistentFailureCount > 0:
		return "PERSISTENT_FAILURE"
	case rollup.ConnectedErrorCount > 0 && rollup.TransientRetryCount > 0:
		return "MIXED"
	case rollup.ConnectedErrorCount > 0:
		return "DEGRADED_CONNECTED"
	case rollup.TransientRetryCount > 0:
		return "TRANSIENT_RETRY"
	default:
		return "ERROR"
	}
}

func diagnosticsRecentErrorHint(rollup DiagnosticsRecentErrorRollup) string {
	switch rollup.MostSevereState {
	case "MIXED":
		return "Recent errors are mixed: some paths are still retrying while others now look persistently broken."
	case "PERSISTENT_FAILURE":
		return "Recent errors are no longer inside a retry window, which points to a persistent path failure."
	case "DEGRADED_CONNECTED":
		return "At least one path is still connected, but recent transport errors are accumulating on the active session."
	case "TRANSIENT_RETRY":
		return "Recent errors look transient because retry windows are already scheduled for the affected paths."
	default:
		return "Recent errors are present, but the current lifecycle does not yet distinguish retrying versus persistent paths."
	}
}

func applyDirectMetricsToUsageSummary(summary DiagnosticsUsageSummary, metrics DirectConnectMetrics) DiagnosticsUsageSummary {
	summary.DirectAttemptCount = metrics.AttemptCount
	summary.DirectSuccessCount = metrics.SuccessCount
	summary.DirectFailureCount = metrics.FailureCount
	summary.DirectSuccessRatePct = metrics.SuccessRatePct
	summary.RelayFallbackCount = metrics.RelayFallbackCount
	summary.DirectFailbackSuccessCount = metrics.FailbackSuccessCount
	return summary
}

func filterConnectionsByNetwork(connections []ConnectionStatus, networkID string) []ConnectionStatus {
	if len(connections) == 0 {
		return nil
	}
	filtered := make([]ConnectionStatus, 0, len(connections))
	for _, connection := range connections {
		if connection.NetworkID == networkID {
			filtered = append(filtered, connection)
		}
	}
	return filtered
}

func filterAdapterBindingsByNetwork(bindings []virtualadapter.NetworkBinding, networkID string) []virtualadapter.NetworkBinding {
	if len(bindings) == 0 {
		return nil
	}
	filtered := make([]virtualadapter.NetworkBinding, 0, len(bindings))
	for _, binding := range bindings {
		if binding.NetworkID == networkID {
			filtered = append(filtered, binding)
		}
	}
	return filtered
}

func filterNeighborsByNetwork(neighbors []NeighborStatus, networkID string) []NeighborStatus {
	if len(neighbors) == 0 {
		return nil
	}
	filtered := make([]NeighborStatus, 0, len(neighbors))
	for _, neighbor := range neighbors {
		if neighbor.NetworkID == networkID {
			filtered = append(filtered, neighbor)
		}
	}
	return dedupeDiagnosticsNeighbors(filtered)
}

func filterGatewayHistoryByNetwork(events []GatewayChangeEvent, networkID string) []GatewayChangeEvent {
	if len(events) == 0 {
		return nil
	}
	filtered := make([]GatewayChangeEvent, 0, len(events))
	for _, event := range events {
		if event.NetworkID == networkID {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func diagnosticsGatewayCurrentPathAndState(binding virtualadapter.NetworkBinding, connections []ConnectionStatus, peers []controlclient.Peer) (string, string) {
	connections = dedupeDiagnosticsConnections(normalizeDiagnosticsConnections(connections, peers))
	if strings.EqualFold(strings.TrimSpace(binding.GatewayRole), "GATEWAY") {
		return "LOCAL", "ACTIVE"
	}
	peerID := strings.TrimSpace(binding.GatewayPeerID)
	if peerID == "" {
		if strings.EqualFold(strings.TrimSpace(binding.PolicyStatus), "PENDING_GATEWAY") {
			return "PENDING", "PENDING_GATEWAY"
		}
		return "", ""
	}
	for _, connection := range connections {
		if connection.NetworkID != binding.NetworkID || connection.RemotePeerID != peerID {
			continue
		}
		return strings.ToUpper(strings.TrimSpace(gatewayPathForConnection(&connection))), strings.ToUpper(strings.TrimSpace(connection.State))
	}
	target := diagnosticsGatewayBindingPeerTarget(binding, peers)
	if target != nil {
		if replacement := diagnosticsPreferredGatewayReplacementConnection(binding, *target, connections); replacement != nil {
			return strings.ToUpper(strings.TrimSpace(gatewayPathForConnection(replacement))), strings.ToUpper(strings.TrimSpace(replacement.State))
		}
	}
	return "PENDING", strings.ToUpper(strings.TrimSpace(binding.PolicyStatus))
}

func diagnosticsGatewayBindingPeerTarget(binding virtualadapter.NetworkBinding, peers []controlclient.Peer) *controlclient.Peer {
	peerID := strings.TrimSpace(binding.GatewayPeerID)
	networkID := strings.TrimSpace(binding.NetworkID)
	if networkID == "" {
		return nil
	}
	if peerID != "" {
		for idx := range peers {
			peer := &peers[idx]
			if strings.EqualFold(strings.TrimSpace(peer.NetworkID), networkID) &&
				strings.EqualFold(strings.TrimSpace(peer.ID), peerID) {
				return peer
			}
		}
	}
	userID := strings.TrimSpace(binding.GatewayUserID)
	virtualIP := strings.TrimSpace(binding.GatewayVirtualIP)
	if userID == "" || virtualIP == "" {
		return nil
	}
	return &controlclient.Peer{
		ID:        peerID,
		NetworkID: networkID,
		UserID:    userID,
		VirtualIP: virtualIP,
	}
}

func diagnosticsPreferredGatewayReplacementConnection(binding virtualadapter.NetworkBinding, target controlclient.Peer, connections []ConnectionStatus) *ConnectionStatus {
	var best *ConnectionStatus
	for idx := range connections {
		candidate := &connections[idx]
		if !strings.EqualFold(strings.TrimSpace(candidate.NetworkID), strings.TrimSpace(binding.NetworkID)) {
			continue
		}
		candidatePeer := controlclient.Peer{
			ID:        candidate.RemotePeerID,
			NetworkID: candidate.NetworkID,
			UserID:    candidate.RemoteUserID,
			VirtualIP: candidate.RemoteVirtualIP,
		}
		if !sameOverlayPeerTarget(target, candidatePeer) {
			continue
		}
		if best == nil || betterGatewayConnection(candidate, "", best, "") {
			best = candidate
		}
	}
	return best
}

func normalizeDiagnosticsConnections(connections []ConnectionStatus, peers []controlclient.Peer) []ConnectionStatus {
	if len(connections) == 0 {
		return nil
	}
	out := make([]ConnectionStatus, len(connections))
	copy(out, connections)
	for idx := range out {
		if strings.TrimSpace(out[idx].RemoteUserID) == "" {
			out[idx].RemoteUserID = strings.TrimSpace(remotePeerUserIDForConnection(peers, out[idx].RemotePeerID))
		}
		if strings.TrimSpace(out[idx].RemoteVirtualIP) == "" {
			out[idx].RemoteVirtualIP = strings.TrimSpace(remotePeerVirtualIPForConnection(peers, out[idx].RemotePeerID))
		}
	}
	return out
}

func normalizeDiagnosticsNeighbors(neighbors []NeighborStatus, peers []controlclient.Peer) []NeighborStatus {
	if len(neighbors) == 0 {
		return nil
	}
	out := make([]NeighborStatus, len(neighbors))
	copy(out, neighbors)
	for idx := range out {
		if strings.TrimSpace(out[idx].RemoteUserID) == "" {
			out[idx].RemoteUserID = strings.TrimSpace(remotePeerUserIDForConnection(peers, out[idx].RemotePeerID))
		}
		if strings.TrimSpace(out[idx].RemoteVirtualIP) == "" {
			out[idx].RemoteVirtualIP = strings.TrimSpace(remotePeerVirtualIPForConnection(peers, out[idx].RemotePeerID))
		}
	}
	return out
}

func dedupeDiagnosticsConnections(connections []ConnectionStatus) []ConnectionStatus {
	if len(connections) < 2 {
		return connections
	}
	deduped := make([]ConnectionStatus, 0, len(connections))
	for _, connection := range connections {
		replaced := false
		for idx := range deduped {
			if !sameDiagnosticsConnectionTarget(deduped[idx], connection) {
				continue
			}
			if betterSignalingConnection(&connection, &deduped[idx]) {
				deduped[idx] = connection
			}
			replaced = true
			break
		}
		if replaced {
			continue
		}
		deduped = append(deduped, connection)
	}
	return deduped
}

func dedupeDiagnosticsPeers(peers []controlclient.Peer) []controlclient.Peer {
	if len(peers) < 2 {
		return peers
	}
	deduped := make([]controlclient.Peer, 0, len(peers))
	for _, peer := range peers {
		replaced := false
		for idx := range deduped {
			if !sameDiagnosticsPeerTarget(deduped[idx], peer) {
				continue
			}
			if betterDiagnosticsPeer(peer, deduped[idx]) {
				deduped[idx] = peer
			}
			replaced = true
			break
		}
		if replaced {
			continue
		}
		deduped = append(deduped, peer)
	}
	return deduped
}

func dedupeDiagnosticsNeighbors(neighbors []NeighborStatus) []NeighborStatus {
	if len(neighbors) < 2 {
		return neighbors
	}
	deduped := make([]NeighborStatus, 0, len(neighbors))
	for _, neighbor := range neighbors {
		replaced := false
		for idx := range deduped {
			if !sameDiagnosticsNeighborTarget(deduped[idx], neighbor) {
				continue
			}
			if betterDiagnosticsNeighbor(neighbor, deduped[idx]) {
				deduped[idx] = neighbor
			}
			replaced = true
			break
		}
		if replaced {
			continue
		}
		deduped = append(deduped, neighbor)
	}
	return deduped
}

func sameDiagnosticsConnectionTarget(current, candidate ConnectionStatus) bool {
	if !strings.EqualFold(strings.TrimSpace(current.NetworkID), strings.TrimSpace(candidate.NetworkID)) {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(current.LocalPeerID), strings.TrimSpace(candidate.LocalPeerID)) {
		return false
	}
	currentVirtualIP := strings.TrimSpace(current.RemoteVirtualIP)
	candidateVirtualIP := strings.TrimSpace(candidate.RemoteVirtualIP)
	if currentVirtualIP == "" || candidateVirtualIP == "" {
		return false
	}
	if !strings.EqualFold(currentVirtualIP, candidateVirtualIP) {
		return false
	}
	currentUserID := strings.TrimSpace(current.RemoteUserID)
	candidateUserID := strings.TrimSpace(candidate.RemoteUserID)
	if currentUserID != "" && candidateUserID != "" && !strings.EqualFold(currentUserID, candidateUserID) {
		return false
	}
	return true
}

func sameDiagnosticsPeerTarget(current, candidate controlclient.Peer) bool {
	return sameOverlayPeerTarget(current, candidate)
}

func sameDiagnosticsNeighborTarget(current, candidate NeighborStatus) bool {
	networkID := strings.TrimSpace(current.NetworkID)
	localPeerID := strings.TrimSpace(current.LocalPeerID)
	remotePeerID := strings.TrimSpace(current.RemotePeerID)
	remoteVirtualIP := strings.TrimSpace(current.RemoteVirtualIP)
	if networkID == "" || localPeerID == "" {
		return false
	}
	if strings.EqualFold(remotePeerID, strings.TrimSpace(candidate.RemotePeerID)) && remotePeerID != "" &&
		strings.EqualFold(networkID, strings.TrimSpace(candidate.NetworkID)) &&
		strings.EqualFold(localPeerID, strings.TrimSpace(candidate.LocalPeerID)) {
		return true
	}
	if remoteVirtualIP == "" ||
		!strings.EqualFold(networkID, strings.TrimSpace(candidate.NetworkID)) ||
		!strings.EqualFold(localPeerID, strings.TrimSpace(candidate.LocalPeerID)) ||
		!strings.EqualFold(remoteVirtualIP, strings.TrimSpace(candidate.RemoteVirtualIP)) {
		return false
	}
	currentUserID := strings.TrimSpace(current.RemoteUserID)
	candidateUserID := strings.TrimSpace(candidate.RemoteUserID)
	if currentUserID != "" && candidateUserID != "" && !strings.EqualFold(currentUserID, candidateUserID) {
		return false
	}
	return true
}

func betterDiagnosticsPeer(candidate, current controlclient.Peer) bool {
	if diagnosticsPeerStatePreference(candidate) != diagnosticsPeerStatePreference(current) {
		return diagnosticsPeerStatePreference(candidate) > diagnosticsPeerStatePreference(current)
	}
	if diagnosticsPeerPresencePreference(candidate) != diagnosticsPeerPresencePreference(current) {
		return diagnosticsPeerPresencePreference(candidate) > diagnosticsPeerPresencePreference(current)
	}
	if candidate.LastSignaledAtUnix != current.LastSignaledAtUnix {
		return candidate.LastSignaledAtUnix > current.LastSignaledAtUnix
	}
	if candidate.LastSeenUnix != current.LastSeenUnix {
		return candidate.LastSeenUnix > current.LastSeenUnix
	}
	return strings.Compare(strings.TrimSpace(candidate.ID), strings.TrimSpace(current.ID)) < 0
}

func diagnosticsPeerStatePreference(peer controlclient.Peer) int {
	switch strings.ToUpper(strings.TrimSpace(peer.ConnectionState)) {
	case "CONNECTED":
		return 4
	case "NEGOTIATING", "DIRECT_CANDIDATE", "DISCOVERING", "RELAY_READY":
		return 3
	case "IDLE":
		return 1
	default:
		return 0
	}
}

func diagnosticsPeerPresencePreference(peer controlclient.Peer) int {
	switch strings.ToUpper(strings.TrimSpace(peer.Status)) {
	case "ONLINE":
		return 2
	case "OFFLINE":
		return 0
	default:
		return 1
	}
}

func betterDiagnosticsNeighbor(candidate, current NeighborStatus) bool {
	if diagnosticsNeighborStatePreference(candidate) != diagnosticsNeighborStatePreference(current) {
		return diagnosticsNeighborStatePreference(candidate) > diagnosticsNeighborStatePreference(current)
	}
	if diagnosticsNeighborPathPreference(candidate) != diagnosticsNeighborPathPreference(current) {
		return diagnosticsNeighborPathPreference(candidate) > diagnosticsNeighborPathPreference(current)
	}
	if candidate.CandidateCount != current.CandidateCount {
		return candidate.CandidateCount > current.CandidateCount
	}
	if candidate.LastSignaledAtUnix != current.LastSignaledAtUnix {
		return candidate.LastSignaledAtUnix > current.LastSignaledAtUnix
	}
	if candidate.LastSeenUnix != current.LastSeenUnix {
		return candidate.LastSeenUnix > current.LastSeenUnix
	}
	return strings.Compare(strings.TrimSpace(candidate.RemotePeerID), strings.TrimSpace(current.RemotePeerID)) < 0
}

func diagnosticsNeighborStatePreference(neighbor NeighborStatus) int {
	if neighbor.TransportReady {
		return 4
	}
	switch strings.ToUpper(strings.TrimSpace(neighbor.NeighborState)) {
	case "CONNECTED":
		return 3
	case "NEGOTIATING", "DIRECT_CANDIDATE", "DISCOVERING", "RELAY_READY":
		return 2
	case "IDLE":
		return 1
	default:
		return 0
	}
}

func diagnosticsNeighborPathPreference(neighbor NeighborStatus) int {
	switch {
	case strings.EqualFold(strings.TrimSpace(neighbor.TransportMode), "DIRECT"), strings.EqualFold(strings.TrimSpace(neighbor.Reachability), "DIRECT"):
		return 2
	case strings.EqualFold(strings.TrimSpace(neighbor.TransportMode), "RELAY"), strings.EqualFold(strings.TrimSpace(neighbor.Reachability), "RELAY"):
		return 1
	default:
		return 0
	}
}

func diagnosticsGatewayCurrentBindingRank(binding virtualadapter.NetworkBinding) int {
	switch strings.ToUpper(strings.TrimSpace(binding.PolicyStatus)) {
	case "ACTIVE":
		return 3
	case "STANDBY_GATEWAY":
		return 2
	case "PENDING_GATEWAY":
		return 1
	default:
		return 0
	}
}

func filterGroupTrafficByNetwork(items []GroupTrafficDiagnostics, networkID string) []GroupTrafficDiagnostics {
	if len(items) == 0 {
		return nil
	}
	filtered := make([]GroupTrafficDiagnostics, 0, len(items))
	for _, item := range items {
		if item.NetworkID == networkID {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func flattenDiagnosticsPeers(networks []DiagnosticsNetwork) []controlclient.Peer {
	if len(networks) == 0 {
		return nil
	}
	total := 0
	for _, network := range networks {
		total += len(network.Peers)
	}
	if total == 0 {
		return nil
	}
	peers := make([]controlclient.Peer, 0, total)
	for _, network := range networks {
		peers = append(peers, network.Peers...)
	}
	return peers
}

func flattenDiagnosticsTunnels(networks []DiagnosticsNetwork) []controlclient.Tunnel {
	if len(networks) == 0 {
		return nil
	}
	total := 0
	for _, network := range networks {
		total += len(network.Tunnels)
	}
	if total == 0 {
		return nil
	}
	tunnels := make([]controlclient.Tunnel, 0, total)
	for _, network := range networks {
		tunnels = append(tunnels, network.Tunnels...)
	}
	return tunnels
}
