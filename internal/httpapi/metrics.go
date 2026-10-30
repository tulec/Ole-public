package httpapi

import (
	"Ole/internal/prommetrics"
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (api *API) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodOrNotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	if api != nil && api.metrics != nil {
		_, _ = w.Write(api.metrics.Render())
	}
	dynamic := prommetrics.NewRegistry()
	api.populateDynamicMetrics(dynamic)
	_, _ = w.Write(dynamic.Render())
}

func (api *API) populateDynamicMetrics(registry *prommetrics.Registry) {
	if registry == nil {
		return
	}
	if api == nil {
		return
	}
	now := time.Now()
	if api.app != nil {
		cleanup := api.app.CleanupMetricsSnapshot()
		registry.SetCounter("ole_server_cleanup_cycles_total", "Cleanup cycles completed by result.", map[string]string{"result": "success"}, float64(cleanup.SuccessCount))
		registry.SetCounter("ole_server_cleanup_cycles_total", "Cleanup cycles completed by result.", map[string]string{"result": "error"}, float64(cleanup.FailureCount))
		registry.SetGauge("ole_server_cleanup_last_run_unix", "Unix timestamp of the last cleanup cycle.", nil, float64(cleanup.LastCleanupUnix))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		readiness := api.app.ReadinessSnapshot(ctx)
		cancel()
		registry.SetGauge("ole_server_db_ready", "Whether the configured server database is currently reachable.", nil, boolGauge(readiness.Ready))
		if api.app.DB != nil {
			stats := api.app.DB.Stats()
			registry.SetGauge("ole_server_db_open_connections", "Current number of opened database connections.", nil, float64(stats.OpenConnections))
			registry.SetGauge("ole_server_db_in_use_connections", "Current number of in-use database connections.", nil, float64(stats.InUse))
			registry.SetGauge("ole_server_db_idle_connections", "Current number of idle database connections.", nil, float64(stats.Idle))
			registry.SetGauge("ole_server_db_max_open_connections", "Configured maximum number of open database connections.", nil, float64(stats.MaxOpenConnections))
			registry.SetCounter("ole_server_db_wait_count_total", "Total database connection waits.", nil, float64(stats.WaitCount))
			registry.SetCounter("ole_server_db_wait_duration_seconds_total", "Total time spent waiting for database connections.", nil, stats.WaitDuration.Seconds())
		}
		api.populateControlPlaneMetrics(registry, now.Unix())
	}
	if api.authLimiter != nil {
		snapshot, err := api.authLimiter.Snapshot(context.Background(), now)
		if err == nil {
			registry.SetGauge("ole_server_auth_rate_limit_tracked_keys", "Tracked auth rate-limit keys.", nil, float64(snapshot.TrackedKeys))
			registry.SetGauge("ole_server_auth_rate_limit_blocked_keys", "Blocked auth rate-limit keys.", nil, float64(snapshot.BlockedKeys))
			registry.SetGauge("ole_server_auth_rate_limit_keys", "Tracked auth rate-limit keys grouped by attempt type.", map[string]string{"attempt_type": "login"}, float64(snapshot.LoginKeys))
			registry.SetGauge("ole_server_auth_rate_limit_keys", "Tracked auth rate-limit keys grouped by attempt type.", map[string]string{"attempt_type": "refresh"}, float64(snapshot.RefreshKeys))
			registry.SetGauge("ole_server_auth_rate_limit_max_failures", "Maximum failure count across tracked auth rate-limit keys.", nil, float64(snapshot.MaxFailures))
			registry.SetGauge("ole_server_auth_rate_limit_last_update_unix", "Unix timestamp of the most recently updated auth rate-limit key.", nil, float64(snapshot.LastUpdatedAtUnix))
		}
	}
	if api.authAbuse != nil {
		snapshot, err := api.authAbuse.Snapshot(context.Background(), now)
		if err == nil {
			registry.SetGauge("ole_server_auth_abuse_active_alerts", "Active auth abuse alerts.", nil, float64(snapshot.ActiveAlerts))
			registry.SetGauge("ole_server_auth_abuse_blocked_keys", "Blocked auth abuse keys.", nil, float64(snapshot.BlockedKeys))
			registry.SetCounter("ole_server_auth_abuse_total_alert_events", "Total auth abuse alert events.", nil, float64(snapshot.TotalAlertEvents))
			registry.SetCounter("ole_server_auth_abuse_total_denied_requests", "Total denied auth abuse requests.", nil, float64(snapshot.TotalDeniedRequests))
		}
	}
	if api.relayStatus != nil {
		snapshot := api.relayStatus.Snapshot()
		registry.SetGauge("ole_server_relay_active_bindings", "Active relay bindings.", nil, float64(snapshot.ActiveBindings))
		registry.SetCounter("ole_server_relay_forwarded_packets_total", "Total relay forwarded packets.", nil, float64(snapshot.ForwardedPackets))
		registry.SetCounter("ole_server_relay_forwarded_bytes_total", "Total relay forwarded bytes.", nil, float64(snapshot.ForwardedBytes))
		registry.SetCounter("ole_server_relay_bind_denials_total", "Total relay bind denials.", nil, float64(snapshot.BindDenials))
		registry.SetCounter("ole_server_relay_send_denials_total", "Total relay send denials.", nil, float64(snapshot.SendDenials))
		registry.SetCounter("ole_server_relay_quota_denials_total", "Total relay quota denials.", nil, float64(snapshot.QuotaDenials))
		registry.SetCounter("ole_server_relay_abuse_alerts_total", "Total relay abuse alerts.", nil, float64(snapshot.AbuseAlerts))
		registry.SetGauge("ole_server_relay_abuse_blocked_sources", "Currently blocked relay abuse sources.", nil, float64(snapshot.AbuseBlockedSources))
	}
}

func (api *API) populateControlPlaneMetrics(registry *prommetrics.Registry, nowUnix int64) {
	if registry == nil || api == nil || api.app == nil || api.app.NetworkRepo == nil {
		return
	}
	networks, err := api.app.NetworkRepo.List()
	if err != nil {
		return
	}
	registry.SetGauge("ole_server_networks_total", "Total overlay networks known to the control plane.", nil, float64(len(networks)))

	totalMembers := 0
	peerCounts := map[string]float64{}
	candidateCounts := map[string]float64{}
	tunnelCounts := map[string]float64{}

	for _, network := range networks {
		if network == nil {
			continue
		}
		totalMembers += len(network.Members)
		if api.app.PeerRepo != nil {
			peers, err := api.app.PeerRepo.ListByNetwork(network.ID)
			if err == nil {
				for _, peer := range peers {
					if peer == nil {
						continue
					}
					peerKey := strings.ToLower(strings.TrimSpace(firstNonEmptyMetricValue(string(peer.Status), "UNKNOWN"))) +
						"|" + strings.ToLower(strings.TrimSpace(firstNonEmptyMetricValue(string(peer.Reachability), "UNKNOWN"))) +
						"|" + strings.ToLower(strings.TrimSpace(firstNonEmptyMetricValue(string(peer.ConnectionState), "IDLE")))
					peerCounts[peerKey]++
					if api.app.SignalCandidateRepo != nil {
						candidates, err := api.app.SignalCandidateRepo.ListByPeerID(peer.ID)
						if err == nil {
							for _, candidate := range candidates {
								if candidate == nil || candidate.IsExpired(nowUnix) {
									continue
								}
								candidateKey := strings.ToLower(strings.TrimSpace(firstNonEmptyMetricValue(string(candidate.Type), "unknown"))) +
									"|" + strings.ToLower(strings.TrimSpace(firstNonEmptyMetricValue(string(candidate.Protocol), "unknown"))) +
									"|" + boolLabel(candidate.Reachable)
								candidateCounts[candidateKey]++
							}
						}
					}
				}
			}
		}
		if api.app.TunnelRepo != nil {
			tunnels, err := api.app.TunnelRepo.ListByNetwork(network.ID)
			if err == nil {
				for _, tunnel := range tunnels {
					if tunnel == nil {
						continue
					}
					tunnelKey := strings.ToLower(strings.TrimSpace(firstNonEmptyMetricValue(string(tunnel.Mode), "unknown"))) +
						"|" + strings.ToLower(strings.TrimSpace(firstNonEmptyMetricValue(string(tunnel.State), "unknown")))
					tunnelCounts[tunnelKey]++
				}
			}
		}
	}

	registry.SetGauge("ole_server_network_members_total", "Total overlay-network memberships.", nil, float64(totalMembers))
	for key, count := range peerCounts {
		parts := strings.Split(key, "|")
		registry.SetGauge("ole_server_signaling_peers_total", "Peers grouped by current signaling state.", map[string]string{
			"status":           parts[0],
			"reachability":     parts[1],
			"connection_state": parts[2],
		}, count)
	}
	for key, count := range candidateCounts {
		parts := strings.Split(key, "|")
		registry.SetGauge("ole_server_signal_candidates_total", "Active signaling candidates grouped by type, protocol, and reachability.", map[string]string{
			"type":      parts[0],
			"protocol":  parts[1],
			"reachable": parts[2],
		}, count)
	}
	for key, count := range tunnelCounts {
		parts := strings.Split(key, "|")
		registry.SetGauge("ole_server_tunnels_total", "Tunnels grouped by mode and state.", map[string]string{
			"mode":  parts[0],
			"state": parts[1],
		}, count)
	}
}

func normalizeMetricsPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" || trimmed == "/" {
		return "/"
	}
	segments := strings.Split(strings.Trim(trimmed, "/"), "/")
	literals := map[string]struct{}{
		"api": {}, "v1": {}, "users": {}, "devices": {}, "sessions": {}, "session": {}, "networks": {}, "members": {},
		"invites": {}, "messages": {}, "peers": {}, "file-transfers": {}, "tunnels": {}, "audit-events": {}, "audit-presets": {}, "status": {}, "config": {},
		"adapter": {}, "mtu": {}, "login": {}, "reconnect": {}, "all": {}, "swagger": {}, "health": {}, "metrics": {},
		"name-resolution": {}, "routing-policy": {}, "group-traffic-policy": {}, "device-approvals": {},
	}
	for idx, segment := range segments {
		if _, ok := literals[segment]; ok {
			continue
		}
		if looksDynamicSegment(segment) {
			segments[idx] = ":id"
		}
	}
	return "/" + strings.Join(segments, "/")
}

func boolGauge(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func boolLabel(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func firstNonEmptyMetricValue(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value != "" {
		return value
	}
	return fallback
}

func looksDynamicSegment(segment string) bool {
	if segment == "" {
		return false
	}
	if strings.Contains(segment, "-") {
		return true
	}
	if _, err := strconv.Atoi(segment); err == nil {
		return true
	}
	return false
}
