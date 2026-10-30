package clientagent

import (
	"Ole/internal/prommetrics"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func renderPrometheusMetrics(agent *Agent, registry *prommetrics.Registry) []byte {
	output := make([]byte, 0, 4096)
	if registry != nil {
		output = append(output, registry.Render()...)
	}
	dynamic := prommetrics.NewRegistry()
	if agent != nil {
		status := agent.Status()
		dynamic.SetGauge("ole_agent_connected", "Whether the Ole agent currently has an active session.", nil, boolGauge(status.Connected))
		dynamic.SetGauge("ole_agent_persisted_session", "Whether the Ole agent has a persisted session.", nil, boolGauge(status.PersistedSession))
		dynamic.SetGauge("ole_agent_managed_peers", "Managed peer count held by the agent.", nil, float64(status.ManagedPeerCount))
		dynamic.SetGauge("ole_agent_discovered_peers", "Discovered peer count held by the agent.", nil, float64(status.DiscoveredPeerCount))
		dynamic.SetGauge("ole_agent_stun_configured", "Whether the Ole agent currently has a STUN server configured.", nil, boolGauge(strings.TrimSpace(status.STUNServerAddress) != ""))
		dynamic.SetGauge("ole_agent_last_stun_probe_unix", "Unix timestamp of the last NAT/STUN probe.", nil, float64(status.LastSTUNProbeUnix))
		dynamic.SetGauge("ole_agent_public_endpoint_known", "Whether the Ole agent currently knows its public endpoint.", nil, boolGauge(strings.TrimSpace(status.PublicEndpoint) != ""))
		dynamic.SetGauge("ole_agent_relay_pool_size", "Configured relay pool size for the Ole agent.", nil, float64(len(status.RelayServerAddresses)))
		dynamic.SetGauge("ole_agent_relay_active", "Whether the Ole agent currently has an active relay selected.", nil, boolGauge(strings.TrimSpace(status.ActiveRelayServer) != ""))
		dynamic.SetGauge("ole_agent_reconnect_backoff_active", "Whether reconnect backoff is active.", nil, boolGauge(status.ReconnectBackoffActive))
		dynamic.SetCounter("ole_agent_reconnect_attempts_total", "Total reconnect attempts in the current agent process.", nil, float64(status.ReconnectAttemptCount))
		dynamic.SetCounter("ole_agent_direct_attempts_total", "Total direct-connect attempts in the current agent process.", nil, float64(status.DirectMetrics.AttemptCount))
		dynamic.SetCounter("ole_agent_direct_successes_total", "Total successful direct-connect attempts.", nil, float64(status.DirectMetrics.SuccessCount))
		dynamic.SetCounter("ole_agent_direct_failures_total", "Total failed direct-connect attempts.", nil, float64(status.DirectMetrics.FailureCount))
		dynamic.SetCounter("ole_agent_relay_fallbacks_total", "Total relay fallbacks after direct failure.", nil, float64(status.DirectMetrics.RelayFallbackCount))
		if natType := strings.TrimSpace(status.NATType); natType != "" {
			dynamic.SetGauge("ole_agent_nat_type_state", "Current NAT type reported by the Ole agent.", map[string]string{"nat_type": strings.ToLower(natType)}, 1)
		}
		connectionStates := map[string]float64{}
		reachabilityStates := map[string]float64{}
		transportModes := map[string]float64{}
		for _, connection := range status.Connections {
			connectionStates[strings.ToLower(firstNonEmptyString(connection.State, "unknown"))]++
			reachabilityStates[strings.ToLower(firstNonEmptyString(connection.Reachability, "unknown"))]++
			transportModes[strings.ToLower(firstNonEmptyString(connection.TransportMode, "none"))]++
		}
		for state, count := range connectionStates {
			dynamic.SetGauge("ole_agent_connections", "Current agent connections grouped by state.", map[string]string{"state": state}, count)
		}
		for reachability, count := range reachabilityStates {
			dynamic.SetGauge("ole_agent_connection_reachability", "Current agent connections grouped by reachability.", map[string]string{"reachability": reachability}, count)
		}
		for mode, count := range transportModes {
			dynamic.SetGauge("ole_agent_connection_transport_mode", "Current agent connections grouped by transport mode.", map[string]string{"mode": mode}, count)
		}
	}
	output = append(output, dynamic.Render()...)
	return output
}

func instrumentHandlerMetrics(registry *prommetrics.Registry, next http.Handler) http.Handler {
	if registry == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &metricsStatusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(recorder, r)
		labels := map[string]string{
			"method": r.Method,
			"path":   normalizeAgentMetricsPath(r.URL.Path),
			"status": strconv.Itoa(recorder.statusCode),
		}
		registry.IncCounter("ole_agent_http_requests_total", "HTTP requests processed by the Ole agent.", labels, 1)
		registry.IncCounter("ole_agent_http_request_duration_seconds_total", "Total agent HTTP request duration in seconds.", labels, time.Since(start).Seconds())
	})
}

type metricsStatusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *metricsStatusRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func normalizeAgentMetricsPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" || trimmed == "/" {
		return "/"
	}
	segments := strings.Split(strings.Trim(trimmed, "/"), "/")
	literals := map[string]struct{}{
		"health": {}, "metrics": {}, "api": {}, "v1": {}, "status": {}, "diagnostics": {}, "bundle": {}, "config": {},
		"adapter": {}, "mtu": {}, "users": {}, "session": {}, "sessions": {}, "devices": {}, "audit-events": {}, "audit-presets": {},
		"networks": {}, "routing-policy": {}, "group-traffic-policy": {}, "name-resolution": {}, "device-approvals": {},
		"invites": {}, "peers": {}, "tunnels": {}, "login": {}, "reconnect": {},
	}
	for idx, segment := range segments {
		if _, ok := literals[segment]; ok {
			continue
		}
		if strings.Contains(segment, "-") || isNumeric(segment) {
			segments[idx] = ":id"
		}
	}
	return "/" + strings.Join(segments, "/")
}

func isNumeric(value string) bool {
	_, err := strconv.Atoi(value)
	return err == nil
}

func boolGauge(value bool) float64 {
	if value {
		return 1
	}
	return 0
}
