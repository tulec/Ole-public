package httpapi

import (
	"Ole/internal/domain"
	"Ole/internal/relay"
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (api *API) listIncidentReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	incidents := api.buildIncidentReports(r.Context(), currentUserID(r), time.Now())
	writeJSON(w, http.StatusOK, listEnvelope[incidentReportResponse]{
		Data: incidents,
		Meta: responseMeta{Count: len(incidents), Total: len(incidents)},
	})
}

func (api *API) buildIncidentReports(ctx context.Context, userID domain.UserID, now time.Time) []incidentReportResponse {
	incidents := []incidentReportResponse{}
	if api == nil {
		return incidents
	}

	if api.app != nil {
		readiness := api.app.ReadinessSnapshot(ctx)
		if !readiness.Ready {
			incidents = append(incidents, incidentReportResponse{
				ID:                "server-readiness",
				Category:          "READINESS",
				Severity:          "critical",
				Status:            "ACTIVE",
				Source:            "server.readiness",
				Summary:           "The server is not ready to serve normal traffic.",
				Detail:            firstNonEmptyIncident(strings.TrimSpace(readiness.Error), "database connectivity check is failing"),
				RecommendedAction: "Restore database reachability and re-check `/readyz` before accepting new admin or control-plane traffic.",
				EventCount:        1,
				DetectedAtUnix:    now.Unix(),
				UpdatedAtUnix:     now.Unix(),
			})
		}
	}

	if api.authAbuse != nil {
		if snapshot, err := api.authAbuse.Snapshot(ctx, now); err == nil && (snapshot.ActiveAlerts > 0 || snapshot.BlockedKeys > 0) {
			incidents = append(incidents, incidentReportResponse{
				ID:                "auth-abuse",
				Category:          "AUTH_ABUSE",
				Severity:          authIncidentSeverity(snapshot),
				Status:            "ACTIVE",
				Source:            "server.auth_abuse",
				Summary:           "Authentication abuse alerts are active.",
				Detail:            formatAuthIncidentDetail(snapshot),
				RecommendedAction: "Review recent failed sign-in traffic, confirm whether the blocked source is expected, and keep the block in place until the source is understood.",
				EventCount:        firstPositive(snapshot.ActiveAlerts, snapshot.TotalAlertEvents),
				DetectedAtUnix:    snapshot.LastAlertedAtUnix,
				UpdatedAtUnix:     snapshot.LastAlertedAtUnix,
			})
		}
	}

	if api.relayStatus != nil {
		snapshot := api.relayStatus.Snapshot()
		if snapshot.AbuseAlerts > 0 || snapshot.AbuseBlockedSources > 0 {
			updatedAt := int64(0)
			for _, source := range snapshot.Sources {
				if source.LastDetectedAtUnix > updatedAt {
					updatedAt = source.LastDetectedAtUnix
				}
			}
			incidents = append(incidents, incidentReportResponse{
				ID:                "relay-abuse",
				Category:          "RELAY_ABUSE",
				Severity:          relayIncidentSeverity(snapshot),
				Status:            "ACTIVE",
				Source:            "server.relay",
				Summary:           "Relay abuse protection is actively blocking or throttling sources.",
				Detail:            formatRelayIncidentDetail(snapshot),
				RecommendedAction: "Inspect recent relay abuse sources, verify whether any blocked source should remain denied, and review malformed or unauthorized relay traffic before lifting blocks.",
				EventCount:        firstPositive(snapshot.AbuseBlockedSources, snapshot.AbuseAlerts),
				DetectedAtUnix:    updatedAt,
				UpdatedAtUnix:     updatedAt,
			})
		}
	}
	if api.app != nil && api.app.AuditRepo != nil && userID.String() != "" {
		events, err := api.app.AuditRepo.ListRecent(1000)
		if err == nil {
			if incident, ok := buildSessionReuseIncident(userID, events); ok {
				incidents = append(incidents, incident)
			}
		}
	}

	sort.SliceStable(incidents, func(i, j int) bool {
		left := incidentSeverityRank(incidents[i].Severity)
		right := incidentSeverityRank(incidents[j].Severity)
		if left != right {
			return left > right
		}
		if incidents[i].UpdatedAtUnix != incidents[j].UpdatedAtUnix {
			return incidents[i].UpdatedAtUnix > incidents[j].UpdatedAtUnix
		}
		return incidents[i].ID < incidents[j].ID
	})
	return incidents
}

func buildSessionReuseIncident(userID domain.UserID, events []*domain.AuditEvent) (incidentReportResponse, bool) {
	affected := 0
	latestDetectedAt := int64(0)
	latestFamilyID := ""
	for _, event := range events {
		if event == nil || event.ActorUserID != userID || !strings.EqualFold(strings.TrimSpace(event.Type), "session.reuse_detected") {
			continue
		}
		affected++
		if event.CreatedAtUnix >= latestDetectedAt {
			latestDetectedAt = event.CreatedAtUnix
			latestFamilyID = strings.TrimSpace(event.Details)
		}
	}
	if affected == 0 {
		return incidentReportResponse{}, false
	}
	return incidentReportResponse{
		ID:                "session-token-reuse",
		Category:          "TOKEN_REUSE",
		Severity:          sessionReuseIncidentSeverity(affected),
		Status:            "ACTIVE",
		Source:            "account.audit",
		Summary:           "One or more session families were revoked after suspicious refresh-token reuse.",
		Detail:            formatSessionReuseIncidentDetail(affected, latestFamilyID),
		RecommendedAction: "Use `Revoke All Sessions`, sign in again, and review the trusted-device list if you do not recognize the affected device.",
		EventCount:        affected,
		DetectedAtUnix:    latestDetectedAt,
		UpdatedAtUnix:     latestDetectedAt,
	}, true
}

func authIncidentSeverity(snapshot authAbuseSnapshot) string {
	switch strings.ToLower(strings.TrimSpace(snapshot.LastSeverity)) {
	case "critical":
		return "critical"
	case "elevated":
		return "elevated"
	case "warning":
		return "warning"
	default:
		if snapshot.BlockedKeys > 0 {
			return "elevated"
		}
		return "warning"
	}
}

func sessionReuseIncidentSeverity(affected int) string {
	if affected > 1 {
		return "critical"
	}
	return "elevated"
}

func relayIncidentSeverity(snapshot relay.StatusSnapshot) string {
	if snapshot.AbuseBlockedSources > 0 {
		return "critical"
	}
	if snapshot.AbuseAlerts > 0 {
		return "elevated"
	}
	return "warning"
}

func formatAuthIncidentDetail(snapshot authAbuseSnapshot) string {
	parts := []string{}
	if snapshot.LoginAlerts > 0 {
		parts = append(parts, strconv.Itoa(snapshot.LoginAlerts)+" login alert(s)")
	}
	if snapshot.RefreshAlerts > 0 {
		parts = append(parts, strconv.Itoa(snapshot.RefreshAlerts)+" refresh alert(s)")
	}
	if snapshot.BlockedKeys > 0 {
		parts = append(parts, strconv.Itoa(snapshot.BlockedKeys)+" blocked key(s)")
	}
	if snapshot.TotalDeniedRequests > 0 {
		parts = append(parts, strconv.Itoa(snapshot.TotalDeniedRequests)+" denied request(s)")
	}
	if strings.TrimSpace(snapshot.LastSeverity) != "" {
		parts = append(parts, "last severity "+strings.ToLower(strings.TrimSpace(snapshot.LastSeverity)))
	}
	if len(parts) == 0 {
		return "Authentication abuse monitoring reported an active incident."
	}
	return strings.Join(parts, ", ")
}

func formatSessionReuseIncidentDetail(affected int, latestFamilyID string) string {
	parts := []string{strconv.Itoa(affected) + " affected session family(s)"}
	if strings.TrimSpace(latestFamilyID) != "" {
		parts = append(parts, "latest family "+strings.TrimSpace(latestFamilyID))
	}
	return strings.Join(parts, ", ")
}

func formatRelayIncidentDetail(snapshot relay.StatusSnapshot) string {
	parts := []string{}
	if snapshot.AbuseBlockedSources > 0 {
		parts = append(parts, strconv.Itoa(snapshot.AbuseBlockedSources)+" blocked source(s)")
	}
	if snapshot.AbuseAlerts > 0 {
		parts = append(parts, strconv.Itoa(snapshot.AbuseAlerts)+" abuse alert(s)")
	}
	if snapshot.AbuseDenials > 0 {
		parts = append(parts, strconv.Itoa(snapshot.AbuseDenials)+" denied relay request(s)")
	}
	if snapshot.MalformedPackets > 0 {
		parts = append(parts, strconv.Itoa(snapshot.MalformedPackets)+" malformed packet(s)")
	}
	if snapshot.QuotaDenials > 0 {
		parts = append(parts, strconv.Itoa(snapshot.QuotaDenials)+" quota denial(s)")
	}
	if len(parts) == 0 {
		return "Relay abuse protection reported an active incident."
	}
	return strings.Join(parts, ", ")
}

func incidentSeverityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 3
	case "elevated":
		return 2
	case "warning":
		return 1
	default:
		return 0
	}
}

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func firstNonEmptyIncident(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
