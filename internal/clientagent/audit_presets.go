package clientagent

import (
	"Ole/internal/controlclient"
	"sort"
	"strings"
)

type AuditFilterPreset struct {
	ServerBaseURL string `json:"serverBaseUrl"`
	UserID        string `json:"userId"`
	Name          string `json:"name"`
	ActorUserID   string `json:"actorUserId"`
	Type          string `json:"type"`
	Query         string `json:"query"`
	FromUnix      int64  `json:"fromUnix"`
	ToUnix        int64  `json:"toUnix"`
}

func normalizeAuditFilterPresets(presets []AuditFilterPreset) []AuditFilterPreset {
	if presets == nil {
		return []AuditFilterPreset{}
	}
	normalized := make([]AuditFilterPreset, 0, len(presets))
	for _, preset := range presets {
		preset.ServerBaseURL = strings.TrimSpace(preset.ServerBaseURL)
		preset.UserID = strings.TrimSpace(preset.UserID)
		preset.Name = strings.TrimSpace(preset.Name)
		preset.ActorUserID = strings.TrimSpace(preset.ActorUserID)
		preset.Type = strings.TrimSpace(preset.Type)
		preset.Query = strings.TrimSpace(preset.Query)
		if preset.FromUnix < 0 {
			preset.FromUnix = 0
		}
		if preset.ToUnix < 0 {
			preset.ToUnix = 0
		}
		if preset.Name == "" {
			continue
		}
		normalized = append(normalized, preset)
	}
	sort.SliceStable(normalized, func(i, j int) bool {
		left := strings.ToLower(normalized[i].Name)
		right := strings.ToLower(normalized[j].Name)
		if left == right {
			if normalized[i].ServerBaseURL == normalized[j].ServerBaseURL {
				return normalized[i].UserID < normalized[j].UserID
			}
			return normalized[i].ServerBaseURL < normalized[j].ServerBaseURL
		}
		return left < right
	})
	return normalized
}

func newAuditFilterPreset(serverBaseURL, userID, name string, filter controlclient.AuditEventFilter) AuditFilterPreset {
	return AuditFilterPreset{
		ServerBaseURL: strings.TrimSpace(serverBaseURL),
		UserID:        strings.TrimSpace(userID),
		Name:          strings.TrimSpace(name),
		ActorUserID:   strings.TrimSpace(filter.ActorUserID),
		Type:          strings.TrimSpace(filter.Type),
		Query:         strings.TrimSpace(filter.Query),
		FromUnix:      filter.FromUnix,
		ToUnix:        filter.ToUnix,
	}
}

func (p AuditFilterPreset) Filter() controlclient.AuditEventFilter {
	return controlclient.AuditEventFilter{
		ActorUserID: strings.TrimSpace(p.ActorUserID),
		Type:        strings.TrimSpace(p.Type),
		Query:       strings.TrimSpace(p.Query),
		FromUnix:    p.FromUnix,
		ToUnix:      p.ToUnix,
	}
}

func (s *PersistentState) AuditPresetsFor(serverBaseURL, userID string) []AuditFilterPreset {
	serverBaseURL = strings.TrimSpace(serverBaseURL)
	userID = strings.TrimSpace(userID)
	presets := make([]AuditFilterPreset, 0, len(s.AuditPresets))
	for _, preset := range s.AuditPresets {
		if preset.ServerBaseURL == serverBaseURL && preset.UserID == userID {
			presets = append(presets, preset)
		}
	}
	return normalizeAuditFilterPresets(presets)
}

func (s *PersistentState) SetAuditPreset(serverBaseURL, userID, name string, filter controlclient.AuditEventFilter) {
	next := newAuditFilterPreset(serverBaseURL, userID, name, filter)
	if next.Name == "" {
		return
	}
	for idx := range s.AuditPresets {
		preset := &s.AuditPresets[idx]
		if preset.ServerBaseURL == next.ServerBaseURL && preset.UserID == next.UserID && strings.EqualFold(preset.Name, next.Name) {
			*preset = next
			s.AuditPresets = normalizeAuditFilterPresets(s.AuditPresets)
			return
		}
	}
	s.AuditPresets = append(s.AuditPresets, next)
	s.AuditPresets = normalizeAuditFilterPresets(s.AuditPresets)
}

func (s *PersistentState) DeleteAuditPreset(serverBaseURL, userID, name string) bool {
	serverBaseURL = strings.TrimSpace(serverBaseURL)
	userID = strings.TrimSpace(userID)
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	filtered := s.AuditPresets[:0]
	removed := false
	for _, preset := range s.AuditPresets {
		if preset.ServerBaseURL == serverBaseURL && preset.UserID == userID && strings.EqualFold(preset.Name, name) {
			removed = true
			continue
		}
		filtered = append(filtered, preset)
	}
	s.AuditPresets = normalizeAuditFilterPresets(filtered)
	return removed
}
