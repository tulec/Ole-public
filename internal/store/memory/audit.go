package memory

import "Ole/internal/domain"

func (r *AuditRepo) ListVisible(userID domain.UserID, networkIDs []domain.NetworkID, limit int) ([]*domain.AuditEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 {
		limit = 50
	}
	allowed := make(map[domain.NetworkID]bool, len(networkIDs))
	for _, id := range networkIDs {
		if id.String() != "" {
			allowed[id] = true
		}
	}
	result := make([]*domain.AuditEvent, 0)
	for i := len(r.events) - 1; i >= 0 && len(result) < limit; i-- {
		event := r.events[i]
		if event.NetworkID.String() == "" {
			if event.ActorUserID != userID {
				continue
			}
		} else if !allowed[event.NetworkID] {
			continue
		}
		clone := *event
		result = append(result, &clone)
	}
	return result, nil
}
