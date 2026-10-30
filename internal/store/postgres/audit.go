package postgres

import (
	"Ole/internal/domain"
	"context"
	"database/sql"
)

func (r *AuditRepo) ListVisible(userID domain.UserID, networkIDs []domain.NetworkID, limit int) ([]*domain.AuditEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	allowed := make([]string, 0, len(networkIDs))
	for _, id := range networkIDs {
		if id.String() != "" {
			allowed = append(allowed, id.String())
		}
	}
	rows, err := r.db.QueryContext(context.Background(), `
		SELECT id, actor_user_id, network_id, type, details, created_at_unix
		FROM audit_events
		WHERE (COALESCE(network_id, '') = '' AND actor_user_id = $1)
		   OR network_id = ANY($2::text[])
		ORDER BY created_at_unix DESC, id DESC
		LIMIT $3
	`, userID.String(), allowed, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]*domain.AuditEvent, 0)
	for rows.Next() {
		var event domain.AuditEvent
		var actor string
		var network sql.NullString
		if err := rows.Scan(&event.ID, &actor, &network, &event.Type, &event.Details, &event.CreatedAtUnix); err != nil {
			return nil, err
		}
		event.ActorUserID = domain.UserID{Value: actor}
		if network.Valid {
			event.NetworkID = domain.NetworkID{Value: network.String}
		}
		result = append(result, &event)
	}
	return result, rows.Err()
}
