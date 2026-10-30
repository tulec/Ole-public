package domain

// ListVisibleAuditEventsForUser combines personal events and authorized network audit.
// Authorship does not bypass a network's MODERATE permission.
func (s *NetworkService) ListVisibleAuditEventsForUser(userID UserID, limit int) ([]*AuditEvent, error) {
	if userID.String() == "" {
		return nil, ErrUnauthorized
	}
	if s.auditRepo == nil {
		return []*AuditEvent{}, nil
	}
	networks, err := s.networkRepo.List()
	if err != nil {
		return nil, err
	}
	allowed := make([]NetworkID, 0)
	for _, network := range networks {
		if network != nil && network.AuthorizeOperation(userID, NetworkOperationViewNetworkAudit) == nil {
			allowed = append(allowed, network.ID)
		}
	}
	events, err := s.auditRepo.ListVisible(userID, allowed, limit)
	if err != nil {
		return nil, err
	}
	return auditEventsForRead(events), nil
}

// Redact legacy invitation secrets before filtering/search, not just serialization.
// Copy events so reading never changes the repository's stored historical records.
func auditEventsForRead(events []*AuditEvent) []*AuditEvent {
	visible := make([]*AuditEvent, 0, len(events))
	for _, event := range events {
		if event == nil {
			continue
		}
		clone := *event
		if clone.Type == "network.invite_generated" {
			clone.Details = "invitation created"
		}
		visible = append(visible, &clone)
	}
	return visible
}
