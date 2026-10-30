package domain_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/memory"
	"errors"
	"testing"
)

type unavailableAuditNetworks struct{ *memory.NetworkRepo }

func (unavailableAuditNetworks) List() ([]*domain.Network, error) {
	return nil, errors.New("network storage unavailable")
}

func TestAuditVisibilityFailsClosedAndPreservesStoredSecretsForMigration(t *testing.T) {
	audit := memory.NewAuditRepo()
	owner := domain.UserID{Value: "usr-owner"}
	networks := memory.NewNetworkRepo()
	service := domain.NewNetworkService(networks, memory.NewInviteRepo(), audit)
	network, err := service.CreateNetwork(owner, "private", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatal(err)
	}
	legacy := &domain.AuditEvent{ID: "legacy", ActorUserID: owner, NetworkID: network.ID, Type: "network.invite_generated", Details: "inv-legacy"}
	if err := audit.Append(legacy); err != nil {
		t.Fatal(err)
	}
	for _, scoped := range []bool{false, true} {
		var events []*domain.AuditEvent
		if scoped {
			events, err = service.ListAuditEventsForUser(owner, network.ID, 100)
		} else {
			events, err = service.ListVisibleAuditEventsForUser(owner, 100)
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			if event.ID == legacy.ID && event.Details != "invitation created" {
				t.Fatal("legacy secret not redacted")
			}
		}
	}
	stored, err := audit.ListByNetworkID(network.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if stored[0].Details != legacy.Details {
		t.Fatal("reading altered stored audit records before migration")
	}
	broken := domain.NewNetworkService(unavailableAuditNetworks{networks}, memory.NewInviteRepo(), audit)
	if events, err := broken.ListVisibleAuditEventsForUser(owner, 100); err == nil || len(events) != 0 {
		t.Fatal("storage failure returned audit events")
	}
	if events, err := service.ListVisibleAuditEventsForUser(domain.UserID{}, 100); !errors.Is(err, domain.ErrUnauthorized) || len(events) != 0 {
		t.Fatal("empty actor returned audit events")
	}
}
