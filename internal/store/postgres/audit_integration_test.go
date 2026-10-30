package postgres_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/postgres"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPostgresAuditVisibilityFiltersBeforeLimit(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()
	users := postgres.NewUserRepo(db)
	owner := domain.UserID{Value: "owner"}
	other := domain.UserID{Value: "other"}
	for _, id := range []domain.UserID{owner, other} {
		if err := users.Create(&domain.User{ID: id, Email: id.String() + "@example.com", PasswordHash: "hash", Status: domain.UserStatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	audit := postgres.NewAuditRepo(db)
	for _, event := range []*domain.AuditEvent{
		{ID: "personal", ActorUserID: owner, Type: "device.enrolled", Details: "own", CreatedAtUnix: 1},
		{ID: "permitted-network", ActorUserID: other, NetworkID: domain.NetworkID{Value: "net-allowed"}, Type: "peer.registered", CreatedAtUnix: 2},
		{ID: "forbidden-network", ActorUserID: owner, NetworkID: domain.NetworkID{Value: "net-forbidden"}, Type: "peer.registered", CreatedAtUnix: 3},
		{ID: "foreign-personal", ActorUserID: other, Type: "device.enrolled", CreatedAtUnix: 4},
	} {
		if err := audit.Append(event); err != nil {
			t.Fatal(err)
		}
	}
	events, err := audit.ListVisible(owner, nil, 1)
	if err != nil || len(events) != 1 || events[0].ID != "personal" {
		t.Fatalf("personal scope/limit: %#v, %v", events, err)
	}
	events, err = audit.ListVisible(owner, []domain.NetworkID{{Value: "net-allowed"}}, 10)
	if err != nil || len(events) != 2 || events[0].ID != "permitted-network" || events[1].ID != "personal" {
		t.Fatalf("network scope: %#v, %v", events, err)
	}
}

func TestPostgresInvitationAuditMigrationRevokesOnlyExposedCodes(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()
	owner := domain.UserID{Value: "owner"}
	if err := postgres.NewUserRepo(db).Create(&domain.User{ID: owner, Email: "owner@example.com", PasswordHash: "hash", Status: domain.UserStatusActive}); err != nil {
		t.Fatal(err)
	}
	networks := domain.NewNetworkService(postgres.NewNetworkRepo(db), postgres.NewInviteRepo(db), nil)
	network, err := networks.CreateNetwork(owner, "private", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatal(err)
	}
	invites := postgres.NewInviteRepo(db)
	for _, code := range []string{"inv-scoped", "inv-unscoped", "inv-safe"} {
		if err := invites.Save(&domain.Invite{Code: code, NetworkID: network.ID, ExpiresAtUnix: 4000000000, MaxUses: 1}); err != nil {
			t.Fatal(err)
		}
	}
	audit := postgres.NewAuditRepo(db)
	for _, event := range []*domain.AuditEvent{
		{ID: "scoped", ActorUserID: owner, NetworkID: network.ID, Type: "network.invite_generated", Details: "inv-scoped"},
		{ID: "unscoped", ActorUserID: owner, Type: "network.invite_generated", Details: "inv-unscoped"},
		{ID: "safe", ActorUserID: owner, NetworkID: network.ID, Type: "network.invite_generated", Details: "invitation created"},
		{ID: "other-event", ActorUserID: owner, Type: "device.enrolled", Details: "unchanged"},
	} {
		if err := audit.Append(event); err != nil {
			t.Fatal(err)
		}
	}
	script, err := os.ReadFile(filepath.Join(migrationsDir(t), "018_redact_invitation_audit_secrets.sql"))
	if err != nil {
		t.Fatal(err)
	}
	// The migration runner applies the script in one transaction; also check idempotence.
	for range 2 {
		tx, err := db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(string(script)); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	for _, code := range []string{"inv-scoped", "inv-unscoped"} {
		invite, err := invites.FindByCode(code)
		if err != nil || invite != nil {
			t.Fatalf("exposed invite survived: %s, %v", code, err)
		}
	}
	safe, err := invites.FindByCode("inv-safe")
	if err != nil || safe == nil {
		t.Fatalf("safe invitation lost: %#v, %v", safe, err)
	}
	if err := safe.UseOnce(100); err != nil {
		t.Fatal(err)
	}
	events, err := audit.ListRecent(10)
	if err != nil || len(events) != 4 {
		t.Fatalf("history lost: %d events, %v", len(events), err)
	}
	for _, event := range events {
		if event.Type == "network.invite_generated" && event.Details != "invitation created" {
			t.Fatal("secret survived migration")
		}
		if event.ID == "other-event" && event.Details != "unchanged" {
			t.Fatal("unrelated history changed")
		}
	}
}
