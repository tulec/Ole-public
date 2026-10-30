package memory_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/memory"
	"errors"
	"testing"
)

func TestSessionRotationCollisionIsAtomicAndSecurityStateIsMonotonic(t *testing.T) {
	repo := memory.NewSessionRepo()
	old := &domain.SessionToken{ID: "old", UserID: domain.UserID{Value: "owner"}, FamilyID: "family", AccessToken: "acc-old", RefreshToken: "ref-old", ExpiresAtUnix: 200, LastUsedAtUnix: 100}
	collision := &domain.SessionToken{ID: "other", UserID: old.UserID, FamilyID: "other-family", AccessToken: "acc-taken", RefreshToken: "ref-taken", ExpiresAtUnix: 200}
	if err := repo.Create(old); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(collision); err != nil {
		t.Fatal(err)
	}
	next := *old
	next.ID, next.AccessToken, next.RefreshToken = "next", collision.AccessToken, "ref-next"
	if err := repo.Rotate(old.RefreshToken, &next, 101); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("expected collision: %v", err)
	}
	stored, err := repo.FindByRefreshToken(old.RefreshToken)
	if err != nil || stored == nil || *stored != *old {
		t.Fatal("failed rotation changed old session")
	}
	next.AccessToken = "acc-next"
	if err := repo.Rotate(old.RefreshToken, &next, 101); err != nil {
		t.Fatal(err)
	}
	stale := *old
	stale.LastUsedAtUnix = 150
	if err := repo.Update(&stale); err != nil {
		t.Fatal(err)
	}
	listed, _, err := repo.ListByUserID(old.UserID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range listed {
		if session.FamilyID == old.FamilyID && session.ID != next.ID {
			t.Fatal("late touch displaced family's current session")
		}
	}
	if err := repo.Update(old); err != nil {
		t.Fatal(err)
	}
	stored, err = repo.FindByRefreshToken(old.RefreshToken)
	if err != nil || stored.ReplacedByToken != next.RefreshToken || stored.RevokedAtUnix != 101 {
		t.Fatal("stale update erased rotation marker")
	}
	if active, err := repo.TouchLastUsed(old.AccessToken, 102); err != nil || active {
		t.Fatal("rotated session accepted touch")
	}
	if err := repo.RevokeFamily(old.UserID, old.FamilyID, 102, true); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(&next); err != nil {
		t.Fatal(err)
	}
	stored, err = repo.FindByAccessToken(next.AccessToken)
	if err != nil || !stored.IsRevoked() || !stored.IsReused() {
		t.Fatal("stale update resurrected reused family")
	}
}

func TestSessionCreateNeverOverwritesExistingTokens(t *testing.T) {
	repo := memory.NewSessionRepo()
	original := &domain.SessionToken{ID: "first", UserID: domain.UserID{Value: "owner"}, FamilyID: "family", AccessToken: "access", RefreshToken: "refresh", ExpiresAtUnix: 200}
	if err := repo.Create(original); err != nil {
		t.Fatal(err)
	}
	for _, duplicate := range []*domain.SessionToken{
		{ID: "second", AccessToken: "access", RefreshToken: "other-refresh"},
		{ID: "third", AccessToken: "other-access", RefreshToken: "refresh"},
	} {
		if err := repo.Create(duplicate); !errors.Is(err, domain.ErrAlreadyExists) {
			t.Fatal("duplicate token was accepted")
		}
		stored, err := repo.FindByAccessToken(original.AccessToken)
		if err != nil || stored == nil || *stored != *original {
			t.Fatal("duplicate create overwrote a session")
		}
	}
}
