package domain_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/memory"
	"errors"
	"testing"
)

func TestRevokeSessionWithoutRepositoryUsesHistory(t *testing.T) {
	auth := domain.NewAuthService(memory.NewUserRepo(), nil, nil, "test-secret", "ole-test")
	user, err := auth.Register("local-revoke@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	old, err := auth.Login(user.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := auth.Login(user.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	current, err := auth.Refresh(old.RefreshToken, domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.RevokeSession(domain.UserID{Value: "foreign-user"}, old.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("foreign ID: %v", err)
	}
	if err := auth.RevokeSession(user.ID, old.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.ValidateAccessToken(current.AccessToken); err == nil {
		t.Fatal("historical ID did not revoke current access")
	}
	if next, err := auth.Refresh(current.RefreshToken, domain.SessionMetadata{}); err == nil || next != nil {
		t.Fatal("historical ID did not revoke refresh")
	}
	if _, err := auth.ValidateAccessToken(other.AccessToken); err != nil {
		t.Fatal("independent family was revoked")
	}
	if err := auth.RevokeSession(user.ID, "missing-id"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown ID: %v", err)
	}
}

func TestRevokeSessionLegacyIDsRemainUserScopedAndUnambiguous(t *testing.T) {
	for _, scenario := range []string{"ambiguous-id", "shared-family-across-users", "shared-id-across-users", "duplicate-id-same-family", "empty-family"} {
		t.Run(scenario, func(t *testing.T) {
			repo := memory.NewSessionRepo()
			auth := domain.NewAuthService(memory.NewUserRepo(), nil, repo, "test-secret", "ole-test")
			owner := domain.UserID{Value: "owner"}
			a := &domain.SessionToken{ID: "legacy-id", UserID: owner, FamilyID: "family-a", AccessToken: "acc-a", RefreshToken: "ref-a", ExpiresAtUnix: 200}
			b := &domain.SessionToken{ID: "other-id", UserID: owner, FamilyID: "family-b", AccessToken: "acc-b", RefreshToken: "ref-b", ExpiresAtUnix: 200}
			wantNotFound, wantBRevoked := false, false
			switch scenario {
			case "ambiguous-id":
				b.ID, wantNotFound = a.ID, true
			case "shared-family-across-users":
				b.UserID, b.FamilyID = domain.UserID{Value: "foreign"}, a.FamilyID
			case "shared-id-across-users":
				b.UserID, b.ID = domain.UserID{Value: "foreign"}, a.ID
			case "duplicate-id-same-family":
				b.ID, b.FamilyID, wantBRevoked = a.ID, a.FamilyID, true
			case "empty-family":
				a.FamilyID, wantNotFound = "", true
			}
			for _, session := range []*domain.SessionToken{a, b} {
				if err := repo.Create(session); err != nil {
					t.Fatal(err)
				}
			}
			err := auth.RevokeSession(owner, a.ID)
			if wantNotFound {
				if !errors.Is(err, domain.ErrNotFound) {
					t.Errorf("ambiguous/empty family: %v, want not found", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			for i, original := range []*domain.SessionToken{a, b} {
				stored, err := repo.FindByAccessToken(original.AccessToken)
				wantRevoked := !wantNotFound && (i == 0 || wantBRevoked)
				if err != nil || stored == nil || stored.IsRevoked() != wantRevoked {
					t.Errorf("session %d: want revoked=%v, stored=%+v err=%v", i, wantRevoked, stored, err)
				}
			}
		})
	}
}

func TestFamilyRevocationDoesNotCrossLegacyUserBoundary(t *testing.T) {
	for _, operation := range []string{"logout", "refresh-reuse"} {
		t.Run(operation, func(t *testing.T) {
			repo := memory.NewSessionRepo()
			auth := domain.NewAuthService(memory.NewUserRepo(), nil, repo, "test-secret", "ole-test")
			user, err := auth.Register("legacy-owner@example.com", "secret")
			if err != nil {
				t.Fatal(err)
			}
			own, err := auth.Login(user.Email, "secret", domain.SessionMetadata{})
			if err != nil {
				t.Fatal(err)
			}
			foreign := &domain.SessionToken{ID: "foreign-id", UserID: domain.UserID{Value: "foreign"}, FamilyID: own.FamilyID, AccessToken: "foreign-access", RefreshToken: "foreign-refresh", ExpiresAtUnix: own.ExpiresAtUnix}
			if err := repo.Create(foreign); err != nil {
				t.Fatal(err)
			}
			if operation == "logout" {
				if err := auth.Logout(own.AccessToken); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := auth.Refresh(own.RefreshToken, domain.SessionMetadata{}); err != nil {
					t.Fatal(err)
				}
				if _, err := auth.Refresh(own.RefreshToken, domain.SessionMetadata{}); !errors.Is(err, domain.ErrUnauthorized) {
					t.Fatalf("reuse: %v", err)
				}
			}
			stored, err := repo.FindByAccessToken(foreign.AccessToken)
			if err != nil || stored == nil || stored.IsRevoked() || stored.IsReused() {
				t.Fatalf("foreign family changed: stored=%+v err=%v", stored, err)
			}
		})
	}
}
