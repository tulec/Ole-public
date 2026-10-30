package postgres_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/postgres"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestPostgresRevokeSessionHistoricalIDWithoutPageLimit(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()
	repo := postgres.NewSessionRepo(db)
	auth := domain.NewAuthService(postgres.NewUserRepo(db), nil, repo, "test-secret", "ole-test")
	user, err := auth.Register("postgres-revoke-id@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	login := func() *domain.SessionToken {
		t.Helper()
		session, err := auth.Login(user.Email, "secret", domain.SessionMetadata{})
		if err != nil {
			t.Fatal(err)
		}
		return session
	}
	old, independent := login(), login()
	current, err := auth.Refresh(old.RefreshToken, domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.RevokeSession(user.ID, old.ID); err != nil {
		t.Fatalf("historical ID: %v", err)
	}
	if _, err := auth.ValidateAccessToken(current.AccessToken); err == nil {
		t.Fatal("historical ID did not revoke current access")
	}
	if next, err := auth.Refresh(current.RefreshToken, domain.SessionMetadata{}); err == nil || next != nil {
		t.Fatal("historical ID did not revoke refresh")
	}
	// Pagination needs stored sessions, not 1001 repetitions of password KDF.
	for i := range 1001 {
		fixture := *independent
		fixture.ID, fixture.FamilyID, fixture.RefreshToken = fmt.Sprintf("bulk-id-%d", i), fmt.Sprintf("bulk-family-%04d", i), fmt.Sprintf("bulk-refresh-%d", i)
		fixture.AccessToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": user.ID.String(), "iss": "ole-test", "exp": fixture.ExpiresAtUnix, "jti": fixture.ID}).SignedString([]byte("test-secret"))
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.Create(&fixture); err != nil {
			t.Fatal(err)
		}
	}
	outside, total, err := repo.ListByUserID(user.ID, 1, 1000)
	if err != nil || total != 1003 || len(outside) != 1 {
		t.Fatalf("fixture: total=%d outside=%d err=%v", total, len(outside), err)
	}
	// Choose an active family outside page 1, excluding the independent login.
	if outside[0].IsRevoked() || outside[0].ID == independent.ID {
		outside, _, err = repo.ListByUserID(user.ID, 3, 1000)
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range outside {
			if !candidate.IsRevoked() && candidate.ID != independent.ID {
				outside = []*domain.SessionToken{candidate}
				break
			}
		}
	}
	target := outside[0]
	if target.IsRevoked() || target.ID == independent.ID {
		t.Fatal("no active target outside first 1000 families")
	}
	if err := auth.RevokeSession(user.ID, target.ID); err != nil {
		t.Fatalf("outside page: %v", err)
	}
	if _, err := auth.ValidateAccessToken(target.AccessToken); err == nil {
		t.Fatal("outside-page access remains active")
	}
	if next, err := auth.Refresh(target.RefreshToken, domain.SessionMetadata{}); err == nil || next != nil {
		t.Fatal("outside-page refresh remains active")
	}
	if _, err := auth.ValidateAccessToken(independent.AccessToken); err != nil {
		t.Fatal("independent family was revoked")
	}
}

func TestPostgresRevokeSessionLegacyScopeAndAmbiguity(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()
	repo := postgres.NewSessionRepo(db)
	auth := domain.NewAuthService(postgres.NewUserRepo(db), nil, repo, "test-secret", "ole-test")
	owner, err := auth.Register("legacy-owner@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := auth.Register("legacy-foreign@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"ambiguous-id", "shared-family-across-users", "shared-id-across-users", "duplicate-id-same-family", "empty-family", "logout-family", "reuse-family"} {
		t.Run(scenario, func(t *testing.T) {
			a := &domain.SessionToken{ID: scenario, UserID: owner.ID, FamilyID: scenario + "-a", AccessToken: scenario + "-acc-a", RefreshToken: scenario + "-ref-a", ExpiresAtUnix: time.Now().Unix() + 3600}
			b := &domain.SessionToken{ID: scenario + "-other", UserID: owner.ID, FamilyID: scenario + "-b", AccessToken: scenario + "-acc-b", RefreshToken: scenario + "-ref-b", ExpiresAtUnix: a.ExpiresAtUnix}
			wantNotFound, wantBRevoked := false, false
			switch scenario {
			case "ambiguous-id":
				b.ID, wantNotFound = a.ID, true
			case "shared-family-across-users", "logout-family", "reuse-family":
				b.UserID, b.FamilyID = foreign.ID, a.FamilyID
			case "shared-id-across-users":
				b.UserID, b.ID = foreign.ID, a.ID
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
			if b.UserID == foreign.ID && b.ID != a.ID {
				if err := auth.RevokeSession(owner.ID, b.ID); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("foreign ID: %v", err)
				}
			}
			if err := auth.RevokeSession(owner.ID, "missing-id"); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("unknown ID: %v", err)
			}
			var err error
			if scenario == "logout-family" || scenario == "reuse-family" {
				err = repo.RevokeFamily(owner.ID, a.FamilyID, time.Now().Unix(), scenario == "reuse-family")
			} else {
				err = auth.RevokeSession(owner.ID, a.ID)
			}
			if wantNotFound {
				if !errors.Is(err, domain.ErrNotFound) {
					t.Errorf("ambiguous/empty: %v, want not found", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			for i, original := range []*domain.SessionToken{a, b} {
				stored, err := repo.FindByAccessToken(original.AccessToken)
				wantRevoked := !wantNotFound && (i == 0 || wantBRevoked)
				if err != nil || stored == nil || stored.IsRevoked() != wantRevoked || (i == 1 && !wantBRevoked && stored.IsReused()) {
					t.Errorf("session %d: want revoked=%v stored=%+v err=%v", i, wantRevoked, stored, err)
				}
			}
		})
	}
}

func TestPostgresConcurrentHistoricalIDRevokeAndRefresh(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()
	db.SetMaxOpenConns(4)
	users, repo := postgres.NewUserRepo(db), postgres.NewSessionRepo(db)
	a := domain.NewAuthService(users, nil, repo, "test-secret", "ole-test")
	b := domain.NewAuthService(users, nil, repo, "test-secret", "ole-test")
	user, err := a.Register("revoke-race@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	independent, err := a.Login(user.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		old, err := a.Login(user.Email, "secret", domain.SessionMetadata{})
		if err != nil {
			t.Fatal(err)
		}
		current, err := b.Refresh(old.RefreshToken, domain.SessionMetadata{})
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		refreshError, revokeError := make(chan error, 1), make(chan error, 1)
		go func() {
			<-start
			_, err := b.Refresh(current.RefreshToken, domain.SessionMetadata{})
			refreshError <- err
		}()
		go func() { <-start; revokeError <- a.RevokeSession(user.ID, old.ID) }()
		close(start)
		if err := <-revokeError; err != nil {
			t.Fatal(err)
		}
		if err := <-refreshError; err != nil && !errors.Is(err, domain.ErrUnauthorized) {
			t.Fatal(err)
		}
		var active int
		if err := db.QueryRow(`SELECT COUNT(*) FROM session_tokens
			WHERE user_id=$1 AND family_id=$2 AND revoked_at_unix=0 AND reuse_detected_at_unix=0
			AND replaced_by_token='' AND expires_at_unix>$3`, user.ID.String(), old.FamilyID, time.Now().Unix()).Scan(&active); err != nil || active != 0 {
			t.Fatalf("active tokens after revoke: %d err=%v", active, err)
		}
		if _, err := b.ValidateAccessToken(independent.AccessToken); err != nil {
			t.Fatal("independent family revoked")
		}
	}
	t.Log("historical_id_revoke_vs_refresh_races=20 active_tokens_after_revoke=0 independent_family_preserved=20")
}
