package postgres_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/postgres"
	"errors"
	"testing"
	"time"
)

func TestPostgresSharedRevocationAndAtomicRotation(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()
	users, repo := postgres.NewUserRepo(db), postgres.NewSessionRepo(db)
	a := domain.NewAuthService(users, nil, repo, "test-secret", "ole-test")
	b := domain.NewAuthService(users, nil, repo, "test-secret", "ole-test")
	user, err := a.Register("shared-postgres@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"single", "all", "reuse-family"} {
		t.Run(kind, func(t *testing.T) {
			session, err := a.Login(user.Email, "secret", domain.SessionMetadata{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.ValidateAccessToken(session.AccessToken); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "single":
				err = b.RevokeSession(user.ID, session.ID)
			case "all":
				err = b.RevokeAllSessions(user.ID)
			case "reuse-family":
				err = repo.RevokeFamily(session.UserID, session.FamilyID, time.Now().Unix(), true)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.ValidateAccessToken(session.AccessToken); err == nil {
				t.Fatal("revoked access accepted")
			}
			if next, err := a.Refresh(session.RefreshToken, domain.SessionMetadata{}); err == nil || next != nil {
				t.Fatal("revoked refresh accepted")
			}
			if err := repo.Update(session); err != nil {
				t.Fatal(err)
			}
			stored, err := repo.FindByAccessToken(session.AccessToken)
			if err != nil || stored == nil || !stored.IsRevoked() {
				t.Fatal("stale metadata update cleared revocation")
			}
			if active, err := repo.TouchLastUsed(session.AccessToken, time.Now().Unix()); err != nil || active {
				t.Fatal("revoked session was touched")
			}
		})
	}
	old, err := a.Login(user.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	collision, err := a.Login(user.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	next := *old
	next.ID, next.AccessToken, next.RefreshToken = "rollback-next", collision.AccessToken, "ref-rollback"
	if err := repo.Rotate(old.RefreshToken, &next, time.Now().Unix()); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("expected INSERT conflict: %v", err)
	}
	stored, err := repo.FindByRefreshToken(old.RefreshToken)
	if err != nil || stored == nil || *stored != *old {
		t.Fatal("INSERT failure partially revoked old session")
	}
	rotated, err := a.Refresh(old.RefreshToken, domain.SessionMetadata{})
	if err != nil {
		t.Fatalf("retry after rollback failed: %v", err)
	}
	if _, err := a.ValidateAccessToken(rotated.AccessToken); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(old); err != nil {
		t.Fatal(err)
	}
	stored, err = repo.FindByRefreshToken(old.RefreshToken)
	if err != nil || stored.ReplacedByToken != rotated.RefreshToken || !stored.IsRevoked() {
		t.Fatal("stale update cleared rotation marker")
	}
}

func TestPostgresConcurrentRotationAndRevokeAll(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()
	db.SetMaxOpenConns(4) // Exercise separate connections, not a serialized single-connection pool.
	users, repo := postgres.NewUserRepo(db), postgres.NewSessionRepo(db)
	a := domain.NewAuthService(users, nil, repo, "test-secret", "ole-test")
	b := domain.NewAuthService(users, nil, repo, "test-secret", "ole-test")
	user, err := a.Register("concurrent-postgres@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		session, err := a.Login(user.Email, "secret", domain.SessionMetadata{})
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		refreshed := make(chan *domain.SessionToken, 1)
		refreshError, revokeError := make(chan error, 1), make(chan error, 1)
		go func() {
			<-start
			next, err := a.Refresh(session.RefreshToken, domain.SessionMetadata{})
			refreshed <- next
			refreshError <- err
		}()
		go func() { <-start; revokeError <- b.RevokeAllSessions(user.ID) }()
		close(start)
		if err := <-revokeError; err != nil {
			t.Fatal(err)
		}
		next := <-refreshed
		if err := <-refreshError; err != nil && !errors.Is(err, domain.ErrUnauthorized) {
			t.Fatal(err)
		}
		if next != nil {
			if _, err := a.ValidateAccessToken(next.AccessToken); err == nil {
				t.Fatal("new session escaped completed revoke-all")
			}
		}
		if _, err := a.ValidateAccessToken(session.AccessToken); err == nil {
			t.Fatal("old session escaped revoke-all")
		}
	}
	t.Log("postgres_refresh_vs_revoke_races=20 active_sessions_after_completion=0")
}
