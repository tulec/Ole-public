package postgres_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/postgres"
	"errors"
	"testing"
)

type logoutRotationHook struct {
	domain.SessionRepo
	beforeRevoke func() error
}

func (r *logoutRotationHook) RevokeFamily(userID domain.UserID, family string, now int64, reused bool) error {
	if hook := r.beforeRevoke; hook != nil {
		r.beforeRevoke = nil
		if err := hook(); err != nil {
			return err
		}
	}
	return r.SessionRepo.RevokeFamily(userID, family, now, reused)
}

func TestPostgresLogoutRevokesRotatedFamilyOnly(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()
	users, repo := postgres.NewUserRepo(db), postgres.NewSessionRepo(db)
	hook := &logoutRotationHook{SessionRepo: repo}
	a := domain.NewAuthService(users, nil, hook, "test-secret", "ole-test")
	b := domain.NewAuthService(users, nil, repo, "test-secret", "ole-test")
	user, err := a.Register("postgres-logout@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	old, err := a.Login(user.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := b.Login(user.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	var child *domain.SessionToken
	hook.beforeRevoke = func() error {
		var err error
		child, err = b.Refresh(old.RefreshToken, domain.SessionMetadata{})
		return err
	}
	if err := a.Logout(old.AccessToken); err != nil {
		t.Fatal(err)
	}
	if child == nil {
		t.Fatal("test did not reach refresh/logout race")
	}
	for _, session := range []*domain.SessionToken{old, child} {
		if _, err := b.ValidateAccessToken(session.AccessToken); err == nil {
			t.Fatal("logged-out family retained active access")
		}
		if next, err := b.Refresh(session.RefreshToken, domain.SessionMetadata{}); err == nil || next != nil {
			t.Fatal("logged-out family refreshed")
		}
	}
	if _, err := b.ValidateAccessToken(other.AccessToken); err != nil {
		t.Fatal("independent login family revoked")
	}
}

func TestPostgresConcurrentLogoutAndRefresh(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()
	db.SetMaxOpenConns(4)
	users, repo := postgres.NewUserRepo(db), postgres.NewSessionRepo(db)
	a := domain.NewAuthService(users, nil, repo, "test-secret", "ole-test")
	b := domain.NewAuthService(users, nil, repo, "test-secret", "ole-test")
	user, err := a.Register("concurrent-logout@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	other, err := b.Login(user.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		old, err := a.Login(user.Email, "secret", domain.SessionMetadata{})
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		refreshed := make(chan *domain.SessionToken, 1)
		refreshError, logoutError := make(chan error, 1), make(chan error, 1)
		go func() {
			<-start
			child, err := b.Refresh(old.RefreshToken, domain.SessionMetadata{})
			refreshed <- child
			refreshError <- err
		}()
		go func() { <-start; logoutError <- a.Logout(old.AccessToken) }()
		close(start)
		if err := <-logoutError; err != nil {
			t.Fatal(err)
		}
		child := <-refreshed
		if err := <-refreshError; err != nil && !errors.Is(err, domain.ErrUnauthorized) {
			t.Fatal(err)
		}
		if child != nil {
			if _, err := b.ValidateAccessToken(child.AccessToken); err == nil {
				t.Fatal("refresh escaped completed logout")
			}
		}
		if _, err := b.ValidateAccessToken(old.AccessToken); err == nil {
			t.Fatal("old access escaped logout")
		}
		if _, err := b.ValidateAccessToken(other.AccessToken); err != nil {
			t.Fatal("independent family did not survive logout")
		}
	}
	t.Log("postgres_logout_vs_refresh_races=20 active_family_tokens_after_logout=0 independent_family_preserved=20")
}
