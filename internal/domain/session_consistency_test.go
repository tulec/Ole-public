package domain_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/memory"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRevocationIsAuthoritativeAcrossAuthServices(t *testing.T) {
	for _, kind := range []string{"single", "all", "reuse-family"} {
		t.Run(kind, func(t *testing.T) {
			users := memory.NewUserRepo()
			repo := memory.NewSessionRepo()
			a := domain.NewAuthService(users, nil, repo, "test-secret", "ole-test")
			b := domain.NewAuthService(users, nil, repo, "test-secret", "ole-test")
			user, err := a.Register("shared@example.com", "secret")
			if err != nil {
				t.Fatal(err)
			}
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
				t.Error("warm service accepted revoked access token")
			}
			if next, err := a.Refresh(session.RefreshToken, domain.SessionMetadata{}); err == nil || next != nil {
				t.Error("warm service refreshed revoked session")
			}
			stored, err := repo.FindByAccessToken(session.AccessToken)
			if err != nil {
				t.Fatal(err)
			}
			if stored != nil && !stored.IsRevoked() {
				t.Error("stale service resurrected revoked session in storage")
			}
		})
	}
}

type sessionRaceRepo struct {
	*memory.SessionRepo
	afterAccessRead, afterRefreshRead func()
	rotateErr, touchErr               error
}

func (r *sessionRaceRepo) FindByAccessToken(token string) (*domain.SessionToken, error) {
	session, err := r.SessionRepo.FindByAccessToken(token)
	if hook := r.afterAccessRead; hook != nil {
		r.afterAccessRead = nil
		hook()
	}
	return session, err
}

func (r *sessionRaceRepo) FindByRefreshToken(token string) (*domain.SessionToken, error) {
	session, err := r.SessionRepo.FindByRefreshToken(token)
	if hook := r.afterRefreshRead; hook != nil {
		r.afterRefreshRead = nil
		hook()
	}
	return session, err
}

func (r *sessionRaceRepo) Rotate(token string, next *domain.SessionToken, now int64) error {
	if r.rotateErr != nil {
		return r.rotateErr
	}
	return r.SessionRepo.Rotate(token, next, now)
}

func (r *sessionRaceRepo) TouchLastUsed(token string, now int64) (bool, error) {
	if r.touchErr != nil {
		return false, r.touchErr
	}
	return r.SessionRepo.TouchLastUsed(token, now)
}

func TestRevocationBetweenReadAndUseCannotResurrectSession(t *testing.T) {
	for _, operation := range []string{"access", "refresh", "touch-error"} {
		t.Run(operation, func(t *testing.T) {
			repo := &sessionRaceRepo{SessionRepo: memory.NewSessionRepo()}
			auth := domain.NewAuthService(memory.NewUserRepo(), nil, repo, "test-secret", "ole-test")
			user, err := auth.Register("race@example.com", "secret")
			if err != nil {
				t.Fatal(err)
			}
			session, err := auth.Login(user.Email, "secret", domain.SessionMetadata{})
			if err != nil {
				t.Fatal(err)
			}
			revoke := func() {
				if err := repo.RevokeByUserID(user.ID, time.Now().Unix()); err != nil {
					t.Fatal(err)
				}
			}
			switch operation {
			case "access":
				repo.afterAccessRead = revoke
			case "refresh":
				repo.afterRefreshRead = revoke
			case "touch-error":
				repo.touchErr = errors.New("touch failed")
			}
			if operation == "refresh" {
				if next, err := auth.Refresh(session.RefreshToken, domain.SessionMetadata{}); err == nil || next != nil {
					t.Fatal("refresh crossed completed revocation")
				}
			} else if _, err := auth.ValidateAccessToken(session.AccessToken); err == nil {
				t.Fatal("access crossed revocation/touch failure")
			}
			stored, err := repo.SessionRepo.FindByAccessToken(session.AccessToken)
			if err != nil || stored == nil {
				t.Fatal("session history lost")
			}
			if operation != "touch-error" && !stored.IsRevoked() {
				t.Fatal("revocation was cleared")
			}
		})
	}
}

func TestRotationFailurePreservesOldSessionAndAllowsRetry(t *testing.T) {
	repo := &sessionRaceRepo{SessionRepo: memory.NewSessionRepo()}
	auth := domain.NewAuthService(memory.NewUserRepo(), nil, repo, "test-secret", "ole-test")
	user, err := auth.Register("rollback@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.Login(user.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("cannot insert next session")
	repo.rotateErr = injected
	if next, err := auth.Refresh(session.RefreshToken, domain.SessionMetadata{}); !errors.Is(err, injected) || next != nil {
		t.Fatal("injected rotation failure not returned")
	}
	stored, err := repo.FindByRefreshToken(session.RefreshToken)
	if err != nil || stored == nil || *stored != *session {
		t.Fatal("failed rotation changed old session")
	}
	if _, err := auth.ValidateAccessToken(session.AccessToken); err != nil {
		t.Fatalf("old access lost after failure: %v", err)
	}
	repo.rotateErr = nil
	next, err := auth.Refresh(session.RefreshToken, domain.SessionMetadata{})
	if err != nil || next.AccessToken == session.AccessToken {
		t.Fatalf("rotation retry failed: %v", err)
	}
	if _, err := auth.ValidateAccessToken(session.AccessToken); err == nil {
		t.Fatal("rotated old access still accepted")
	}
	if _, err := auth.ValidateAccessToken(next.AccessToken); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentRefreshAndRevokeAllLeaveNoActiveSession(t *testing.T) {
	users, repo := memory.NewUserRepo(), memory.NewSessionRepo()
	a := domain.NewAuthService(users, nil, repo, "test-secret", "ole-test")
	b := domain.NewAuthService(users, nil, repo, "test-secret", "ole-test")
	user, err := a.Register("concurrent@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	for range 100 {
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
				t.Fatal("rotated child escaped revoke-all")
			}
		}
		if _, err := a.ValidateAccessToken(session.AccessToken); err == nil {
			t.Fatal("old token escaped revoke-all")
		}
	}
	t.Log("refresh_vs_revoke_races=100 active_sessions_after_completion=0")
}

type refreshBarrierRepo struct {
	*memory.SessionRepo
	arrived, release chan struct{}
}

func (r *refreshBarrierRepo) FindByRefreshToken(token string) (*domain.SessionToken, error) {
	session, err := r.SessionRepo.FindByRefreshToken(token)
	if session != nil && !session.IsRevoked() && session.ReplacedByToken == "" {
		r.arrived <- struct{}{}
		<-r.release
	}
	return session, err
}

func TestTwoServicesCannotRotateOneRefreshTwice(t *testing.T) {
	repo := &refreshBarrierRepo{SessionRepo: memory.NewSessionRepo(), arrived: make(chan struct{}, 2), release: make(chan struct{})}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(repo.release) }) })
	users := memory.NewUserRepo()
	a := domain.NewAuthService(users, nil, repo, "test-secret", "ole-test")
	b := domain.NewAuthService(users, nil, repo, "test-secret", "ole-test")
	user, err := a.Register("double-refresh@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	session, err := a.Login(user.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for _, auth := range []*domain.AuthService{a, b} {
		go func(auth *domain.AuthService) {
			_, err := auth.Refresh(session.RefreshToken, domain.SessionMetadata{})
			results <- err
		}(auth)
	}
	for range 2 {
		select {
		case <-repo.arrived:
		case <-time.After(5 * time.Second):
			t.Fatal("both refreshes did not reach barrier")
		}
	}
	release.Do(func() { close(repo.release) })
	success, denied := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			success++
		} else if errors.Is(err, domain.ErrUnauthorized) {
			denied++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || denied != 1 {
		t.Fatalf("success=%d denied=%d", success, denied)
	}
	all, _, err := repo.ListByUserID(user.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, stored := range all {
		if !stored.IsRevoked() || !stored.IsReused() {
			t.Fatal("refresh reuse failed to revoke winner's family")
		}
	}
}

type sessionFailureRepo struct {
	*memory.SessionRepo
	createErr, lookupErr error
	candidate            *domain.SessionToken
}

func (r *sessionFailureRepo) Create(session *domain.SessionToken) error {
	copy := *session
	r.candidate = &copy
	if r.createErr != nil {
		return r.createErr
	}
	return r.SessionRepo.Create(session)
}

func (r *sessionFailureRepo) FindByAccessToken(token string) (*domain.SessionToken, error) {
	if r.lookupErr != nil {
		return nil, r.lookupErr
	}
	return r.SessionRepo.FindByAccessToken(token)
}

func TestSessionStorageFailureCannotFallBackToCache(t *testing.T) {
	for _, failedOperation := range []string{"create", "read"} {
		t.Run(failedOperation, func(t *testing.T) {
			repo := &sessionFailureRepo{SessionRepo: memory.NewSessionRepo()}
			auth := domain.NewAuthService(memory.NewUserRepo(), nil, repo, "test-secret", "ole-test")
			user, err := auth.Register("failure@example.com", "secret")
			if err != nil {
				t.Fatal(err)
			}
			if failedOperation == "create" {
				repo.createErr = errors.New("storage unavailable")
			}
			session, err := auth.Login(user.Email, "secret", domain.SessionMetadata{})
			if failedOperation == "create" {
				if err == nil || session != nil {
					t.Fatal("login did not return storage failure")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				repo.lookupErr = errors.New("storage unavailable")
			}
			if _, err := auth.ValidateAccessToken(repo.candidate.AccessToken); err == nil {
				t.Error("session accepted from cache despite failed persistence/lookup")
			}
		})
	}
}

func TestIndependentLoginTokensAreUnique(t *testing.T) {
	auth := domain.NewAuthService(memory.NewUserRepo(), nil, memory.NewSessionRepo(), "test-secret", "ole-test")
	user, err := auth.Register("unique@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	duplicates := 0
	for range 20 {
		session, err := auth.Login(user.Email, "secret", domain.SessionMetadata{})
		if err != nil {
			t.Fatal(err)
		}
		if seen[session.AccessToken] {
			duplicates++
		}
		seen[session.AccessToken] = true
	}
	t.Logf("login_tokens=20 unique=%d duplicates=%d", len(seen), duplicates)
	if duplicates != 0 {
		t.Fatal("independent logins reused an access JWT")
	}
}
