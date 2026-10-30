package httpapi_test

import (
	"Ole/internal/app"
	"Ole/internal/domain"
	"Ole/internal/httpapi"
	"Ole/internal/store/memory"
	"errors"
	"net/http"
	"strings"
	"testing"
)

type logoutSessionRepo struct {
	*memory.SessionRepo
	beforeRevoke func() error
	revokeErr    error
	lookupMode   string
	lookups      int
}

func (r *logoutSessionRepo) FindByAccessToken(token string) (*domain.SessionToken, error) {
	r.lookups++
	// The first lookup authorizes middleware; inject failure in Logout itself.
	if r.lookups > 1 {
		switch r.lookupMode {
		case "error":
			return nil, errors.New("private-storage-diagnostic")
		case "missing":
			return nil, nil
		}
	}
	return r.SessionRepo.FindByAccessToken(token)
}

func (r *logoutSessionRepo) beforeLogoutRevoke() error {
	if hook := r.beforeRevoke; hook != nil {
		r.beforeRevoke = nil
		if err := hook(); err != nil {
			return err
		}
	}
	return r.revokeErr
}

func (r *logoutSessionRepo) RevokeByAccessToken(token string, now int64) error {
	if err := r.beforeLogoutRevoke(); err != nil {
		return err
	}
	return r.SessionRepo.RevokeByAccessToken(token, now)
}

func (r *logoutSessionRepo) RevokeFamily(userID domain.UserID, family string, now int64, reuse bool) error {
	if err := r.beforeLogoutRevoke(); err != nil {
		return err
	}
	return r.SessionRepo.RevokeFamily(userID, family, now, reuse)
}

func TestLogoutHTTPHandlesRefreshRaceAndStorageFailures(t *testing.T) {
	for _, scenario := range []string{"refresh-race", "revoke-error", "lookup-error", "missing-after-middleware"} {
		t.Run(scenario, func(t *testing.T) {
			users := memory.NewUserRepo()
			repo := &logoutSessionRepo{SessionRepo: memory.NewSessionRepo()}
			a := domain.NewAuthService(users, nil, repo, "test-secret", "ole-test")
			// A separate service bypasses the fault-injection wrapper and local mutex.
			b := domain.NewAuthService(users, nil, repo.SessionRepo, "test-secret", "ole-test")
			user, err := a.Register("logout@example.com", "secret")
			if err != nil {
				t.Fatal(err)
			}
			session, err := a.Login(user.Email, "secret", domain.SessionMetadata{})
			if err != nil {
				t.Fatal(err)
			}
			other, err := b.Login(user.Email, "secret", domain.SessionMetadata{})
			if err != nil {
				t.Fatal(err)
			}
			var rotated *domain.SessionToken
			wantStatus := http.StatusInternalServerError
			switch scenario {
			case "refresh-race":
				wantStatus = http.StatusNoContent
				repo.beforeRevoke = func() error {
					var err error
					rotated, err = b.Refresh(session.RefreshToken, domain.SessionMetadata{})
					return err
				}
			case "revoke-error":
				repo.revokeErr = errors.New("private-storage-diagnostic")
			case "lookup-error":
				repo.lookupMode = "error"
			case "missing-after-middleware":
				repo.lookupMode = "missing"
				wantStatus = http.StatusUnauthorized
			}
			router := httpapi.NewRouter(&app.App{AuthService: a})
			response := performAuthenticatedJSON(t, router, http.MethodDelete, "/api/v1/sessions", session.AccessToken, nil)
			if response.Code != wantStatus {
				t.Errorf("got status=%d, want=%d", response.Code, wantStatus)
			}
			if strings.Contains(response.Body.String(), "private-storage-diagnostic") {
				t.Error("storage diagnostic leaked to response")
			}
			if rotated != nil {
				if _, err := b.ValidateAccessToken(rotated.AccessToken); err == nil {
					t.Error("successful logout left rotated access active")
				}
				if next, err := b.Refresh(rotated.RefreshToken, domain.SessionMetadata{}); err == nil || next != nil {
					t.Error("successful logout left rotated refresh active")
				}
			} else {
				if _, err := b.ValidateAccessToken(session.AccessToken); err != nil {
					t.Error("failed logout unexpectedly destroyed session; retry unavailable")
				}
				// Clear the injected failure; retry must perform real revocation.
				repo.lookupMode, repo.revokeErr = "", nil
				retry := performAuthenticatedJSON(t, router, http.MethodDelete, "/api/v1/sessions", session.AccessToken, nil)
				if retry.Code != http.StatusNoContent {
					t.Errorf("logout retry: %d", retry.Code)
				}
				if _, err := b.ValidateAccessToken(session.AccessToken); err == nil {
					t.Error("retry did not revoke access")
				}
				if next, err := b.Refresh(session.RefreshToken, domain.SessionMetadata{}); err == nil || next != nil {
					t.Error("retry did not revoke refresh")
				}
			}
			if _, err := b.ValidateAccessToken(other.AccessToken); err != nil {
				t.Error("logout revoked an independent login family")
			}
		})
	}
}
