package httpapi_test

import (
	"Ole/internal/app"
	"Ole/internal/domain"
	"Ole/internal/httpapi"
	"Ole/internal/store/memory"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestRevokeSessionHTTPUsesHistoricalIDWithoutPageLimit(t *testing.T) {
	for _, scenario := range []string{"historical-id", "1001-families"} {
		t.Run(scenario, func(t *testing.T) {
			repo := memory.NewSessionRepo()
			auth := domain.NewAuthService(memory.NewUserRepo(), nil, repo, "test-secret", "ole-test")
			user, err := auth.Register("revoke-id@example.com", "secret")
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
			caller := login() // Authenticate using an independent family.
			target := login()
			current := target
			if scenario == "historical-id" {
				current, err = auth.Refresh(target.RefreshToken, domain.SessionMetadata{})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				// Populate already-issued sessions without doing 999 password KDFs.
				for i := range 999 {
					fixture := *target
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
				if err != nil || total != 1001 || len(outside) != 1 {
					t.Fatalf("fixture: total=%d outside=%d err=%v", total, len(outside), err)
				}
				target, current = outside[0], outside[0]
				if caller.ID == target.ID {
					first, _, err := repo.ListByUserID(user.ID, 1, 0)
					if err != nil {
						t.Fatal(err)
					}
					caller = first[0]
				}
			}
			router := httpapi.NewRouter(&app.App{AuthService: auth})
			response := performAuthenticatedJSON(t, router, http.MethodDelete, "/api/v1/sessions/"+target.ID, caller.AccessToken, nil)
			if response.Code != http.StatusNoContent {
				t.Errorf("revoke returned %d, want 204: %s", response.Code, response.Body.String())
			}
			if _, err := auth.ValidateAccessToken(current.AccessToken); err == nil {
				t.Error("target family's access remains active")
			}
			if next, err := auth.Refresh(current.RefreshToken, domain.SessionMetadata{}); err == nil || next != nil {
				t.Error("target family's refresh remains active")
			}
			if _, err := auth.ValidateAccessToken(caller.AccessToken); err != nil {
				t.Error("independent caller family was revoked")
			}
		})
	}
}

type revokeByIDFailureRepo struct {
	*memory.SessionRepo
	fail bool
}

func (r *revokeByIDFailureRepo) RevokeBySessionID(userID domain.UserID, id string, now int64) error {
	if r.fail {
		return errors.New("private-storage-diagnostic")
	}
	return r.SessionRepo.RevokeBySessionID(userID, id, now)
}

func TestRevokeSessionHTTPStorageFailureIsRetryable(t *testing.T) {
	repo := &revokeByIDFailureRepo{SessionRepo: memory.NewSessionRepo(), fail: true}
	auth := domain.NewAuthService(memory.NewUserRepo(), nil, repo, "test-secret", "ole-test")
	user, err := auth.Register("revoke-retry@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.Login(user.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	router := httpapi.NewRouter(&app.App{AuthService: auth})
	path := "/api/v1/sessions/" + session.ID
	response := performAuthenticatedJSON(t, router, http.MethodDelete, path, session.AccessToken, nil)
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "private-storage-diagnostic") {
		t.Fatalf("failed revoke: status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := auth.ValidateAccessToken(session.AccessToken); err != nil {
		t.Fatal("failed revoke changed session state")
	}
	repo.fail = false
	response = performAuthenticatedJSON(t, router, http.MethodDelete, path, session.AccessToken, nil)
	if response.Code != http.StatusNoContent {
		t.Fatalf("retry: status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := auth.ValidateAccessToken(session.AccessToken); err == nil {
		t.Fatal("successful retry left access active")
	}
	if next, err := auth.Refresh(session.RefreshToken, domain.SessionMetadata{}); err == nil || next != nil {
		t.Fatal("successful retry left refresh active")
	}
}

func TestRevokeSessionHTTPRejectsForeignAndUnknownID(t *testing.T) {
	repo := memory.NewSessionRepo()
	auth := domain.NewAuthService(memory.NewUserRepo(), nil, repo, "test-secret", "ole-test")
	var sessions []*domain.SessionToken
	for _, email := range []string{"owner@example.com", "foreign@example.com"} {
		if _, err := auth.Register(email, "secret"); err != nil {
			t.Fatal(err)
		}
		session, err := auth.Login(email, "secret", domain.SessionMetadata{})
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, session)
	}
	router := httpapi.NewRouter(&app.App{AuthService: auth})
	for _, id := range []string{sessions[1].ID, "missing-id"} {
		response := performAuthenticatedJSON(t, router, http.MethodDelete, "/api/v1/sessions/"+id, sessions[0].AccessToken, nil)
		if response.Code != http.StatusNotFound {
			t.Errorf("foreign/unknown ID: got %d, want 404", response.Code)
		}
	}
	for _, session := range sessions {
		if _, err := auth.ValidateAccessToken(session.AccessToken); err != nil {
			t.Error("failed request revoked an unrelated family")
		}
	}
}
