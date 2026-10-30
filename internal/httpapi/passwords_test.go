package httpapi_test

import (
	"Ole/internal/app"
	"Ole/internal/domain"
	"Ole/internal/httpapi"
	"Ole/internal/store/memory"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestPasswordHTTPRejectsEmptyChangeAndDoesNotExposeHashes(t *testing.T) {
	users, sessions := memory.NewUserRepo(), memory.NewSessionRepo()
	auth := domain.NewAuthService(users, nil, sessions, "test-secret", "ole-test")
	router := httpapi.NewRouter(&app.App{AuthService: auth, UserRepo: users})
	register := performJSON(t, router, http.MethodPost, "/api/v1/users", map[string]string{"email": "password-http@example.com", "password": "old secret"})
	if register.Code != http.StatusCreated {
		t.Fatal(register.Code)
	}
	user, err := users.FindByEmail("password-http@example.com")
	if err != nil || user == nil {
		t.Fatal(err)
	}
	login, err := auth.Login(user.Email, "old secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	responses := []string{register.Body.String()}
	profile := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/users/"+user.ID.String(), login.AccessToken, nil)
	if profile.Code != http.StatusOK {
		t.Fatal(profile.Code)
	}
	responses = append(responses, profile.Body.String())
	for _, change := range []struct{ old, next string }{{"old secret", ""}, {"wrong", "new secret"}} {
		response := performAuthenticatedJSON(t, router, http.MethodPut, "/api/v1/users/"+user.ID.String()+"/password", login.AccessToken, map[string]string{"oldPassword": change.old, "newPassword": change.next})
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid change: %d", response.Code)
		}
		stored, _ := users.FindByID(user.ID)
		if stored.PasswordHash != user.PasswordHash {
			t.Fatal("invalid request changed password")
		}
	}
	changed := performAuthenticatedJSON(t, router, http.MethodPut, "/api/v1/users/"+user.ID.String()+"/password", login.AccessToken, map[string]string{"oldPassword": "old secret", "newPassword": "new secret"})
	if changed.Code != http.StatusOK {
		t.Fatal(changed.Code)
	}
	responses = append(responses, changed.Body.String())
	if _, err := auth.Login(user.Email, "old secret", domain.SessionMetadata{}); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatal("old password still accepted")
	}
	newLogin := performJSON(t, router, http.MethodPost, "/api/v1/sessions", map[string]string{"email": user.Email, "password": "new secret"})
	if newLogin.Code != http.StatusCreated {
		t.Fatal(newLogin.Code)
	}
	responses = append(responses, newLogin.Body.String())
	stored, _ := users.FindByID(user.ID)
	for _, body := range responses {
		if strings.Contains(body, "passwordHash") || strings.Contains(body, user.PasswordHash) || strings.Contains(body, stored.PasswordHash) || strings.Contains(body, "old secret") || strings.Contains(body, "new secret") {
			t.Error("API response exposes a password or hash")
		}
	}
}

type failingPasswordUserRepo struct {
	*memory.UserRepo
	fail bool
}

func (r *failingPasswordUserRepo) CompareAndSwapPassword(id domain.UserID, old, next string) (bool, error) {
	if r.fail {
		return false, errors.New("private-storage-diagnostic " + old)
	}
	return r.UserRepo.CompareAndSwapPassword(id, old, next)
}

func TestPasswordHTTPStorageFailureIsPrivateAndRetryable(t *testing.T) {
	for _, operation := range []string{"migration", "change"} {
		t.Run(operation, func(t *testing.T) {
			users := &failingPasswordUserRepo{UserRepo: memory.NewUserRepo(), fail: true}
			sessions := memory.NewSessionRepo()
			auth := domain.NewAuthService(users, nil, sessions, "test-secret", "ole-test")
			sum := sha256.Sum256([]byte("old secret"))
			user := &domain.User{ID: domain.UserID{Value: "legacy"}, Email: "failure-http@example.com", PasswordHash: hex.EncodeToString(sum[:]), Status: domain.UserStatusActive}
			if operation == "migration" {
				if err := users.Create(user); err != nil {
					t.Fatal(err)
				}
			} else {
				var err error
				user, err = auth.Register(user.Email, "old secret")
				if err != nil {
					t.Fatal(err)
				}
			}
			router := httpapi.NewRouter(&app.App{AuthService: auth, UserRepo: users})
			var access string
			if operation == "change" {
				session, err := auth.Login(user.Email, "old secret", domain.SessionMetadata{})
				if err != nil {
					t.Fatal(err)
				}
				access = session.AccessToken
			}
			for range 4 {
				var responseCode int
				var body string
				if operation == "migration" {
					response := performJSON(t, router, http.MethodPost, "/api/v1/sessions", map[string]string{"email": user.Email, "password": "old secret"})
					responseCode, body = response.Code, response.Body.String()
				} else {
					response := performAuthenticatedJSON(t, router, http.MethodPut, "/api/v1/users/"+user.ID.String()+"/password", access, map[string]string{"oldPassword": "old secret", "newPassword": "new secret"})
					responseCode, body = response.Code, response.Body.String()
				}
				if responseCode != http.StatusInternalServerError || strings.Contains(body, "private-storage-diagnostic") || strings.Contains(body, user.PasswordHash) {
					t.Fatalf("storage failure response: status=%d", responseCode)
				}
			}
			stored, _ := users.FindByID(user.ID)
			if stored.PasswordHash != user.PasswordHash {
				t.Fatal("failed writes changed password")
			}
			_, total, err := sessions.ListByUserID(user.ID, 10, 0)
			want := 0
			if operation == "change" {
				want = 1
			}
			if err != nil || total != want {
				t.Fatalf("unexpected sessions after failed write: %d", total)
			}
			users.fail = false
			if operation == "change" {
				response := performAuthenticatedJSON(t, router, http.MethodPut, "/api/v1/users/"+user.ID.String()+"/password", access, map[string]string{"oldPassword": "old secret", "newPassword": "new secret"})
				if response.Code != http.StatusOK {
					t.Fatal("password change retry failed")
				}
			} else {
				response := performJSON(t, router, http.MethodPost, "/api/v1/sessions", map[string]string{"email": user.Email, "password": "old secret"})
				if response.Code != http.StatusCreated {
					t.Fatal("login retry blocked after storage failures")
				}
			}
		})
	}
}
