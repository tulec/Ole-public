package domain_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/memory"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func legacyPasswordHash(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

func TestPasswordRegistrationsUseIndependentSalts(t *testing.T) {
	auth := domain.NewAuthService(memory.NewUserRepo(), nil, nil, "test-secret", "ole-test")
	hashes := map[string]bool{}
	duplicates, modern := 0, 0
	for i := range 20 {
		user, err := auth.Register(fmt.Sprintf("salt-%d@example.com", i), "same password")
		if err != nil {
			t.Fatal(err)
		}
		if hashes[user.PasswordHash] {
			duplicates++
		}
		hashes[user.PasswordHash] = true
		if strings.HasPrefix(user.PasswordHash, "$argon2id$") {
			modern++
		}
	}
	if duplicates != 0 || modern != 20 {
		t.Errorf("registrations=20 duplicate_hashes=%d argon2id_hashes=%d", duplicates, modern)
	}
	t.Logf("registrations=20 duplicate_hashes=%d argon2id_hashes=%d", duplicates, modern)
}

func TestLegacyPasswordLoginUpgradesOnlyAfterValidPassword(t *testing.T) {
	for _, uppercase := range []bool{false, true} {
		t.Run(fmt.Sprint(uppercase), func(t *testing.T) {
			repo := memory.NewUserRepo()
			hash := legacyPasswordHash("legacy secret")
			if uppercase {
				hash = strings.ToUpper(hash)
			}
			user := &domain.User{ID: domain.UserID{Value: "legacy-user"}, Email: "legacy@example.com", PasswordHash: hash, Status: domain.UserStatusActive}
			if err := repo.Create(user); err != nil {
				t.Fatal(err)
			}
			auth := domain.NewAuthService(repo, nil, memory.NewSessionRepo(), "test-secret", "ole-test")
			if session, err := auth.Login(user.Email, "wrong", domain.SessionMetadata{}); session != nil || !errors.Is(err, domain.ErrInvalidCredentials) {
				t.Fatalf("wrong password: session=%v err=%v", session != nil, err)
			}
			stored, err := repo.FindByID(user.ID)
			if err != nil || stored.PasswordHash != hash {
				t.Fatal("wrong password changed the stored hash")
			}
			session, err := auth.Login(user.Email, "legacy secret", domain.SessionMetadata{})
			if err != nil || session == nil {
				t.Fatalf("legacy login failed: %v", err)
			}
			stored, err = repo.FindByID(user.ID)
			if err != nil || !strings.HasPrefix(stored.PasswordHash, "$argon2id$") {
				t.Fatal("successful legacy login did not persist Argon2id")
			}
			upgraded := stored.PasswordHash
			if _, err := auth.Login(user.Email, "legacy secret", domain.SessionMetadata{}); err != nil {
				t.Fatal(err)
			}
			stored, err = repo.FindByID(user.ID)
			if err != nil || stored.PasswordHash != upgraded {
				t.Fatal("current-policy hash was unnecessarily replaced")
			}
		})
	}
}

func TestChangePasswordRejectsEmptyAndPreservesOldPassword(t *testing.T) {
	repo := memory.NewUserRepo()
	auth := domain.NewAuthService(repo, nil, nil, "test-secret", "ole-test")
	user, err := auth.Register("empty-password@example.com", "old secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ChangePassword(user.ID, "old secret", ""); !errors.Is(err, domain.ErrInvalidPassword) {
		t.Errorf("empty password accepted: %v", err)
	}
	stored, err := repo.FindByID(user.ID)
	if err != nil || stored.PasswordHash != user.PasswordHash {
		t.Error("empty password request modified storage")
	}
	if _, err := auth.Login(user.Email, "old secret", domain.SessionMetadata{}); err != nil {
		t.Error("old password stopped working after rejected request")
	}
}

func TestUserJSONDoesNotExposePasswordHash(t *testing.T) {
	encoded, err := json.Marshal(&domain.User{PasswordHash: "private-password-hash"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "private-password-hash") || strings.Contains(string(encoded), "passwordHash") {
		t.Fatal("user JSON exposes password hash")
	}
}

type passwordWriteRepo struct {
	*memory.UserRepo
	writeErr  error
	beforeCAS func() error
}

func (r *passwordWriteRepo) CompareAndSwapPassword(id domain.UserID, old, next string) (bool, error) {
	if hook := r.beforeCAS; hook != nil {
		r.beforeCAS = nil
		if err := hook(); err != nil {
			return false, err
		}
	}
	if r.writeErr != nil {
		return false, r.writeErr
	}
	return r.UserRepo.CompareAndSwapPassword(id, old, next)
}

func TestPasswordStorageFailuresDoNotPublishChangesOrSessions(t *testing.T) {
	for _, operation := range []string{"migration", "change"} {
		t.Run(operation, func(t *testing.T) {
			repo := &passwordWriteRepo{UserRepo: memory.NewUserRepo(), writeErr: errors.New("storage unavailable")}
			user := &domain.User{ID: domain.UserID{Value: "legacy"}, Email: "failure@example.com", PasswordHash: legacyPasswordHash("old"), Status: domain.UserStatusActive}
			if err := repo.Create(user); err != nil {
				t.Fatal(err)
			}
			sessions := memory.NewSessionRepo()
			auth := domain.NewAuthService(repo, nil, sessions, "test-secret", "ole-test")
			var err error
			if operation == "migration" {
				var session *domain.SessionToken
				session, err = auth.Login(user.Email, "old", domain.SessionMetadata{})
				if session != nil {
					t.Error("failed migration returned session")
				}
			} else {
				err = auth.ChangePassword(user.ID, "old", "new")
			}
			if !errors.Is(err, domain.ErrPasswordStorage) || !errors.Is(err, repo.writeErr) {
				t.Fatalf("storage error not propagated: %v", err)
			}
			stored, _ := repo.FindByID(user.ID)
			if stored.PasswordHash != user.PasswordHash {
				t.Error("failed write changed stored password")
			}
			if _, total, err := sessions.ListByUserID(user.ID, 10, 0); err != nil || total != 0 {
				t.Error("failed write published a session")
			}
			repo.writeErr = nil
			if operation == "change" {
				if err := auth.ChangePassword(user.ID, "old", "new"); err != nil {
					t.Fatal(err)
				}
				if _, err := auth.Login(user.Email, "old", domain.SessionMetadata{}); !errors.Is(err, domain.ErrInvalidCredentials) {
					t.Fatal("old password accepted after successful change")
				}
				if _, err := auth.Login(user.Email, "new", domain.SessionMetadata{}); err != nil {
					t.Fatal(err)
				}
			} else if _, err := auth.Login(user.Email, "old", domain.SessionMetadata{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPasswordCompareAndSwapPreventsStaleMigrationAndChange(t *testing.T) {
	for _, operation := range []string{"migration-vs-change", "change-vs-change", "two-migrations"} {
		t.Run(operation, func(t *testing.T) {
			repo := &passwordWriteRepo{UserRepo: memory.NewUserRepo()}
			user := &domain.User{ID: domain.UserID{Value: "legacy"}, Email: "race@example.com", PasswordHash: legacyPasswordHash("old"), Status: domain.UserStatusActive}
			if err := repo.Create(user); err != nil {
				t.Fatal(err)
			}
			sessions := memory.NewSessionRepo()
			a := domain.NewAuthService(repo, nil, sessions, "test-secret", "ole-test")
			b := domain.NewAuthService(repo.UserRepo, nil, sessions, "test-secret", "ole-test")
			repo.beforeCAS = func() error {
				if operation == "two-migrations" {
					_, err := b.Login(user.Email, "old", domain.SessionMetadata{})
					return err
				}
				return b.ChangePassword(user.ID, "old", "winner")
			}
			if operation == "change-vs-change" {
				if err := a.ChangePassword(user.ID, "old", "loser"); !errors.Is(err, domain.ErrInvalidPassword) {
					t.Fatalf("stale password change: %v", err)
				}
			} else {
				session, err := a.Login(user.Email, "old", domain.SessionMetadata{})
				if operation == "two-migrations" {
					if err != nil || session == nil {
						t.Fatalf("concurrent successful migration denied: %v", err)
					}
				} else if session != nil || !errors.Is(err, domain.ErrInvalidCredentials) {
					t.Fatalf("stale migration logged in with replaced password: %v", err)
				}
			}
			if operation != "two-migrations" {
				if _, err := b.Login(user.Email, "winner", domain.SessionMetadata{}); err != nil {
					t.Fatal("winning password was overwritten")
				}
				if _, err := b.Login(user.Email, "old", domain.SessionMetadata{}); !errors.Is(err, domain.ErrInvalidCredentials) {
					t.Fatal("old password survived change")
				}
			}
			_, total, err := sessions.ListByUserID(user.ID, 10, 0)
			want := 1
			if operation == "two-migrations" {
				want = 2
			}
			if err != nil || total != want {
				t.Fatalf("published sessions=%d, want %d err=%v", total, want, err)
			}
		})
	}
}
