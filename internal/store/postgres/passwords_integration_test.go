package postgres_test

import (
	"Ole/internal/domain"
	"Ole/internal/passwordhash"
	"Ole/internal/store/postgres"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

func postgresLegacyPassword(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

func TestPostgresPasswordLifecycleAndLegacyUpgrade(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()
	users, sessions := postgres.NewUserRepo(db), postgres.NewSessionRepo(db)
	auth := domain.NewAuthService(users, nil, sessions, "test-secret", "ole-test")
	a, err := auth.Register("salt-a@example.com", "same secret")
	if err != nil {
		t.Fatal(err)
	}
	b, err := auth.Register("salt-b@example.com", "same secret")
	if err != nil || a.PasswordHash == b.PasswordHash {
		t.Fatal("equal passwords do not have independent salts")
	}
	legacy := &domain.User{ID: domain.UserID{Value: "legacy"}, Email: "legacy@example.com", PasswordHash: postgresLegacyPassword("old"), Status: domain.UserStatusActive}
	if err := users.Create(legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Login(legacy.Email, "wrong", domain.SessionMetadata{}); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatal("wrong password accepted")
	}
	stored, err := users.FindByID(legacy.ID)
	if err != nil || *stored != *legacy {
		t.Fatal("wrong password changed legacy user")
	}
	if _, err := auth.Login(legacy.Email, "old", domain.SessionMetadata{}); err != nil {
		t.Fatal(err)
	}
	stored, err = users.FindByID(legacy.ID)
	if err != nil || stored.ID != legacy.ID || stored.Email != legacy.Email || stored.Status != legacy.Status {
		t.Fatal("upgrade changed user identity or metadata")
	}
	if valid, upgrade := passwordhash.Verify("old", stored.PasswordHash); !valid || upgrade {
		t.Fatal("legacy hash not upgraded")
	}
	upgraded := stored.PasswordHash
	for _, old := range []string{"wrong", "old"} {
		if err := auth.ChangePassword(legacy.ID, old, ""); !errors.Is(err, domain.ErrInvalidPassword) {
			t.Fatal("empty password accepted")
		}
	}
	stored, err = users.FindByID(legacy.ID)
	if err != nil || stored.PasswordHash != upgraded {
		t.Fatal("invalid change modified storage")
	}
	if err := auth.ChangePassword(legacy.ID, "old", "new"); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Login(legacy.Email, "old", domain.SessionMetadata{}); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatal("old password still accepted")
	}
	if _, err := auth.Login(legacy.Email, "new", domain.SessionMetadata{}); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresPasswordWriteFailureDoesNotIssueSession(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()
	users, sessions := postgres.NewUserRepo(db), postgres.NewSessionRepo(db)
	auth := domain.NewAuthService(users, nil, sessions, "test-secret", "ole-test")
	legacy := &domain.User{ID: domain.UserID{Value: "legacy"}, Email: "failure@example.com", PasswordHash: postgresLegacyPassword("old"), Status: domain.UserStatusActive}
	if err := users.Create(legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE FUNCTION reject_password_write() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'forced password write failure'; END $$;
		CREATE TRIGGER reject_password_write BEFORE UPDATE OF password_hash ON users
		FOR EACH ROW EXECUTE FUNCTION reject_password_write()`); err != nil {
		t.Fatal(err)
	}
	if session, err := auth.Login(legacy.Email, "old", domain.SessionMetadata{}); session != nil || !errors.Is(err, domain.ErrPasswordStorage) {
		t.Fatal("failed migration returned success")
	}
	if err := auth.ChangePassword(legacy.ID, "old", "new"); !errors.Is(err, domain.ErrPasswordStorage) {
		t.Fatal("failed password change returned success")
	}
	stored, err := users.FindByID(legacy.ID)
	if err != nil || *stored != *legacy {
		t.Fatal("failed writes changed user")
	}
	if _, total, err := sessions.ListByUserID(legacy.ID, 10, 0); err != nil || total != 0 {
		t.Fatal("failed migration published a session")
	}
	if _, err := db.Exec(`DROP TRIGGER reject_password_write ON users; DROP FUNCTION reject_password_write()`); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Login(legacy.Email, "old", domain.SessionMetadata{}); err != nil {
		t.Fatal("retry after storage recovery failed")
	}
	if err := auth.ChangePassword(legacy.ID, "old", "new"); err != nil {
		t.Fatal("password change retry failed")
	}
}

func TestPostgresConcurrentPasswordMigrationAndChange(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()
	db.SetMaxOpenConns(4)
	users, sessions := postgres.NewUserRepo(db), postgres.NewSessionRepo(db)
	a := domain.NewAuthService(users, nil, sessions, "test-secret", "ole-test")
	b := domain.NewAuthService(users, nil, sessions, "test-secret", "ole-test")
	for i := range 20 {
		user := &domain.User{ID: domain.UserID{Value: fmt.Sprintf("race-%d", i)}, Email: fmt.Sprintf("race-%d@example.com", i), PasswordHash: postgresLegacyPassword("old"), Status: domain.UserStatusActive}
		if err := users.Create(user); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		loginResult, changeResult := make(chan error, 1), make(chan error, 1)
		go func() { <-start; _, err := a.Login(user.Email, "old", domain.SessionMetadata{}); loginResult <- err }()
		go func() { <-start; changeResult <- b.ChangePassword(user.ID, "old", "new") }()
		close(start)
		if err := <-loginResult; err != nil && !errors.Is(err, domain.ErrInvalidCredentials) {
			t.Fatal(err)
		}
		changeErr := <-changeResult
		if errors.Is(changeErr, domain.ErrInvalidPassword) {
			// A concurrent upgrade changed the verified hash. A normal retry
			// verifies the current record before applying the requested change.
			changeErr = b.ChangePassword(user.ID, "old", "new")
		}
		if changeErr != nil {
			t.Fatal(changeErr)
		}
		if _, err := a.Login(user.Email, "old", domain.SessionMetadata{}); !errors.Is(err, domain.ErrInvalidCredentials) {
			t.Fatal("stale migration restored the replaced password")
		}
		if _, err := a.Login(user.Email, "new", domain.SessionMetadata{}); err != nil {
			t.Fatal("winning password was lost")
		}
		stored, err := users.FindByID(user.ID)
		if err != nil || stored.Email != user.Email || stored.Status != user.Status {
			t.Fatal("password update modified other user fields")
		}
	}
	t.Log("postgres_password_migration_vs_change_races=20 restored_old_passwords=0 winning_passwords_preserved=20")
}
