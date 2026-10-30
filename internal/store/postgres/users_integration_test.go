package postgres_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/postgres"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestPostgresUserCreateRejectsConflictsWithoutOverwriting(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()
	repo := postgres.NewUserRepo(db)
	original := &domain.User{ID: domain.UserID{Value: "usr-1"}, Email: "owner@example.com", PasswordHash: "original", Status: domain.UserStatusActive}
	if err := repo.Create(original); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, id, email string }{
		{"same ID", "usr-1", "other@example.com"},
		{"same email", "usr-other", "OWNER@EXAMPLE.COM"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conflict := &domain.User{ID: domain.UserID{Value: tc.id}, Email: tc.email, PasswordHash: "replacement", Status: domain.UserStatusBanned}
			if err := repo.Create(conflict); !errors.Is(err, domain.ErrAlreadyExists) {
				t.Fatalf("create conflict: got %v, want ErrAlreadyExists", err)
			}
			stored, err := repo.FindByID(original.ID)
			if err != nil || stored == nil || *stored != *original {
				t.Fatalf("original user changed: %#v, %v", stored, err)
			}
		})
	}
	original.PasswordHash = "updated"
	if err := repo.Save(original); err != nil {
		t.Fatal(err)
	}
	stored, err := repo.FindByID(original.ID)
	if err != nil || stored == nil || *stored != *original {
		t.Fatalf("legacy ID update failed: %#v, %v", stored, err)
	}
}

func TestPostgresRegistrationsSurviveProcessRestart(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()
	var schema string
	if err := db.QueryRow("SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	adminDSN := strings.TrimSpace(os.Getenv("OLE_TEST_DATABASE_URL"))
	if adminDSN == "" {
		adminDSN = strings.TrimSpace(os.Getenv("OLE_DATABASE_URL"))
	}
	if adminDSN == "" {
		adminDSN = "postgres://postgres:postgres@localhost:5432/ole?sslmode=disable"
	}
	testDSN := withSearchPath(adminDSN, schema)
	registerInProcess := func(email string) domain.UserID {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPostgresRegistrationProcessHelper$")
		cmd.Env = append(os.Environ(), "OLE_REGISTRATION_PROCESS_DSN="+testDSN, "OLE_REGISTRATION_PROCESS_EMAIL="+email)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("registration process failed: %v: %s", err, output)
		}
		var id string
		if err := json.Unmarshal(output, &id); err != nil || id == "" {
			t.Fatalf("decode registration ID: %v", err)
		}
		return domain.UserID{Value: id}
	}
	firstID := registerInProcess("first@example.com")
	repo := postgres.NewUserRepo(db)
	first, err := repo.FindByID(firstID)
	if err != nil || first == nil {
		t.Fatalf("read first user: %#v, %v", first, err)
	}
	networkRepo := postgres.NewNetworkRepo(db)
	networks := domain.NewNetworkService(networkRepo, postgres.NewInviteRepo(db), nil)
	network, err := networks.CreateNetwork(firstID, "existing network", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatal(err)
	}
	secondID := registerInProcess("second@example.com")
	if secondID == firstID {
		t.Fatal("independent registration processes reused a user ID")
	}
	stored, err := repo.FindByID(firstID)
	if err != nil || stored == nil || *stored != *first {
		t.Fatalf("first user changed after restart: %#v, %v", stored, err)
	}
	storedNetwork, err := networkRepo.FindByID(network.ID)
	if err != nil || storedNetwork == nil || storedNetwork.OwnerID != firstID || !storedNetwork.HasMember(firstID) {
		t.Fatalf("first user's network ownership changed: %#v, %v", storedNetwork, err)
	}
}

func TestPostgresRegistrationProcessHelper(t *testing.T) {
	dsn := os.Getenv("OLE_REGISTRATION_PROCESS_DSN")
	if dsn == "" {
		return
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	auth := domain.NewAuthService(postgres.NewUserRepo(db), nil, nil, "test-secret", "ole-test")
	user, err := auth.Register(os.Getenv("OLE_REGISTRATION_PROCESS_EMAIL"), "secret")
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(user.ID.String()); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
