package httpapi

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"Ole/internal/store/postgres"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestAuthRateLimiterSharesAttemptsAcrossInstancesWithSharedStore(t *testing.T) {
	store := newMemoryAuthRateLimitStore()
	first := newAuthRateLimiterWithStore(store)
	second := newAuthRateLimiterWithStore(store)
	now := time.Unix(100, 0)
	key := "127.0.0.1:login"

	_, allowed, err := first.Allow(context.Background(), key, now)
	if err != nil {
		t.Fatalf("allow before failures: %v", err)
	}
	if !allowed {
		t.Fatalf("expected first limiter to allow before failures")
	}

	for i := 0; i < 3; i++ {
		if _, err := first.RegisterFailure(context.Background(), key, now); err != nil {
			t.Fatalf("register failure %d: %v", i, err)
		}
	}

	_, allowed, err = second.Allow(context.Background(), key, now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("shared allow after failures: %v", err)
	}
	if allowed {
		t.Fatalf("expected second limiter instance to observe shared block state")
	}

	if err := second.RegisterSuccess(context.Background(), key, now); err != nil {
		t.Fatalf("register success: %v", err)
	}
	_, allowed, err = first.Allow(context.Background(), key, now.Add(31*time.Second))
	if err != nil {
		t.Fatalf("allow after success: %v", err)
	}
	if !allowed {
		t.Fatalf("expected success on second limiter to clear shared state for first limiter")
	}
}

func TestPostgresAuthRateLimiterSharesAttemptsAcrossInstances(t *testing.T) {
	db, cleanup := openRateLimiterIntegrationDB(t)
	defer cleanup()

	first := newAuthRateLimiterWithDB(db)
	second := newAuthRateLimiterWithDB(db)
	now := time.Unix(200, 0)
	key := "127.0.0.1:refresh"

	for i := 0; i < 3; i++ {
		if _, err := first.RegisterFailure(context.Background(), key, now); err != nil {
			t.Fatalf("register failure %d: %v", i, err)
		}
	}

	_, allowed, err := second.Allow(context.Background(), key, now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("allow through second limiter: %v", err)
	}
	if allowed {
		t.Fatalf("expected second limiter instance to observe postgres-backed block state")
	}

	if err := second.RegisterSuccess(context.Background(), key, now); err != nil {
		t.Fatalf("register success through second limiter: %v", err)
	}
	_, allowed, err = first.Allow(context.Background(), key, now.Add(31*time.Second))
	if err != nil {
		t.Fatalf("allow through first limiter after success: %v", err)
	}
	if !allowed {
		t.Fatalf("expected postgres-backed success to clear shared state across limiter instances")
	}
}

func TestAuthRateLimiterSnapshotAggregatesTrackedKeys(t *testing.T) {
	store := newMemoryAuthRateLimitStore()
	limiter := newAuthRateLimiterWithStore(store)
	now := time.Unix(300, 0)

	if _, err := limiter.RegisterFailure(context.Background(), "198.51.100.10:login", now); err != nil {
		t.Fatalf("register login failure: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := limiter.RegisterFailure(context.Background(), "198.51.100.11:refresh", now); err != nil {
			t.Fatalf("register refresh failure %d: %v", i, err)
		}
	}

	snapshot, err := limiter.Snapshot(context.Background(), now)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snapshot.TrackedKeys != 2 || snapshot.LoginKeys != 1 || snapshot.RefreshKeys != 1 {
		t.Fatalf("unexpected tracked-key snapshot: %#v", snapshot)
	}
	if snapshot.BlockedKeys != 1 || snapshot.MaxFailures != 3 || snapshot.LastUpdatedAtUnix != now.Unix() {
		t.Fatalf("unexpected blocking snapshot: %#v", snapshot)
	}
}

func openRateLimiterIntegrationDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()

	adminDSN := strings.TrimSpace(os.Getenv("OLE_TEST_DATABASE_URL"))
	if adminDSN == "" {
		adminDSN = strings.TrimSpace(os.Getenv("OLE_DATABASE_URL"))
	}
	if adminDSN == "" {
		adminDSN = "postgres://postgres:postgres@localhost:5432/ole?sslmode=disable"
	}

	adminDB, err := sql.Open("pgx", adminDSN)
	if err != nil {
		t.Fatalf("open postgres admin connection: %v", err)
	}
	if err := postgres.Ping(adminDB); err != nil {
		_ = adminDB.Close()
		t.Skipf("postgres integration test skipped: %v", err)
	}

	schemaName := fmt.Sprintf("ole_httpapi_test_%d", time.Now().UnixNano())
	if _, err := adminDB.ExecContext(context.Background(), "CREATE SCHEMA "+schemaName); err != nil {
		_ = adminDB.Close()
		t.Fatalf("create test schema %s: %v", schemaName, err)
	}

	testDSN := withRateLimiterSearchPath(adminDSN, schemaName)
	testDB, err := sql.Open("pgx", testDSN)
	if err != nil {
		_, _ = adminDB.ExecContext(context.Background(), "DROP SCHEMA "+schemaName+" CASCADE")
		_ = adminDB.Close()
		t.Fatalf("open postgres test connection: %v", err)
	}
	testDB.SetMaxOpenConns(1)

	if err := postgres.RunMigrations(context.Background(), testDB, rateLimiterMigrationsDir(t)); err != nil {
		_ = testDB.Close()
		_, _ = adminDB.ExecContext(context.Background(), "DROP SCHEMA "+schemaName+" CASCADE")
		_ = adminDB.Close()
		t.Fatalf("run migrations: %v", err)
	}

	cleanup := func() {
		_ = testDB.Close()
		_, _ = adminDB.ExecContext(context.Background(), "DROP SCHEMA "+schemaName+" CASCADE")
		_ = adminDB.Close()
	}
	return testDB, cleanup
}

func withRateLimiterSearchPath(dsn, schemaName string) string {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}

	query := parsed.Query()
	searchPathOption := "-csearch_path=" + schemaName
	if existing := strings.TrimSpace(query.Get("options")); existing != "" {
		query.Set("options", existing+" "+searchPathOption)
	} else {
		query.Set("options", searchPathOption)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func rateLimiterMigrationsDir(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve current file for migrations path")
	}
	return filepath.Join(filepath.Dir(file), "..", "store", "postgres", "migrations")
}
