package httpapi

import (
	"context"
	"testing"
	"time"
)

func TestAuthAbuseMonitorSharesAlertsAcrossInstancesWithSharedStore(t *testing.T) {
	store := newMemoryAuthAbuseStore()
	first := newAuthAbuseMonitorWithStore(store)
	second := newAuthAbuseMonitorWithStore(store)
	now := time.Unix(100, 0)
	key := "127.0.0.1:login"

	attempt := authAttempt{failures: 3, blockedUntilUnix: now.Add(time.Minute).Unix(), updatedAtUnix: now.Unix()}
	first.ObserveFailure(context.Background(), key, attempt, now)

	snapshot, err := second.Snapshot(context.Background(), now)
	if err != nil {
		t.Fatalf("snapshot after failure alert: %v", err)
	}
	if snapshot.ActiveAlerts != 1 || snapshot.WarningAlerts != 1 || snapshot.LoginAlerts != 1 {
		t.Fatalf("unexpected snapshot after warning alert: %+v", snapshot)
	}

	second.ObserveDenied(context.Background(), key, attempt, now.Add(30*time.Second))
	snapshot, err = first.Snapshot(context.Background(), now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("snapshot after denied attempt: %v", err)
	}
	if snapshot.TotalDeniedRequests != 1 || snapshot.BlockedKeys != 1 {
		t.Fatalf("expected denied and blocked counts after denied attempt, got %+v", snapshot)
	}

	first.Resolve(context.Background(), key, now.Add(2*time.Minute))
	snapshot, err = second.Snapshot(context.Background(), now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("snapshot after resolve: %v", err)
	}
	if snapshot.ActiveAlerts != 0 {
		t.Fatalf("expected resolved abuse alert to disappear, got %+v", snapshot)
	}
}

func TestPostgresAuthAbuseMonitorSharesAlertsAcrossInstances(t *testing.T) {
	db, cleanup := openRateLimiterIntegrationDB(t)
	defer cleanup()

	first := newAuthAbuseMonitorWithDB(db)
	second := newAuthAbuseMonitorWithDB(db)
	now := time.Unix(200, 0)
	key := "127.0.0.1:refresh"
	attempt := authAttempt{failures: 6, blockedUntilUnix: now.Add(5 * time.Minute).Unix(), updatedAtUnix: now.Unix()}

	first.ObserveFailure(context.Background(), key, attempt, now)
	second.ObserveDenied(context.Background(), key, attempt, now.Add(10*time.Second))

	snapshot, err := first.Snapshot(context.Background(), now.Add(10*time.Second))
	if err != nil {
		t.Fatalf("postgres snapshot: %v", err)
	}
	if snapshot.ActiveAlerts != 1 || snapshot.RefreshAlerts != 1 || snapshot.ElevatedAlerts != 1 {
		t.Fatalf("unexpected postgres abuse snapshot: %+v", snapshot)
	}
	if snapshot.TotalDeniedRequests != 1 {
		t.Fatalf("expected denied request to be shared through postgres-backed store, got %+v", snapshot)
	}
}
