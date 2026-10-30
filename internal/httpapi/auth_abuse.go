package httpapi

import (
	"Ole/internal/structuredlog"
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	authAbuseCleanupEvery  = time.Minute
	authAbuseRetention     = 24 * time.Hour
	authAbuseAlertCooldown = 5 * time.Minute
)

type authAbuseSeverity string

const (
	authAbuseSeverityNone     authAbuseSeverity = ""
	authAbuseSeverityWarning  authAbuseSeverity = "warning"
	authAbuseSeverityElevated authAbuseSeverity = "elevated"
	authAbuseSeverityCritical authAbuseSeverity = "critical"
)

type authAbuseRecord struct {
	AttemptKey        string
	AttemptType       string
	Severity          authAbuseSeverity
	FailureCount      int
	DeniedCount       int
	TotalAlerts       int
	FirstDetectedUnix int64
	LastDetectedUnix  int64
	LastAlertedUnix   int64
	BlockedUntilUnix  int64
}

type authAbuseSnapshot struct {
	ActiveAlerts        int
	LoginAlerts         int
	RefreshAlerts       int
	WarningAlerts       int
	ElevatedAlerts      int
	CriticalAlerts      int
	BlockedKeys         int
	TotalAlertEvents    int
	TotalDeniedRequests int
	LastAlertType       string
	LastSeverity        string
	LastAlertedAtUnix   int64
}

type authAbuseStore interface {
	ObserveFailure(ctx context.Context, key string, attempt authAttempt, now time.Time) (authAbuseRecord, bool, error)
	ObserveDenied(ctx context.Context, key string, attempt authAttempt, now time.Time) (authAbuseRecord, bool, error)
	Resolve(ctx context.Context, key string) error
	DeleteStale(ctx context.Context, staleBeforeUnix, nowUnix int64) error
	Snapshot(ctx context.Context, nowUnix int64) (authAbuseSnapshot, error)
}

type authAbuseMonitor struct {
	store         authAbuseStore
	logger        *structuredlog.Logger
	cleanupMu     sync.Mutex
	lastCleanupAt time.Time
	cleanupEvery  time.Duration
	retention     time.Duration
}

func newAuthAbuseMonitor() *authAbuseMonitor {
	return newAuthAbuseMonitorWithStore(newMemoryAuthAbuseStore())
}

func newAuthAbuseMonitorWithDB(db *sql.DB) *authAbuseMonitor {
	if db == nil {
		return newAuthAbuseMonitor()
	}
	return newAuthAbuseMonitorWithStore(newPostgresAuthAbuseStore(db))
}

func newAuthAbuseMonitorWithStore(store authAbuseStore) *authAbuseMonitor {
	return &authAbuseMonitor{
		store:        store,
		logger:       structuredlog.New("server.auth_abuse"),
		cleanupEvery: authAbuseCleanupEvery,
		retention:    authAbuseRetention,
	}
}

func (m *authAbuseMonitor) ObserveFailure(ctx context.Context, key string, attempt authAttempt, now time.Time) {
	if m == nil || m.store == nil {
		return
	}
	if err := m.cleanupIfDue(ctx, now); err != nil {
		m.logError("auth abuse cleanup failed", "error", err)
		return
	}
	record, alerted, err := m.store.ObserveFailure(ctx, key, attempt, now)
	if err != nil {
		m.logError("auth abuse failure observation failed", "error", err, "attemptType", authAttemptTypeFromKey(key), "key", key)
		return
	}
	if alerted {
		m.logInfo("auth abuse alert raised", "attemptType", record.AttemptType, "severity", record.Severity, "failures", record.FailureCount, "denied", record.DeniedCount, "blockedUntilUnix", record.BlockedUntilUnix, "key", record.AttemptKey)
	}
}

func (m *authAbuseMonitor) ObserveDenied(ctx context.Context, key string, attempt authAttempt, now time.Time) {
	if m == nil || m.store == nil {
		return
	}
	if err := m.cleanupIfDue(ctx, now); err != nil {
		m.logError("auth abuse cleanup failed", "error", err)
		return
	}
	record, alerted, err := m.store.ObserveDenied(ctx, key, attempt, now)
	if err != nil {
		m.logError("auth abuse denied observation failed", "error", err, "attemptType", authAttemptTypeFromKey(key), "key", key)
		return
	}
	if alerted {
		m.logInfo("auth abuse alert raised", "attemptType", record.AttemptType, "severity", record.Severity, "failures", record.FailureCount, "denied", record.DeniedCount, "blockedUntilUnix", record.BlockedUntilUnix, "key", record.AttemptKey)
	}
}

func (m *authAbuseMonitor) Resolve(ctx context.Context, key string, now time.Time) {
	if m == nil || m.store == nil {
		return
	}
	if err := m.cleanupIfDue(ctx, now); err != nil {
		m.logError("auth abuse cleanup failed", "error", err)
		return
	}
	if err := m.store.Resolve(ctx, key); err != nil {
		m.logError("auth abuse resolve failed", "error", err, "key", key)
	}
}

func (m *authAbuseMonitor) logInfo(message string, keyvals ...any) {
	if m == nil || m.logger == nil {
		return
	}
	m.logger.Info(message, keyvals...)
}

func (m *authAbuseMonitor) logError(message string, keyvals ...any) {
	if m == nil || m.logger == nil {
		return
	}
	m.logger.Error(message, keyvals...)
}

func (m *authAbuseMonitor) Snapshot(ctx context.Context, now time.Time) (authAbuseSnapshot, error) {
	if m == nil || m.store == nil {
		return authAbuseSnapshot{}, nil
	}
	if err := m.cleanupIfDue(ctx, now); err != nil {
		return authAbuseSnapshot{}, err
	}
	return m.store.Snapshot(ctx, now.Unix())
}

func (m *authAbuseMonitor) cleanupIfDue(ctx context.Context, now time.Time) error {
	if m.cleanupEvery <= 0 || m.retention <= 0 {
		return nil
	}
	m.cleanupMu.Lock()
	defer m.cleanupMu.Unlock()
	if !m.lastCleanupAt.IsZero() && now.Sub(m.lastCleanupAt) < m.cleanupEvery {
		return nil
	}
	staleBeforeUnix := now.Add(-m.retention).Unix()
	if err := m.store.DeleteStale(ctx, staleBeforeUnix, now.Unix()); err != nil {
		return err
	}
	m.lastCleanupAt = now
	return nil
}

type memoryAuthAbuseStore struct {
	mu      sync.Mutex
	records map[string]authAbuseRecord
}

func newMemoryAuthAbuseStore() *memoryAuthAbuseStore {
	return &memoryAuthAbuseStore{records: map[string]authAbuseRecord{}}
}

func (s *memoryAuthAbuseStore) ObserveFailure(_ context.Context, key string, attempt authAttempt, now time.Time) (authAbuseRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, alerted, keep := observeAuthAbuseRecord(s.records[key], key, attempt, now, false)
	if keep {
		s.records[key] = record
	} else {
		delete(s.records, key)
	}
	return record, alerted, nil
}

func (s *memoryAuthAbuseStore) ObserveDenied(_ context.Context, key string, attempt authAttempt, now time.Time) (authAbuseRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, alerted, keep := observeAuthAbuseRecord(s.records[key], key, attempt, now, true)
	if keep {
		s.records[key] = record
	} else {
		delete(s.records, key)
	}
	return record, alerted, nil
}

func (s *memoryAuthAbuseStore) Resolve(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, key)
	return nil
}

func (s *memoryAuthAbuseStore) DeleteStale(_ context.Context, staleBeforeUnix, nowUnix int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, record := range s.records {
		if record.LastDetectedUnix <= staleBeforeUnix && record.BlockedUntilUnix <= nowUnix {
			delete(s.records, key)
		}
	}
	return nil
}

func (s *memoryAuthAbuseStore) Snapshot(_ context.Context, nowUnix int64) (authAbuseSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return aggregateAuthAbuseSnapshot(s.records, nowUnix), nil
}

type postgresAuthAbuseStore struct {
	db *sql.DB
}

func newPostgresAuthAbuseStore(db *sql.DB) *postgresAuthAbuseStore {
	return &postgresAuthAbuseStore{db: db}
}

func (s *postgresAuthAbuseStore) ObserveFailure(ctx context.Context, key string, attempt authAttempt, now time.Time) (authAbuseRecord, bool, error) {
	return s.observe(ctx, key, attempt, now, false)
}

func (s *postgresAuthAbuseStore) ObserveDenied(ctx context.Context, key string, attempt authAttempt, now time.Time) (authAbuseRecord, bool, error) {
	return s.observe(ctx, key, attempt, now, true)
}

func (s *postgresAuthAbuseStore) observe(ctx context.Context, key string, attempt authAttempt, now time.Time, denied bool) (authAbuseRecord, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return authAbuseRecord{}, false, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	record := authAbuseRecord{}
	row := tx.QueryRowContext(ctx, `
		SELECT attempt_key, attempt_type, severity, failure_count, denied_count, total_alerts,
		       first_detected_at_unix, last_detected_at_unix, last_alerted_at_unix, blocked_until_unix
		FROM auth_abuse_alerts
		WHERE attempt_key = $1
		FOR UPDATE
	`, key)
	switch scanErr := row.Scan(&record.AttemptKey, &record.AttemptType, &record.Severity, &record.FailureCount, &record.DeniedCount, &record.TotalAlerts, &record.FirstDetectedUnix, &record.LastDetectedUnix, &record.LastAlertedUnix, &record.BlockedUntilUnix); {
	case scanErr == nil:
	case errors.Is(scanErr, sql.ErrNoRows):
	default:
		err = scanErr
		return authAbuseRecord{}, false, err
	}

	updated, alerted, keep := observeAuthAbuseRecord(record, key, attempt, now, denied)
	if keep {
		if _, err = tx.ExecContext(ctx, `
			INSERT INTO auth_abuse_alerts(
				attempt_key, attempt_type, severity, failure_count, denied_count, total_alerts,
				first_detected_at_unix, last_detected_at_unix, last_alerted_at_unix, blocked_until_unix
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (attempt_key) DO UPDATE SET
				attempt_type = EXCLUDED.attempt_type,
				severity = EXCLUDED.severity,
				failure_count = EXCLUDED.failure_count,
				denied_count = EXCLUDED.denied_count,
				total_alerts = EXCLUDED.total_alerts,
				first_detected_at_unix = EXCLUDED.first_detected_at_unix,
				last_detected_at_unix = EXCLUDED.last_detected_at_unix,
				last_alerted_at_unix = EXCLUDED.last_alerted_at_unix,
				blocked_until_unix = EXCLUDED.blocked_until_unix
		`, updated.AttemptKey, updated.AttemptType, string(updated.Severity), updated.FailureCount, updated.DeniedCount, updated.TotalAlerts, updated.FirstDetectedUnix, updated.LastDetectedUnix, updated.LastAlertedUnix, updated.BlockedUntilUnix); err != nil {
			return authAbuseRecord{}, false, err
		}
	} else {
		if _, err = tx.ExecContext(ctx, `
			DELETE FROM auth_abuse_alerts WHERE attempt_key = $1
		`, key); err != nil {
			return authAbuseRecord{}, false, err
		}
	}

	err = tx.Commit()
	return updated, alerted, err
}

func (s *postgresAuthAbuseStore) Resolve(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM auth_abuse_alerts
		WHERE attempt_key = $1
	`, key)
	return err
}

func (s *postgresAuthAbuseStore) DeleteStale(ctx context.Context, staleBeforeUnix, nowUnix int64) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM auth_abuse_alerts
		WHERE last_detected_at_unix <= $1
		  AND blocked_until_unix <= $2
	`, staleBeforeUnix, nowUnix)
	return err
}

func (s *postgresAuthAbuseStore) Snapshot(ctx context.Context, nowUnix int64) (authAbuseSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT attempt_key, attempt_type, severity, failure_count, denied_count, total_alerts,
		       first_detected_at_unix, last_detected_at_unix, last_alerted_at_unix, blocked_until_unix
		FROM auth_abuse_alerts
	`)
	if err != nil {
		return authAbuseSnapshot{}, err
	}
	defer rows.Close()

	records := make(map[string]authAbuseRecord)
	for rows.Next() {
		record := authAbuseRecord{}
		var severity string
		if err := rows.Scan(&record.AttemptKey, &record.AttemptType, &severity, &record.FailureCount, &record.DeniedCount, &record.TotalAlerts, &record.FirstDetectedUnix, &record.LastDetectedUnix, &record.LastAlertedUnix, &record.BlockedUntilUnix); err != nil {
			return authAbuseSnapshot{}, err
		}
		record.Severity = authAbuseSeverity(severity)
		records[record.AttemptKey] = record
	}
	if err := rows.Err(); err != nil {
		return authAbuseSnapshot{}, err
	}
	return aggregateAuthAbuseSnapshot(records, nowUnix), nil
}

func observeAuthAbuseRecord(record authAbuseRecord, key string, attempt authAttempt, now time.Time, denied bool) (authAbuseRecord, bool, bool) {
	record.AttemptKey = key
	if record.AttemptType == "" {
		record.AttemptType = authAttemptTypeFromKey(key)
	}
	record.FailureCount = attempt.failures
	record.BlockedUntilUnix = attempt.blockedUntilUnix
	if denied {
		record.DeniedCount++
	}
	severity := authAbuseSeverityForAttempt(attempt.failures, record.DeniedCount)
	if severity == authAbuseSeverityNone {
		return record, false, false
	}
	nowUnix := now.Unix()
	if record.FirstDetectedUnix == 0 {
		record.FirstDetectedUnix = nowUnix
	}
	record.LastDetectedUnix = nowUnix
	previousSeverity := record.Severity
	record.Severity = severity
	alerted := shouldAlertAuthAbuse(previousSeverity, record.LastAlertedUnix, severity, nowUnix)
	if alerted {
		record.TotalAlerts++
		record.LastAlertedUnix = nowUnix
	}
	return record, alerted, true
}

func authAttemptTypeFromKey(key string) string {
	idx := strings.LastIndex(key, ":")
	if idx < 0 || idx == len(key)-1 {
		return "unknown"
	}
	return key[idx+1:]
}

func authAbuseSeverityForAttempt(failures, deniedCount int) authAbuseSeverity {
	switch {
	case failures >= 10 || deniedCount >= 5:
		return authAbuseSeverityCritical
	case failures >= 6 || deniedCount >= 2:
		return authAbuseSeverityElevated
	case failures >= authRateLimitBlockThreshold:
		return authAbuseSeverityWarning
	default:
		return authAbuseSeverityNone
	}
}

func shouldAlertAuthAbuse(previous authAbuseSeverity, lastAlertedUnix int64, current authAbuseSeverity, nowUnix int64) bool {
	if current == authAbuseSeverityNone {
		return false
	}
	if lastAlertedUnix == 0 {
		return true
	}
	if authAbuseSeverityRank(current) > authAbuseSeverityRank(previous) {
		return true
	}
	return nowUnix-lastAlertedUnix >= int64(authAbuseAlertCooldown/time.Second)
}

func authAbuseSeverityRank(severity authAbuseSeverity) int {
	switch severity {
	case authAbuseSeverityCritical:
		return 3
	case authAbuseSeverityElevated:
		return 2
	case authAbuseSeverityWarning:
		return 1
	default:
		return 0
	}
}

func aggregateAuthAbuseSnapshot(records map[string]authAbuseRecord, nowUnix int64) authAbuseSnapshot {
	snapshot := authAbuseSnapshot{}
	for _, record := range records {
		snapshot.ActiveAlerts++
		snapshot.TotalAlertEvents += record.TotalAlerts
		snapshot.TotalDeniedRequests += record.DeniedCount
		if record.BlockedUntilUnix > nowUnix {
			snapshot.BlockedKeys++
		}
		switch record.AttemptType {
		case "login":
			snapshot.LoginAlerts++
		case "refresh":
			snapshot.RefreshAlerts++
		}
		switch record.Severity {
		case authAbuseSeverityWarning:
			snapshot.WarningAlerts++
		case authAbuseSeverityElevated:
			snapshot.ElevatedAlerts++
		case authAbuseSeverityCritical:
			snapshot.CriticalAlerts++
		}
		if record.LastAlertedUnix >= snapshot.LastAlertedAtUnix {
			snapshot.LastAlertedAtUnix = record.LastAlertedUnix
			snapshot.LastAlertType = record.AttemptType
			snapshot.LastSeverity = string(record.Severity)
		}
	}
	return snapshot
}
