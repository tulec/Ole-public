package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"
)

const (
	authRateLimitCleanupEvery   = time.Minute
	authRateLimitRetention      = 24 * time.Hour
	authRateLimitBlockThreshold = 3
)

type authAttempt struct {
	failures         int
	blockedUntilUnix int64
	updatedAtUnix    int64
}

type authRateLimitSnapshot struct {
	TrackedKeys       int
	BlockedKeys       int
	LoginKeys         int
	RefreshKeys       int
	MaxFailures       int
	LastUpdatedAtUnix int64
}

type authRateLimitStore interface {
	Allow(ctx context.Context, key string, now time.Time) (authAttempt, bool, error)
	RegisterFailure(ctx context.Context, key string, now time.Time) (authAttempt, error)
	RegisterSuccess(ctx context.Context, key string) error
	DeleteStale(ctx context.Context, staleBeforeUnix, nowUnix int64) error
	Snapshot(ctx context.Context, nowUnix int64) (authRateLimitSnapshot, error)
}

type authRateLimiter struct {
	store         authRateLimitStore
	cleanupMu     sync.Mutex
	lastCleanupAt time.Time
	cleanupEvery  time.Duration
	retention     time.Duration
}

func newAuthRateLimiter() *authRateLimiter {
	return newAuthRateLimiterWithStore(newMemoryAuthRateLimitStore())
}

func newAuthRateLimiterWithDB(db *sql.DB) *authRateLimiter {
	if db == nil {
		return newAuthRateLimiter()
	}
	return newAuthRateLimiterWithStore(newPostgresAuthRateLimitStore(db))
}

func newAuthRateLimiterWithStore(store authRateLimitStore) *authRateLimiter {
	return &authRateLimiter{
		store:        store,
		cleanupEvery: authRateLimitCleanupEvery,
		retention:    authRateLimitRetention,
	}
}

func (l *authRateLimiter) Allow(ctx context.Context, key string, now time.Time) (authAttempt, bool, error) {
	if l == nil || l.store == nil {
		return authAttempt{}, true, nil
	}
	if err := l.cleanupIfDue(ctx, now); err != nil {
		return authAttempt{}, false, err
	}
	return l.store.Allow(ctx, key, now)
}

func (l *authRateLimiter) RegisterFailure(ctx context.Context, key string, now time.Time) (authAttempt, error) {
	if l == nil || l.store == nil {
		return authAttempt{}, nil
	}
	if err := l.cleanupIfDue(ctx, now); err != nil {
		return authAttempt{}, err
	}
	return l.store.RegisterFailure(ctx, key, now)
}

func (l *authRateLimiter) RegisterSuccess(ctx context.Context, key string, now time.Time) error {
	if l == nil || l.store == nil {
		return nil
	}
	if err := l.cleanupIfDue(ctx, now); err != nil {
		return err
	}
	return l.store.RegisterSuccess(ctx, key)
}

func (l *authRateLimiter) cleanupIfDue(ctx context.Context, now time.Time) error {
	if l.cleanupEvery <= 0 || l.retention <= 0 {
		return nil
	}
	l.cleanupMu.Lock()
	defer l.cleanupMu.Unlock()
	if !l.lastCleanupAt.IsZero() && now.Sub(l.lastCleanupAt) < l.cleanupEvery {
		return nil
	}
	staleBeforeUnix := now.Add(-l.retention).Unix()
	if err := l.store.DeleteStale(ctx, staleBeforeUnix, now.Unix()); err != nil {
		return err
	}
	l.lastCleanupAt = now
	return nil
}

func (l *authRateLimiter) Snapshot(ctx context.Context, now time.Time) (authRateLimitSnapshot, error) {
	if l == nil || l.store == nil {
		return authRateLimitSnapshot{}, nil
	}
	if err := l.cleanupIfDue(ctx, now); err != nil {
		return authRateLimitSnapshot{}, err
	}
	return l.store.Snapshot(ctx, now.Unix())
}

type memoryAuthRateLimitStore struct {
	mu       sync.Mutex
	attempts map[string]authAttempt
}

func newMemoryAuthRateLimitStore() *memoryAuthRateLimitStore {
	return &memoryAuthRateLimitStore{attempts: map[string]authAttempt{}}
}

func (s *memoryAuthRateLimitStore) Allow(_ context.Context, key string, now time.Time) (authAttempt, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	attempt, ok := s.attempts[key]
	if !ok {
		return authAttempt{}, true, nil
	}
	return attempt, attempt.blockedUntilUnix <= now.Unix(), nil
}

func (s *memoryAuthRateLimitStore) RegisterFailure(_ context.Context, key string, now time.Time) (authAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	attempt := s.attempts[key]
	attempt.failures++
	attempt.blockedUntilUnix = blockedUntilUnixForFailures(attempt.failures, now)
	attempt.updatedAtUnix = now.Unix()
	s.attempts[key] = attempt
	return attempt, nil
}

func (s *memoryAuthRateLimitStore) RegisterSuccess(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.attempts, key)
	return nil
}

func (s *memoryAuthRateLimitStore) DeleteStale(_ context.Context, staleBeforeUnix, nowUnix int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, attempt := range s.attempts {
		if attempt.updatedAtUnix <= staleBeforeUnix && attempt.blockedUntilUnix <= nowUnix {
			delete(s.attempts, key)
		}
	}
	return nil
}

func (s *memoryAuthRateLimitStore) Snapshot(_ context.Context, nowUnix int64) (authRateLimitSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return aggregateAuthRateLimitSnapshot(s.attempts, nowUnix), nil
}

type postgresAuthRateLimitStore struct {
	db *sql.DB
}

func newPostgresAuthRateLimitStore(db *sql.DB) *postgresAuthRateLimitStore {
	return &postgresAuthRateLimitStore{db: db}
}

func (s *postgresAuthRateLimitStore) Allow(ctx context.Context, key string, now time.Time) (authAttempt, bool, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT failures, blocked_until_unix, updated_at_unix
		FROM auth_rate_limits
		WHERE attempt_key = $1
	`, key)
	var attempt authAttempt
	if err := row.Scan(&attempt.failures, &attempt.blockedUntilUnix, &attempt.updatedAtUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return authAttempt{}, true, nil
		}
		return authAttempt{}, false, err
	}
	return attempt, attempt.blockedUntilUnix <= now.Unix(), nil
}

func (s *postgresAuthRateLimitStore) RegisterFailure(ctx context.Context, key string, now time.Time) (authAttempt, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return authAttempt{}, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	attempt := authAttempt{}
	row := tx.QueryRowContext(ctx, `
		SELECT failures, blocked_until_unix, updated_at_unix
		FROM auth_rate_limits
		WHERE attempt_key = $1
		FOR UPDATE
	`, key)
	switch scanErr := row.Scan(&attempt.failures, &attempt.blockedUntilUnix, &attempt.updatedAtUnix); {
	case scanErr == nil:
	case errors.Is(scanErr, sql.ErrNoRows):
	default:
		err = scanErr
		return authAttempt{}, err
	}

	attempt.failures++
	attempt.blockedUntilUnix = blockedUntilUnixForFailures(attempt.failures, now)
	attempt.updatedAtUnix = now.Unix()

	if _, err = tx.ExecContext(ctx, `
		INSERT INTO auth_rate_limits(attempt_key, failures, blocked_until_unix, updated_at_unix)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (attempt_key) DO UPDATE SET
			failures = EXCLUDED.failures,
			blocked_until_unix = EXCLUDED.blocked_until_unix,
			updated_at_unix = EXCLUDED.updated_at_unix
	`, key, attempt.failures, attempt.blockedUntilUnix, attempt.updatedAtUnix); err != nil {
		return authAttempt{}, err
	}

	err = tx.Commit()
	return attempt, err
}

func (s *postgresAuthRateLimitStore) RegisterSuccess(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM auth_rate_limits
		WHERE attempt_key = $1
	`, key)
	return err
}

func (s *postgresAuthRateLimitStore) DeleteStale(ctx context.Context, staleBeforeUnix, nowUnix int64) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM auth_rate_limits
		WHERE updated_at_unix <= $1
		  AND blocked_until_unix <= $2
	`, staleBeforeUnix, nowUnix)
	return err
}

func (s *postgresAuthRateLimitStore) Snapshot(ctx context.Context, nowUnix int64) (authRateLimitSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT attempt_key, failures, blocked_until_unix, updated_at_unix
		FROM auth_rate_limits
	`)
	if err != nil {
		return authRateLimitSnapshot{}, err
	}
	defer rows.Close()

	attempts := map[string]authAttempt{}
	for rows.Next() {
		var (
			key     string
			attempt authAttempt
		)
		if err := rows.Scan(&key, &attempt.failures, &attempt.blockedUntilUnix, &attempt.updatedAtUnix); err != nil {
			return authRateLimitSnapshot{}, err
		}
		attempts[key] = attempt
	}
	if err := rows.Err(); err != nil {
		return authRateLimitSnapshot{}, err
	}
	return aggregateAuthRateLimitSnapshot(attempts, nowUnix), nil
}

func blockedUntilUnixForFailures(failures int, now time.Time) int64 {
	switch {
	case failures >= 10:
		return now.Add(15 * time.Minute).Unix()
	case failures >= 6:
		return now.Add(5 * time.Minute).Unix()
	case failures >= authRateLimitBlockThreshold:
		return now.Add(1 * time.Minute).Unix()
	default:
		return 0
	}
}

func aggregateAuthRateLimitSnapshot(attempts map[string]authAttempt, nowUnix int64) authRateLimitSnapshot {
	snapshot := authRateLimitSnapshot{}
	for key, attempt := range attempts {
		snapshot.TrackedKeys++
		if attempt.blockedUntilUnix > nowUnix {
			snapshot.BlockedKeys++
		}
		switch authAttemptTypeFromKey(key) {
		case "login":
			snapshot.LoginKeys++
		case "refresh":
			snapshot.RefreshKeys++
		}
		if attempt.failures > snapshot.MaxFailures {
			snapshot.MaxFailures = attempt.failures
		}
		if attempt.updatedAtUnix > snapshot.LastUpdatedAtUnix {
			snapshot.LastUpdatedAtUnix = attempt.updatedAtUnix
		}
	}
	return snapshot
}
