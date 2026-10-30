package postgres

import (
	"Ole/internal/domain"
	"context"
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

type sessionExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func insertSession(executor sessionExecutor, session *domain.SessionToken) error {
	_, err := executor.ExecContext(context.Background(), `
		INSERT INTO session_tokens(id, family_id, access_token, refresh_token, user_id, device_name, ip, user_agent, last_used_at_unix, expires_at_unix, replaced_by_token, revoked_at_unix, reuse_detected_at_unix)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
	`, session.ID, session.FamilyID, session.AccessToken, session.RefreshToken, session.UserID.String(), session.DeviceName, session.IP, session.UserAgent, session.LastUsedAtUnix, session.ExpiresAtUnix, session.ReplacedByToken, session.RevokedAtUnix, session.ReuseDetectedAtUnix)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return domain.ErrAlreadyExists
	}
	return err
}

func (r *SessionRepo) Create(session *domain.SessionToken) error { return insertSession(r.db, session) }

// Retained for explicit metadata updates. Security fields are monotonic: a stale
// object can never clear revocation/reuse or a previously recorded replacement.
func (r *SessionRepo) Update(session *domain.SessionToken) error {
	result, err := r.db.ExecContext(context.Background(), `
		UPDATE session_tokens
		SET device_name=$1, ip=$2, user_agent=$3, last_used_at_unix=$4, expires_at_unix=$5,
		    replaced_by_token=CASE WHEN replaced_by_token='' THEN $6 ELSE replaced_by_token END,
		    revoked_at_unix=GREATEST(revoked_at_unix,$7), reuse_detected_at_unix=GREATEST(reuse_detected_at_unix,$8)
		WHERE id=$9 AND access_token=$10 AND refresh_token=$11 AND user_id=$12 AND family_id=$13
	`, session.DeviceName, session.IP, session.UserAgent, session.LastUsedAtUnix, session.ExpiresAtUnix, session.ReplacedByToken, session.RevokedAtUnix, session.ReuseDetectedAtUnix, session.ID, session.AccessToken, session.RefreshToken, session.UserID.String(), session.FamilyID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *SessionRepo) TouchLastUsed(accessToken string, nowUnix int64) (bool, error) {
	result, err := r.db.ExecContext(context.Background(), `
		UPDATE session_tokens SET last_used_at_unix=GREATEST(last_used_at_unix,$2)
		WHERE access_token=$1 AND revoked_at_unix=0 AND reuse_detected_at_unix=0
		  AND replaced_by_token='' AND expires_at_unix>$2
	`, accessToken, nowUnix)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

func (r *SessionRepo) Rotate(refreshToken string, next *domain.SessionToken, nowUnix int64) error {
	if next == nil {
		return domain.ErrUnauthorized
	}
	tx, err := r.db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Every family/user revoke locks the same user row before changing sessions.
	// This also prevents a revoke query from missing a concurrently inserted child.
	var lockedUser string
	if err := tx.QueryRow(`SELECT id FROM users WHERE id=$1 FOR UPDATE`, next.UserID.String()).Scan(&lockedUser); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ErrUnauthorized
		}
		return err
	}
	old, err := scanSession(tx.QueryRow(`
		SELECT id,user_id,family_id,access_token,refresh_token,device_name,ip,user_agent,last_used_at_unix,expires_at_unix,replaced_by_token,revoked_at_unix,reuse_detected_at_unix
		FROM session_tokens WHERE refresh_token=$1 FOR UPDATE
	`, refreshToken))
	if err != nil {
		return err
	}
	if !old.CanRotateTo(next, nowUnix) {
		return domain.ErrUnauthorized
	}
	if _, err := tx.Exec(`UPDATE session_tokens SET revoked_at_unix=$2,replaced_by_token=$3 WHERE refresh_token=$1`, refreshToken, nowUnix, next.RefreshToken); err != nil {
		return err
	}
	if err := insertSession(tx, next); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *SessionRepo) RevokeBySessionID(userID domain.UserID, sessionID string, nowUnix int64) error {
	if sessionID == "" {
		return domain.ErrNotFound
	}
	tx, err := r.db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Resolve history and revoke under the same user lock as Rotate. The UPDATE
	// must include user_id: legacy family IDs can also collide across users.
	var lockedUser string
	if err := tx.QueryRow(`SELECT id FROM users WHERE id=$1 FOR UPDATE`, userID.String()).Scan(&lockedUser); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ErrNotFound
		}
		return err
	}
	var familyID sql.NullString
	var familyCount int
	if err := tx.QueryRow(`SELECT MIN(family_id),COUNT(DISTINCT family_id)
		FROM session_tokens WHERE user_id=$1 AND id=$2`, userID.String(), sessionID).Scan(&familyID, &familyCount); err != nil {
		return err
	}
	if familyCount != 1 || !familyID.Valid || familyID.String == "" {
		return domain.ErrNotFound
	}
	if _, err := tx.Exec(`UPDATE session_tokens SET revoked_at_unix=GREATEST(revoked_at_unix,$3)
		WHERE user_id=$1 AND family_id=$2`, userID.String(), familyID.String, nowUnix); err != nil {
		return err
	}
	return tx.Commit()
}

// column is selected only by the fixed wrappers below, never from user input.
func (r *SessionRepo) revokeSessions(column, key string, nowUnix int64, reuse bool, replacement, ownerID string) error {
	tx, err := r.db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT id FROM users WHERE id IN
		(SELECT user_id FROM session_tokens WHERE `+column+`=$1 AND ($2='' OR user_id=$2))
		ORDER BY id FOR UPDATE`, key, ownerID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
	}
	rowErr := rows.Err()
	closeErr := rows.Close()
	if rowErr != nil {
		return rowErr
	}
	if closeErr != nil {
		return closeErr
	}
	_, err = tx.Exec(`UPDATE session_tokens
		SET revoked_at_unix=GREATEST(revoked_at_unix,$2),
		    reuse_detected_at_unix=CASE WHEN $3 THEN GREATEST(reuse_detected_at_unix,$2) ELSE reuse_detected_at_unix END,
		    replaced_by_token=CASE WHEN replaced_by_token='' THEN $4 ELSE replaced_by_token END
		WHERE `+column+`=$1 AND ($5='' OR user_id=$5)`, key, nowUnix, reuse, replacement, ownerID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *SessionRepo) RevokeByAccessToken(token string, nowUnix int64) error {
	return r.revokeSessions("access_token", token, nowUnix, false, "", "")
}
func (r *SessionRepo) RevokeByRefreshToken(token, replacement string, nowUnix int64) error {
	return r.revokeSessions("refresh_token", token, nowUnix, false, replacement, "")
}
func (r *SessionRepo) RevokeByUserID(userID domain.UserID, nowUnix int64) error {
	return r.revokeSessions("user_id", userID.String(), nowUnix, false, "", userID.String())
}
func (r *SessionRepo) RevokeFamily(userID domain.UserID, familyID string, nowUnix int64, reuse bool) error {
	if userID.String() == "" || familyID == "" {
		return domain.ErrNotFound
	}
	return r.revokeSessions("family_id", familyID, nowUnix, reuse, "", userID.String())
}
