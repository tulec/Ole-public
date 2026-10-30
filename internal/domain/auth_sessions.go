package domain

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (s *AuthService) Login(email, password string, meta SessionMetadata) (*SessionToken, error) {
	user, err := s.userRepo.FindByEmail(strings.TrimSpace(strings.ToLower(email)))
	if err != nil || user == nil {
		return nil, ErrInvalidCredentials
	}
	if !user.CanLogin() {
		return nil, ErrUserBanned
	}
	user, err = s.verifyAndUpgradePassword(user, password)
	if err != nil {
		return nil, err
	}
	nowUnix := time.Now().Unix()
	session := &SessionToken{ID: nextID("ses"), UserID: user.ID, FamilyID: nextID("fam"), RefreshToken: secureToken("ref"),
		DeviceName: strings.TrimSpace(meta.DeviceName), IP: strings.TrimSpace(meta.IP), UserAgent: strings.TrimSpace(meta.UserAgent),
		LastUsedAtUnix: nowUnix, ExpiresAtUnix: nowUnix + s.sessionTTL}
	session.AccessToken, err = s.issueAccessToken(user.ID, session.ID, session.ExpiresAtUnix)
	if err != nil {
		return nil, err
	}
	if s.sessionRepo != nil {
		if err := s.sessionRepo.Create(session); err != nil {
			return nil, err
		}
	} else {
		s.mu.Lock()
		s.cacheSessionLocked(session)
		s.mu.Unlock()
	}
	s.appendAudit(user.ID, "user.logged_in", email)
	return session, nil
}

// Persistent sessions are always read from storage. The maps are only the
// standalone, no-repository implementation; they never override database state.
func (s *AuthService) Refresh(refreshToken string, meta SessionMetadata) (*SessionToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var session *SessionToken
	if s.sessionRepo != nil {
		var err error
		session, err = s.sessionRepo.FindByRefreshToken(refreshToken)
		if err != nil {
			return nil, err
		}
	} else {
		session = s.sessionsByRefresh[refreshToken]
	}
	if session == nil {
		return nil, ErrUnauthorized
	}
	nowUnix := time.Now().Unix()
	if session.IsRevoked() || session.IsReused() || session.ReplacedByToken != "" {
		return nil, s.rejectSessionReuseLocked(session, nowUnix)
	}
	if session.IsExpired(nowUnix) {
		return nil, ErrUnauthorized
	}
	next := &SessionToken{ID: nextID("ses"), UserID: session.UserID, FamilyID: session.FamilyID,
		RefreshToken: secureToken("ref"), DeviceName: firstNonEmpty(strings.TrimSpace(meta.DeviceName), session.DeviceName),
		IP: firstNonEmpty(strings.TrimSpace(meta.IP), session.IP), UserAgent: firstNonEmpty(strings.TrimSpace(meta.UserAgent), session.UserAgent),
		LastUsedAtUnix: nowUnix, ExpiresAtUnix: nowUnix + s.sessionTTL}
	var err error
	next.AccessToken, err = s.issueAccessToken(next.UserID, next.ID, next.ExpiresAtUnix)
	if err != nil {
		return nil, err
	}
	if s.sessionRepo != nil {
		if err := s.sessionRepo.Rotate(refreshToken, next, nowUnix); err != nil {
			if errors.Is(err, ErrUnauthorized) {
				// A different service may have rotated/revoked after our read.
				latest, readErr := s.sessionRepo.FindByRefreshToken(refreshToken)
				if readErr != nil {
					return nil, readErr
				}
				if latest != nil && (latest.IsRevoked() || latest.ReplacedByToken != "") {
					return nil, s.rejectSessionReuseLocked(latest, nowUnix)
				}
			}
			return nil, err
		}
	} else {
		old := *session
		old.MarkRotated(next.RefreshToken, nowUnix)
		delete(s.sessionsByAccess, old.AccessToken)
		s.sessionsByRefresh[old.RefreshToken] = &old // retain reuse detection until expiry
		s.cacheSessionLocked(next)
	}
	return next, nil
}

func (s *AuthService) rejectSessionReuseLocked(session *SessionToken, nowUnix int64) error {
	alreadyReused := session.IsReused()
	if s.sessionRepo != nil {
		if err := s.sessionRepo.RevokeFamily(session.UserID, session.FamilyID, nowUnix, true); err != nil {
			return err
		}
	}
	s.revokeFamilyInMemory(session.UserID, session.FamilyID, nowUnix, true)
	if !alreadyReused {
		s.appendAudit(session.UserID, "session.reuse_detected", session.FamilyID)
	}
	return ErrUnauthorized
}

func (s *AuthService) cacheSessionLocked(session *SessionToken) {
	copy := *session
	s.sessionsByAccess[copy.AccessToken] = &copy
	s.sessionsByRefresh[copy.RefreshToken] = &copy
}

func (s *AuthService) ValidateAccessToken(accessToken string) (UserID, error) {
	token, err := jwt.Parse(accessToken, func(*jwt.Token) (any, error) { return s.jwtSecret, nil }, jwt.WithIssuer(s.jwtIssuer), jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !token.Valid {
		return UserID{}, ErrUnauthorized
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return UserID{}, ErrUnauthorized
	}
	subject, err := claims.GetSubject()
	if err != nil || subject == "" {
		return UserID{}, ErrUnauthorized
	}
	nowUnix := time.Now().Unix()
	if s.sessionRepo != nil {
		session, err := s.sessionRepo.FindByAccessToken(accessToken)
		if err != nil {
			return UserID{}, err
		}
		if !validStoredSession(session, subject, nowUnix) {
			return UserID{}, ErrUnauthorized
		}
		active, err := s.sessionRepo.TouchLastUsed(accessToken, nowUnix)
		if err != nil {
			return UserID{}, err
		}
		if !active {
			return UserID{}, ErrUnauthorized
		}
		return session.UserID, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.sessionsByAccess[accessToken]
	if !validStoredSession(session, subject, nowUnix) {
		return UserID{}, ErrUnauthorized
	}
	session.Touch("", "", nowUnix)
	return session.UserID, nil
}

func validStoredSession(session *SessionToken, subject string, nowUnix int64) bool {
	return session != nil && session.UserID.String() == subject && !session.IsExpired(nowUnix) && !session.IsRevoked() && !session.IsReused() && session.ReplacedByToken == ""
}

func (s *AuthService) issueAccessToken(userID UserID, sessionID string, expUnix int64) (string, error) {
	claims := jwt.MapClaims{"sub": userID.String(), "iss": s.jwtIssuer, "exp": expUnix, "iat": time.Now().Unix(), "jti": sessionID}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtSecret)
}
