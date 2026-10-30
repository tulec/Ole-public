package memory

import (
	"Ole/internal/domain"
	"sort"
)

func (r *SessionRepo) Create(session *domain.SessionToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byAccessToken[session.AccessToken] != nil || r.byRefreshToken[session.RefreshToken] != nil {
		return domain.ErrAlreadyExists
	}
	r.insertSessionLocked(session)
	return nil
}

func (r *SessionRepo) insertSessionLocked(session *domain.SessionToken) {
	clone := *session
	r.byAccessToken[clone.AccessToken] = &clone
	r.byRefreshToken[clone.RefreshToken] = &clone
}

// Compatibility for explicit metadata updates; stale copies cannot undo revocation.
func (r *SessionRepo) Update(session *domain.SessionToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := r.byAccessToken[session.AccessToken]
	if stored == nil || stored.ID != session.ID || stored.RefreshToken != session.RefreshToken || stored.UserID != session.UserID || stored.FamilyID != session.FamilyID {
		return domain.ErrNotFound
	}
	copy := *session
	copy.RevokedAtUnix = max(stored.RevokedAtUnix, copy.RevokedAtUnix)
	copy.ReuseDetectedAtUnix = max(stored.ReuseDetectedAtUnix, copy.ReuseDetectedAtUnix)
	if stored.ReplacedByToken != "" {
		copy.ReplacedByToken = stored.ReplacedByToken
	}
	r.insertSessionLocked(&copy)
	return nil
}

func (r *SessionRepo) TouchLastUsed(accessToken string, nowUnix int64) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	session := r.byAccessToken[accessToken]
	if session == nil || session.IsRevoked() || session.IsReused() || session.IsExpired(nowUnix) || session.ReplacedByToken != "" {
		return false, nil
	}
	session.LastUsedAtUnix = max(session.LastUsedAtUnix, nowUnix)
	return true, nil
}

func (r *SessionRepo) Rotate(refreshToken string, next *domain.SessionToken, nowUnix int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.byRefreshToken[refreshToken]
	if !old.CanRotateTo(next, nowUnix) {
		return domain.ErrUnauthorized
	}
	if r.byAccessToken[next.AccessToken] != nil || r.byRefreshToken[next.RefreshToken] != nil {
		return domain.ErrAlreadyExists
	}
	rotated := *old
	rotated.MarkRotated(next.RefreshToken, nowUnix)
	r.insertSessionLocked(&rotated)
	r.insertSessionLocked(next)
	return nil
}

func (r *SessionRepo) FindByRefreshToken(refreshToken string) (*domain.SessionToken, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if session := r.byRefreshToken[refreshToken]; session != nil {
		clone := *session
		return &clone, nil
	}
	return nil, nil
}

func (r *SessionRepo) FindByAccessToken(accessToken string) (*domain.SessionToken, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if session := r.byAccessToken[accessToken]; session != nil {
		clone := *session
		return &clone, nil
	}
	return nil, nil
}

func (r *SessionRepo) ListByUserID(userID domain.UserID, limit, offset int) ([]*domain.SessionToken, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	families := map[string]*domain.SessionToken{}
	for _, session := range r.byRefreshToken {
		if session.UserID != userID {
			continue
		}
		previous := families[session.FamilyID]
		if previous != nil {
			leaf, previousLeaf := session.ReplacedByToken == "", previous.ReplacedByToken == ""
			if leaf != previousLeaf {
				if !leaf {
					continue
				}
			} else if session.LastUsedAtUnix < previous.LastUsedAtUnix || (session.LastUsedAtUnix == previous.LastUsedAtUnix && session.ID <= previous.ID) {
				continue
			}
		}
		families[session.FamilyID] = session
	}
	all := make([]*domain.SessionToken, 0, len(families))
	for _, session := range families {
		clone := *session
		all = append(all, &clone)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].FamilyID < all[j].FamilyID })
	total := len(all)
	if offset > total {
		offset = total
	}
	if limit <= 0 {
		limit = total
	}
	return all[offset:min(total, offset+limit)], total, nil
}

func (r *SessionRepo) RevokeBySessionID(userID domain.UserID, sessionID string, nowUnix int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sessionID == "" {
		return domain.ErrNotFound
	}
	familyID := ""
	for _, session := range r.byRefreshToken {
		if session.UserID == userID && session.ID == sessionID {
			if session.FamilyID == "" || (familyID != "" && familyID != session.FamilyID) {
				return domain.ErrNotFound
			}
			familyID = session.FamilyID
		}
	}
	if familyID == "" {
		return domain.ErrNotFound
	}
	for _, session := range r.byRefreshToken {
		if session.UserID == userID && session.FamilyID == familyID {
			session.RevokedAtUnix = max(session.RevokedAtUnix, nowUnix)
		}
	}
	return nil
}

func (r *SessionRepo) RevokeByAccessToken(accessToken string, nowUnix int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if session := r.byAccessToken[accessToken]; session != nil {
		session.RevokedAtUnix = max(session.RevokedAtUnix, nowUnix)
	}
	return nil
}

func (r *SessionRepo) RevokeByRefreshToken(refreshToken, replacedByToken string, nowUnix int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if session := r.byRefreshToken[refreshToken]; session != nil {
		session.RevokedAtUnix = max(session.RevokedAtUnix, nowUnix)
		if session.ReplacedByToken == "" {
			session.ReplacedByToken = replacedByToken
		}
	}
	return nil
}

func (r *SessionRepo) RevokeByUserID(userID domain.UserID, nowUnix int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, session := range r.byRefreshToken {
		if session.UserID == userID {
			session.RevokedAtUnix = max(session.RevokedAtUnix, nowUnix)
		}
	}
	return nil
}

func (r *SessionRepo) RevokeFamily(userID domain.UserID, familyID string, nowUnix int64, reuseDetected bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if userID.String() == "" || familyID == "" {
		return domain.ErrNotFound
	}
	for _, session := range r.byRefreshToken {
		if session.UserID == userID && session.FamilyID == familyID {
			session.RevokedAtUnix = max(session.RevokedAtUnix, nowUnix)
			if reuseDetected {
				session.ReuseDetectedAtUnix = max(session.ReuseDetectedAtUnix, nowUnix)
			}
		}
	}
	return nil
}

func (r *SessionRepo) DeleteExpired(nowUnix int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for token, session := range r.byRefreshToken {
		if session.IsExpired(nowUnix) {
			delete(r.byRefreshToken, token)
			delete(r.byAccessToken, session.AccessToken)
		}
	}
	return nil
}
