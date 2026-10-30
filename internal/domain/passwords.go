package domain

import (
	"Ole/internal/passwordhash"
	"errors"
	"fmt"
)

var ErrPasswordStorage = errors.New("failed to update password")

func (s *AuthService) verifyAndUpgradePassword(user *User, password string) (*User, error) {
	matched, upgrade := passwordhash.Verify(password, user.PasswordHash)
	if !matched {
		return nil, ErrInvalidCredentials
	}
	if !upgrade {
		return user, nil
	}
	nextHash, err := passwordhash.Hash(password)
	if err != nil {
		return nil, err
	}
	updated, err := s.userRepo.CompareAndSwapPassword(user.ID, user.PasswordHash, nextHash)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPasswordStorage, err)
	}
	if !updated {
		// Another login may have upgraded, or a password change may have won.
		// Never restore a stale password or issue a token for a replaced one.
		current, err := s.userRepo.FindByID(user.ID)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrPasswordStorage, err)
		}
		if current == nil {
			return nil, ErrInvalidCredentials
		}
		if !current.CanLogin() {
			return nil, ErrUserBanned
		}
		matched, stillLegacy := passwordhash.Verify(password, current.PasswordHash)
		if !matched || stillLegacy {
			return nil, ErrInvalidCredentials
		}
		return current, nil
	}
	copy := *user
	copy.PasswordHash = nextHash
	return &copy, nil
}

func (s *AuthService) ChangePassword(userID UserID, oldPassword, newPassword string) error {
	if newPassword == "" {
		return ErrInvalidPassword
	}
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPasswordStorage, err)
	}
	if user == nil {
		return ErrNotFound
	}
	if valid, _ := passwordhash.Verify(oldPassword, user.PasswordHash); !valid {
		return ErrInvalidPassword
	}
	nextHash, err := passwordhash.Hash(newPassword)
	if err != nil {
		return err
	}
	updated, err := s.userRepo.CompareAndSwapPassword(userID, user.PasswordHash, nextHash)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPasswordStorage, err)
	}
	if !updated {
		return ErrInvalidPassword
	}
	s.appendAudit(userID, "user.password_changed", user.Email)
	return nil
}
