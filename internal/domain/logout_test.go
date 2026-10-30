package domain_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/memory"
	"errors"
	"testing"
)

func TestLogoutWithoutRepositoryRevokesRotatedFamilyOnly(t *testing.T) {
	auth := domain.NewAuthService(memory.NewUserRepo(), nil, nil, "test-secret", "ole-test")
	user, err := auth.Register("local-logout@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	old, err := auth.Login(user.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := auth.Login(user.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	current, err := auth.Refresh(old.RefreshToken, domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.Logout(old.AccessToken); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{old.AccessToken, current.AccessToken} {
		if _, err := auth.ValidateAccessToken(token); err == nil {
			t.Fatal("rotated family still has valid access")
		}
	}
	if next, err := auth.Refresh(current.RefreshToken, domain.SessionMetadata{}); err == nil || next != nil {
		t.Fatal("logged-out family refreshed")
	}
	if _, err := auth.ValidateAccessToken(other.AccessToken); err != nil {
		t.Fatal("independent login family was revoked")
	}
	if err := auth.Logout("missing-access"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("missing session returned success: %v", err)
	}
}
