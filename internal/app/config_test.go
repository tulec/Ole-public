package app

import (
	"Ole/internal/config"
	"context"
	"strings"
	"testing"
)

func TestNewRejectsInvalidJWTSecretBeforeDatabase(t *testing.T) {
	for _, secret := range []string{"", "ole-dev-secret-change-me", "short-private-secret"} {
		application, err := New(context.Background(), config.Config{
			JWTSecret:   secret,
			DatabaseURL: "://invalid-dsn-with-private-marker",
		})
		if application != nil || err == nil || !strings.HasPrefix(err.Error(), "OLE_JWT_SECRET ") {
			t.Fatal("expected configuration rejection before database initialization")
		}
		if strings.Contains(err.Error(), "private-marker") {
			t.Fatal("configuration error disclosed the database URL")
		}
	}
}
