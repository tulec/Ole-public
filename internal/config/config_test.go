package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoadJWTSecretPrecedence(t *testing.T) {
	const processSecret = "process-secret-0123456789abcdef0123456789"
	const localSecret = "local-secret-0123456789abcdef0123456789"
	const baseSecret = "base-secret-0123456789abcdef0123456789"
	for _, tc := range []struct {
		name    string
		process *string
		files   map[string]string
		want    string
	}{
		{"process wins", ptr(processSecret), map[string]string{".env": baseSecret, ".env.local": localSecret}, processSecret},
		{"empty process blocks files", ptr(""), map[string]string{".env": baseSecret, ".env.local": localSecret}, ""},
		{"whitespace process blocks files", ptr("  \t"), map[string]string{".env": baseSecret, ".env.local": localSecret}, ""},
		{"local wins over base", nil, map[string]string{".env": baseSecret, ".env.local": localSecret}, localSecret},
		{"base only", nil, map[string]string{".env": baseSecret}, baseSecret},
		{"local only", nil, map[string]string{".env.local": localSecret}, localSecret},
		{"empty local blocks base", nil, map[string]string{".env": baseSecret, ".env.local": ""}, ""},
		{"no fallback", nil, nil, ""},
		{"process without files", ptr(processSecret), nil, processSecret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			t.Setenv("OLE_JWT_SECRET", "")
			if tc.process == nil {
				if err := os.Unsetenv("OLE_JWT_SECRET"); err != nil {
					t.Fatal(err)
				}
			} else {
				t.Setenv("OLE_JWT_SECRET", *tc.process)
			}
			for path, value := range tc.files {
				if err := os.WriteFile(path, []byte("OLE_JWT_SECRET="+value+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if got := Load().JWTSecret; got != tc.want {
				t.Error("JWT secret did not follow process > .env.local > .env precedence")
			}
		})
	}
}

func ptr(value string) *string { return &value }

func TestValidateServerJWTSecret(t *testing.T) {
	for _, tc := range []struct {
		name   string
		secret string
		valid  bool
	}{
		{"empty", "", false},
		{"whitespace", " \t\n", false},
		{"legacy development value", "ole-dev-secret-change-me", false},
		{"padded development value", "  ole-dev-secret-change-me  ", false},
		{"uppercase development value", "OLE-DEV-SECRET-CHANGE-ME", false},
		{"short", "private-but-short", false},
		{"31 bytes", strings.Repeat("a", 31), false},
		{"32 bytes", "0123456789abcdef0123456789abcdef", true},
		{"longer secret", "dedicated-server-key-0123456789abcdef0123456789abcdef", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := (Config{JWTSecret: tc.secret}).ValidateServer()
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, expected %v", err == nil, tc.valid)
			}
			if err != nil && !strings.HasPrefix(err.Error(), "OLE_JWT_SECRET ") {
				t.Fatal("validation must identify the setting without including its value")
			}
			if err != nil && strings.TrimSpace(tc.secret) != "" && strings.Contains(err.Error(), tc.secret) {
				t.Fatal("validation error disclosed the secret")
			}
		})
	}
}

func TestLoadProcessEnvironmentWinsOtherSettings(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("OLE_DATABASE_URL", "process-dsn")
	t.Setenv("OLE_HTTP_PORT", ":18080")
	for _, path := range []string{".env", ".env.local"} {
		if err := os.WriteFile(path, []byte("OLE_DATABASE_URL=file-dsn\nOLE_HTTP_PORT=:28080\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := Load()
	if cfg.DatabaseURL != "process-dsn" || cfg.HTTPPort != ":18080" {
		t.Fatal("dotenv replaced process configuration")
	}
}

func TestLoadHTTPTrustedProxies(t *testing.T) {
	t.Chdir(t.TempDir()) // Do not load an operator's .env during configuration tests.
	for _, value := range []string{"", " 127.0.0.1/32,::1/128 "} {
		t.Setenv("OLE_HTTP_TRUSTED_PROXIES", value)
		want := ""
		if value != "" {
			want = "127.0.0.1/32,::1/128"
		}
		if got := Load().HTTPTrustedProxies; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
