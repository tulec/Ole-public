package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestServerRejectsInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct{ name, secret string }{
		{"missing", ""},
		{"whitespace", "  \t"},
		{"legacy", "ole-dev-secret-change-me"},
		{"short", "private-short-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OLE_SERVER_CONFIG_TEST_HELPER", "1")
			t.Setenv("OLE_JWT_SECRET", tc.secret)
			t.Setenv("OLE_DATABASE_URL", "://private-database-marker")
			t.Setenv("OLE_HTTP_PORT", "invalid-listen-address")
			t.Setenv("OLE_HTTP_TRUSTED_PROXIES", "invalid-proxy-marker")
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(binary, "-test.run=^TestServerConfigurationProcess$")
			cmd.Dir = t.TempDir()
			output, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatalf("expected exit code 1, got %v", err)
			}
			if !strings.Contains(string(output), "invalid server configuration") || !strings.Contains(string(output), "OLE_JWT_SECRET") {
				t.Fatal("missing safe JWT configuration error")
			}
			for _, marker := range []string{"private-database-marker", "invalid-listen-address", "invalid-proxy-marker", "ole-dev-secret-change-me", "private-short-key"} {
				if strings.Contains(string(output), marker) {
					t.Fatal("startup logged a configuration value or proceeded beyond JWT validation")
				}
			}
		})
	}
}

func TestServerConfigurationProcess(t *testing.T) {
	if os.Getenv("OLE_SERVER_CONFIG_TEST_HELPER") != "1" {
		return
	}
	main()
	t.Fatal("server returned without rejecting invalid JWT configuration")
}
