package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPostgresHTTPAuthRateLimitUsesCanonicalIPAcrossRouters(t *testing.T) {
	db, cleanup := openRateLimiterIntegrationDB(t)
	defer cleanup()
	application := authIPTestApp()
	application.DB = db // Shared SQL limiter/abuse state; auth fails before session writes.
	proxies, err := ParseTrustedProxies("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"direct", "trusted-proxy"} {
		t.Run(mode, func(t *testing.T) {
			routers := []http.Handler{NewRouter(application, proxies...), NewRouter(application, proxies...)}
			clientIP := "198.51.100.17"
			if mode == "trusted-proxy" {
				clientIP = "198.51.100.18"
			}
			for _, path := range []string{"/api/v1/sessions", "/api/v1/sessions/refresh"} {
				for i := range 4 {
					remote := fmt.Sprintf("%s:%d", clientIP, 4000+i)
					forwarded := []string{fmt.Sprintf("203.0.113.%d", i+1)}
					if mode == "trusted-proxy" {
						remote = fmt.Sprintf("10.0.0.2:%d", 4000+i)
						forwarded = []string{fmt.Sprintf("203.0.113.%d", i+1), clientIP + ", 10.0.0.1"}
					}
					response := authIPRequest(routers[i%2], path, remote, forwarded)
					want := http.StatusUnauthorized
					if i == 3 {
						want = http.StatusTooManyRequests
					}
					if response.Code != want {
						t.Fatalf("%s attempt %d: got %d, want %d; %s", path, i+1, response.Code, want, response.Body.String())
					}
				}
				kind := "login"
				if strings.HasSuffix(path, "/refresh") {
					kind = "refresh"
				}
				var failures int
				var blockedUntil int64
				if err := db.QueryRow(`SELECT failures,blocked_until_unix FROM auth_rate_limits WHERE attempt_key=$1`, clientIP+":"+kind).Scan(&failures, &blockedUntil); err != nil {
					t.Fatal(err)
				}
				if failures != 3 || blockedUntil <= time.Now().Unix() {
					t.Errorf("wrong shared bucket: failures=%d blocked_until=%d", failures, blockedUntil)
				}
			}
		})
	}
	var keys int
	if err := db.QueryRow(`SELECT COUNT(*) FROM auth_rate_limits`).Scan(&keys); err != nil || keys != 4 {
		t.Fatalf("expected 4 canonical SQL keys for 16 requests, got %d err=%v", keys, err)
	}
	t.Log("routers=2 requests=16 canonical_buckets=4 blocked_fourth_attempts=4")
}
