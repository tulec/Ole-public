package httpapi

import (
	"Ole/internal/app"
	"Ole/internal/domain"
	"Ole/internal/store/memory"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func authIPTestApp() *app.App {
	return &app.App{AuthService: domain.NewAuthService(memory.NewUserRepo(), nil, memory.NewSessionRepo(), "test-secret", "ole-test")}
}

func TestClientIPTrustedProxyBoundary(t *testing.T) {
	proxies, err := ParseTrustedProxies("10.0.0.0/24,fd00::/64,::ffff:192.0.2.0/120")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, remote, want string
		forwarded          []string
		noTrust            bool
	}{
		{"default-ignores-xff", "10.0.0.1:4000", "10.0.0.1", []string{"203.0.113.7"}, true},
		{"outside-trusted-cidr", "10.0.1.1:4000", "10.0.1.1", []string{"203.0.113.7"}, false},
		{"trusted-single", "10.0.0.1:4000", "203.0.113.7", []string{"203.0.113.7"}, false},
		{"trusted-multiple", "10.0.0.2:4000", "198.51.100.17", []string{"203.0.113.7, 198.51.100.17, 10.0.0.1"}, false},
		{"repeated-fields", "10.0.0.2:4000", "198.51.100.17", []string{"203.0.113.7", "198.51.100.17, 10.0.0.1"}, false},
		{"untrusted-intermediate", "10.0.0.2:4000", "198.51.100.17", []string{"203.0.113.7, 198.51.100.17"}, false},
		{"untrusted-left-garbage-ignored", "10.0.0.2:4000", "198.51.100.17", []string{"garbage, 198.51.100.17"}, false},
		{"missing-header", "10.0.0.1:4000", "10.0.0.1", nil, false},
		{"all-trusted", "10.0.0.2:4000", "10.0.0.1", []string{"10.0.0.1"}, false},
		{"ipv6-proxy", "[fd00::1]:4000", "2001:db8::7", []string{"2001:0db8:0:0:0:0:0:7"}, false},
		{"mapped-proxy", "[::ffff:192.0.2.17]:4000", "198.51.100.17", []string{"198.51.100.17"}, false},
		{"mapped-client", "10.0.0.1:4000", "198.51.100.17", []string{"::ffff:198.51.100.17"}, false},
		{"remote-zone", "[fe80::1%eth0]:4000", "fe80::1", nil, false},
		{"bare-ip", "2001:0db8::7", "2001:db8::7", nil, false},
		{"malformed-closest-hop", "10.0.0.1:4000", "10.0.0.1", []string{"203.0.113.7, garbage"}, false},
		{"malformed-trusted-chain", "10.0.0.2:4000", "10.0.0.2", []string{"garbage, 10.0.0.1"}, false},
		{"header-port-rejected", "10.0.0.1:4000", "10.0.0.1", []string{"203.0.113.7:4000"}, false},
		{"header-zone-rejected", "10.0.0.1:4000", "10.0.0.1", []string{"fe80::7%eth0"}, false},
		{"header-empty-rejected", "10.0.0.1:4000", "10.0.0.1", []string{""}, false},
		{"header-brackets-rejected", "10.0.0.1:4000", "10.0.0.1", []string{"[2001:db8::7]"}, false},
		{"malformed-peer", "garbage", "unknown", []string{"203.0.113.7"}, false},
		{"empty-peer", "", "unknown", []string{"203.0.113.7"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &API{trustedProxies: proxies}
			if tc.noTrust {
				api.trustedProxies = nil
			}
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.RemoteAddr = tc.remote
			for _, value := range tc.forwarded {
				req.Header.Add("X-Forwarded-For", value)
			}
			req.Header.Set("X-Real-IP", "203.0.113.99")
			req.Header.Set("Forwarded", "for=203.0.113.99")
			if got := api.clientIP(req); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseTrustedProxiesValidatesCompleteConfiguration(t *testing.T) {
	for _, value := range []string{"proxy.example.com", "10.0.0.1:80", "10.0.0.0/33", "10.0.0.1,", ",10.0.0.1", "10.0.0.1,garbage", "fe80::1%eth0", "::ffff:192.0.2.0/80", "*"} {
		if proxies, err := ParseTrustedProxies(value); err == nil || proxies != nil {
			t.Errorf("invalid config %q accepted: %v err=%v", value, proxies, err)
		}
	}
	proxies, err := ParseTrustedProxies(" 127.0.0.1, ::1, 10.0.0.17/24, ::ffff:192.0.2.17, ::ffff:198.51.100.17/120 ")
	want := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("192.0.2.17/32"), netip.MustParsePrefix("198.51.100.0/24")}
	if err != nil || fmt.Sprint(proxies) != fmt.Sprint(want) {
		t.Errorf("normalization: %v err=%v, want %v", proxies, err, want)
	}
	if proxies, err := ParseTrustedProxies(" "); err != nil || len(proxies) != 0 {
		t.Errorf("empty config: %v %v", proxies, err)
	}
}

func TestTrustedProxyAuthRateLimitStopsSpoofedPrefix(t *testing.T) {
	proxies, err := ParseTrustedProxies("10.0.0.0/24,fd00::/64")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/sessions", "/api/v1/sessions/refresh"} {
		for _, scenario := range []string{"single-field", "repeated-fields", "ipv6-client"} {
			t.Run(path+"/"+scenario, func(t *testing.T) {
				router := NewRouter(authIPTestApp(), proxies...)
				for i := range 4 {
					forwarded := []string{fmt.Sprintf("203.0.113.%d, 198.51.100.17, 10.0.0.1", i+1)}
					if scenario == "repeated-fields" {
						forwarded = []string{fmt.Sprintf("203.0.113.%d", i+1), "198.51.100.17, 10.0.0.1"}
					} else if scenario == "ipv6-client" {
						forwarded = []string{fmt.Sprintf("203.0.113.%d, 2001:db8::17, fd00::1", i+1)}
					}
					response := authIPRequest(router, path, fmt.Sprintf("10.0.0.2:%d", 4000+i), forwarded)
					want := http.StatusUnauthorized
					if i == 3 {
						want = http.StatusTooManyRequests
					}
					if response.Code != want {
						t.Errorf("attempt %d: got %d, want %d", i+1, response.Code, want)
					}
				}
				if response := authIPRequest(router, path, "10.0.0.2:5000", []string{"198.51.100.18, 10.0.0.1"}); response.Code != http.StatusUnauthorized {
					t.Errorf("different real client blocked: %d", response.Code)
				}
			})
		}
	}
}

func TestSessionMetadataUsesResolvedIPForLoginAndRefresh(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		t.Run(fmt.Sprint(trusted), func(t *testing.T) {
			application := authIPTestApp()
			if _, err := application.AuthService.Register("ip-metadata@example.com", "secret"); err != nil {
				t.Fatal(err)
			}
			var proxies []netip.Prefix
			wantIP := "10.0.0.1"
			if trusted {
				proxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}
				wantIP = "198.51.100.17"
			}
			router := NewRouter(application, proxies...)
			body := `{"email":"ip-metadata@example.com","password":"secret"}`
			for _, path := range []string{"/api/v1/sessions", "/api/v1/sessions/refresh"} {
				req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
				req.RemoteAddr = "10.0.0.1:4000"
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Forwarded-For", "203.0.113.99, ::ffff:198.51.100.17")
				response := httptest.NewRecorder()
				router.ServeHTTP(response, req)
				if response.Code != http.StatusCreated && response.Code != http.StatusOK {
					t.Fatalf("%s: %d %s", path, response.Code, response.Body.String())
				}
				var result envelope[sessionResponse]
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if result.Data.IP != wantIP {
					t.Errorf("%s metadata IP=%q, want %q", path, result.Data.IP, wantIP)
				}
				body = fmt.Sprintf(`{"refreshToken":%q}`, result.Data.RefreshToken)
			}
		})
	}
}

func authIPRequest(router http.Handler, path, remote string, forwarded []string) *httptest.ResponseRecorder {
	body := `{"email":"missing@example.com","password":"wrong"}`
	if strings.HasSuffix(path, "/refresh") {
		body = `{"refreshToken":"missing-refresh"}`
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.RemoteAddr = remote
	req.Header.Set("Content-Type", "application/json")
	for _, value := range forwarded {
		req.Header.Add("X-Forwarded-For", value)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	return response
}

func TestAuthRateLimitCannotBeResetByClientAddressFormatting(t *testing.T) {
	for _, path := range []string{"/api/v1/sessions", "/api/v1/sessions/refresh"} {
		for _, scenario := range []string{"source-port", "spoofed-xff", "ipv6-spelling", "ipv4-mapped"} {
			t.Run(path+"/"+scenario, func(t *testing.T) {
				router := NewRouter(authIPTestApp())
				for i := range 4 {
					remote := "198.51.100.17:4000"
					var forwarded []string
					switch scenario {
					case "source-port":
						remote = fmt.Sprintf("198.51.100.17:%d", 4000+i)
					case "spoofed-xff":
						forwarded = []string{fmt.Sprintf("203.0.113.%d", i+1)}
					case "ipv6-spelling":
						remote = []string{"[2001:db8::1]:4000", "[2001:0db8:0:0:0:0:0:1]:4000", "[2001:DB8::1]:4000", "[2001:db8:0:0::1]:4000"}[i]
					case "ipv4-mapped":
						remote = []string{"198.51.100.17:4000", "[::ffff:198.51.100.17]:4000", "[::ffff:c633:6411]:4000", "198.51.100.17:4000"}[i]
					}
					response := authIPRequest(router, path, remote, forwarded)
					want := http.StatusUnauthorized
					if i == 3 {
						want = http.StatusTooManyRequests
					}
					if response.Code != want {
						t.Errorf("attempt %d: got %d, want %d", i+1, response.Code, want)
					}
				}
			})
		}
	}
}

func TestAuthRateLimitKeepsDifferentIPsAndRoutesSeparate(t *testing.T) {
	router := NewRouter(authIPTestApp())
	for range 3 {
		if response := authIPRequest(router, "/api/v1/sessions", "198.51.100.17:4000", nil); response.Code != http.StatusUnauthorized {
			t.Fatal(response.Code)
		}
	}
	for _, request := range []struct{ path, remote string }{
		{"/api/v1/sessions", "198.51.100.18:4000"},
		{"/api/v1/sessions/refresh", "198.51.100.17:4000"},
	} {
		if response := authIPRequest(router, request.path, request.remote, nil); response.Code != http.StatusUnauthorized {
			t.Errorf("unrelated IP/route was blocked: %d", response.Code)
		}
	}
	if response := authIPRequest(router, "/api/v1/sessions", "198.51.100.17:4000", nil); response.Code != http.StatusTooManyRequests {
		t.Errorf("original bucket lost its limit: %d", response.Code)
	}
}
