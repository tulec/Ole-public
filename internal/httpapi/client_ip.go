package httpapi

import (
	"Ole/internal/domain"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ParseTrustedProxies accepts a comma-separated list of literal IPs and CIDRs.
// Empty configuration trusts no proxy; invalid entries must prevent startup.
func ParseTrustedProxies(value string) ([]netip.Prefix, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var proxies []netip.Prefix
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			addr, addrErr := netip.ParseAddr(entry)
			if addrErr != nil || addr.Zone() != "" {
				return nil, fmt.Errorf("invalid trusted proxy IP or CIDR %q", entry)
			}
			addr = addr.Unmap()
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		} else if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return nil, fmt.Errorf("mapped IPv4 proxy CIDR must be /96 or narrower: %q", entry)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		proxies = append(proxies, prefix.Masked())
	}
	return proxies, nil
}

func (api *API) sessionMetadataFromRequest(r *http.Request, deviceName string) domain.SessionMetadata {
	return domain.SessionMetadata{
		DeviceName: strings.TrimSpace(deviceName),
		IP:         api.clientIP(r),
		UserAgent:  strings.TrimSpace(r.UserAgent()),
	}
}

func (api *API) clientIP(r *http.Request) string {
	host := strings.TrimSpace(r.RemoteAddr)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		// Never use an arbitrary malformed address as a fresh limiter key.
		return "unknown"
	}
	remote = remote.WithZone("").Unmap()
	client := remote
	// Header.Values preserves repeated XFF fields in wire order. Stop at the
	// closest untrusted hop; anything to its left may have been supplied by it.
	values := r.Header.Values("X-Forwarded-For")
	for i := len(values) - 1; i >= 0; i-- {
		if !api.isTrustedProxy(client) {
			break
		}
		hops := strings.Split(values[i], ",")
		for j := len(hops) - 1; j >= 0; j-- {
			if !api.isTrustedProxy(client) {
				return client.String()
			}
			next, err := netip.ParseAddr(strings.TrimSpace(hops[j]))
			if err != nil || next.Zone() != "" {
				// A malformed trusted-proxy chain falls back to the actual peer,
				// so varying invalid header values cannot create new buckets.
				return remote.String()
			}
			client = next.Unmap()
		}
	}
	return client.String()
}

func (api *API) isTrustedProxy(addr netip.Addr) bool {
	for _, prefix := range api.trustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
