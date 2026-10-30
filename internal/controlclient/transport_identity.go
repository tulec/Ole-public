package controlclient

import (
	"Ole/internal/domain"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// TransportIdentities only accepts an authenticated HTTPS control plane, with
// explicit loopback HTTP for local development. Redirects cannot change authority.
func (c *Client) TransportIdentities(peerID string) (*domain.TransportIdentitySnapshot, error) {
	u, err := url.Parse(c.baseURL)
	if err != nil || u.User != nil || u.Host == "" {
		return nil, errors.New("invalid transport identity authority")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if u.Scheme != "https" && !(u.Scheme == "http" && (strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback())) {
		return nil, errors.New("transport identities require HTTPS or loopback HTTP")
	}
	client := *c
	httpClient := *c.httpClient
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("transport identity redirects are forbidden")
	}
	client.httpClient = &httpClient
	var response apiEnvelope[domain.TransportIdentitySnapshot]
	if err := client.doJSON(http.MethodGet, "/api/v1/peers/"+url.PathEscape(peerID)+"/transport-identities", nil, &response); err != nil {
		return nil, err
	}
	return &response.Data, nil
}
