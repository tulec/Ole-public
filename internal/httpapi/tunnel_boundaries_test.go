package httpapi_test

import (
	"Ole/internal/app"
	"Ole/internal/domain"
	"Ole/internal/httpapi"
	"Ole/internal/store/memory"
	"net/http"
	"testing"
)

func TestTunnelRoutesEnforceNetworkAndParticipantBoundaries(t *testing.T) {
	users := memory.NewUserRepo()
	peers := memory.NewPeerRepo()
	networks := memory.NewNetworkRepo()
	tunnels := memory.NewTunnelRepo()
	auth := domain.NewAuthService(users, nil, memory.NewSessionRepo(), "test-secret", "ole-test")
	register := func(email string) (domain.UserID, string) {
		t.Helper()
		user, err := auth.Register(email, "secret")
		if err != nil {
			t.Fatal(err)
		}
		session, err := auth.Login(email, "secret", domain.SessionMetadata{})
		if err != nil {
			t.Fatal(err)
		}
		return user.ID, session.AccessToken
	}
	owner, ownerToken := register("owner-tunnel@example.com")
	member, memberToken := register("member-tunnel@example.com")
	unrelated, unrelatedToken := register("unrelated-tunnel@example.com")
	network := domain.NewNetwork(domain.NetworkID{Value: "network-a"}, owner, "private", domain.NetworkAccessInviteOnly, false)
	for _, id := range []domain.UserID{member, unrelated} {
		if err := network.AddMember(id); err != nil {
			t.Fatal(err)
		}
	}
	if err := networks.Save(network); err != nil {
		t.Fatal(err)
	}
	for _, p := range []*domain.Peer{
		{ID: domain.PeerID{Value: "a"}, UserID: owner, NetworkID: network.ID, Endpoint: "127.0.0.1:10001"},
		{ID: domain.PeerID{Value: "b"}, UserID: member, NetworkID: network.ID, Endpoint: "127.0.0.1:10002"},
		{ID: domain.PeerID{Value: "foreign-a"}, UserID: owner, NetworkID: domain.NetworkID{Value: "network-b"}},
		{ID: domain.PeerID{Value: "foreign-b"}, UserID: owner, NetworkID: domain.NetworkID{Value: "network-b"}},
	} {
		if err := peers.Save(p); err != nil {
			t.Fatal(err)
		}
	}
	coordinator := domain.NewTunnelCoordinator(tunnels, peers, nil, networks)
	router := httpapi.NewRouter(&app.App{AuthService: auth, TunnelCoordinator: coordinator})
	path := "/api/v1/networks/" + network.ID.String() + "/tunnels"
	for _, tc := range []struct {
		name, a, b, mode, token string
		status                  int
	}{
		{"foreign target", "a", "foreign-a", "RELAY", ownerToken, http.StatusUnauthorized},
		{"foreign source", "foreign-a", "a", "RELAY", ownerToken, http.StatusUnauthorized},
		{"both foreign", "foreign-a", "foreign-b", "RELAY", ownerToken, http.StatusUnauthorized},
		{"same peer", "a", "a", "RELAY", ownerToken, http.StatusBadRequest},
		{"invalid mode", "a", "b", "UNKNOWN", ownerToken, http.StatusBadRequest},
		{"not a participant", "a", "b", "RELAY", unrelatedToken, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := performAuthenticatedJSON(t, router, http.MethodPost, path, tc.token, map[string]string{"peerAId": tc.a, "peerBId": tc.b, "mode": tc.mode})
			if response.Code != tc.status {
				t.Fatalf("got status %d, want %d: %s", response.Code, tc.status, response.Body.String())
			}
			stored, err := tunnels.ListByNetwork(network.ID)
			if err != nil || len(stored) != 0 {
				t.Fatal("forbidden HTTP request created tunnel")
			}
		})
	}
	for _, mode := range []domain.TunnelMode{domain.TunnelModeP2P, domain.TunnelModeRelay} {
		response := performAuthenticatedJSON(t, router, http.MethodPost, path, ownerToken, map[string]string{"peerAId": "a", "peerBId": "b", "mode": string(mode)})
		if response.Code != http.StatusCreated {
			t.Fatalf("valid %s request failed: %d: %s", mode, response.Code, response.Body.String())
		}
		tunnel, err := tunnels.FindByPeers(network.ID, domain.PeerID{Value: "a"}, domain.PeerID{Value: "b"})
		if err != nil || tunnel == nil || tunnel.Mode != mode {
			t.Fatal("valid tunnel was not saved")
		}
		updatePath := "/api/v1/tunnels/" + tunnel.ID.String()
		opened := performAuthenticatedJSON(t, router, http.MethodPatch, updatePath, memberToken, map[string]string{"state": "OPEN"})
		if opened.Code != http.StatusOK {
			t.Fatalf("participant failed to open tunnel: %d", opened.Code)
		}
		denied := performAuthenticatedJSON(t, router, http.MethodPatch, updatePath, unrelatedToken, map[string]string{"state": "CLOSED"})
		if denied.Code != http.StatusUnauthorized {
			t.Fatalf("unrelated member modified tunnel: %d", denied.Code)
		}
		stored, err := tunnels.FindByID(tunnel.ID)
		if err != nil || stored.State != domain.TunnelStateOpen {
			t.Fatal("rejected update changed tunnel")
		}
	}
}
