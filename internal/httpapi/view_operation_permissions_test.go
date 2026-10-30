package httpapi_test

import (
	"Ole/internal/app"
	"Ole/internal/domain"
	"Ole/internal/httpapi"
	"Ole/internal/store/memory"
	"net/http"
	"testing"
)

func TestNetworkPeerAndTunnelViewRoutesRespectExplicitViewOperations(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:       domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:     domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:    domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:     domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		TunnelCoordinator: domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:         auditRepo,
		UserRepo:          userRepo,
		DeviceRepo:        deviceRepo,
		NetworkRepo:       networkRepo,
		PeerRepo:          peerRepo,
		TunnelRepo:        tunnelRepo,
		InviteRepo:        inviteRepo,
		SessionRepo:       sessionRepo,
	}
	router := httpapi.NewRouter(application)

	registerAndLogin := func(email string) (string, string) {
		t.Helper()
		userResp := performJSON(t, router, http.MethodPost, "/api/v1/users", map[string]string{"email": email, "password": "secret"})
		if userResp.Code != http.StatusCreated {
			t.Fatalf("register %s: expected 201, got %d", email, userResp.Code)
		}
		var userBody struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		decodeBody(t, userResp, &userBody)

		loginResp := performJSON(t, router, http.MethodPost, "/api/v1/sessions", map[string]string{"email": email, "password": "secret"})
		if loginResp.Code != http.StatusCreated {
			t.Fatalf("login %s: expected 201, got %d", email, loginResp.Code)
		}
		var loginBody struct {
			Data struct {
				AccessToken string `json:"accessToken"`
			} `json:"data"`
		}
		decodeBody(t, loginResp, &loginBody)
		return userBody.Data.ID, loginBody.Data.AccessToken
	}

	ownerID, ownerToken := registerAndLogin("owner-view-ops-http@example.com")
	memberID, memberToken := registerAndLogin("member-view-ops-http@example.com")
	moderatorID, moderatorToken := registerAndLogin("moderator-view-ops-http@example.com")
	fileAdminID, fileAdminToken := registerAndLogin("fileadmin-view-ops-http@example.com")
	readOnlyID, readOnlyToken := registerAndLogin("readonly-view-ops-http@example.com")
	_, outsiderToken := registerAndLogin("outsider-view-ops-http@example.com")

	createDevice := func(token, name, publicKey string) string {
		t.Helper()
		resp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/devices", token, map[string]string{"name": name, "publicKey": publicKey})
		if resp.Code != http.StatusCreated {
			t.Fatalf("create device %s: expected 201, got %d", name, resp.Code)
		}
		var body struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		decodeBody(t, resp, &body)
		return body.Data.ID
	}

	ownerDeviceID := createDevice(ownerToken, "owner-device", "owner-pub")
	memberDeviceID := createDevice(memberToken, "member-device", "member-pub")

	createNetworkResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks", ownerToken, map[string]any{
		"ownerId": ownerID,
		"name":    "view-ops-http",
		"access":  "INVITE_ONLY",
	})
	if createNetworkResp.Code != http.StatusCreated {
		t.Fatalf("create network: expected 201, got %d", createNetworkResp.Code)
	}
	var networkBody struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, createNetworkResp, &networkBody)
	networkID := networkBody.Data.ID

	addMember := func(token, memberID, role string) {
		t.Helper()
		payload := map[string]string{"memberId": memberID}
		if role != "" {
			payload["role"] = role
		}
		resp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+networkID+"/members", token, payload)
		if resp.Code != http.StatusCreated {
			t.Fatalf("add member %s: expected 201, got %d", memberID, resp.Code)
		}
	}
	addMember(ownerToken, memberID, "")
	addMember(ownerToken, moderatorID, "MODERATOR")
	addMember(ownerToken, fileAdminID, "FILE_ADMIN")
	addMember(ownerToken, readOnlyID, "READ_ONLY")

	createPeer := func(token, userID, deviceID, endpoint string) string {
		t.Helper()
		resp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+networkID+"/peers", token, map[string]string{
			"userId":   userID,
			"deviceId": deviceID,
			"endpoint": endpoint,
		})
		if resp.Code != http.StatusCreated {
			t.Fatalf("create peer for %s: expected 201, got %d", userID, resp.Code)
		}
		var body struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		decodeBody(t, resp, &body)
		return body.Data.ID
	}

	ownerPeerID := createPeer(ownerToken, ownerID, ownerDeviceID, "127.0.0.1:9960")
	memberPeerID := createPeer(memberToken, memberID, memberDeviceID, "127.0.0.1:9961")

	tunnel, err := application.TunnelCoordinator.RequestTunnelForUser(domain.UserID{Value: ownerID}, domain.NetworkID{Value: networkID}, domain.PeerID{Value: ownerPeerID}, domain.PeerID{Value: memberPeerID}, domain.TunnelModeP2P, 130)
	if err != nil {
		t.Fatalf("request tunnel: %v", err)
	}

	for _, actor := range []struct {
		name  string
		token string
	}{
		{name: "moderator", token: moderatorToken},
		{name: "file-admin", token: fileAdminToken},
		{name: "read-only", token: readOnlyToken},
	} {
		networkListResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/networks", actor.token, nil)
		if networkListResp.Code != http.StatusOK {
			t.Fatalf("expected %s network list to return 200, got %d", actor.name, networkListResp.Code)
		}
		networkGetResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/networks/"+networkID, actor.token, nil)
		if networkGetResp.Code != http.StatusOK {
			t.Fatalf("expected %s network get to return 200, got %d", actor.name, networkGetResp.Code)
		}
		peerListResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/networks/"+networkID+"/peers", actor.token, nil)
		if peerListResp.Code != http.StatusOK {
			t.Fatalf("expected %s peer list to return 200, got %d", actor.name, peerListResp.Code)
		}
		peerGetResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/peers/"+ownerPeerID, actor.token, nil)
		if peerGetResp.Code != http.StatusOK {
			t.Fatalf("expected %s peer get to return 200, got %d", actor.name, peerGetResp.Code)
		}
		tunnelListResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/networks/"+networkID+"/tunnels", actor.token, nil)
		if tunnelListResp.Code != http.StatusOK {
			t.Fatalf("expected %s tunnel list to return 200, got %d", actor.name, tunnelListResp.Code)
		}
		tunnelGetResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/tunnels/"+tunnel.ID.String(), actor.token, nil)
		if tunnelGetResp.Code != http.StatusOK {
			t.Fatalf("expected %s tunnel get to return 200, got %d", actor.name, tunnelGetResp.Code)
		}
	}

	outsiderNetworkGetResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/networks/"+networkID, outsiderToken, nil)
	if outsiderNetworkGetResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider network get to return 401, got %d", outsiderNetworkGetResp.Code)
	}
	outsiderPeerListResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/networks/"+networkID+"/peers", outsiderToken, nil)
	if outsiderPeerListResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider peer list to return 401, got %d", outsiderPeerListResp.Code)
	}
	outsiderPeerGetResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/peers/"+ownerPeerID, outsiderToken, nil)
	if outsiderPeerGetResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider peer get to return 401, got %d", outsiderPeerGetResp.Code)
	}
	outsiderTunnelListResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/networks/"+networkID+"/tunnels", outsiderToken, nil)
	if outsiderTunnelListResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider tunnel list to return 401, got %d", outsiderTunnelListResp.Code)
	}
	outsiderTunnelGetResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/tunnels/"+tunnel.ID.String(), outsiderToken, nil)
	if outsiderTunnelGetResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider tunnel get to return 401, got %d", outsiderTunnelGetResp.Code)
	}
}
