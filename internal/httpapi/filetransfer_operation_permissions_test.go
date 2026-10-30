package httpapi_test

import (
	"Ole/internal/app"
	"Ole/internal/domain"
	"Ole/internal/httpapi"
	"Ole/internal/store/memory"
	"encoding/base64"
	"net/http"
	"testing"
)

func TestFileTransferContentAndParticipantRoutesRespectPermissionBoundaries(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	fileTransferRepo := memory.NewFileTransferRepo()
	fileTransferPayloadRepo := memory.NewFileTransferPayloadRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:             domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:           domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:          domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:           domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		FileTransferService:     domain.NewFileTransferService(fileTransferRepo, peerRepo, networkRepo, auditRepo, fileTransferPayloadRepo),
		AuditRepo:               auditRepo,
		UserRepo:                userRepo,
		DeviceRepo:              deviceRepo,
		NetworkRepo:             networkRepo,
		PeerRepo:                peerRepo,
		FileTransferRepo:        fileTransferRepo,
		FileTransferPayloadRepo: fileTransferPayloadRepo,
		InviteRepo:              inviteRepo,
		SessionRepo:             sessionRepo,
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

	ownerID, ownerToken := registerAndLogin("owner-transfer-ops-http@example.com")
	memberID, memberToken := registerAndLogin("member-transfer-ops-http@example.com")
	fileAdminID, fileAdminToken := registerAndLogin("fileadmin-transfer-ops-http@example.com")
	readOnlyID, readOnlyToken := registerAndLogin("readonly-transfer-ops-http@example.com")
	_, outsiderToken := registerAndLogin("outsider-transfer-ops-http@example.com")

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
		"name":    "transfer-ops-http",
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

	ownerPeerID := createPeer(ownerToken, ownerID, ownerDeviceID, "127.0.0.1:9920")
	memberPeerID := createPeer(memberToken, memberID, memberDeviceID, "127.0.0.1:9921")

	payload := []byte("ole-http-transfer-ops")
	transferResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+networkID+"/file-transfers", memberToken, map[string]any{
		"fromPeerId": memberPeerID,
		"toPeerId":   ownerPeerID,
		"fileName":   "ops.txt",
		"sizeBytes":  len(payload),
	})
	if transferResp.Code != http.StatusCreated {
		t.Fatalf("create transfer: expected 201, got %d", transferResp.Code)
	}
	var transferBody struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, transferResp, &transferBody)

	memberUploadResp := performAuthenticatedJSON(t, router, http.MethodPut, "/api/v1/file-transfers/"+transferBody.Data.ID+"/content", memberToken, map[string]any{
		"contentType":   "text/plain",
		"payloadBase64": base64.StdEncoding.EncodeToString(payload),
	})
	if memberUploadResp.Code != http.StatusOK {
		t.Fatalf("expected member payload upload to return 200, got %d", memberUploadResp.Code)
	}

	readOnlyUploadResp := performAuthenticatedJSON(t, router, http.MethodPut, "/api/v1/file-transfers/"+transferBody.Data.ID+"/content", readOnlyToken, map[string]any{
		"contentType":   "text/plain",
		"payloadBase64": base64.StdEncoding.EncodeToString(payload),
	})
	if readOnlyUploadResp.Code != http.StatusForbidden {
		t.Fatalf("expected read-only payload upload to return 403, got %d", readOnlyUploadResp.Code)
	}
	outsiderUploadResp := performAuthenticatedJSON(t, router, http.MethodPut, "/api/v1/file-transfers/"+transferBody.Data.ID+"/content", outsiderToken, map[string]any{
		"contentType":   "text/plain",
		"payloadBase64": base64.StdEncoding.EncodeToString(payload),
	})
	if outsiderUploadResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider payload upload to return 401, got %d", outsiderUploadResp.Code)
	}

	fileAdminDownloadResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/file-transfers/"+transferBody.Data.ID+"/content", fileAdminToken, nil)
	if fileAdminDownloadResp.Code != http.StatusOK {
		t.Fatalf("expected file-admin payload download to return 200, got %d", fileAdminDownloadResp.Code)
	}
	readOnlyDownloadResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/file-transfers/"+transferBody.Data.ID+"/content", readOnlyToken, nil)
	if readOnlyDownloadResp.Code != http.StatusForbidden {
		t.Fatalf("expected read-only payload download to return 403, got %d", readOnlyDownloadResp.Code)
	}

	acceptResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/file-transfers/"+transferBody.Data.ID, ownerToken, map[string]string{
		"action": "ACCEPT",
	})
	if acceptResp.Code != http.StatusOK {
		t.Fatalf("expected owner accept to return 200, got %d", acceptResp.Code)
	}
	readOnlyAcceptResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/file-transfers/"+transferBody.Data.ID, readOnlyToken, map[string]string{
		"action": "ACCEPT",
	})
	if readOnlyAcceptResp.Code != http.StatusForbidden {
		t.Fatalf("expected read-only accept to return 403, got %d", readOnlyAcceptResp.Code)
	}

	memberProgressResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/file-transfers/"+transferBody.Data.ID, memberToken, map[string]any{
		"progressPercent": 50,
	})
	if memberProgressResp.Code != http.StatusOK {
		t.Fatalf("expected member progress update to return 200, got %d", memberProgressResp.Code)
	}
	outsiderProgressResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/file-transfers/"+transferBody.Data.ID, outsiderToken, map[string]any{
		"progressPercent": 75,
	})
	if outsiderProgressResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider progress update to return 401, got %d", outsiderProgressResp.Code)
	}
}
