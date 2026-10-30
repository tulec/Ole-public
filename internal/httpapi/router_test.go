package httpapi_test

import (
	"Ole/internal/app"
	"Ole/internal/domain"
	"Ole/internal/httpapi"
	"Ole/internal/relay"
	"Ole/internal/store/memory"
	"Ole/internal/tracectx"
	"Ole/internal/versioninfo"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeRelayStatusProvider struct {
	snapshot relay.StatusSnapshot
}

func (f fakeRelayStatusProvider) Snapshot() relay.StatusSnapshot {
	return f.snapshot
}

func TestRESTLifecycle(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
	}

	router := httpapi.NewRouter(application)

	createUserResp := performJSON(t, router, http.MethodPost, "/api/v1/users", map[string]string{
		"email":    "owner@example.com",
		"password": "secret",
	})
	if createUserResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createUserResp.Code)
	}

	var createdUser struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, createUserResp, &createdUser)

	loginResp := performJSON(t, router, http.MethodPost, "/api/v1/sessions", map[string]string{
		"email":    "owner@example.com",
		"password": "secret",
	})
	if loginResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", loginResp.Code)
	}

	var createdSession struct {
		Data struct {
			AccessToken string `json:"accessToken"`
		} `json:"data"`
	}
	decodeBody(t, loginResp, &createdSession)

	createNetworkResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks", createdSession.Data.AccessToken, map[string]string{
		"ownerId": createdUser.Data.ID,
		"name":    "friends",
		"access":  "INVITE_ONLY",
	})
	if createNetworkResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createNetworkResp.Code)
	}

	createDeviceResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/devices", createdSession.Data.AccessToken, map[string]string{
		"name":      "test-device",
		"publicKey": "public-key",
	})
	if createDeviceResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createDeviceResp.Code)
	}

	var createdDevice struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, createDeviceResp, &createdDevice)

	var createdNetwork struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, createNetworkResp, &createdNetwork)

	getNetworkReq := httptest.NewRequest(http.MethodGet, "/api/v1/networks/"+createdNetwork.Data.ID, nil)
	getNetworkReq.Header.Set("Authorization", "Bearer "+createdSession.Data.AccessToken)
	getNetworkResp := httptest.NewRecorder()
	router.ServeHTTP(getNetworkResp, getNetworkReq)
	if getNetworkResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", getNetworkResp.Code)
	}

	createPeerResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+createdNetwork.Data.ID+"/peers", createdSession.Data.AccessToken, map[string]string{
		"userId":   createdUser.Data.ID,
		"deviceId": createdDevice.Data.ID,
		"endpoint": "127.0.0.1:4000",
	})
	if createPeerResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createPeerResp.Code)
	}
	var createdPeer struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, createPeerResp, &createdPeer)

	createDeviceResp2 := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/devices", createdSession.Data.AccessToken, map[string]string{
		"name":      "test-device-2",
		"publicKey": "public-key-2",
	})
	if createDeviceResp2.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createDeviceResp2.Code)
	}
	var createdDevice2 struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, createDeviceResp2, &createdDevice2)

	createPeerResp2 := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+createdNetwork.Data.ID+"/peers", createdSession.Data.AccessToken, map[string]string{
		"userId":   createdUser.Data.ID,
		"deviceId": createdDevice2.Data.ID,
		"endpoint": "127.0.0.1:4001",
	})
	if createPeerResp2.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createPeerResp2.Code)
	}
	var createdPeer2 struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, createPeerResp2, &createdPeer2)

	createCandidateResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/peers/"+createdPeer.Data.ID+"/candidates", createdSession.Data.AccessToken, map[string]any{
		"type":       "HOST",
		"protocol":   "UDP",
		"address":    "127.0.0.1:4000",
		"preference": 100,
		"reachable":  true,
		"ttlSec":     120,
	})
	if createCandidateResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 for candidate create, got %d", createCandidateResp.Code)
	}

	patchPeerResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/peers/"+createdPeer.Data.ID, createdSession.Data.AccessToken, map[string]any{
		"reachability":    "DIRECT",
		"connectionState": "DIRECT_CANDIDATE",
	})
	if patchPeerResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for peer signaling patch, got %d", patchPeerResp.Code)
	}

	listCandidatesReq := httptest.NewRequest(http.MethodGet, "/api/v1/peers/"+createdPeer.Data.ID+"/candidates", nil)
	listCandidatesReq.Header.Set("Authorization", "Bearer "+createdSession.Data.AccessToken)
	listCandidatesResp := httptest.NewRecorder()
	router.ServeHTTP(listCandidatesResp, listCandidatesReq)
	if listCandidatesResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for candidate list, got %d", listCandidatesResp.Code)
	}

	createTunnelResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+createdNetwork.Data.ID+"/tunnels", createdSession.Data.AccessToken, map[string]any{
		"peerAId": createdPeer.Data.ID,
		"peerBId": createdPeer2.Data.ID,
		"mode":    "P2P",
	})
	if createTunnelResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 for tunnel create, got %d", createTunnelResp.Code)
	}
	var createdTunnel struct {
		Data struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"data"`
	}
	decodeBody(t, createTunnelResp, &createdTunnel)
	if createdTunnel.Data.State != "NEGOTIATING" {
		t.Fatalf("expected negotiating tunnel, got %q", createdTunnel.Data.State)
	}

	openTunnelResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/tunnels/"+createdTunnel.Data.ID, createdSession.Data.AccessToken, map[string]any{
		"state": "OPEN",
	})
	if openTunnelResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for tunnel open patch, got %d", openTunnelResp.Code)
	}

	revokeAllReq := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/all", nil)
	revokeAllReq.Header.Set("Authorization", "Bearer "+createdSession.Data.AccessToken)
	revokeAllResp := httptest.NewRecorder()
	router.ServeHTTP(revokeAllResp, revokeAllReq)
	if revokeAllResp.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", revokeAllResp.Code)
	}
}

func TestTraceHeadersPropagateAcrossRequests(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
	}

	router := httpapi.NewRouter(application)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set(tracectx.HeaderTraceID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	req.Header.Set(tracectx.HeaderParentSpanID, "bbbbbbbbbbbbbbbb")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	if got := resp.Header().Get(tracectx.HeaderTraceID); got != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("expected response trace header to preserve trace id, got %q", got)
	}
	if got := resp.Header().Get(tracectx.HeaderParentSpanID); got != "bbbbbbbbbbbbbbbb" {
		t.Fatalf("expected response parent span header to preserve client span id, got %q", got)
	}
	if got := resp.Header().Get(tracectx.HeaderSpanID); len(got) != 16 {
		t.Fatalf("expected response span id header, got %q", got)
	}
}

func TestSensitiveNetworkDeviceApprovalFlow(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
	}
	router := httpapi.NewRouter(application)

	ownerUserResp := performJSON(t, router, http.MethodPost, "/api/v1/users", map[string]string{"email": "owner-sensitive@example.com", "password": "secret"})
	if ownerUserResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", ownerUserResp.Code)
	}
	memberUserResp := performJSON(t, router, http.MethodPost, "/api/v1/users", map[string]string{"email": "member-sensitive@example.com", "password": "secret"})
	if memberUserResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", memberUserResp.Code)
	}
	var ownerUser struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	var memberUser struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, ownerUserResp, &ownerUser)
	decodeBody(t, memberUserResp, &memberUser)

	ownerLoginResp := performJSON(t, router, http.MethodPost, "/api/v1/sessions", map[string]string{"email": "owner-sensitive@example.com", "password": "secret"})
	memberLoginResp := performJSON(t, router, http.MethodPost, "/api/v1/sessions", map[string]string{"email": "member-sensitive@example.com", "password": "secret"})
	if ownerLoginResp.Code != http.StatusCreated || memberLoginResp.Code != http.StatusCreated {
		t.Fatalf("expected session creation for both users, got owner=%d member=%d", ownerLoginResp.Code, memberLoginResp.Code)
	}
	var ownerSession struct {
		Data struct {
			AccessToken string `json:"accessToken"`
		} `json:"data"`
	}
	var memberSession struct {
		Data struct {
			AccessToken string `json:"accessToken"`
		} `json:"data"`
	}
	decodeBody(t, ownerLoginResp, &ownerSession)
	decodeBody(t, memberLoginResp, &memberSession)

	ownerDeviceResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/devices", ownerSession.Data.AccessToken, map[string]string{"name": "owner-device", "publicKey": "owner-pub"})
	memberDeviceResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/devices", memberSession.Data.AccessToken, map[string]string{"name": "member-device", "publicKey": "member-pub"})
	if ownerDeviceResp.Code != http.StatusCreated || memberDeviceResp.Code != http.StatusCreated {
		t.Fatalf("expected device creation for both users, got owner=%d member=%d", ownerDeviceResp.Code, memberDeviceResp.Code)
	}
	var memberDevice struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, memberDeviceResp, &memberDevice)

	createNetworkResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks", ownerSession.Data.AccessToken, map[string]any{
		"ownerId":                ownerUser.Data.ID,
		"name":                   "sensitive",
		"access":                 "INVITE_ONLY",
		"deviceApprovalRequired": true,
	})
	if createNetworkResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createNetworkResp.Code)
	}
	var createdNetwork struct {
		Data struct {
			ID                     string   `json:"id"`
			DeviceApprovalRequired bool     `json:"deviceApprovalRequired"`
			ApprovedDeviceIDs      []string `json:"approvedDeviceIds"`
		} `json:"data"`
	}
	decodeBody(t, createNetworkResp, &createdNetwork)
	if !createdNetwork.Data.DeviceApprovalRequired || len(createdNetwork.Data.ApprovedDeviceIDs) != 0 {
		t.Fatalf("expected sensitive network response, got %#v", createdNetwork.Data)
	}

	addMemberResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+createdNetwork.Data.ID+"/members", ownerSession.Data.AccessToken, map[string]string{
		"ownerId":  ownerUser.Data.ID,
		"memberId": memberUser.Data.ID,
	})
	if addMemberResp.Code != http.StatusCreated && addMemberResp.Code != http.StatusNoContent && addMemberResp.Code != http.StatusOK {
		t.Fatalf("expected successful member add, got %d", addMemberResp.Code)
	}

	memberPeerResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+createdNetwork.Data.ID+"/peers", memberSession.Data.AccessToken, map[string]string{
		"userId":   memberUser.Data.ID,
		"deviceId": memberDevice.Data.ID,
		"endpoint": "127.0.0.1:4012",
	})
	if memberPeerResp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 before device approval, got %d", memberPeerResp.Code)
	}

	approveResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+createdNetwork.Data.ID+"/device-approvals/"+memberDevice.Data.ID, ownerSession.Data.AccessToken, nil)
	if approveResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for device approval, got %d", approveResp.Code)
	}
	var approvedNetwork struct {
		Data struct {
			ApprovedDeviceIDs []string `json:"approvedDeviceIds"`
		} `json:"data"`
	}
	decodeBody(t, approveResp, &approvedNetwork)
	if len(approvedNetwork.Data.ApprovedDeviceIDs) != 1 || approvedNetwork.Data.ApprovedDeviceIDs[0] != memberDevice.Data.ID {
		t.Fatalf("expected approved device in response, got %#v", approvedNetwork.Data.ApprovedDeviceIDs)
	}

	memberPeerResp = performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+createdNetwork.Data.ID+"/peers", memberSession.Data.AccessToken, map[string]string{
		"userId":   memberUser.Data.ID,
		"deviceId": memberDevice.Data.ID,
		"endpoint": "127.0.0.1:4012",
	})
	if memberPeerResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 after device approval, got %d", memberPeerResp.Code)
	}
}

func TestNetworkNameResolutionPolicyFlow(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
	}
	router := httpapi.NewRouter(application)

	userResp := performJSON(t, router, http.MethodPost, "/api/v1/users", map[string]string{"email": "dns-owner@example.com", "password": "secret"})
	if userResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", userResp.Code)
	}
	var user struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, userResp, &user)

	loginResp := performJSON(t, router, http.MethodPost, "/api/v1/sessions", map[string]string{"email": "dns-owner@example.com", "password": "secret"})
	if loginResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", loginResp.Code)
	}
	var session struct {
		Data struct {
			AccessToken string `json:"accessToken"`
		} `json:"data"`
	}
	decodeBody(t, loginResp, &session)

	createNetworkResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks", session.Data.AccessToken, map[string]any{
		"ownerId":            user.Data.ID,
		"name":               "friends",
		"access":             "INVITE_ONLY",
		"nameResolutionMode": "NETWORK_ONLY",
		"dnsLabel":           "friends-lan",
	})
	if createNetworkResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createNetworkResp.Code)
	}
	var createdNetwork struct {
		Data struct {
			ID                 string `json:"id"`
			NameResolutionMode string `json:"nameResolutionMode"`
			DNSLabel           string `json:"dnsLabel"`
		} `json:"data"`
	}
	decodeBody(t, createNetworkResp, &createdNetwork)
	if createdNetwork.Data.NameResolutionMode != "NETWORK_ONLY" || createdNetwork.Data.DNSLabel != "friends-lan" {
		t.Fatalf("expected network dns policy to round-trip on create, got %#v", createdNetwork.Data)
	}

	updateResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/networks/"+createdNetwork.Data.ID+"/name-resolution", session.Data.AccessToken, map[string]any{
		"mode":     "DISABLED",
		"dnsLabel": "ignored",
	})
	if updateResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", updateResp.Code)
	}
	var updatedNetwork struct {
		Data struct {
			NameResolutionMode string `json:"nameResolutionMode"`
			DNSLabel           string `json:"dnsLabel"`
		} `json:"data"`
	}
	decodeBody(t, updateResp, &updatedNetwork)
	if updatedNetwork.Data.NameResolutionMode != "DISABLED" || updatedNetwork.Data.DNSLabel != "" {
		t.Fatalf("expected disabled dns policy to clear label, got %#v", updatedNetwork.Data)
	}
}

func TestNetworkRoutingPolicyFlow(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
	}
	router := httpapi.NewRouter(application)

	userResp := performJSON(t, router, http.MethodPost, "/api/v1/users", map[string]string{"email": "routing-owner@example.com", "password": "secret"})
	if userResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", userResp.Code)
	}
	var user struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, userResp, &user)

	loginResp := performJSON(t, router, http.MethodPost, "/api/v1/sessions", map[string]string{"email": "routing-owner@example.com", "password": "secret"})
	if loginResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", loginResp.Code)
	}
	var session struct {
		Data struct {
			AccessToken string `json:"accessToken"`
		} `json:"data"`
	}
	decodeBody(t, loginResp, &session)

	createNetworkResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks", session.Data.AccessToken, map[string]any{
		"ownerId":       user.Data.ID,
		"name":          "friends",
		"access":        "INVITE_ONLY",
		"routingPolicy": "FULL",
	})
	if createNetworkResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createNetworkResp.Code)
	}
	var createdNetwork struct {
		Data struct {
			ID            string `json:"id"`
			RoutingPolicy string `json:"routingPolicy"`
		} `json:"data"`
	}
	decodeBody(t, createNetworkResp, &createdNetwork)
	if createdNetwork.Data.RoutingPolicy != "FULL" {
		t.Fatalf("expected network routing policy to round-trip on create, got %#v", createdNetwork.Data)
	}

	updateResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/networks/"+createdNetwork.Data.ID+"/routing-policy", session.Data.AccessToken, map[string]any{
		"policy": "SPLIT",
	})
	if updateResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", updateResp.Code)
	}
	var updatedNetwork struct {
		Data struct {
			RoutingPolicy string `json:"routingPolicy"`
		} `json:"data"`
	}
	decodeBody(t, updateResp, &updatedNetwork)
	if updatedNetwork.Data.RoutingPolicy != "SPLIT" {
		t.Fatalf("expected split routing policy after update, got %#v", updatedNetwork.Data)
	}
}

func TestNetworkFileTransferPolicyFlow(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
	}
	router := httpapi.NewRouter(application)

	userResp := performJSON(t, router, http.MethodPost, "/api/v1/users", map[string]string{"email": "file-policy-owner@example.com", "password": "secret"})
	if userResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", userResp.Code)
	}
	var user struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, userResp, &user)

	loginResp := performJSON(t, router, http.MethodPost, "/api/v1/sessions", map[string]string{"email": "file-policy-owner@example.com", "password": "secret"})
	if loginResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", loginResp.Code)
	}
	var session struct {
		Data struct {
			AccessToken string `json:"accessToken"`
		} `json:"data"`
	}
	decodeBody(t, loginResp, &session)

	createNetworkResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks", session.Data.AccessToken, map[string]any{
		"ownerId":              user.Data.ID,
		"name":                 "friends",
		"access":               "INVITE_ONLY",
		"fileTransfersEnabled": false,
		"fileTransferMaxBytes": 2048,
	})
	if createNetworkResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createNetworkResp.Code)
	}
	var createdNetwork struct {
		Data struct {
			ID                   string `json:"id"`
			FileTransfersEnabled bool   `json:"fileTransfersEnabled"`
			FileTransferMaxBytes int64  `json:"fileTransferMaxBytes"`
		} `json:"data"`
	}
	decodeBody(t, createNetworkResp, &createdNetwork)
	if createdNetwork.Data.FileTransfersEnabled || createdNetwork.Data.FileTransferMaxBytes != 2048 {
		t.Fatalf("expected network file transfer policy to round-trip on create, got %#v", createdNetwork.Data)
	}

	updateResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/networks/"+createdNetwork.Data.ID+"/file-transfer-policy", session.Data.AccessToken, map[string]any{
		"enabled":  true,
		"maxBytes": 4096,
	})
	if updateResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", updateResp.Code)
	}
	var updatedNetwork struct {
		Data struct {
			FileTransfersEnabled bool  `json:"fileTransfersEnabled"`
			FileTransferMaxBytes int64 `json:"fileTransferMaxBytes"`
		} `json:"data"`
	}
	decodeBody(t, updateResp, &updatedNetwork)
	if !updatedNetwork.Data.FileTransfersEnabled || updatedNetwork.Data.FileTransferMaxBytes != 4096 {
		t.Fatalf("expected enabled file transfer policy after update, got %#v", updatedNetwork.Data)
	}
}

func TestNetworkReadVisibilityAndSettingsPermissionBoundaries(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
	}
	router := httpapi.NewRouter(application)

	owner, err := application.AuthService.Register("owner-boundary@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	readOnlyUser, err := application.AuthService.Register("readonly-boundary@example.com", "secret")
	if err != nil {
		t.Fatalf("register read-only user: %v", err)
	}
	outsider, err := application.AuthService.Register("outsider-boundary@example.com", "secret")
	if err != nil {
		t.Fatalf("register outsider: %v", err)
	}

	readOnlySession, err := application.AuthService.Login(readOnlyUser.Email, "secret", domain.SessionMetadata{DeviceName: "readonly"})
	if err != nil {
		t.Fatalf("login read-only user: %v", err)
	}
	outsiderSession, err := application.AuthService.Login(outsider.Email, "secret", domain.SessionMetadata{DeviceName: "outsider"})
	if err != nil {
		t.Fatalf("login outsider: %v", err)
	}

	network, err := application.NetworkService.CreateNetwork(owner.ID, "boundary-net", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if err := application.NetworkService.AddMember(owner.ID, network.ID, readOnlyUser.ID); err != nil {
		t.Fatalf("add read-only user: %v", err)
	}
	if err := application.NetworkService.ChangeMemberRole(owner.ID, network.ID, readOnlyUser.ID, domain.NetworkRoleReadOnly); err != nil {
		t.Fatalf("set read-only role: %v", err)
	}

	ownerDeviceA, err := application.DeviceService.Enroll(owner.ID, "owner-a", "owner-boundary-pub-a", 100)
	if err != nil {
		t.Fatalf("enroll owner device A: %v", err)
	}
	ownerDeviceB, err := application.DeviceService.Enroll(owner.ID, "owner-b", "owner-boundary-pub-b", 101)
	if err != nil {
		t.Fatalf("enroll owner device B: %v", err)
	}
	peerA, err := application.PeerDirectory.RegisterPeer(owner.ID, ownerDeviceA.ID, network.ID, "127.0.0.1:9200", 110)
	if err != nil {
		t.Fatalf("register peer A: %v", err)
	}
	peerB, err := application.PeerDirectory.RegisterPeer(owner.ID, ownerDeviceB.ID, network.ID, "127.0.0.1:9201", 111)
	if err != nil {
		t.Fatalf("register peer B: %v", err)
	}
	tunnel, err := application.TunnelCoordinator.RequestTunnelForUser(owner.ID, network.ID, peerA.ID, peerB.ID, domain.TunnelModeP2P, 120)
	if err != nil {
		t.Fatalf("request tunnel: %v", err)
	}

	outsiderNetworkResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/networks/"+network.ID.String(), outsiderSession.AccessToken, nil)
	if outsiderNetworkResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider network get to return 401, got %d", outsiderNetworkResp.Code)
	}
	readOnlyNetworkResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/networks/"+network.ID.String(), readOnlySession.AccessToken, nil)
	if readOnlyNetworkResp.Code != http.StatusOK {
		t.Fatalf("expected read-only network get to return 200, got %d", readOnlyNetworkResp.Code)
	}

	outsiderPeerListResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/networks/"+network.ID.String()+"/peers", outsiderSession.AccessToken, nil)
	if outsiderPeerListResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider peer list to return 401, got %d", outsiderPeerListResp.Code)
	}
	readOnlyPeerListResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/networks/"+network.ID.String()+"/peers", readOnlySession.AccessToken, nil)
	if readOnlyPeerListResp.Code != http.StatusOK {
		t.Fatalf("expected read-only peer list to return 200, got %d", readOnlyPeerListResp.Code)
	}

	outsiderPeerResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/peers/"+peerA.ID.String(), outsiderSession.AccessToken, nil)
	if outsiderPeerResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider peer get to return 401, got %d", outsiderPeerResp.Code)
	}
	readOnlyPeerResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/peers/"+peerA.ID.String(), readOnlySession.AccessToken, nil)
	if readOnlyPeerResp.Code != http.StatusOK {
		t.Fatalf("expected read-only peer get to return 200, got %d", readOnlyPeerResp.Code)
	}

	outsiderTunnelListResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/networks/"+network.ID.String()+"/tunnels", outsiderSession.AccessToken, nil)
	if outsiderTunnelListResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider tunnel list to return 401, got %d", outsiderTunnelListResp.Code)
	}
	readOnlyTunnelListResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/networks/"+network.ID.String()+"/tunnels", readOnlySession.AccessToken, nil)
	if readOnlyTunnelListResp.Code != http.StatusOK {
		t.Fatalf("expected read-only tunnel list to return 200, got %d", readOnlyTunnelListResp.Code)
	}

	outsiderTunnelResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/tunnels/"+tunnel.ID.String(), outsiderSession.AccessToken, nil)
	if outsiderTunnelResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider tunnel get to return 401, got %d", outsiderTunnelResp.Code)
	}
	readOnlyTunnelResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/tunnels/"+tunnel.ID.String(), readOnlySession.AccessToken, nil)
	if readOnlyTunnelResp.Code != http.StatusOK {
		t.Fatalf("expected read-only tunnel get to return 200, got %d", readOnlyTunnelResp.Code)
	}

	readOnlyRoutingUpdateResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/networks/"+network.ID.String()+"/routing-policy", readOnlySession.AccessToken, map[string]any{
		"policy": "FULL",
	})
	if readOnlyRoutingUpdateResp.Code != http.StatusForbidden {
		t.Fatalf("expected read-only routing update to return 403, got %d", readOnlyRoutingUpdateResp.Code)
	}
}

func TestNetworkManagePermissionBoundaries(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
	}
	router := httpapi.NewRouter(application)

	owner, err := application.AuthService.Register("owner-manage-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	adminUser, err := application.AuthService.Register("admin-manage-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register admin: %v", err)
	}
	readOnlyUser, err := application.AuthService.Register("readonly-manage-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register read-only: %v", err)
	}
	outsider, err := application.AuthService.Register("outsider-manage-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register outsider: %v", err)
	}
	newMember, err := application.AuthService.Register("new-member-manage-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register new member: %v", err)
	}

	adminSession, err := application.AuthService.Login(adminUser.Email, "secret", domain.SessionMetadata{DeviceName: "admin"})
	if err != nil {
		t.Fatalf("login admin: %v", err)
	}
	readOnlySession, err := application.AuthService.Login(readOnlyUser.Email, "secret", domain.SessionMetadata{DeviceName: "readonly"})
	if err != nil {
		t.Fatalf("login read-only: %v", err)
	}
	outsiderSession, err := application.AuthService.Login(outsider.Email, "secret", domain.SessionMetadata{DeviceName: "outsider"})
	if err != nil {
		t.Fatalf("login outsider: %v", err)
	}

	network, err := application.NetworkService.CreateNetworkWithPolicy(owner.ID, "manage-http-boundary", domain.NetworkAccessInviteOnly, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if err := application.NetworkService.AddMember(owner.ID, network.ID, adminUser.ID); err != nil {
		t.Fatalf("add admin user: %v", err)
	}
	if err := application.NetworkService.ChangeMemberRole(owner.ID, network.ID, adminUser.ID, domain.NetworkRoleAdmin); err != nil {
		t.Fatalf("set admin role: %v", err)
	}
	if err := application.NetworkService.AddMember(owner.ID, network.ID, readOnlyUser.ID); err != nil {
		t.Fatalf("add read-only user: %v", err)
	}
	if err := application.NetworkService.ChangeMemberRole(owner.ID, network.ID, readOnlyUser.ID, domain.NetworkRoleReadOnly); err != nil {
		t.Fatalf("set read-only role: %v", err)
	}

	adminDevice, err := application.DeviceService.Enroll(adminUser.ID, "admin-http-device", "admin-http-pub", 100)
	if err != nil {
		t.Fatalf("enroll admin device: %v", err)
	}

	adminAddMemberResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+network.ID.String()+"/members", adminSession.AccessToken, map[string]string{
		"memberId": newMember.ID.String(),
	})
	if adminAddMemberResp.Code != http.StatusCreated {
		t.Fatalf("expected admin add member to return 201, got %d", adminAddMemberResp.Code)
	}

	adminInviteResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+network.ID.String()+"/invites", adminSession.AccessToken, map[string]any{
		"ttlSec":  3600,
		"maxUses": 1,
	})
	if adminInviteResp.Code != http.StatusCreated {
		t.Fatalf("expected admin invite creation to return 201, got %d", adminInviteResp.Code)
	}

	adminApproveResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+network.ID.String()+"/device-approvals/"+adminDevice.ID.String(), adminSession.AccessToken, nil)
	if adminApproveResp.Code != http.StatusOK {
		t.Fatalf("expected admin device approval to return 200, got %d", adminApproveResp.Code)
	}

	readOnlyAddMemberResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+network.ID.String()+"/members", readOnlySession.AccessToken, map[string]string{
		"memberId": outsider.ID.String(),
	})
	if readOnlyAddMemberResp.Code != http.StatusForbidden {
		t.Fatalf("expected read-only add member to return 403, got %d", readOnlyAddMemberResp.Code)
	}
	readOnlyInviteResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+network.ID.String()+"/invites", readOnlySession.AccessToken, map[string]any{
		"ttlSec":  3600,
		"maxUses": 1,
	})
	if readOnlyInviteResp.Code != http.StatusForbidden {
		t.Fatalf("expected read-only invite creation to return 403, got %d", readOnlyInviteResp.Code)
	}
	readOnlyApproveResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+network.ID.String()+"/device-approvals/"+adminDevice.ID.String(), readOnlySession.AccessToken, nil)
	if readOnlyApproveResp.Code != http.StatusForbidden {
		t.Fatalf("expected read-only device approval to return 403, got %d", readOnlyApproveResp.Code)
	}

	outsiderAddMemberResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+network.ID.String()+"/members", outsiderSession.AccessToken, map[string]string{
		"memberId": outsider.ID.String(),
	})
	if outsiderAddMemberResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider add member to return 401, got %d", outsiderAddMemberResp.Code)
	}
	outsiderInviteResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+network.ID.String()+"/invites", outsiderSession.AccessToken, map[string]any{
		"ttlSec":  3600,
		"maxUses": 1,
	})
	if outsiderInviteResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider invite creation to return 401, got %d", outsiderInviteResp.Code)
	}
	outsiderApproveResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+network.ID.String()+"/device-approvals/"+adminDevice.ID.String(), outsiderSession.AccessToken, nil)
	if outsiderApproveResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider device approval to return 401, got %d", outsiderApproveResp.Code)
	}

	adminRoleChangeResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/networks/"+network.ID.String()+"/members/"+newMember.ID.String(), adminSession.AccessToken, map[string]string{
		"role": "MODERATOR",
	})
	if adminRoleChangeResp.Code != http.StatusForbidden {
		t.Fatalf("expected admin role change to remain owner-only and return 403, got %d", adminRoleChangeResp.Code)
	}
}

func TestNetworkAuditModerationBoundaries(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
	}
	router := httpapi.NewRouter(application)

	owner, err := application.AuthService.Register("owner-audit-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	adminUser, err := application.AuthService.Register("admin-audit-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register admin: %v", err)
	}
	moderatorUser, err := application.AuthService.Register("moderator-audit-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register moderator: %v", err)
	}
	fileAdminUser, err := application.AuthService.Register("file-admin-audit-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register file admin: %v", err)
	}
	memberUser, err := application.AuthService.Register("member-audit-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register member: %v", err)
	}
	readOnlyUser, err := application.AuthService.Register("readonly-audit-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register read-only: %v", err)
	}
	outsider, err := application.AuthService.Register("outsider-audit-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register outsider: %v", err)
	}

	login := func(email string) string {
		session, loginErr := application.AuthService.Login(email, "secret", domain.SessionMetadata{DeviceName: email})
		if loginErr != nil {
			t.Fatalf("login %s: %v", email, loginErr)
		}
		return session.AccessToken
	}

	adminToken := login(adminUser.Email)
	moderatorToken := login(moderatorUser.Email)
	fileAdminToken := login(fileAdminUser.Email)
	memberToken := login(memberUser.Email)
	readOnlyToken := login(readOnlyUser.Email)
	outsiderToken := login(outsider.Email)

	network, err := application.NetworkService.CreateNetwork(owner.ID, "audit-http-boundary", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	assignRole := func(user domain.UserID, role domain.NetworkRole) {
		if err := application.NetworkService.AddMember(owner.ID, network.ID, user); err != nil {
			t.Fatalf("add member %s: %v", user.String(), err)
		}
		if role != domain.NetworkRoleMember {
			if err := application.NetworkService.ChangeMemberRole(owner.ID, network.ID, user, role); err != nil {
				t.Fatalf("set role %s for %s: %v", role, user.String(), err)
			}
		}
	}
	assignRole(adminUser.ID, domain.NetworkRoleAdmin)
	assignRole(moderatorUser.ID, domain.NetworkRoleModerator)
	assignRole(fileAdminUser.ID, domain.NetworkRoleFileAdmin)
	assignRole(memberUser.ID, domain.NetworkRoleMember)
	assignRole(readOnlyUser.ID, domain.NetworkRoleReadOnly)

	_ = auditRepo.Append(&domain.AuditEvent{
		ID:            "aud-http-1",
		ActorUserID:   owner.ID,
		NetworkID:     network.ID,
		Type:          "network.member_added",
		Details:       memberUser.ID.String(),
		CreatedAtUnix: 100,
	})
	_ = auditRepo.Append(&domain.AuditEvent{
		ID:            "aud-http-2",
		ActorUserID:   moderatorUser.ID,
		NetworkID:     network.ID,
		Type:          "peer.registered",
		Details:       "peer-http-1",
		CreatedAtUnix: 101,
	})

	request := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/networks/"+network.ID.String()+"/audit-events?q=peer", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		return resp
	}

	adminResp := request(adminToken)
	if adminResp.Code != http.StatusOK {
		t.Fatalf("expected admin audit list to return 200, got %d", adminResp.Code)
	}
	var adminBody struct {
		Data []struct {
			ID        string `json:"id"`
			NetworkID string `json:"networkId"`
		} `json:"data"`
	}
	decodeBody(t, adminResp, &adminBody)
	if len(adminBody.Data) != 1 || adminBody.Data[0].ID != "aud-http-2" || adminBody.Data[0].NetworkID != network.ID.String() {
		t.Fatalf("expected filtered network audit response for admin, got %#v", adminBody.Data)
	}

	moderatorResp := request(moderatorToken)
	if moderatorResp.Code != http.StatusOK {
		t.Fatalf("expected moderator audit list to return 200, got %d", moderatorResp.Code)
	}
	fileAdminResp := request(fileAdminToken)
	if fileAdminResp.Code != http.StatusForbidden {
		t.Fatalf("expected file admin audit list to return 403, got %d", fileAdminResp.Code)
	}
	memberResp := request(memberToken)
	if memberResp.Code != http.StatusForbidden {
		t.Fatalf("expected member audit list to return 403, got %d", memberResp.Code)
	}
	readOnlyResp := request(readOnlyToken)
	if readOnlyResp.Code != http.StatusForbidden {
		t.Fatalf("expected read-only audit list to return 403, got %d", readOnlyResp.Code)
	}
	outsiderResp := request(outsiderToken)
	if outsiderResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider audit list to return 401, got %d", outsiderResp.Code)
	}
}

func TestPeerPatchRequiresPeerOwnership(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
	}
	router := httpapi.NewRouter(application)

	owner, err := application.AuthService.Register("owner-peer-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	outsider, err := application.AuthService.Register("outsider-peer-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register outsider: %v", err)
	}
	ownerSession, err := application.AuthService.Login(owner.Email, "secret", domain.SessionMetadata{DeviceName: "owner"})
	if err != nil {
		t.Fatalf("login owner: %v", err)
	}
	outsiderSession, err := application.AuthService.Login(outsider.Email, "secret", domain.SessionMetadata{DeviceName: "outsider"})
	if err != nil {
		t.Fatalf("login outsider: %v", err)
	}

	network, err := application.NetworkService.CreateNetwork(owner.ID, "peer-http-boundary", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	device, err := application.DeviceService.Enroll(owner.ID, "owner-peer-http-device", "owner-peer-http-pub", 100)
	if err != nil {
		t.Fatalf("enroll owner device: %v", err)
	}
	peer, err := application.PeerDirectory.RegisterPeer(owner.ID, device.ID, network.ID, "127.0.0.1:9400", 110)
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}

	outsiderHeartbeatResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/peers/"+peer.ID.String(), outsiderSession.AccessToken, map[string]any{
		"endpoint": "127.0.0.1:9401",
	})
	if outsiderHeartbeatResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider heartbeat patch to return 401, got %d", outsiderHeartbeatResp.Code)
	}
	storedPeer, err := application.PeerDirectory.GetPeer(peer.ID)
	if err != nil {
		t.Fatalf("reload peer after outsider heartbeat attempt: %v", err)
	}
	if storedPeer.Endpoint != "127.0.0.1:9400" {
		t.Fatalf("expected outsider heartbeat attempt to leave endpoint unchanged, got %q", storedPeer.Endpoint)
	}

	ownerHeartbeatResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/peers/"+peer.ID.String(), ownerSession.AccessToken, map[string]any{
		"endpoint": "127.0.0.1:9401",
	})
	if ownerHeartbeatResp.Code != http.StatusOK {
		t.Fatalf("expected owner heartbeat patch to return 200, got %d", ownerHeartbeatResp.Code)
	}

	outsiderDisconnectResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/peers/"+peer.ID.String(), outsiderSession.AccessToken, map[string]any{
		"status": "OFFLINE",
	})
	if outsiderDisconnectResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider disconnect patch to return 401, got %d", outsiderDisconnectResp.Code)
	}

	ownerDisconnectResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/peers/"+peer.ID.String(), ownerSession.AccessToken, map[string]any{
		"status": "OFFLINE",
	})
	if ownerDisconnectResp.Code != http.StatusOK {
		t.Fatalf("expected owner disconnect patch to return 200, got %d", ownerDisconnectResp.Code)
	}
	storedPeer, err = application.PeerDirectory.GetPeer(peer.ID)
	if err != nil {
		t.Fatalf("reload peer after owner disconnect: %v", err)
	}
	if storedPeer.Status != domain.PeerStatusOffline {
		t.Fatalf("expected owner disconnect to mark peer offline, got %#v", storedPeer)
	}
}

func TestDeleteNetworkPermissionBoundaries(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
	}
	router := httpapi.NewRouter(application)

	owner, err := application.AuthService.Register("owner-delete-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	adminUser, err := application.AuthService.Register("admin-delete-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register admin: %v", err)
	}
	readOnlyUser, err := application.AuthService.Register("readonly-delete-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register read-only: %v", err)
	}
	outsider, err := application.AuthService.Register("outsider-delete-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register outsider: %v", err)
	}

	ownerSession, err := application.AuthService.Login(owner.Email, "secret", domain.SessionMetadata{DeviceName: "owner"})
	if err != nil {
		t.Fatalf("login owner: %v", err)
	}
	adminSession, err := application.AuthService.Login(adminUser.Email, "secret", domain.SessionMetadata{DeviceName: "admin"})
	if err != nil {
		t.Fatalf("login admin: %v", err)
	}
	readOnlySession, err := application.AuthService.Login(readOnlyUser.Email, "secret", domain.SessionMetadata{DeviceName: "readonly"})
	if err != nil {
		t.Fatalf("login read-only: %v", err)
	}
	outsiderSession, err := application.AuthService.Login(outsider.Email, "secret", domain.SessionMetadata{DeviceName: "outsider"})
	if err != nil {
		t.Fatalf("login outsider: %v", err)
	}

	createFixture := func(name string) *domain.Network {
		network, err := application.NetworkService.CreateNetwork(owner.ID, name, domain.NetworkAccessInviteOnly)
		if err != nil {
			t.Fatalf("create network %q: %v", name, err)
		}
		if err := application.NetworkService.AddMember(owner.ID, network.ID, adminUser.ID); err != nil {
			t.Fatalf("add admin to %q: %v", name, err)
		}
		if err := application.NetworkService.ChangeMemberRole(owner.ID, network.ID, adminUser.ID, domain.NetworkRoleAdmin); err != nil {
			t.Fatalf("set admin role on %q: %v", name, err)
		}
		if err := application.NetworkService.AddMember(owner.ID, network.ID, readOnlyUser.ID); err != nil {
			t.Fatalf("add read-only to %q: %v", name, err)
		}
		if err := application.NetworkService.ChangeMemberRole(owner.ID, network.ID, readOnlyUser.ID, domain.NetworkRoleReadOnly); err != nil {
			t.Fatalf("set read-only role on %q: %v", name, err)
		}
		return network
	}

	deleteWithToken := func(token, networkID string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/networks/"+networkID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		return resp
	}

	adminNetwork := createFixture("admin-delete-http-boundary")
	adminDeleteResp := deleteWithToken(adminSession.AccessToken, adminNetwork.ID.String())
	if adminDeleteResp.Code != http.StatusForbidden {
		t.Fatalf("expected admin delete to return 403, got %d", adminDeleteResp.Code)
	}

	readOnlyNetwork := createFixture("readonly-delete-http-boundary")
	readOnlyDeleteResp := deleteWithToken(readOnlySession.AccessToken, readOnlyNetwork.ID.String())
	if readOnlyDeleteResp.Code != http.StatusForbidden {
		t.Fatalf("expected read-only delete to return 403, got %d", readOnlyDeleteResp.Code)
	}

	outsiderNetwork := createFixture("outsider-delete-http-boundary")
	outsiderDeleteResp := deleteWithToken(outsiderSession.AccessToken, outsiderNetwork.ID.String())
	if outsiderDeleteResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider delete to return 401, got %d", outsiderDeleteResp.Code)
	}

	ownerNetwork := createFixture("owner-delete-http-boundary")
	ownerDeleteResp := deleteWithToken(ownerSession.AccessToken, ownerNetwork.ID.String())
	if ownerDeleteResp.Code != http.StatusNoContent {
		t.Fatalf("expected owner delete to return 204, got %d", ownerDeleteResp.Code)
	}
	getDeletedResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/networks/"+ownerNetwork.ID.String(), ownerSession.AccessToken, nil)
	if getDeletedResp.Code != http.StatusNotFound {
		t.Fatalf("expected deleted network fetch to return 404, got %d", getDeletedResp.Code)
	}
}

func TestPeerPatchEmptyPayloadStillRequiresOwnership(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
	}
	router := httpapi.NewRouter(application)

	owner, err := application.AuthService.Register("owner-empty-patch@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	outsider, err := application.AuthService.Register("outsider-empty-patch@example.com", "secret")
	if err != nil {
		t.Fatalf("register outsider: %v", err)
	}
	ownerSession, err := application.AuthService.Login(owner.Email, "secret", domain.SessionMetadata{DeviceName: "owner"})
	if err != nil {
		t.Fatalf("login owner: %v", err)
	}
	outsiderSession, err := application.AuthService.Login(outsider.Email, "secret", domain.SessionMetadata{DeviceName: "outsider"})
	if err != nil {
		t.Fatalf("login outsider: %v", err)
	}
	network, err := application.NetworkService.CreateNetwork(owner.ID, "empty-patch-net", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	device, err := application.DeviceService.Enroll(owner.ID, "empty-patch-device", "empty-patch-pub", 100)
	if err != nil {
		t.Fatalf("enroll device: %v", err)
	}
	peer, err := application.PeerDirectory.RegisterPeer(owner.ID, device.ID, network.ID, "127.0.0.1:9600", 110)
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}

	outsiderResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/peers/"+peer.ID.String(), outsiderSession.AccessToken, map[string]any{})
	if outsiderResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider empty patch to return 401, got %d", outsiderResp.Code)
	}

	ownerResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/peers/"+peer.ID.String(), ownerSession.AccessToken, map[string]any{})
	if ownerResp.Code != http.StatusOK {
		t.Fatalf("expected owner empty patch to return 200, got %d", ownerResp.Code)
	}
}

func TestNetworkUsePermissionBoundaries(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
	}
	router := httpapi.NewRouter(application)

	owner, err := application.AuthService.Register("owner-use-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	member, err := application.AuthService.Register("member-use-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register member: %v", err)
	}
	readOnlyUser, err := application.AuthService.Register("readonly-use-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register read-only: %v", err)
	}
	outsider, err := application.AuthService.Register("outsider-use-http@example.com", "secret")
	if err != nil {
		t.Fatalf("register outsider: %v", err)
	}

	memberSession, err := application.AuthService.Login(member.Email, "secret", domain.SessionMetadata{DeviceName: "member"})
	if err != nil {
		t.Fatalf("login member: %v", err)
	}
	readOnlySession, err := application.AuthService.Login(readOnlyUser.Email, "secret", domain.SessionMetadata{DeviceName: "readonly"})
	if err != nil {
		t.Fatalf("login read-only: %v", err)
	}
	outsiderSession, err := application.AuthService.Login(outsider.Email, "secret", domain.SessionMetadata{DeviceName: "outsider"})
	if err != nil {
		t.Fatalf("login outsider: %v", err)
	}

	network, err := application.NetworkService.CreateNetwork(owner.ID, "use-http-boundary", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if err := application.NetworkService.AddMember(owner.ID, network.ID, member.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if err := application.NetworkService.AddMember(owner.ID, network.ID, readOnlyUser.ID); err != nil {
		t.Fatalf("add read-only: %v", err)
	}
	if err := application.NetworkService.ChangeMemberRole(owner.ID, network.ID, readOnlyUser.ID, domain.NetworkRoleReadOnly); err != nil {
		t.Fatalf("set read-only role: %v", err)
	}

	ownerDevice, err := application.DeviceService.Enroll(owner.ID, "owner-use-http-device", "owner-use-http-pub", 100)
	if err != nil {
		t.Fatalf("enroll owner device: %v", err)
	}
	memberDevice, err := application.DeviceService.Enroll(member.ID, "member-use-http-device", "member-use-http-pub", 101)
	if err != nil {
		t.Fatalf("enroll member device: %v", err)
	}
	readOnlyDevice, err := application.DeviceService.Enroll(readOnlyUser.ID, "readonly-use-http-device", "readonly-use-http-pub", 102)
	if err != nil {
		t.Fatalf("enroll read-only device: %v", err)
	}
	outsiderDevice, err := application.DeviceService.Enroll(outsider.ID, "outsider-use-http-device", "outsider-use-http-pub", 103)
	if err != nil {
		t.Fatalf("enroll outsider device: %v", err)
	}

	ownerPeer, err := application.PeerDirectory.RegisterPeer(owner.ID, ownerDevice.ID, network.ID, "127.0.0.1:9800", 110)
	if err != nil {
		t.Fatalf("register owner peer: %v", err)
	}

	memberPeerResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+network.ID.String()+"/peers", memberSession.AccessToken, map[string]string{
		"deviceId": memberDevice.ID.String(),
		"endpoint": "127.0.0.1:9801",
	})
	if memberPeerResp.Code != http.StatusCreated {
		t.Fatalf("expected member peer register to return 201, got %d", memberPeerResp.Code)
	}
	var memberPeerBody struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, memberPeerResp, &memberPeerBody)

	readOnlyPeerResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+network.ID.String()+"/peers", readOnlySession.AccessToken, map[string]string{
		"deviceId": readOnlyDevice.ID.String(),
		"endpoint": "127.0.0.1:9802",
	})
	if readOnlyPeerResp.Code != http.StatusForbidden {
		t.Fatalf("expected read-only peer register to return 403, got %d", readOnlyPeerResp.Code)
	}
	outsiderPeerResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+network.ID.String()+"/peers", outsiderSession.AccessToken, map[string]string{
		"deviceId": outsiderDevice.ID.String(),
		"endpoint": "127.0.0.1:9803",
	})
	if outsiderPeerResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider peer register to return 401, got %d", outsiderPeerResp.Code)
	}

	memberCandidateResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/peers/"+memberPeerBody.Data.ID+"/candidates", memberSession.AccessToken, map[string]any{
		"type":       "HOST",
		"protocol":   "UDP",
		"address":    "127.0.0.1:9801",
		"preference": 100,
	})
	if memberCandidateResp.Code != http.StatusCreated {
		t.Fatalf("expected member candidate publish to return 201, got %d", memberCandidateResp.Code)
	}

	if err := application.NetworkService.ChangeMemberRole(owner.ID, network.ID, member.ID, domain.NetworkRoleReadOnly); err != nil {
		t.Fatalf("demote member to read-only: %v", err)
	}
	readOnlyCandidateResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/peers/"+memberPeerBody.Data.ID+"/candidates", memberSession.AccessToken, map[string]any{
		"type":       "HOST",
		"protocol":   "UDP",
		"address":    "127.0.0.1:9801",
		"preference": 100,
	})
	if readOnlyCandidateResp.Code != http.StatusForbidden {
		t.Fatalf("expected read-only candidate publish to return 403, got %d", readOnlyCandidateResp.Code)
	}
	readOnlyCandidateListReq := httptest.NewRequest(http.MethodGet, "/api/v1/peers/"+memberPeerBody.Data.ID+"/candidates", nil)
	readOnlyCandidateListReq.Header.Set("Authorization", "Bearer "+memberSession.AccessToken)
	readOnlyCandidateListResp := httptest.NewRecorder()
	router.ServeHTTP(readOnlyCandidateListResp, readOnlyCandidateListReq)
	if readOnlyCandidateListResp.Code != http.StatusForbidden {
		t.Fatalf("expected read-only candidate list to return 403, got %d", readOnlyCandidateListResp.Code)
	}

	outsiderCandidateListReq := httptest.NewRequest(http.MethodGet, "/api/v1/peers/"+memberPeerBody.Data.ID+"/candidates", nil)
	outsiderCandidateListReq.Header.Set("Authorization", "Bearer "+outsiderSession.AccessToken)
	outsiderCandidateListResp := httptest.NewRecorder()
	router.ServeHTTP(outsiderCandidateListResp, outsiderCandidateListReq)
	if outsiderCandidateListResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider candidate list to return 401, got %d", outsiderCandidateListResp.Code)
	}

	if err := application.NetworkService.ChangeMemberRole(owner.ID, network.ID, member.ID, domain.NetworkRoleMember); err != nil {
		t.Fatalf("restore member role: %v", err)
	}
	memberTunnelResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+network.ID.String()+"/tunnels", memberSession.AccessToken, map[string]any{
		"peerAId": ownerPeer.ID.String(),
		"peerBId": memberPeerBody.Data.ID,
		"mode":    "P2P",
	})
	if memberTunnelResp.Code != http.StatusCreated {
		t.Fatalf("expected member tunnel create to return 201, got %d", memberTunnelResp.Code)
	}
	var memberTunnelBody struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, memberTunnelResp, &memberTunnelBody)

	readOnlyTunnelCreateResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+network.ID.String()+"/tunnels", readOnlySession.AccessToken, map[string]any{
		"peerAId": ownerPeer.ID.String(),
		"peerBId": memberPeerBody.Data.ID,
		"mode":    "P2P",
	})
	if readOnlyTunnelCreateResp.Code != http.StatusForbidden {
		t.Fatalf("expected read-only tunnel create to return 403, got %d", readOnlyTunnelCreateResp.Code)
	}

	if err := application.NetworkService.ChangeMemberRole(owner.ID, network.ID, member.ID, domain.NetworkRoleReadOnly); err != nil {
		t.Fatalf("demote member again to read-only: %v", err)
	}
	readOnlyTunnelPatchResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/tunnels/"+memberTunnelBody.Data.ID, memberSession.AccessToken, map[string]any{
		"state": "OPEN",
	})
	if readOnlyTunnelPatchResp.Code != http.StatusForbidden {
		t.Fatalf("expected read-only tunnel patch to return 403, got %d", readOnlyTunnelPatchResp.Code)
	}
}

func TestNetworkGroupTrafficPolicyFlow(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
	}
	router := httpapi.NewRouter(application)

	userResp := performJSON(t, router, http.MethodPost, "/api/v1/users", map[string]string{"email": "group-owner@example.com", "password": "secret"})
	if userResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", userResp.Code)
	}
	var user struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, userResp, &user)

	loginResp := performJSON(t, router, http.MethodPost, "/api/v1/sessions", map[string]string{"email": "group-owner@example.com", "password": "secret"})
	if loginResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", loginResp.Code)
	}
	var session struct {
		Data struct {
			AccessToken string `json:"accessToken"`
		} `json:"data"`
	}
	decodeBody(t, loginResp, &session)

	createNetworkResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks", session.Data.AccessToken, map[string]any{
		"ownerId":            user.Data.ID,
		"name":               "friends",
		"access":             "INVITE_ONLY",
		"groupTrafficPolicy": "FLOOD",
	})
	if createNetworkResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createNetworkResp.Code)
	}
	var createdNetwork struct {
		Data struct {
			ID                 string `json:"id"`
			GroupTrafficPolicy string `json:"groupTrafficPolicy"`
		} `json:"data"`
	}
	decodeBody(t, createNetworkResp, &createdNetwork)
	if createdNetwork.Data.GroupTrafficPolicy != "FLOOD" {
		t.Fatalf("expected network group traffic policy to round-trip on create, got %#v", createdNetwork.Data)
	}

	updateResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/networks/"+createdNetwork.Data.ID+"/group-traffic", session.Data.AccessToken, map[string]any{
		"policy": "BLOCKED",
	})
	if updateResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", updateResp.Code)
	}
	var updatedNetwork struct {
		Data struct {
			GroupTrafficPolicy string `json:"groupTrafficPolicy"`
		} `json:"data"`
	}
	decodeBody(t, updateResp, &updatedNetwork)
	if updatedNetwork.Data.GroupTrafficPolicy != "BLOCKED" {
		t.Fatalf("expected blocked group traffic policy after update, got %#v", updatedNetwork.Data)
	}
}

func TestHealthIncludesRelayStatusSnapshot(t *testing.T) {
	router := httpapi.NewRouterWithRelayStatusAndVersion(&app.App{}, stubRelayStatusProvider{
		snapshot: relay.StatusSnapshot{
			ListenAddress:           "127.0.0.1:3479",
			StartedAtUnix:           123,
			ActiveBindings:          2,
			TotalBindRequests:       3,
			SuccessfulBinds:         2,
			BindDenials:             1,
			TotalSendRequests:       4,
			ForwardedPackets:        5,
			ForwardedBytes:          321,
			SendDenials:             1,
			QuotaDenials:            2,
			QuotaWindowSeconds:      60,
			MaxPacketsPerPeerWindow: 100,
			MaxBytesPerPeerWindow:   2048,
			MalformedPackets:        4,
			AbuseDenials:            3,
			AbuseAlerts:             2,
			AbuseBlockedSources:     1,
			AbuseWindowSeconds:      120,
			AbuseThreshold:          3,
			AbuseBlockSeconds:       300,
		},
	}, versioninfo.ServerMetadata{
		APIVersion:       "v1",
		ServerVersion:    "0.1.0",
		MinClientVersion: "0.1.0",
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}

	var body struct {
		Status  string `json:"status"`
		Version struct {
			ServerVersion    string `json:"serverVersion"`
			MinClientVersion string `json:"minClientVersion"`
		} `json:"version"`
		Auth struct {
			ActiveAbuseAlerts int `json:"activeAbuseAlerts"`
		} `json:"auth"`
		Relay struct {
			ListenAddress           string `json:"listenAddress"`
			ForwardedPackets        int    `json:"forwardedPackets"`
			QuotaDenials            int    `json:"quotaDenials"`
			MaxPacketsPerPeerWindow int    `json:"maxPacketsPerPeerWindow"`
			MalformedPackets        int    `json:"malformedPackets"`
			AbuseDenials            int    `json:"abuseDenials"`
			AbuseAlerts             int    `json:"abuseAlerts"`
			AbuseBlockedSources     int    `json:"abuseBlockedSources"`
		} `json:"relay"`
	}
	decodeBody(t, resp, &body)
	if body.Status != "ok" {
		t.Fatalf("expected ok status, got %q", body.Status)
	}
	if body.Version.ServerVersion != "0.1.0" || body.Version.MinClientVersion != "0.1.0" {
		t.Fatalf("unexpected version payload: %+v", body.Version)
	}
	if body.Relay.ListenAddress != "127.0.0.1:3479" || body.Relay.ForwardedPackets != 5 || body.Relay.QuotaDenials != 2 || body.Relay.MaxPacketsPerPeerWindow != 100 {
		t.Fatalf("unexpected relay health payload: %+v", body.Relay)
	}
	if body.Relay.MalformedPackets != 4 || body.Relay.AbuseDenials != 3 || body.Relay.AbuseAlerts != 2 || body.Relay.AbuseBlockedSources != 1 {
		t.Fatalf("unexpected relay abuse health payload: %+v", body.Relay)
	}
	if body.Auth.ActiveAbuseAlerts != 0 {
		t.Fatalf("expected empty auth abuse health payload, got %+v", body.Auth)
	}
}

func TestLivenessEndpointReturnsAlive(t *testing.T) {
	router := httpapi.NewRouterWithRelayStatusAndVersion(&app.App{}, nil, versioninfo.ServerMetadata{
		APIVersion:       "v1",
		ServerVersion:    "0.1.0",
		MinClientVersion: "0.1.0",
	})

	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 from livez, got %d", resp.Code)
	}

	var body struct {
		Status string `json:"status"`
		Checks map[string]struct {
			Status string `json:"status"`
		} `json:"checks"`
	}
	decodeBody(t, resp, &body)
	if body.Status != "alive" || body.Checks["process"].Status != "ok" || body.Checks["http"].Status != "ok" {
		t.Fatalf("unexpected liveness payload: %+v", body)
	}
}

func TestReadinessEndpointReturnsReadyWhenDependenciesAreHealthy(t *testing.T) {
	router := httpapi.NewRouterWithRelayStatusAndVersion(&app.App{}, nil, versioninfo.ServerMetadata{
		APIVersion:       "v1",
		ServerVersion:    "0.1.0",
		MinClientVersion: "0.1.0",
	})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 from readyz, got %d", resp.Code)
	}

	var body struct {
		Status string `json:"status"`
		Checks map[string]struct {
			Status string `json:"status"`
		} `json:"checks"`
	}
	decodeBody(t, resp, &body)
	if body.Status != "ready" || body.Checks["database"].Status != "ok" {
		t.Fatalf("unexpected readiness payload: %+v", body)
	}
}

func TestReadinessEndpointReturnsServiceUnavailableWhenDependencyFails(t *testing.T) {
	router := httpapi.NewRouterWithRelayStatusAndVersion(&app.App{
		ReadinessCheck: func(context.Context) error {
			return errors.New("database unavailable")
		},
	}, nil, versioninfo.ServerMetadata{
		APIVersion:       "v1",
		ServerVersion:    "0.1.0",
		MinClientVersion: "0.1.0",
	})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 from readyz, got %d", resp.Code)
	}

	var body struct {
		Status string `json:"status"`
		Checks map[string]struct {
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	decodeBody(t, resp, &body)
	if body.Status != "not_ready" || body.Checks["database"].Status != "error" || body.Checks["database"].Detail != "database unavailable" {
		t.Fatalf("unexpected readiness failure payload: %+v", body)
	}
}

func TestMetricsExposeHTTPAndRelayObservability(t *testing.T) {
	router := httpapi.NewRouterWithRelayStatusAndVersion(&app.App{}, stubRelayStatusProvider{
		snapshot: relay.StatusSnapshot{
			ActiveBindings:      2,
			ForwardedPackets:    7,
			ForwardedBytes:      512,
			BindDenials:         1,
			SendDenials:         3,
			QuotaDenials:        4,
			AbuseAlerts:         5,
			AbuseBlockedSources: 1,
		},
	}, versioninfo.ServerMetadata{
		APIVersion:       "v1",
		ServerVersion:    "0.2.0",
		MinClientVersion: "0.2.0",
	})

	healthReq := httptest.NewRequest(http.MethodGet, "/health", nil)
	healthResp := httptest.NewRecorder()
	router.ServeHTTP(healthResp, healthReq)
	if healthResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from health, got %d", healthResp.Code)
	}

	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsResp := httptest.NewRecorder()
	router.ServeHTTP(metricsResp, metricsReq)
	if metricsResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from metrics, got %d", metricsResp.Code)
	}
	body := metricsResp.Body.String()
	assertContains(t, body, `ole_server_http_requests_total{method="GET",path="/health",status="200"} 1`)
	assertContains(t, body, `ole_server_db_ready 1`)
	assertContains(t, body, `ole_server_auth_rate_limit_tracked_keys 0`)
	assertContains(t, body, `ole_server_relay_active_bindings 2`)
	assertContains(t, body, `ole_server_relay_abuse_alerts_total 5`)
	assertContains(t, body, `ole_server_auth_abuse_active_alerts 0`)
}

func TestMetricsExposeControlPlaneSignalingAndTunnelState(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
		ReadinessCheck: func(context.Context) error {
			return nil
		},
	}
	nowUnix := time.Now().Unix()

	user, err := application.AuthService.Register("metrics-signal@example.com", "secret")
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	deviceA, err := application.DeviceService.Enroll(user.ID, "device-a", "pub-a", nowUnix)
	if err != nil {
		t.Fatalf("enroll device a: %v", err)
	}
	deviceB, err := application.DeviceService.Enroll(user.ID, "device-b", "pub-b", nowUnix+1)
	if err != nil {
		t.Fatalf("enroll device b: %v", err)
	}
	network, err := application.NetworkService.CreateNetwork(user.ID, "friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	peerA, err := application.PeerDirectory.RegisterPeer(user.ID, deviceA.ID, network.ID, "127.0.0.1:4000", nowUnix+2)
	if err != nil {
		t.Fatalf("register peer a: %v", err)
	}
	peerB, err := application.PeerDirectory.RegisterPeer(user.ID, deviceB.ID, network.ID, "127.0.0.1:4001", nowUnix+3)
	if err != nil {
		t.Fatalf("register peer b: %v", err)
	}
	if _, err := application.SignalingService.PublishCandidate(user.ID, peerA.ID, "HOST", "UDP", "127.0.0.1:4000", 100, true, 120, nowUnix+4); err != nil {
		t.Fatalf("publish candidate: %v", err)
	}
	if _, err := application.PeerDirectory.UpdateSignaling(user.ID, peerA.ID, "DIRECT", "DIRECT_CANDIDATE", nowUnix+5); err != nil {
		t.Fatalf("update signaling: %v", err)
	}
	if _, err := application.TunnelCoordinator.RequestTunnel(network.ID, peerA.ID, peerB.ID, "P2P", nowUnix+6); err != nil {
		t.Fatalf("request tunnel: %v", err)
	}

	router := httpapi.NewRouter(application)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 from metrics, got %d", resp.Code)
	}
	body := resp.Body.String()
	assertContains(t, body, `ole_server_networks_total 1`)
	assertContains(t, body, `ole_server_network_members_total 1`)
	assertContains(t, body, `ole_server_signaling_peers_total{connection_state="direct_candidate",reachability="direct",status="online"} 1`)
	assertContains(t, body, `ole_server_signal_candidates_total{protocol="udp",reachable="true",type="host"} 1`)
	assertContains(t, body, `ole_server_tunnels_total{mode="p2p",state="negotiating"} 1`)
}

func TestHealthIncludesAuthAbuseSnapshotAfterRepeatedLoginFailures(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
	}
	router := httpapi.NewRouter(application)

	createUserResp := performJSON(t, router, http.MethodPost, "/api/v1/users", map[string]string{
		"email":    "abuse@example.com",
		"password": "secret",
	})
	if createUserResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createUserResp.Code)
	}

	for i := 0; i < 4; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewReader([]byte(`{"email":"abuse@example.com","password":"wrong"}`)))
		req.RemoteAddr = "198.51.100.10:12345"
		req.Header.Set("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		if i < 3 && resp.Code != http.StatusUnauthorized {
			t.Fatalf("expected unauthorized on failed login %d, got %d", i, resp.Code)
		}
		if i == 3 && resp.Code != http.StatusTooManyRequests {
			t.Fatalf("expected rate limit on fourth login attempt, got %d", resp.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 from health, got %d", resp.Code)
	}

	var body struct {
		Auth struct {
			ActiveAbuseAlerts   int    `json:"activeAbuseAlerts"`
			LoginAlerts         int    `json:"loginAlerts"`
			WarningAlerts       int    `json:"warningAlerts"`
			BlockedKeys         int    `json:"blockedKeys"`
			TotalDeniedRequests int    `json:"totalDeniedRequests"`
			LastAlertType       string `json:"lastAlertType"`
			LastSeverity        string `json:"lastSeverity"`
		} `json:"auth"`
	}
	decodeBody(t, resp, &body)
	if body.Auth.ActiveAbuseAlerts != 1 || body.Auth.LoginAlerts != 1 || body.Auth.WarningAlerts != 1 {
		t.Fatalf("expected one warning login abuse alert, got %+v", body.Auth)
	}
	if body.Auth.BlockedKeys != 1 || body.Auth.TotalDeniedRequests != 1 {
		t.Fatalf("expected blocked and denied counts to be reflected in health, got %+v", body.Auth)
	}
	if body.Auth.LastAlertType != "login" || body.Auth.LastSeverity != "warning" {
		t.Fatalf("unexpected auth abuse alert metadata: %+v", body.Auth)
	}
}

func TestIncidentReportsExposeReadinessAuthAndRelayIncidents(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
		ReadinessCheck: func(context.Context) error {
			return errors.New("database unavailable")
		},
	}

	router := httpapi.NewRouterWithRelayStatus(application, fakeRelayStatusProvider{
		snapshot: relay.StatusSnapshot{
			AbuseAlerts:         2,
			AbuseBlockedSources: 1,
			AbuseDenials:        3,
			MalformedPackets:    4,
			Sources: []relay.SourceAbuseSnapshot{
				{
					SourceIP:           "203.0.113.10",
					LastDetectedAtUnix: 1710000000,
					BlockedUntilUnix:   1710003600,
				},
			},
		},
	})

	createUserResp := performJSON(t, router, http.MethodPost, "/api/v1/users", map[string]string{
		"email":    "incident-owner@example.com",
		"password": "secret",
	})
	if createUserResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createUserResp.Code)
	}

	loginResp := performJSON(t, router, http.MethodPost, "/api/v1/sessions", map[string]string{
		"email":    "incident-owner@example.com",
		"password": "secret",
	})
	if loginResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", loginResp.Code)
	}

	var session struct {
		Data struct {
			AccessToken string `json:"accessToken"`
		} `json:"data"`
	}
	decodeBody(t, loginResp, &session)

	for i := 0; i < 4; i++ {
		resp := performJSON(t, router, http.MethodPost, "/api/v1/sessions", map[string]string{
			"email":    "incident-owner@example.com",
			"password": "wrong-secret",
		})
		if i < 3 && resp.Code != http.StatusUnauthorized {
			t.Fatalf("expected unauthorized on failed login %d, got %d", i, resp.Code)
		}
		if i == 3 && resp.Code != http.StatusTooManyRequests {
			t.Fatalf("expected rate limit on fourth failed login, got %d", resp.Code)
		}
	}

	resp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/incidents", session.Data.AccessToken, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}

	var body struct {
		Data []struct {
			ID       string `json:"id"`
			Category string `json:"category"`
			Severity string `json:"severity"`
			Source   string `json:"source"`
		} `json:"data"`
	}
	decodeBody(t, resp, &body)
	if len(body.Data) != 3 {
		t.Fatalf("expected three incidents, got %#v", body.Data)
	}
	assertIncident := func(id, category, severity string) {
		t.Helper()
		for _, item := range body.Data {
			if item.ID == id && item.Category == category && item.Severity == severity {
				return
			}
		}
		t.Fatalf("expected incident %s/%s/%s in %#v", id, category, severity, body.Data)
	}
	assertIncident("server-readiness", "READINESS", "critical")
	assertIncident("relay-abuse", "RELAY_ABUSE", "critical")
	assertIncident("auth-abuse", "AUTH_ABUSE", "warning")
}

func TestIncidentReportsExposeSessionTokenReuseIncident(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
	}

	router := httpapi.NewRouter(application)

	createUserResp := performJSON(t, router, http.MethodPost, "/api/v1/users", map[string]string{
		"email":    "reuse-owner@example.com",
		"password": "secret",
	})
	if createUserResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createUserResp.Code)
	}

	loginResp := performJSON(t, router, http.MethodPost, "/api/v1/sessions", map[string]string{
		"email":    "reuse-owner@example.com",
		"password": "secret",
	})
	if loginResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 from login, got %d", loginResp.Code)
	}

	var loginBody struct {
		Data struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
			FamilyID     string `json:"familyId"`
		} `json:"data"`
	}
	decodeBody(t, loginResp, &loginBody)

	refreshResp := performJSON(t, router, http.MethodPost, "/api/v1/sessions/refresh", map[string]string{
		"refreshToken": loginBody.Data.RefreshToken,
		"deviceName":   "Ole Desktop",
	})
	if refreshResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from session refresh, got %d", refreshResp.Code)
	}

	reuseResp := performJSON(t, router, http.MethodPost, "/api/v1/sessions/refresh", map[string]string{
		"refreshToken": loginBody.Data.RefreshToken,
		"deviceName":   "Ole Desktop",
	})
	if reuseResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 from refresh-token reuse, got %d", reuseResp.Code)
	}

	secondLoginResp := performJSON(t, router, http.MethodPost, "/api/v1/sessions", map[string]string{
		"email":    "reuse-owner@example.com",
		"password": "secret",
	})
	if secondLoginResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 from second login, got %d", secondLoginResp.Code)
	}

	var secondLoginBody struct {
		Data struct {
			AccessToken string `json:"accessToken"`
		} `json:"data"`
	}
	decodeBody(t, secondLoginResp, &secondLoginBody)

	resp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/incidents", secondLoginBody.Data.AccessToken, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}

	var body struct {
		Data []struct {
			ID         string `json:"id"`
			Category   string `json:"category"`
			Severity   string `json:"severity"`
			EventCount int    `json:"eventCount"`
			Source     string `json:"source"`
		} `json:"data"`
	}
	decodeBody(t, resp, &body)
	if len(body.Data) != 1 {
		t.Fatalf("expected one incident, got %#v", body.Data)
	}
	if body.Data[0].ID != "session-token-reuse" || body.Data[0].Category != "TOKEN_REUSE" || body.Data[0].Severity != "elevated" {
		t.Fatalf("unexpected token reuse incident: %#v", body.Data[0])
	}
	if body.Data[0].EventCount != 1 || body.Data[0].Source != "account.audit" {
		t.Fatalf("unexpected token reuse incident metadata: %#v", body.Data[0])
	}
}

func TestRejectsTooOldClientVersionHeader(t *testing.T) {
	router := httpapi.NewRouterWithRelayStatusAndVersion(&app.App{}, nil, versioninfo.ServerMetadata{
		APIVersion:       "v1",
		ServerVersion:    "0.2.0",
		MinClientVersion: "0.2.0",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader([]byte(`{"email":"a@example.com","password":"secret"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(versioninfo.HeaderClientVersion, "0.1.0")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusUpgradeRequired {
		t.Fatalf("expected 426, got %d", resp.Code)
	}
	if got := resp.Header().Get(versioninfo.HeaderMinClientVersion); got != "0.2.0" {
		t.Fatalf("expected min client version header, got %q", got)
	}
}

func assertContains(t *testing.T, value, fragment string) {
	t.Helper()
	if !strings.Contains(value, fragment) {
		t.Fatalf("expected %q to contain %q", value, fragment)
	}
}

func TestAuditEventsSupportTimeRangeAndTextFilters(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: candidateRepo,
		SessionRepo:         sessionRepo,
	}
	router := httpapi.NewRouter(application)

	createUserResp := performJSON(t, router, http.MethodPost, "/api/v1/users", map[string]string{
		"email":    "owner@example.com",
		"password": "secret",
	})
	if createUserResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createUserResp.Code)
	}
	var createdUser struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, createUserResp, &createdUser)

	loginResp := performJSON(t, router, http.MethodPost, "/api/v1/sessions", map[string]string{
		"email":    "owner@example.com",
		"password": "secret",
	})
	if loginResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", loginResp.Code)
	}
	var createdSession struct {
		Data struct {
			AccessToken string `json:"accessToken"`
		} `json:"data"`
	}
	decodeBody(t, loginResp, &createdSession)

	_ = auditRepo.Append(&domain.AuditEvent{ID: "aud-1", ActorUserID: domain.UserID{Value: createdUser.Data.ID}, Type: "device.enrolled", Details: "dev-1", CreatedAtUnix: 100})
	_ = auditRepo.Append(&domain.AuditEvent{ID: "aud-2", ActorUserID: domain.UserID{Value: createdUser.Data.ID}, Type: "device.revoked", Details: "dev-2", CreatedAtUnix: 200})
	_ = auditRepo.Append(&domain.AuditEvent{ID: "aud-3", ActorUserID: domain.UserID{Value: "usr-2"}, Type: "network.created", Details: "net-1", CreatedAtUnix: 300})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit-events?actorUserId="+createdUser.Data.ID+"&type=device.revoked&q=dev-2&fromUnix=150&toUnix=250", nil)
	req.Header.Set("Authorization", "Bearer "+createdSession.Data.AccessToken)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}

	var body struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, resp, &body)
	if len(body.Data) != 1 || body.Data[0].ID != "aud-2" {
		t.Fatalf("expected only aud-2 after audit filtering, got %#v", body.Data)
	}
}

func TestMessagesAndFileTransfersRespectACLBoundaries(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	peerRepo := memory.NewPeerRepo()
	messageRepo := memory.NewMessageRepo()
	fileTransferRepo := memory.NewFileTransferRepo()
	fileTransferPayloadRepo := memory.NewFileTransferPayloadRepo()
	candidateRepo := memory.NewSignalCandidateRepo()
	tunnelRepo := memory.NewTunnelRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	sessionRepo := memory.NewSessionRepo()

	application := &app.App{
		AuthService:             domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test"),
		DeviceService:           domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:          domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:           domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo),
		MessagingService:        domain.NewMessagingService(messageRepo, peerRepo, networkRepo, auditRepo),
		FileTransferService:     domain.NewFileTransferService(fileTransferRepo, peerRepo, networkRepo, auditRepo, fileTransferPayloadRepo),
		SignalingService:        domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo),
		TunnelCoordinator:       domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:               auditRepo,
		UserRepo:                userRepo,
		DeviceRepo:              deviceRepo,
		NetworkRepo:             networkRepo,
		PeerRepo:                peerRepo,
		MessageRepo:             messageRepo,
		FileTransferRepo:        fileTransferRepo,
		FileTransferPayloadRepo: fileTransferPayloadRepo,
		TunnelRepo:              tunnelRepo,
		InviteRepo:              inviteRepo,
		SignalCandidateRepo:     candidateRepo,
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

	ownerID, ownerToken := registerAndLogin("owner-files-http@example.com")
	memberID, memberToken := registerAndLogin("member-files-http@example.com")
	fileAdminID, fileAdminToken := registerAndLogin("fileadmin-files-http@example.com")
	readOnlyID, readOnlyToken := registerAndLogin("readonly-files-http@example.com")
	_, outsiderToken := registerAndLogin("outsider-files-http@example.com")

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
	fileAdminDeviceID := createDevice(fileAdminToken, "fileadmin-device", "fileadmin-pub")

	createNetworkResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks", ownerToken, map[string]any{
		"ownerId": ownerID,
		"name":    "files-http",
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

	ownerPeerID := createPeer(ownerToken, ownerID, ownerDeviceID, "127.0.0.1:9810")
	memberPeerID := createPeer(memberToken, memberID, memberDeviceID, "127.0.0.1:9811")
	_ = createPeer(fileAdminToken, fileAdminID, fileAdminDeviceID, "127.0.0.1:9812")

	messageResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+networkID+"/messages", memberToken, map[string]string{
		"fromPeerId": memberPeerID,
		"text":       "hello from member",
	})
	if messageResp.Code != http.StatusCreated {
		t.Fatalf("expected member message create to return 201, got %d", messageResp.Code)
	}
	var messageBody struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, messageResp, &messageBody)

	readOnlyMessageResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+networkID+"/messages", readOnlyToken, map[string]string{
		"fromPeerId": memberPeerID,
		"text":       "blocked",
	})
	if readOnlyMessageResp.Code != http.StatusForbidden {
		t.Fatalf("expected read-only message create to return 403, got %d", readOnlyMessageResp.Code)
	}
	readOnlyMessageListResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/networks/"+networkID+"/messages", readOnlyToken, nil)
	if readOnlyMessageListResp.Code != http.StatusOK {
		t.Fatalf("expected read-only message list to return 200, got %d", readOnlyMessageListResp.Code)
	}
	outsiderMessageListResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/networks/"+networkID+"/messages", outsiderToken, nil)
	if outsiderMessageListResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider message list to return 401, got %d", outsiderMessageListResp.Code)
	}
	memberMessageGetResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/messages/"+messageBody.Data.ID, memberToken, nil)
	if memberMessageGetResp.Code != http.StatusOK {
		t.Fatalf("expected message get to return 200, got %d", memberMessageGetResp.Code)
	}

	transferPayload := []byte("ole-file")
	transferResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+networkID+"/file-transfers", memberToken, map[string]any{
		"fromPeerId": memberPeerID,
		"toPeerId":   ownerPeerID,
		"fileName":   "guide.txt",
		"sizeBytes":  len(transferPayload),
	})
	if transferResp.Code != http.StatusCreated {
		t.Fatalf("expected transfer create to return 201, got %d", transferResp.Code)
	}
	var transferBody struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, transferResp, &transferBody)

	readOnlyTransferResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+networkID+"/file-transfers", readOnlyToken, map[string]any{
		"fromPeerId": memberPeerID,
		"toPeerId":   ownerPeerID,
		"fileName":   "blocked.txt",
		"sizeBytes":  1,
	})
	if readOnlyTransferResp.Code != http.StatusForbidden {
		t.Fatalf("expected read-only transfer create to return 403, got %d", readOnlyTransferResp.Code)
	}

	uploadResp := performAuthenticatedJSON(t, router, http.MethodPut, "/api/v1/file-transfers/"+transferBody.Data.ID+"/content", memberToken, map[string]any{
		"contentType":   "text/plain",
		"payloadBase64": base64.StdEncoding.EncodeToString(transferPayload),
	})
	if uploadResp.Code != http.StatusOK {
		t.Fatalf("expected transfer payload upload to return 200, got %d", uploadResp.Code)
	}

	acceptResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/file-transfers/"+transferBody.Data.ID, ownerToken, map[string]string{
		"action": "ACCEPT",
	})
	if acceptResp.Code != http.StatusOK {
		t.Fatalf("expected owner accept to return 200, got %d", acceptResp.Code)
	}
	progressResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/file-transfers/"+transferBody.Data.ID, memberToken, map[string]any{
		"progressPercent": 45,
	})
	if progressResp.Code != http.StatusOK {
		t.Fatalf("expected sender progress update to return 200, got %d", progressResp.Code)
	}
	downloadResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/file-transfers/"+transferBody.Data.ID+"/content", ownerToken, nil)
	if downloadResp.Code != http.StatusOK {
		t.Fatalf("expected payload download to return 200, got %d", downloadResp.Code)
	}
	var downloadBody struct {
		Data struct {
			Transfer struct {
				Status           string `json:"status"`
				ProgressPercent  int    `json:"progressPercent"`
				DownloadedAtUnix int64  `json:"downloadedAtUnix"`
			} `json:"transfer"`
			PayloadBase64 string `json:"payloadBase64"`
		} `json:"data"`
	}
	decodeBody(t, downloadResp, &downloadBody)
	if decoded, err := base64.StdEncoding.DecodeString(downloadBody.Data.PayloadBase64); err != nil || !bytes.Equal(decoded, transferPayload) {
		t.Fatalf("expected downloaded payload to round-trip, got %q err=%v", downloadBody.Data.PayloadBase64, err)
	}
	if downloadBody.Data.Transfer.Status != "DONE" || downloadBody.Data.Transfer.ProgressPercent != 100 || downloadBody.Data.Transfer.DownloadedAtUnix == 0 {
		t.Fatalf("expected payload download to complete transfer, got %#v", downloadBody.Data.Transfer)
	}

	chunkTransferResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+networkID+"/file-transfers", memberToken, map[string]any{
		"fromPeerId": memberPeerID,
		"toPeerId":   ownerPeerID,
		"fileName":   "chunked.txt",
		"sizeBytes":  len(transferPayload),
	})
	if chunkTransferResp.Code != http.StatusCreated {
		t.Fatalf("expected chunk transfer create to return 201, got %d", chunkTransferResp.Code)
	}
	var chunkTransferBody struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, chunkTransferResp, &chunkTransferBody)

	chunkUploadResp := performAuthenticatedJSON(t, router, http.MethodPut, "/api/v1/file-transfers/"+chunkTransferBody.Data.ID+"/content-chunks", memberToken, map[string]any{
		"contentType":   "text/plain",
		"payloadBase64": base64.StdEncoding.EncodeToString(transferPayload[:4]),
		"offsetBytes":   0,
	})
	if chunkUploadResp.Code != http.StatusOK {
		t.Fatalf("expected first chunk upload to return 200, got %d", chunkUploadResp.Code)
	}
	var firstChunkUploadBody struct {
		Data struct {
			PayloadReady         bool  `json:"payloadReady"`
			PayloadUploadedBytes int64 `json:"payloadUploadedBytes"`
		} `json:"data"`
	}
	decodeBody(t, chunkUploadResp, &firstChunkUploadBody)
	if firstChunkUploadBody.Data.PayloadReady || firstChunkUploadBody.Data.PayloadUploadedBytes != 4 {
		t.Fatalf("expected partial chunk upload metadata, got %#v", firstChunkUploadBody.Data)
	}

	chunkResumeResp := performAuthenticatedJSON(t, router, http.MethodPut, "/api/v1/file-transfers/"+chunkTransferBody.Data.ID+"/content-chunks", memberToken, map[string]any{
		"contentType":   "text/plain",
		"payloadBase64": base64.StdEncoding.EncodeToString(transferPayload[4:]),
		"offsetBytes":   4,
	})
	if chunkResumeResp.Code != http.StatusOK {
		t.Fatalf("expected resumed chunk upload to return 200, got %d", chunkResumeResp.Code)
	}
	acceptChunkResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/file-transfers/"+chunkTransferBody.Data.ID, ownerToken, map[string]string{
		"action": "ACCEPT",
	})
	if acceptChunkResp.Code != http.StatusOK {
		t.Fatalf("expected chunk transfer accept to return 200, got %d", acceptChunkResp.Code)
	}
	chunkDownloadResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/file-transfers/"+chunkTransferBody.Data.ID+"/content-chunks?offsetBytes=0&limitBytes=4", ownerToken, nil)
	if chunkDownloadResp.Code != http.StatusOK {
		t.Fatalf("expected first chunk download to return 200, got %d", chunkDownloadResp.Code)
	}
	var firstChunkDownloadBody struct {
		Data struct {
			PayloadBase64    string `json:"payloadBase64"`
			NextOffsetBytes  int64  `json:"nextOffsetBytes"`
			TotalSizeBytes   int64  `json:"totalSizeBytes"`
			Complete         bool   `json:"complete"`
			DownloadedAtUnix int64  `json:"downloadedAtUnix"`
		} `json:"data"`
	}
	decodeBody(t, chunkDownloadResp, &firstChunkDownloadBody)
	if decoded, err := base64.StdEncoding.DecodeString(firstChunkDownloadBody.Data.PayloadBase64); err != nil || !bytes.Equal(decoded, transferPayload[:4]) {
		t.Fatalf("expected first downloaded chunk to round-trip, got %q err=%v", firstChunkDownloadBody.Data.PayloadBase64, err)
	}
	if firstChunkDownloadBody.Data.Complete || firstChunkDownloadBody.Data.NextOffsetBytes != 4 || firstChunkDownloadBody.Data.TotalSizeBytes != int64(len(transferPayload)) || firstChunkDownloadBody.Data.DownloadedAtUnix != 0 {
		t.Fatalf("unexpected first chunk download metadata: %#v", firstChunkDownloadBody.Data)
	}
	chunkDownloadCompleteResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/file-transfers/"+chunkTransferBody.Data.ID+"/content-chunks?offsetBytes=4&limitBytes=16", ownerToken, nil)
	if chunkDownloadCompleteResp.Code != http.StatusOK {
		t.Fatalf("expected final chunk download to return 200, got %d", chunkDownloadCompleteResp.Code)
	}
	var finalChunkDownloadBody struct {
		Data struct {
			Transfer struct {
				Status           string `json:"status"`
				DownloadedAtUnix int64  `json:"downloadedAtUnix"`
			} `json:"transfer"`
			PayloadBase64 string `json:"payloadBase64"`
			Complete      bool   `json:"complete"`
		} `json:"data"`
	}
	decodeBody(t, chunkDownloadCompleteResp, &finalChunkDownloadBody)
	if decoded, err := base64.StdEncoding.DecodeString(finalChunkDownloadBody.Data.PayloadBase64); err != nil || !bytes.Equal(decoded, transferPayload[4:]) {
		t.Fatalf("expected final downloaded chunk to round-trip, got %q err=%v", finalChunkDownloadBody.Data.PayloadBase64, err)
	}
	if !finalChunkDownloadBody.Data.Complete || finalChunkDownloadBody.Data.Transfer.Status != "DONE" || finalChunkDownloadBody.Data.Transfer.DownloadedAtUnix == 0 {
		t.Fatalf("expected final chunk download to complete transfer, got %#v", finalChunkDownloadBody.Data)
	}

	mirrorTransferResp := performAuthenticatedJSON(t, router, http.MethodPost, "/api/v1/networks/"+networkID+"/file-transfers", ownerToken, map[string]any{
		"fromPeerId": ownerPeerID,
		"toPeerId":   memberPeerID,
		"fileName":   "mirror.txt",
		"sizeBytes":  len(transferPayload),
	})
	if mirrorTransferResp.Code != http.StatusCreated {
		t.Fatalf("expected mirror transfer create to return 201, got %d", mirrorTransferResp.Code)
	}
	var mirrorTransferBody struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, mirrorTransferResp, &mirrorTransferBody)

	mirrorBeforeAcceptResp := performAuthenticatedJSON(t, router, http.MethodPut, "/api/v1/file-transfers/"+mirrorTransferBody.Data.ID+"/content-chunks", memberToken, map[string]any{
		"contentType":   "text/plain",
		"payloadBase64": base64.StdEncoding.EncodeToString(transferPayload),
		"offsetBytes":   0,
	})
	if mirrorBeforeAcceptResp.Code != http.StatusForbidden {
		t.Fatalf("expected receiver mirror upload before accept to return 403, got %d", mirrorBeforeAcceptResp.Code)
	}
	acceptMirrorResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/file-transfers/"+mirrorTransferBody.Data.ID, memberToken, map[string]string{
		"action": "ACCEPT",
	})
	if acceptMirrorResp.Code != http.StatusOK {
		t.Fatalf("expected mirror transfer accept to return 200, got %d", acceptMirrorResp.Code)
	}
	mirrorUploadResp := performAuthenticatedJSON(t, router, http.MethodPut, "/api/v1/file-transfers/"+mirrorTransferBody.Data.ID+"/content-chunks", memberToken, map[string]any{
		"contentType":   "text/plain",
		"payloadBase64": base64.StdEncoding.EncodeToString(transferPayload),
		"offsetBytes":   0,
	})
	if mirrorUploadResp.Code != http.StatusOK {
		t.Fatalf("expected receiver mirror upload after accept to return 200, got %d", mirrorUploadResp.Code)
	}
	var mirrorUploadBody struct {
		Data struct {
			PayloadReady         bool   `json:"payloadReady"`
			PayloadUploadedBytes int64  `json:"payloadUploadedBytes"`
			ContentType          string `json:"contentType"`
		} `json:"data"`
	}
	decodeBody(t, mirrorUploadResp, &mirrorUploadBody)
	if !mirrorUploadBody.Data.PayloadReady || mirrorUploadBody.Data.PayloadUploadedBytes != int64(len(transferPayload)) || mirrorUploadBody.Data.ContentType != "text/plain" {
		t.Fatalf("expected receiver mirror upload to populate payload, got %#v", mirrorUploadBody.Data)
	}

	cancelResp := performAuthenticatedJSON(t, router, http.MethodPatch, "/api/v1/file-transfers/"+transferBody.Data.ID, fileAdminToken, map[string]string{
		"action": "CANCEL",
		"reason": "quota exceeded",
	})
	if cancelResp.Code != http.StatusOK {
		t.Fatalf("expected file admin cancel to return 200, got %d", cancelResp.Code)
	}
	outsiderTransferListResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/networks/"+networkID+"/file-transfers", outsiderToken, nil)
	if outsiderTransferListResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected outsider transfer list to return 401, got %d", outsiderTransferListResp.Code)
	}
	fileAdminTransferGetResp := performAuthenticatedJSON(t, router, http.MethodGet, "/api/v1/file-transfers/"+transferBody.Data.ID, fileAdminToken, nil)
	if fileAdminTransferGetResp.Code != http.StatusOK {
		t.Fatalf("expected file transfer get to return 200, got %d", fileAdminTransferGetResp.Code)
	}
}

func performJSON(t *testing.T, handler http.Handler, method, path string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	return resp
}

func performAuthenticatedJSON(t *testing.T, handler http.Handler, method, path, accessToken string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	return resp
}

func decodeBody(t *testing.T, resp *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(resp.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

type stubRelayStatusProvider struct {
	snapshot relay.StatusSnapshot
}

func (s stubRelayStatusProvider) Snapshot() relay.StatusSnapshot {
	return s.snapshot
}
