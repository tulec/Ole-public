package httpapi

import (
	"Ole/internal/domain"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (api *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	response := healthResponse{Status: "ok", Time: time.Now().Unix()}
	response.Version = &versionStatusResponse{
		APIVersion:       api.versionInfo.APIVersion,
		ServerVersion:    api.versionInfo.ServerVersion,
		MinClientVersion: api.versionInfo.MinClientVersion,
	}
	if api.relayStatus != nil {
		snapshot := api.relayStatus.Snapshot()
		response.Relay = &relayStatusResponse{
			ListenAddress:           snapshot.ListenAddress,
			StartedAtUnix:           snapshot.StartedAtUnix,
			ActiveBindings:          snapshot.ActiveBindings,
			TotalBindRequests:       snapshot.TotalBindRequests,
			SuccessfulBinds:         snapshot.SuccessfulBinds,
			BindDenials:             snapshot.BindDenials,
			TotalSendRequests:       snapshot.TotalSendRequests,
			ForwardedPackets:        snapshot.ForwardedPackets,
			ForwardedBytes:          snapshot.ForwardedBytes,
			SendDenials:             snapshot.SendDenials,
			QuotaDenials:            snapshot.QuotaDenials,
			QuotaWindowSeconds:      snapshot.QuotaWindowSeconds,
			MaxPacketsPerPeerWindow: snapshot.MaxPacketsPerPeerWindow,
			MaxBytesPerPeerWindow:   snapshot.MaxBytesPerPeerWindow,
			MalformedPackets:        snapshot.MalformedPackets,
			AbuseDenials:            snapshot.AbuseDenials,
			AbuseAlerts:             snapshot.AbuseAlerts,
			AbuseBlockedSources:     snapshot.AbuseBlockedSources,
			AbuseWindowSeconds:      snapshot.AbuseWindowSeconds,
			AbuseThreshold:          snapshot.AbuseThreshold,
			AbuseBlockSeconds:       snapshot.AbuseBlockSeconds,
		}
	}
	if api.authAbuse != nil {
		snapshot, err := api.authAbuse.Snapshot(r.Context(), time.Now())
		if err == nil {
			response.Auth = &authStatusResponse{
				ActiveAbuseAlerts:   snapshot.ActiveAlerts,
				LoginAlerts:         snapshot.LoginAlerts,
				RefreshAlerts:       snapshot.RefreshAlerts,
				WarningAlerts:       snapshot.WarningAlerts,
				ElevatedAlerts:      snapshot.ElevatedAlerts,
				CriticalAlerts:      snapshot.CriticalAlerts,
				BlockedKeys:         snapshot.BlockedKeys,
				TotalAlertEvents:    snapshot.TotalAlertEvents,
				TotalDeniedRequests: snapshot.TotalDeniedRequests,
				LastAlertType:       snapshot.LastAlertType,
				LastSeverity:        snapshot.LastSeverity,
				LastAlertedAtUnix:   snapshot.LastAlertedAtUnix,
			}
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (api *API) handleLiveness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, probeResponse{
		Status:  "alive",
		Time:    time.Now().Unix(),
		Version: api.versionStatus(),
		Checks: map[string]probeCheckItem{
			"process": {Status: "ok"},
			"http":    {Status: "ok"},
		},
	})
}

func (api *API) handleReadiness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	response := probeResponse{
		Status:  "ready",
		Time:    time.Now().Unix(),
		Version: api.versionStatus(),
		Checks: map[string]probeCheckItem{
			"http": {Status: "ok"},
		},
	}
	statusCode := http.StatusOK
	if api != nil && api.app != nil {
		snapshot := api.app.ReadinessSnapshot(r.Context())
		check := probeCheckItem{Status: "ok"}
		if snapshot.Error != "" {
			check.Detail = snapshot.Error
		}
		if !snapshot.Ready {
			check.Status = "error"
			response.Status = "not_ready"
			statusCode = http.StatusServiceUnavailable
		}
		response.Checks["database"] = check
	}
	writeJSON(w, statusCode, response)
}

func (api *API) versionStatus() *versionStatusResponse {
	if api == nil {
		return nil
	}
	return &versionStatusResponse{
		APIVersion:       api.versionInfo.APIVersion,
		ServerVersion:    api.versionInfo.ServerVersion,
		MinClientVersion: api.versionInfo.MinClientVersion,
	}
}

func (api *API) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, rootResponse{
		Name:    "Ole API",
		Version: "v1",
		Server: &versionStatusResponse{
			APIVersion:       api.versionInfo.APIVersion,
			ServerVersion:    api.versionInfo.ServerVersion,
			MinClientVersion: api.versionInfo.MinClientVersion,
		},
		Resources: []string{
			"/livez",
			"/readyz",
			"/metrics",
			"/openapi.yaml",
			"/swagger",
			"/api/v1/users",
			"/api/v1/devices",
			"/api/v1/sessions",
			"/api/v1/networks",
			"/api/v1/invites",
			"/api/v1/messages",
			"/api/v1/peers",
			"/api/v1/file-transfers",
			"/api/v1/tunnels",
			"/api/v1/audit-events",
			"/api/v1/incidents",
		},
	})
}

func (api *API) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	http.ServeFile(w, r, "docs/openapi.yaml")
}

func (api *API) handleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	http.Redirect(w, r, "/swagger/", http.StatusTemporaryRedirect)
}

func (api *API) createUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	user, err := api.app.AuthService.Register(req.Email, req.Password)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, envelope[userResponse]{Data: toUserResponse(user)})
}

func (api *API) listDevices(w http.ResponseWriter, r *http.Request) {
	limit, offset := paginationFromRequest(r)
	devices, _, err := api.app.DeviceService.List(currentUserID(r), 1000, 0)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	devices = filterDevices(devices, r)
	devicesPage, total := paginateSlice(devices, limit, offset)
	writeJSON(w, http.StatusOK, listEnvelope[deviceResponse]{
		Data: toDeviceResponses(devicesPage),
		Meta: responseMeta{Count: len(devicesPage), Total: total, Limit: limit, Offset: offset},
	})
}

func (api *API) createDevice(w http.ResponseWriter, r *http.Request) {
	var req createDeviceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	userID := currentUserID(r)
	if req.UserID != "" && req.UserID != userID.String() {
		writeDomainError(w, domain.ErrUnauthorized)
		return
	}
	device, err := api.app.DeviceService.Enroll(userID, req.Name, req.PublicKey, time.Now().Unix())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, envelope[deviceResponse]{Data: toDeviceResponse(device)})
}

func (api *API) getDevice(w http.ResponseWriter, r *http.Request, deviceID string) {
	device, err := api.app.DeviceService.Get(currentUserID(r), domain.DeviceID{Value: deviceID})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[deviceResponse]{Data: toDeviceResponse(device)})
}

func (api *API) patchDevice(w http.ResponseWriter, r *http.Request, deviceID string) {
	var req patchDeviceRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	current := currentUserID(r)
	if req.Name != nil {
		if _, err := api.app.DeviceService.Rename(current, domain.DeviceID{Value: deviceID}, *req.Name); err != nil {
			writeDomainError(w, err)
			return
		}
	}
	if req.Status != nil {
		if _, err := api.app.DeviceService.SetStatus(current, domain.DeviceID{Value: deviceID}, domain.DeviceStatus(strings.ToUpper(strings.TrimSpace(*req.Status)))); err != nil {
			writeDomainError(w, err)
			return
		}
	}

	device, err := api.app.DeviceService.Get(current, domain.DeviceID{Value: deviceID})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[deviceResponse]{Data: toDeviceResponse(device)})
}

func (api *API) deleteDevice(w http.ResponseWriter, r *http.Request, deviceID string) {
	if err := api.app.DeviceService.Revoke(currentUserID(r), domain.DeviceID{Value: deviceID}, time.Now().Unix()); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (api *API) getUser(w http.ResponseWriter, _ *http.Request, userID string) {
	user, err := api.app.UserRepo.FindByID(domain.UserID{Value: userID})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if user == nil {
		writeDomainError(w, domain.ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, envelope[userResponse]{Data: toUserResponse(user)})
}

func (api *API) updateUserPassword(w http.ResponseWriter, r *http.Request, userID string) {
	if currentUserID(r).String() != userID {
		writeDomainError(w, domain.ErrUnauthorized)
		return
	}
	var req updateUserPasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := api.app.AuthService.ChangePassword(domain.UserID{Value: userID}, req.OldPassword, req.NewPassword); err != nil {
		writeDomainError(w, err)
		return
	}
	user, _ := api.app.UserRepo.FindByID(domain.UserID{Value: userID})
	writeJSON(w, http.StatusOK, envelope[userResponse]{Data: toUserResponse(user)})
}

func (api *API) createSession(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	authKey := api.clientIP(r) + ":login"
	attempt, allowed, err := api.authLimiter.Allow(r.Context(), authKey, now)
	if err != nil {
		api.traceError(r, "auth.login.rate_limit_check_failed", "login rate limit check failed", "authKey", authKey, "error", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "rate limit check failed"})
		return
	}
	if !allowed {
		api.authAbuse.ObserveDenied(r.Context(), authKey, attempt, now)
		api.traceError(r, "auth.login.rate_limited", "login rate limited", "authKey", authKey, "attempt", attempt)
		writeJSON(w, http.StatusTooManyRequests, errorResponse{Error: "too many login attempts, try later"})
		return
	}
	var req createSessionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	session, err := api.app.AuthService.Login(req.Email, req.Password, api.sessionMetadataFromRequest(r, req.DeviceName))
	if err != nil {
		if errors.Is(err, domain.ErrPasswordStorage) {
			writeDomainError(w, err)
			return
		}
		attempt, limiterErr := api.authLimiter.RegisterFailure(r.Context(), authKey, now)
		if limiterErr != nil {
			api.traceError(r, "auth.login.rate_limit_update_failed", "login rate limit update failed", "authKey", authKey, "email", req.Email, "error", limiterErr)
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "rate limit update failed"})
			return
		}
		api.authAbuse.ObserveFailure(r.Context(), authKey, attempt, now)
		api.traceError(r, "auth.login.failed", "login failed", "authKey", authKey, "email", req.Email, "attempt", attempt, "error", err)
		writeDomainError(w, err)
		return
	}
	if err := api.authLimiter.RegisterSuccess(r.Context(), authKey, now); err != nil {
		api.traceError(r, "auth.login.rate_limit_update_failed", "login rate limit update failed", "authKey", authKey, "email", req.Email, "error", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "rate limit update failed"})
		return
	}
	api.authAbuse.Resolve(r.Context(), authKey, now)
	api.traceInfo(r, "auth.login.succeeded", "login succeeded", "authKey", authKey, "email", req.Email, "userId", session.UserID.String(), "sessionId", session.ID)
	writeJSON(w, http.StatusCreated, envelope[sessionResponse]{Data: toSessionResponse(session)})
}

func (api *API) refreshSession(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	authKey := api.clientIP(r) + ":refresh"
	attempt, allowed, err := api.authLimiter.Allow(r.Context(), authKey, now)
	if err != nil {
		api.traceError(r, "auth.refresh.rate_limit_check_failed", "refresh rate limit check failed", "authKey", authKey, "error", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "rate limit check failed"})
		return
	}
	if !allowed {
		api.authAbuse.ObserveDenied(r.Context(), authKey, attempt, now)
		api.traceError(r, "auth.refresh.rate_limited", "refresh rate limited", "authKey", authKey, "attempt", attempt)
		writeJSON(w, http.StatusTooManyRequests, errorResponse{Error: "too many refresh attempts, try later"})
		return
	}
	var req refreshSessionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	session, err := api.app.AuthService.Refresh(req.RefreshToken, api.sessionMetadataFromRequest(r, req.DeviceName))
	if err != nil {
		attempt, limiterErr := api.authLimiter.RegisterFailure(r.Context(), authKey, now)
		if limiterErr != nil {
			api.traceError(r, "auth.refresh.rate_limit_update_failed", "refresh rate limit update failed", "authKey", authKey, "error", limiterErr)
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "rate limit update failed"})
			return
		}
		api.authAbuse.ObserveFailure(r.Context(), authKey, attempt, now)
		api.traceError(r, "auth.refresh.failed", "refresh failed", "authKey", authKey, "attempt", attempt, "error", err)
		writeDomainError(w, err)
		return
	}
	if err := api.authLimiter.RegisterSuccess(r.Context(), authKey, now); err != nil {
		api.traceError(r, "auth.refresh.rate_limit_update_failed", "refresh rate limit update failed", "authKey", authKey, "sessionId", session.ID, "error", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "rate limit update failed"})
		return
	}
	api.authAbuse.Resolve(r.Context(), authKey, now)
	api.traceInfo(r, "auth.refresh.succeeded", "refresh succeeded", "authKey", authKey, "sessionId", session.ID, "userId", session.UserID.String())
	writeJSON(w, http.StatusOK, envelope[sessionResponse]{Data: toSessionResponse(session)})
}

func (api *API) listSessions(w http.ResponseWriter, r *http.Request) {
	limit, offset := paginationFromRequest(r)
	sessions, total, err := api.app.AuthService.ListSessions(currentUserID(r), limit, offset)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, listEnvelope[sessionResponse]{
		Data: toSessionResponses(sessions),
		Meta: responseMeta{Count: len(sessions), Total: total, Limit: limit, Offset: offset},
	})
}

func (api *API) deleteSession(w http.ResponseWriter, r *http.Request) {
	accessToken := strings.TrimSpace(r.URL.Query().Get("accessToken"))
	if accessToken == "" {
		accessToken = strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}
	if err := api.app.AuthService.Logout(accessToken); err != nil {
		if errors.Is(err, domain.ErrUnauthorized) {
			writeDomainError(w, err)
		} else {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to revoke session"})
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (api *API) deleteAllSessions(w http.ResponseWriter, r *http.Request) {
	if err := api.app.AuthService.RevokeAllSessions(currentUserID(r)); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (api *API) deleteSessionByID(w http.ResponseWriter, r *http.Request, sessionID string) {
	if err := api.app.AuthService.RevokeSession(currentUserID(r), sessionID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeDomainError(w, err)
		} else {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to revoke session"})
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func paginationFromRequest(r *http.Request) (int, int) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (api *API) listNetworks(w http.ResponseWriter, r *http.Request) {
	networks, err := api.app.NetworkService.ListVisibleNetworks(currentUserID(r))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	networks = filterNetworks(networks, r)
	limit, offset := paginationFromRequest(r)
	networksPage, total := paginateSlice(networks, limit, offset)
	writeJSON(w, http.StatusOK, listEnvelope[networkResponse]{
		Data: toNetworkResponses(networksPage),
		Meta: responseMeta{Count: len(networksPage), Total: total, Limit: limit, Offset: offset},
	})
}

func (api *API) createNetwork(w http.ResponseWriter, r *http.Request) {
	var req createNetworkRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ownerID := currentUserID(r)
	if req.OwnerID != "" && req.OwnerID != ownerID.String() {
		writeDomainError(w, domain.ErrUnauthorized)
		return
	}
	network, err := api.app.NetworkService.CreateNetworkWithOptions(ownerID, req.Name, req.Access, domain.NetworkCreateOptions{
		DeviceApprovalRequired:  req.DeviceApprovalRequired,
		RoutingPolicy:           domain.NetworkRoutingPolicy(req.RoutingPolicy),
		GroupTrafficPolicy:      domain.NetworkGroupTrafficPolicy(req.GroupTrafficPolicy),
		NameResolutionMode:      domain.NetworkNameResolutionMode(req.NameResolutionMode),
		DNSLabel:                req.DNSLabel,
		FileTransfersEnabledSet: req.FileTransfersEnabled != nil,
		FileTransfersEnabled:    req.FileTransfersEnabled == nil || *req.FileTransfersEnabled,
		FileTransferMaxBytes:    req.FileTransferMaxBytes,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, envelope[networkResponse]{Data: toNetworkResponse(network)})
}

func (api *API) updateNetworkRoutingPolicy(w http.ResponseWriter, r *http.Request, networkID string) {
	var req updateNetworkRoutingPolicyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	network, err := api.app.NetworkService.UpdateRoutingPolicy(
		currentUserID(r),
		domain.NetworkID{Value: networkID},
		domain.NetworkRoutingPolicy(req.Policy),
	)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[networkResponse]{Data: toNetworkResponse(network)})
}

func (api *API) updateNetworkNameResolution(w http.ResponseWriter, r *http.Request, networkID string) {
	var req updateNetworkNameResolutionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	network, err := api.app.NetworkService.UpdateNameResolutionPolicy(
		currentUserID(r),
		domain.NetworkID{Value: networkID},
		domain.NetworkNameResolutionMode(req.Mode),
		req.DNSLabel,
	)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[networkResponse]{Data: toNetworkResponse(network)})
}

func (api *API) updateNetworkGroupTrafficPolicy(w http.ResponseWriter, r *http.Request, networkID string) {
	var req updateNetworkGroupTrafficPolicyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	network, err := api.app.NetworkService.UpdateGroupTrafficPolicy(
		currentUserID(r),
		domain.NetworkID{Value: networkID},
		domain.NetworkGroupTrafficPolicy(req.Policy),
	)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[networkResponse]{Data: toNetworkResponse(network)})
}

func (api *API) updateNetworkFileTransferPolicy(w http.ResponseWriter, r *http.Request, networkID string) {
	var req updateNetworkFileTransferPolicyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	network, err := api.app.NetworkService.UpdateFileTransferPolicy(
		currentUserID(r),
		domain.NetworkID{Value: networkID},
		req.Enabled,
		req.MaxBytes,
	)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[networkResponse]{Data: toNetworkResponse(network)})
}

func (api *API) approveNetworkDevice(w http.ResponseWriter, r *http.Request, networkID, deviceID string) {
	network, err := api.app.NetworkService.ApproveDevice(currentUserID(r), domain.NetworkID{Value: networkID}, domain.DeviceID{Value: deviceID}, time.Now().Unix())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[networkResponse]{Data: toNetworkResponse(network)})
}

func (api *API) revokeNetworkDeviceApproval(w http.ResponseWriter, r *http.Request, networkID, deviceID string) {
	network, err := api.app.NetworkService.RevokeDeviceApproval(currentUserID(r), domain.NetworkID{Value: networkID}, domain.DeviceID{Value: deviceID}, time.Now().Unix())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[networkResponse]{Data: toNetworkResponse(network)})
}

func (api *API) getNetwork(w http.ResponseWriter, r *http.Request, networkID string) {
	network, err := api.app.NetworkService.GetNetwork(currentUserID(r), domain.NetworkID{Value: networkID})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[networkResponse]{Data: toNetworkResponse(network)})
}

func (api *API) deleteNetwork(w http.ResponseWriter, r *http.Request, networkID string) {
	requestorID := strings.TrimSpace(r.URL.Query().Get("requestorId"))
	current := currentUserID(r)
	if requestorID != "" && requestorID != current.String() {
		writeDomainError(w, domain.ErrUnauthorized)
		return
	}
	if err := api.app.NetworkService.DeleteNetwork(current, domain.NetworkID{Value: networkID}); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (api *API) addNetworkMember(w http.ResponseWriter, r *http.Request, networkID string) {
	var req addNetworkMemberRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ownerID := currentUserID(r)
	if req.OwnerID != "" && req.OwnerID != ownerID.String() {
		writeDomainError(w, domain.ErrUnauthorized)
		return
	}
	if err := api.app.NetworkService.AddMember(ownerID, domain.NetworkID{Value: networkID}, domain.UserID{Value: req.MemberID}); err != nil {
		writeDomainError(w, err)
		return
	}
	if req.Role != "" && strings.ToUpper(req.Role) != string(domain.NetworkRoleMember) {
		role := domain.NetworkRole(strings.ToUpper(strings.TrimSpace(req.Role)))
		if !isAllowedNetworkRole(role) {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "unsupported network role"})
			return
		}
		if err := api.app.NetworkService.ChangeMemberRole(ownerID, domain.NetworkID{Value: networkID}, domain.UserID{Value: req.MemberID}, role); err != nil {
			writeDomainError(w, err)
			return
		}
	}
	network, _ := api.app.NetworkRepo.FindByID(domain.NetworkID{Value: networkID})
	writeJSON(w, http.StatusCreated, envelope[networkResponse]{Data: toNetworkResponse(network)})
}

func (api *API) updateNetworkMemberRole(w http.ResponseWriter, r *http.Request, networkID, memberID string) {
	var req updateNetworkMemberRoleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	role := domain.NetworkRole(strings.ToUpper(strings.TrimSpace(req.Role)))
	if !isAllowedNetworkRole(role) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "unsupported network role"})
		return
	}

	requestorID := currentUserID(r)
	if err := api.app.NetworkService.ChangeMemberRole(requestorID, domain.NetworkID{Value: networkID}, domain.UserID{Value: memberID}, role); err != nil {
		writeDomainError(w, err)
		return
	}
	network, _ := api.app.NetworkRepo.FindByID(domain.NetworkID{Value: networkID})
	writeJSON(w, http.StatusOK, envelope[networkResponse]{Data: toNetworkResponse(network)})
}

func isAllowedNetworkRole(role domain.NetworkRole) bool {
	switch role {
	case domain.NetworkRoleOwner, domain.NetworkRoleAdmin, domain.NetworkRoleModerator, domain.NetworkRoleFileAdmin, domain.NetworkRoleMember, domain.NetworkRoleReadOnly:
		return true
	default:
		return false
	}
}

func (api *API) removeNetworkMember(w http.ResponseWriter, r *http.Request, networkID, memberID string) {
	ownerID := strings.TrimSpace(r.URL.Query().Get("ownerId"))
	current := currentUserID(r)
	if ownerID != "" && ownerID != current.String() {
		writeDomainError(w, domain.ErrUnauthorized)
		return
	}
	if err := api.app.NetworkService.RemoveMember(current, domain.NetworkID{Value: networkID}, domain.UserID{Value: memberID}); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (api *API) createNetworkInvite(w http.ResponseWriter, r *http.Request, networkID string) {
	var req createInviteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ownerID := currentUserID(r)
	if req.OwnerID != "" && req.OwnerID != ownerID.String() {
		writeDomainError(w, domain.ErrUnauthorized)
		return
	}
	invite, err := api.app.NetworkService.GenerateInvite(ownerID, domain.NetworkID{Value: networkID}, req.TTLSec, req.MaxUses, time.Now().Unix())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, envelope[inviteResponse]{Data: toInviteResponse(invite)})
}

func (api *API) listNetworkAuditEvents(w http.ResponseWriter, r *http.Request, networkID string) {
	events, err := api.app.NetworkService.ListAuditEventsForUser(currentUserID(r), domain.NetworkID{Value: networkID}, 1000)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	events = filterAuditEvents(events, r)
	limit, offset := paginationFromRequest(r)
	eventsPage, total := paginateSlice(events, limit, offset)
	writeJSON(w, http.StatusOK, listEnvelope[auditEventResponse]{
		Data: toAuditEventResponses(eventsPage),
		Meta: responseMeta{Count: len(eventsPage), Total: total, Limit: limit, Offset: offset},
	})
}

func (api *API) redeemInvite(w http.ResponseWriter, r *http.Request, code string) {
	var req redeemInviteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	userID := currentUserID(r)
	if req.UserID != "" && req.UserID != userID.String() {
		writeDomainError(w, domain.ErrUnauthorized)
		return
	}
	network, err := api.app.NetworkService.JoinByInvite(userID, code, time.Now().Unix())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, envelope[networkResponse]{Data: toNetworkResponse(network)})
}

func (api *API) listNetworkPeers(w http.ResponseWriter, r *http.Request, networkID string) {
	peers, err := api.app.PeerDirectory.ListPeersForUser(currentUserID(r), domain.NetworkID{Value: networkID})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	peers = filterPeers(peers, r)
	limit, offset := paginationFromRequest(r)
	peersPage, total := paginateSlice(peers, limit, offset)
	writeJSON(w, http.StatusOK, listEnvelope[peerResponse]{
		Data: toPeerResponses(peersPage),
		Meta: responseMeta{Count: len(peersPage), Total: total, Limit: limit, Offset: offset},
	})
}

func (api *API) createNetworkPeer(w http.ResponseWriter, r *http.Request, networkID string) {
	var req createPeerRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	userID := currentUserID(r)
	if req.UserID != "" && req.UserID != userID.String() {
		api.traceError(r, "signaling.peer.register_unauthorized", "peer registration rejected", "networkId", networkID, "requestedUserId", req.UserID, "currentUserId", userID.String())
		writeDomainError(w, domain.ErrUnauthorized)
		return
	}
	peer, err := api.app.PeerDirectory.RegisterPeer(userID, domain.DeviceID{Value: req.DeviceID}, domain.NetworkID{Value: networkID}, req.Endpoint, time.Now().Unix())
	if err != nil {
		api.traceError(r, "signaling.peer.register_failed", "peer registration failed", "networkId", networkID, "deviceId", req.DeviceID, "endpoint", req.Endpoint, "error", err)
		writeDomainError(w, err)
		return
	}
	api.traceInfo(r, "signaling.peer.registered", "peer registered", "networkId", networkID, "peerId", peer.ID.String(), "deviceId", peer.DeviceID.String(), "endpoint", peer.Endpoint)
	writeJSON(w, http.StatusCreated, envelope[peerResponse]{Data: toPeerResponse(peer)})
}

func (api *API) listNetworkMessages(w http.ResponseWriter, r *http.Request, networkID string) {
	messages, err := api.app.MessagingService.ListMessagesForUser(currentUserID(r), domain.NetworkID{Value: networkID})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	messages = filterMessages(messages, r)
	limit, offset := paginationFromRequest(r)
	messagesPage, total := paginateSlice(messages, limit, offset)
	writeJSON(w, http.StatusOK, listEnvelope[messageResponse]{
		Data: toMessageResponses(messagesPage),
		Meta: responseMeta{Count: len(messagesPage), Total: total, Limit: limit, Offset: offset},
	})
}

func (api *API) createNetworkMessage(w http.ResponseWriter, r *http.Request, networkID string) {
	var req createMessageRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	message, err := api.app.MessagingService.SendMessage(
		currentUserID(r),
		domain.NetworkID{Value: networkID},
		domain.PeerID{Value: req.FromPeerID},
		req.Text,
		time.Now().Unix(),
	)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, envelope[messageResponse]{Data: toMessageResponse(message)})
}

func (api *API) getMessage(w http.ResponseWriter, r *http.Request, messageID string) {
	message, err := api.app.MessagingService.GetMessageForUser(currentUserID(r), messageID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[messageResponse]{Data: toMessageResponse(message)})
}

func (api *API) getPeer(w http.ResponseWriter, r *http.Request, peerID string) {
	peer, err := api.app.PeerDirectory.GetPeerForUser(currentUserID(r), domain.PeerID{Value: peerID})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[peerResponse]{Data: toPeerResponse(peer)})
}

func (api *API) patchPeer(w http.ResponseWriter, r *http.Request, peerID string) {
	var req patchPeerRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Endpoint != nil {
		if err := api.app.PeerDirectory.HeartbeatForUser(currentUserID(r), domain.PeerID{Value: peerID}, *req.Endpoint, time.Now().Unix()); err != nil {
			api.traceError(r, "signaling.peer.heartbeat_failed", "peer heartbeat failed", "peerId", peerID, "endpoint", *req.Endpoint, "error", err)
			writeDomainError(w, err)
			return
		}
		api.traceInfo(r, "signaling.peer.heartbeat_succeeded", "peer heartbeat updated", "peerId", peerID, "endpoint", *req.Endpoint)
	}
	if req.Status != nil && strings.EqualFold(*req.Status, string(domain.PeerStatusOffline)) {
		if err := api.app.PeerDirectory.DisconnectForUser(currentUserID(r), domain.PeerID{Value: peerID}, time.Now().Unix()); err != nil {
			api.traceError(r, "signaling.peer.disconnect_failed", "peer disconnect failed", "peerId", peerID, "error", err)
			writeDomainError(w, err)
			return
		}
		api.traceInfo(r, "signaling.peer.disconnected", "peer disconnected", "peerId", peerID)
	}
	if req.Reachability != nil || req.ConnectionState != nil {
		reachability := domain.PeerReachability("")
		connectionState := domain.ConnectionState("")
		if req.Reachability != nil {
			reachability = domain.PeerReachability(strings.ToUpper(strings.TrimSpace(*req.Reachability)))
		}
		if req.ConnectionState != nil {
			connectionState = domain.ConnectionState(strings.ToUpper(strings.TrimSpace(*req.ConnectionState)))
		}
		if _, err := api.app.PeerDirectory.UpdateSignaling(currentUserID(r), domain.PeerID{Value: peerID}, reachability, connectionState, time.Now().Unix()); err != nil {
			api.traceError(r, "signaling.peer.state_update_failed", "peer signaling update failed", "peerId", peerID, "reachability", reachability, "connectionState", connectionState, "error", err)
			writeDomainError(w, err)
			return
		}
		api.traceInfo(r, "signaling.peer.state_updated", "peer signaling updated", "peerId", peerID, "reachability", reachability, "connectionState", connectionState)
	}
	peer, err := api.app.PeerDirectory.GetOwnedPeer(currentUserID(r), domain.PeerID{Value: peerID})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[peerResponse]{Data: toPeerResponse(peer)})
}

func (api *API) listPeerCandidates(w http.ResponseWriter, r *http.Request, peerID string) {
	candidates, err := api.app.SignalingService.ListCandidates(currentUserID(r), domain.PeerID{Value: peerID}, time.Now().Unix())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, listEnvelope[signalCandidateResponse]{
		Data: toSignalCandidateResponses(candidates),
		Meta: responseMeta{Count: len(candidates), Total: len(candidates)},
	})
}

func (api *API) createPeerCandidate(w http.ResponseWriter, r *http.Request, peerID string) {
	var req createSignalCandidateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	reachable := true
	if req.Reachable != nil {
		reachable = *req.Reachable
	}
	candidate, err := api.app.SignalingService.PublishCandidate(
		currentUserID(r),
		domain.PeerID{Value: peerID},
		domain.SignalCandidateType(strings.ToUpper(strings.TrimSpace(req.Type))),
		domain.SignalCandidateProtocol(strings.ToUpper(strings.TrimSpace(req.Protocol))),
		req.Address,
		req.Preference,
		reachable,
		req.TTLSec,
		time.Now().Unix(),
	)
	if err != nil {
		api.traceError(r, "signaling.candidate.publish_failed", "signal candidate publish failed", "peerId", peerID, "candidateType", req.Type, "protocol", req.Protocol, "address", req.Address, "error", err)
		writeDomainError(w, err)
		return
	}
	api.traceInfo(r, "signaling.candidate.published", "signal candidate published", "peerId", peerID, "candidateId", candidate.ID, "candidateType", candidate.Type, "protocol", candidate.Protocol, "address", candidate.Address)
	writeJSON(w, http.StatusCreated, envelope[signalCandidateResponse]{Data: toSignalCandidateResponse(candidate)})
}

func (api *API) listNetworkTunnels(w http.ResponseWriter, r *http.Request, networkID string) {
	tunnels, err := api.app.TunnelCoordinator.ListTunnelsForUser(currentUserID(r), domain.NetworkID{Value: networkID})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	tunnels = filterTunnels(tunnels, r)
	limit, offset := paginationFromRequest(r)
	tunnelsPage, total := paginateSlice(tunnels, limit, offset)
	writeJSON(w, http.StatusOK, listEnvelope[tunnelResponse]{
		Data: toTunnelResponses(tunnelsPage),
		Meta: responseMeta{Count: len(tunnelsPage), Total: total, Limit: limit, Offset: offset},
	})
}

func (api *API) createNetworkTunnel(w http.ResponseWriter, r *http.Request, networkID string) {
	var req createTunnelRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	mode := domain.TunnelMode(strings.ToUpper(strings.TrimSpace(req.Mode)))
	tunnel, err := api.app.TunnelCoordinator.RequestTunnelForUser(currentUserID(r), domain.NetworkID{Value: networkID}, domain.PeerID{Value: req.PeerAID}, domain.PeerID{Value: req.PeerBID}, mode, time.Now().Unix())
	if err != nil {
		api.traceError(r, "signaling.tunnel.request_failed", "tunnel request failed", "networkId", networkID, "peerAId", req.PeerAID, "peerBId", req.PeerBID, "mode", mode, "error", err)
		writeDomainError(w, err)
		return
	}
	api.traceInfo(r, "signaling.tunnel.requested", "tunnel requested", "networkId", networkID, "tunnelId", tunnel.ID.String(), "peerAId", tunnel.A.String(), "peerBId", tunnel.B.String(), "mode", tunnel.Mode, "state", tunnel.State)
	writeJSON(w, http.StatusCreated, envelope[tunnelResponse]{Data: toTunnelResponse(tunnel)})
}

func (api *API) listNetworkFileTransfers(w http.ResponseWriter, r *http.Request, networkID string) {
	transfers, err := api.app.FileTransferService.ListTransfersForUser(currentUserID(r), domain.NetworkID{Value: networkID})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	transfers = filterFileTransfers(transfers, r)
	limit, offset := paginationFromRequest(r)
	transfersPage, total := paginateSlice(transfers, limit, offset)
	writeJSON(w, http.StatusOK, listEnvelope[fileTransferResponse]{
		Data: toFileTransferResponses(transfersPage),
		Meta: responseMeta{Count: len(transfersPage), Total: total, Limit: limit, Offset: offset},
	})
}

func (api *API) createNetworkFileTransfer(w http.ResponseWriter, r *http.Request, networkID string) {
	var req createFileTransferRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	transfer, err := api.app.FileTransferService.CreateTransfer(
		currentUserID(r),
		domain.NetworkID{Value: networkID},
		domain.PeerID{Value: req.FromPeerID},
		domain.PeerID{Value: req.ToPeerID},
		req.FileName,
		req.SizeBytes,
	)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, envelope[fileTransferResponse]{Data: toFileTransferResponse(transfer)})
}

func (api *API) getFileTransfer(w http.ResponseWriter, r *http.Request, transferID string) {
	transfer, err := api.app.FileTransferService.GetTransferForUser(currentUserID(r), transferID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[fileTransferResponse]{Data: toFileTransferResponse(transfer)})
}

func (api *API) uploadFileTransferContent(w http.ResponseWriter, r *http.Request, transferID string) {
	var req uploadFileTransferContentRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PayloadBase64))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "payloadBase64 must be valid base64"})
		return
	}
	transfer, err := api.app.FileTransferService.UploadTransferPayload(currentUserID(r), transferID, req.ContentType, payload, time.Now().Unix())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[fileTransferResponse]{Data: toFileTransferResponse(transfer)})
}

func (api *API) uploadFileTransferContentChunk(w http.ResponseWriter, r *http.Request, transferID string) {
	var req uploadFileTransferContentChunkRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PayloadBase64))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "payloadBase64 must be valid base64"})
		return
	}
	transfer, err := api.app.FileTransferService.UploadTransferPayloadChunk(currentUserID(r), transferID, req.ContentType, req.OffsetBytes, payload, time.Now().Unix())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[fileTransferResponse]{Data: toFileTransferResponse(transfer)})
}

func (api *API) downloadFileTransferContent(w http.ResponseWriter, r *http.Request, transferID string) {
	payload, transfer, err := api.app.FileTransferService.DownloadTransferPayload(currentUserID(r), transferID, time.Now().Unix())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[fileTransferContentResponse]{Data: toFileTransferContentResponse(payload, transfer)})
}

func (api *API) downloadFileTransferContentChunk(w http.ResponseWriter, r *http.Request, transferID string) {
	offsetBytes, err := parseInt64QueryParam(r, "offsetBytes")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}
	limitBytes, err := parseInt64QueryParam(r, "limitBytes")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}
	payload, _, err := api.app.FileTransferService.DownloadTransferPayloadChunk(currentUserID(r), transferID, offsetBytes, limitBytes, time.Now().Unix())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[fileTransferContentChunkResponse]{Data: toFileTransferContentChunkResponse(payload)})
}

func (api *API) patchFileTransfer(w http.ResponseWriter, r *http.Request, transferID string) {
	var req patchFileTransferRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	var (
		transfer *domain.FileTransfer
		err      error
	)
	switch strings.ToUpper(strings.TrimSpace(req.Action)) {
	case "ACCEPT":
		transfer, err = api.app.FileTransferService.AcceptTransfer(currentUserID(r), transferID)
	case "CANCEL":
		transfer, err = api.app.FileTransferService.CancelTransfer(currentUserID(r), transferID, req.Reason)
	case "":
		if req.ProgressPercent == nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "action or progressPercent is required"})
			return
		}
		transfer, err = api.app.FileTransferService.UpdateTransferProgress(currentUserID(r), transferID, *req.ProgressPercent)
	default:
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "action must be ACCEPT or CANCEL"})
		return
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[fileTransferResponse]{Data: toFileTransferResponse(transfer)})
}

func parseInt64QueryParam(r *http.Request, name string) (int64, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a whole number", name)
	}
	return value, nil
}

func (api *API) getTunnel(w http.ResponseWriter, r *http.Request, tunnelID string) {
	tunnel, err := api.app.TunnelCoordinator.GetTunnelForUser(currentUserID(r), domain.TunnelID{Value: tunnelID})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope[tunnelResponse]{Data: toTunnelResponse(tunnel)})
}

func (api *API) patchTunnel(w http.ResponseWriter, r *http.Request, tunnelID string) {
	var req patchTunnelRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	var err error
	switch strings.ToUpper(strings.TrimSpace(req.State)) {
	case string(domain.TunnelStateOpen):
		err = api.app.TunnelCoordinator.OpenTunnelForUser(currentUserID(r), domain.TunnelID{Value: tunnelID})
	case string(domain.TunnelStateClosed):
		err = api.app.TunnelCoordinator.CloseTunnelForUser(currentUserID(r), domain.TunnelID{Value: tunnelID})
	case string(domain.TunnelStateFailed):
		err = api.app.TunnelCoordinator.MarkFailedForUser(currentUserID(r), domain.TunnelID{Value: tunnelID})
	default:
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "state must be OPEN, CLOSED, or FAILED"})
		return
	}
	if err != nil {
		api.traceError(r, "signaling.tunnel.state_update_failed", "tunnel state update failed", "tunnelId", tunnelID, "state", req.State, "error", err)
		writeDomainError(w, err)
		return
	}
	tunnel, _ := api.app.TunnelCoordinator.GetTunnelForUser(currentUserID(r), domain.TunnelID{Value: tunnelID})
	if tunnel != nil {
		api.traceInfo(r, "signaling.tunnel.state_updated", "tunnel state updated", "tunnelId", tunnelID, "state", tunnel.State, "mode", tunnel.Mode)
	}
	writeJSON(w, http.StatusOK, envelope[tunnelResponse]{Data: toTunnelResponse(tunnel)})
}

func (api *API) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	events, err := api.app.NetworkService.ListVisibleAuditEventsForUser(currentUserID(r), 1000)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	events = filterAuditEvents(events, r)
	limit, offset := paginationFromRequest(r)
	eventsPage, total := paginateSlice(events, limit, offset)
	writeJSON(w, http.StatusOK, listEnvelope[auditEventResponse]{
		Data: toAuditEventResponses(eventsPage),
		Meta: responseMeta{Count: len(eventsPage), Total: total, Limit: limit, Offset: offset},
	})
}
