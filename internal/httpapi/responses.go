package httpapi

import (
	"Ole/internal/domain"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

func toUserResponse(user *domain.User) userResponse {
	if user == nil {
		return userResponse{}
	}
	return userResponse{ID: user.ID.String(), Email: user.Email, Status: string(user.Status)}
}

func toDeviceResponse(device *domain.Device) deviceResponse {
	if device == nil {
		return deviceResponse{}
	}
	return deviceResponse{
		ID:            device.ID.String(),
		UserID:        device.UserID.String(),
		Name:          device.Name,
		PublicKey:     device.PublicKey,
		Fingerprint:   device.Fingerprint,
		Status:        string(device.Status),
		CreatedAtUnix: device.CreatedAtUnix,
		RevokedAtUnix: device.RevokedAtUnix,
	}
}

func toNetworkResponse(network *domain.Network) networkResponse {
	if network == nil {
		return networkResponse{}
	}
	memberIDs := network.MemberIDs()
	approvedDeviceIDs := network.ApprovedDeviceIDs()
	members := make([]string, 0, len(memberIDs))
	approvedDevices := make([]string, 0, len(approvedDeviceIDs))
	memberRoles := make(map[string]string, len(network.Members))
	for _, memberID := range memberIDs {
		members = append(members, memberID.String())
		if role, ok := network.RoleOf(memberID); ok {
			memberRoles[memberID.String()] = string(role)
		}
	}
	for _, deviceID := range approvedDeviceIDs {
		approvedDevices = append(approvedDevices, deviceID.String())
	}
	return networkResponse{
		ID:                     network.ID.String(),
		Name:                   network.Name,
		OwnerID:                network.OwnerID.String(),
		Access:                 string(network.Access),
		DeviceApprovalRequired: network.DeviceApprovalRequired,
		RoutingPolicy:          string(network.RoutingPolicy),
		GroupTrafficPolicy:     string(network.GroupTrafficPolicy),
		NameResolutionMode:     string(network.NameResolutionMode),
		DNSLabel:               network.DNSLabel,
		FileTransfersEnabled:   network.FileTransfersEnabled,
		FileTransferMaxBytes:   network.FileTransferMaxBytes,
		ApprovedDeviceIDs:      approvedDevices,
		Members:                members,
		MemberRoles:            memberRoles,
	}
}

func toPeerResponse(peer *domain.Peer) peerResponse {
	if peer == nil {
		return peerResponse{}
	}
	return peerResponse{
		ID:                 peer.ID.String(),
		UserID:             peer.UserID.String(),
		DeviceID:           peer.DeviceID.String(),
		NetworkID:          peer.NetworkID.String(),
		OverlayCIDR:        peer.OverlayCIDR,
		VirtualIP:          peer.VirtualIP,
		Endpoint:           peer.Endpoint,
		Status:             string(peer.Status),
		Reachability:       string(peer.Reachability),
		ConnectionState:    string(peer.ConnectionState),
		LastSeenUnix:       peer.LastSeenUnix,
		LastSignaledAtUnix: peer.LastSignaledAtUnix,
	}
}

func toMessageResponse(message *domain.Message) messageResponse {
	if message == nil {
		return messageResponse{}
	}
	return messageResponse{
		ID:         message.ID,
		NetworkID:  message.NetworkID.String(),
		FromPeerID: message.FromPeerID.String(),
		Text:       message.Text,
		Preview:    message.Preview(80),
		SentAtUnix: message.SentAtUnix,
	}
}

func toFileTransferResponse(transfer *domain.FileTransfer) fileTransferResponse {
	if transfer == nil {
		return fileTransferResponse{}
	}
	return fileTransferResponse{
		ID:                   transfer.ID,
		NetworkID:            transfer.NetworkID.String(),
		FromPeerID:           transfer.FromPeerID.String(),
		FromUserID:           transfer.FromUserID.String(),
		ToPeerID:             transfer.ToPeerID.String(),
		ToUserID:             transfer.ToUserID.String(),
		FileName:             transfer.FileName,
		SizeBytes:            transfer.SizeBytes,
		Status:               string(transfer.Status),
		ProgressPercent:      transfer.ProgressPercent,
		CancelReason:         transfer.CancelReason,
		ContentType:          transfer.ContentType,
		PayloadSHA256:        transfer.PayloadSHA256,
		PayloadReady:         transfer.PayloadReady,
		PayloadUploadedBytes: transfer.PayloadUploadedBytes,
		UploadedAtUnix:       transfer.UploadedAtUnix,
		DownloadedAtUnix:     transfer.DownloadedAtUnix,
	}
}

func toFileTransferContentResponse(payload *domain.FileTransferPayload, transfer *domain.FileTransfer) fileTransferContentResponse {
	if payload == nil {
		return fileTransferContentResponse{Transfer: toFileTransferResponse(transfer)}
	}
	return fileTransferContentResponse{
		Transfer:         toFileTransferResponse(transfer),
		ContentType:      payload.ContentType,
		SHA256:           payload.SHA256,
		PayloadBase64:    base64.StdEncoding.EncodeToString(payload.Payload),
		SizeBytes:        payload.SizeBytes,
		UploadedAtUnix:   payload.UploadedAtUnix,
		DownloadedAtUnix: payload.DownloadedAtUnix,
	}
}

func toFileTransferContentChunkResponse(payload *domain.FileTransferPayloadChunk) fileTransferContentChunkResponse {
	if payload == nil {
		return fileTransferContentChunkResponse{}
	}
	var transfer fileTransferResponse
	if payload.Transfer != nil {
		transfer = toFileTransferResponse(payload.Transfer)
	}
	return fileTransferContentChunkResponse{
		Transfer:         transfer,
		ContentType:      payload.ContentType,
		SHA256:           payload.SHA256,
		PayloadBase64:    base64.StdEncoding.EncodeToString(payload.Payload),
		OffsetBytes:      payload.OffsetBytes,
		NextOffsetBytes:  payload.NextOffsetBytes,
		TotalSizeBytes:   payload.TotalSizeBytes,
		UploadedAtUnix:   payload.UploadedAtUnix,
		DownloadedAtUnix: payload.DownloadedAtUnix,
		Complete:         payload.Complete,
	}
}

func toSignalCandidateResponse(candidate *domain.SignalCandidate) signalCandidateResponse {
	if candidate == nil {
		return signalCandidateResponse{}
	}
	return signalCandidateResponse{
		ID:            candidate.ID,
		PeerID:        candidate.PeerID.String(),
		NetworkID:     candidate.NetworkID.String(),
		Type:          string(candidate.Type),
		Protocol:      string(candidate.Protocol),
		Address:       candidate.Address,
		Preference:    candidate.Preference,
		Reachable:     candidate.Reachable,
		CreatedAtUnix: candidate.CreatedAtUnix,
		ExpiresAtUnix: candidate.ExpiresAtUnix,
	}
}

func toInviteResponse(invite *domain.Invite) inviteResponse {
	if invite == nil {
		return inviteResponse{}
	}
	return inviteResponse{
		Code:          invite.Code,
		NetworkID:     invite.NetworkID.String(),
		ExpiresAtUnix: invite.ExpiresAtUnix,
		MaxUses:       invite.MaxUses,
		Uses:          invite.Uses,
	}
}

func toTunnelResponse(tunnel *domain.Tunnel) tunnelResponse {
	if tunnel == nil {
		return tunnelResponse{}
	}
	return tunnelResponse{
		ID:            tunnel.ID.String(),
		NetworkID:     tunnel.NetworkID.String(),
		PeerAID:       tunnel.A.String(),
		PeerBID:       tunnel.B.String(),
		Mode:          string(tunnel.Mode),
		State:         string(tunnel.State),
		CreatedAtUnix: tunnel.CreatedAtUnix,
	}
}

func toSessionResponse(session *domain.SessionToken) sessionResponse {
	if session == nil {
		return sessionResponse{}
	}
	return sessionResponse{
		ID:                  session.ID,
		UserID:              session.UserID.String(),
		FamilyID:            session.FamilyID,
		AccessToken:         session.AccessToken,
		RefreshToken:        session.RefreshToken,
		DeviceName:          session.DeviceName,
		IP:                  session.IP,
		UserAgent:           session.UserAgent,
		LastUsedAtUnix:      session.LastUsedAtUnix,
		ExpiresAtUnix:       session.ExpiresAtUnix,
		RevokedAtUnix:       session.RevokedAtUnix,
		ReuseDetectedAtUnix: session.ReuseDetectedAtUnix,
	}
}

func toAuditEventResponses(events []*domain.AuditEvent) []auditEventResponse {
	out := make([]auditEventResponse, 0, len(events))
	for _, event := range events {
		out = append(out, auditEventResponse{
			ID:            event.ID,
			ActorUserID:   event.ActorUserID.String(),
			NetworkID:     event.NetworkID.String(),
			Type:          event.Type,
			Details:       event.Details,
			CreatedAtUnix: event.CreatedAtUnix,
		})
	}
	return out
}

func toNetworkResponses(networks []*domain.Network) []networkResponse {
	out := make([]networkResponse, 0, len(networks))
	for _, network := range networks {
		out = append(out, toNetworkResponse(network))
	}
	return out
}

func toDeviceResponses(devices []*domain.Device) []deviceResponse {
	out := make([]deviceResponse, 0, len(devices))
	for _, device := range devices {
		out = append(out, toDeviceResponse(device))
	}
	return out
}

func toPeerResponses(peers []*domain.Peer) []peerResponse {
	out := make([]peerResponse, 0, len(peers))
	for _, peer := range peers {
		out = append(out, toPeerResponse(peer))
	}
	return out
}

func toMessageResponses(messages []*domain.Message) []messageResponse {
	out := make([]messageResponse, 0, len(messages))
	for _, message := range messages {
		out = append(out, toMessageResponse(message))
	}
	return out
}

func toFileTransferResponses(transfers []*domain.FileTransfer) []fileTransferResponse {
	out := make([]fileTransferResponse, 0, len(transfers))
	for _, transfer := range transfers {
		out = append(out, toFileTransferResponse(transfer))
	}
	return out
}

func toSignalCandidateResponses(candidates []*domain.SignalCandidate) []signalCandidateResponse {
	out := make([]signalCandidateResponse, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, toSignalCandidateResponse(candidate))
	}
	return out
}

func toTunnelResponses(tunnels []*domain.Tunnel) []tunnelResponse {
	out := make([]tunnelResponse, 0, len(tunnels))
	for _, tunnel := range tunnels {
		out = append(out, toTunnelResponse(tunnel))
	}
	return out
}

func toSessionResponses(sessions []*domain.SessionToken) []sessionResponse {
	out := make([]sessionResponse, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, toSessionResponse(session))
	}
	return out
}

func splitPath(path string) []string {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	return strings.Split(strings.Trim(path, "/"), "/")
}

func trimPrefix(value, prefix string) string {
	return strings.TrimPrefix(value, prefix)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON payload"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeNotFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, errorResponse{Error: "resource not found"})
}

func writeMethodNotAllowed(w http.ResponseWriter) {
	writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
}

func writeMethodOrNotFound(w http.ResponseWriter, segments []string) {
	if len(segments) == 0 {
		writeMethodNotAllowed(w)
		return
	}
	writeNotFound(w)
}

func writeDomainError(w http.ResponseWriter, err error) {
	if errors.Is(err, domain.ErrPasswordStorage) {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: domain.ErrPasswordStorage.Error()})
		return
	}
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, domain.ErrUnauthorized), errors.Is(err, domain.ErrInvalidCredentials):
		status = http.StatusUnauthorized
	case errors.Is(err, domain.ErrNotFound), errors.Is(err, domain.ErrTransferPayloadMissing):
		status = http.StatusNotFound
	case errors.Is(err, domain.ErrAlreadyExists):
		status = http.StatusConflict
	case errors.Is(err, domain.ErrTransferPayloadOffsetMismatch):
		status = http.StatusConflict
	case errors.Is(err, domain.ErrOnlyOwnerCanManage), errors.Is(err, domain.ErrInsufficientNetworkRole), errors.Is(err, domain.ErrDeviceApprovalRequired):
		status = http.StatusForbidden
	case errors.Is(err, domain.ErrTransferPayloadTooLarge), errors.Is(err, domain.ErrTransferPolicyExceeded):
		status = http.StatusRequestEntityTooLarge
	}
	writeJSON(w, status, errorResponse{Error: err.Error()})
}
