package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/prommetrics"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type envelope[T any] struct {
	Data T `json:"data"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func NewHandler(agent *Agent) http.Handler {
	mux := http.NewServeMux()
	registry := prommetrics.NewRegistry()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		writeJSON(w, http.StatusOK, envelope[Status]{Data: agent.Status()})
	})
	mux.HandleFunc("/livez", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		writeJSON(w, http.StatusOK, envelope[ProbeResponse]{Data: agent.livenessProbe()})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		response, statusCode := agent.readinessProbe()
		writeJSON(w, statusCode, envelope[ProbeResponse]{Data: response})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write(renderPrometheusMetrics(agent, registry))
	})
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		writeJSON(w, http.StatusOK, envelope[Status]{Data: agent.Status()})
	})
	mux.HandleFunc("/api/v1/diagnostics/bundle", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		writeJSON(w, http.StatusOK, envelope[DiagnosticsBundle]{Data: agent.DiagnosticsBundle()})
	})
	mux.HandleFunc("/api/v1/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			writeMethodNotAllowed(w)
			return
		}
		var req SetConfigRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		writeJSON(w, http.StatusOK, envelope[Status]{Data: agent.SetServerBaseURL(req.ServerBaseURL)})
	})
	mux.HandleFunc("/api/v1/config/adapter/mtu", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			writeMethodNotAllowed(w)
			return
		}
		var req SetAdapterMTURequest
		if !decodeJSON(w, r, &req) {
			return
		}
		status, err := agent.SetAdapterMTU(req.MTU)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope[Status]{Data: status})
	})
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w)
			return
		}
		var req RegisterRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		user, err := agent.Register(req.Email, req.Password)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, envelope[*controlclient.User]{Data: user})
	})
	mux.HandleFunc("/api/v1/session/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w)
			return
		}
		var req LoginRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		status, err := agent.Login(req.Email, req.Password)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope[Status]{Data: status})
	})
	mux.HandleFunc("/api/v1/session/reconnect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w)
			return
		}
		status, err := agent.Reconnect()
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope[Status]{Data: status})
	})
	mux.HandleFunc("/api/v1/update/check", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w)
			return
		}
		status, err := agent.CheckForUpdates()
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope[Status]{Data: status})
	})
	mux.HandleFunc("/api/v1/update/channel", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			writeMethodNotAllowed(w)
			return
		}
		var req SetUpdateChannelRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		status, err := agent.SetUpdateChannel(req.Channel)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope[Status]{Data: status})
	})
	mux.HandleFunc("/api/v1/update/download", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w)
			return
		}
		status, err := agent.DownloadUpdate()
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope[Status]{Data: status})
	})
	mux.HandleFunc("/api/v1/update/rollback/download", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w)
			return
		}
		status, err := agent.DownloadRollback()
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope[Status]{Data: status})
	})
	mux.HandleFunc("/api/v1/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w)
			return
		}
		if err := agent.Logout(); err != nil {
			writeError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		sessions, err := agent.ListSessions()
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope[[]controlclient.Session]{Data: sessions})
	})
	mux.HandleFunc("/api/v1/sessions/all", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w)
			return
		}
		status, err := agent.RevokeAllSessions()
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope[Status]{Data: status})
	})
	mux.HandleFunc("/api/v1/devices", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		devices, err := agent.ListDevices()
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope[[]controlclient.Device]{Data: devices})
	})
	mux.HandleFunc("/api/v1/sessions/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w)
			return
		}
		sessionID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/sessions/"))
		if sessionID == "" {
			writeNotFound(w)
			return
		}
		status, err := agent.RevokeSession(sessionID)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope[Status]{Data: status})
	})
	mux.HandleFunc("/api/v1/audit-events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		filter := controlclient.AuditEventFilter{
			ActorUserID: strings.TrimSpace(r.URL.Query().Get("actorUserId")),
			Type:        strings.TrimSpace(r.URL.Query().Get("type")),
			Query:       strings.TrimSpace(r.URL.Query().Get("q")),
		}
		if value := strings.TrimSpace(r.URL.Query().Get("fromUnix")); value != "" {
			if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
				filter.FromUnix = parsed
			}
		}
		if value := strings.TrimSpace(r.URL.Query().Get("toUnix")); value != "" {
			if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
				filter.ToUnix = parsed
			}
		}
		if value := strings.TrimSpace(r.URL.Query().Get("limit")); value != "" {
			if parsed, err := strconv.Atoi(value); err == nil {
				filter.Limit = parsed
			}
		}
		if value := strings.TrimSpace(r.URL.Query().Get("offset")); value != "" {
			if parsed, err := strconv.Atoi(value); err == nil {
				filter.Offset = parsed
			}
		}
		events, err := agent.ListAuditEvents(filter)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope[[]controlclient.AuditEvent]{Data: events})
	})
	mux.HandleFunc("/api/v1/audit-presets", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			presets, err := agent.ListAuditPresets()
			if err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, envelope[[]AuditFilterPreset]{Data: presets})
		case http.MethodPost:
			var req SaveAuditPresetRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			presets, err := agent.SaveAuditPreset(req.Name, req.Filter())
			if err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, envelope[[]AuditFilterPreset]{Data: presets})
		default:
			writeMethodNotAllowed(w)
		}
	})
	mux.HandleFunc("/api/v1/audit-presets/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w)
			return
		}
		name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/audit-presets/"))
		if name == "" {
			writeNotFound(w)
			return
		}
		decoded, err := url.PathUnescape(name)
		if err != nil {
			writeError(w, err)
			return
		}
		presets, err := agent.DeleteAuditPreset(decoded)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope[[]AuditFilterPreset]{Data: presets})
	})
	mux.HandleFunc("/api/v1/incidents", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		incidents, err := agent.ListIncidentReports()
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope[[]controlclient.IncidentReport]{Data: incidents})
	})
	mux.HandleFunc("/api/v1/invites/redeem", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w)
			return
		}
		var req RedeemInviteRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		network, err := agent.RedeemInvite(req.Code)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, envelope[*controlclient.Network]{Data: network})
	})
	mux.HandleFunc("/api/v1/file-transfers/", func(w http.ResponseWriter, r *http.Request) {
		parts := splitPath(strings.TrimPrefix(r.URL.Path, "/api/v1/file-transfers/"))
		if len(parts) == 0 {
			writeNotFound(w)
			return
		}
		transferID := strings.TrimSpace(parts[0])
		if transferID == "" {
			writeNotFound(w)
			return
		}
		if len(parts) == 2 && parts[1] == "content" {
			switch r.Method {
			case http.MethodPut:
				var req UploadFileTransferContentRequest
				if !decodeJSON(w, r, &req) {
					return
				}
				payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PayloadBase64))
				if err != nil {
					writeError(w, errors.New("payloadBase64 must be valid base64"))
					return
				}
				transfer, err := agent.UploadFileTransferContent(transferID, req.ContentType, payload)
				if err != nil {
					writeError(w, err)
					return
				}
				writeJSON(w, http.StatusOK, envelope[*controlclient.FileTransfer]{Data: transfer})
			case http.MethodGet:
				content, err := agent.DownloadFileTransferContent(transferID)
				if err != nil {
					writeError(w, err)
					return
				}
				type contentEnvelope struct {
					Transfer         controlclient.FileTransfer `json:"transfer"`
					ContentType      string                     `json:"contentType"`
					SHA256           string                     `json:"sha256"`
					PayloadBase64    string                     `json:"payloadBase64"`
					SizeBytes        int64                      `json:"sizeBytes"`
					UploadedAtUnix   int64                      `json:"uploadedAtUnix"`
					DownloadedAtUnix int64                      `json:"downloadedAtUnix"`
				}
				writeJSON(w, http.StatusOK, envelope[contentEnvelope]{Data: contentEnvelope{
					Transfer:         content.Transfer,
					ContentType:      content.ContentType,
					SHA256:           content.SHA256,
					PayloadBase64:    base64.StdEncoding.EncodeToString(content.Payload),
					SizeBytes:        content.SizeBytes,
					UploadedAtUnix:   content.UploadedAtUnix,
					DownloadedAtUnix: content.DownloadedAtUnix,
				}})
			default:
				writeMethodNotAllowed(w)
			}
			return
		}
		if len(parts) == 2 && parts[1] == "content-chunks" {
			switch r.Method {
			case http.MethodPut:
				var req UploadFileTransferContentChunkRequest
				if !decodeJSON(w, r, &req) {
					return
				}
				payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PayloadBase64))
				if err != nil {
					writeError(w, errors.New("payloadBase64 must be valid base64"))
					return
				}
				transfer, err := agent.UploadFileTransferContentChunk(transferID, req.ContentType, req.OffsetBytes, payload)
				if err != nil {
					writeError(w, err)
					return
				}
				writeJSON(w, http.StatusOK, envelope[*controlclient.FileTransfer]{Data: transfer})
			case http.MethodGet:
				offsetBytes, err := parseInt64Query(r, "offsetBytes")
				if err != nil {
					writeError(w, err)
					return
				}
				limitBytes, err := parseInt64Query(r, "limitBytes")
				if err != nil {
					writeError(w, err)
					return
				}
				content, err := agent.DownloadFileTransferContentChunk(transferID, offsetBytes, limitBytes)
				if err != nil {
					writeError(w, err)
					return
				}
				type chunkEnvelope struct {
					Transfer         controlclient.FileTransfer `json:"transfer"`
					ContentType      string                     `json:"contentType"`
					SHA256           string                     `json:"sha256"`
					PayloadBase64    string                     `json:"payloadBase64"`
					OffsetBytes      int64                      `json:"offsetBytes"`
					NextOffsetBytes  int64                      `json:"nextOffsetBytes"`
					TotalSizeBytes   int64                      `json:"totalSizeBytes"`
					UploadedAtUnix   int64                      `json:"uploadedAtUnix"`
					DownloadedAtUnix int64                      `json:"downloadedAtUnix"`
					Complete         bool                       `json:"complete"`
				}
				writeJSON(w, http.StatusOK, envelope[chunkEnvelope]{Data: chunkEnvelope{
					Transfer:         content.Transfer,
					ContentType:      content.ContentType,
					SHA256:           content.SHA256,
					PayloadBase64:    base64.StdEncoding.EncodeToString(content.Payload),
					OffsetBytes:      content.OffsetBytes,
					NextOffsetBytes:  content.NextOffsetBytes,
					TotalSizeBytes:   content.TotalSizeBytes,
					UploadedAtUnix:   content.UploadedAtUnix,
					DownloadedAtUnix: content.DownloadedAtUnix,
					Complete:         content.Complete,
				}})
			default:
				writeMethodNotAllowed(w)
			}
			return
		}
		if len(parts) == 2 && parts[1] == "source" {
			if r.Method != http.MethodPut {
				writeMethodNotAllowed(w)
				return
			}
			var req RegisterFileTransferSourceRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			transfer, err := agent.RegisterFileTransferSource(transferID, req.SourcePath, req.ContentType)
			if err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, envelope[*controlclient.FileTransfer]{Data: transfer})
			return
		}
		if len(parts) == 2 && parts[1] == "local-state" {
			if r.Method != http.MethodGet {
				writeMethodNotAllowed(w)
				return
			}
			localState, err := agent.GetFileTransferLocalState(transferID)
			if err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, envelope[*FileTransferLocalState]{Data: localState})
			return
		}
		if len(parts) == 1 && r.Method == http.MethodGet {
			transfer, err := agent.GetFileTransfer(transferID)
			if err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, envelope[*controlclient.FileTransfer]{Data: transfer})
			return
		}
		if len(parts) != 1 || r.Method != http.MethodPatch {
			writeMethodNotAllowed(w)
			return
		}
		var req PatchFileTransferRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		var (
			transfer *controlclient.FileTransfer
			err      error
		)
		switch strings.ToLower(strings.TrimSpace(req.Action)) {
		case "accept":
			transfer, err = agent.AcceptFileTransfer(transferID)
		case "cancel":
			transfer, err = agent.CancelFileTransfer(transferID, req.Reason)
		case "progress":
			transfer, err = agent.UpdateFileTransferProgress(transferID, req.ProgressPercent)
		default:
			writeError(w, errors.New("unsupported file transfer action"))
			return
		}
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope[*controlclient.FileTransfer]{Data: transfer})
	})
	mux.HandleFunc("/api/v1/networks", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			networks, err := agent.ListNetworks()
			if err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, envelope[[]controlclient.Network]{Data: networks})
		case http.MethodPost:
			var req CreateNetworkRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			network, err := agent.CreateNetworkWithOptions(req.Name, req.Access, controlclient.NetworkCreateOptions{
				DeviceApprovalRequired:  req.DeviceApprovalRequired,
				RoutingPolicy:           req.RoutingPolicy,
				GroupTrafficPolicy:      req.GroupTrafficPolicy,
				NameResolutionMode:      req.NameResolutionMode,
				DNSLabel:                req.DNSLabel,
				FileTransfersEnabledSet: true,
				FileTransfersEnabled:    req.FileTransfersEnabled,
				FileTransferMaxBytes:    req.FileTransferMaxBytes,
			})
			if err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusCreated, envelope[*controlclient.Network]{Data: network})
		default:
			writeMethodNotAllowed(w)
		}
	})
	mux.HandleFunc("/api/v1/networks/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/networks/")
		parts := splitPath(path)
		if len(parts) < 2 || len(parts) > 3 {
			writeNotFound(w)
			return
		}

		networkID := parts[0]
		switch parts[1] {
		case "routing-policy":
			if len(parts) != 2 {
				writeNotFound(w)
				return
			}
			if r.Method != http.MethodPatch {
				writeMethodNotAllowed(w)
				return
			}
			var req UpdateNetworkRoutingPolicyRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			network, err := agent.UpdateNetworkRoutingPolicy(networkID, req.Policy)
			if err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, envelope[*controlclient.Network]{Data: network})
		case "group-traffic":
			if len(parts) != 2 {
				writeNotFound(w)
				return
			}
			if r.Method != http.MethodPatch {
				writeMethodNotAllowed(w)
				return
			}
			var req UpdateNetworkGroupTrafficPolicyRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			network, err := agent.UpdateNetworkGroupTrafficPolicy(networkID, req.Policy)
			if err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, envelope[*controlclient.Network]{Data: network})
		case "name-resolution":
			if len(parts) != 2 {
				writeNotFound(w)
				return
			}
			if r.Method != http.MethodPatch {
				writeMethodNotAllowed(w)
				return
			}
			var req UpdateNetworkNameResolutionRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			network, err := agent.UpdateNetworkNameResolution(networkID, req.Mode, req.DNSLabel)
			if err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, envelope[*controlclient.Network]{Data: network})
		case "file-transfer-policy":
			if len(parts) != 2 {
				writeNotFound(w)
				return
			}
			if r.Method != http.MethodPatch {
				writeMethodNotAllowed(w)
				return
			}
			var req UpdateNetworkFileTransferPolicyRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			network, err := agent.UpdateNetworkFileTransferPolicy(networkID, req.Enabled, req.MaxBytes)
			if err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, envelope[*controlclient.Network]{Data: network})
		case "device-approvals":
			if len(parts) != 3 {
				writeNotFound(w)
				return
			}
			deviceID := parts[2]
			switch r.Method {
			case http.MethodPost:
				network, err := agent.ApproveNetworkDevice(networkID, deviceID)
				if err != nil {
					writeError(w, err)
					return
				}
				writeJSON(w, http.StatusOK, envelope[*controlclient.Network]{Data: network})
			case http.MethodDelete:
				network, err := agent.RevokeNetworkDeviceApproval(networkID, deviceID)
				if err != nil {
					writeError(w, err)
					return
				}
				writeJSON(w, http.StatusOK, envelope[*controlclient.Network]{Data: network})
			default:
				writeMethodNotAllowed(w)
			}
		case "invites":
			if len(parts) != 2 {
				writeNotFound(w)
				return
			}
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w)
				return
			}
			var req CreateInviteRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			invite, err := agent.CreateInvite(networkID, req.TTLSec, req.MaxUses)
			if err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusCreated, envelope[*controlclient.Invite]{Data: invite})
		case "peers":
			if len(parts) != 2 {
				writeNotFound(w)
				return
			}
			switch r.Method {
			case http.MethodGet:
				peers, err := agent.ListPeers(networkID)
				if err != nil {
					writeError(w, err)
					return
				}
				writeJSON(w, http.StatusOK, envelope[[]controlclient.Peer]{Data: peers})
			case http.MethodPost:
				var req RegisterPeerRequest
				if !decodeJSON(w, r, &req) {
					return
				}
				peer, err := agent.RegisterPeer(networkID, req.Endpoint)
				if err != nil {
					writeError(w, err)
					return
				}
				writeJSON(w, http.StatusCreated, envelope[*controlclient.Peer]{Data: peer})
			default:
				writeMethodNotAllowed(w)
			}
		case "messages":
			if len(parts) != 2 {
				writeNotFound(w)
				return
			}
			switch r.Method {
			case http.MethodGet:
				messages, err := agent.ListMessages(networkID)
				if err != nil {
					writeError(w, err)
					return
				}
				writeJSON(w, http.StatusOK, envelope[[]controlclient.Message]{Data: messages})
			case http.MethodPost:
				var req CreateMessageRequest
				if !decodeJSON(w, r, &req) {
					return
				}
				message, err := agent.SendMessage(networkID, req.FromPeerID, req.Text)
				if err != nil {
					writeError(w, err)
					return
				}
				writeJSON(w, http.StatusCreated, envelope[*controlclient.Message]{Data: message})
			default:
				writeMethodNotAllowed(w)
			}
		case "file-transfers":
			if len(parts) != 2 {
				writeNotFound(w)
				return
			}
			switch r.Method {
			case http.MethodGet:
				transfers, err := agent.ListFileTransfers(networkID)
				if err != nil {
					writeError(w, err)
					return
				}
				writeJSON(w, http.StatusOK, envelope[[]controlclient.FileTransfer]{Data: transfers})
			case http.MethodPost:
				var req CreateFileTransferRequest
				if !decodeJSON(w, r, &req) {
					return
				}
				transfer, err := agent.CreateFileTransfer(networkID, req.FromPeerID, req.ToPeerID, req.FileName, req.SizeBytes)
				if err != nil {
					writeError(w, err)
					return
				}
				writeJSON(w, http.StatusCreated, envelope[*controlclient.FileTransfer]{Data: transfer})
			default:
				writeMethodNotAllowed(w)
			}
		case "rejoin":
			if len(parts) != 2 {
				writeNotFound(w)
				return
			}
			if r.Method != http.MethodPost {
				writeMethodNotAllowed(w)
				return
			}
			var req RejoinNetworkRequest
			if !decodeJSON(w, r, &req) {
				return
			}
			status, err := agent.RejoinNetwork(networkID, req.Endpoint)
			if err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, envelope[Status]{Data: status})
		case "tunnels":
			if len(parts) != 2 {
				writeNotFound(w)
				return
			}
			switch r.Method {
			case http.MethodGet:
				tunnels, err := agent.ListTunnels(networkID)
				if err != nil {
					writeError(w, err)
					return
				}
				writeJSON(w, http.StatusOK, envelope[[]controlclient.Tunnel]{Data: tunnels})
			case http.MethodPost:
				var req CreateTunnelRequest
				if !decodeJSON(w, r, &req) {
					return
				}
				tunnel, err := agent.CreateTunnel(networkID, req.PeerAID, req.PeerBID)
				if err != nil {
					writeError(w, err)
					return
				}
				writeJSON(w, http.StatusCreated, envelope[*controlclient.Tunnel]{Data: tunnel})
			default:
				writeMethodNotAllowed(w)
			}
		default:
			writeNotFound(w)
		}
	})

	return instrumentHandlerMetrics(registry, mux)
}

func splitPath(path string) []string {
	raw := strings.Split(strings.Trim(path, "/"), "/")
	parts := make([]string, 0, len(raw))
	for _, part := range raw {
		part = strings.TrimSpace(part)
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid json"})
		return false
	}
	return true
}

func parseInt64Query(r *http.Request, name string) (int64, error) {
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

func writeError(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
}

func writeMethodNotAllowed(w http.ResponseWriter) {
	writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
}

func writeNotFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, errorResponse{Error: "not found"})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
