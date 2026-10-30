package clientagent

import (
	"Ole/internal/controlclient"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type IPCClient struct {
	baseURL    string
	httpClient *http.Client
}

const fileTransferIPCChunkSizeBytes = 1 << 20

func NewIPCClient(baseURL string) *IPCClient {
	normalized := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if normalized == "" {
		normalized = DefaultIPCBaseURL
	}
	return &IPCClient{
		baseURL: normalized,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (c *IPCClient) GetStatus() (*Status, error) {
	var resp envelope[Status]
	if err := c.doJSON(http.MethodGet, "/api/v1/status", nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) GetDiagnosticsBundle() (*DiagnosticsBundle, error) {
	var resp envelope[DiagnosticsBundle]
	if err := c.doJSON(http.MethodGet, "/api/v1/diagnostics/bundle", nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) SetServerBaseURL(serverBaseURL string) (*Status, error) {
	var resp envelope[Status]
	if err := c.doJSON(http.MethodPut, "/api/v1/config", SetConfigRequest{ServerBaseURL: serverBaseURL}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) SetAdapterMTU(mtu int) (*Status, error) {
	var resp envelope[Status]
	if err := c.doJSON(http.MethodPut, "/api/v1/config/adapter/mtu", SetAdapterMTURequest{MTU: mtu}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) Register(email, password string) (*controlclient.User, error) {
	var resp envelope[controlclient.User]
	if err := c.doJSON(http.MethodPost, "/api/v1/users", RegisterRequest{Email: email, Password: password}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) Login(email, password string) (*Status, error) {
	var resp envelope[Status]
	if err := c.doJSON(http.MethodPost, "/api/v1/session/login", LoginRequest{Email: email, Password: password}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) Reconnect() (*Status, error) {
	var resp envelope[Status]
	if err := c.doJSON(http.MethodPost, "/api/v1/session/reconnect", nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) CheckForUpdates() (*Status, error) {
	var resp envelope[Status]
	if err := c.doJSON(http.MethodPost, "/api/v1/update/check", nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) SetUpdateChannel(channel string) (*Status, error) {
	var resp envelope[Status]
	if err := c.doJSON(http.MethodPut, "/api/v1/update/channel", SetUpdateChannelRequest{Channel: channel}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) DownloadUpdate() (*Status, error) {
	var resp envelope[Status]
	if err := c.doJSON(http.MethodPost, "/api/v1/update/download", nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) DownloadRollback() (*Status, error) {
	var resp envelope[Status]
	if err := c.doJSON(http.MethodPost, "/api/v1/update/rollback/download", nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) Logout() error {
	return c.doJSON(http.MethodDelete, "/api/v1/session", nil, nil)
}

func (c *IPCClient) ListSessions() ([]controlclient.Session, error) {
	var resp envelope[[]controlclient.Session]
	if err := c.doJSON(http.MethodGet, "/api/v1/sessions", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *IPCClient) ListDevices() ([]controlclient.Device, error) {
	var resp envelope[[]controlclient.Device]
	if err := c.doJSON(http.MethodGet, "/api/v1/devices", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *IPCClient) RevokeSession(sessionID string) (*Status, error) {
	var resp envelope[Status]
	if err := c.doJSON(http.MethodDelete, "/api/v1/sessions/"+sessionID, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) RevokeAllSessions() (*Status, error) {
	var resp envelope[Status]
	if err := c.doJSON(http.MethodDelete, "/api/v1/sessions/all", nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) ListAuditEvents(filter controlclient.AuditEventFilter) ([]controlclient.AuditEvent, error) {
	values := url.Values{}
	if strings.TrimSpace(filter.ActorUserID) != "" {
		values.Set("actorUserId", strings.TrimSpace(filter.ActorUserID))
	}
	if strings.TrimSpace(filter.Type) != "" {
		values.Set("type", strings.TrimSpace(filter.Type))
	}
	if strings.TrimSpace(filter.Query) != "" {
		values.Set("q", strings.TrimSpace(filter.Query))
	}
	if filter.FromUnix > 0 {
		values.Set("fromUnix", fmt.Sprintf("%d", filter.FromUnix))
	}
	if filter.ToUnix > 0 {
		values.Set("toUnix", fmt.Sprintf("%d", filter.ToUnix))
	}
	if filter.Limit > 0 {
		values.Set("limit", fmt.Sprintf("%d", filter.Limit))
	}
	if filter.Offset > 0 {
		values.Set("offset", fmt.Sprintf("%d", filter.Offset))
	}
	path := "/api/v1/audit-events"
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var resp envelope[[]controlclient.AuditEvent]
	if err := c.doJSON(http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *IPCClient) ListIncidentReports() ([]controlclient.IncidentReport, error) {
	var resp envelope[[]controlclient.IncidentReport]
	if err := c.doJSON(http.MethodGet, "/api/v1/incidents", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *IPCClient) ListAuditPresets() ([]AuditFilterPreset, error) {
	var resp envelope[[]AuditFilterPreset]
	if err := c.doJSON(http.MethodGet, "/api/v1/audit-presets", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *IPCClient) SaveAuditPreset(name string, filter controlclient.AuditEventFilter) ([]AuditFilterPreset, error) {
	var resp envelope[[]AuditFilterPreset]
	req := SaveAuditPresetRequest{
		Name:        strings.TrimSpace(name),
		ActorUserID: strings.TrimSpace(filter.ActorUserID),
		Type:        strings.TrimSpace(filter.Type),
		Query:       strings.TrimSpace(filter.Query),
		FromUnix:    filter.FromUnix,
		ToUnix:      filter.ToUnix,
	}
	if err := c.doJSON(http.MethodPost, "/api/v1/audit-presets", req, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *IPCClient) DeleteAuditPreset(name string) ([]AuditFilterPreset, error) {
	var resp envelope[[]AuditFilterPreset]
	path := "/api/v1/audit-presets/" + url.PathEscape(strings.TrimSpace(name))
	if err := c.doJSON(http.MethodDelete, path, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *IPCClient) ListNetworks() ([]controlclient.Network, error) {
	var resp envelope[[]controlclient.Network]
	if err := c.doJSON(http.MethodGet, "/api/v1/networks", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *IPCClient) CreateNetwork(name, access string) (*controlclient.Network, error) {
	return c.CreateNetworkWithPolicy(name, access, false)
}

func (c *IPCClient) CreateNetworkWithPolicy(name, access string, deviceApprovalRequired bool) (*controlclient.Network, error) {
	return c.CreateNetworkWithOptions(name, access, controlclient.NetworkCreateOptions{
		DeviceApprovalRequired:  deviceApprovalRequired,
		FileTransfersEnabledSet: true,
		FileTransfersEnabled:    true,
	})
}

func (c *IPCClient) CreateNetworkWithOptions(name, access string, options controlclient.NetworkCreateOptions) (*controlclient.Network, error) {
	var resp envelope[controlclient.Network]
	if err := c.doJSON(http.MethodPost, "/api/v1/networks", CreateNetworkRequest{
		Name:                   name,
		Access:                 access,
		DeviceApprovalRequired: options.DeviceApprovalRequired,
		RoutingPolicy:          options.RoutingPolicy,
		GroupTrafficPolicy:     options.GroupTrafficPolicy,
		NameResolutionMode:     options.NameResolutionMode,
		DNSLabel:               options.DNSLabel,
		FileTransfersEnabled:   !options.FileTransfersEnabledSet || options.FileTransfersEnabled,
		FileTransferMaxBytes:   options.FileTransferMaxBytes,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) UpdateNetworkRoutingPolicy(networkID, policy string) (*controlclient.Network, error) {
	var resp envelope[controlclient.Network]
	if err := c.doJSON(http.MethodPatch, "/api/v1/networks/"+networkID+"/routing-policy", UpdateNetworkRoutingPolicyRequest{
		Policy: policy,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) UpdateNetworkGroupTrafficPolicy(networkID, policy string) (*controlclient.Network, error) {
	var resp envelope[controlclient.Network]
	if err := c.doJSON(http.MethodPatch, "/api/v1/networks/"+networkID+"/group-traffic", UpdateNetworkGroupTrafficPolicyRequest{
		Policy: policy,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) UpdateNetworkNameResolution(networkID, mode, dnsLabel string) (*controlclient.Network, error) {
	var resp envelope[controlclient.Network]
	if err := c.doJSON(http.MethodPatch, "/api/v1/networks/"+networkID+"/name-resolution", UpdateNetworkNameResolutionRequest{
		Mode:     mode,
		DNSLabel: dnsLabel,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) UpdateNetworkFileTransferPolicy(networkID string, enabled bool, maxBytes int64) (*controlclient.Network, error) {
	var resp envelope[controlclient.Network]
	if err := c.doJSON(http.MethodPatch, "/api/v1/networks/"+networkID+"/file-transfer-policy", UpdateNetworkFileTransferPolicyRequest{
		Enabled:  enabled,
		MaxBytes: maxBytes,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) ApproveNetworkDevice(networkID, deviceID string) (*controlclient.Network, error) {
	var resp envelope[controlclient.Network]
	if err := c.doJSON(http.MethodPost, "/api/v1/networks/"+networkID+"/device-approvals/"+deviceID, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) RevokeNetworkDeviceApproval(networkID, deviceID string) (*controlclient.Network, error) {
	var resp envelope[controlclient.Network]
	if err := c.doJSON(http.MethodDelete, "/api/v1/networks/"+networkID+"/device-approvals/"+deviceID, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) RedeemInvite(code string) (*controlclient.Network, error) {
	var resp envelope[controlclient.Network]
	if err := c.doJSON(http.MethodPost, "/api/v1/invites/redeem", RedeemInviteRequest{Code: code}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) CreateInvite(networkID string, ttlSec, maxUses int) (*controlclient.Invite, error) {
	var resp envelope[controlclient.Invite]
	if err := c.doJSON(http.MethodPost, "/api/v1/networks/"+networkID+"/invites", CreateInviteRequest{TTLSec: ttlSec, MaxUses: maxUses}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) ListPeers(networkID string) ([]controlclient.Peer, error) {
	var resp envelope[[]controlclient.Peer]
	if err := c.doJSON(http.MethodGet, "/api/v1/networks/"+networkID+"/peers", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *IPCClient) ListMessages(networkID string) ([]controlclient.Message, error) {
	var resp envelope[[]controlclient.Message]
	if err := c.doJSON(http.MethodGet, "/api/v1/networks/"+networkID+"/messages", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *IPCClient) SendMessage(networkID, fromPeerID, text string) (*controlclient.Message, error) {
	var resp envelope[controlclient.Message]
	if err := c.doJSON(http.MethodPost, "/api/v1/networks/"+networkID+"/messages", CreateMessageRequest{
		FromPeerID: fromPeerID,
		Text:       text,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) ListFileTransfers(networkID string) ([]controlclient.FileTransfer, error) {
	var resp envelope[[]controlclient.FileTransfer]
	if err := c.doJSON(http.MethodGet, "/api/v1/networks/"+networkID+"/file-transfers", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *IPCClient) CreateFileTransfer(networkID, fromPeerID, toPeerID, fileName string, sizeBytes int64) (*controlclient.FileTransfer, error) {
	var resp envelope[controlclient.FileTransfer]
	if err := c.doJSON(http.MethodPost, "/api/v1/networks/"+networkID+"/file-transfers", CreateFileTransferRequest{
		FromPeerID: fromPeerID,
		ToPeerID:   toPeerID,
		FileName:   fileName,
		SizeBytes:  sizeBytes,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) GetFileTransfer(transferID string) (*controlclient.FileTransfer, error) {
	var resp envelope[controlclient.FileTransfer]
	if err := c.doJSON(http.MethodGet, "/api/v1/file-transfers/"+transferID, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) GetFileTransferLocalState(transferID string) (*FileTransferLocalState, error) {
	var resp envelope[FileTransferLocalState]
	if err := c.doJSON(http.MethodGet, "/api/v1/file-transfers/"+transferID+"/local-state", nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) AcceptFileTransfer(transferID string) (*controlclient.FileTransfer, error) {
	return c.patchFileTransfer(transferID, PatchFileTransferRequest{Action: "accept"})
}

func (c *IPCClient) CancelFileTransfer(transferID, reason string) (*controlclient.FileTransfer, error) {
	return c.patchFileTransfer(transferID, PatchFileTransferRequest{
		Action: "cancel",
		Reason: reason,
	})
}

func (c *IPCClient) UpdateFileTransferProgress(transferID string, progressPercent int) (*controlclient.FileTransfer, error) {
	return c.patchFileTransfer(transferID, PatchFileTransferRequest{
		Action:          "progress",
		ProgressPercent: progressPercent,
	})
}

func (c *IPCClient) UploadFileTransferContent(transferID, contentType string, payload []byte) (*controlclient.FileTransfer, error) {
	transfer, err := c.GetFileTransfer(transferID)
	if err != nil {
		return nil, err
	}
	offset := transfer.PayloadUploadedBytes
	for offset < int64(len(payload)) {
		end := offset + fileTransferIPCChunkSizeBytes
		if end > int64(len(payload)) {
			end = int64(len(payload))
		}
		transfer, err = c.UploadFileTransferContentChunk(transferID, contentType, offset, payload[int(offset):int(end)])
		if err != nil {
			return nil, err
		}
		offset = transfer.PayloadUploadedBytes
	}
	return transfer, nil
}

func (c *IPCClient) UploadFileTransferContentChunk(transferID, contentType string, offsetBytes int64, payload []byte) (*controlclient.FileTransfer, error) {
	var resp envelope[controlclient.FileTransfer]
	if err := c.doJSON(http.MethodPut, "/api/v1/file-transfers/"+transferID+"/content-chunks", UploadFileTransferContentChunkRequest{
		ContentType:   contentType,
		PayloadBase64: base64.StdEncoding.EncodeToString(payload),
		OffsetBytes:   offsetBytes,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) RegisterFileTransferSource(transferID, sourcePath, contentType string) (*controlclient.FileTransfer, error) {
	var resp envelope[controlclient.FileTransfer]
	if err := c.doJSON(http.MethodPut, "/api/v1/file-transfers/"+transferID+"/source", RegisterFileTransferSourceRequest{
		SourcePath:  sourcePath,
		ContentType: contentType,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) DownloadFileTransferContent(transferID string) (*controlclient.FileTransferContent, error) {
	var (
		offset int64
		buffer []byte
		last   *controlclient.FileTransferContentChunk
	)
	for {
		chunk, err := c.DownloadFileTransferContentChunk(transferID, offset, fileTransferIPCChunkSizeBytes)
		if err != nil {
			return nil, err
		}
		buffer = append(buffer, chunk.Payload...)
		offset = chunk.NextOffsetBytes
		last = chunk
		if chunk.Complete {
			break
		}
	}
	if last == nil {
		return nil, errors.New("file transfer payload chunk response is empty")
	}
	return &controlclient.FileTransferContent{
		Transfer:         last.Transfer,
		ContentType:      last.ContentType,
		SHA256:           last.SHA256,
		Payload:          buffer,
		SizeBytes:        last.TotalSizeBytes,
		UploadedAtUnix:   last.UploadedAtUnix,
		DownloadedAtUnix: last.DownloadedAtUnix,
	}, nil
}

func (c *IPCClient) DownloadFileTransferContentChunk(transferID string, offsetBytes, limitBytes int64) (*controlclient.FileTransferContentChunk, error) {
	values := url.Values{}
	if offsetBytes > 0 {
		values.Set("offsetBytes", fmt.Sprintf("%d", offsetBytes))
	}
	if limitBytes > 0 {
		values.Set("limitBytes", fmt.Sprintf("%d", limitBytes))
	}
	path := "/api/v1/file-transfers/" + transferID + "/content-chunks"
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var resp envelope[struct {
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
	}]
	if err := c.doJSON(http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(resp.Data.PayloadBase64))
	if err != nil {
		return nil, err
	}
	return &controlclient.FileTransferContentChunk{
		Transfer:         resp.Data.Transfer,
		ContentType:      resp.Data.ContentType,
		SHA256:           resp.Data.SHA256,
		Payload:          payload,
		OffsetBytes:      resp.Data.OffsetBytes,
		NextOffsetBytes:  resp.Data.NextOffsetBytes,
		TotalSizeBytes:   resp.Data.TotalSizeBytes,
		UploadedAtUnix:   resp.Data.UploadedAtUnix,
		DownloadedAtUnix: resp.Data.DownloadedAtUnix,
		Complete:         resp.Data.Complete,
	}, nil
}

func (c *IPCClient) RegisterPeer(networkID, endpoint string) (*controlclient.Peer, error) {
	var resp envelope[controlclient.Peer]
	if err := c.doJSON(http.MethodPost, "/api/v1/networks/"+networkID+"/peers", RegisterPeerRequest{Endpoint: endpoint}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) RejoinNetwork(networkID, endpoint string) (*Status, error) {
	var resp envelope[Status]
	if err := c.doJSON(http.MethodPost, "/api/v1/networks/"+networkID+"/rejoin", RejoinNetworkRequest{Endpoint: endpoint}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) ListTunnels(networkID string) ([]controlclient.Tunnel, error) {
	var resp envelope[[]controlclient.Tunnel]
	if err := c.doJSON(http.MethodGet, "/api/v1/networks/"+networkID+"/tunnels", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *IPCClient) CreateTunnel(networkID, peerAID, peerBID string) (*controlclient.Tunnel, error) {
	var resp envelope[controlclient.Tunnel]
	if err := c.doJSON(http.MethodPost, "/api/v1/networks/"+networkID+"/tunnels", CreateTunnelRequest{PeerAID: peerAID, PeerBID: peerBID}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) patchFileTransfer(transferID string, req PatchFileTransferRequest) (*controlclient.FileTransfer, error) {
	var resp envelope[controlclient.FileTransfer]
	if err := c.doJSON(http.MethodPatch, "/api/v1/file-transfers/"+transferID, req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *IPCClient) doJSON(method, path string, payload any, dst any) error {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		var apiErr errorResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiErr); err == nil && apiErr.Error != "" {
			return errors.New(apiErr.Error)
		}
		return fmt.Errorf("request failed with status %d", resp.StatusCode)
	}

	if dst == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}
