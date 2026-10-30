package controlclient

import (
	"Ole/internal/tracectx"
	"Ole/internal/versioninfo"
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

type Client struct {
	baseURL       string
	httpClient    *http.Client
	accessToken   string
	clientVersion string
	observer      func(RequestTrace)
}

const fileTransferChunkSizeBytes = 1 << 20

type RequestTrace struct {
	Method        string
	Path          string
	TraceID       string
	SpanID        string
	ServerSpanID  string
	ResponseTrace string
	StatusCode    int
	DurationMs    int64
	Error         string
}

func New(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		clientVersion: versioninfo.DefaultClientVersion,
	}
}

func (c *Client) SetBaseURL(baseURL string) {
	c.baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
}

func (c *Client) BaseURL() string {
	return c.baseURL
}

func (c *Client) SetAccessToken(accessToken string) {
	c.accessToken = strings.TrimSpace(accessToken)
}

func (c *Client) AccessToken() string {
	return c.accessToken
}

func (c *Client) ClearAccessToken() {
	c.accessToken = ""
}

func (c *Client) ClientVersion() string {
	return c.clientVersion
}

func (c *Client) SetRequestObserver(observer func(RequestTrace)) {
	c.observer = observer
}

type ServerInfo struct {
	Status  string                      `json:"status"`
	Time    int64                       `json:"time"`
	Version *versioninfo.ServerMetadata `json:"version"`
}

func (c *Client) GetServerInfo() (*ServerInfo, error) {
	var resp ServerInfo
	if err := c.doJSON(http.MethodGet, "/health", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) CheckCompatibility() (versioninfo.Compatibility, error) {
	info, err := c.GetServerInfo()
	if err != nil {
		return versioninfo.Compatibility{}, err
	}
	metadata := versioninfo.ServerMetadata{}
	if info != nil && info.Version != nil {
		metadata = *info.Version
	}
	return versioninfo.Evaluate(c.clientVersion, metadata), nil
}

type apiEnvelope[T any] struct {
	Data T `json:"data"`
}

type apiListEnvelope[T any] struct {
	Data []T `json:"data"`
}

type apiError struct {
	Error string `json:"error"`
}

type User struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Status string `json:"status"`
}

type Device struct {
	ID            string `json:"id"`
	UserID        string `json:"userId"`
	Name          string `json:"name"`
	PublicKey     string `json:"publicKey"`
	Fingerprint   string `json:"fingerprint"`
	Status        string `json:"status"`
	CreatedAtUnix int64  `json:"createdAtUnix"`
	RevokedAtUnix int64  `json:"revokedAtUnix"`
}

type Session struct {
	ID                  string `json:"id"`
	UserID              string `json:"userId"`
	FamilyID            string `json:"familyId"`
	AccessToken         string `json:"accessToken"`
	RefreshToken        string `json:"refreshToken"`
	DeviceName          string `json:"deviceName"`
	IP                  string `json:"ip"`
	UserAgent           string `json:"userAgent"`
	LastUsedAtUnix      int64  `json:"lastUsedAtUnix"`
	ExpiresAtUnix       int64  `json:"expiresAtUnix"`
	RevokedAtUnix       int64  `json:"revokedAtUnix"`
	ReuseDetectedAtUnix int64  `json:"reuseDetectedAtUnix"`
}

type Network struct {
	ID                     string            `json:"id"`
	Name                   string            `json:"name"`
	OwnerID                string            `json:"ownerId"`
	Access                 string            `json:"access"`
	DeviceApprovalRequired bool              `json:"deviceApprovalRequired"`
	RoutingPolicy          string            `json:"routingPolicy"`
	GroupTrafficPolicy     string            `json:"groupTrafficPolicy"`
	NameResolutionMode     string            `json:"nameResolutionMode"`
	DNSLabel               string            `json:"dnsLabel"`
	FileTransfersEnabled   bool              `json:"fileTransfersEnabled"`
	FileTransferMaxBytes   int64             `json:"fileTransferMaxBytes"`
	ApprovedDeviceIDs      []string          `json:"approvedDeviceIds"`
	Members                []string          `json:"members"`
	MemberRoles            map[string]string `json:"memberRoles"`
}

type NetworkCreateOptions struct {
	DeviceApprovalRequired  bool
	RoutingPolicy           string
	GroupTrafficPolicy      string
	NameResolutionMode      string
	DNSLabel                string
	FileTransfersEnabledSet bool
	FileTransfersEnabled    bool
	FileTransferMaxBytes    int64
}

type Invite struct {
	Code          string `json:"code"`
	NetworkID     string `json:"networkId"`
	ExpiresAtUnix int64  `json:"expiresAtUnix"`
	MaxUses       int    `json:"maxUses"`
	Uses          int    `json:"uses"`
}

type Peer struct {
	ID                 string `json:"id"`
	UserID             string `json:"userId"`
	DeviceID           string `json:"deviceId"`
	NetworkID          string `json:"networkId"`
	OverlayCIDR        string `json:"overlayCidr,omitempty"`
	VirtualIP          string `json:"virtualIp"`
	Endpoint           string `json:"endpoint"`
	Status             string `json:"status"`
	Reachability       string `json:"reachability"`
	ConnectionState    string `json:"connectionState"`
	LastSeenUnix       int64  `json:"lastSeenUnix"`
	LastSignaledAtUnix int64  `json:"lastSignaledAtUnix"`
}

type SignalCandidate struct {
	ID            string `json:"id"`
	PeerID        string `json:"peerId"`
	NetworkID     string `json:"networkId"`
	Type          string `json:"type"`
	Protocol      string `json:"protocol"`
	Address       string `json:"address"`
	Preference    int    `json:"preference"`
	Reachable     bool   `json:"reachable"`
	CreatedAtUnix int64  `json:"createdAtUnix"`
	ExpiresAtUnix int64  `json:"expiresAtUnix"`
}

type Tunnel struct {
	ID            string `json:"id"`
	NetworkID     string `json:"networkId"`
	PeerAID       string `json:"peerAId"`
	PeerBID       string `json:"peerBId"`
	Mode          string `json:"mode"`
	State         string `json:"state"`
	CreatedAtUnix int64  `json:"createdAtUnix"`
}

type Message struct {
	ID         string `json:"id"`
	NetworkID  string `json:"networkId"`
	FromPeerID string `json:"fromPeerId"`
	Text       string `json:"text"`
	Preview    string `json:"preview"`
	SentAtUnix int64  `json:"sentAtUnix"`
}

type FileTransfer struct {
	ID                   string `json:"id"`
	NetworkID            string `json:"networkId"`
	FromPeerID           string `json:"fromPeerId"`
	FromUserID           string `json:"fromUserId"`
	ToPeerID             string `json:"toPeerId"`
	ToUserID             string `json:"toUserId"`
	FileName             string `json:"fileName"`
	SizeBytes            int64  `json:"sizeBytes"`
	Status               string `json:"status"`
	ProgressPercent      int    `json:"progressPercent"`
	CancelReason         string `json:"cancelReason"`
	ContentType          string `json:"contentType"`
	PayloadSHA256        string `json:"payloadSha256"`
	PayloadReady         bool   `json:"payloadReady"`
	PayloadUploadedBytes int64  `json:"payloadUploadedBytes"`
	UploadedAtUnix       int64  `json:"uploadedAtUnix"`
	DownloadedAtUnix     int64  `json:"downloadedAtUnix"`
}

type FileTransferContent struct {
	Transfer         FileTransfer `json:"transfer"`
	ContentType      string       `json:"contentType"`
	SHA256           string       `json:"sha256"`
	Payload          []byte       `json:"payload"`
	SizeBytes        int64        `json:"sizeBytes"`
	UploadedAtUnix   int64        `json:"uploadedAtUnix"`
	DownloadedAtUnix int64        `json:"downloadedAtUnix"`
}

type FileTransferContentChunk struct {
	Transfer         FileTransfer `json:"transfer"`
	ContentType      string       `json:"contentType"`
	SHA256           string       `json:"sha256"`
	Payload          []byte       `json:"payload"`
	OffsetBytes      int64        `json:"offsetBytes"`
	NextOffsetBytes  int64        `json:"nextOffsetBytes"`
	TotalSizeBytes   int64        `json:"totalSizeBytes"`
	UploadedAtUnix   int64        `json:"uploadedAtUnix"`
	DownloadedAtUnix int64        `json:"downloadedAtUnix"`
	Complete         bool         `json:"complete"`
}

type AuditEvent struct {
	ID            string `json:"id"`
	ActorUserID   string `json:"actorUserId"`
	NetworkID     string `json:"networkId,omitempty"`
	Type          string `json:"type"`
	Details       string `json:"details"`
	CreatedAtUnix int64  `json:"createdAtUnix"`
}

type IncidentReport struct {
	ID                string `json:"id"`
	Category          string `json:"category"`
	Severity          string `json:"severity"`
	Status            string `json:"status"`
	Source            string `json:"source"`
	Summary           string `json:"summary"`
	Detail            string `json:"detail"`
	RecommendedAction string `json:"recommendedAction"`
	EventCount        int    `json:"eventCount"`
	DetectedAtUnix    int64  `json:"detectedAtUnix"`
	UpdatedAtUnix     int64  `json:"updatedAtUnix"`
}

type AuditEventFilter struct {
	ActorUserID string
	Type        string
	Query       string
	FromUnix    int64
	ToUnix      int64
	Limit       int
	Offset      int
}

func (c *Client) Register(email, password string) (*User, error) {
	var resp apiEnvelope[User]
	if err := c.doJSON(http.MethodPost, "/api/v1/users", map[string]string{
		"email":    email,
		"password": password,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) Login(email, password string) (*Session, error) {
	var resp apiEnvelope[Session]
	if err := c.doJSON(http.MethodPost, "/api/v1/sessions", map[string]string{
		"email":      email,
		"password":   password,
		"deviceName": "Ole Desktop",
	}, &resp); err != nil {
		return nil, err
	}
	c.accessToken = resp.Data.AccessToken
	return &resp.Data, nil
}

func (c *Client) RefreshSession(refreshToken, deviceName string) (*Session, error) {
	var resp apiEnvelope[Session]
	if err := c.doJSON(http.MethodPost, "/api/v1/sessions/refresh", map[string]string{
		"refreshToken": refreshToken,
		"deviceName":   deviceName,
	}, &resp); err != nil {
		return nil, err
	}
	c.accessToken = resp.Data.AccessToken
	return &resp.Data, nil
}

func (c *Client) Logout(accessToken string) error {
	values := url.Values{}
	values.Set("accessToken", accessToken)
	err := c.doJSON(http.MethodDelete, "/api/v1/sessions?"+values.Encode(), nil, nil)
	c.accessToken = ""
	return err
}

func (c *Client) GetUser(userID string) (*User, error) {
	var resp apiEnvelope[User]
	if err := c.doJSON(http.MethodGet, "/api/v1/users/"+userID, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) ListSessions() ([]Session, error) {
	var resp apiListEnvelope[Session]
	if err := c.doJSON(http.MethodGet, "/api/v1/sessions", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *Client) ListIncidentReports() ([]IncidentReport, error) {
	var resp apiListEnvelope[IncidentReport]
	if err := c.doJSON(http.MethodGet, "/api/v1/incidents", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *Client) RevokeSession(sessionID string) error {
	return c.doJSON(http.MethodDelete, "/api/v1/sessions/"+sessionID, nil, nil)
}

func (c *Client) RevokeAllSessions() error {
	return c.doJSON(http.MethodDelete, "/api/v1/sessions/all", nil, nil)
}

func (c *Client) ListDevices() ([]Device, error) {
	var resp apiListEnvelope[Device]
	if err := c.doJSON(http.MethodGet, "/api/v1/devices", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *Client) CreateDevice(name, publicKey string) (*Device, error) {
	var resp apiEnvelope[Device]
	if err := c.doJSON(http.MethodPost, "/api/v1/devices", map[string]string{
		"name":      name,
		"publicKey": publicKey,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) ListNetworks() ([]Network, error) {
	var resp apiListEnvelope[Network]
	if err := c.doJSON(http.MethodGet, "/api/v1/networks", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *Client) CreateNetwork(ownerID, name, access string) (*Network, error) {
	return c.CreateNetworkWithPolicy(ownerID, name, access, false)
}

func (c *Client) CreateNetworkWithPolicy(ownerID, name, access string, deviceApprovalRequired bool) (*Network, error) {
	return c.CreateNetworkWithOptions(ownerID, name, access, NetworkCreateOptions{
		DeviceApprovalRequired:  deviceApprovalRequired,
		FileTransfersEnabledSet: true,
		FileTransfersEnabled:    true,
	})
}

func (c *Client) CreateNetworkWithOptions(ownerID, name, access string, options NetworkCreateOptions) (*Network, error) {
	payload := map[string]any{
		"ownerId":                ownerID,
		"name":                   name,
		"access":                 access,
		"deviceApprovalRequired": options.DeviceApprovalRequired,
		"routingPolicy":          options.RoutingPolicy,
		"groupTrafficPolicy":     options.GroupTrafficPolicy,
		"nameResolutionMode":     options.NameResolutionMode,
		"dnsLabel":               options.DNSLabel,
	}
	if options.FileTransfersEnabledSet {
		payload["fileTransfersEnabled"] = options.FileTransfersEnabled
	}
	if options.FileTransferMaxBytes > 0 {
		payload["fileTransferMaxBytes"] = options.FileTransferMaxBytes
	}
	var resp apiEnvelope[Network]
	if err := c.doJSON(http.MethodPost, "/api/v1/networks", payload, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdateNetworkRoutingPolicy(networkID, policy string) (*Network, error) {
	var resp apiEnvelope[Network]
	if err := c.doJSON(http.MethodPatch, "/api/v1/networks/"+networkID+"/routing-policy", map[string]any{
		"policy": policy,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdateNetworkGroupTrafficPolicy(networkID, policy string) (*Network, error) {
	var resp apiEnvelope[Network]
	if err := c.doJSON(http.MethodPatch, "/api/v1/networks/"+networkID+"/group-traffic", map[string]any{
		"policy": policy,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdateNetworkNameResolution(networkID, mode, dnsLabel string) (*Network, error) {
	var resp apiEnvelope[Network]
	if err := c.doJSON(http.MethodPatch, "/api/v1/networks/"+networkID+"/name-resolution", map[string]any{
		"mode":     mode,
		"dnsLabel": dnsLabel,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdateNetworkFileTransferPolicy(networkID string, enabled bool, maxBytes int64) (*Network, error) {
	var resp apiEnvelope[Network]
	if err := c.doJSON(http.MethodPatch, "/api/v1/networks/"+networkID+"/file-transfer-policy", map[string]any{
		"enabled":  enabled,
		"maxBytes": maxBytes,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) ApproveNetworkDevice(networkID, deviceID string) (*Network, error) {
	var resp apiEnvelope[Network]
	if err := c.doJSON(http.MethodPost, "/api/v1/networks/"+networkID+"/device-approvals/"+deviceID, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) RevokeNetworkDeviceApproval(networkID, deviceID string) (*Network, error) {
	var resp apiEnvelope[Network]
	if err := c.doJSON(http.MethodDelete, "/api/v1/networks/"+networkID+"/device-approvals/"+deviceID, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) CreateInvite(networkID, ownerID string, ttlSec, maxUses int) (*Invite, error) {
	var resp apiEnvelope[Invite]
	if err := c.doJSON(http.MethodPost, "/api/v1/networks/"+networkID+"/invites", map[string]any{
		"ownerId": ownerID,
		"ttlSec":  ttlSec,
		"maxUses": maxUses,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) RedeemInvite(code, userID string) (*Network, error) {
	var resp apiEnvelope[Network]
	if err := c.doJSON(http.MethodPost, "/api/v1/invites/"+code+"/redemptions", map[string]string{
		"userId": userID,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) ListPeers(networkID string) ([]Peer, error) {
	var resp apiListEnvelope[Peer]
	if err := c.doJSON(http.MethodGet, "/api/v1/networks/"+networkID+"/peers", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *Client) RegisterPeer(networkID, userID, deviceID, endpoint string) (*Peer, error) {
	var resp apiEnvelope[Peer]
	if err := c.doJSON(http.MethodPost, "/api/v1/networks/"+networkID+"/peers", map[string]string{
		"deviceId": deviceID,
		"userId":   userID,
		"endpoint": endpoint,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) HeartbeatPeer(peerID, endpoint string) (*Peer, error) {
	var resp apiEnvelope[Peer]
	if err := c.doJSON(http.MethodPatch, "/api/v1/peers/"+peerID, map[string]string{
		"endpoint": endpoint,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdatePeerSignaling(peerID, reachability, connectionState string) (*Peer, error) {
	var payload = map[string]string{}
	if strings.TrimSpace(reachability) != "" {
		payload["reachability"] = reachability
	}
	if strings.TrimSpace(connectionState) != "" {
		payload["connectionState"] = connectionState
	}
	var resp apiEnvelope[Peer]
	if err := c.doJSON(http.MethodPatch, "/api/v1/peers/"+peerID, payload, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) DisconnectPeer(peerID string) (*Peer, error) {
	var resp apiEnvelope[Peer]
	if err := c.doJSON(http.MethodPatch, "/api/v1/peers/"+peerID, map[string]string{
		"status": "OFFLINE",
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) PublishCandidate(peerID, candidateType, protocol, address string, preference int, reachable bool, ttlSec int64) (*SignalCandidate, error) {
	var resp apiEnvelope[SignalCandidate]
	if err := c.doJSON(http.MethodPost, "/api/v1/peers/"+peerID+"/candidates", map[string]any{
		"type":       candidateType,
		"protocol":   protocol,
		"address":    address,
		"preference": preference,
		"reachable":  reachable,
		"ttlSec":     ttlSec,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) ListCandidates(peerID string) ([]SignalCandidate, error) {
	var resp apiListEnvelope[SignalCandidate]
	if err := c.doJSON(http.MethodGet, "/api/v1/peers/"+peerID+"/candidates", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *Client) ListTunnels(networkID string) ([]Tunnel, error) {
	var resp apiListEnvelope[Tunnel]
	if err := c.doJSON(http.MethodGet, "/api/v1/networks/"+networkID+"/tunnels", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *Client) ListMessages(networkID string) ([]Message, error) {
	var resp apiListEnvelope[Message]
	if err := c.doJSON(http.MethodGet, "/api/v1/networks/"+networkID+"/messages", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *Client) SendMessage(networkID, fromPeerID, text string) (*Message, error) {
	var resp apiEnvelope[Message]
	if err := c.doJSON(http.MethodPost, "/api/v1/networks/"+networkID+"/messages", map[string]string{
		"fromPeerId": fromPeerID,
		"text":       text,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) ListFileTransfers(networkID string) ([]FileTransfer, error) {
	var resp apiListEnvelope[FileTransfer]
	if err := c.doJSON(http.MethodGet, "/api/v1/networks/"+networkID+"/file-transfers", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *Client) CreateFileTransfer(networkID, fromPeerID, toPeerID, fileName string, sizeBytes int64) (*FileTransfer, error) {
	var resp apiEnvelope[FileTransfer]
	if err := c.doJSON(http.MethodPost, "/api/v1/networks/"+networkID+"/file-transfers", map[string]any{
		"fromPeerId": fromPeerID,
		"toPeerId":   toPeerID,
		"fileName":   fileName,
		"sizeBytes":  sizeBytes,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) GetFileTransfer(transferID string) (*FileTransfer, error) {
	var resp apiEnvelope[FileTransfer]
	if err := c.doJSON(http.MethodGet, "/api/v1/file-transfers/"+transferID, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UploadFileTransferContent(transferID, contentType string, payload []byte) (*FileTransfer, error) {
	transfer, err := c.GetFileTransfer(transferID)
	if err != nil {
		return nil, err
	}
	offset := transfer.PayloadUploadedBytes
	for offset < int64(len(payload)) {
		end := offset + fileTransferChunkSizeBytes
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

func (c *Client) UploadFileTransferContentChunk(transferID, contentType string, offsetBytes int64, payload []byte) (*FileTransfer, error) {
	var resp apiEnvelope[FileTransfer]
	if err := c.doJSON(http.MethodPut, "/api/v1/file-transfers/"+transferID+"/content-chunks", map[string]any{
		"contentType":   contentType,
		"payloadBase64": base64.StdEncoding.EncodeToString(payload),
		"offsetBytes":   offsetBytes,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) DownloadFileTransferContent(transferID string) (*FileTransferContent, error) {
	var (
		offset int64
		buffer []byte
		last   *FileTransferContentChunk
	)
	for {
		chunk, err := c.DownloadFileTransferContentChunk(transferID, offset, fileTransferChunkSizeBytes)
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
	return &FileTransferContent{
		Transfer:         last.Transfer,
		ContentType:      last.ContentType,
		SHA256:           last.SHA256,
		Payload:          buffer,
		SizeBytes:        last.TotalSizeBytes,
		UploadedAtUnix:   last.UploadedAtUnix,
		DownloadedAtUnix: last.DownloadedAtUnix,
	}, nil
}

func (c *Client) DownloadFileTransferContentChunk(transferID string, offsetBytes, limitBytes int64) (*FileTransferContentChunk, error) {
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
	var resp apiEnvelope[struct {
		Transfer         FileTransfer `json:"transfer"`
		ContentType      string       `json:"contentType"`
		SHA256           string       `json:"sha256"`
		PayloadBase64    string       `json:"payloadBase64"`
		OffsetBytes      int64        `json:"offsetBytes"`
		NextOffsetBytes  int64        `json:"nextOffsetBytes"`
		TotalSizeBytes   int64        `json:"totalSizeBytes"`
		UploadedAtUnix   int64        `json:"uploadedAtUnix"`
		DownloadedAtUnix int64        `json:"downloadedAtUnix"`
		Complete         bool         `json:"complete"`
	}]
	if err := c.doJSON(http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(resp.Data.PayloadBase64))
	if err != nil {
		return nil, err
	}
	return &FileTransferContentChunk{
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

func (c *Client) AcceptFileTransfer(transferID string) (*FileTransfer, error) {
	return c.patchFileTransfer(transferID, map[string]any{"action": "accept"})
}

func (c *Client) CancelFileTransfer(transferID, reason string) (*FileTransfer, error) {
	return c.patchFileTransfer(transferID, map[string]any{
		"action": "cancel",
		"reason": reason,
	})
}

func (c *Client) UpdateFileTransferProgress(transferID string, progressPercent int) (*FileTransfer, error) {
	return c.patchFileTransfer(transferID, map[string]any{
		"action":          "progress",
		"progressPercent": progressPercent,
	})
}

func (c *Client) CreateTunnel(networkID, peerAID, peerBID, mode string) (*Tunnel, error) {
	var resp apiEnvelope[Tunnel]
	payload := map[string]string{
		"peerAId": peerAID,
		"peerBId": peerBID,
	}
	if strings.TrimSpace(mode) != "" {
		payload["mode"] = mode
	}
	if err := c.doJSON(http.MethodPost, "/api/v1/networks/"+networkID+"/tunnels", payload, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdateTunnelState(tunnelID, state string) (*Tunnel, error) {
	var resp apiEnvelope[Tunnel]
	if err := c.doJSON(http.MethodPatch, "/api/v1/tunnels/"+tunnelID, map[string]string{
		"state": state,
	}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) ListAuditEvents(filter AuditEventFilter) ([]AuditEvent, error) {
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
	var resp apiListEnvelope[AuditEvent]
	if err := c.doJSON(http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *Client) patchFileTransfer(transferID string, payload map[string]any) (*FileTransfer, error) {
	var resp apiEnvelope[FileTransfer]
	if err := c.doJSON(http.MethodPatch, "/api/v1/file-transfers/"+transferID, payload, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) doJSON(method, path string, payload any, dst any) error {
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
	trace := tracectx.StartClientTrace()
	tracectx.ApplyRequestHeaders(req.Header, trace)
	if strings.TrimSpace(c.clientVersion) != "" {
		req.Header.Set(versioninfo.HeaderClientVersion, c.clientVersion)
		req.Header.Set("User-Agent", "ole-client/"+c.clientVersion)
	}
	if c.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}

	startedAt := time.Now()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.observeTrace(RequestTrace{
			Method:     method,
			Path:       path,
			TraceID:    trace.TraceID,
			SpanID:     trace.SpanID,
			DurationMs: time.Since(startedAt).Milliseconds(),
			Error:      err.Error(),
		})
		return err
	}
	defer resp.Body.Close()
	responseTrace := strings.TrimSpace(resp.Header.Get(tracectx.HeaderTraceID))
	serverSpanID := strings.TrimSpace(resp.Header.Get(tracectx.HeaderSpanID))

	if resp.StatusCode >= http.StatusBadRequest {
		var apiErr apiError
		if err := json.NewDecoder(resp.Body).Decode(&apiErr); err == nil && apiErr.Error != "" {
			c.observeTrace(RequestTrace{
				Method:        method,
				Path:          path,
				TraceID:       trace.TraceID,
				SpanID:        trace.SpanID,
				ServerSpanID:  serverSpanID,
				ResponseTrace: responseTrace,
				StatusCode:    resp.StatusCode,
				DurationMs:    time.Since(startedAt).Milliseconds(),
				Error:         apiErr.Error,
			})
			return errors.New(apiErr.Error)
		}
		err := fmt.Errorf("request failed with status %d", resp.StatusCode)
		c.observeTrace(RequestTrace{
			Method:        method,
			Path:          path,
			TraceID:       trace.TraceID,
			SpanID:        trace.SpanID,
			ServerSpanID:  serverSpanID,
			ResponseTrace: responseTrace,
			StatusCode:    resp.StatusCode,
			DurationMs:    time.Since(startedAt).Milliseconds(),
			Error:         err.Error(),
		})
		return err
	}

	if dst == nil || resp.StatusCode == http.StatusNoContent {
		c.observeTrace(RequestTrace{
			Method:        method,
			Path:          path,
			TraceID:       trace.TraceID,
			SpanID:        trace.SpanID,
			ServerSpanID:  serverSpanID,
			ResponseTrace: responseTrace,
			StatusCode:    resp.StatusCode,
			DurationMs:    time.Since(startedAt).Milliseconds(),
		})
		return nil
	}

	err = json.NewDecoder(resp.Body).Decode(dst)
	traceLog := RequestTrace{
		Method:        method,
		Path:          path,
		TraceID:       trace.TraceID,
		SpanID:        trace.SpanID,
		ServerSpanID:  serverSpanID,
		ResponseTrace: responseTrace,
		StatusCode:    resp.StatusCode,
		DurationMs:    time.Since(startedAt).Milliseconds(),
	}
	if err != nil {
		traceLog.Error = err.Error()
	}
	c.observeTrace(traceLog)
	return err
}

func (c *Client) observeTrace(trace RequestTrace) {
	if c == nil || c.observer == nil {
		return
	}
	c.observer(trace)
}
