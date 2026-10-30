package httpapi

import "Ole/internal/domain"

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type updateUserPasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

type createDeviceRequest struct {
	UserID    string `json:"userId"`
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

type patchDeviceRequest struct {
	Name   *string `json:"name"`
	Status *string `json:"status"`
}

type createSessionRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	DeviceName string `json:"deviceName"`
}

type refreshSessionRequest struct {
	RefreshToken string `json:"refreshToken"`
	DeviceName   string `json:"deviceName"`
}

type createNetworkRequest struct {
	OwnerID                string               `json:"ownerId"`
	Name                   string               `json:"name"`
	Access                 domain.NetworkAccess `json:"access"`
	DeviceApprovalRequired bool                 `json:"deviceApprovalRequired"`
	RoutingPolicy          string               `json:"routingPolicy"`
	GroupTrafficPolicy     string               `json:"groupTrafficPolicy"`
	NameResolutionMode     string               `json:"nameResolutionMode"`
	DNSLabel               string               `json:"dnsLabel"`
	FileTransfersEnabled   *bool                `json:"fileTransfersEnabled"`
	FileTransferMaxBytes   int64                `json:"fileTransferMaxBytes"`
}

type updateNetworkRoutingPolicyRequest struct {
	Policy string `json:"policy"`
}

type updateNetworkGroupTrafficPolicyRequest struct {
	Policy string `json:"policy"`
}

type updateNetworkNameResolutionRequest struct {
	Mode     string `json:"mode"`
	DNSLabel string `json:"dnsLabel"`
}

type updateNetworkFileTransferPolicyRequest struct {
	Enabled  bool  `json:"enabled"`
	MaxBytes int64 `json:"maxBytes"`
}

type addNetworkMemberRequest struct {
	OwnerID  string `json:"ownerId"`
	MemberID string `json:"memberId"`
	Role     string `json:"role"`
}

type updateNetworkMemberRoleRequest struct {
	Role string `json:"role"`
}

type createInviteRequest struct {
	OwnerID string `json:"ownerId"`
	TTLSec  int64  `json:"ttlSec"`
	MaxUses int    `json:"maxUses"`
}

type redeemInviteRequest struct {
	UserID string `json:"userId"`
}

type createPeerRequest struct {
	DeviceID string `json:"deviceId"`
	UserID   string `json:"userId"`
	Endpoint string `json:"endpoint"`
}

type createMessageRequest struct {
	FromPeerID string `json:"fromPeerId"`
	Text       string `json:"text"`
}

type createFileTransferRequest struct {
	FromPeerID string `json:"fromPeerId"`
	ToPeerID   string `json:"toPeerId"`
	FileName   string `json:"fileName"`
	SizeBytes  int64  `json:"sizeBytes"`
}

type uploadFileTransferContentRequest struct {
	ContentType   string `json:"contentType"`
	PayloadBase64 string `json:"payloadBase64"`
}

type uploadFileTransferContentChunkRequest struct {
	ContentType   string `json:"contentType"`
	PayloadBase64 string `json:"payloadBase64"`
	OffsetBytes   int64  `json:"offsetBytes"`
}

type patchFileTransferRequest struct {
	Action          string `json:"action"`
	Reason          string `json:"reason"`
	ProgressPercent *int   `json:"progressPercent"`
}

type patchPeerRequest struct {
	Endpoint        *string `json:"endpoint"`
	Status          *string `json:"status"`
	Reachability    *string `json:"reachability"`
	ConnectionState *string `json:"connectionState"`
}

type createSignalCandidateRequest struct {
	Type       string `json:"type"`
	Protocol   string `json:"protocol"`
	Address    string `json:"address"`
	Preference int    `json:"preference"`
	Reachable  *bool  `json:"reachable"`
	TTLSec     int64  `json:"ttlSec"`
}

type createTunnelRequest struct {
	PeerAID string `json:"peerAId"`
	PeerBID string `json:"peerBId"`
	Mode    string `json:"mode"`
}

type patchTunnelRequest struct {
	State string `json:"state"`
}

type envelope[T any] struct {
	Data T `json:"data"`
}

type listEnvelope[T any] struct {
	Data []T          `json:"data"`
	Meta responseMeta `json:"meta"`
}

type responseMeta struct {
	Count  int `json:"count"`
	Total  int `json:"total,omitempty"`
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type healthResponse struct {
	Status  string                 `json:"status"`
	Time    int64                  `json:"time"`
	Version *versionStatusResponse `json:"version,omitempty"`
	Relay   *relayStatusResponse   `json:"relay,omitempty"`
	Auth    *authStatusResponse    `json:"auth,omitempty"`
}

type probeResponse struct {
	Status  string                    `json:"status"`
	Time    int64                     `json:"time"`
	Version *versionStatusResponse    `json:"version,omitempty"`
	Checks  map[string]probeCheckItem `json:"checks,omitempty"`
}

type probeCheckItem struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type rootResponse struct {
	Name      string                 `json:"name"`
	Version   string                 `json:"version"`
	Server    *versionStatusResponse `json:"server,omitempty"`
	Resources []string               `json:"resources"`
}

type versionStatusResponse struct {
	APIVersion       string `json:"apiVersion"`
	ServerVersion    string `json:"serverVersion"`
	MinClientVersion string `json:"minClientVersion"`
}

type relayStatusResponse struct {
	ListenAddress           string `json:"listenAddress"`
	StartedAtUnix           int64  `json:"startedAtUnix"`
	ActiveBindings          int    `json:"activeBindings"`
	TotalBindRequests       int    `json:"totalBindRequests"`
	SuccessfulBinds         int    `json:"successfulBinds"`
	BindDenials             int    `json:"bindDenials"`
	TotalSendRequests       int    `json:"totalSendRequests"`
	ForwardedPackets        int    `json:"forwardedPackets"`
	ForwardedBytes          int64  `json:"forwardedBytes"`
	SendDenials             int    `json:"sendDenials"`
	QuotaDenials            int    `json:"quotaDenials"`
	QuotaWindowSeconds      int64  `json:"quotaWindowSeconds"`
	MaxPacketsPerPeerWindow int    `json:"maxPacketsPerPeerWindow"`
	MaxBytesPerPeerWindow   int64  `json:"maxBytesPerPeerWindow"`
	MalformedPackets        int    `json:"malformedPackets"`
	AbuseDenials            int    `json:"abuseDenials"`
	AbuseAlerts             int    `json:"abuseAlerts"`
	AbuseBlockedSources     int    `json:"abuseBlockedSources"`
	AbuseWindowSeconds      int64  `json:"abuseWindowSeconds"`
	AbuseThreshold          int    `json:"abuseThreshold"`
	AbuseBlockSeconds       int64  `json:"abuseBlockSeconds"`
}

type authStatusResponse struct {
	ActiveAbuseAlerts   int    `json:"activeAbuseAlerts"`
	LoginAlerts         int    `json:"loginAlerts"`
	RefreshAlerts       int    `json:"refreshAlerts"`
	WarningAlerts       int    `json:"warningAlerts"`
	ElevatedAlerts      int    `json:"elevatedAlerts"`
	CriticalAlerts      int    `json:"criticalAlerts"`
	BlockedKeys         int    `json:"blockedKeys"`
	TotalAlertEvents    int    `json:"totalAlertEvents"`
	TotalDeniedRequests int    `json:"totalDeniedRequests"`
	LastAlertType       string `json:"lastAlertType"`
	LastSeverity        string `json:"lastSeverity"`
	LastAlertedAtUnix   int64  `json:"lastAlertedAtUnix"`
}

type incidentReportResponse struct {
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

type userResponse struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Status string `json:"status"`
}

type networkResponse struct {
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

type deviceResponse struct {
	ID            string `json:"id"`
	UserID        string `json:"userId"`
	Name          string `json:"name"`
	PublicKey     string `json:"publicKey"`
	Fingerprint   string `json:"fingerprint"`
	Status        string `json:"status"`
	CreatedAtUnix int64  `json:"createdAtUnix"`
	RevokedAtUnix int64  `json:"revokedAtUnix"`
}

type peerResponse struct {
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

type messageResponse struct {
	ID         string `json:"id"`
	NetworkID  string `json:"networkId"`
	FromPeerID string `json:"fromPeerId"`
	Text       string `json:"text"`
	Preview    string `json:"preview"`
	SentAtUnix int64  `json:"sentAtUnix"`
}

type fileTransferResponse struct {
	ID                   string `json:"id"`
	NetworkID            string `json:"networkId"`
	FromPeerID           string `json:"fromPeerId"`
	FromUserID           string `json:"fromUserId,omitempty"`
	ToPeerID             string `json:"toPeerId"`
	ToUserID             string `json:"toUserId,omitempty"`
	FileName             string `json:"fileName"`
	SizeBytes            int64  `json:"sizeBytes"`
	Status               string `json:"status"`
	ProgressPercent      int    `json:"progressPercent"`
	CancelReason         string `json:"cancelReason,omitempty"`
	ContentType          string `json:"contentType,omitempty"`
	PayloadSHA256        string `json:"payloadSha256,omitempty"`
	PayloadReady         bool   `json:"payloadReady"`
	PayloadUploadedBytes int64  `json:"payloadUploadedBytes,omitempty"`
	UploadedAtUnix       int64  `json:"uploadedAtUnix,omitempty"`
	DownloadedAtUnix     int64  `json:"downloadedAtUnix,omitempty"`
}

type fileTransferContentResponse struct {
	Transfer         fileTransferResponse `json:"transfer"`
	ContentType      string               `json:"contentType"`
	SHA256           string               `json:"sha256"`
	PayloadBase64    string               `json:"payloadBase64"`
	SizeBytes        int64                `json:"sizeBytes"`
	UploadedAtUnix   int64                `json:"uploadedAtUnix"`
	DownloadedAtUnix int64                `json:"downloadedAtUnix,omitempty"`
}

type fileTransferContentChunkResponse struct {
	Transfer         fileTransferResponse `json:"transfer"`
	ContentType      string               `json:"contentType"`
	SHA256           string               `json:"sha256"`
	PayloadBase64    string               `json:"payloadBase64"`
	OffsetBytes      int64                `json:"offsetBytes"`
	NextOffsetBytes  int64                `json:"nextOffsetBytes"`
	TotalSizeBytes   int64                `json:"totalSizeBytes"`
	UploadedAtUnix   int64                `json:"uploadedAtUnix"`
	DownloadedAtUnix int64                `json:"downloadedAtUnix,omitempty"`
	Complete         bool                 `json:"complete"`
}

type signalCandidateResponse struct {
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

type inviteResponse struct {
	Code          string `json:"code"`
	NetworkID     string `json:"networkId"`
	ExpiresAtUnix int64  `json:"expiresAtUnix"`
	MaxUses       int    `json:"maxUses"`
	Uses          int    `json:"uses"`
}

type tunnelResponse struct {
	ID            string `json:"id"`
	NetworkID     string `json:"networkId"`
	PeerAID       string `json:"peerAId"`
	PeerBID       string `json:"peerBId"`
	Mode          string `json:"mode"`
	State         string `json:"state"`
	CreatedAtUnix int64  `json:"createdAtUnix"`
}

type sessionResponse struct {
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

type auditEventResponse struct {
	ID            string `json:"id"`
	ActorUserID   string `json:"actorUserId"`
	NetworkID     string `json:"networkId,omitempty"`
	Type          string `json:"type"`
	Details       string `json:"details"`
	CreatedAtUnix int64  `json:"createdAtUnix"`
}
