package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
)

var (
	ErrUserBanned                    = errors.New("user is banned")
	ErrInvalidPassword               = errors.New("invalid password")
	ErrDeviceNotActive               = errors.New("device is not active")
	ErrDeviceAlreadyRevoked          = errors.New("device is already revoked")
	ErrDeviceApprovalRequired        = errors.New("device approval required")
	ErrUserAlreadyMember             = errors.New("user is already a member")
	ErrUserNotMember                 = errors.New("user is not a member")
	ErrOnlyOwnerCanManage            = errors.New("only owner can manage members")
	ErrInsufficientNetworkRole       = errors.New("insufficient network role")
	ErrInviteExpired                 = errors.New("invite expired")
	ErrInviteExhausted               = errors.New("invite exhausted")
	ErrMessageEmpty                  = errors.New("message text is empty")
	ErrInvalidTransferPercent        = errors.New("transfer percent must be between 0 and 100")
	ErrTransferPayloadMissing        = errors.New("file transfer payload is not available")
	ErrTransferPayloadUploaded       = errors.New("file transfer payload is already uploaded")
	ErrTransferPayloadTooLarge       = errors.New("file transfer payload is too large")
	ErrTransferPayloadOffsetMismatch = errors.New("file transfer payload offset does not match current upload state")
	ErrFileTransfersDisabled         = errors.New("file transfers are disabled for this network")
	ErrTransferPolicyExceeded        = errors.New("file transfer exceeds the network policy size limit")
)

const (
	DefaultControlPlaneFileTransferPayloadMaxBytes int64 = 64 << 20
	DefaultMirroredFileTransferPayloadMaxBytes     int64 = 2 * DefaultControlPlaneFileTransferPayloadMaxBytes
	DefaultNetworkFileTransferMaxBytes             int64 = DefaultControlPlaneFileTransferPayloadMaxBytes
	MaxFileTransferChunkBytes                      int64 = 8 << 20
	DefaultFileTransferChunkBytes                  int64 = 1 << 20
)

type User struct {
	ID           UserID     `json:"id"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"-"`
	Status       UserStatus `json:"status"`
}

func (u *User) CanLogin() bool {
	return u.Status == UserStatusActive
}

func (u *User) Ban(_ string) {
	u.Status = UserStatusBanned
}

func (u *User) Unban() {
	u.Status = UserStatusActive
}

func (u *User) ChangePassword(oldHash, newHash string) error {
	if u.PasswordHash != oldHash {
		return ErrInvalidPassword
	}
	u.PasswordHash = newHash
	return nil
}

type Device struct {
	ID            DeviceID     `json:"id"`
	UserID        UserID       `json:"userId"`
	Name          string       `json:"name"`
	PublicKey     string       `json:"publicKey"`
	Fingerprint   string       `json:"fingerprint"`
	Status        DeviceStatus `json:"status"`
	CreatedAtUnix int64        `json:"createdAtUnix"`
	RevokedAtUnix int64        `json:"revokedAtUnix"`
}

func NewDevice(id DeviceID, userID UserID, name, publicKey string, nowUnix int64) *Device {
	device := &Device{
		ID:            id,
		UserID:        userID,
		Name:          strings.TrimSpace(name),
		PublicKey:     strings.TrimSpace(publicKey),
		Status:        DeviceStatusActive,
		CreatedAtUnix: nowUnix,
	}
	if device.Name == "" {
		device.Name = "Ole Device"
	}
	device.refreshFingerprint()
	return device
}

func (d *Device) Rename(name string) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Ole Device"
	}
	d.Name = name
}

func (d *Device) SetPublicKey(publicKey string) {
	d.PublicKey = strings.TrimSpace(publicKey)
	d.refreshFingerprint()
}

func (d *Device) Disable() error {
	if d.Status == DeviceStatusRevoked {
		return ErrDeviceAlreadyRevoked
	}
	d.Status = DeviceStatusDisabled
	return nil
}

func (d *Device) Activate() error {
	if d.Status == DeviceStatusRevoked {
		return ErrDeviceAlreadyRevoked
	}
	d.Status = DeviceStatusActive
	return nil
}

func (d *Device) Revoke(nowUnix int64) error {
	if d.Status == DeviceStatusRevoked {
		return ErrDeviceAlreadyRevoked
	}
	d.Status = DeviceStatusRevoked
	d.RevokedAtUnix = nowUnix
	return nil
}

func (d *Device) IsActive() bool {
	return d.Status == DeviceStatusActive
}

func (d *Device) refreshFingerprint() {
	if d.PublicKey == "" {
		d.Fingerprint = ""
		return
	}
	sum := sha256.Sum256([]byte(d.PublicKey))
	d.Fingerprint = strings.ToUpper(hex.EncodeToString(sum[:8]))
}

type Network struct {
	ID                     NetworkID                 `json:"id"`
	Name                   string                    `json:"name"`
	OwnerID                UserID                    `json:"ownerId"`
	Access                 NetworkAccess             `json:"access"`
	DeviceApprovalRequired bool                      `json:"deviceApprovalRequired"`
	RoutingPolicy          NetworkRoutingPolicy      `json:"routingPolicy"`
	GroupTrafficPolicy     NetworkGroupTrafficPolicy `json:"groupTrafficPolicy"`
	NameResolutionMode     NetworkNameResolutionMode `json:"nameResolutionMode"`
	DNSLabel               string                    `json:"dnsLabel"`
	FileTransfersEnabled   bool                      `json:"fileTransfersEnabled"`
	FileTransferMaxBytes   int64                     `json:"fileTransferMaxBytes"`
	Members                map[string]NetworkRole    `json:"members"`
	ApprovedDevices        map[string]bool           `json:"approvedDevices"`
}

type NetworkRoutingPolicy string

const (
	NetworkRoutingPolicySplit NetworkRoutingPolicy = "SPLIT"
	NetworkRoutingPolicyFull  NetworkRoutingPolicy = "FULL"
)

type NetworkGroupTrafficPolicy string

const (
	NetworkGroupTrafficPolicyBlocked NetworkGroupTrafficPolicy = "BLOCKED"
	NetworkGroupTrafficPolicyFlood   NetworkGroupTrafficPolicy = "FLOOD"
)

type NetworkNameResolutionMode string

const (
	NetworkNameResolutionDefault     NetworkNameResolutionMode = "DEFAULT"
	NetworkNameResolutionNetworkOnly NetworkNameResolutionMode = "NETWORK_ONLY"
	NetworkNameResolutionDisabled    NetworkNameResolutionMode = "DISABLED"
)

func NewNetwork(id NetworkID, ownerID UserID, name string, access NetworkAccess, deviceApprovalRequired bool) *Network {
	n := &Network{
		ID:                     id,
		Name:                   name,
		OwnerID:                ownerID,
		Access:                 access,
		DeviceApprovalRequired: deviceApprovalRequired,
		RoutingPolicy:          NetworkRoutingPolicySplit,
		GroupTrafficPolicy:     NetworkGroupTrafficPolicyBlocked,
		NameResolutionMode:     NetworkNameResolutionDefault,
		FileTransfersEnabled:   true,
		FileTransferMaxBytes:   DefaultNetworkFileTransferMaxBytes,
		Members:                map[string]NetworkRole{},
		ApprovedDevices:        map[string]bool{},
	}
	n.Members[ownerID.String()] = NetworkRoleOwner
	return n
}

func (n *Network) Rename(newName string) {
	n.Name = strings.TrimSpace(newName)
}

func (n *Network) IsOwner(userID UserID) bool {
	return n.OwnerID == userID
}

func (n *Network) AddMember(userID UserID) error {
	return n.AddMemberWithRole(userID, NetworkRoleMember)
}

func (n *Network) AddMemberWithRole(userID UserID, role NetworkRole) error {
	if n.HasMember(userID) {
		return ErrUserAlreadyMember
	}
	n.Members[userID.String()] = role
	return nil
}

func (n *Network) RemoveMember(userID UserID) error {
	if !n.HasMember(userID) {
		return ErrUserNotMember
	}
	delete(n.Members, userID.String())
	return nil
}

func (n *Network) HasMember(userID UserID) bool {
	_, ok := n.Members[userID.String()]
	return ok
}

func (n *Network) RoleOf(userID UserID) (NetworkRole, bool) {
	role, ok := n.Members[userID.String()]
	return role, ok
}

func (n *Network) CanManageMembers(userID UserID) bool {
	role, ok := n.RoleOf(userID)
	return ok && HasPermissionForNetworkOperation(role, NetworkOperationManageMembers)
}

func (n *Network) CanManageInvites(userID UserID) bool {
	role, ok := n.RoleOf(userID)
	return ok && HasPermissionForNetworkOperation(role, NetworkOperationManageInvites)
}

func (n *Network) CanView(userID UserID) bool {
	role, ok := n.RoleOf(userID)
	return ok && HasPermissionForNetworkOperation(role, NetworkOperationViewNetwork)
}

func (n *Network) CanManageSettings(userID UserID) bool {
	role, ok := n.RoleOf(userID)
	return ok && HasPermission(role, PermissionManageNetworkSettings)
}

func (n *Network) AuthorizeOperation(userID UserID, operation NetworkOperation) error {
	role, ok := n.RoleOf(userID)
	if !ok {
		return ErrUnauthorized
	}
	if !HasPermissionForNetworkOperation(role, operation) {
		return ErrInsufficientNetworkRole
	}
	return nil
}

func (n *Network) ChangeMemberRole(requestorID, memberID UserID, role NetworkRole) error {
	if !n.IsOwner(requestorID) {
		return ErrOnlyOwnerCanManage
	}
	if !n.HasMember(memberID) {
		return ErrUserNotMember
	}
	if memberID == n.OwnerID {
		n.Members[memberID.String()] = NetworkRoleOwner
		return nil
	}
	n.Members[memberID.String()] = role
	return nil
}

func (n *Network) ChangeAccess(access NetworkAccess) {
	n.Access = access
}

func (n *Network) SetRoutingPolicy(policy NetworkRoutingPolicy) error {
	normalizedPolicy, err := normalizeNetworkRoutingPolicy(policy)
	if err != nil {
		return err
	}
	n.RoutingPolicy = normalizedPolicy
	return nil
}

func (n *Network) SetNameResolutionPolicy(mode NetworkNameResolutionMode, dnsLabel string) error {
	normalizedMode, err := normalizeNetworkNameResolutionMode(mode)
	if err != nil {
		return err
	}
	normalizedLabel, err := normalizeNetworkDNSLabel(dnsLabel)
	if err != nil {
		return err
	}
	if normalizedMode == NetworkNameResolutionDisabled {
		normalizedLabel = ""
	}
	n.NameResolutionMode = normalizedMode
	n.DNSLabel = normalizedLabel
	return nil
}

func (n *Network) SetGroupTrafficPolicy(policy NetworkGroupTrafficPolicy) error {
	normalizedPolicy, err := normalizeNetworkGroupTrafficPolicy(policy)
	if err != nil {
		return err
	}
	n.GroupTrafficPolicy = normalizedPolicy
	return nil
}

func (n *Network) SetFileTransferPolicy(enabled bool, maxBytes int64) error {
	normalizedMaxBytes, err := normalizeNetworkFileTransferMaxBytes(maxBytes)
	if err != nil {
		return err
	}
	n.FileTransfersEnabled = enabled
	n.FileTransferMaxBytes = normalizedMaxBytes
	return nil
}

func (n *Network) ApproveDevice(deviceID DeviceID) {
	if n.ApprovedDevices == nil {
		n.ApprovedDevices = map[string]bool{}
	}
	if deviceID.String() == "" {
		return
	}
	n.ApprovedDevices[deviceID.String()] = true
}

func (n *Network) RevokeDeviceApproval(deviceID DeviceID) {
	if n.ApprovedDevices == nil {
		return
	}
	delete(n.ApprovedDevices, deviceID.String())
}

func normalizeNetworkRoutingPolicy(policy NetworkRoutingPolicy) (NetworkRoutingPolicy, error) {
	normalized := NetworkRoutingPolicy(strings.ToUpper(strings.TrimSpace(string(policy))))
	if normalized == "" {
		return NetworkRoutingPolicySplit, nil
	}
	switch normalized {
	case NetworkRoutingPolicySplit, NetworkRoutingPolicyFull:
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported routing policy %q", policy)
	}
}

func normalizeNetworkNameResolutionMode(mode NetworkNameResolutionMode) (NetworkNameResolutionMode, error) {
	normalized := NetworkNameResolutionMode(strings.ToUpper(strings.TrimSpace(string(mode))))
	if normalized == "" {
		return NetworkNameResolutionDefault, nil
	}
	switch normalized {
	case NetworkNameResolutionDefault, NetworkNameResolutionNetworkOnly, NetworkNameResolutionDisabled:
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported name resolution mode %q", mode)
	}
}

func normalizeNetworkGroupTrafficPolicy(policy NetworkGroupTrafficPolicy) (NetworkGroupTrafficPolicy, error) {
	normalized := NetworkGroupTrafficPolicy(strings.ToUpper(strings.TrimSpace(string(policy))))
	if normalized == "" {
		return NetworkGroupTrafficPolicyBlocked, nil
	}
	switch normalized {
	case NetworkGroupTrafficPolicyBlocked, NetworkGroupTrafficPolicyFlood:
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported group traffic policy %q", policy)
	}
}

func normalizeNetworkDNSLabel(label string) (string, error) {
	label = strings.ToLower(strings.TrimSpace(label))
	if label == "" {
		return "", nil
	}
	if len(label) > 63 {
		return "", fmt.Errorf("dns label must be 63 characters or fewer")
	}
	for idx, r := range label {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
			if idx == 0 || idx == len(label)-1 {
				return "", fmt.Errorf("dns label cannot start or end with '-'")
			}
		default:
			return "", fmt.Errorf("dns label must contain only letters, digits, or '-'")
		}
	}
	return label, nil
}

func normalizeNetworkFileTransferMaxBytes(maxBytes int64) (int64, error) {
	if maxBytes <= 0 {
		return DefaultNetworkFileTransferMaxBytes, nil
	}
	return maxBytes, nil
}

func (n *Network) IsDeviceApproved(deviceID DeviceID) bool {
	if !n.DeviceApprovalRequired {
		return true
	}
	if n.ApprovedDevices == nil {
		return false
	}
	return n.ApprovedDevices[deviceID.String()]
}

func (n *Network) MemberIDs() []UserID {
	ids := make([]UserID, 0, len(n.Members))
	for id := range n.Members {
		ids = append(ids, UserID{Value: id})
	}
	slices.SortFunc(ids, func(a, b UserID) int {
		return strings.Compare(a.String(), b.String())
	})
	return ids
}

func (n *Network) MemberRoles() map[string]NetworkRole {
	out := make(map[string]NetworkRole, len(n.Members))
	for id, role := range n.Members {
		out[id] = role
	}
	return out
}

func (n *Network) ApprovedDeviceIDs() []DeviceID {
	ids := make([]DeviceID, 0, len(n.ApprovedDevices))
	for id, approved := range n.ApprovedDevices {
		if approved {
			ids = append(ids, DeviceID{Value: id})
		}
	}
	slices.SortFunc(ids, func(a, b DeviceID) int {
		return strings.Compare(a.String(), b.String())
	})
	return ids
}

type Peer struct {
	ID                 PeerID           `json:"id"`
	UserID             UserID           `json:"userId"`
	DeviceID           DeviceID         `json:"deviceId"`
	NetworkID          NetworkID        `json:"networkId"`
	OverlayCIDR        string           `json:"overlayCidr,omitempty"`
	VirtualIP          string           `json:"virtualIp"`
	Endpoint           string           `json:"endpoint"`
	Status             PeerStatus       `json:"status"`
	Reachability       PeerReachability `json:"reachability"`
	ConnectionState    ConnectionState  `json:"connectionState"`
	LastSeenUnix       int64            `json:"lastSeenUnix"`
	LastSignaledAtUnix int64            `json:"lastSignaledAtUnix"`
}

func (p *Peer) MarkOnline(nowUnix int64) {
	p.Status = PeerStatusOnline
	p.LastSeenUnix = nowUnix
}

func (p *Peer) MarkOffline(nowUnix int64) {
	p.Status = PeerStatusOffline
	p.LastSeenUnix = nowUnix
}

func (p *Peer) UpdateEndpoint(endpoint string) {
	p.Endpoint = strings.TrimSpace(endpoint)
}

func (p *Peer) IsStale(nowUnix, ttlSec int64) bool {
	return nowUnix-p.LastSeenUnix > ttlSec
}

func (p *Peer) AssignVirtualIP(ip string) {
	p.VirtualIP = ip
}

func (p *Peer) SetOverlayCIDR(cidr string) {
	p.OverlayCIDR = strings.TrimSpace(cidr)
}

func (p *Peer) UpdateReachability(reachability PeerReachability, connectionState ConnectionState, nowUnix int64) {
	if reachability != "" {
		p.Reachability = reachability
	}
	if connectionState != "" {
		p.ConnectionState = connectionState
	}
	p.LastSignaledAtUnix = nowUnix
}

type SignalCandidate struct {
	ID            string                  `json:"id"`
	PeerID        PeerID                  `json:"peerId"`
	NetworkID     NetworkID               `json:"networkId"`
	Type          SignalCandidateType     `json:"type"`
	Protocol      SignalCandidateProtocol `json:"protocol"`
	Address       string                  `json:"address"`
	Preference    int                     `json:"preference"`
	Reachable     bool                    `json:"reachable"`
	CreatedAtUnix int64                   `json:"createdAtUnix"`
	ExpiresAtUnix int64                   `json:"expiresAtUnix"`
}

func (c *SignalCandidate) IsExpired(nowUnix int64) bool {
	return nowUnix >= c.ExpiresAtUnix
}

type VirtualIPPool struct {
	NetworkID NetworkID         `json:"networkId"`
	CIDR      string            `json:"cidr"`
	Leases    map[string]PeerID `json:"leases"`
}

func NewVirtualIPPool(networkID NetworkID, cidr string) *VirtualIPPool {
	return &VirtualIPPool{
		NetworkID: networkID,
		CIDR:      cidr,
		Leases:    map[string]PeerID{},
	}
}

func (p *VirtualIPPool) Allocate(peerID PeerID) (string, error) {
	for ip, leasedPeerID := range p.Leases {
		if leasedPeerID == peerID {
			return ip, nil
		}
	}

	ip, network, err := net.ParseCIDR(p.CIDR)
	if err != nil {
		return "", err
	}
	base := ip.To4()
	if base == nil {
		return "", fmt.Errorf("only IPv4 pools are supported: %s", p.CIDR)
	}

	candidate := cloneIP(base)
	incrementIPv4(candidate)
	for network.Contains(candidate) {
		candidateText := candidate.String()
		if !p.IsAllocated(candidateText) {
			p.Leases[candidateText] = peerID
			return candidateText, nil
		}
		incrementIPv4(candidate)
	}

	return "", fmt.Errorf("virtual IP pool exhausted")
}

func (p *VirtualIPPool) Release(peerID PeerID) {
	for ip, leasedPeerID := range p.Leases {
		if leasedPeerID == peerID {
			delete(p.Leases, ip)
			return
		}
	}
}

func (p *VirtualIPPool) IsAllocated(ip string) bool {
	_, ok := p.Leases[ip]
	return ok
}

func (p *VirtualIPPool) CountLeases() int {
	return len(p.Leases)
}

type Invite struct {
	Code          string    `json:"code"`
	NetworkID     NetworkID `json:"networkId"`
	ExpiresAtUnix int64     `json:"expiresAtUnix"`
	MaxUses       int       `json:"maxUses"`
	Uses          int       `json:"uses"`
}

func (i *Invite) IsExpired(nowUnix int64) bool {
	return nowUnix >= i.ExpiresAtUnix
}

func (i *Invite) CanUse(nowUnix int64) bool {
	if i.IsExpired(nowUnix) {
		return false
	}
	if i.MaxUses <= 0 {
		return true
	}
	return i.Uses < i.MaxUses
}

func (i *Invite) IsExhausted() bool {
	return i.MaxUses > 0 && i.Uses >= i.MaxUses
}

func (i *Invite) UseOnce(nowUnix int64) error {
	if i.IsExpired(nowUnix) {
		return ErrInviteExpired
	}
	if i.MaxUses > 0 && i.Uses >= i.MaxUses {
		return ErrInviteExhausted
	}
	i.Uses++
	return nil
}

type Tunnel struct {
	ID            TunnelID    `json:"id"`
	NetworkID     NetworkID   `json:"networkId"`
	A             PeerID      `json:"a"`
	B             PeerID      `json:"b"`
	Mode          TunnelMode  `json:"mode"`
	State         TunnelState `json:"state"`
	CreatedAtUnix int64       `json:"createdAtUnix"`
}

func (t *Tunnel) BeginNegotiation(mode TunnelMode) {
	t.Mode = mode
	t.State = TunnelStateNegotiating
}

func (t *Tunnel) Open(mode TunnelMode) {
	t.Mode = mode
	t.State = TunnelStateOpen
}

func (t *Tunnel) Close() {
	t.State = TunnelStateClosed
}

func (t *Tunnel) MarkFailed() {
	t.State = TunnelStateFailed
}

func (t *Tunnel) IsActive() bool {
	return t.State == TunnelStateOpen
}

func (t *Tunnel) Involves(peerID PeerID) bool {
	return t.A == peerID || t.B == peerID
}

type Message struct {
	ID         string    `json:"id"`
	NetworkID  NetworkID `json:"networkId"`
	FromPeerID PeerID    `json:"fromPeerId"`
	Text       string    `json:"text"`
	SentAtUnix int64     `json:"sentAtUnix"`
}

func (m *Message) Validate() error {
	if strings.TrimSpace(m.Text) == "" {
		return ErrMessageEmpty
	}
	return nil
}

func (m *Message) Preview(maxLen int) string {
	if maxLen <= 0 || len(m.Text) <= maxLen {
		return m.Text
	}
	return m.Text[:maxLen]
}

type FileTransfer struct {
	ID                   string         `json:"id"`
	NetworkID            NetworkID      `json:"networkId"`
	FromPeerID           PeerID         `json:"fromPeerId"`
	FromUserID           UserID         `json:"fromUserId"`
	ToPeerID             PeerID         `json:"toPeerId"`
	ToUserID             UserID         `json:"toUserId"`
	FileName             string         `json:"fileName"`
	SizeBytes            int64          `json:"sizeBytes"`
	Status               TransferStatus `json:"status"`
	ProgressPercent      int            `json:"progressPercent"`
	CancelReason         string         `json:"cancelReason,omitempty"`
	ContentType          string         `json:"contentType,omitempty"`
	PayloadSHA256        string         `json:"payloadSha256,omitempty"`
	PayloadReady         bool           `json:"payloadReady"`
	PayloadUploadedBytes int64          `json:"payloadUploadedBytes"`
	UploadedAtUnix       int64          `json:"uploadedAtUnix"`
	DownloadedAtUnix     int64          `json:"downloadedAtUnix"`
}

func (f *FileTransfer) Start() {
	f.Status = TransferStatusInProgress
	f.CancelReason = ""
}

func (f *FileTransfer) Accept() {
	f.Status = TransferStatusInProgress
	f.CancelReason = ""
}

func (f *FileTransfer) Cancel(reason string) {
	f.Status = TransferStatusCanceled
	f.CancelReason = strings.TrimSpace(reason)
}

func (f *FileTransfer) AttachPayload(contentType, sha256 string, uploadedAtUnix int64) {
	f.ContentType = strings.TrimSpace(contentType)
	f.PayloadSHA256 = strings.TrimSpace(sha256)
	f.PayloadReady = true
	f.PayloadUploadedBytes = f.SizeBytes
	f.UploadedAtUnix = uploadedAtUnix
	f.DownloadedAtUnix = 0
}

func (f *FileTransfer) UpdatePayloadUploadState(contentType string, uploadedBytes int64) {
	f.ContentType = strings.TrimSpace(contentType)
	f.PayloadUploadedBytes = max(0, min(uploadedBytes, f.SizeBytes))
	if f.PayloadUploadedBytes < f.SizeBytes {
		f.PayloadReady = false
		f.PayloadSHA256 = ""
		f.UploadedAtUnix = 0
	}
}

func (f *FileTransfer) Progress(percent int) error {
	if percent < 0 || percent > 100 {
		return ErrInvalidTransferPercent
	}
	f.ProgressPercent = percent
	if percent == 100 {
		f.Status = TransferStatusDone
	} else if f.Status == TransferStatusInit {
		f.Status = TransferStatusInProgress
	}
	if f.Status == TransferStatusDone {
		f.CancelReason = ""
	}
	return nil
}

func (f *FileTransfer) IsTerminal() bool {
	return f.Status == TransferStatusDone || f.Status == TransferStatusCanceled || f.Status == TransferStatusFailed
}

func (f *FileTransfer) CompleteDownload(nowUnix int64) {
	f.ProgressPercent = 100
	f.Status = TransferStatusDone
	f.CancelReason = ""
	f.DownloadedAtUnix = nowUnix
}

type FileTransferPayload struct {
	TransferID       string `json:"transferId"`
	ContentType      string `json:"contentType"`
	SizeBytes        int64  `json:"sizeBytes"`
	SHA256           string `json:"sha256"`
	Payload          []byte `json:"payload,omitempty"`
	UploadedAtUnix   int64  `json:"uploadedAtUnix"`
	DownloadedAtUnix int64  `json:"downloadedAtUnix,omitempty"`
}

type FileTransferPayloadChunk struct {
	Transfer         *FileTransfer `json:"transfer,omitempty"`
	ContentType      string        `json:"contentType"`
	SHA256           string        `json:"sha256"`
	Payload          []byte        `json:"payload,omitempty"`
	OffsetBytes      int64         `json:"offsetBytes"`
	NextOffsetBytes  int64         `json:"nextOffsetBytes"`
	TotalSizeBytes   int64         `json:"totalSizeBytes"`
	UploadedAtUnix   int64         `json:"uploadedAtUnix"`
	DownloadedAtUnix int64         `json:"downloadedAtUnix,omitempty"`
	Complete         bool          `json:"complete"`
}

type AuditEvent struct {
	ID            string    `json:"id"`
	ActorUserID   UserID    `json:"actorUserId"`
	NetworkID     NetworkID `json:"networkId,omitempty"`
	Type          string    `json:"type"`
	Details       string    `json:"details"`
	CreatedAtUnix int64     `json:"createdAtUnix"`
}

func (e *AuditEvent) FormatLine() string {
	if e.NetworkID.String() != "" {
		return fmt.Sprintf("%d [%s] [%s] %s: %s", e.CreatedAtUnix, e.ActorUserID.String(), e.NetworkID.String(), e.Type, e.Details)
	}
	return fmt.Sprintf("%d [%s] %s: %s", e.CreatedAtUnix, e.ActorUserID.String(), e.Type, e.Details)
}

type SessionToken struct {
	ID                  string `json:"id"`
	UserID              UserID `json:"userId"`
	FamilyID            string `json:"familyId"`
	AccessToken         string `json:"accessToken"`
	RefreshToken        string `json:"refreshToken"`
	DeviceName          string `json:"deviceName"`
	IP                  string `json:"ip"`
	UserAgent           string `json:"userAgent"`
	LastUsedAtUnix      int64  `json:"lastUsedAtUnix"`
	ExpiresAtUnix       int64  `json:"expiresAtUnix"`
	ReplacedByToken     string `json:"replacedByToken"`
	RevokedAtUnix       int64  `json:"revokedAtUnix"`
	ReuseDetectedAtUnix int64  `json:"reuseDetectedAtUnix"`
}

func (s *SessionToken) IsExpired(nowUnix int64) bool {
	return nowUnix >= s.ExpiresAtUnix
}

func (s *SessionToken) IsRevoked() bool {
	return s.RevokedAtUnix > 0
}

func (s *SessionToken) IsReused() bool {
	return s.ReuseDetectedAtUnix > 0
}

func (s *SessionToken) CanRotateTo(next *SessionToken, nowUnix int64) bool {
	return s != nil && next != nil && !s.IsRevoked() && !s.IsReused() && !s.IsExpired(nowUnix) && s.ReplacedByToken == "" &&
		next.ID != "" && next.ID != s.ID && next.UserID == s.UserID && next.FamilyID == s.FamilyID &&
		next.AccessToken != "" && next.AccessToken != s.AccessToken && next.RefreshToken != "" && next.RefreshToken != s.RefreshToken &&
		!next.IsRevoked() && !next.IsReused() && !next.IsExpired(nowUnix) && next.ReplacedByToken == ""
}

func (s *SessionToken) Rotate(newAccess, newRefresh string, newExp int64) {
	s.AccessToken = newAccess
	s.RefreshToken = newRefresh
	s.ExpiresAtUnix = newExp
}

func (s *SessionToken) Touch(ip, userAgent string, nowUnix int64) {
	if strings.TrimSpace(ip) != "" {
		s.IP = strings.TrimSpace(ip)
	}
	if strings.TrimSpace(userAgent) != "" {
		s.UserAgent = strings.TrimSpace(userAgent)
	}
	s.LastUsedAtUnix = nowUnix
}

func (s *SessionToken) MarkRotated(replacedByToken string, nowUnix int64) {
	s.ReplacedByToken = replacedByToken
	s.RevokedAtUnix = nowUnix
}

func (s *SessionToken) MarkReuseDetected(nowUnix int64) {
	s.ReuseDetectedAtUnix = nowUnix
	s.RevokedAtUnix = nowUnix
}

type SessionMetadata struct {
	DeviceName string
	IP         string
	UserAgent  string
}

func cloneIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

func incrementIPv4(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}
