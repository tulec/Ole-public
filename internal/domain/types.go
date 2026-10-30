package domain

type UserID struct {
	Value string `json:"value"`
}

type DeviceID struct {
	Value string `json:"value"`
}

type NetworkID struct {
	Value string `json:"value"`
}

type PeerID struct {
	Value string `json:"value"`
}

type TunnelID struct {
	Value string `json:"value"`
}

func (id UserID) String() string {
	return id.Value
}

func (id DeviceID) String() string {
	return id.Value
}

func (id NetworkID) String() string {
	return id.Value
}

func (id PeerID) String() string {
	return id.Value
}

func (id TunnelID) String() string {
	return id.Value
}

type UserStatus string

const (
	UserStatusActive UserStatus = "ACTIVE"
	UserStatusBanned UserStatus = "BANNED"
)

type DeviceStatus string

const (
	DeviceStatusActive   DeviceStatus = "ACTIVE"
	DeviceStatusDisabled DeviceStatus = "DISABLED"
	DeviceStatusRevoked  DeviceStatus = "REVOKED"
)

type NetworkAccess string

const (
	NetworkAccessPrivate    NetworkAccess = "PRIVATE"
	NetworkAccessInviteOnly NetworkAccess = "INVITE_ONLY"
)

type NetworkRole string

const (
	NetworkRoleOwner     NetworkRole = "OWNER"
	NetworkRoleAdmin     NetworkRole = "ADMIN"
	NetworkRoleModerator NetworkRole = "MODERATOR"
	NetworkRoleFileAdmin NetworkRole = "FILE_ADMIN"
	NetworkRoleMember    NetworkRole = "MEMBER"
	NetworkRoleReadOnly  NetworkRole = "READ_ONLY"
)

type PeerStatus string

const (
	PeerStatusOnline     PeerStatus = "ONLINE"
	PeerStatusOffline    PeerStatus = "OFFLINE"
	PeerStatusConnecting PeerStatus = "CONNECTING"
)

type PeerReachability string

const (
	PeerReachabilityUnknown PeerReachability = "UNKNOWN"
	PeerReachabilityDirect  PeerReachability = "DIRECT"
	PeerReachabilityRelay   PeerReachability = "RELAY"
)

type ConnectionState string

const (
	ConnectionStateIdle            ConnectionState = "IDLE"
	ConnectionStateDiscovering     ConnectionState = "DISCOVERING"
	ConnectionStateDirectCandidate ConnectionState = "DIRECT_CANDIDATE"
	ConnectionStateNegotiating     ConnectionState = "NEGOTIATING"
	ConnectionStateConnected       ConnectionState = "CONNECTED"
	ConnectionStateRelayReady      ConnectionState = "RELAY_READY"
)

type SignalCandidateType string

const (
	SignalCandidateTypeHost  SignalCandidateType = "HOST"
	SignalCandidateTypeSrflx SignalCandidateType = "SRFLX"
	SignalCandidateTypeRelay SignalCandidateType = "RELAY"
)

type SignalCandidateProtocol string

const (
	SignalCandidateProtocolUDP SignalCandidateProtocol = "UDP"
)

type TunnelMode string

const (
	TunnelModeP2P   TunnelMode = "P2P"
	TunnelModeRelay TunnelMode = "RELAY"
)

type TunnelState string

const (
	TunnelStateNegotiating TunnelState = "NEGOTIATING"
	TunnelStateOpen        TunnelState = "OPEN"
	TunnelStateClosed      TunnelState = "CLOSED"
	TunnelStateFailed      TunnelState = "FAILED"
)

type TransferStatus string

const (
	TransferStatusInit       TransferStatus = "INIT"
	TransferStatusInProgress TransferStatus = "IN_PROGRESS"
	TransferStatusDone       TransferStatus = "DONE"
	TransferStatusCanceled   TransferStatus = "CANCELED"
	TransferStatusFailed     TransferStatus = "FAILED"
)
