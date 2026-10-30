package clientagent

import (
	"Ole/internal/autoupdate"
	"Ole/internal/controlclient"
	"Ole/internal/directprobe"
	"Ole/internal/domain"
	"Ole/internal/overlaydns"
	"Ole/internal/relaytransport"
	"Ole/internal/stun"
	"Ole/internal/transportauth"
	"Ole/internal/versioninfo"
	"Ole/internal/virtualadapter"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultIPCBaseURL               = "http://127.0.0.1:5858"
	DefaultListenAddress            = "127.0.0.1:5858"
	DefaultServerBaseURL            = "http://localhost:8080"
	defaultIPv4Route                = "0.0.0.0/0"
	defaultGatewayHistoryLimit      = 24
	fileTransferAgentChunkBytes     = 1 << 20
	fileTransferDataplaneChunkBytes = 768
	updateChannelStable             = "stable"
	updateChannelBeta               = "beta"
)

type RuntimeConfig struct {
	LifecycleInterval         time.Duration
	SessionRefreshSkew        time.Duration
	SecurityDiagnosticsPeriod time.Duration
	ReconnectRetryBase        time.Duration
	ReconnectRetryMax         time.Duration
	UpdateCheckPeriod         time.Duration
	UpdateChannel             string
	UpdateManifestURL         string
	UpdateStableManifestURL   string
	UpdateBetaManifestURL     string
	UpdateDownloadDir         string
	OverlayDNSListenAddress   string
	OverlayDNSDomain          string
	HeartbeatInterval         time.Duration
	PeerDiscoveryPeriod       time.Duration
	FileTransferMirrorPeriod  time.Duration
	STUNProbePeriod           time.Duration
	STUNServerAddress         string
	RelayServerAddress        string
	RelayFailbackPeriod       time.Duration
	TransportKeepalive        time.Duration
	TransportLossLimit        int
	DirectProbeTimeout        time.Duration
	DirectRetryBase           time.Duration
	DirectRetryMax            time.Duration
	DirectMaxAttempts         int
	TransportSessionTTL       time.Duration
	TransportRekeyAfter       int
}

type Status struct {
	ServiceName             string                    `json:"serviceName"`
	ListenAddress           string                    `json:"listenAddress"`
	ServerBaseURL           string                    `json:"serverBaseUrl"`
	ClientVersion           string                    `json:"clientVersion"`
	ServerVersion           string                    `json:"serverVersion"`
	MinClientVersion        string                    `json:"minClientVersion"`
	CompatibilityStatus     string                    `json:"compatibilityStatus"`
	CompatibilityMessage    string                    `json:"compatibilityMessage"`
	DirectMetrics           DirectConnectMetrics      `json:"directMetrics"`
	RelayServerAddresses    []string                  `json:"relayServerAddresses"`
	ActiveRelayServer       string                    `json:"activeRelayServer"`
	RelayFailoverCount      int                       `json:"relayFailoverCount"`
	StatePath               string                    `json:"statePath"`
	StartedAtUnix           int64                     `json:"startedAtUnix"`
	UncleanShutdownDetected bool                      `json:"uncleanShutdownDetected"`
	LastStartUnix           int64                     `json:"lastStartUnix"`
	LastCleanShutdownUnix   int64                     `json:"lastCleanShutdownUnix"`
	LastCrashRecoveryUnix   int64                     `json:"lastCrashRecoveryUnix"`
	CrashRecoveryCount      int                       `json:"crashRecoveryCount"`
	Connected               bool                      `json:"connected"`
	PersistedSession        bool                      `json:"persistedSession"`
	OverlayDNSListenAddress string                    `json:"overlayDnsListenAddress"`
	OverlayDNSDomain        string                    `json:"overlayDnsDomain"`
	OverlayDNSRecordCount   int                       `json:"overlayDnsRecordCount"`
	OverlayDNSLastError     string                    `json:"overlayDnsLastError"`
	ManagedPeerCount        int                       `json:"managedPeerCount"`
	DiscoveredPeerCount     int                       `json:"discoveredPeerCount"`
	ReconnectState          string                    `json:"reconnectState"`
	ReconnectBackoffActive  bool                      `json:"reconnectBackoffActive"`
	ReconnectAttemptCount   int                       `json:"reconnectAttemptCount"`
	LastReconnectAttemptMs  int64                     `json:"lastReconnectAttemptMs"`
	NextReconnectAttemptMs  int64                     `json:"nextReconnectAttemptMs"`
	ReconnectRemainingMs    int64                     `json:"reconnectRemainingMs"`
	LastReconnectError      string                    `json:"lastReconnectError"`
	LastSessionRefreshUnix  int64                     `json:"lastSessionRefreshUnix"`
	LastHeartbeatUnix       int64                     `json:"lastHeartbeatUnix"`
	LastPeerDiscoveryUnix   int64                     `json:"lastPeerDiscoveryUnix"`
	LastSTUNProbeUnix       int64                     `json:"lastStunProbeUnix"`
	LastDirectProbeUnix     int64                     `json:"lastDirectProbeUnix"`
	LastLifecycleError      string                    `json:"lastLifecycleError"`
	STUNServerAddress       string                    `json:"stunServerAddress"`
	RelayServerAddress      string                    `json:"relayServerAddress"`
	NATType                 string                    `json:"natType"`
	PublicEndpoint          string                    `json:"publicEndpoint"`
	Update                  UpdateStatus              `json:"update"`
	Adapter                 virtualadapter.Status     `json:"adapter"`
	Security                SecurityDiagnostics       `json:"security"`
	Incidents               IncidentSummary           `json:"incidents"`
	GroupTraffic            []GroupTrafficDiagnostics `json:"groupTraffic,omitempty"`
	GatewayHistory          []GatewayChangeEvent      `json:"gatewayHistory,omitempty"`
	Neighbors               []NeighborStatus          `json:"neighbors"`
	Connections             []ConnectionStatus        `json:"connections"`
	CurrentUser             *controlclient.User       `json:"currentUser"`
	CurrentSession          *controlclient.Session    `json:"currentSession"`
	CurrentDevice           *controlclient.Device     `json:"currentDevice"`
}

type UpdateStatus struct {
	Channel                    string   `json:"channel"`
	AvailableChannels          []string `json:"availableChannels"`
	ManifestURL                string   `json:"manifestUrl"`
	CurrentVersion             string   `json:"currentVersion"`
	CheckPeriodSec             int64    `json:"checkPeriodSec"`
	Checking                   bool     `json:"checking"`
	LastCheckedUnix            int64    `json:"lastCheckedUnix"`
	LatestVersion              string   `json:"latestVersion"`
	PublishedAtUnix            int64    `json:"publishedAtUnix"`
	Available                  bool     `json:"available"`
	PolicyStatus               string   `json:"policyStatus"`
	PolicyMessage              string   `json:"policyMessage"`
	MinimumServerVersion       string   `json:"minimumServerVersion"`
	MaximumServerVersion       string   `json:"maximumServerVersion"`
	MinimumRollbackVersion     string   `json:"minimumRollbackVersion"`
	InstallerURL               string   `json:"installerUrl"`
	ReleaseNotesURL            string   `json:"releaseNotesUrl"`
	SignatureURL               string   `json:"signatureUrl"`
	CertificateURL             string   `json:"certificateUrl"`
	SHA256                     string   `json:"sha256"`
	Downloaded                 bool     `json:"downloaded"`
	DownloadedPath             string   `json:"downloadedPath"`
	LastDownloadedUnix         int64    `json:"lastDownloadedUnix"`
	RollbackAvailable          bool     `json:"rollbackAvailable"`
	RollbackVersion            string   `json:"rollbackVersion"`
	RollbackReason             string   `json:"rollbackReason"`
	RollbackInstallerURL       string   `json:"rollbackInstallerUrl"`
	RollbackReleaseNotesURL    string   `json:"rollbackReleaseNotesUrl"`
	RollbackSignatureURL       string   `json:"rollbackSignatureUrl"`
	RollbackCertificateURL     string   `json:"rollbackCertificateUrl"`
	RollbackSHA256             string   `json:"rollbackSha256"`
	RollbackDownloaded         bool     `json:"rollbackDownloaded"`
	RollbackDownloadedPath     string   `json:"rollbackDownloadedPath"`
	RollbackLastDownloadedUnix int64    `json:"rollbackLastDownloadedUnix"`
	LastError                  string   `json:"lastError"`
}

type IncidentSummary struct {
	ActiveCount       int    `json:"activeCount,omitempty"`
	CriticalCount     int    `json:"criticalCount,omitempty"`
	ElevatedCount     int    `json:"elevatedCount,omitempty"`
	WarningCount      int    `json:"warningCount,omitempty"`
	TokenReuseCount   int    `json:"tokenReuseCount,omitempty"`
	MostSevere        string `json:"mostSevere,omitempty"`
	LastUpdatedUnix   int64  `json:"lastUpdatedUnix,omitempty"`
	LastCheckedUnix   int64  `json:"lastCheckedUnix,omitempty"`
	RecommendedAction string `json:"recommendedAction,omitempty"`
	LastRefreshError  string `json:"lastRefreshError,omitempty"`
}

type GatewayChangeEvent struct {
	NetworkID             string `json:"networkId"`
	Event                 string `json:"event"`
	PreviousGatewayRole   string `json:"previousGatewayRole,omitempty"`
	PreviousGatewayPeerID string `json:"previousGatewayPeerId,omitempty"`
	PreviousPath          string `json:"previousPath,omitempty"`
	PreviousPolicyStatus  string `json:"previousPolicyStatus,omitempty"`
	CurrentGatewayRole    string `json:"currentGatewayRole,omitempty"`
	CurrentGatewayPeerID  string `json:"currentGatewayPeerId,omitempty"`
	CurrentPath           string `json:"currentPath,omitempty"`
	CurrentPolicyStatus   string `json:"currentPolicyStatus,omitempty"`
	ChangedAtUnix         int64  `json:"changedAtUnix"`
}

type GroupTrafficDiagnostics struct {
	NetworkID            string `json:"networkId"`
	Policy               string `json:"policy"`
	BlockedPacketCount   int    `json:"blockedPacketCount,omitempty"`
	FloodPacketCount     int    `json:"floodPacketCount,omitempty"`
	FanoutCopyCount      int    `json:"fanoutCopyCount,omitempty"`
	BroadcastPacketCount int    `json:"broadcastPacketCount,omitempty"`
	MulticastPacketCount int    `json:"multicastPacketCount,omitempty"`
	LastPacketUnix       int64  `json:"lastPacketUnix,omitempty"`
	LastAction           string `json:"lastAction,omitempty"`
}

type NeighborStatus struct {
	NetworkID          string `json:"networkId"`
	LocalPeerID        string `json:"localPeerId"`
	RemotePeerID       string `json:"remotePeerId"`
	RemoteUserID       string `json:"remoteUserId,omitempty"`
	RemoteVirtualIP    string `json:"remoteVirtualIp"`
	RemoteEndpoint     string `json:"remoteEndpoint"`
	OverlayCIDR        string `json:"overlayCidr"`
	Presence           string `json:"presence"`
	NeighborState      string `json:"neighborState"`
	Reachability       string `json:"reachability"`
	CandidateCount     int    `json:"candidateCount"`
	TransportReady     bool   `json:"transportReady"`
	TransportMode      string `json:"transportMode"`
	LastSeenUnix       int64  `json:"lastSeenUnix"`
	LastSignaledAtUnix int64  `json:"lastSignaledAtUnix"`
}

type ConnectionStatus struct {
	NetworkID                string   `json:"networkId"`
	LocalPeerID              string   `json:"localPeerId"`
	RemotePeerID             string   `json:"remotePeerId"`
	RemoteUserID             string   `json:"remoteUserId,omitempty"`
	RemoteVirtualIP          string   `json:"remoteVirtualIp"`
	RemoteEndpoint           string   `json:"remoteEndpoint"`
	RemoteCandidateCount     int      `json:"remoteCandidateCount"`
	RemoteCandidates         []string `json:"remoteCandidates"`
	Reachability             string   `json:"reachability"`
	State                    string   `json:"state"`
	SelectedCandidate        string   `json:"selectedCandidate"`
	AttemptCount             int      `json:"attemptCount"`
	LastAttemptUnix          int64    `json:"lastAttemptUnix"`
	NextRetryUnix            int64    `json:"nextRetryUnix"`
	LastError                string   `json:"lastError"`
	TunnelID                 string   `json:"tunnelId"`
	TunnelMode               string   `json:"tunnelMode"`
	TunnelState              string   `json:"tunnelState"`
	TransportReady           bool     `json:"transportReady"`
	TransportMode            string   `json:"transportMode"`
	TransportSessionID       string   `json:"transportSessionId"`
	TransportEstablishedUnix int64    `json:"transportEstablishedUnix"`
	TransportPacketCount     int      `json:"transportPacketCount"`
	TransportRekeyDueUnix    int64    `json:"transportRekeyDueUnix"`
	LastTransportUnix        int64    `json:"lastTransportUnix"`
	LastKeepaliveUnix        int64    `json:"lastKeepaliveUnix"`
	LastRTTMillis            int64    `json:"lastRttMillis"`
	AverageRTTMillis         int64    `json:"averageRttMillis"`
	ConsecutiveLosses        int      `json:"consecutiveLosses"`
	GroupTrafficPacketCopies int      `json:"groupTrafficPacketCopies,omitempty"`
	GroupBroadcastCopies     int      `json:"groupBroadcastCopies,omitempty"`
	GroupMulticastCopies     int      `json:"groupMulticastCopies,omitempty"`
	LastGroupTrafficUnix     int64    `json:"lastGroupTrafficUnix,omitempty"`
}

type DirectConnectMetrics struct {
	AttemptCount         int    `json:"attemptCount,omitempty"`
	SuccessCount         int    `json:"successCount,omitempty"`
	FailureCount         int    `json:"failureCount,omitempty"`
	RelayFallbackCount   int    `json:"relayFallbackCount,omitempty"`
	FailbackSuccessCount int    `json:"failbackSuccessCount,omitempty"`
	SuccessRatePct       int    `json:"successRatePct,omitempty"`
	LastAttemptUnix      int64  `json:"lastAttemptUnix,omitempty"`
	LastSuccessUnix      int64  `json:"lastSuccessUnix,omitempty"`
	LastFailureUnix      int64  `json:"lastFailureUnix,omitempty"`
	LastFallbackUnix     int64  `json:"lastFallbackUnix,omitempty"`
	LastFailbackUnix     int64  `json:"lastFailbackUnix,omitempty"`
	LastSuccessCandidate string `json:"lastSuccessCandidate,omitempty"`
}

type SetConfigRequest struct {
	ServerBaseURL string `json:"serverBaseUrl"`
}

type SetAdapterMTURequest struct {
	MTU int `json:"mtu"`
}

type SetUpdateChannelRequest struct {
	Channel string `json:"channel"`
}

type SaveAuditPresetRequest struct {
	Name        string `json:"name"`
	ActorUserID string `json:"actorUserId"`
	Type        string `json:"type"`
	Query       string `json:"query"`
	FromUnix    int64  `json:"fromUnix"`
	ToUnix      int64  `json:"toUnix"`
}

func (r SaveAuditPresetRequest) Filter() controlclient.AuditEventFilter {
	return controlclient.AuditEventFilter{
		ActorUserID: strings.TrimSpace(r.ActorUserID),
		Type:        strings.TrimSpace(r.Type),
		Query:       strings.TrimSpace(r.Query),
		FromUnix:    r.FromUnix,
		ToUnix:      r.ToUnix,
	}
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RejoinNetworkRequest struct {
	Endpoint string `json:"endpoint"`
}

type CreateNetworkRequest struct {
	Name                   string `json:"name"`
	Access                 string `json:"access"`
	DeviceApprovalRequired bool   `json:"deviceApprovalRequired"`
	RoutingPolicy          string `json:"routingPolicy"`
	GroupTrafficPolicy     string `json:"groupTrafficPolicy"`
	NameResolutionMode     string `json:"nameResolutionMode"`
	DNSLabel               string `json:"dnsLabel"`
	FileTransfersEnabled   bool   `json:"fileTransfersEnabled"`
	FileTransferMaxBytes   int64  `json:"fileTransferMaxBytes"`
}

type UpdateNetworkRoutingPolicyRequest struct {
	Policy string `json:"policy"`
}

type UpdateNetworkGroupTrafficPolicyRequest struct {
	Policy string `json:"policy"`
}

type UpdateNetworkNameResolutionRequest struct {
	Mode     string `json:"mode"`
	DNSLabel string `json:"dnsLabel"`
}

type UpdateNetworkFileTransferPolicyRequest struct {
	Enabled  bool  `json:"enabled"`
	MaxBytes int64 `json:"maxBytes"`
}

type RedeemInviteRequest struct {
	Code string `json:"code"`
}

type CreateInviteRequest struct {
	TTLSec  int `json:"ttlSec"`
	MaxUses int `json:"maxUses"`
}

type RegisterPeerRequest struct {
	Endpoint string `json:"endpoint"`
}

type CreateMessageRequest struct {
	FromPeerID string `json:"fromPeerId"`
	Text       string `json:"text"`
}

type CreateFileTransferRequest struct {
	FromPeerID string `json:"fromPeerId"`
	ToPeerID   string `json:"toPeerId"`
	FileName   string `json:"fileName"`
	SizeBytes  int64  `json:"sizeBytes"`
}

type UploadFileTransferContentRequest struct {
	ContentType   string `json:"contentType"`
	PayloadBase64 string `json:"payloadBase64"`
}

type UploadFileTransferContentChunkRequest struct {
	ContentType   string `json:"contentType"`
	PayloadBase64 string `json:"payloadBase64"`
	OffsetBytes   int64  `json:"offsetBytes"`
}

type RegisterFileTransferSourceRequest struct {
	SourcePath  string `json:"sourcePath"`
	ContentType string `json:"contentType"`
}

type PatchFileTransferRequest struct {
	Action          string `json:"action"`
	Reason          string `json:"reason"`
	ProgressPercent int    `json:"progressPercent"`
}

type CreateTunnelRequest struct {
	PeerAID string `json:"peerAId"`
	PeerBID string `json:"peerBId"`
}

type Agent struct {
	recoveryPaused           atomic.Pointer[recoveryPause]
	outboundPump             *outboundPacketPump
	packetPumpsClosed        atomic.Bool
	inboundPump              *inboundPacketPump
	forwardingRoutes         atomic.Pointer[forwardingRoutes]
	forwardingPolicy         *forwardingPolicySnapshot // Protected by mu.
	transportCredentials     map[string]cachedTransportCredentials
	mu                       sync.Mutex
	logsMu                   sync.Mutex
	remote                   *controlclient.Client
	listenAddress            string
	startedAt                time.Time
	currentUser              *controlclient.User
	currentSession           *controlclient.Session
	currentDevice            *controlclient.Device
	stateStore               *StateStore
	deviceState              *PersistentState
	stateErr                 error
	runtime                  RuntimeConfig
	adapterManager           virtualadapter.Manager
	directManager            directprobe.Manager
	relayManager             relaytransport.Manager
	overlayDNS               overlaydns.Manager
	discoveredPeers          map[string][]controlclient.Peer
	neighbors                []NeighborStatus
	connections              []ConnectionStatus
	directAttempts           map[string]DirectAttemptState
	fileTransferSources      map[string]localFileTransferSource
	fileTransferCaches       map[string]localFileTransferCache
	groupTrafficDiagnostics  map[string]GroupTrafficDiagnostics
	gatewaySelections        map[string]gatewaySelectionState
	gatewayHistory           []GatewayChangeEvent
	gatewayHistoryLimit      int
	logs                     []LogEntry
	logCapacity              int
	securityDiagnostics      SecurityDiagnostics
	incidentSummary          IncidentSummary
	updateStatus             UpdateStatus
	lastSessionRefreshAt     time.Time
	lastReconnectAttemptAt   time.Time
	nextReconnectAttemptAt   time.Time
	lastCleanShutdownAt      time.Time
	lastCrashRecoveryAt      time.Time
	lastSecurityRefreshAt    time.Time
	lastIncidentRefreshAt    time.Time
	lastHeartbeatAt          time.Time
	lastPeerDiscoveryAt      time.Time
	lastFileTransferMirrorAt time.Time
	lastSTUNProbeAt          time.Time
	lastDirectProbeAt        time.Time
	lastUpdateCheckAt        time.Time
	uncleanShutdownDetected  bool
	crashRecoveryCount       int
	reconnectAttemptCount    int
	lastReconnectError       string
	lastLifecycleError       string
	serverVersion            string
	minClientVersion         string
	compatibilityStatus      string
	compatibilityMessage     string
	directMetrics            DirectConnectMetrics
	activeRelayServer        string
	relayFailoverCount       int
	natType                  string
	publicEndpoint           string
	localSTUNEndpoint        string
	lifecycleCancel          context.CancelFunc
	lifecycleStopped         chan struct{}
}

type gatewaySelectionState struct {
	NetworkID          string
	GatewayRole        string
	GatewayPeerID      string
	GatewayUserID      string
	GatewayVirtualIP   string
	GatewayEndpointKey string
	GatewayTargetRole  string
	Path               string
	PolicyStatus       string
}

type directSTUNProber interface {
	ProbeSTUN(localPeerID, serverAddress string, timeout time.Duration) (stun.ProbeResult, error)
}

type DirectAttemptState struct {
	AttemptCount             int
	LastAttemptAt            time.Time
	NextAttemptAt            time.Time
	NextFailbackAt           time.Time
	LastError                string
	LocalEndpoint            string
	RemoteEndpointKey        string
	SelectedCandidate        string
	DirectReady              bool
	TransportMode            string
	TransportSessionID       string
	TransportStartedAt       time.Time
	TransportPacketCount     int
	LastTransportAt          time.Time
	LastKeepaliveAt          time.Time
	LastRTT                  time.Duration
	AverageRTT               time.Duration
	ConsecutiveLosses        int
	GroupTrafficPacketCopies int
	GroupBroadcastCopies     int
	GroupMulticastCopies     int
	LastGroupTrafficAt       time.Time
}

type localFileTransferSource struct {
	TransferID     string
	NetworkID      string
	LocalPeerID    string
	RemotePeerID   string
	RemoteUserID   string
	SourcePath     string
	FileName       string
	ContentType    string
	PayloadSHA256  string
	SizeBytes      int64
	UploadedAtUnix int64
}

type localFileTransferCache struct {
	TransferID     string
	NetworkID      string
	LocalPeerID    string
	RemotePeerID   string
	CachePath      string
	FileName       string
	ContentType    string
	PayloadSHA256  string
	SizeBytes      int64
	CachedBytes    int64
	UploadedAtUnix int64
}

type dataplaneFileTransferChunk struct {
	*controlclient.FileTransferContentChunk
	LocalPeerID  string
	RemotePeerID string
}

type FileTransferLocalState struct {
	TransferID             string `json:"transferId"`
	SenderSourceRegistered bool   `json:"senderSourceRegistered"`
	SenderSourceAvailable  bool   `json:"senderSourceAvailable"`
	SenderSourcePath       string `json:"senderSourcePath,omitempty"`
	SenderSourceSizeBytes  int64  `json:"senderSourceSizeBytes,omitempty"`
	ReceiverCacheAvailable bool   `json:"receiverCacheAvailable"`
	ReceiverCachePath      string `json:"receiverCachePath,omitempty"`
	ReceiverCachedBytes    int64  `json:"receiverCachedBytes,omitempty"`
	ReceiverCacheSizeBytes int64  `json:"receiverCacheSizeBytes,omitempty"`
	ReceiverCacheComplete  bool   `json:"receiverCacheComplete"`
}

type fileTransferDataplaneRequest struct {
	Type        string `json:"type"`
	TransferID  string `json:"transferId"`
	OffsetBytes int64  `json:"offsetBytes"`
	LimitBytes  int64  `json:"limitBytes"`
}

type fileTransferDataplaneResponse struct {
	Type            string `json:"type"`
	Error           string `json:"error,omitempty"`
	ContentType     string `json:"contentType,omitempty"`
	SHA256          string `json:"sha256,omitempty"`
	Payload         []byte `json:"payload,omitempty"`
	OffsetBytes     int64  `json:"offsetBytes"`
	NextOffsetBytes int64  `json:"nextOffsetBytes"`
	TotalSizeBytes  int64  `json:"totalSizeBytes"`
	UploadedAtUnix  int64  `json:"uploadedAtUnix,omitempty"`
	Complete        bool   `json:"complete"`
}

func DefaultRuntimeConfig() RuntimeConfig {
	return normalizeRuntimeConfig(RuntimeConfig{
		LifecycleInterval:         time.Second,
		SessionRefreshSkew:        5 * time.Minute,
		SecurityDiagnosticsPeriod: 30 * time.Second,
		ReconnectRetryBase:        time.Second,
		ReconnectRetryMax:         time.Minute,
		UpdateCheckPeriod:         6 * time.Hour,
		UpdateChannel:             updateChannelStable,
		OverlayDNSDomain:          "",
		OverlayDNSListenAddress:   "",
		HeartbeatInterval:         10 * time.Second,
		PeerDiscoveryPeriod:       10 * time.Second,
		FileTransferMirrorPeriod:  30 * time.Second,
		STUNProbePeriod:           10 * time.Second,
		RelayFailbackPeriod:       10 * time.Second,
		TransportKeepalive:        5 * time.Second,
		TransportLossLimit:        3,
		DirectProbeTimeout:        300 * time.Millisecond,
		DirectRetryBase:           time.Second,
		DirectRetryMax:            30 * time.Second,
		DirectMaxAttempts:         5,
		TransportSessionTTL:       10 * time.Minute,
		TransportRekeyAfter:       4096,
	})
}

func normalizeRuntimeConfig(config RuntimeConfig) RuntimeConfig {
	if config.LifecycleInterval <= 0 {
		config.LifecycleInterval = time.Second
	}
	if config.SessionRefreshSkew <= 0 {
		config.SessionRefreshSkew = 5 * time.Minute
	}
	if config.SecurityDiagnosticsPeriod <= 0 {
		config.SecurityDiagnosticsPeriod = 30 * time.Second
	}
	if config.ReconnectRetryBase <= 0 {
		config.ReconnectRetryBase = time.Second
	}
	if config.ReconnectRetryMax <= 0 {
		config.ReconnectRetryMax = time.Minute
	}
	if config.ReconnectRetryMax < config.ReconnectRetryBase {
		config.ReconnectRetryMax = config.ReconnectRetryBase
	}
	if config.UpdateCheckPeriod <= 0 {
		config.UpdateCheckPeriod = 6 * time.Hour
	}
	config.UpdateChannel = normalizeUpdateChannel(config.UpdateChannel)
	config.UpdateManifestURL = strings.TrimSpace(config.UpdateManifestURL)
	config.UpdateStableManifestURL = strings.TrimSpace(config.UpdateStableManifestURL)
	config.UpdateBetaManifestURL = strings.TrimSpace(config.UpdateBetaManifestURL)
	if config.UpdateStableManifestURL == "" && config.UpdateManifestURL != "" {
		config.UpdateStableManifestURL = config.UpdateManifestURL
	}
	config.UpdateDownloadDir = strings.TrimSpace(config.UpdateDownloadDir)
	if config.UpdateDownloadDir == "" {
		config.UpdateDownloadDir = autoupdate.DefaultDownloadDir()
	}
	config.OverlayDNSListenAddress = strings.TrimSpace(config.OverlayDNSListenAddress)
	config.OverlayDNSDomain = strings.Trim(strings.ToLower(strings.TrimSpace(config.OverlayDNSDomain)), ".")
	if config.HeartbeatInterval <= 0 {
		config.HeartbeatInterval = 10 * time.Second
	}
	if config.PeerDiscoveryPeriod <= 0 {
		config.PeerDiscoveryPeriod = 10 * time.Second
	}
	if config.FileTransferMirrorPeriod <= 0 {
		config.FileTransferMirrorPeriod = 30 * time.Second
	}
	config.STUNServerAddress = strings.TrimSpace(config.STUNServerAddress)
	config.RelayServerAddress = strings.Join(parseRelayServerAddresses(config.RelayServerAddress), ",")
	if config.STUNProbePeriod <= 0 {
		config.STUNProbePeriod = 10 * time.Second
	}
	if config.RelayFailbackPeriod <= 0 {
		config.RelayFailbackPeriod = 10 * time.Second
	}
	if config.TransportKeepalive <= 0 {
		config.TransportKeepalive = 5 * time.Second
	}
	if config.TransportLossLimit <= 0 {
		config.TransportLossLimit = 3
	}
	if config.DirectProbeTimeout <= 0 {
		config.DirectProbeTimeout = 300 * time.Millisecond
	}
	if config.DirectRetryBase <= 0 {
		config.DirectRetryBase = time.Second
	}
	if config.DirectRetryMax <= 0 {
		config.DirectRetryMax = 30 * time.Second
	}
	if config.DirectRetryMax < config.DirectRetryBase {
		config.DirectRetryMax = config.DirectRetryBase
	}
	if config.DirectMaxAttempts <= 0 {
		config.DirectMaxAttempts = 5
	}
	if config.TransportSessionTTL <= 0 {
		config.TransportSessionTTL = 10 * time.Minute
	}
	if config.TransportRekeyAfter <= 0 {
		config.TransportRekeyAfter = 4096
	}
	return config
}

func New() *Agent {
	return NewWithClient(nil, DefaultListenAddress)
}

func NewWithClient(remote *controlclient.Client, listenAddress string) *Agent {
	return NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(remote, listenAddress, NewStateStore(""), DefaultRuntimeConfig(), virtualadapter.NewDefaultManager(), directprobe.New(), relaytransport.New())
}

func NewWithClientAndStore(remote *controlclient.Client, listenAddress string, stateStore *StateStore) *Agent {
	return NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(remote, listenAddress, stateStore, DefaultRuntimeConfig(), virtualadapter.NewDefaultManager(), directprobe.New(), relaytransport.New())
}

func NewWithClientAndStoreAndRuntime(remote *controlclient.Client, listenAddress string, stateStore *StateStore, runtime RuntimeConfig) *Agent {
	return NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(remote, listenAddress, stateStore, runtime, virtualadapter.NewDefaultManager(), directprobe.New(), relaytransport.New())
}

func NewWithClientAndStoreAndRuntimeAndAdapter(remote *controlclient.Client, listenAddress string, stateStore *StateStore, runtime RuntimeConfig, adapterManager virtualadapter.Manager) *Agent {
	return NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(remote, listenAddress, stateStore, runtime, adapterManager, directprobe.New(), relaytransport.New())
}

func NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(remote *controlclient.Client, listenAddress string, stateStore *StateStore, runtime RuntimeConfig, adapterManager virtualadapter.Manager, directManager directprobe.Manager) *Agent {
	return NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(remote, listenAddress, stateStore, runtime, adapterManager, directManager, relaytransport.New())
}

func NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(remote *controlclient.Client, listenAddress string, stateStore *StateStore, runtime RuntimeConfig, adapterManager virtualadapter.Manager, directManager directprobe.Manager, relayManager relaytransport.Manager) *Agent {
	if remote == nil {
		remote = controlclient.New(DefaultServerBaseURL)
	}
	if strings.TrimSpace(remote.BaseURL()) == "" {
		remote.SetBaseURL(DefaultServerBaseURL)
	}
	if strings.TrimSpace(listenAddress) == "" {
		listenAddress = DefaultListenAddress
	}
	if stateStore == nil {
		stateStore = NewStateStore("")
	}
	if adapterManager == nil {
		adapterManager = virtualadapter.NewDefaultManager()
	}
	if directManager == nil {
		directManager = directprobe.New()
	}
	if relayManager == nil {
		relayManager = relaytransport.New()
	}
	deviceState, stateErr := stateStore.Load()
	normalizedRuntime := normalizeRuntimeConfig(runtime)
	dnsManager := overlaydns.New(normalizedRuntime.OverlayDNSListenAddress, normalizedRuntime.OverlayDNSDomain)
	agent := &Agent{
		remote:              remote,
		listenAddress:       listenAddress,
		startedAt:           time.Now(),
		stateStore:          stateStore,
		deviceState:         deviceState,
		stateErr:            stateErr,
		runtime:             normalizedRuntime,
		adapterManager:      adapterManager,
		directManager:       directManager,
		relayManager:        relayManager,
		overlayDNS:          dnsManager,
		discoveredPeers:     map[string][]controlclient.Peer{},
		neighbors:           []NeighborStatus{},
		directAttempts:      map[string]DirectAttemptState{},
		fileTransferSources: map[string]localFileTransferSource{},
		fileTransferCaches:  map[string]localFileTransferCache{},
		gatewaySelections:   map[string]gatewaySelectionState{},
		gatewayHistoryLimit: defaultGatewayHistoryLimit,
		logCapacity:         defaultLogCapacity,
		updateStatus: UpdateStatus{
			Channel:           normalizedRuntime.UpdateChannel,
			AvailableChannels: availableUpdateChannelsForRuntime(normalizedRuntime),
			ManifestURL:       resolveUpdateManifestURLForRuntime(normalizedRuntime, normalizedRuntime.UpdateChannel),
			CurrentVersion:    remote.ClientVersion(),
			CheckPeriodSec:    int64(normalizedRuntime.UpdateCheckPeriod / time.Second),
		},
	}
	remote.SetRequestObserver(agent.observeControlPlaneTrace)
	agent.mu.Lock()
	agent.initializeLifecycleStateLocked()
	agent.logInfow("agent.initialized", "agent initialized", "listenAddress", listenAddress, "statePath", agent.statePathLocked())
	agent.mu.Unlock()
	agent.startInboundPacketPump()
	agent.startOutboundPacketPump()
	agent.startLifecycleLoop()
	return agent
}

func (a *Agent) Close() error {
	a.packetPumpsClosed.Store(true)
	if snapshot := a.forwardingRoutes.Load(); snapshot != nil {
		snapshot.valid.Store(false)
	}
	a.outboundPump.stop()
	a.inboundPump.stop()
	a.mu.Lock()
	a.invalidateForwardingRoutesLocked()
	a.mergeInboundReportsLocked()
	a.mergeOutboundReportsLocked(false)
	cancel := a.lifecycleCancel
	stopped := a.lifecycleStopped
	a.lifecycleCancel = nil
	a.lifecycleStopped = nil
	a.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if stopped != nil {
		<-stopped
	}
	var closeErr error
	a.mu.Lock()
	if state, err := a.ensurePersistentStateLocked(); err != nil {
		if closeErr == nil {
			closeErr = err
		}
		a.logErrorf("persist service shutdown lifecycle failed: %v", err)
	} else {
		state.MarkServiceStopped(time.Now().Unix())
		a.lastCleanShutdownAt = time.Unix(state.Lifecycle.LastCleanShutdownUnix, 0)
		a.uncleanShutdownDetected = false
		if err := a.savePersistentStateLocked(); err != nil {
			if closeErr == nil {
				closeErr = err
			}
			a.logErrorf("persist service shutdown lifecycle failed: %v", err)
		}
	}
	a.mu.Unlock()
	if a.directManager != nil {
		if err := a.directManager.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	if a.relayManager != nil {
		if err := a.relayManager.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	if a.adapterManager != nil {
		if err := a.adapterManager.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	if a.overlayDNS != nil {
		if err := a.overlayDNS.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

func (a *Agent) Restore() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	err := a.restoreSessionLocked()
	if err != nil {
		a.recordReconnectFailureLocked(time.Now(), err)
		a.logErrorw("session.restore.failed", "restore failed", "error", err, "serverBaseURL", a.remote.BaseURL())
	} else if a.currentSession != nil && a.currentUser != nil {
		a.clearReconnectBackoffLocked()
		a.logInfow("session.restore.succeeded", "restore succeeded", "email", a.currentUser.Email, "userId", a.currentUser.ID)
	}
	return err
}

func (a *Agent) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mergeInboundReportsLocked()
	a.mergeOutboundReportsLocked(false)
	return a.snapshotLocked()
}

func (a *Agent) SetServerBaseURL(baseURL string) Status {
	a.mu.Lock()
	defer a.mu.Unlock()

	normalized := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if normalized == "" {
		normalized = DefaultServerBaseURL
	}
	if normalized != a.remote.BaseURL() {
		a.remote.SetBaseURL(normalized)
		a.clearInMemorySessionLocked()
		a.logInfof("server base URL set to %s", normalized)
	}
	if err := a.refreshCompatibilityLocked(); err != nil {
		a.compatibilityStatus = versioninfo.StatusUnknown
		a.compatibilityMessage = err.Error()
		a.logErrorf("compatibility check failed: %v", err)
	}
	if err := a.restoreSessionLocked(); err != nil {
		a.recordReconnectFailureLocked(time.Now(), err)
		a.logErrorf("restore after server base URL change failed: %v", err)
	}
	return a.snapshotLocked()
}

func (a *Agent) SetAdapterMTU(mtu int) (Status, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if mtu < 576 || mtu > transportauth.MaxMessageBytes {
		return Status{}, fmt.Errorf("adapter MTU must be between 576 and %d", transportauth.MaxMessageBytes)
	}
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return Status{}, err
	}
	state.AdapterMTU = mtu
	if err := a.savePersistentStateLocked(); err != nil {
		a.logErrorf("persist adapter MTU failed: %v", err)
		return Status{}, err
	}
	if err := a.reconcileManagedRuntimeLocked(); err != nil {
		a.logErrorf("reconcile adapter MTU failed: %v", err)
		return Status{}, err
	}
	a.logInfof("adapter MTU set to %d", mtu)
	return a.snapshotLocked(), nil
}

func (a *Agent) SetUpdateChannel(channel string) (Status, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	resolved := normalizeUpdateChannel(channel)
	if !containsString(availableUpdateChannelsForRuntime(a.runtime), resolved) {
		return Status{}, fmt.Errorf("update channel %s is not configured", resolved)
	}
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return Status{}, err
	}
	state.SetUpdateChannel(resolved)
	if err := a.savePersistentStateLocked(); err != nil {
		return Status{}, err
	}
	a.lastUpdateCheckAt = time.Time{}
	a.updateStatus = UpdateStatus{
		Channel:           resolved,
		AvailableChannels: availableUpdateChannelsForRuntime(a.runtime),
		ManifestURL:       a.resolveUpdateManifestURLLocked(),
		CurrentVersion:    a.remote.ClientVersion(),
		CheckPeriodSec:    int64(a.runtime.UpdateCheckPeriod / time.Second),
	}
	a.logInfow("update.channel.changed", "update channel changed", "channel", resolved, "manifestURL", a.updateStatus.ManifestURL)
	return a.snapshotLocked(), nil
}

func (a *Agent) CheckForUpdates() (Status, error) {
	a.mu.Lock()
	if a.updateStatus.Checking {
		status := a.snapshotLocked()
		a.mu.Unlock()
		return status, errors.New("update check is already running")
	}
	a.updateStatus.Checking = true
	a.updateStatus.Channel = a.resolveUpdateChannelLocked()
	a.updateStatus.AvailableChannels = availableUpdateChannelsForRuntime(a.runtime)
	a.updateStatus.ManifestURL = a.resolveUpdateManifestURLLocked()
	a.updateStatus.CurrentVersion = a.remote.ClientVersion()
	channel := a.resolveUpdateChannelLocked()
	manifestURL := a.resolveUpdateManifestURLLocked()
	currentVersion := a.remote.ClientVersion()
	a.mu.Unlock()

	result, err := a.checkForUpdatesNow(manifestURL, currentVersion)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.applyUpdateCheckResultLocked(channel, manifestURL, result, err)
	if err != nil {
		a.logErrorw("update.check.failed", "update check failed", "error", err, "channel", channel, "manifestURL", manifestURL)
		return a.snapshotLocked(), err
	}
	a.logInfow("update.check.completed", "update check completed", "channel", channel, "manifestURL", manifestURL, "available", result.Available, "latestVersion", result.Manifest.Version)
	return a.snapshotLocked(), nil
}

func (a *Agent) DownloadUpdate() (Status, error) {
	a.mu.Lock()
	channel := a.resolveUpdateChannelLocked()
	manifestURL := a.resolveUpdateManifestURLLocked()
	currentVersion := a.remote.ClientVersion()
	downloadDir := a.runtime.UpdateDownloadDir
	knownAvailable := a.updateStatus.Available && strings.TrimSpace(a.updateStatus.InstallerURL) != ""
	knownManifest := autoupdate.Manifest{
		Version:         a.updateStatus.LatestVersion,
		PublishedAtUnix: a.updateStatus.PublishedAtUnix,
		InstallerURL:    a.updateStatus.InstallerURL,
		SHA256:          a.updateStatus.SHA256,
		ReleaseNotesURL: a.updateStatus.ReleaseNotesURL,
		SignatureURL:    a.updateStatus.SignatureURL,
		CertificateURL:  a.updateStatus.CertificateURL,
	}
	a.mu.Unlock()

	if !knownAvailable {
		result, err := a.checkForUpdatesNow(manifestURL, currentVersion)
		a.mu.Lock()
		a.applyUpdateCheckResultLocked(channel, manifestURL, result, err)
		status := a.snapshotLocked()
		a.mu.Unlock()
		if err != nil {
			a.logErrorw("update.download.check_failed", "update preflight check failed", "error", err, "channel", channel, "manifestURL", manifestURL)
			return status, err
		}
		if !result.Available {
			return status, errors.New("no update is currently available")
		}
		knownManifest = result.Manifest
	}
	if updatePolicyBlocked(a.updateStatus.PolicyStatus) {
		a.mu.Lock()
		status := a.snapshotLocked()
		message := a.updateStatus.PolicyMessage
		a.mu.Unlock()
		return status, errors.New(message)
	}

	client := autoupdate.NewClient(manifestURL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	path, err := client.DownloadInstaller(ctx, knownManifest, downloadDir)

	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.updateStatus.LastError = err.Error()
		a.logErrorw("update.download.failed", "update download failed", "error", err, "channel", channel, "installerURL", knownManifest.InstallerURL)
		return a.snapshotLocked(), err
	}
	a.updateStatus.Downloaded = true
	a.updateStatus.DownloadedPath = path
	a.updateStatus.LastDownloadedUnix = time.Now().Unix()
	a.updateStatus.LastError = ""
	a.logInfow("update.download.completed", "update download completed", "channel", channel, "path", path, "latestVersion", knownManifest.Version)
	return a.snapshotLocked(), nil
}

func (a *Agent) DownloadRollback() (Status, error) {
	a.mu.Lock()
	channel := a.resolveUpdateChannelLocked()
	manifestURL := a.resolveUpdateManifestURLLocked()
	currentVersion := a.remote.ClientVersion()
	downloadDir := a.runtime.UpdateDownloadDir
	rollback := autoupdate.Release{
		Version:         a.updateStatus.RollbackVersion,
		InstallerURL:    a.updateStatus.RollbackInstallerURL,
		SHA256:          a.updateStatus.RollbackSHA256,
		SignatureURL:    a.updateStatus.RollbackSignatureURL,
		CertificateURL:  a.updateStatus.RollbackCertificateURL,
		ReleaseNotesURL: a.updateStatus.RollbackReleaseNotesURL,
		Reason:          a.updateStatus.RollbackReason,
	}
	knownManifest := autoupdate.Manifest{
		Version:         a.updateStatus.LatestVersion,
		PublishedAtUnix: a.updateStatus.PublishedAtUnix,
		InstallerURL:    a.updateStatus.InstallerURL,
		SHA256:          a.updateStatus.SHA256,
		ReleaseNotesURL: a.updateStatus.ReleaseNotesURL,
		SignatureURL:    a.updateStatus.SignatureURL,
		CertificateURL:  a.updateStatus.CertificateURL,
		Rollback:        &rollback,
	}
	needRefresh := !a.updateStatus.RollbackAvailable || strings.TrimSpace(a.updateStatus.RollbackInstallerURL) == ""
	a.mu.Unlock()

	if needRefresh {
		result, err := a.checkForUpdatesNow(manifestURL, currentVersion)
		a.mu.Lock()
		a.applyUpdateCheckResultLocked(channel, manifestURL, result, err)
		status := a.snapshotLocked()
		a.mu.Unlock()
		if err != nil {
			a.logErrorw("update.rollback.check_failed", "rollback preflight check failed", "error", err, "channel", channel, "manifestURL", manifestURL)
			return status, err
		}
		if !status.Update.RollbackAvailable {
			return status, errors.New("no rollback release is available")
		}
		knownManifest = result.Manifest
	}

	client := autoupdate.NewClient(manifestURL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	path, err := client.DownloadRollback(ctx, knownManifest, downloadDir)

	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.updateStatus.LastError = err.Error()
		a.logErrorw("update.rollback.download_failed", "rollback download failed", "error", err, "channel", channel, "installerURL", knownManifest.Rollback.InstallerURL)
		return a.snapshotLocked(), err
	}
	a.updateStatus.RollbackDownloaded = true
	a.updateStatus.RollbackDownloadedPath = path
	a.updateStatus.RollbackLastDownloadedUnix = time.Now().Unix()
	a.updateStatus.LastError = ""
	a.logInfow("update.rollback.download_completed", "rollback download completed", "channel", channel, "path", path, "rollbackVersion", knownManifest.Rollback.Version)
	return a.snapshotLocked(), nil
}

func (a *Agent) Reconnect() (Status, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	a.lastReconnectAttemptAt = now
	if err := a.restoreSessionLocked(); err != nil {
		a.recordReconnectFailureLocked(now, err)
		a.logErrorw("session.reconnect.manual_failed", "manual reconnect failed", "error", err, "serverBaseURL", a.remote.BaseURL())
		return Status{}, err
	}
	if a.currentSession == nil || a.currentUser == nil {
		err := fmt.Errorf("no persisted session is available to reconnect")
		a.recordReconnectFailureLocked(now, err)
		a.logErrorw("session.reconnect.manual_failed", "manual reconnect failed", "error", err, "serverBaseURL", a.remote.BaseURL())
		return Status{}, err
	}
	a.clearReconnectBackoffLocked()
	a.logInfow("session.reconnect.manual_succeeded", "manual reconnect completed", "email", a.currentUser.Email, "userId", a.currentUser.ID)
	return a.snapshotLocked(), nil
}

func (a *Agent) Register(email, password string) (*controlclient.User, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	user, err := a.remote.Register(email, password)
	if err != nil {
		a.logErrorf("user registration failed for %s: %v", email, err)
		return nil, err
	}
	a.logInfof("user registered: %s", user.Email)
	return user, nil
}

func (a *Agent) Login(email, password string) (Status, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := a.ensureCompatibleLocked(); err != nil {
		a.logErrorf("compatibility gate blocked login for %s: %v", email, err)
		return Status{}, err
	}
	session, err := a.remote.Login(email, password)
	if err != nil {
		a.logErrorf("login failed for %s: %v", email, err)
		return Status{}, err
	}
	user, err := a.remote.GetUser(session.UserID)
	if err != nil {
		a.remote.ClearAccessToken()
		a.logErrorf("load current user after login failed for %s: %v", email, err)
		return Status{}, err
	}

	a.currentSession = cloneSession(session)
	a.currentUser = cloneUser(user)
	device, err := a.ensureCurrentDeviceLocked()
	if err != nil {
		a.clearInMemorySessionLocked()
		a.logErrorf("device enrollment after login failed for %s: %v", email, err)
		return Status{}, err
	}
	a.currentDevice = cloneDevice(device)
	if err := a.persistCurrentSessionLocked(); err != nil {
		a.logErrorf("persist session after login failed for %s: %v", email, err)
		return Status{}, err
	}
	a.clearReconnectBackoffLocked()
	a.lastLifecycleError = ""
	if err := a.refreshSecurityDiagnosticsLocked(time.Now()); err != nil {
		a.lastLifecycleError = err.Error()
		a.logErrorf("security diagnostics refresh after login failed for %s: %v", email, err)
	}
	if err := a.refreshIncidentSummaryLocked(time.Now()); err != nil {
		a.logErrorf("incident summary refresh after login failed for %s: %v", email, err)
	}
	a.logInfow("session.login.succeeded", "login succeeded", "email", email, "userId", a.currentUser.ID, "deviceId", firstNonEmptyString(device.ID, ""))
	return a.snapshotLocked(), nil
}

func (a *Agent) Logout() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	var logoutErr error
	_ = a.disconnectManagedPeersLocked(true)
	if a.currentSession != nil {
		logoutErr = a.remote.Logout(a.currentSession.AccessToken)
	}
	a.clearPersistentSessionLocked(true)
	if logoutErr != nil {
		a.logErrorf("logout failed: %v", logoutErr)
	} else {
		a.logInfow("session.logout.completed", "logout completed", "serverBaseURL", a.remote.BaseURL())
	}
	return logoutErr
}

func (a *Agent) ListSessions() ([]controlclient.Session, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sessions, err := a.remote.ListSessions()
	if err != nil {
		return nil, err
	}
	if err := a.refreshSecurityDiagnosticsWithSessionsLocked(sessions, time.Now()); err != nil {
		a.lastLifecycleError = err.Error()
		a.logErrorf("security diagnostics refresh after listing sessions failed: %v", err)
	}
	return sessions, nil
}

func (a *Agent) ListDevices() ([]controlclient.Device, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	devices, err := a.remote.ListDevices()
	if err != nil {
		return nil, err
	}
	return devices, nil
}

func (a *Agent) RevokeSession(sessionID string) (Status, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	sessions, err := a.remote.ListSessions()
	if err != nil {
		return Status{}, err
	}
	revokesCurrent := false
	for _, session := range sessions {
		if session.ID == sessionID && a.currentSession != nil && session.FamilyID == a.currentSession.FamilyID {
			revokesCurrent = true
			break
		}
	}
	if err := a.remote.RevokeSession(sessionID); err != nil {
		a.logErrorf("revoke session %s failed: %v", sessionID, err)
		return Status{}, err
	}
	if revokesCurrent {
		_ = a.disconnectManagedPeersLocked(true)
		a.clearPersistentSessionLocked(true)
	} else if err := a.refreshSecurityDiagnosticsLocked(time.Now()); err != nil {
		a.lastLifecycleError = err.Error()
		a.logErrorf("security diagnostics refresh after revoking session %s failed: %v", sessionID, err)
	}
	a.logInfof("session revoked: %s", sessionID)
	return a.snapshotLocked(), nil
}

func (a *Agent) RevokeAllSessions() (Status, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.currentSession == nil {
		return Status{}, errors.New("no active session is available")
	}
	if err := a.remote.RevokeAllSessions(); err != nil {
		a.logErrorf("revoke all sessions failed: %v", err)
		return Status{}, err
	}
	_ = a.disconnectManagedPeersLocked(true)
	a.clearPersistentSessionLocked(true)
	a.logInfof("all sessions revoked; current service session cleared")
	return a.snapshotLocked(), nil
}

func (a *Agent) ListAuditEvents(filter controlclient.AuditEventFilter) ([]controlclient.AuditEvent, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.remote.ListAuditEvents(filter)
}

func (a *Agent) ListIncidentReports() ([]controlclient.IncidentReport, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.remote.ListIncidentReports()
}

func (a *Agent) ListAuditPresets() ([]AuditFilterPreset, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, err := a.requireCurrentUserLocked()
	if err != nil {
		return nil, err
	}
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return nil, err
	}
	return state.AuditPresetsFor(a.remote.BaseURL(), user.ID), nil
}

func (a *Agent) SaveAuditPreset(name string, filter controlclient.AuditEventFilter) ([]AuditFilterPreset, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, err := a.requireCurrentUserLocked()
	if err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("audit preset name is required")
	}
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return nil, err
	}
	state.SetAuditPreset(a.remote.BaseURL(), user.ID, name, filter)
	if err := a.savePersistentStateLocked(); err != nil {
		a.logErrorf("save audit preset %s failed: %v", name, err)
		return nil, err
	}
	a.logInfof("audit preset saved: %s", name)
	return state.AuditPresetsFor(a.remote.BaseURL(), user.ID), nil
}

func (a *Agent) DeleteAuditPreset(name string) ([]AuditFilterPreset, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, err := a.requireCurrentUserLocked()
	if err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("audit preset name is required")
	}
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return nil, err
	}
	if !state.DeleteAuditPreset(a.remote.BaseURL(), user.ID, name) {
		return nil, fmt.Errorf("audit preset %s was not found", name)
	}
	if err := a.savePersistentStateLocked(); err != nil {
		a.logErrorf("delete audit preset %s failed: %v", name, err)
		return nil, err
	}
	a.logInfof("audit preset deleted: %s", name)
	return state.AuditPresetsFor(a.remote.BaseURL(), user.ID), nil
}

func (a *Agent) ListNetworks() ([]controlclient.Network, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.remote.ListNetworks()
}

func (a *Agent) CreateNetwork(name, access string) (*controlclient.Network, error) {
	return a.CreateNetworkWithPolicy(name, access, false)
}

func (a *Agent) CreateNetworkWithPolicy(name, access string, deviceApprovalRequired bool) (*controlclient.Network, error) {
	return a.CreateNetworkWithOptions(name, access, controlclient.NetworkCreateOptions{
		DeviceApprovalRequired:  deviceApprovalRequired,
		FileTransfersEnabledSet: true,
		FileTransfersEnabled:    true,
	})
}

func (a *Agent) CreateNetworkWithOptions(name, access string, options controlclient.NetworkCreateOptions) (*controlclient.Network, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, err := a.requireCurrentUserLocked()
	if err != nil {
		return nil, err
	}
	network, err := a.remote.CreateNetworkWithOptions(user.ID, name, access, options)
	if err != nil {
		a.logErrorf("create network failed for %s: %v", name, err)
		return nil, err
	}
	a.logInfof("network created: %s (%s)", network.Name, network.ID)
	return network, nil
}

func (a *Agent) UpdateNetworkGroupTrafficPolicy(networkID, policy string) (*controlclient.Network, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, err := a.requireCurrentUserLocked()
	if err != nil {
		return nil, err
	}
	a.invalidateForwardingRoutesLocked()
	a.forwardingPolicy = nil
	network, err := a.remote.UpdateNetworkGroupTrafficPolicy(networkID, policy)
	if err != nil {
		a.logErrorf("update group traffic policy failed for %s: %v", networkID, err)
		return nil, err
	}
	if err := a.reconcileManagedRuntimeLocked(); err != nil {
		a.logErrorf("reconcile managed runtime after group traffic policy update failed for %s: %v", networkID, err)
		return nil, err
	}
	a.logInfof("network group traffic policy updated: %s -> %s by %s", networkID, network.GroupTrafficPolicy, user.Email)
	return network, nil
}

func (a *Agent) UpdateNetworkNameResolution(networkID, mode, dnsLabel string) (*controlclient.Network, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireCurrentUserLocked(); err != nil {
		return nil, err
	}
	network, err := a.remote.UpdateNetworkNameResolution(networkID, mode, dnsLabel)
	if err != nil {
		a.logErrorf("update network name resolution failed for %s: %v", networkID, err)
		return nil, err
	}
	a.logInfof("network name resolution updated: %s -> %s (%s)", networkID, network.NameResolutionMode, network.DNSLabel)
	return network, nil
}

func (a *Agent) UpdateNetworkRoutingPolicy(networkID, policy string) (*controlclient.Network, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireCurrentUserLocked(); err != nil {
		return nil, err
	}
	a.invalidateForwardingRoutesLocked()
	a.forwardingPolicy = nil
	network, err := a.remote.UpdateNetworkRoutingPolicy(networkID, policy)
	if err != nil {
		a.logErrorf("update network routing policy failed for %s: %v", networkID, err)
		return nil, err
	}
	if err := a.reconcileManagedRuntimeLocked(); err != nil {
		a.logErrorf("reconcile managed runtime after routing policy update failed for %s: %v", networkID, err)
		return nil, err
	}
	a.logInfof("network routing policy updated: %s -> %s", networkID, network.RoutingPolicy)
	return network, nil
}

func (a *Agent) UpdateNetworkFileTransferPolicy(networkID string, enabled bool, maxBytes int64) (*controlclient.Network, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireCurrentUserLocked(); err != nil {
		return nil, err
	}
	network, err := a.remote.UpdateNetworkFileTransferPolicy(networkID, enabled, maxBytes)
	if err != nil {
		a.logErrorf("update network file transfer policy failed for %s: %v", networkID, err)
		return nil, err
	}
	a.logInfof("network file transfer policy updated: %s -> enabled=%t maxBytes=%d", networkID, network.FileTransfersEnabled, network.FileTransferMaxBytes)
	return network, nil
}

func (a *Agent) ApproveNetworkDevice(networkID, deviceID string) (*controlclient.Network, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireCurrentUserLocked(); err != nil {
		return nil, err
	}
	a.invalidateForwardingRoutesLocked()
	a.forwardingPolicy = nil
	network, err := a.remote.ApproveNetworkDevice(networkID, deviceID)
	if err != nil {
		a.logErrorf("approve device %s for network %s failed: %v", deviceID, networkID, err)
		return nil, err
	}
	a.logInfof("device approved for network: %s -> %s", deviceID, networkID)
	return network, nil
}

func (a *Agent) RevokeNetworkDeviceApproval(networkID, deviceID string) (*controlclient.Network, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireCurrentUserLocked(); err != nil {
		return nil, err
	}
	a.invalidateForwardingRoutesLocked()
	a.forwardingPolicy = nil
	network, err := a.remote.RevokeNetworkDeviceApproval(networkID, deviceID)
	if err != nil {
		a.logErrorf("revoke device approval %s for network %s failed: %v", deviceID, networkID, err)
		return nil, err
	}
	a.logInfof("device approval revoked for network: %s -> %s", deviceID, networkID)
	return network, nil
}

func (a *Agent) RedeemInvite(code string) (*controlclient.Network, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, err := a.requireCurrentUserLocked()
	if err != nil {
		return nil, err
	}
	network, err := a.remote.RedeemInvite(code, user.ID)
	if err != nil {
		a.logErrorf("redeem invite failed: %v", err)
		return nil, err
	}
	a.logInfof("invite redeemed into network %s", network.ID)
	return network, nil
}

func (a *Agent) CreateInvite(networkID string, ttlSec, maxUses int) (*controlclient.Invite, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, err := a.requireCurrentUserLocked()
	if err != nil {
		return nil, err
	}
	invite, err := a.remote.CreateInvite(networkID, user.ID, ttlSec, maxUses)
	if err != nil {
		a.logErrorf("create invite failed for network %s: %v", networkID, err)
		return nil, err
	}
	a.logInfof("invite created for network %s", networkID)
	return invite, nil
}

func (a *Agent) ListPeers(networkID string) ([]controlclient.Peer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.remote.ListPeers(networkID)
}

func (a *Agent) ListMessages(networkID string) ([]controlclient.Message, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.remote.ListMessages(networkID)
}

func (a *Agent) SendMessage(networkID, fromPeerID, text string) (*controlclient.Message, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireCurrentUserLocked(); err != nil {
		return nil, err
	}
	message, err := a.remote.SendMessage(networkID, fromPeerID, text)
	if err != nil {
		a.logErrorf("send message failed for network %s from peer %s: %v", networkID, fromPeerID, err)
		return nil, err
	}
	a.logInfof("message sent on network %s from peer %s", networkID, fromPeerID)
	return message, nil
}

func (a *Agent) ListFileTransfers(networkID string) ([]controlclient.FileTransfer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.remote.ListFileTransfers(networkID)
}

func (a *Agent) CreateFileTransfer(networkID, fromPeerID, toPeerID, fileName string, sizeBytes int64) (*controlclient.FileTransfer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireCurrentUserLocked(); err != nil {
		return nil, err
	}
	transfer, err := a.remote.CreateFileTransfer(networkID, fromPeerID, toPeerID, fileName, sizeBytes)
	if err != nil {
		a.logErrorf("create file transfer failed for network %s: %v", networkID, err)
		return nil, err
	}
	a.logInfof("file transfer created on network %s: %s", networkID, transfer.ID)
	return transfer, nil
}

func (a *Agent) GetFileTransfer(transferID string) (*controlclient.FileTransfer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireCurrentUserLocked(); err != nil {
		return nil, err
	}
	transfer, err := a.remote.GetFileTransfer(transferID)
	if err != nil {
		a.logErrorf("get file transfer %s failed: %v", transferID, err)
		return nil, err
	}
	return transfer, nil
}

func (a *Agent) GetFileTransferLocalState(transferID string) (*FileTransferLocalState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireCurrentUserLocked(); err != nil {
		return nil, err
	}
	localState := &FileTransferLocalState{TransferID: strings.TrimSpace(transferID)}
	if source, ok := a.fileTransferSources[transferID]; ok {
		localState.SenderSourceRegistered = true
		localState.SenderSourcePath = strings.TrimSpace(source.SourcePath)
		localState.SenderSourceSizeBytes = source.SizeBytes
		if info, err := os.Stat(source.SourcePath); err == nil && !info.IsDir() && info.Size() == source.SizeBytes {
			localState.SenderSourceAvailable = true
		}
	}
	if cache, ok := a.fileTransferCaches[transferID]; ok {
		localState.ReceiverCachePath = strings.TrimSpace(cache.CachePath)
		localState.ReceiverCacheSizeBytes = cache.SizeBytes
		if info, err := os.Stat(cache.CachePath); err == nil && !info.IsDir() {
			localState.ReceiverCacheAvailable = info.Size() > 0
			localState.ReceiverCachedBytes = minInt64(maxInt64(0, cache.CachedBytes), info.Size())
			if cache.SizeBytes > 0 {
				localState.ReceiverCachedBytes = minInt64(localState.ReceiverCachedBytes, cache.SizeBytes)
				localState.ReceiverCacheComplete = localState.ReceiverCachedBytes >= cache.SizeBytes
			}
		}
	}
	return localState, nil
}

func (a *Agent) AcceptFileTransfer(transferID string) (*controlclient.FileTransfer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireCurrentUserLocked(); err != nil {
		return nil, err
	}
	transfer, err := a.remote.AcceptFileTransfer(transferID)
	if err != nil {
		a.logErrorf("accept file transfer %s failed: %v", transferID, err)
		return nil, err
	}
	a.logInfof("file transfer accepted: %s", transferID)
	return transfer, nil
}

func (a *Agent) CancelFileTransfer(transferID, reason string) (*controlclient.FileTransfer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireCurrentUserLocked(); err != nil {
		return nil, err
	}
	transfer, err := a.remote.CancelFileTransfer(transferID, reason)
	if err != nil {
		a.logErrorf("cancel file transfer %s failed: %v", transferID, err)
		return nil, err
	}
	a.logInfof("file transfer canceled: %s", transferID)
	return transfer, nil
}

func (a *Agent) UpdateFileTransferProgress(transferID string, progressPercent int) (*controlclient.FileTransfer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireCurrentUserLocked(); err != nil {
		return nil, err
	}
	transfer, err := a.remote.UpdateFileTransferProgress(transferID, progressPercent)
	if err != nil {
		a.logErrorf("update file transfer progress failed for %s: %v", transferID, err)
		return nil, err
	}
	a.logInfof("file transfer progress updated: %s -> %d%%", transferID, progressPercent)
	return transfer, nil
}

func (a *Agent) UploadFileTransferContent(transferID, contentType string, payload []byte) (*controlclient.FileTransfer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireCurrentUserLocked(); err != nil {
		return nil, err
	}
	transfer, err := a.remote.UploadFileTransferContent(transferID, contentType, payload)
	if err != nil {
		a.logErrorf("upload file transfer payload failed for %s: %v", transferID, err)
		return nil, err
	}
	if err := a.syncRegisteredFileTransferSourceLocked(transfer); err != nil {
		return nil, err
	}
	a.logInfof("file transfer payload uploaded: %s", transferID)
	return transfer, nil
}

func (a *Agent) UploadFileTransferContentChunk(transferID, contentType string, offsetBytes int64, payload []byte) (*controlclient.FileTransfer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireCurrentUserLocked(); err != nil {
		return nil, err
	}
	transfer, err := a.remote.UploadFileTransferContentChunk(transferID, contentType, offsetBytes, payload)
	if err != nil {
		a.logErrorf("upload file transfer payload chunk failed for %s at %d: %v", transferID, offsetBytes, err)
		return nil, err
	}
	if err := a.syncRegisteredFileTransferSourceLocked(transfer); err != nil {
		return nil, err
	}
	a.logInfof("file transfer payload chunk uploaded: %s -> %d", transferID, transfer.PayloadUploadedBytes)
	return transfer, nil
}

func (a *Agent) RegisterFileTransferSource(transferID, sourcePath, contentType string) (*controlclient.FileTransfer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireCurrentUserLocked(); err != nil {
		return nil, err
	}
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return nil, fmt.Errorf("source path is required")
	}
	transfer, err := a.remote.GetFileTransfer(transferID)
	if err != nil {
		a.logErrorf("get file transfer for source registration failed for %s: %v", transferID, err)
		return nil, err
	}
	localPeerID := a.localManagedPeerIDLocked(transfer.NetworkID, transfer.FromPeerID)
	if localPeerID == "" && a.currentUser != nil && strings.EqualFold(strings.TrimSpace(transfer.FromUserID), strings.TrimSpace(a.currentUser.ID)) {
		localPeerID = a.currentManagedPeerIDForNetworkLocked(transfer.NetworkID)
	}
	if localPeerID == "" {
		return nil, fmt.Errorf("transfer sender peer %s is not managed by this agent", transfer.FromPeerID)
	}
	info, err := os.Stat(sourcePath)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("source path must be a file")
	}
	if info.Size() != transfer.SizeBytes {
		return nil, fmt.Errorf("source file size %d does not match transfer size %d", info.Size(), transfer.SizeBytes)
	}
	if a.fileTransferSources == nil {
		a.fileTransferSources = map[string]localFileTransferSource{}
	}
	a.fileTransferSources[transfer.ID] = localFileTransferSource{
		TransferID:     transfer.ID,
		NetworkID:      transfer.NetworkID,
		LocalPeerID:    localPeerID,
		RemotePeerID:   transfer.ToPeerID,
		RemoteUserID:   transfer.ToUserID,
		SourcePath:     sourcePath,
		FileName:       transfer.FileName,
		ContentType:    firstNonEmptyString(strings.TrimSpace(contentType), strings.TrimSpace(transfer.ContentType), "application/octet-stream"),
		PayloadSHA256:  strings.TrimSpace(transfer.PayloadSHA256),
		SizeBytes:      transfer.SizeBytes,
		UploadedAtUnix: transfer.UploadedAtUnix,
	}
	if err := a.persistFileTransferSourceLocked(a.fileTransferSources[transfer.ID]); err != nil {
		return nil, err
	}
	a.logInfof("file transfer source registered: %s -> %s", transfer.ID, sourcePath)
	return transfer, nil
}

func (a *Agent) DownloadFileTransferContent(transferID string) (*controlclient.FileTransferContent, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireCurrentUserLocked(); err != nil {
		return nil, err
	}
	content, err := a.remote.DownloadFileTransferContent(transferID)
	if err != nil {
		a.logErrorf("download file transfer payload failed for %s: %v", transferID, err)
		return nil, err
	}
	a.logInfof("file transfer payload downloaded: %s", transferID)
	return content, nil
}

func (a *Agent) DownloadFileTransferContentChunk(transferID string, offsetBytes, limitBytes int64) (*controlclient.FileTransferContentChunk, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.requireCurrentUserLocked(); err != nil {
		return nil, err
	}
	transfer, err := a.remote.GetFileTransfer(transferID)
	if err != nil {
		a.logErrorf("get file transfer %s before chunk download failed: %v", transferID, err)
		return nil, err
	}
	if cached, ok := a.downloadFileTransferContentChunkFromLocalCacheLocked(*transfer, offsetBytes, limitBytes); ok {
		return cached, nil
	}
	if transfer.PayloadReady {
		content, err := a.remote.DownloadFileTransferContentChunk(transferID, offsetBytes, limitBytes)
		if err != nil {
			a.logErrorf("download mirrored file transfer payload chunk failed for %s at %d: %v", transferID, offsetBytes, err)
			return nil, err
		}
		return content, nil
	}
	var content *controlclient.FileTransferContentChunk
	dataplaneContent, dataplaneErr := a.downloadFileTransferContentChunkViaDataplaneLocked(*transfer, offsetBytes, limitBytes)
	if dataplaneErr == nil && dataplaneContent != nil {
		content := dataplaneContent.FileTransferContentChunk
		if a.shouldStageDataplaneChunkToLocalCacheLocked(content.Transfer) {
			content = a.stageDataplaneChunkToLocalCacheLocked(content, dataplaneContent.LocalPeerID, dataplaneContent.RemotePeerID)
		} else {
			content = a.mirrorDataplaneChunkToControlPlaneLocked(content)
		}
		return content, nil
	}
	dataplaneContent, cacheErr := a.downloadFileTransferContentChunkViaReceiverCacheLocked(*transfer, offsetBytes, limitBytes)
	if cacheErr == nil && dataplaneContent != nil {
		content := dataplaneContent.FileTransferContentChunk
		if a.shouldStageDataplaneChunkToLocalCacheLocked(content.Transfer) {
			content = a.stageDataplaneChunkToLocalCacheLocked(content, dataplaneContent.LocalPeerID, dataplaneContent.RemotePeerID)
		} else {
			content = a.mirrorDataplaneChunkToControlPlaneLocked(content)
		}
		return content, nil
	}
	content, err = a.remote.DownloadFileTransferContentChunk(transferID, offsetBytes, limitBytes)
	if err != nil {
		a.logErrorf("download file transfer payload chunk failed for %s at %d: %v", transferID, offsetBytes, err)
		return nil, errors.Join(dataplaneErr, cacheErr, err)
	}
	return content, nil
}

func (a *Agent) downloadFileTransferContentChunkViaDataplaneLocked(transfer controlclient.FileTransfer, offsetBytes, limitBytes int64) (*dataplaneFileTransferChunk, error) {
	deadline := time.Now().Add(fileTransferDataplaneDeadline)
	var lastErr error
	for _, connection := range a.transportReadyConnectionsForTransferDownloadLocked(transfer) {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w: download deadline exceeded", errFileTransferInterrupted)
		}
		content, err := a.downloadFileTransferFromConnectionLocked(transfer, connection, offsetBytes, limitBytes, deadline, false)
		if err != nil {
			lastErr = err
			continue
		}
		if content != nil {
			if content.Complete {
				if updated, err := a.remote.UpdateFileTransferProgress(transfer.ID, 100); err == nil {
					content.Transfer = *updated
				} else {
					a.logErrorf("mark dataplane file transfer complete failed for %s: %v", transfer.ID, err)
				}
			}
			return content, nil
		}
	}
	return nil, lastErr
}

func (a *Agent) downloadFileTransferContentChunkViaReceiverCacheLocked(transfer controlclient.FileTransfer, offsetBytes, limitBytes int64) (*dataplaneFileTransferChunk, error) {
	deadline := time.Now().Add(fileTransferDataplaneDeadline)
	var lastErr error
	for _, connection := range a.transportReadyConnectionsForTransferReceiverCacheLocked(transfer) {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w: download deadline exceeded", errFileTransferInterrupted)
		}
		content, err := a.downloadFileTransferFromConnectionLocked(transfer, connection, offsetBytes, limitBytes, deadline, true)
		if err != nil {
			lastErr = err
			continue
		}
		if content != nil {
			return content, nil
		}
	}
	return nil, lastErr
}

func (a *Agent) downloadFileTransferContentChunkViaPeerCacheConnectionLocked(transfer controlclient.FileTransfer, connection *ConnectionStatus, offsetBytes, limitBytes int64) (*dataplaneFileTransferChunk, error) {
	return a.downloadFileTransferFromConnectionLocked(transfer, connection, offsetBytes, limitBytes, time.Now().Add(fileTransferDataplaneDeadline), true)
}

func (a *Agent) mirrorDataplaneChunkToControlPlaneLocked(content *controlclient.FileTransferContentChunk) *controlclient.FileTransferContentChunk {
	if content == nil || len(content.Payload) == 0 {
		return content
	}
	if content.Transfer.PayloadReady {
		return content
	}
	if content.Transfer.SizeBytes <= 0 {
		return content
	}
	if domain.DefaultMirroredFileTransferPayloadMaxBytes > 0 && content.Transfer.SizeBytes > domain.DefaultMirroredFileTransferPayloadMaxBytes {
		return content
	}
	updated, err := a.remote.UploadFileTransferContentChunk(content.Transfer.ID, firstNonEmptyString(strings.TrimSpace(content.ContentType), strings.TrimSpace(content.Transfer.ContentType), "application/octet-stream"), content.OffsetBytes, content.Payload)
	if err != nil {
		a.logErrorf("mirror dataplane file transfer chunk failed for %s at %d: %v", content.Transfer.ID, content.OffsetBytes, err)
		return content
	}
	content.Transfer = *updated
	content.ContentType = firstNonEmptyString(strings.TrimSpace(updated.ContentType), content.ContentType, "application/octet-stream")
	content.SHA256 = firstNonEmptyString(strings.TrimSpace(updated.PayloadSHA256), content.SHA256)
	content.TotalSizeBytes = firstPositiveInt64(updated.SizeBytes, content.TotalSizeBytes)
	if updated.UploadedAtUnix > 0 {
		content.UploadedAtUnix = updated.UploadedAtUnix
	}
	if updated.DownloadedAtUnix > 0 {
		content.DownloadedAtUnix = updated.DownloadedAtUnix
	}
	return content
}

func (a *Agent) shouldStageDataplaneChunkToLocalCacheLocked(transfer controlclient.FileTransfer) bool {
	if transfer.ID == "" || transfer.SizeBytes <= 0 || transfer.PayloadReady {
		return false
	}
	return domain.DefaultMirroredFileTransferPayloadMaxBytes > 0 && transfer.SizeBytes > domain.DefaultMirroredFileTransferPayloadMaxBytes
}

func (a *Agent) downloadFileTransferContentChunkFromLocalCacheLocked(transfer controlclient.FileTransfer, offsetBytes, limitBytes int64) (*controlclient.FileTransferContentChunk, bool) {
	cache, ok := a.fileTransferCaches[transfer.ID]
	if !ok || cache.CachePath == "" || cache.CachedBytes <= 0 {
		return nil, false
	}
	if offsetBytes < 0 || offsetBytes >= cache.CachedBytes {
		return nil, false
	}
	if limitBytes <= 0 || limitBytes > fileTransferAgentChunkBytes {
		limitBytes = fileTransferAgentChunkBytes
	}
	endOffset := minInt64(offsetBytes+limitBytes, cache.CachedBytes)
	file, err := os.Open(cache.CachePath)
	if err != nil {
		a.logErrorf("open file transfer cache failed for %s: %v", transfer.ID, err)
		return nil, false
	}
	defer file.Close()
	if _, err := file.Seek(offsetBytes, io.SeekStart); err != nil {
		a.logErrorf("seek file transfer cache failed for %s at %d: %v", transfer.ID, offsetBytes, err)
		return nil, false
	}
	payload := make([]byte, endOffset-offsetBytes)
	n, err := io.ReadFull(file, payload)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		a.logErrorf("read file transfer cache failed for %s at %d: %v", transfer.ID, offsetBytes, err)
		return nil, false
	}
	payload = payload[:n]
	if len(payload) == 0 {
		return nil, false
	}
	return &controlclient.FileTransferContentChunk{
		Transfer:         transfer,
		ContentType:      firstNonEmptyString(strings.TrimSpace(cache.ContentType), strings.TrimSpace(transfer.ContentType), "application/octet-stream"),
		SHA256:           firstNonEmptyString(strings.TrimSpace(cache.PayloadSHA256), strings.TrimSpace(transfer.PayloadSHA256)),
		Payload:          payload,
		OffsetBytes:      offsetBytes,
		NextOffsetBytes:  offsetBytes + int64(len(payload)),
		TotalSizeBytes:   firstPositiveInt64(cache.SizeBytes, transfer.SizeBytes),
		UploadedAtUnix:   firstPositiveInt64(cache.UploadedAtUnix, transfer.UploadedAtUnix),
		DownloadedAtUnix: transfer.DownloadedAtUnix,
		Complete:         offsetBytes+int64(len(payload)) >= transfer.SizeBytes && cache.CachedBytes >= transfer.SizeBytes,
	}, true
}

func (a *Agent) stageDataplaneChunkToLocalCacheLocked(content *controlclient.FileTransferContentChunk, localPeerID, remotePeerID string) *controlclient.FileTransferContentChunk {
	if content == nil || len(content.Payload) == 0 {
		return content
	}
	if !a.shouldStageDataplaneChunkToLocalCacheLocked(content.Transfer) {
		return content
	}
	cache := a.fileTransferCaches[content.Transfer.ID]
	if cache.TransferID == "" {
		cache = localFileTransferCache{
			TransferID:     content.Transfer.ID,
			NetworkID:      content.Transfer.NetworkID,
			LocalPeerID:    content.Transfer.ToPeerID,
			RemotePeerID:   content.Transfer.FromPeerID,
			CachePath:      a.fileTransferCachePathLocked(content.Transfer.ID),
			FileName:       content.Transfer.FileName,
			ContentType:    firstNonEmptyString(strings.TrimSpace(content.ContentType), strings.TrimSpace(content.Transfer.ContentType), "application/octet-stream"),
			PayloadSHA256:  firstNonEmptyString(strings.TrimSpace(content.SHA256), strings.TrimSpace(content.Transfer.PayloadSHA256)),
			SizeBytes:      content.Transfer.SizeBytes,
			UploadedAtUnix: firstPositiveInt64(content.UploadedAtUnix, content.Transfer.UploadedAtUnix),
		}
	}
	if cache.CachePath == "" {
		return content
	}
	if strings.TrimSpace(localPeerID) != "" {
		cache.LocalPeerID = strings.TrimSpace(localPeerID)
	}
	if strings.TrimSpace(remotePeerID) != "" {
		cache.RemotePeerID = strings.TrimSpace(remotePeerID)
	}
	if content.OffsetBytes > cache.CachedBytes {
		return content
	}
	if err := os.MkdirAll(filepath.Dir(cache.CachePath), 0o755); err != nil {
		a.logErrorf("create file transfer cache dir failed for %s: %v", content.Transfer.ID, err)
		return content
	}
	file, err := os.OpenFile(cache.CachePath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		a.logErrorf("open file transfer cache failed for %s: %v", content.Transfer.ID, err)
		return content
	}
	defer file.Close()
	if cache.CachedBytes == 0 && content.OffsetBytes == 0 {
		if err := file.Truncate(0); err != nil {
			a.logErrorf("truncate file transfer cache failed for %s: %v", content.Transfer.ID, err)
			return content
		}
	}
	writeOffset := maxInt64(content.OffsetBytes, cache.CachedBytes)
	if writeOffset < content.NextOffsetBytes {
		payloadOffset := writeOffset - content.OffsetBytes
		if _, err := file.Seek(writeOffset, io.SeekStart); err != nil {
			a.logErrorf("seek file transfer cache failed for %s at %d: %v", content.Transfer.ID, writeOffset, err)
			return content
		}
		if _, err := file.Write(content.Payload[payloadOffset:]); err != nil {
			a.logErrorf("write file transfer cache failed for %s at %d: %v", content.Transfer.ID, writeOffset, err)
			return content
		}
	}
	cache.NetworkID = firstNonEmptyString(strings.TrimSpace(content.Transfer.NetworkID), cache.NetworkID)
	cache.LocalPeerID = firstNonEmptyString(strings.TrimSpace(localPeerID), strings.TrimSpace(content.Transfer.ToPeerID), cache.LocalPeerID)
	cache.RemotePeerID = firstNonEmptyString(strings.TrimSpace(remotePeerID), strings.TrimSpace(content.Transfer.FromPeerID), cache.RemotePeerID)
	cache.FileName = firstNonEmptyString(strings.TrimSpace(content.Transfer.FileName), cache.FileName)
	cache.ContentType = firstNonEmptyString(strings.TrimSpace(content.ContentType), strings.TrimSpace(content.Transfer.ContentType), cache.ContentType, "application/octet-stream")
	cache.PayloadSHA256 = firstNonEmptyString(strings.TrimSpace(content.SHA256), strings.TrimSpace(content.Transfer.PayloadSHA256), cache.PayloadSHA256)
	cache.SizeBytes = firstPositiveInt64(content.Transfer.SizeBytes, cache.SizeBytes)
	cache.CachedBytes = maxInt64(cache.CachedBytes, content.NextOffsetBytes)
	if cache.SizeBytes > 0 && cache.CachedBytes > cache.SizeBytes {
		cache.CachedBytes = cache.SizeBytes
	}
	cache.UploadedAtUnix = firstPositiveInt64(content.UploadedAtUnix, content.Transfer.UploadedAtUnix, cache.UploadedAtUnix)
	a.fileTransferCaches[content.Transfer.ID] = cache
	if err := a.persistFileTransferCacheLocked(cache); err != nil {
		a.logErrorf("persist file transfer cache failed for %s: %v", content.Transfer.ID, err)
	}
	return content
}

func (a *Agent) autoMirrorAcceptedFileTransfersLocked() error {
	if a.currentUser == nil || a.deviceState == nil {
		return nil
	}
	managedPeers := a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	if len(managedPeers) == 0 {
		return nil
	}
	networks, err := a.remote.ListNetworks()
	if err != nil {
		return err
	}
	networksByID := make(map[string]controlclient.Network, len(networks))
	for _, network := range networks {
		networksByID[network.ID] = network
	}
	networkIDs := make([]string, 0, len(managedPeers))
	seenNetworks := map[string]struct{}{}
	for _, managedPeer := range managedPeers {
		if _, ok := seenNetworks[managedPeer.NetworkID]; ok {
			continue
		}
		seenNetworks[managedPeer.NetworkID] = struct{}{}
		networkIDs = append(networkIDs, managedPeer.NetworkID)
	}
	sort.Strings(networkIDs)
	for _, networkID := range networkIDs {
		localPeer := managedPeerByNetwork(managedPeers, networkID)
		if localPeer.PeerID == "" {
			continue
		}
		transfers, err := a.remote.ListFileTransfers(networkID)
		if err != nil {
			return err
		}
		sort.SliceStable(transfers, func(i, j int) bool {
			if transfers[i].UploadedAtUnix == transfers[j].UploadedAtUnix {
				return transfers[i].ID < transfers[j].ID
			}
			return transfers[i].UploadedAtUnix < transfers[j].UploadedAtUnix
		})
		for _, transfer := range transfers {
			if a.shouldAutoMirrorFileTransferLocked(networksByID[networkID], localPeer.PeerID, transfer) {
				mirrored, err := a.autoMirrorFileTransferChunkLocked(transfer)
				if err != nil {
					return err
				}
				if mirrored {
					return nil
				}
				continue
			}
			if !a.shouldAutoStageFileTransferLocked(networksByID[networkID], localPeer.PeerID, transfer) {
				continue
			}
			staged, err := a.autoStageFileTransferChunkLocked(transfer)
			if err != nil {
				return err
			}
			if staged {
				return nil
			}
		}
	}
	return nil
}

func (a *Agent) shouldAutoMirrorFileTransferLocked(network controlclient.Network, localPeerID string, transfer controlclient.FileTransfer) bool {
	if localPeerID == "" || transfer.ID == "" {
		return false
	}
	if transfer.PayloadReady || transfer.SizeBytes <= 0 {
		return false
	}
	if transfer.PayloadUploadedBytes < 0 || transfer.PayloadUploadedBytes >= transfer.SizeBytes {
		return false
	}
	if !a.transferTargetsCurrentUserLocked(transfer) {
		return false
	}
	if !fileTransferAllowsBackgroundDataplaneStatus(transfer.Status) {
		return false
	}
	if !network.FileTransfersEnabled {
		return false
	}
	if network.FileTransferMaxBytes > 0 && transfer.SizeBytes > network.FileTransferMaxBytes {
		return false
	}
	if domain.DefaultMirroredFileTransferPayloadMaxBytes > 0 && transfer.SizeBytes > domain.DefaultMirroredFileTransferPayloadMaxBytes {
		return false
	}
	return len(a.transportReadyConnectionsForTransferDownloadLocked(transfer)) > 0
}

func (a *Agent) shouldAutoStageFileTransferLocked(network controlclient.Network, localPeerID string, transfer controlclient.FileTransfer) bool {
	if localPeerID == "" || transfer.ID == "" {
		return false
	}
	if !a.shouldStageDataplaneChunkToLocalCacheLocked(transfer) {
		return false
	}
	if !a.transferTargetsCurrentUserLocked(transfer) {
		return false
	}
	if !fileTransferAllowsBackgroundDataplaneStatus(transfer.Status) {
		return false
	}
	if !network.FileTransfersEnabled {
		return false
	}
	if network.FileTransferMaxBytes > 0 && transfer.SizeBytes > network.FileTransferMaxBytes {
		return false
	}
	if a.cachedFileTransferBytesLocked(transfer.ID) >= transfer.SizeBytes {
		return false
	}
	return len(a.transportReadyConnectionsForTransferDownloadLocked(transfer)) > 0 || len(a.transportReadyConnectionsForTransferReceiverCacheLocked(transfer)) > 0
}

func fileTransferAllowsBackgroundDataplaneStatus(status string) bool {
	switch {
	case strings.EqualFold(strings.TrimSpace(status), string(domain.TransferStatusInProgress)):
		return true
	case strings.EqualFold(strings.TrimSpace(status), string(domain.TransferStatusDone)):
		return true
	default:
		return false
	}
}

func (a *Agent) autoMirrorFileTransferChunkLocked(transfer controlclient.FileTransfer) (bool, error) {
	dataplaneContent, err := a.downloadFileTransferContentChunkViaDataplaneLocked(transfer, transfer.PayloadUploadedBytes, fileTransferAgentChunkBytes)
	if err != nil || dataplaneContent == nil {
		return false, err
	}
	content := dataplaneContent.FileTransferContentChunk
	if len(content.Payload) == 0 {
		return false, nil
	}
	content = a.mirrorDataplaneChunkToControlPlaneLocked(content)
	if content == nil {
		return false, nil
	}
	if content.Transfer.PayloadUploadedBytes <= transfer.PayloadUploadedBytes && !content.Transfer.PayloadReady {
		return false, nil
	}
	a.logInfof("file transfer auto mirrored: %s -> %d/%d", transfer.ID, content.Transfer.PayloadUploadedBytes, content.Transfer.SizeBytes)
	return true, nil
}

func (a *Agent) autoStageFileTransferChunkLocked(transfer controlclient.FileTransfer) (bool, error) {
	startOffset := a.cachedFileTransferBytesLocked(transfer.ID)
	dataplaneContent, err := a.downloadFileTransferContentChunkViaDataplaneLocked(transfer, startOffset, fileTransferAgentChunkBytes)
	if dataplaneContent == nil {
		var cacheErr error
		dataplaneContent, cacheErr = a.downloadFileTransferContentChunkViaReceiverCacheLocked(transfer, startOffset, fileTransferAgentChunkBytes)
		if cacheErr != nil || dataplaneContent == nil {
			return false, errors.Join(err, cacheErr)
		}
	}
	content := dataplaneContent.FileTransferContentChunk
	if len(content.Payload) == 0 {
		return false, nil
	}
	content = a.stageDataplaneChunkToLocalCacheLocked(content, dataplaneContent.LocalPeerID, dataplaneContent.RemotePeerID)
	if content == nil {
		return false, nil
	}
	if a.cachedFileTransferBytesLocked(transfer.ID) <= startOffset {
		return false, nil
	}
	a.logInfof("file transfer auto staged locally: %s -> %d/%d", transfer.ID, a.cachedFileTransferBytesLocked(transfer.ID), transfer.SizeBytes)
	return true, nil
}

func (a *Agent) RegisterPeer(networkID, endpoint string) (*controlclient.Peer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, err := a.requireCurrentUserLocked()
	if err != nil {
		return nil, err
	}
	device, err := a.ensureCurrentDeviceLocked()
	if err != nil {
		return nil, err
	}
	a.currentDevice = cloneDevice(device)
	peer, err := a.remote.RegisterPeer(networkID, user.ID, device.ID, endpoint)
	if err != nil {
		a.logErrorf("register peer failed for network %s: %v", networkID, err)
		return nil, err
	}
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return nil, err
	}
	if a.resolveSTUNServerAddressLocked() != "" {
		if err := a.refreshSTUNForEndpointLocked(time.Now(), peer.ID, endpoint); err != nil {
			a.lastLifecycleError = err.Error()
		}
	}
	state.SetManagedPeer(a.remote.BaseURL(), user.ID, networkID, peer.ID, endpoint, peer.OverlayCIDR, peer.VirtualIP)
	if err := a.savePersistentStateLocked(); err != nil {
		return nil, err
	}
	if err := a.reconcileManagedRuntimeLocked(); err != nil {
		a.logErrorf("reconcile managed runtime after peer registration failed: %v", err)
		return nil, err
	}
	a.logInfof("peer registered: %s on network %s", peer.ID, networkID)
	return peer, nil
}

func (a *Agent) RejoinNetwork(networkID, endpoint string) (Status, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, err := a.requireCurrentUserLocked()
	if err != nil {
		return Status{}, err
	}
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return Status{}, err
	}
	managedPeers := state.ManagedPeersFor(a.remote.BaseURL(), user.ID)
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	managedPeer := managedPeerByNetwork(managedPeers, networkID)
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		endpoint = strings.TrimSpace(managedPeer.Endpoint)
	}
	if endpoint == "" {
		return Status{}, fmt.Errorf("endpoint is required to rejoin network %s", networkID)
	}

	device, err := a.ensureCurrentDeviceLocked()
	if err != nil {
		return Status{}, err
	}
	a.currentDevice = cloneDevice(device)

	peers, err := a.remote.ListPeers(networkID)
	if err != nil {
		return Status{}, err
	}

	var peer *controlclient.Peer
	for _, candidate := range peers {
		if candidate.DeviceID == device.ID {
			refreshed, err := a.remote.HeartbeatPeer(candidate.ID, endpoint)
			if err != nil {
				return Status{}, err
			}
			peer = refreshed
			break
		}
	}
	if peer == nil {
		peer, err = a.remote.RegisterPeer(networkID, user.ID, device.ID, endpoint)
		if err != nil {
			return Status{}, err
		}
	}

	if a.resolveSTUNServerAddressLocked() != "" {
		if err := a.refreshSTUNForEndpointLocked(time.Now(), peer.ID, endpoint); err != nil {
			a.lastLifecycleError = err.Error()
		}
	}
	state.SetManagedPeer(a.remote.BaseURL(), user.ID, networkID, peer.ID, endpoint, peer.OverlayCIDR, peer.VirtualIP)
	if err := a.savePersistentStateLocked(); err != nil {
		return Status{}, err
	}
	if err := a.reconcileManagedRuntimeLocked(); err != nil {
		return Status{}, err
	}
	if err := a.refreshPeerDiscoveryLocked(time.Now()); err != nil {
		a.lastLifecycleError = err.Error()
	}
	if err := a.outboundControlLocked(func() error { return a.negotiateDirectConnectionsLocked(time.Now()) }); err != nil {
		a.lastLifecycleError = err.Error()
	}
	if err := a.reconcileNegotiationTunnelsLocked(); err != nil {
		a.lastLifecycleError = err.Error()
	}
	a.logInfof("network rejoin completed for %s on %s", networkID, peer.ID)
	return a.snapshotLocked(), nil
}

func (a *Agent) ListTunnels(networkID string) ([]controlclient.Tunnel, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.remote.ListTunnels(networkID)
}

func (a *Agent) CreateTunnel(networkID, peerAID, peerBID string) (*controlclient.Tunnel, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	tunnel, err := a.remote.CreateTunnel(networkID, peerAID, peerBID, "")
	if err != nil {
		a.logErrorf("create tunnel failed for network %s: %v", networkID, err)
		return nil, err
	}
	a.logInfof("tunnel created: %s", tunnel.ID)
	return tunnel, nil
}

func (a *Agent) Handler() http.Handler {
	return NewHandler(a)
}

func (a *Agent) requireCurrentUserLocked() (*controlclient.User, error) {
	if a.currentUser == nil {
		return nil, fmt.Errorf("not connected to Ole service")
	}
	return a.currentUser, nil
}

func (a *Agent) ensureCurrentDeviceLocked() (*controlclient.Device, error) {
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return nil, err
	}
	devices, err := a.remote.ListDevices()
	if err != nil {
		return nil, err
	}

	if a.currentUser != nil {
		if enrollment := state.EnrollmentFor(a.remote.BaseURL(), a.currentUser.ID); enrollment != nil {
			for _, device := range devices {
				if device.ID == enrollment.DeviceID && strings.EqualFold(device.Status, "ACTIVE") {
					return cloneDevice(&device), nil
				}
			}
		}
	}

	for _, device := range devices {
		if strings.EqualFold(device.Status, "ACTIVE") && strings.TrimSpace(device.PublicKey) == state.PublicKey {
			if a.currentUser != nil {
				state.SetEnrollment(a.remote.BaseURL(), a.currentUser.ID, device.ID)
				if err := a.savePersistentStateLocked(); err != nil {
					return nil, err
				}
			}
			return cloneDevice(&device), nil
		}
	}

	device, err := a.remote.CreateDevice(state.DeviceName, state.PublicKey)
	if err != nil {
		return nil, err
	}
	if a.currentUser != nil {
		state.SetEnrollment(a.remote.BaseURL(), a.currentUser.ID, device.ID)
		if err := a.savePersistentStateLocked(); err != nil {
			return nil, err
		}
	}
	return device, nil
}

func (a *Agent) startLifecycleLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	a.lifecycleCancel = cancel
	a.lifecycleStopped = stopped

	go func() {
		ticker := time.NewTicker(a.runtime.LifecycleInterval)
		defer ticker.Stop()
		defer close(stopped)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.runLifecycle()
			}
		}
	}()
}

func (a *Agent) runLifecycle() {
	a.mu.Lock()
	defer a.mu.Unlock()
	defer a.refreshForwardingRoutesLocked()
	a.mergeInboundReportsLocked()
	a.mergeOutboundReportsLocked(true)

	now := time.Now()
	if a.currentSession == nil || a.currentUser == nil {
		a.runReconnectLifecycleLocked(now)
		return
	}
	if a.shouldRefreshSessionLocked(now) {
		if err := a.refreshCurrentSessionLocked(now); err != nil {
			a.handleLifecycleErrorLocked(err)
			return
		}
	}
	if a.shouldRefreshSecurityDiagnosticsLocked(now) {
		if err := a.refreshSecurityDiagnosticsLocked(now); err != nil {
			a.lastLifecycleError = err.Error()
			a.logErrorf("security diagnostics refresh failed: %v", err)
		}
		if err := a.refreshIncidentSummaryLocked(now); err != nil {
			a.logErrorf("incident summary refresh failed: %v", err)
		}
	}
	a.refreshTransportCredentialsLocked()
	if a.shouldHeartbeatLocked(now) {
		if err := a.heartbeatManagedPeersLocked(now); err != nil {
			a.handleLifecycleErrorLocked(err)
			return
		}
		a.lastHeartbeatAt = now
	}
	if a.shouldProbeSTUNLocked(now) {
		if err := a.refreshSTUNLocked(now); err != nil {
			a.lastLifecycleError = err.Error()
		}
	}
	if err := a.publishManagedCandidatesLocked(now); err != nil {
		a.handleLifecycleErrorLocked(err)
		return
	}
	if a.shouldDiscoverPeersLocked(now) {
		if err := a.refreshPeerDiscoveryLocked(now); err != nil {
			a.handleLifecycleErrorLocked(err)
			return
		}
		a.lastPeerDiscoveryAt = now
	}
	if err := a.outboundControlLocked(func() error { return a.negotiateDirectConnectionsLocked(now) }); err != nil {
		a.handleLifecycleErrorLocked(err)
		return
	}
	if err := a.forwardTransportPacketsLocked(now); err != nil {
		a.handleLifecycleErrorLocked(err)
		return
	}
	if err := a.outboundControlLocked(func() error { return a.maintainTransportQualityLocked(now) }); err != nil {
		a.handleLifecycleErrorLocked(err)
		return
	}
	if a.shouldAutoMirrorFileTransfersLocked(now) {
		if err := a.autoMirrorAcceptedFileTransfersLocked(); err != nil {
			a.lastLifecycleError = err.Error()
			a.logErrorf("file transfer auto mirror failed: %v", err)
		}
		a.lastFileTransferMirrorAt = now
	}
	if err := a.reconcileNegotiationTunnelsLocked(); err != nil {
		a.handleLifecycleErrorLocked(err)
		return
	}
	a.maybeStartAutoUpdateCheckLocked(now)
	a.lastLifecycleError = ""
}

func (a *Agent) runReconnectLifecycleLocked(now time.Time) {
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		a.lastLifecycleError = err.Error()
		return
	}
	if state.SessionFor(a.remote.BaseURL()) == nil {
		a.clearReconnectBackoffLocked()
		return
	}
	if !a.nextReconnectAttemptAt.IsZero() && now.Before(a.nextReconnectAttemptAt) {
		return
	}
	a.lastReconnectAttemptAt = now
	if err := a.restoreSessionLocked(); err != nil {
		a.recordReconnectFailureLocked(now, err)
		a.logErrorw("session.reconnect.auto_failed", "auto reconnect failed", "error", err, "attemptCount", a.reconnectAttemptCount, "nextReconnectUnix", unixOrZero(a.nextReconnectAttemptAt))
		return
	}
	if a.currentSession != nil && a.currentUser != nil {
		a.clearReconnectBackoffLocked()
		a.lastLifecycleError = ""
		a.logInfow("session.reconnect.auto_succeeded", "auto reconnect restored session", "email", a.currentUser.Email, "userId", a.currentUser.ID)
	}
}

func (a *Agent) recordReconnectFailureLocked(now time.Time, err error) {
	a.reconnectAttemptCount++
	a.lastReconnectAttemptAt = now
	a.lastReconnectError = err.Error()
	a.lastLifecycleError = err.Error()
	a.nextReconnectAttemptAt = now.Add(directRetryDelay(a.runtime.ReconnectRetryBase, a.runtime.ReconnectRetryMax, a.reconnectAttemptCount))
	a.persistReconnectLifecycleLocked()
}

func (a *Agent) clearReconnectBackoffLocked() {
	a.reconnectAttemptCount = 0
	a.lastReconnectAttemptAt = time.Time{}
	a.nextReconnectAttemptAt = time.Time{}
	a.lastReconnectError = ""
	a.persistReconnectLifecycleLocked()
}

func (a *Agent) shouldRefreshSessionLocked(now time.Time) bool {
	if a.currentSession == nil {
		return false
	}
	refreshAt := time.Unix(a.currentSession.ExpiresAtUnix, 0).Add(-a.runtime.SessionRefreshSkew)
	return !now.Before(refreshAt)
}

func (a *Agent) shouldRefreshSecurityDiagnosticsLocked(now time.Time) bool {
	if a.currentSession == nil || a.currentUser == nil {
		return false
	}
	return a.lastSecurityRefreshAt.IsZero() || now.Sub(a.lastSecurityRefreshAt) >= a.runtime.SecurityDiagnosticsPeriod
}

func (a *Agent) shouldHeartbeatLocked(now time.Time) bool {
	if a.currentUser == nil || a.deviceState == nil {
		return false
	}
	if len(a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)) == 0 {
		return false
	}
	return a.lastHeartbeatAt.IsZero() || now.Sub(a.lastHeartbeatAt) >= a.runtime.HeartbeatInterval
}

func (a *Agent) shouldDiscoverPeersLocked(now time.Time) bool {
	if a.currentUser == nil || a.deviceState == nil {
		return false
	}
	if len(a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)) == 0 {
		return false
	}
	return a.lastPeerDiscoveryAt.IsZero() || now.Sub(a.lastPeerDiscoveryAt) >= a.runtime.PeerDiscoveryPeriod
}

func (a *Agent) shouldAutoMirrorFileTransfersLocked(now time.Time) bool {
	if a.currentUser == nil || a.deviceState == nil {
		return false
	}
	if len(a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)) == 0 {
		return false
	}
	return a.lastFileTransferMirrorAt.IsZero() || now.Sub(a.lastFileTransferMirrorAt) >= a.runtime.FileTransferMirrorPeriod
}

func (a *Agent) shouldProbeSTUNLocked(now time.Time) bool {
	if a.currentUser == nil || a.deviceState == nil {
		return false
	}
	managedPeers := a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	if len(managedPeers) == 0 {
		return false
	}
	return a.resolveSTUNServerAddressLocked() != "" && (a.lastSTUNProbeAt.IsZero() || now.Sub(a.lastSTUNProbeAt) >= a.runtime.STUNProbePeriod)
}

func (a *Agent) refreshCurrentSessionLocked(now time.Time) error {
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return err
	}
	if a.currentSession == nil {
		return nil
	}
	session, err := a.remote.RefreshSession(a.currentSession.RefreshToken, state.DeviceName)
	if err != nil {
		return err
	}
	a.currentSession = cloneSession(session)
	if a.currentUser == nil || a.currentUser.ID != session.UserID {
		user, err := a.remote.GetUser(session.UserID)
		if err != nil {
			return err
		}
		a.currentUser = cloneUser(user)
	}
	device, err := a.ensureCurrentDeviceLocked()
	if err != nil {
		return err
	}
	a.currentDevice = cloneDevice(device)
	if err := a.persistCurrentSessionLocked(); err != nil {
		return err
	}
	if err := a.refreshSecurityDiagnosticsLocked(now); err != nil {
		a.lastLifecycleError = err.Error()
		a.logErrorf("security diagnostics refresh after session refresh failed: %v", err)
	}
	if err := a.refreshIncidentSummaryLocked(now); err != nil {
		a.logErrorf("incident summary refresh after session refresh failed: %v", err)
	}
	a.lastSessionRefreshAt = now
	return nil
}

func (a *Agent) heartbeatManagedPeersLocked(now time.Time) error {
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return err
	}
	if a.currentUser == nil {
		return nil
	}
	managedPeers := state.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	changed := false
	for _, managedPeer := range managedPeers {
		previousEndpoint := strings.TrimSpace(managedPeer.Endpoint)
		peer, err := a.remote.HeartbeatPeer(managedPeer.PeerID, managedPeer.Endpoint)
		if err != nil {
			if isNotFoundError(err) {
				peer, err = a.restoreManagedPeerRegistrationLocked(managedPeer)
				if err != nil {
					return err
				}
				changed = true
				state.SetManagedPeer(a.remote.BaseURL(), a.currentUser.ID, managedPeer.NetworkID, peer.ID, peer.Endpoint, peer.OverlayCIDR, peer.VirtualIP)
				a.lastPeerDiscoveryAt = time.Time{}
			} else {
				return err
			}
		} else {
			state.UpdateManagedPeer(a.remote.BaseURL(), a.currentUser.ID, peer.ID, peer.Endpoint, peer.OverlayCIDR, peer.VirtualIP)
			changed = true
		}
		currentEndpoint := strings.TrimSpace(peer.Endpoint)
		if currentEndpoint != "" && !strings.EqualFold(previousEndpoint, currentEndpoint) {
			if err := a.handleManagedPeerRoamingLocked(managedPeer, currentEndpoint, now); err != nil {
				a.lastLifecycleError = err.Error()
			}
		}
	}
	if changed {
		if err := a.savePersistentStateLocked(); err != nil {
			return err
		}
	}
	if err := a.reconcileManagedRuntimeLocked(); err != nil {
		return err
	}
	a.lastHeartbeatAt = now
	return nil
}

func (a *Agent) restoreManagedPeerRegistrationLocked(managedPeer ManagedPeerState) (*controlclient.Peer, error) {
	if a.currentUser == nil {
		return nil, fmt.Errorf("not connected to Ole service")
	}
	endpoint := strings.TrimSpace(managedPeer.Endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("endpoint is required to restore managed peer on network %s", managedPeer.NetworkID)
	}
	device, err := a.ensureCurrentDeviceLocked()
	if err != nil {
		return nil, err
	}
	a.currentDevice = cloneDevice(device)
	peer, err := a.remote.RegisterPeer(managedPeer.NetworkID, a.currentUser.ID, device.ID, endpoint)
	if err != nil {
		return nil, err
	}
	a.logInfow("managed_peer.auto_reregistered", "managed peer re-registered after heartbeat miss", "networkId", managedPeer.NetworkID, "previousPeerId", managedPeer.PeerID, "peerId", peer.ID, "endpoint", peer.Endpoint)
	return peer, nil
}

func (a *Agent) refreshPeerDiscoveryLocked(now time.Time) error {
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return err
	}
	if a.currentUser == nil {
		a.discoveredPeers = map[string][]controlclient.Peer{}
		a.neighbors = nil
		a.connections = nil
		return nil
	}
	managedPeers := state.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	networkIDs := make([]string, 0, len(managedPeers))
	seenNetworks := map[string]struct{}{}
	for _, peer := range managedPeers {
		if _, ok := seenNetworks[peer.NetworkID]; ok {
			continue
		}
		seenNetworks[peer.NetworkID] = struct{}{}
		networkIDs = append(networkIDs, peer.NetworkID)
	}
	sort.Strings(networkIDs)

	discovered := make(map[string][]controlclient.Peer, len(networkIDs))
	neighbors := make([]NeighborStatus, 0)
	connections := make([]ConnectionStatus, 0)
	for _, networkID := range networkIDs {
		peers, err := a.remote.ListPeers(networkID)
		if err != nil {
			return err
		}
		discovered[networkID] = peers
		localPeer := managedPeerByNetwork(managedPeers, networkID)
		if localPeer.PeerID == "" {
			continue
		}
		for _, peer := range peers {
			if peer.ID == localPeer.PeerID {
				continue
			}
			candidates, err := a.remote.ListCandidates(peer.ID)
			if err != nil {
				return err
			}
			previous := a.connectionByPeersLocked(networkID, localPeer.PeerID, peer.ID)
			if previous == nil {
				previous = a.replacementConnectionForPeerRefreshLocked(networkID, localPeer.PeerID, peer, candidates)
			}
			connection := buildConnectionStatus(networkID, localPeer.PeerID, peer, candidates, previous)
			connections = append(connections, connection)
			neighbors = append(neighbors, buildNeighborStatus(networkID, localPeer.PeerID, peer, candidates, connection))
		}
	}
	a.cleanupRemovedConnectionsLocked(a.connections, connections)
	a.discoveredPeers = discovered
	a.neighbors = neighbors
	a.connections = connections
	if err := a.reconcileOverlayDNSLocked(managedPeers); err != nil {
		a.lastLifecycleError = err.Error()
	}
	a.lastPeerDiscoveryAt = now
	return nil
}

func (a *Agent) publishManagedCandidatesLocked(_ time.Time) error {
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return err
	}
	if a.currentUser == nil {
		return nil
	}
	managedPeers := state.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	for _, managedPeer := range managedPeers {
		if strings.TrimSpace(managedPeer.Endpoint) == "" {
			continue
		}
		if _, err := a.remote.PublishCandidate(managedPeer.PeerID, "HOST", "UDP", managedPeer.Endpoint, 100, true, 120); err != nil {
			return err
		}
		if a.natType == stun.NATTypeNAT && strings.EqualFold(strings.TrimSpace(managedPeer.Endpoint), strings.TrimSpace(a.localSTUNEndpoint)) && strings.TrimSpace(a.publicEndpoint) != "" {
			if _, err := a.remote.PublishCandidate(managedPeer.PeerID, "SRFLX", "UDP", a.publicEndpoint, 200, true, 120); err != nil {
				return err
			}
		}
		for idx, relayAddress := range a.resolveRelayServerAddressesLocked() {
			preference := 10 - idx
			if preference < 1 {
				preference = 1
			}
			if _, err := a.remote.PublishCandidate(managedPeer.PeerID, "RELAY", "UDP", relayAddress, preference, true, 120); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *Agent) disconnectManagedPeersLocked(clearState bool) error {
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return err
	}
	if a.currentUser == nil {
		return nil
	}
	managedPeers := state.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	if err := a.closeManagedNegotiationTunnelsLocked(managedPeers); err != nil {
		return err
	}
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	for _, managedPeer := range managedPeers {
		if _, err := a.remote.DisconnectPeer(managedPeer.PeerID); err != nil && !isNotFoundError(err) {
			return err
		}
	}
	if clearState {
		state.ClearManagedPeers(a.remote.BaseURL(), a.currentUser.ID)
		state.ClearFileTransferSources(a.remote.BaseURL(), a.currentUser.ID)
		state.ClearFileTransferCaches(a.remote.BaseURL(), a.currentUser.ID)
		if err := a.savePersistentStateLocked(); err != nil {
			return err
		}
	}
	if err := a.reconcileManagedRuntimeLocked(); err != nil {
		return err
	}
	return nil
}

func (a *Agent) restoreSessionLocked() error {
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return err
	}
	storedSession := state.SessionFor(a.remote.BaseURL())
	if storedSession == nil {
		a.logInfof("restore skipped: no persisted session")
		return nil
	}
	if err := a.ensureCompatibleLocked(); err != nil {
		return err
	}

	a.remote.SetAccessToken(storedSession.AccessToken)
	currentSession := &controlclient.Session{
		UserID:        storedSession.UserID,
		AccessToken:   storedSession.AccessToken,
		RefreshToken:  storedSession.RefreshToken,
		ExpiresAtUnix: storedSession.ExpiresAtUnix,
	}
	user, err := a.remote.GetUser(storedSession.UserID)
	if err != nil {
		refreshedSession, refreshErr := a.remote.RefreshSession(storedSession.RefreshToken, state.DeviceName)
		if refreshErr != nil {
			a.remote.ClearAccessToken()
			if shouldClearPersistedSession(refreshErr) {
				state.ClearSession(a.remote.BaseURL())
				_ = a.savePersistentStateLocked()
			}
			a.logErrorf("restore refresh failed: %v", refreshErr)
			return refreshErr
		}
		currentSession = cloneSession(refreshedSession)
		user, err = a.remote.GetUser(refreshedSession.UserID)
		if err != nil {
			a.remote.ClearAccessToken()
			if shouldClearPersistedSession(err) {
				state.ClearSession(a.remote.BaseURL())
				_ = a.savePersistentStateLocked()
			}
			a.logErrorf("restore user lookup after refresh failed: %v", err)
			return err
		}
		a.lastSessionRefreshAt = time.Now()
	}

	a.currentSession = currentSession
	a.currentUser = cloneUser(user)
	device, err := a.ensureCurrentDeviceLocked()
	if err != nil {
		return err
	}
	a.currentDevice = cloneDevice(device)
	if err := a.persistCurrentSessionLocked(); err != nil {
		a.logErrorf("persist restored session failed: %v", err)
		return err
	}
	if err := a.refreshSecurityDiagnosticsLocked(time.Now()); err != nil {
		a.lastLifecycleError = err.Error()
		a.logErrorf("security diagnostics refresh during restore failed: %v", err)
	}
	if err := a.refreshIncidentSummaryLocked(time.Now()); err != nil {
		a.logErrorf("incident summary refresh during restore failed: %v", err)
	}
	if err := a.refreshSTUNLocked(time.Now()); err != nil {
		a.lastLifecycleError = err.Error()
	}
	if err := a.reconcileManagedRuntimeLocked(); err != nil {
		a.logErrorf("reconcile managed runtime during restore failed: %v", err)
		return err
	}
	if err := a.restorePersistedFileTransferSourcesLocked(); err != nil {
		a.logErrorf("restore file transfer sources during restore failed: %v", err)
		return err
	}
	if err := a.restorePersistedFileTransferCachesLocked(); err != nil {
		a.logErrorf("restore file transfer caches during restore failed: %v", err)
		return err
	}
	if err := a.refreshPeerDiscoveryLocked(time.Now()); err != nil {
		a.lastLifecycleError = err.Error()
	}
	if err := a.outboundControlLocked(func() error { return a.negotiateDirectConnectionsLocked(time.Now()) }); err != nil {
		a.lastLifecycleError = err.Error()
	}
	if err := a.forwardTransportPacketsLocked(time.Now()); err != nil {
		a.lastLifecycleError = err.Error()
	}
	if err := a.reconcileNegotiationTunnelsLocked(); err != nil {
		a.lastLifecycleError = err.Error()
	}
	a.lastLifecycleError = ""
	if a.currentUser != nil {
		a.logInfow("session.restore.loaded", "restore loaded session", "email", a.currentUser.Email, "userId", a.currentUser.ID)
	}
	return nil
}

func (a *Agent) persistCurrentSessionLocked() error {
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return err
	}
	if a.currentSession == nil || a.currentUser == nil {
		state.ClearSession(a.remote.BaseURL())
		return a.savePersistentStateLocked()
	}
	deviceID := ""
	if a.currentDevice != nil {
		deviceID = a.currentDevice.ID
	}
	state.SetSession(a.remote.BaseURL(), a.currentUser.ID, deviceID, &SessionState{
		AccessToken:   a.currentSession.AccessToken,
		RefreshToken:  a.currentSession.RefreshToken,
		ExpiresAtUnix: a.currentSession.ExpiresAtUnix,
	})
	return a.savePersistentStateLocked()
}

func (a *Agent) currentEnrolledDeviceIDLocked() string {
	if a.deviceState == nil || a.currentUser == nil {
		return ""
	}
	enrollment := a.deviceState.EnrollmentFor(a.remote.BaseURL(), a.currentUser.ID)
	if enrollment == nil {
		return ""
	}
	return strings.TrimSpace(enrollment.DeviceID)
}

func (a *Agent) refreshSecurityDiagnosticsLocked(now time.Time) error {
	sessions, err := a.remote.ListSessions()
	if err != nil {
		return err
	}
	return a.refreshSecurityDiagnosticsWithSessionsLocked(sessions, now)
}

func (a *Agent) refreshIncidentSummaryLocked(now time.Time) error {
	incidents, err := a.remote.ListIncidentReports()
	if err != nil {
		a.incidentSummary.LastCheckedUnix = now.Unix()
		a.incidentSummary.LastRefreshError = err.Error()
		return err
	}
	a.incidentSummary = summarizeIncidentReports(incidents, now)
	a.lastIncidentRefreshAt = now
	return nil
}

func (a *Agent) refreshSecurityDiagnosticsWithSessionsLocked(sessions []controlclient.Session, now time.Time) error {
	devices, err := a.remote.ListDevices()
	if err != nil {
		return err
	}
	a.securityDiagnostics = deriveSecurityDiagnostics(sessions, devices, a.currentSession, a.currentDevice, a.currentEnrolledDeviceIDLocked(), now)
	a.lastSecurityRefreshAt = now
	return nil
}

func (a *Agent) clearInMemorySessionLocked() {
	a.invalidateForwardingRoutesLocked()
	a.forwardingPolicy = nil
	a.remote.ClearAccessToken()
	a.transportCredentials = nil
	a.currentUser = nil
	a.currentSession = nil
	a.currentDevice = nil
	a.discoveredPeers = map[string][]controlclient.Peer{}
	a.neighbors = nil
	a.connections = nil
	a.directAttempts = map[string]DirectAttemptState{}
	a.fileTransferSources = map[string]localFileTransferSource{}
	a.fileTransferCaches = map[string]localFileTransferCache{}
	a.gatewaySelections = map[string]gatewaySelectionState{}
	a.gatewayHistory = nil
	a.lastSTUNProbeAt = time.Time{}
	a.lastDirectProbeAt = time.Time{}
	a.lastSecurityRefreshAt = time.Time{}
	a.lastIncidentRefreshAt = time.Time{}
	a.securityDiagnostics = SecurityDiagnostics{}
	a.incidentSummary = IncidentSummary{}
	a.natType = ""
	a.publicEndpoint = ""
	a.localSTUNEndpoint = ""
	a.clearReconnectBackoffLocked()
}

func (a *Agent) localManagedPeerIDLocked(networkID, peerID string) string {
	if a.currentUser == nil || a.deviceState == nil {
		return ""
	}
	managedPeers := a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	for _, managedPeer := range managedPeers {
		if managedPeer.NetworkID == networkID && managedPeer.PeerID == peerID {
			return managedPeer.PeerID
		}
	}
	return ""
}

func (a *Agent) currentManagedPeerIDForNetworkLocked(networkID string) string {
	if a.currentUser == nil || a.deviceState == nil {
		return ""
	}
	managedPeers := a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	return managedPeerByNetwork(managedPeers, networkID).PeerID
}

func (a *Agent) hasManagedPeerLocked(peerID string) bool {
	if a.currentUser == nil || a.deviceState == nil {
		return false
	}
	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return false
	}
	managedPeers := a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	for _, managedPeer := range managedPeers {
		if strings.EqualFold(strings.TrimSpace(managedPeer.PeerID), peerID) {
			return true
		}
	}
	return false
}

func (a *Agent) persistFileTransferSourceLocked(source localFileTransferSource) error {
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return err
	}
	if a.currentUser == nil {
		return nil
	}
	state.SetFileTransferSource(FileTransferSourceState{
		ServerBaseURL:  a.remote.BaseURL(),
		UserID:         a.currentUser.ID,
		TransferID:     strings.TrimSpace(source.TransferID),
		NetworkID:      strings.TrimSpace(source.NetworkID),
		LocalPeerID:    strings.TrimSpace(source.LocalPeerID),
		RemotePeerID:   strings.TrimSpace(source.RemotePeerID),
		RemoteUserID:   strings.TrimSpace(source.RemoteUserID),
		SourcePath:     strings.TrimSpace(source.SourcePath),
		FileName:       strings.TrimSpace(source.FileName),
		ContentType:    strings.TrimSpace(source.ContentType),
		PayloadSHA256:  strings.TrimSpace(source.PayloadSHA256),
		SizeBytes:      source.SizeBytes,
		UploadedAtUnix: source.UploadedAtUnix,
	})
	return a.savePersistentStateLocked()
}

func (a *Agent) fileTransferSourceLocalPeerIDLocked(source localFileTransferSource, transfer *controlclient.FileTransfer) string {
	networkID := strings.TrimSpace(source.NetworkID)
	fromPeerID := ""
	if transfer != nil {
		networkID = firstNonEmptyString(strings.TrimSpace(transfer.NetworkID), networkID)
		fromPeerID = strings.TrimSpace(transfer.FromPeerID)
	}
	if localPeerID := a.localManagedPeerIDLocked(networkID, fromPeerID); localPeerID != "" {
		return localPeerID
	}
	activeLocalPeerID := strings.TrimSpace(a.currentManagedPeerIDForNetworkLocked(networkID))
	if activeLocalPeerID == "" {
		return ""
	}
	if transfer != nil && a.currentUser != nil && strings.EqualFold(strings.TrimSpace(transfer.FromUserID), strings.TrimSpace(a.currentUser.ID)) {
		return activeLocalPeerID
	}
	if strings.EqualFold(strings.TrimSpace(source.NetworkID), networkID) {
		return activeLocalPeerID
	}
	return ""
}

func (a *Agent) syncRegisteredFileTransferSourceLocked(transfer *controlclient.FileTransfer) error {
	if transfer == nil {
		return nil
	}
	source, ok := a.fileTransferSources[transfer.ID]
	if !ok {
		return nil
	}
	source.NetworkID = firstNonEmptyString(strings.TrimSpace(transfer.NetworkID), source.NetworkID)
	localPeerID := a.fileTransferSourceLocalPeerIDLocked(source, transfer)
	source.LocalPeerID = firstNonEmptyString(localPeerID, source.LocalPeerID)
	source.RemoteUserID = firstNonEmptyString(a.fileTransferSourceRemoteUserIDLocked(source, transfer), source.RemoteUserID)
	if activeRemotePeerID := a.activeTransferParticipantRemotePeerIDLocked(source.NetworkID, source.RemotePeerID, source.RemoteUserID); activeRemotePeerID != "" {
		source.RemotePeerID = activeRemotePeerID
	} else if !a.fileTransferSourceRemotePeerMatchesParticipantLocked(source, transfer) {
		source.RemotePeerID = firstNonEmptyString(strings.TrimSpace(transfer.ToPeerID), source.RemotePeerID)
	}
	source.FileName = firstNonEmptyString(strings.TrimSpace(transfer.FileName), source.FileName)
	source.ContentType = firstNonEmptyString(strings.TrimSpace(transfer.ContentType), source.ContentType, "application/octet-stream")
	source.PayloadSHA256 = firstNonEmptyString(strings.TrimSpace(transfer.PayloadSHA256), source.PayloadSHA256)
	if transfer.SizeBytes > 0 {
		source.SizeBytes = transfer.SizeBytes
	}
	if transfer.UploadedAtUnix > 0 {
		source.UploadedAtUnix = transfer.UploadedAtUnix
	}
	a.fileTransferSources[transfer.ID] = source
	return a.persistFileTransferSourceLocked(source)
}

func (a *Agent) fileTransferSourceRemoteUserIDLocked(source localFileTransferSource, transfer *controlclient.FileTransfer) string {
	networkID := strings.TrimSpace(source.NetworkID)
	if transfer != nil {
		networkID = firstNonEmptyString(strings.TrimSpace(transfer.NetworkID), networkID)
		if remoteUserID := strings.TrimSpace(transfer.ToUserID); remoteUserID != "" {
			return remoteUserID
		}
		if remoteUserID := strings.TrimSpace(a.peerUserIDInNetworkUnlocked(networkID, transfer.ToPeerID)); remoteUserID != "" {
			return remoteUserID
		}
	}
	if remoteUserID := strings.TrimSpace(source.RemoteUserID); remoteUserID != "" {
		return remoteUserID
	}
	return strings.TrimSpace(a.peerUserIDInNetworkUnlocked(networkID, source.RemotePeerID))
}

func (a *Agent) activeTransferParticipantRemotePeerIDLocked(networkID, expectedPeerID, remoteUserID string) string {
	networkID = strings.TrimSpace(networkID)
	expectedPeerID = strings.TrimSpace(expectedPeerID)
	remoteUserID = strings.TrimSpace(remoteUserID)
	if networkID == "" || (expectedPeerID == "" && remoteUserID == "") {
		return ""
	}
	var best *ConnectionStatus
	for idx := range a.connections {
		connection := &a.connections[idx]
		if !strings.EqualFold(strings.TrimSpace(connection.NetworkID), networkID) || !connection.TransportReady {
			continue
		}
		matchesParticipant := false
		if remoteUserID != "" {
			connectionRemoteUserID := strings.TrimSpace(firstNonEmptyString(connection.RemoteUserID, a.peerUserIDInNetworkUnlocked(networkID, connection.RemotePeerID)))
			if connectionRemoteUserID != "" && strings.EqualFold(connectionRemoteUserID, remoteUserID) {
				matchesParticipant = true
			}
		}
		if !matchesParticipant && expectedPeerID != "" {
			matchesParticipant = a.connectionMatchesRemotePeerTargetLocked(networkID, expectedPeerID, remoteUserID, connection)
		}
		if !matchesParticipant {
			continue
		}
		if best == nil || betterSignalingConnection(connection, best) {
			best = connection
		}
	}
	if best == nil {
		return ""
	}
	return strings.TrimSpace(best.RemotePeerID)
}

func (a *Agent) fileTransferSourceRemotePeerMatchesParticipantLocked(source localFileTransferSource, transfer *controlclient.FileTransfer) bool {
	if transfer == nil {
		return false
	}
	currentRemotePeerID := strings.TrimSpace(source.RemotePeerID)
	transferRemotePeerID := strings.TrimSpace(transfer.ToPeerID)
	if currentRemotePeerID == "" || transferRemotePeerID == "" || strings.EqualFold(currentRemotePeerID, transferRemotePeerID) {
		return false
	}
	networkID := firstNonEmptyString(strings.TrimSpace(transfer.NetworkID), strings.TrimSpace(source.NetworkID))
	currentRemoteUserID := strings.TrimSpace(firstNonEmptyString(source.RemoteUserID, a.peerUserIDInNetworkUnlocked(networkID, currentRemotePeerID)))
	transferRemoteUserID := strings.TrimSpace(firstNonEmptyString(strings.TrimSpace(transfer.ToUserID), a.peerUserIDInNetworkUnlocked(networkID, transferRemotePeerID)))
	currentTarget := a.peerTargetInNetworkUnlocked(networkID, currentRemotePeerID)
	transferTarget := a.peerTargetInNetworkUnlocked(networkID, transferRemotePeerID)
	if strings.TrimSpace(currentTarget.ID) != "" && strings.TrimSpace(transferTarget.ID) != "" && sameOverlayPeerTarget(currentTarget, transferTarget) {
		return true
	}
	if currentRemoteUserID != "" && transferRemoteUserID == "" {
		return true
	}
	return currentRemoteUserID != "" && transferRemoteUserID != "" && strings.EqualFold(currentRemoteUserID, transferRemoteUserID)
}

func (a *Agent) restorePersistedFileTransferSourcesLocked() error {
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return err
	}
	a.fileTransferSources = map[string]localFileTransferSource{}
	if a.currentUser == nil {
		return nil
	}
	serverBaseURL := a.remote.BaseURL()
	userID := a.currentUser.ID
	managedPeers := state.ManagedPeersFor(serverBaseURL, userID)
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	allowed := map[string]struct{}{}
	for _, peer := range managedPeers {
		allowed[peer.NetworkID+"|"+peer.PeerID] = struct{}{}
	}
	replacementPeersByNetwork := replacementManagedPeerIDsByNetwork(managedPeers)
	sources := state.FileTransferSourcesFor(serverBaseURL, userID)
	changed := false
	for _, persisted := range sources {
		if _, ok := allowed[persisted.NetworkID+"|"+persisted.LocalPeerID]; !ok {
			if replacementPeerID := replacementPeersByNetwork[persisted.NetworkID]; replacementPeerID != "" {
				persisted.LocalPeerID = replacementPeerID
				state.SetFileTransferSource(persisted)
				changed = true
			} else {
				if state.DeleteFileTransferSource(serverBaseURL, userID, persisted.TransferID) {
					changed = true
				}
				continue
			}
		}
		info, statErr := os.Stat(persisted.SourcePath)
		if statErr != nil || info.IsDir() || info.Size() != persisted.SizeBytes {
			if state.DeleteFileTransferSource(serverBaseURL, userID, persisted.TransferID) {
				changed = true
			}
			continue
		}
		promotedSource, promoted := a.promotePersistedFileTransferSourceRemotePeerLocked(localFileTransferSource{
			TransferID:     persisted.TransferID,
			NetworkID:      persisted.NetworkID,
			LocalPeerID:    persisted.LocalPeerID,
			RemotePeerID:   persisted.RemotePeerID,
			RemoteUserID:   persisted.RemoteUserID,
			SourcePath:     persisted.SourcePath,
			FileName:       persisted.FileName,
			ContentType:    firstNonEmptyString(persisted.ContentType, "application/octet-stream"),
			PayloadSHA256:  persisted.PayloadSHA256,
			SizeBytes:      persisted.SizeBytes,
			UploadedAtUnix: persisted.UploadedAtUnix,
		})
		if promoted {
			persisted.RemotePeerID = promotedSource.RemotePeerID
			persisted.RemoteUserID = promotedSource.RemoteUserID
			state.SetFileTransferSource(persisted)
			changed = true
		}
		a.fileTransferSources[persisted.TransferID] = localFileTransferSource{
			TransferID:     persisted.TransferID,
			NetworkID:      persisted.NetworkID,
			LocalPeerID:    persisted.LocalPeerID,
			RemotePeerID:   promotedSource.RemotePeerID,
			RemoteUserID:   promotedSource.RemoteUserID,
			SourcePath:     persisted.SourcePath,
			FileName:       persisted.FileName,
			ContentType:    promotedSource.ContentType,
			PayloadSHA256:  persisted.PayloadSHA256,
			SizeBytes:      persisted.SizeBytes,
			UploadedAtUnix: persisted.UploadedAtUnix,
		}
	}
	if changed {
		return a.savePersistentStateLocked()
	}
	return nil
}

func (a *Agent) pruneFileTransferSourcesLocked(managedPeers []ManagedPeerState) error {
	if a.currentUser == nil || a.deviceState == nil {
		a.fileTransferSources = map[string]localFileTransferSource{}
		return nil
	}
	allowed := map[string]struct{}{}
	for _, managedPeer := range managedPeers {
		allowed[managedPeer.NetworkID+"|"+managedPeer.PeerID] = struct{}{}
	}
	replacementPeersByNetwork := replacementManagedPeerIDsByNetwork(managedPeers)
	changed := false
	for transferID, source := range a.fileTransferSources {
		if _, ok := allowed[source.NetworkID+"|"+source.LocalPeerID]; ok {
			if promotedSource, promoted := a.promotePersistedFileTransferSourceRemotePeerLocked(source); promoted {
				a.fileTransferSources[transferID] = promotedSource
				a.deviceState.SetFileTransferSource(a.fileTransferSourceStateLocked(promotedSource))
				changed = true
			}
			continue
		}
		if replacementPeerID := replacementPeersByNetwork[source.NetworkID]; replacementPeerID != "" {
			source.LocalPeerID = replacementPeerID
			if promotedSource, promoted := a.promotePersistedFileTransferSourceRemotePeerLocked(source); promoted {
				source = promotedSource
			}
			a.fileTransferSources[transferID] = source
			a.deviceState.SetFileTransferSource(a.fileTransferSourceStateLocked(source))
			changed = true
			continue
		}
		delete(a.fileTransferSources, transferID)
	}
	if a.deviceState.PruneFileTransferSources(a.remote.BaseURL(), a.currentUser.ID, allowed) {
		changed = true
	}
	if changed {
		return a.savePersistentStateLocked()
	}
	return nil
}

func (a *Agent) persistFileTransferCacheLocked(cache localFileTransferCache) error {
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return err
	}
	if a.currentUser == nil {
		return nil
	}
	state.SetFileTransferCache(FileTransferCacheState{
		ServerBaseURL:  a.remote.BaseURL(),
		UserID:         a.currentUser.ID,
		TransferID:     strings.TrimSpace(cache.TransferID),
		NetworkID:      strings.TrimSpace(cache.NetworkID),
		LocalPeerID:    strings.TrimSpace(cache.LocalPeerID),
		RemotePeerID:   strings.TrimSpace(cache.RemotePeerID),
		CachePath:      strings.TrimSpace(cache.CachePath),
		FileName:       strings.TrimSpace(cache.FileName),
		ContentType:    strings.TrimSpace(cache.ContentType),
		PayloadSHA256:  strings.TrimSpace(cache.PayloadSHA256),
		SizeBytes:      cache.SizeBytes,
		CachedBytes:    cache.CachedBytes,
		UploadedAtUnix: cache.UploadedAtUnix,
	})
	return a.savePersistentStateLocked()
}

func (a *Agent) restorePersistedFileTransferCachesLocked() error {
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return err
	}
	a.fileTransferCaches = map[string]localFileTransferCache{}
	if a.currentUser == nil {
		return nil
	}
	serverBaseURL := a.remote.BaseURL()
	userID := a.currentUser.ID
	managedPeers := state.ManagedPeersFor(serverBaseURL, userID)
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	allowed := map[string]struct{}{}
	for _, peer := range managedPeers {
		allowed[peer.NetworkID+"|"+peer.PeerID] = struct{}{}
	}
	replacementPeersByNetwork := replacementManagedPeerIDsByNetwork(managedPeers)
	caches := state.FileTransferCachesFor(serverBaseURL, userID)
	changed := false
	for _, persisted := range caches {
		if _, ok := allowed[persisted.NetworkID+"|"+persisted.LocalPeerID]; !ok {
			if replacementPeerID := replacementPeersByNetwork[persisted.NetworkID]; replacementPeerID != "" {
				persisted.LocalPeerID = replacementPeerID
				state.SetFileTransferCache(persisted)
				changed = true
			} else {
				if state.DeleteFileTransferCache(serverBaseURL, userID, persisted.TransferID) {
					changed = true
				}
				continue
			}
		}
		info, statErr := os.Stat(persisted.CachePath)
		if statErr != nil || info.IsDir() {
			if state.DeleteFileTransferCache(serverBaseURL, userID, persisted.TransferID) {
				changed = true
			}
			continue
		}
		cachedBytes := minInt64(maxInt64(0, persisted.CachedBytes), info.Size())
		if persisted.SizeBytes > 0 {
			cachedBytes = minInt64(cachedBytes, persisted.SizeBytes)
		}
		if cachedBytes <= 0 {
			if state.DeleteFileTransferCache(serverBaseURL, userID, persisted.TransferID) {
				changed = true
			}
			continue
		}
		if cachedBytes != persisted.CachedBytes {
			persisted.CachedBytes = cachedBytes
			state.SetFileTransferCache(persisted)
			changed = true
		}
		promotedCache, promoted := a.promotePersistedFileTransferCacheRemotePeerLocked(localFileTransferCache{
			TransferID:     persisted.TransferID,
			NetworkID:      persisted.NetworkID,
			LocalPeerID:    persisted.LocalPeerID,
			RemotePeerID:   persisted.RemotePeerID,
			CachePath:      persisted.CachePath,
			FileName:       persisted.FileName,
			ContentType:    firstNonEmptyString(persisted.ContentType, "application/octet-stream"),
			PayloadSHA256:  persisted.PayloadSHA256,
			SizeBytes:      persisted.SizeBytes,
			CachedBytes:    cachedBytes,
			UploadedAtUnix: persisted.UploadedAtUnix,
		})
		if promoted {
			persisted.RemotePeerID = promotedCache.RemotePeerID
			state.SetFileTransferCache(persisted)
			changed = true
		}
		a.fileTransferCaches[persisted.TransferID] = localFileTransferCache{
			TransferID:     persisted.TransferID,
			NetworkID:      persisted.NetworkID,
			LocalPeerID:    persisted.LocalPeerID,
			RemotePeerID:   promotedCache.RemotePeerID,
			CachePath:      persisted.CachePath,
			FileName:       persisted.FileName,
			ContentType:    promotedCache.ContentType,
			PayloadSHA256:  persisted.PayloadSHA256,
			SizeBytes:      persisted.SizeBytes,
			CachedBytes:    cachedBytes,
			UploadedAtUnix: persisted.UploadedAtUnix,
		}
	}
	if changed {
		return a.savePersistentStateLocked()
	}
	return nil
}

func (a *Agent) pruneFileTransferCachesLocked(managedPeers []ManagedPeerState) error {
	if a.currentUser == nil || a.deviceState == nil {
		a.fileTransferCaches = map[string]localFileTransferCache{}
		return nil
	}
	allowed := map[string]struct{}{}
	for _, managedPeer := range managedPeers {
		allowed[managedPeer.NetworkID+"|"+managedPeer.PeerID] = struct{}{}
	}
	replacementPeersByNetwork := replacementManagedPeerIDsByNetwork(managedPeers)
	changed := false
	for transferID, cache := range a.fileTransferCaches {
		if _, ok := allowed[cache.NetworkID+"|"+cache.LocalPeerID]; ok {
			if promotedCache, promoted := a.promotePersistedFileTransferCacheRemotePeerLocked(cache); promoted {
				a.fileTransferCaches[transferID] = promotedCache
				a.deviceState.SetFileTransferCache(a.fileTransferCacheStateLocked(promotedCache))
				changed = true
			}
			continue
		}
		if replacementPeerID := replacementPeersByNetwork[cache.NetworkID]; replacementPeerID != "" {
			cache.LocalPeerID = replacementPeerID
			if promotedCache, promoted := a.promotePersistedFileTransferCacheRemotePeerLocked(cache); promoted {
				cache = promotedCache
			}
			a.fileTransferCaches[transferID] = cache
			a.deviceState.SetFileTransferCache(a.fileTransferCacheStateLocked(cache))
			changed = true
			continue
		}
		delete(a.fileTransferCaches, transferID)
	}
	if a.deviceState.PruneFileTransferCaches(a.remote.BaseURL(), a.currentUser.ID, allowed) {
		changed = true
	}
	if changed {
		return a.savePersistentStateLocked()
	}
	return nil
}

func replacementManagedPeerIDsByNetwork(managedPeers []ManagedPeerState) map[string]string {
	replacements := make(map[string]string, len(managedPeers))
	ambiguous := map[string]struct{}{}
	for _, managedPeer := range managedPeers {
		networkID := strings.TrimSpace(managedPeer.NetworkID)
		peerID := strings.TrimSpace(managedPeer.PeerID)
		if networkID == "" || peerID == "" {
			continue
		}
		if existing, ok := replacements[networkID]; ok && existing != peerID {
			delete(replacements, networkID)
			ambiguous[networkID] = struct{}{}
			continue
		}
		if _, ok := ambiguous[networkID]; ok {
			continue
		}
		replacements[networkID] = peerID
	}
	return replacements
}

func (a *Agent) promotePersistedFileTransferSourceRemotePeerLocked(source localFileTransferSource) (localFileTransferSource, bool) {
	expectedRemoteUserID := strings.TrimSpace(firstNonEmptyString(source.RemoteUserID, a.peerUserIDInNetworkUnlocked(source.NetworkID, source.RemotePeerID)))
	preferredRemotePeerID := a.preferredActiveTransferRemotePeerIDLocked(source.NetworkID, source.RemotePeerID, expectedRemoteUserID)
	if preferredRemotePeerID == "" || strings.EqualFold(strings.TrimSpace(source.RemotePeerID), preferredRemotePeerID) {
		return source, false
	}
	source.RemotePeerID = preferredRemotePeerID
	source.RemoteUserID = firstNonEmptyString(strings.TrimSpace(a.connectionRemoteUserIDUnlocked(source.NetworkID, preferredRemotePeerID)), strings.TrimSpace(a.peerUserIDInNetworkUnlocked(source.NetworkID, preferredRemotePeerID)), source.RemoteUserID)
	return source, true
}

func (a *Agent) promotePersistedFileTransferCacheRemotePeerLocked(cache localFileTransferCache) (localFileTransferCache, bool) {
	expectedRemoteUserID := ""
	if a.currentUser != nil {
		expectedRemoteUserID = strings.TrimSpace(a.currentUser.ID)
	}
	preferredRemotePeerID := a.preferredActiveTransferRemotePeerIDLocked(cache.NetworkID, cache.RemotePeerID, expectedRemoteUserID)
	if preferredRemotePeerID == "" || strings.EqualFold(strings.TrimSpace(cache.RemotePeerID), preferredRemotePeerID) {
		return cache, false
	}
	cache.RemotePeerID = preferredRemotePeerID
	return cache, true
}

func (a *Agent) preferredActiveTransferRemotePeerIDLocked(networkID, expectedPeerID, expectedUserID string) string {
	networkID = strings.TrimSpace(networkID)
	expectedPeerID = strings.TrimSpace(expectedPeerID)
	expectedUserID = strings.TrimSpace(expectedUserID)
	if networkID == "" || expectedPeerID == "" {
		return ""
	}
	var best *ConnectionStatus
	for idx := range a.connections {
		connection := &a.connections[idx]
		if !connection.TransportReady || !strings.EqualFold(strings.TrimSpace(connection.NetworkID), networkID) {
			continue
		}
		if !a.connectionMatchesRemotePeerTargetLocked(networkID, expectedPeerID, expectedUserID, connection) {
			continue
		}
		if best == nil || betterSignalingConnection(connection, best) {
			best = connection
		}
	}
	if best == nil {
		return ""
	}
	return strings.TrimSpace(best.RemotePeerID)
}

func (a *Agent) fileTransferSourceStateLocked(source localFileTransferSource) FileTransferSourceState {
	userID := ""
	if a.currentUser != nil {
		userID = a.currentUser.ID
	}
	return FileTransferSourceState{
		ServerBaseURL:  a.remote.BaseURL(),
		UserID:         userID,
		TransferID:     strings.TrimSpace(source.TransferID),
		NetworkID:      strings.TrimSpace(source.NetworkID),
		LocalPeerID:    strings.TrimSpace(source.LocalPeerID),
		RemotePeerID:   strings.TrimSpace(source.RemotePeerID),
		RemoteUserID:   strings.TrimSpace(source.RemoteUserID),
		SourcePath:     strings.TrimSpace(source.SourcePath),
		FileName:       strings.TrimSpace(source.FileName),
		ContentType:    strings.TrimSpace(source.ContentType),
		PayloadSHA256:  strings.TrimSpace(source.PayloadSHA256),
		SizeBytes:      source.SizeBytes,
		UploadedAtUnix: source.UploadedAtUnix,
	}
}

func (a *Agent) fileTransferCacheStateLocked(cache localFileTransferCache) FileTransferCacheState {
	userID := ""
	if a.currentUser != nil {
		userID = a.currentUser.ID
	}
	return FileTransferCacheState{
		ServerBaseURL:  a.remote.BaseURL(),
		UserID:         userID,
		TransferID:     strings.TrimSpace(cache.TransferID),
		NetworkID:      strings.TrimSpace(cache.NetworkID),
		LocalPeerID:    strings.TrimSpace(cache.LocalPeerID),
		RemotePeerID:   strings.TrimSpace(cache.RemotePeerID),
		CachePath:      strings.TrimSpace(cache.CachePath),
		FileName:       strings.TrimSpace(cache.FileName),
		ContentType:    strings.TrimSpace(cache.ContentType),
		PayloadSHA256:  strings.TrimSpace(cache.PayloadSHA256),
		SizeBytes:      cache.SizeBytes,
		CachedBytes:    cache.CachedBytes,
		UploadedAtUnix: cache.UploadedAtUnix,
	}
}

func (a *Agent) cachedFileTransferBytesLocked(transferID string) int64 {
	cache, ok := a.fileTransferCaches[transferID]
	if !ok {
		return 0
	}
	return maxInt64(0, cache.CachedBytes)
}

func (a *Agent) fileTransferCachePathLocked(transferID string) string {
	transferID = strings.TrimSpace(transferID)
	if transferID == "" {
		return ""
	}
	baseDir := filepath.Dir(a.statePathLocked())
	if strings.TrimSpace(baseDir) == "" || baseDir == "." {
		baseDir = "."
	}
	name := strings.NewReplacer("\\", "-", "/", "-", ":", "-", "*", "-", "?", "-", "\"", "-", "<", "-", ">", "-", "|", "-").Replace(transferID)
	return filepath.Join(baseDir, "file-transfer-cache", name+".part")
}

func (a *Agent) transportExchangeHandler(localPeerID string) func(string, []byte) []byte {
	return func(remotePeerID string, payload []byte) []byte {
		var request fileTransferDataplaneRequest
		if err := json.Unmarshal(payload, &request); err != nil || request.Type != "file-transfer-chunk-request" {
			return nil
		}
		response := a.buildFileTransferDataplaneResponse(localPeerID, remotePeerID, request)
		return encodeFileTransferDataplaneResponse(response)
	}
}

func (a *Agent) buildFileTransferDataplaneResponse(localPeerID, remotePeerID string, request fileTransferDataplaneRequest) fileTransferDataplaneResponse {
	response := fileTransferDataplaneResponse{
		Type:        "file-transfer-chunk-response",
		OffsetBytes: maxInt64(0, request.OffsetBytes),
	}
	a.mu.Lock()
	source, ok := a.fileTransferSources[request.TransferID]
	cache, cacheOK := a.fileTransferCaches[request.TransferID]
	cacheRequesterAllowed := false
	sourceRequesterAllowed := false
	sourceRequesterUserID := ""
	if !ok && cacheOK {
		if !a.rebindFileTransferCacheToActiveManagedPeerLocked(request.TransferID, &cache, localPeerID, remotePeerID) {
			a.mu.Unlock()
			response.Error = "file transfer source is not available for this peer pair"
			return response
		}
		cacheRequesterAllowed = a.fileTransferCacheRequesterMatchesLocked(localPeerID, cache, remotePeerID)
	}
	if ok {
		if !a.rebindFileTransferSourceToActiveManagedPeerLocked(request.TransferID, &source, localPeerID, remotePeerID) {
			a.mu.Unlock()
			response.Error = "file transfer source is not available for this peer pair"
			return response
		}
		sourceRequesterAllowed, sourceRequesterUserID = a.fileTransferSourceRequesterMatchesLocked(localPeerID, source, remotePeerID)
	}
	a.mu.Unlock()
	if !ok {
		if !cacheOK {
			response.Error = "file transfer source is not registered on sender"
			return response
		}
		if !cacheRequesterAllowed {
			response.Error = "file transfer source is not available for this peer pair"
			return response
		}
		a.rebindFileTransferCacheRemotePeerOnFirstUse(request.TransferID, &cache, remotePeerID)
		if request.OffsetBytes < 0 {
			response.Error = "file transfer dataplane offset is invalid"
			return response
		}
		if request.OffsetBytes > cache.CachedBytes {
			response.Error = "file transfer dataplane offset exceeds cached transfer size"
			return response
		}
		limitBytes := request.LimitBytes
		if limitBytes <= 0 {
			limitBytes = fileTransferDataplaneChunkBytes
		}
		if limitBytes > fileTransferDataplaneChunkBytes {
			limitBytes = fileTransferDataplaneChunkBytes
		}
		response.ContentType = firstNonEmptyString(strings.TrimSpace(cache.ContentType), "application/octet-stream")
		response.SHA256 = strings.TrimSpace(cache.PayloadSHA256)
		response.TotalSizeBytes = cache.SizeBytes
		response.UploadedAtUnix = cache.UploadedAtUnix
		if request.OffsetBytes == cache.CachedBytes {
			response.NextOffsetBytes = cache.CachedBytes
			response.Complete = cache.SizeBytes >= 0 && cache.CachedBytes >= cache.SizeBytes
			return response
		}
		file, err := os.Open(cache.CachePath)
		if err != nil {
			response.Error = err.Error()
			return response
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			response.Error = err.Error()
			return response
		}
		actualCachedBytes := minInt64(maxInt64(0, cache.CachedBytes), info.Size())
		if request.OffsetBytes > actualCachedBytes {
			response.Error = "file transfer dataplane offset exceeds cached transfer size"
			return response
		}
		if _, err := file.Seek(request.OffsetBytes, io.SeekStart); err != nil {
			response.Error = err.Error()
			return response
		}
		availableBytes := actualCachedBytes - request.OffsetBytes
		if availableBytes < limitBytes {
			limitBytes = availableBytes
		}
		buffer := make([]byte, limitBytes)
		n, err := file.Read(buffer)
		if err != nil && !errors.Is(err, io.EOF) {
			response.Error = err.Error()
			return response
		}
		response.Payload = append([]byte(nil), buffer[:n]...)
		response.NextOffsetBytes = request.OffsetBytes + int64(n)
		response.Complete = cache.SizeBytes >= 0 && response.NextOffsetBytes >= cache.SizeBytes && actualCachedBytes >= cache.SizeBytes
		return response
	}
	if source.RemotePeerID != remotePeerID {
		if !sourceRequesterAllowed {
			response.Error = "file transfer source is not available for this peer pair"
			return response
		}
		a.rebindFileTransferSourceRemotePeerOnFirstUse(request.TransferID, &source, remotePeerID, sourceRequesterUserID)
	}
	if request.OffsetBytes < 0 {
		response.Error = "file transfer dataplane offset is invalid"
		return response
	}
	if request.OffsetBytes > source.SizeBytes {
		response.Error = "file transfer dataplane offset exceeds transfer size"
		return response
	}
	limitBytes := request.LimitBytes
	if limitBytes <= 0 {
		limitBytes = fileTransferDataplaneChunkBytes
	}
	if limitBytes > fileTransferDataplaneChunkBytes {
		limitBytes = fileTransferDataplaneChunkBytes
	}
	response.ContentType = firstNonEmptyString(strings.TrimSpace(source.ContentType), "application/octet-stream")
	response.SHA256 = strings.TrimSpace(source.PayloadSHA256)
	response.TotalSizeBytes = source.SizeBytes
	response.UploadedAtUnix = source.UploadedAtUnix
	if request.OffsetBytes == source.SizeBytes {
		response.NextOffsetBytes = source.SizeBytes
		response.Complete = true
		return response
	}
	file, err := os.Open(source.SourcePath)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		response.Error = err.Error()
		return response
	}
	if info.Size() != source.SizeBytes {
		response.Error = fmt.Sprintf("source file size changed to %d bytes", info.Size())
		return response
	}
	if _, err := file.Seek(request.OffsetBytes, io.SeekStart); err != nil {
		response.Error = err.Error()
		return response
	}
	buffer := make([]byte, limitBytes)
	n, err := file.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		response.Error = err.Error()
		return response
	}
	response.Payload = append([]byte(nil), buffer[:n]...)
	response.NextOffsetBytes = request.OffsetBytes + int64(n)
	response.Complete = response.NextOffsetBytes >= source.SizeBytes
	return response
}

func (a *Agent) rebindFileTransferSourceToActiveManagedPeerLocked(transferID string, source *localFileTransferSource, localPeerID, remotePeerID string) bool {
	if source == nil {
		return false
	}
	localPeerID = strings.TrimSpace(localPeerID)
	if localPeerID == "" {
		return false
	}
	activeLocalPeerID := strings.TrimSpace(a.currentManagedPeerIDForNetworkLocked(source.NetworkID))
	currentLocalPeerID := strings.TrimSpace(source.LocalPeerID)
	if strings.EqualFold(currentLocalPeerID, localPeerID) {
		if activeLocalPeerID == "" || strings.EqualFold(currentLocalPeerID, activeLocalPeerID) {
			return true
		}
		if !a.transferRequestUsesSupersededLocalPeerLocked(source.NetworkID, activeLocalPeerID, localPeerID, remotePeerID) {
			return false
		}
		source.LocalPeerID = activeLocalPeerID
		a.fileTransferSources[transferID] = *source
		if a.deviceState != nil && a.currentUser != nil {
			a.deviceState.SetFileTransferSource(a.fileTransferSourceStateLocked(*source))
			if err := a.savePersistentStateLocked(); err != nil {
				a.logErrorf("persist rebound file transfer source failed for %s: %v", transferID, err)
			}
		}
		return true
	}
	if strings.EqualFold(localPeerID, activeLocalPeerID) {
		source.LocalPeerID = activeLocalPeerID
		a.fileTransferSources[transferID] = *source
		if a.deviceState != nil && a.currentUser != nil {
			a.deviceState.SetFileTransferSource(a.fileTransferSourceStateLocked(*source))
			if err := a.savePersistentStateLocked(); err != nil {
				a.logErrorf("persist rebound file transfer source failed for %s: %v", transferID, err)
			}
		}
		return true
	}
	if !a.transferRequestUsesSupersededLocalPeerLocked(source.NetworkID, activeLocalPeerID, localPeerID, remotePeerID) {
		return false
	}
	if activeLocalPeerID != "" && !strings.EqualFold(currentLocalPeerID, activeLocalPeerID) {
		source.LocalPeerID = activeLocalPeerID
		a.fileTransferSources[transferID] = *source
		if a.deviceState != nil && a.currentUser != nil {
			a.deviceState.SetFileTransferSource(a.fileTransferSourceStateLocked(*source))
			if err := a.savePersistentStateLocked(); err != nil {
				a.logErrorf("persist rebound file transfer source failed for %s: %v", transferID, err)
			}
		}
	}
	return true
}

func (a *Agent) rebindFileTransferSourceRemotePeerOnFirstUse(transferID string, source *localFileTransferSource, remotePeerID, remoteUserID string) {
	if source == nil {
		return
	}
	remotePeerID = strings.TrimSpace(remotePeerID)
	remoteUserID = strings.TrimSpace(remoteUserID)
	if remotePeerID == "" {
		return
	}
	if strings.EqualFold(strings.TrimSpace(source.RemotePeerID), remotePeerID) && (remoteUserID == "" || strings.EqualFold(strings.TrimSpace(source.RemoteUserID), remoteUserID)) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	current, ok := a.fileTransferSources[transferID]
	if !ok {
		return
	}
	preferredRemotePeerID := a.preferredFileTransferRemotePeerOnFirstUseLocked(current.NetworkID, current.LocalPeerID, current.RemotePeerID, remotePeerID, firstNonEmptyString(remoteUserID, current.RemoteUserID))
	preferredRemoteUserID := firstNonEmptyString(remoteUserID, current.RemoteUserID)
	if strings.EqualFold(strings.TrimSpace(current.RemotePeerID), preferredRemotePeerID) && strings.EqualFold(strings.TrimSpace(current.RemoteUserID), preferredRemoteUserID) {
		return
	}
	current.RemotePeerID = preferredRemotePeerID
	current.RemoteUserID = preferredRemoteUserID
	*source = current
	a.fileTransferSources[transferID] = current
	if a.deviceState != nil && a.currentUser != nil {
		a.deviceState.SetFileTransferSource(a.fileTransferSourceStateLocked(current))
		if err := a.savePersistentStateLocked(); err != nil {
			a.logErrorf("persist rebound file transfer source remote peer failed for %s: %v", transferID, err)
		}
	}
}

func (a *Agent) rebindFileTransferCacheToActiveManagedPeerLocked(transferID string, cache *localFileTransferCache, localPeerID, remotePeerID string) bool {
	if cache == nil {
		return false
	}
	localPeerID = strings.TrimSpace(localPeerID)
	if localPeerID == "" {
		return false
	}
	activeLocalPeerID := strings.TrimSpace(a.currentManagedPeerIDForNetworkLocked(cache.NetworkID))
	currentLocalPeerID := strings.TrimSpace(cache.LocalPeerID)
	if strings.EqualFold(currentLocalPeerID, localPeerID) {
		if activeLocalPeerID == "" || strings.EqualFold(currentLocalPeerID, activeLocalPeerID) {
			return true
		}
		if !a.transferRequestUsesSupersededLocalPeerLocked(cache.NetworkID, activeLocalPeerID, localPeerID, remotePeerID) {
			return false
		}
		cache.LocalPeerID = activeLocalPeerID
		a.fileTransferCaches[transferID] = *cache
		if a.deviceState != nil && a.currentUser != nil {
			a.deviceState.SetFileTransferCache(a.fileTransferCacheStateLocked(*cache))
			if err := a.savePersistentStateLocked(); err != nil {
				a.logErrorf("persist rebound file transfer cache failed for %s: %v", transferID, err)
			}
		}
		return true
	}
	if strings.EqualFold(localPeerID, activeLocalPeerID) {
		cache.LocalPeerID = activeLocalPeerID
		a.fileTransferCaches[transferID] = *cache
		if a.deviceState != nil && a.currentUser != nil {
			a.deviceState.SetFileTransferCache(a.fileTransferCacheStateLocked(*cache))
			if err := a.savePersistentStateLocked(); err != nil {
				a.logErrorf("persist rebound file transfer cache failed for %s: %v", transferID, err)
			}
		}
		return true
	}
	if !a.transferRequestUsesSupersededLocalPeerLocked(cache.NetworkID, activeLocalPeerID, localPeerID, remotePeerID) {
		return false
	}
	if activeLocalPeerID != "" && !strings.EqualFold(currentLocalPeerID, activeLocalPeerID) {
		cache.LocalPeerID = activeLocalPeerID
		a.fileTransferCaches[transferID] = *cache
		if a.deviceState != nil && a.currentUser != nil {
			a.deviceState.SetFileTransferCache(a.fileTransferCacheStateLocked(*cache))
			if err := a.savePersistentStateLocked(); err != nil {
				a.logErrorf("persist rebound file transfer cache failed for %s: %v", transferID, err)
			}
		}
	}
	return true
}

func (a *Agent) transferRequestUsesSupersededLocalPeerLocked(networkID, activeLocalPeerID, localPeerID, remotePeerID string) bool {
	networkID = strings.TrimSpace(networkID)
	activeLocalPeerID = strings.TrimSpace(activeLocalPeerID)
	localPeerID = strings.TrimSpace(localPeerID)
	remotePeerID = strings.TrimSpace(remotePeerID)
	if networkID == "" || activeLocalPeerID == "" || localPeerID == "" || remotePeerID == "" {
		return false
	}
	if strings.EqualFold(localPeerID, activeLocalPeerID) {
		return true
	}
	exact := a.connectionByPeersLocked(networkID, localPeerID, remotePeerID)
	if exact == nil {
		return false
	}
	return a.preferredTransportConnectionForLocalPeerLocked(networkID, activeLocalPeerID, exact) != nil
}

func (a *Agent) rebindFileTransferCacheRemotePeerOnFirstUse(transferID string, cache *localFileTransferCache, remotePeerID string) {
	if cache == nil {
		return
	}
	remotePeerID = strings.TrimSpace(remotePeerID)
	if remotePeerID == "" || strings.EqualFold(strings.TrimSpace(cache.RemotePeerID), remotePeerID) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	current, ok := a.fileTransferCaches[transferID]
	if !ok {
		return
	}
	expectedRemoteUserID := strings.TrimSpace(a.peerUserIDInNetworkUnlocked(current.NetworkID, current.RemotePeerID))
	if a.currentUser != nil {
		expectedRemoteUserID = firstNonEmptyString(strings.TrimSpace(a.currentUser.ID), expectedRemoteUserID)
	}
	preferredRemotePeerID := a.preferredFileTransferRemotePeerOnFirstUseLocked(current.NetworkID, current.LocalPeerID, current.RemotePeerID, remotePeerID, expectedRemoteUserID)
	if strings.EqualFold(strings.TrimSpace(current.RemotePeerID), preferredRemotePeerID) {
		return
	}
	current.RemotePeerID = preferredRemotePeerID
	*cache = current
	a.fileTransferCaches[transferID] = current
	if a.deviceState != nil && a.currentUser != nil {
		a.deviceState.SetFileTransferCache(a.fileTransferCacheStateLocked(current))
		if err := a.savePersistentStateLocked(); err != nil {
			a.logErrorf("persist rebound file transfer cache remote peer failed for %s: %v", transferID, err)
		}
	}
}

func (a *Agent) preferredFileTransferRemotePeerOnFirstUseLocked(networkID, localPeerID, currentRemotePeerID, candidateRemotePeerID, expectedRemoteUserID string) string {
	networkID = strings.TrimSpace(networkID)
	localPeerID = strings.TrimSpace(localPeerID)
	currentRemotePeerID = strings.TrimSpace(currentRemotePeerID)
	candidateRemotePeerID = strings.TrimSpace(candidateRemotePeerID)
	expectedRemoteUserID = strings.TrimSpace(expectedRemoteUserID)
	switch {
	case candidateRemotePeerID == "":
		return currentRemotePeerID
	case currentRemotePeerID == "":
		return candidateRemotePeerID
	case strings.EqualFold(currentRemotePeerID, candidateRemotePeerID):
		return currentRemotePeerID
	}

	currentConnection := a.connectionByPeersLocked(networkID, localPeerID, currentRemotePeerID)
	candidateConnection := a.connectionByPeersLocked(networkID, localPeerID, candidateRemotePeerID)
	switch {
	case currentConnection != nil && candidateConnection != nil:
		if a.sameTransportRoutingTargetLocked(currentConnection, candidateConnection) {
			if betterSignalingConnection(candidateConnection, currentConnection) {
				return candidateRemotePeerID
			}
			return currentRemotePeerID
		}
	case currentConnection != nil:
		if a.connectionMatchesRemotePeerTargetLocked(networkID, candidateRemotePeerID, expectedRemoteUserID, currentConnection) {
			return currentRemotePeerID
		}
	case candidateConnection != nil:
		if a.connectionMatchesRemotePeerTargetLocked(networkID, currentRemotePeerID, expectedRemoteUserID, candidateConnection) {
			return candidateRemotePeerID
		}
	}

	currentTarget := a.peerTargetInNetworkUnlocked(networkID, currentRemotePeerID)
	candidateTarget := a.peerTargetInNetworkUnlocked(networkID, candidateRemotePeerID)
	if strings.TrimSpace(currentTarget.ID) != "" && strings.TrimSpace(candidateTarget.ID) != "" && sameOverlayPeerTarget(currentTarget, candidateTarget) {
		return currentRemotePeerID
	}
	return candidateRemotePeerID
}

func (a *Agent) localPeerMatchesActiveManagedPeerLocked(networkID, localPeerID string) bool {
	if strings.TrimSpace(networkID) == "" || strings.TrimSpace(localPeerID) == "" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(a.currentManagedPeerIDForNetworkLocked(networkID)), strings.TrimSpace(localPeerID))
}

func (a *Agent) clearPersistentSessionLocked(clearManagedPeers bool) {
	serverBaseURL := a.remote.BaseURL()
	userID := ""
	if a.currentUser != nil {
		userID = a.currentUser.ID
	}
	a.clearInMemorySessionLocked()
	if a.deviceState != nil {
		a.deviceState.ClearSession(serverBaseURL)
		if clearManagedPeers && userID != "" {
			a.deviceState.ClearManagedPeers(serverBaseURL, userID)
			a.deviceState.ClearFileTransferSources(serverBaseURL, userID)
			a.deviceState.ClearFileTransferCaches(serverBaseURL, userID)
		}
		_ = a.savePersistentStateLocked()
	}
	_ = a.reconcileManagedRuntimeLocked()
}

func (a *Agent) snapshotLocked() Status {
	reconnectState, reconnectBackoffActive, reconnectRemaining := a.reconnectStatusLocked(time.Now())
	dnsStatus := overlaydns.Status{}
	if a.overlayDNS != nil {
		dnsStatus = a.overlayDNS.Snapshot()
	}
	return Status{
		ServiceName:             "Ole Agent",
		ListenAddress:           a.listenAddress,
		ServerBaseURL:           a.remote.BaseURL(),
		ClientVersion:           a.remote.ClientVersion(),
		ServerVersion:           a.serverVersion,
		MinClientVersion:        a.minClientVersion,
		CompatibilityStatus:     firstNonEmptyString(a.compatibilityStatus, versioninfo.StatusUnknown),
		CompatibilityMessage:    a.compatibilityMessage,
		DirectMetrics:           a.directMetrics,
		RelayServerAddresses:    a.resolveRelayServerAddressesLocked(),
		ActiveRelayServer:       a.resolveRelayServerAddressLocked(),
		RelayFailoverCount:      a.relayFailoverCount,
		StatePath:               a.statePathLocked(),
		StartedAtUnix:           a.startedAt.Unix(),
		UncleanShutdownDetected: a.uncleanShutdownDetected,
		LastStartUnix:           lifecycleUnixOrZero(a.deviceState, func(lifecycle ServiceLifecycleState) int64 { return lifecycle.LastStartUnix }),
		LastCleanShutdownUnix:   unixOrZero(a.lastCleanShutdownAt),
		LastCrashRecoveryUnix:   unixOrZero(a.lastCrashRecoveryAt),
		CrashRecoveryCount:      a.crashRecoveryCount,
		Connected:               a.currentSession != nil && a.currentUser != nil,
		PersistedSession:        a.hasPersistedSessionLocked(),
		OverlayDNSListenAddress: dnsStatus.ListenAddress,
		OverlayDNSDomain:        dnsStatus.Domain,
		OverlayDNSRecordCount:   dnsStatus.RecordCount,
		OverlayDNSLastError:     dnsStatus.LastError,
		ManagedPeerCount:        a.managedPeerCountLocked(),
		DiscoveredPeerCount:     a.discoveredPeerCountLocked(),
		ReconnectState:          reconnectState,
		ReconnectBackoffActive:  reconnectBackoffActive,
		ReconnectAttemptCount:   a.reconnectAttemptCount,
		LastReconnectAttemptMs:  unixMilliOrZero(a.lastReconnectAttemptAt),
		NextReconnectAttemptMs:  unixMilliOrZero(a.nextReconnectAttemptAt),
		ReconnectRemainingMs:    reconnectRemaining.Milliseconds(),
		LastReconnectError:      a.lastReconnectError,
		LastSessionRefreshUnix:  unixOrZero(a.lastSessionRefreshAt),
		LastHeartbeatUnix:       unixOrZero(a.lastHeartbeatAt),
		LastPeerDiscoveryUnix:   unixOrZero(a.lastPeerDiscoveryAt),
		LastSTUNProbeUnix:       unixOrZero(a.lastSTUNProbeAt),
		LastDirectProbeUnix:     unixOrZero(a.lastDirectProbeAt),
		LastLifecycleError:      a.lastLifecycleError,
		STUNServerAddress:       a.resolveSTUNServerAddressLocked(),
		RelayServerAddress:      a.resolveRelayServerAddressLocked(),
		NATType:                 a.natType,
		PublicEndpoint:          a.publicEndpoint,
		Update:                  cloneUpdateStatus(a.updateStatus),
		Adapter:                 a.adapterSnapshotLocked(),
		Security:                cloneSecurityDiagnostics(a.securityDiagnostics),
		Incidents:               cloneIncidentSummary(a.incidentSummary),
		GroupTraffic:            cloneGroupTrafficDiagnostics(a.groupTrafficDiagnostics),
		GatewayHistory:          cloneGatewayHistory(a.gatewayHistory),
		Neighbors:               a.dedupeStatusNeighborsLocked(a.cloneStatusNeighborsLocked()),
		Connections:             a.dedupeStatusConnectionsLocked(a.cloneStatusConnectionsLocked()),
		CurrentUser:             cloneUser(a.currentUser),
		CurrentSession:          cloneSession(a.currentSession),
		CurrentDevice:           cloneDevice(a.currentDevice),
	}
}

func (a *Agent) maybeStartAutoUpdateCheckLocked(now time.Time) {
	manifestURL := a.resolveUpdateManifestURLLocked()
	if strings.TrimSpace(manifestURL) == "" || a.updateStatus.Checking {
		return
	}
	if !a.lastUpdateCheckAt.IsZero() && now.Sub(a.lastUpdateCheckAt) < a.runtime.UpdateCheckPeriod {
		return
	}
	a.updateStatus.Checking = true
	channel := a.resolveUpdateChannelLocked()
	currentVersion := a.remote.ClientVersion()
	go a.runAutoUpdateCheck(channel, manifestURL, currentVersion)
}

func (a *Agent) runAutoUpdateCheck(channel, manifestURL, currentVersion string) {
	result, err := a.checkForUpdatesNow(manifestURL, currentVersion)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.applyUpdateCheckResultLocked(channel, manifestURL, result, err)
	if err != nil {
		a.logErrorw("update.check.auto_failed", "automatic update check failed", "error", err, "channel", channel, "manifestURL", manifestURL)
		return
	}
	a.logInfow("update.check.auto_completed", "automatic update check completed", "channel", channel, "manifestURL", manifestURL, "available", result.Available, "latestVersion", result.Manifest.Version)
}

func (a *Agent) checkForUpdatesNow(manifestURL, currentVersion string) (autoupdate.CheckResult, error) {
	client := autoupdate.NewClient(manifestURL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return client.Check(ctx, currentVersion)
}

func (a *Agent) applyUpdateCheckResultLocked(channel, manifestURL string, result autoupdate.CheckResult, err error) {
	a.updateStatus.Channel = normalizeUpdateChannel(channel)
	a.updateStatus.AvailableChannels = availableUpdateChannelsForRuntime(a.runtime)
	a.updateStatus.ManifestURL = manifestURL
	a.updateStatus.CurrentVersion = a.remote.ClientVersion()
	a.updateStatus.CheckPeriodSec = int64(a.runtime.UpdateCheckPeriod / time.Second)
	a.updateStatus.Checking = false
	a.lastUpdateCheckAt = time.Now()
	a.updateStatus.LastCheckedUnix = a.lastUpdateCheckAt.Unix()
	if err != nil {
		a.updateStatus.LastError = err.Error()
		a.updateStatus.Available = false
		return
	}
	manifest := result.Manifest
	a.updateStatus.LatestVersion = manifest.Version
	a.updateStatus.PublishedAtUnix = manifest.PublishedAtUnix
	a.updateStatus.Available = result.Available
	a.updateStatus.MinimumServerVersion = manifest.Compatibility.MinimumServerVersion
	a.updateStatus.MaximumServerVersion = manifest.Compatibility.MaximumServerVersion
	a.updateStatus.MinimumRollbackVersion = manifest.Compatibility.MinimumRollbackVersion
	a.updateStatus.InstallerURL = manifest.InstallerURL
	a.updateStatus.ReleaseNotesURL = manifest.ReleaseNotesURL
	a.updateStatus.SignatureURL = manifest.SignatureURL
	a.updateStatus.CertificateURL = manifest.CertificateURL
	a.updateStatus.SHA256 = manifest.SHA256
	a.updateStatus.PolicyStatus, a.updateStatus.PolicyMessage = evaluateUpdatePolicy(a.serverVersion, manifest.Compatibility)
	a.updateStatus.LastError = ""
	if manifest.Rollback != nil {
		a.updateStatus.RollbackAvailable = true
		a.updateStatus.RollbackVersion = manifest.Rollback.Version
		a.updateStatus.RollbackReason = manifest.Rollback.Reason
		a.updateStatus.RollbackInstallerURL = manifest.Rollback.InstallerURL
		a.updateStatus.RollbackReleaseNotesURL = manifest.Rollback.ReleaseNotesURL
		a.updateStatus.RollbackSignatureURL = manifest.Rollback.SignatureURL
		a.updateStatus.RollbackCertificateURL = manifest.Rollback.CertificateURL
		a.updateStatus.RollbackSHA256 = manifest.Rollback.SHA256
	} else {
		a.updateStatus.RollbackAvailable = false
		a.updateStatus.RollbackVersion = ""
		a.updateStatus.RollbackReason = ""
		a.updateStatus.RollbackInstallerURL = ""
		a.updateStatus.RollbackReleaseNotesURL = ""
		a.updateStatus.RollbackSignatureURL = ""
		a.updateStatus.RollbackCertificateURL = ""
		a.updateStatus.RollbackSHA256 = ""
		a.updateStatus.RollbackDownloaded = false
		a.updateStatus.RollbackDownloadedPath = ""
		a.updateStatus.RollbackLastDownloadedUnix = 0
	}
	if !result.Available {
		a.updateStatus.Downloaded = false
		a.updateStatus.DownloadedPath = ""
		a.updateStatus.LastDownloadedUnix = 0
	}
	if a.updateStatus.Downloaded && strings.TrimSpace(a.updateStatus.DownloadedPath) != "" {
		if !fileExists(a.updateStatus.DownloadedPath) {
			a.updateStatus.Downloaded = false
			a.updateStatus.DownloadedPath = ""
			a.updateStatus.LastDownloadedUnix = 0
		}
	}
	if a.updateStatus.RollbackDownloaded && strings.TrimSpace(a.updateStatus.RollbackDownloadedPath) != "" {
		if !fileExists(a.updateStatus.RollbackDownloadedPath) {
			a.updateStatus.RollbackDownloaded = false
			a.updateStatus.RollbackDownloadedPath = ""
			a.updateStatus.RollbackLastDownloadedUnix = 0
		}
	}
}

func cloneUpdateStatus(status UpdateStatus) UpdateStatus {
	if status.AvailableChannels != nil {
		status.AvailableChannels = append([]string(nil), status.AvailableChannels...)
	}
	return status
}

func cloneIncidentSummary(summary IncidentSummary) IncidentSummary {
	return summary
}

func summarizeIncidentReports(reports []controlclient.IncidentReport, now time.Time) IncidentSummary {
	summary := IncidentSummary{LastCheckedUnix: now.Unix()}
	for _, report := range reports {
		if !strings.EqualFold(strings.TrimSpace(report.Status), "ACTIVE") {
			continue
		}
		summary.ActiveCount++
		switch strings.ToLower(strings.TrimSpace(report.Severity)) {
		case "critical":
			summary.CriticalCount++
		case "elevated":
			summary.ElevatedCount++
		case "warning":
			summary.WarningCount++
		}
		if strings.EqualFold(strings.TrimSpace(report.Category), "TOKEN_REUSE") {
			summary.TokenReuseCount++
		}
		if incidentSeverityRank(report.Severity) > incidentSeverityRank(summary.MostSevere) {
			summary.MostSevere = strings.ToLower(strings.TrimSpace(report.Severity))
			summary.RecommendedAction = strings.TrimSpace(report.RecommendedAction)
		}
		if report.UpdatedAtUnix > summary.LastUpdatedUnix {
			summary.LastUpdatedUnix = report.UpdatedAtUnix
		}
	}
	if strings.TrimSpace(summary.RecommendedAction) == "" && summary.ActiveCount > 0 {
		summary.RecommendedAction = "Open Incident Reports to review the active server or account incidents."
	}
	return summary
}

func incidentSeverityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 3
	case "elevated":
		return 2
	case "warning":
		return 1
	default:
		return 0
	}
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func normalizeUpdateChannel(channel string) string {
	switch strings.ToLower(strings.TrimSpace(channel)) {
	case updateChannelBeta:
		return updateChannelBeta
	case updateChannelStable:
		return updateChannelStable
	default:
		return updateChannelStable
	}
}

func containsString(values []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), target) {
			return true
		}
	}
	return false
}

func availableUpdateChannelsForRuntime(runtime RuntimeConfig) []string {
	channels := make([]string, 0, 2)
	if strings.TrimSpace(runtime.UpdateStableManifestURL) != "" || strings.TrimSpace(runtime.UpdateManifestURL) != "" {
		channels = append(channels, updateChannelStable)
	}
	if strings.TrimSpace(runtime.UpdateBetaManifestURL) != "" {
		channels = append(channels, updateChannelBeta)
	}
	return channels
}

func resolveUpdateManifestURLForRuntime(runtime RuntimeConfig, channel string) string {
	switch normalizeUpdateChannel(channel) {
	case updateChannelBeta:
		return strings.TrimSpace(runtime.UpdateBetaManifestURL)
	default:
		if strings.TrimSpace(runtime.UpdateStableManifestURL) != "" {
			return strings.TrimSpace(runtime.UpdateStableManifestURL)
		}
		return strings.TrimSpace(runtime.UpdateManifestURL)
	}
}

func (a *Agent) resolveUpdateChannelLocked() string {
	channels := availableUpdateChannelsForRuntime(a.runtime)
	if len(channels) == 0 {
		return normalizeUpdateChannel(a.runtime.UpdateChannel)
	}
	selected := normalizeUpdateChannel(a.runtime.UpdateChannel)
	if a.deviceState != nil {
		selected = normalizeUpdateChannel(a.deviceState.UpdateChannelOrDefault(selected))
	}
	if containsString(channels, selected) {
		return selected
	}
	return channels[0]
}

func (a *Agent) resolveUpdateManifestURLLocked() string {
	return resolveUpdateManifestURLForRuntime(a.runtime, a.resolveUpdateChannelLocked())
}

func evaluateUpdatePolicy(serverVersion string, policy autoupdate.CompatibilityPolicy) (string, string) {
	serverVersion = strings.TrimSpace(serverVersion)
	minServer := strings.TrimSpace(policy.MinimumServerVersion)
	maxServer := strings.TrimSpace(policy.MaximumServerVersion)
	switch {
	case minServer == "" && maxServer == "":
		return "COMPATIBLE", "update manifest does not restrict server compatibility"
	case serverVersion == "":
		return "UNKNOWN", "server version is unavailable, so update compatibility could not be verified"
	}
	if minServer != "" {
		if cmp, err := versioninfo.Compare(serverVersion, minServer); err == nil && cmp < 0 {
			return "BLOCKED_SERVER_TOO_OLD", fmt.Sprintf("server %s is below the minimum supported version %s for this update", serverVersion, minServer)
		}
	}
	if maxServer != "" {
		if cmp, err := versioninfo.Compare(serverVersion, maxServer); err == nil && cmp > 0 {
			return "BLOCKED_SERVER_TOO_NEW", fmt.Sprintf("server %s is above the maximum supported version %s for this update", serverVersion, maxServer)
		}
	}
	return "COMPATIBLE", "current server version is compatible with this update"
}

func updatePolicyBlocked(status string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(status)), "BLOCKED_")
}

func (a *Agent) reconnectStatusLocked(now time.Time) (string, bool, time.Duration) {
	switch {
	case a.currentSession != nil && a.currentUser != nil:
		return "CONNECTED", false, 0
	case !a.hasPersistedSessionLocked():
		return "NONE", false, 0
	case !a.nextReconnectAttemptAt.IsZero() && now.Before(a.nextReconnectAttemptAt):
		return "BACKOFF", true, a.nextReconnectAttemptAt.Sub(now)
	case a.reconnectAttemptCount > 0 || !a.lastReconnectAttemptAt.IsZero():
		return "READY", false, 0
	default:
		return "PERSISTED", false, 0
	}
}

func (a *Agent) refreshCompatibilityLocked() error {
	info, err := a.remote.GetServerInfo()
	if err != nil {
		return err
	}
	metadata := versioninfo.ServerMetadata{}
	if info != nil && info.Version != nil {
		metadata = *info.Version
	}
	compatibility := versioninfo.Evaluate(a.remote.ClientVersion(), metadata)
	a.serverVersion = metadata.ServerVersion
	a.minClientVersion = metadata.MinClientVersion
	a.compatibilityStatus = compatibility.Status
	a.compatibilityMessage = compatibility.Message
	return nil
}

func (a *Agent) ensureCompatibleLocked() error {
	if err := a.refreshCompatibilityLocked(); err != nil {
		return err
	}
	if strings.EqualFold(a.compatibilityStatus, versioninfo.StatusUpgradeRequired) {
		return errors.New(a.compatibilityMessage)
	}
	return nil
}

func (a *Agent) managedPeerCountLocked() int {
	if a.deviceState == nil || a.currentUser == nil {
		return 0
	}
	managedPeers := a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	return len(a.dedupeManagedPeersForRuntime(managedPeers))
}

func (a *Agent) hasPersistedSessionLocked() bool {
	if a.deviceState == nil {
		return false
	}
	return a.deviceState.SessionFor(a.remote.BaseURL()) != nil
}

func (a *Agent) initializeLifecycleStateLocked() {
	if a.stateErr != nil {
		a.lastLifecycleError = a.stateErr.Error()
		return
	}
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		a.lastLifecycleError = err.Error()
		return
	}
	now := time.Now()
	lifecycle := state.Lifecycle
	a.lastCleanShutdownAt = timeFromUnixOrZero(lifecycle.LastCleanShutdownUnix)
	a.lastCrashRecoveryAt = timeFromUnixOrZero(lifecycle.LastCrashRecoveryUnix)
	a.crashRecoveryCount = lifecycle.CrashRecoveryCount
	a.reconnectAttemptCount = lifecycle.ReconnectAttemptCount
	a.lastReconnectAttemptAt = timeFromUnixOrZero(lifecycle.LastReconnectAttemptUnix)
	a.nextReconnectAttemptAt = timeFromUnixOrZero(lifecycle.NextReconnectAttemptUnix)
	a.lastReconnectError = strings.TrimSpace(lifecycle.LastReconnectError)
	a.updateStatus.Channel = a.resolveUpdateChannelLocked()
	a.updateStatus.AvailableChannels = availableUpdateChannelsForRuntime(a.runtime)
	a.updateStatus.ManifestURL = a.resolveUpdateManifestURLLocked()
	if state.MarkServiceStarted(now.Unix()) {
		a.uncleanShutdownDetected = true
		a.lastCrashRecoveryAt = timeFromUnixOrZero(state.Lifecycle.LastCrashRecoveryUnix)
		a.crashRecoveryCount = state.Lifecycle.CrashRecoveryCount
		if state.SessionFor(a.remote.BaseURL()) != nil {
			a.nextReconnectAttemptAt = time.Time{}
			state.SetReconnectLifecycle(a.reconnectAttemptCount, unixOrZero(a.lastReconnectAttemptAt), 0, a.lastReconnectError)
		}
		a.logInfow("service.crash_recovery.detected", "unclean shutdown detected", "crashRecoveryCount", a.crashRecoveryCount, "persistedSession", state.SessionFor(a.remote.BaseURL()) != nil)
	}
	if err := a.savePersistentStateLocked(); err != nil {
		a.lastLifecycleError = err.Error()
	}
}

func (a *Agent) persistReconnectLifecycleLocked() {
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		a.lastLifecycleError = err.Error()
		return
	}
	state.SetReconnectLifecycle(
		a.reconnectAttemptCount,
		unixOrZero(a.lastReconnectAttemptAt),
		unixOrZero(a.nextReconnectAttemptAt),
		a.lastReconnectError,
	)
	if err := a.savePersistentStateLocked(); err != nil {
		a.lastLifecycleError = err.Error()
		a.logErrorf("persist reconnect lifecycle failed: %v", err)
	}
}

func (a *Agent) overlayDNSSettingsLocked() (string, string) {
	if a.overlayDNS == nil {
		return "", ""
	}
	status := a.overlayDNS.Snapshot()
	if status.ListenAddress == "" || status.Domain == "" {
		return "", ""
	}
	host, _, err := net.SplitHostPort(status.ListenAddress)
	if err != nil {
		host = status.ListenAddress
	}
	host = strings.TrimSpace(host)
	if net.ParseIP(host) == nil {
		return "", ""
	}
	return host, status.Domain
}

func (a *Agent) reconcileOverlayDNSLocked(managedPeers []ManagedPeerState) error {
	if a.overlayDNS == nil {
		return nil
	}
	records := map[string]string{}
	domain := a.overlayDNS.Domain()
	if domain == "" {
		return a.overlayDNS.Reconcile(records)
	}
	networks, err := a.listNetworksByIDLocked()
	if err != nil {
		return err
	}
	return a.reconcileOverlayDNSWithNetworksLocked(managedPeers, networks)
}

func (a *Agent) reconcileOverlayDNSWithNetworksLocked(managedPeers []ManagedPeerState, networks map[string]controlclient.Network) error {
	if a.overlayDNS == nil {
		return nil
	}
	records := map[string]string{}
	domain := a.overlayDNS.Domain()
	if domain == "" {
		return a.overlayDNS.Reconcile(records)
	}
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	globalRecords := map[string]string{}
	globalConflicts := map[string]struct{}{}
	for _, peer := range managedPeers {
		addOverlayDNSRecord(records, globalRecords, globalConflicts, peer.PeerID, peer.NetworkID, peer.VirtualIP, domain, networkDNSPolicy(networks[peer.NetworkID], peer.NetworkID))
	}
	for networkID, peers := range a.discoveredPeers {
		for _, peer := range a.dedupeDiscoveredPeersForOverlayDNS(networkID, peers) {
			addOverlayDNSRecord(records, globalRecords, globalConflicts, peer.ID, networkID, peer.VirtualIP, domain, networkDNSPolicy(networks[networkID], networkID))
		}
	}
	for name, ip := range globalRecords {
		if _, conflicted := globalConflicts[name]; conflicted {
			continue
		}
		records[name] = ip
	}
	return a.overlayDNS.Reconcile(records)
}

type overlayDNSPolicy struct {
	mode         string
	networkLabel string
}

func networkRoutingPolicyOrDefault(network controlclient.Network) string {
	policy := strings.ToUpper(strings.TrimSpace(network.RoutingPolicy))
	if policy == "" {
		return "SPLIT"
	}
	return policy
}

func networkGroupTrafficPolicyOrDefault(network controlclient.Network) string {
	policy := strings.ToUpper(strings.TrimSpace(network.GroupTrafficPolicy))
	if policy == "" {
		return "BLOCKED"
	}
	return policy
}

func (a *Agent) listNetworksByIDLocked() (map[string]controlclient.Network, error) {
	if a.currentUser == nil {
		a.invalidateForwardingRoutesLocked()
		a.forwardingPolicy = nil
		return map[string]controlclient.Network{}, nil
	}
	started := time.Now()
	networks, err := a.remote.ListNetworks()
	if err != nil {
		a.invalidateForwardingRoutesLocked()
		a.forwardingPolicy = nil
		return nil, err
	}
	index := make(map[string]controlclient.Network, len(networks))
	for _, network := range networks {
		index[network.ID] = network
	}
	a.publishForwardingPolicyLocked(index, started)
	return index, nil
}

func addOverlayDNSRecord(records, globalRecords map[string]string, globalConflicts map[string]struct{}, peerID, networkID, virtualIP, domain string, policy overlayDNSPolicy) {
	peerLabel := sanitizeDNSLabel(peerID)
	if peerLabel == "" || net.ParseIP(strings.TrimSpace(virtualIP)).To4() == nil || domain == "" {
		return
	}
	if strings.EqualFold(policy.mode, "DISABLED") {
		return
	}
	trimmedIP := strings.TrimSpace(virtualIP)
	if strings.EqualFold(policy.mode, "DEFAULT") {
		globalName := peerLabel + "." + domain
		if existingIP, exists := globalRecords[globalName]; exists && existingIP != trimmedIP {
			delete(globalRecords, globalName)
			globalConflicts[globalName] = struct{}{}
		} else if _, conflicted := globalConflicts[globalName]; !conflicted {
			globalRecords[globalName] = trimmedIP
		}
	}
	networkLabel := firstNonEmptyString(policy.networkLabel, sanitizeDNSLabel(networkID))
	if networkLabel != "" {
		records[peerLabel+"."+networkLabel+"."+domain] = strings.TrimSpace(virtualIP)
	}
}

func overlayDNSPeerKey(networkID, userID, virtualIP, peerID string) string {
	normalizedNetwork := strings.TrimSpace(networkID)
	normalizedUser := strings.TrimSpace(userID)
	normalizedIP := strings.TrimSpace(virtualIP)
	if normalizedUser == "" || normalizedIP == "" {
		return normalizedNetwork + "|" + strings.TrimSpace(peerID)
	}
	return normalizedNetwork + "|" + normalizedUser + "|" + normalizedIP
}

func (a *Agent) dedupeManagedPeersForRuntime(peers []ManagedPeerState) []ManagedPeerState {
	if len(peers) < 2 {
		return peers
	}
	selected := make(map[string]ManagedPeerState, len(peers))
	for _, peer := range peers {
		key := managedPeerRuntimeKey(peer)
		if key == "" {
			continue
		}
		if current, exists := selected[key]; exists {
			if a.betterManagedPeerForRuntime(peer, current) {
				selected[key] = peer
			}
			continue
		}
		selected[key] = peer
	}
	out := make([]ManagedPeerState, 0, len(selected))
	seen := map[string]struct{}{}
	for _, peer := range peers {
		key := managedPeerRuntimeKey(peer)
		if key == "" {
			continue
		}
		chosen, exists := selected[key]
		if !exists {
			continue
		}
		if chosen.PeerID != peer.PeerID {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, chosen)
	}
	return out
}

func managedPeerRuntimeKey(peer ManagedPeerState) string {
	networkID := strings.TrimSpace(peer.NetworkID)
	if networkID == "" {
		return ""
	}
	return strings.ToLower(networkID)
}

func (a *Agent) preferredConnectionForManagedPeer(peerID string) *ConnectionStatus {
	var best *ConnectionStatus
	for idx := range a.connections {
		connection := &a.connections[idx]
		if connection.LocalPeerID != peerID {
			continue
		}
		if best == nil || betterSignalingConnection(connection, best) {
			best = connection
		}
	}
	return best
}

func (a *Agent) betterManagedPeerForRuntime(candidate, current ManagedPeerState) bool {
	candidateConnection := a.preferredConnectionForManagedPeer(candidate.PeerID)
	currentConnection := a.preferredConnectionForManagedPeer(current.PeerID)
	if betterSignalingConnection(candidateConnection, currentConnection) {
		return true
	}
	if betterSignalingConnection(currentConnection, candidateConnection) {
		return false
	}
	if strings.TrimSpace(candidate.Endpoint) != strings.TrimSpace(current.Endpoint) {
		return strings.TrimSpace(candidate.Endpoint) != "" && strings.TrimSpace(current.Endpoint) == ""
	}
	return false
}

func (a *Agent) dedupeDiscoveredPeersForOverlayDNS(networkID string, peers []controlclient.Peer) []controlclient.Peer {
	if len(peers) < 2 {
		return peers
	}
	preferred := a.overlayDNSPreferredRemotePeerByID(networkID, peers)
	selected := make([]controlclient.Peer, 0, len(peers))
	for _, peer := range peers {
		replaced := false
		for idx := range selected {
			current := selected[idx]
			if !sameOverlayPeerTarget(current, peer) {
				continue
			}
			preferredPeerID := firstNonEmptyString(preferred[current.ID], preferred[peer.ID])
			if a.betterOverlayDNSPeer(peer, current, preferredPeerID) {
				selected[idx] = peer
			}
			replaced = true
			break
		}
		if replaced {
			continue
		}
		selected = append(selected, peer)
	}
	return selected
}

func (a *Agent) overlayDNSPreferredRemotePeerByID(networkID string, peers []controlclient.Peer) map[string]string {
	out := map[string]string{}
	for _, peer := range peers {
		var best *ConnectionStatus
		for idx := range a.connections {
			connection := &a.connections[idx]
			if connection.NetworkID != networkID {
				continue
			}
			if !overlayDNSPeerMatchesConnection(peer, connection, peers) {
				continue
			}
			if best == nil || a.betterTransportLifecycleConnectionLocked(connection, best) {
				best = connection
			}
		}
		if best == nil {
			continue
		}
		out[peer.ID] = best.RemotePeerID
	}
	return out
}

func sameOverlayPeerTarget(current, candidate controlclient.Peer) bool {
	currentIP := strings.TrimSpace(current.VirtualIP)
	candidateIP := strings.TrimSpace(candidate.VirtualIP)
	if currentIP != "" && candidateIP != "" {
		if !strings.EqualFold(currentIP, candidateIP) {
			return false
		}
		currentUserID := strings.TrimSpace(current.UserID)
		candidateUserID := strings.TrimSpace(candidate.UserID)
		if currentUserID != "" && candidateUserID != "" && !strings.EqualFold(currentUserID, candidateUserID) {
			return false
		}
		return true
	}
	return strings.EqualFold(strings.TrimSpace(current.ID), strings.TrimSpace(candidate.ID))
}

func overlayDNSPeerMatchesConnection(peer controlclient.Peer, connection *ConnectionStatus, peers []controlclient.Peer) bool {
	if connection == nil {
		return false
	}
	peerIP := strings.TrimSpace(peer.VirtualIP)
	connectionIP := strings.TrimSpace(firstNonEmptyString(connection.RemoteVirtualIP, remotePeerVirtualIPForConnection(peers, connection.RemotePeerID)))
	if peerIP == "" || connectionIP == "" || !strings.EqualFold(peerIP, connectionIP) {
		return false
	}
	peerUserID := strings.TrimSpace(peer.UserID)
	connectionUserID := strings.TrimSpace(firstNonEmptyString(connection.RemoteUserID, remotePeerUserIDForConnection(peers, connection.RemotePeerID)))
	if peerUserID != "" && connectionUserID != "" && !strings.EqualFold(peerUserID, connectionUserID) {
		return false
	}
	return true
}

func (a *Agent) betterOverlayDNSPeer(candidate, current controlclient.Peer, preferredPeerID string) bool {
	if preferredPeerID != "" {
		if candidate.ID == preferredPeerID && current.ID != preferredPeerID {
			return true
		}
		if current.ID == preferredPeerID && candidate.ID != preferredPeerID {
			return false
		}
	}
	candidateState := signalingStatePreference(candidate.ConnectionState)
	currentState := signalingStatePreference(current.ConnectionState)
	if candidateState != currentState {
		return candidateState > currentState
	}
	if overlayDNSPeerPresencePreference(candidate) != overlayDNSPeerPresencePreference(current) {
		return overlayDNSPeerPresencePreference(candidate) > overlayDNSPeerPresencePreference(current)
	}
	if candidate.LastSignaledAtUnix != current.LastSignaledAtUnix {
		return candidate.LastSignaledAtUnix > current.LastSignaledAtUnix
	}
	if candidate.LastSeenUnix != current.LastSeenUnix {
		return candidate.LastSeenUnix > current.LastSeenUnix
	}
	return false
}

func overlayDNSPeerPresencePreference(peer controlclient.Peer) int {
	switch strings.ToUpper(strings.TrimSpace(peer.Status)) {
	case "ONLINE":
		return 2
	case "OFFLINE":
		return 0
	default:
		return 1
	}
}

func networkDNSPolicy(network controlclient.Network, networkID string) overlayDNSPolicy {
	mode := strings.ToUpper(strings.TrimSpace(network.NameResolutionMode))
	if mode == "" {
		mode = "DEFAULT"
	}
	switch mode {
	case "DEFAULT", "NETWORK_ONLY", "DISABLED":
	default:
		mode = "DEFAULT"
	}
	return overlayDNSPolicy{
		mode:         mode,
		networkLabel: sanitizeDNSLabel(firstNonEmptyString(network.DNSLabel, networkID)),
	}
}

func sanitizeDNSLabel(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	var builder strings.Builder
	lastDash := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && builder.Len() > 0 {
				builder.WriteByte('-')
				lastDash = true
			}
		}
	}
	label := strings.Trim(builder.String(), "-")
	if len(label) > 63 {
		label = label[:63]
	}
	return label
}

func (a *Agent) discoveredPeerCountLocked() int {
	deduped := make([]controlclient.Peer, 0)
	for networkID, peers := range a.discoveredPeers {
		for _, peer := range peers {
			peer.NetworkID = strings.TrimSpace(firstNonEmptyString(peer.NetworkID, networkID))
			if strings.TrimSpace(peer.ID) == "" {
				continue
			}
			replaced := false
			for idx := range deduped {
				if !sameOverlayPeerTarget(deduped[idx], peer) {
					continue
				}
				if betterDiagnosticsPeer(peer, deduped[idx]) {
					deduped[idx] = peer
				}
				replaced = true
				break
			}
			if replaced {
				continue
			}
			deduped = append(deduped, peer)
		}
	}
	return len(deduped)
}

func (a *Agent) adapterSnapshotLocked() virtualadapter.Status {
	var snapshot virtualadapter.Status
	if a.adapterManager == nil {
		snapshot = virtualadapter.Status{}
	} else {
		snapshot = a.adapterManager.Snapshot()
	}
	if a.deviceState != nil && a.deviceState.AdapterMTU > 0 {
		snapshot.DesiredMTU = a.deviceState.AdapterMTU
	}
	return snapshot
}

func cloneUser(user *controlclient.User) *controlclient.User {
	if user == nil {
		return nil
	}
	copy := *user
	return &copy
}

func cloneSession(session *controlclient.Session) *controlclient.Session {
	if session == nil {
		return nil
	}
	copy := *session
	return &copy
}

func cloneDevice(device *controlclient.Device) *controlclient.Device {
	if device == nil {
		return nil
	}
	copy := *device
	return &copy
}

func cloneConnections(connections []ConnectionStatus) []ConnectionStatus {
	if len(connections) == 0 {
		return nil
	}
	out := make([]ConnectionStatus, len(connections))
	copy(out, connections)
	return out
}

func (a *Agent) cloneStatusConnectionsLocked() []ConnectionStatus {
	out := cloneConnections(a.connections)
	for idx := range out {
		if strings.TrimSpace(out[idx].RemoteVirtualIP) == "" {
			out[idx].RemoteVirtualIP = a.connectionRemoteVirtualIPUnlocked(&out[idx])
		}
	}
	return out
}

func (a *Agent) dedupeStatusConnectionsLocked(connections []ConnectionStatus) []ConnectionStatus {
	if len(connections) <= 1 {
		return connections
	}
	endpointCandidates := connectionStatusPointers(connections)
	type statusConnectionEntry struct {
		connection ConnectionStatus
		sourceIdx  int
	}
	entries := make([]statusConnectionEntry, 0, len(connections))
	for idx := range connections {
		connection := connections[idx]
		replaced := false
		for existingIdx := range entries {
			current := &entries[existingIdx].connection
			currentSource := endpointCandidates[entries[existingIdx].sourceIdx]
			candidateSource := endpointCandidates[idx]
			if !a.sameStatusConnectionTargetWithCandidatesLocked(currentSource, candidateSource, endpointCandidates) {
				continue
			}
			if a.betterStatusConnectionLocked(&connection, current) {
				entries[existingIdx] = statusConnectionEntry{connection: connection, sourceIdx: idx}
			}
			replaced = true
			break
		}
		if replaced {
			continue
		}
		entries = append(entries, statusConnectionEntry{connection: connection, sourceIdx: idx})
	}
	out := make([]ConnectionStatus, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.connection)
	}
	return out
}

func (a *Agent) dedupeStatusNeighborsLocked(neighbors []NeighborStatus) []NeighborStatus {
	if len(neighbors) <= 1 {
		return neighbors
	}
	out := make([]NeighborStatus, 0, len(neighbors))
	for idx := range neighbors {
		neighbor := neighbors[idx]
		replaced := false
		for existingIdx := range out {
			current := out[existingIdx]
			if !a.sameStatusNeighborTargetLocked(current, neighbor) {
				continue
			}
			if a.betterStatusNeighborLocked(neighbor, current) {
				out[existingIdx] = neighbor
			}
			replaced = true
			break
		}
		if replaced {
			continue
		}
		out = append(out, neighbor)
	}
	return out
}

func cloneGatewayHistory(events []GatewayChangeEvent) []GatewayChangeEvent {
	if len(events) == 0 {
		return nil
	}
	out := make([]GatewayChangeEvent, len(events))
	copy(out, events)
	return out
}

func cloneGroupTrafficDiagnostics(values map[string]GroupTrafficDiagnostics) []GroupTrafficDiagnostics {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]GroupTrafficDiagnostics, 0, len(keys))
	for _, key := range keys {
		out = append(out, values[key])
	}
	return out
}

func cloneNeighbors(neighbors []NeighborStatus) []NeighborStatus {
	if len(neighbors) == 0 {
		return nil
	}
	out := make([]NeighborStatus, len(neighbors))
	copy(out, neighbors)
	return out
}

func (a *Agent) cloneStatusNeighborsLocked() []NeighborStatus {
	out := cloneNeighbors(a.neighbors)
	for idx := range out {
		if strings.TrimSpace(out[idx].RemoteUserID) == "" {
			out[idx].RemoteUserID = strings.TrimSpace(a.peerUserIDInNetworkUnlocked(out[idx].NetworkID, out[idx].RemotePeerID))
		}
		if strings.TrimSpace(out[idx].RemoteVirtualIP) == "" {
			out[idx].RemoteVirtualIP = strings.TrimSpace(a.peerVirtualIPInNetworkUnlocked(out[idx].NetworkID, out[idx].RemotePeerID))
		}
	}
	return out
}

func (a *Agent) sameStatusConnectionTargetLocked(current, candidate *ConnectionStatus) bool {
	return a.sameStatusConnectionTargetWithCandidatesLocked(current, candidate, a.transportReadyConnectionPointersLocked())
}

func (a *Agent) sameStatusConnectionTargetWithCandidatesLocked(current, candidate *ConnectionStatus, endpointCandidates []*ConnectionStatus) bool {
	if current == nil || candidate == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(current.NetworkID), strings.TrimSpace(candidate.NetworkID)) {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(current.LocalPeerID), strings.TrimSpace(candidate.LocalPeerID)) {
		return a.sameTransportRoutingTargetLocked(current, candidate) ||
			a.transportRoutingEndpointContinuityReplacementMatchWithCandidatesLocked(current, candidate, endpointCandidates)
	}
	activeLocalPeerID := strings.TrimSpace(a.currentManagedPeerIDForNetworkLocked(current.NetworkID))
	if activeLocalPeerID == "" {
		return false
	}
	currentActive := strings.EqualFold(strings.TrimSpace(current.LocalPeerID), activeLocalPeerID)
	candidateActive := strings.EqualFold(strings.TrimSpace(candidate.LocalPeerID), activeLocalPeerID)
	if currentActive == candidateActive {
		return false
	}
	return a.sameTransportRoutingTargetLocked(current, candidate) ||
		a.transportRoutingEndpointContinuityReplacementMatchWithCandidatesLocked(current, candidate, endpointCandidates)
}

func (a *Agent) betterStatusConnectionLocked(candidate, current *ConnectionStatus) bool {
	if candidate == nil {
		return false
	}
	if current == nil {
		return true
	}
	candidateActive := a.localPeerMatchesActiveManagedPeerLocked(candidate.NetworkID, candidate.LocalPeerID)
	currentActive := a.localPeerMatchesActiveManagedPeerLocked(current.NetworkID, current.LocalPeerID)
	if candidateActive != currentActive {
		return candidateActive
	}
	return betterSignalingConnection(candidate, current)
}

func (a *Agent) sameStatusNeighborTargetLocked(current, candidate NeighborStatus) bool {
	if !strings.EqualFold(strings.TrimSpace(current.NetworkID), strings.TrimSpace(candidate.NetworkID)) {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(current.LocalPeerID), strings.TrimSpace(candidate.LocalPeerID)) {
		return sameDiagnosticsNeighborTarget(current, candidate)
	}
	activeLocalPeerID := strings.TrimSpace(a.currentManagedPeerIDForNetworkLocked(current.NetworkID))
	if activeLocalPeerID == "" {
		return false
	}
	currentActive := strings.EqualFold(strings.TrimSpace(current.LocalPeerID), activeLocalPeerID)
	candidateActive := strings.EqualFold(strings.TrimSpace(candidate.LocalPeerID), activeLocalPeerID)
	if currentActive == candidateActive {
		return false
	}
	return sameStatusNeighborRemoteTarget(current, candidate)
}

func sameStatusNeighborRemoteTarget(current, candidate NeighborStatus) bool {
	if !strings.EqualFold(strings.TrimSpace(current.NetworkID), strings.TrimSpace(candidate.NetworkID)) {
		return false
	}
	currentRemotePeerID := strings.TrimSpace(current.RemotePeerID)
	candidateRemotePeerID := strings.TrimSpace(candidate.RemotePeerID)
	if currentRemotePeerID != "" && strings.EqualFold(currentRemotePeerID, candidateRemotePeerID) {
		return true
	}
	currentVirtualIP := strings.TrimSpace(current.RemoteVirtualIP)
	candidateVirtualIP := strings.TrimSpace(candidate.RemoteVirtualIP)
	if currentVirtualIP == "" || candidateVirtualIP == "" || !strings.EqualFold(currentVirtualIP, candidateVirtualIP) {
		return false
	}
	currentUserID := strings.TrimSpace(current.RemoteUserID)
	candidateUserID := strings.TrimSpace(candidate.RemoteUserID)
	if currentUserID != "" && candidateUserID != "" && !strings.EqualFold(currentUserID, candidateUserID) {
		return false
	}
	return true
}

func (a *Agent) betterStatusNeighborLocked(candidate, current NeighborStatus) bool {
	candidateActive := a.localPeerMatchesActiveManagedPeerLocked(candidate.NetworkID, candidate.LocalPeerID)
	currentActive := a.localPeerMatchesActiveManagedPeerLocked(current.NetworkID, current.LocalPeerID)
	if candidateActive != currentActive {
		return candidateActive
	}
	return betterDiagnosticsNeighbor(candidate, current)
}

func (a *Agent) ensurePersistentStateLocked() (*PersistentState, error) {
	if a.stateErr != nil {
		return nil, a.stateErr
	}
	if a.deviceState == nil {
		a.deviceState = defaultPersistentState()
	}
	changed, err := a.deviceState.EnsureKeyPair()
	if err != nil {
		return nil, err
	}
	if changed {
		if err := a.savePersistentStateLocked(); err != nil {
			return nil, err
		}
	}
	return a.deviceState, nil
}

func (a *Agent) savePersistentStateLocked() error {
	if a.stateStore == nil {
		return nil
	}
	if err := a.stateStore.Save(a.deviceState); err != nil {
		a.stateErr = err
		return err
	}
	return nil
}

func (a *Agent) statePathLocked() string {
	if a.stateStore == nil {
		return ""
	}
	return a.stateStore.Path()
}

func (a *Agent) reconcileManagedRuntimeLocked() error {
	return a.reconcileManagedRuntimeWithInputsLocked(nil)
}

func (a *Agent) reconcileManagedRuntimeWithInputsLocked(inputs *runtimeReconcileInputs) error {
	if a.recoveryPaused.Load() != nil {
		a.invalidateForwardingRoutesLocked() // This operation may replace shared listeners/adapter state.
	}
	if a.deviceState == nil || a.currentUser == nil {
		a.fileTransferSources = map[string]localFileTransferSource{}
		a.fileTransferCaches = map[string]localFileTransferCache{}
		if a.overlayDNS != nil {
			_ = a.overlayDNS.Reconcile(nil)
		}
		if a.directManager != nil {
			if err := a.directManager.Reconcile(nil); err != nil {
				return err
			}
		}
		if a.relayManager != nil {
			if err := a.relayManager.Reconcile(nil); err != nil {
				return err
			}
		}
		if a.adapterManager != nil {
			_, err := a.adapterManager.Reconcile(nil)
			return err
		}
		return nil
	}

	managedPeers := a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	if err := a.pruneFileTransferSourcesLocked(managedPeers); err != nil {
		return err
	}
	if err := a.pruneFileTransferCachesLocked(managedPeers); err != nil {
		return err
	}
	var dnsErr error
	if inputs != nil {
		dnsErr = a.reconcileOverlayDNSWithNetworksLocked(managedPeers, inputs.networks)
	} else {
		dnsErr = a.reconcileOverlayDNSLocked(managedPeers)
	}
	if dnsErr != nil {
		return dnsErr
	}
	if a.directManager != nil {
		bindings := make([]directprobe.Binding, 0, len(managedPeers))
		seenNetworks := map[string]struct{}{}
		for _, peer := range managedPeers {
			networkID := strings.TrimSpace(peer.NetworkID)
			if networkID == "" {
				continue
			}
			if _, seen := seenNetworks[networkID]; seen {
				continue
			}
			if strings.TrimSpace(peer.Endpoint) == "" {
				continue
			}
			seenNetworks[networkID] = struct{}{}
			bindings = append(bindings, directprobe.Binding{
				Credentials:   a.runtimeCredentialsLocked(peer, inputs),
				PeerID:        peer.PeerID,
				ListenAddress: peer.Endpoint,
			})
		}
		if err := a.directManager.Reconcile(bindings); err != nil {
			return err
		}
		for _, binding := range bindings {
			if err := a.directManager.SetExchangeHandler(binding.PeerID, a.transportExchangeHandler(binding.PeerID)); err != nil {
				return err
			}
		}
	}
	if a.relayManager != nil {
		var credentials map[string]*transportauth.Credentials
		if inputs != nil {
			credentials = inputs.credentials
		}
		if err := a.reconcileRelayBindingsWithCredentialsLocked(credentials); err != nil {
			return err
		}
	}
	if a.adapterManager == nil {
		return nil
	}
	desired := make([]virtualadapter.NetworkConfig, 0, len(managedPeers))
	seenNetworks := map[string]struct{}{}
	dnsServer, dnsSuffix := a.overlayDNSSettingsLocked()
	var networksByID map[string]controlclient.Network
	var err error
	if inputs != nil {
		networksByID = inputs.networks
	} else {
		networksByID, err = a.listNetworksByIDLocked()
	}
	if err != nil {
		return err
	}
	primaryFullTunnelClientNetworkID := a.primaryFullTunnelClientNetworkLocked(managedPeers, networksByID)
	for _, peer := range managedPeers {
		networkID := strings.TrimSpace(peer.NetworkID)
		if networkID == "" {
			continue
		}
		if _, seen := seenNetworks[networkID]; seen {
			continue
		}
		seenNetworks[networkID] = struct{}{}
		network := networksByID[peer.NetworkID]
		config, err := a.adapterConfigForManagedPeerLocked(peer, network, primaryFullTunnelClientNetworkID)
		if err != nil {
			return err
		}
		config.MTU = a.deviceState.AdapterMTU
		config.DNSServer = dnsServer
		config.DNSSuffix = dnsSuffix
		desired = append(desired, config)
	}
	a.observeGatewaySelectionsLocked(desired)
	_, err = a.adapterManager.Reconcile(desired)
	return err
}

func (a *Agent) adapterConfigForManagedPeerLocked(peer ManagedPeerState, network controlclient.Network, primaryFullTunnelClientNetworkID string) (virtualadapter.NetworkConfig, error) {
	overlayPrefix, prefixLength, err := routeConfigForManagedPeer(peer)
	if err != nil {
		return virtualadapter.NetworkConfig{}, err
	}
	config := virtualadapter.NetworkConfig{
		NetworkID:     peer.NetworkID,
		VirtualIP:     peer.VirtualIP,
		PrefixLength:  prefixLength,
		OverlayCIDR:   overlayPrefix,
		RoutePrefix:   overlayPrefix,
		RoutingPolicy: networkRoutingPolicyOrDefault(network),
	}
	if !strings.EqualFold(config.RoutingPolicy, "FULL") || a.currentUser == nil {
		return config, nil
	}
	if localUserCanActAsGateway(network, a.currentUser.ID) {
		config.GatewayRole = "GATEWAY"
		return config, nil
	}
	if gateway := a.gatewayConnectionForNetworkLocked(network, peer.PeerID); gateway != nil {
		config.GatewayRole = "CLIENT"
		config.GatewayPeerID = gateway.RemotePeerID
		config.GatewayUserID = strings.TrimSpace(firstNonEmptyString(gateway.RemoteUserID, a.peerUserIDInNetworkUnlocked(network.ID, gateway.RemotePeerID)))
		config.GatewayVirtualIP = a.connectionRemoteVirtualIPUnlocked(gateway)
		if selection, ok := a.gatewaySelections[network.ID]; ok && a.gatewaySelectionMatchesConnectionLocked(selection, gateway) {
			if config.GatewayUserID == "" {
				config.GatewayUserID = strings.TrimSpace(selection.GatewayUserID)
			}
			if config.GatewayVirtualIP == "" {
				config.GatewayVirtualIP = strings.TrimSpace(selection.GatewayVirtualIP)
			}
		}
		config.GatewayTargetRole = a.remotePeerGatewayRoleForConnectionLocked(network, gateway.RemotePeerID)
		if primaryFullTunnelClientNetworkID == "" || peer.NetworkID == primaryFullTunnelClientNetworkID {
			config.RoutePrefix = defaultIPv4Route
		} else {
			config.PolicyStatusHint = "STANDBY_GATEWAY"
		}
	}
	return config, nil
}

func (a *Agent) primaryFullTunnelClientNetworkLocked(managedPeers []ManagedPeerState, networksByID map[string]controlclient.Network) string {
	if a.currentUser == nil {
		return ""
	}
	bestNetworkID := ""
	var bestConnection *ConnectionStatus
	bestRole := ""
	for _, peer := range managedPeers {
		network := networksByID[peer.NetworkID]
		if !strings.EqualFold(networkRoutingPolicyOrDefault(network), "FULL") || localUserCanActAsGateway(network, a.currentUser.ID) {
			continue
		}
		gateway := a.gatewayConnectionForNetworkLocked(network, peer.PeerID)
		if gateway == nil {
			continue
		}
		role := a.remotePeerGatewayRoleForConnectionLocked(network, gateway.RemotePeerID)
		if bestConnection == nil || betterGatewayConnection(gateway, role, bestConnection, bestRole) {
			bestNetworkID = peer.NetworkID
			bestConnection = gateway
			bestRole = role
			continue
		}
		if !betterGatewayConnection(bestConnection, bestRole, gateway, role) && strings.Compare(strings.TrimSpace(peer.NetworkID), strings.TrimSpace(bestNetworkID)) < 0 {
			bestNetworkID = peer.NetworkID
			bestConnection = gateway
			bestRole = role
		}
	}
	currentNetworkID, currentConnection, currentRole := a.currentActiveFullTunnelClientGatewayLocked(managedPeers, networksByID)
	if bestNetworkID != "" && currentNetworkID != "" && currentNetworkID != bestNetworkID && currentConnection != nil {
		if !materiallyBetterPrimaryFullTunnelGatewayConnection(bestConnection, bestRole, currentConnection, currentRole) &&
			!materiallyBetterPrimaryFullTunnelGatewayConnection(currentConnection, currentRole, bestConnection, bestRole) {
			return currentNetworkID
		}
	}
	return bestNetworkID
}

func (a *Agent) currentActiveFullTunnelClientGatewayLocked(managedPeers []ManagedPeerState, networksByID map[string]controlclient.Network) (string, *ConnectionStatus, string) {
	for networkID, selection := range a.gatewaySelections {
		if !strings.EqualFold(strings.TrimSpace(selection.GatewayRole), "CLIENT") ||
			!strings.EqualFold(strings.TrimSpace(selection.PolicyStatus), "ACTIVE") {
			continue
		}
		network := networksByID[networkID]
		if !strings.EqualFold(networkRoutingPolicyOrDefault(network), "FULL") || localUserCanActAsGateway(network, a.currentUser.ID) {
			continue
		}
		managedPeer := managedPeerByNetwork(managedPeers, networkID)
		if managedPeer.PeerID == "" {
			continue
		}
		gateway := a.gatewayConnectionForNetworkLocked(network, managedPeer.PeerID)
		if gateway == nil {
			continue
		}
		return networkID, gateway, a.remotePeerGatewayRoleForConnectionLocked(network, gateway.RemotePeerID)
	}
	return "", nil, ""
}

func (a *Agent) observeGatewaySelectionsLocked(desired []virtualadapter.NetworkConfig) {
	current := a.currentGatewaySelectionsLocked(desired)
	if a.gatewaySelections == nil {
		a.gatewaySelections = map[string]gatewaySelectionState{}
	}
	now := time.Now()
	for networkID, selection := range current {
		previous, ok := a.gatewaySelections[networkID]
		if !ok {
			a.gatewaySelections[networkID] = selection
			if shouldRecordInitialGatewayChange(selection) {
				a.appendGatewayChangeLocked(classifyGatewayChange(gatewaySelectionState{}, selection), gatewaySelectionState{}, selection, now)
			}
			continue
		}
		if gatewaySelectionEqual(previous, selection) {
			a.gatewaySelections[networkID] = selection
			continue
		}
		a.appendGatewayChangeLocked(classifyGatewayChange(previous, selection), previous, selection, now)
		a.gatewaySelections[networkID] = selection
	}
	for networkID, previous := range a.gatewaySelections {
		if _, ok := current[networkID]; ok {
			continue
		}
		delete(a.gatewaySelections, networkID)
		if shouldRecordGatewayRemoval(previous) {
			a.appendGatewayChangeLocked("REMOVED", previous, gatewaySelectionState{NetworkID: networkID, PolicyStatus: "REMOVED"}, now)
		}
	}
}

func (a *Agent) currentGatewaySelectionsLocked(desired []virtualadapter.NetworkConfig) map[string]gatewaySelectionState {
	selections := make(map[string]gatewaySelectionState, len(desired))
	for _, config := range desired {
		if !strings.EqualFold(strings.TrimSpace(config.RoutingPolicy), "FULL") {
			continue
		}
		previous := a.gatewaySelections[config.NetworkID]
		selection := gatewaySelectionState{
			NetworkID:     config.NetworkID,
			GatewayRole:   strings.ToUpper(strings.TrimSpace(config.GatewayRole)),
			GatewayPeerID: strings.TrimSpace(config.GatewayPeerID),
			GatewayUserID: strings.TrimSpace(firstNonEmptyString(
				strings.TrimSpace(config.GatewayUserID),
				a.gatewayUserIDForSelectionLocked(config.NetworkID, config.GatewayPeerID),
			)),
			GatewayVirtualIP: strings.TrimSpace(firstNonEmptyString(
				strings.TrimSpace(config.GatewayVirtualIP),
				a.gatewayVirtualIPForSelectionLocked(config.NetworkID, config.GatewayPeerID),
			)),
			GatewayTargetRole: strings.ToUpper(strings.TrimSpace(config.GatewayTargetRole)),
			PolicyStatus:      currentGatewayPolicyStatus(config),
		}
		reference := selection
		if strings.EqualFold(strings.TrimSpace(previous.NetworkID), strings.TrimSpace(selection.NetworkID)) &&
			strings.EqualFold(strings.TrimSpace(previous.GatewayPeerID), strings.TrimSpace(selection.GatewayPeerID)) {
			if strings.TrimSpace(reference.GatewayUserID) == "" {
				reference.GatewayUserID = strings.TrimSpace(previous.GatewayUserID)
			}
			if strings.TrimSpace(reference.GatewayVirtualIP) == "" {
				reference.GatewayVirtualIP = strings.TrimSpace(previous.GatewayVirtualIP)
			}
		}
		connection := a.preferredConnectionForGatewaySelectionLocked(reference)
		if strings.TrimSpace(selection.GatewayUserID) == "" && connection != nil {
			selection.GatewayUserID = strings.TrimSpace(firstNonEmptyString(connection.RemoteUserID, a.peerUserIDInNetworkUnlocked(connection.NetworkID, connection.RemotePeerID)))
		}
		if strings.TrimSpace(selection.GatewayVirtualIP) == "" && connection != nil {
			selection.GatewayVirtualIP = a.connectionRemoteVirtualIPUnlocked(connection)
		}
		if connection != nil {
			selection.GatewayEndpointKey = normalizedEndpointContinuityKey(strings.TrimSpace(connection.RemoteEndpoint), connection.RemoteCandidates)
		}
		if strings.TrimSpace(selection.GatewayEndpointKey) == "" {
			selection.GatewayEndpointKey = strings.TrimSpace(previous.GatewayEndpointKey)
		}
		if strings.TrimSpace(selection.GatewayUserID) == "" &&
			strings.EqualFold(strings.TrimSpace(previous.NetworkID), strings.TrimSpace(selection.NetworkID)) &&
			strings.EqualFold(strings.TrimSpace(previous.GatewayPeerID), strings.TrimSpace(selection.GatewayPeerID)) {
			selection.GatewayUserID = strings.TrimSpace(previous.GatewayUserID)
		}
		if strings.TrimSpace(selection.GatewayVirtualIP) == "" &&
			strings.EqualFold(strings.TrimSpace(previous.NetworkID), strings.TrimSpace(selection.NetworkID)) &&
			strings.EqualFold(strings.TrimSpace(previous.GatewayPeerID), strings.TrimSpace(selection.GatewayPeerID)) {
			selection.GatewayVirtualIP = strings.TrimSpace(previous.GatewayVirtualIP)
		}
		switch {
		case strings.EqualFold(selection.GatewayRole, "GATEWAY"):
			selection.Path = "LOCAL"
		case selection.GatewayPeerID != "":
			selection.Path = gatewayPathForConnection(connection)
		default:
			selection.Path = "PENDING"
		}
		selections[selection.NetworkID] = selection
	}
	return selections
}

func (a *Agent) preferredConnectionForGatewaySelectionLocked(selection gatewaySelectionState) *ConnectionStatus {
	if strings.TrimSpace(selection.NetworkID) == "" || strings.TrimSpace(selection.GatewayPeerID) == "" {
		return nil
	}
	activeLocalPeerID := strings.TrimSpace(a.currentManagedPeerIDForNetworkLocked(selection.NetworkID))
	var best *ConnectionStatus
	for idx := range a.connections {
		candidate := &a.connections[idx]
		if !strings.EqualFold(strings.TrimSpace(candidate.NetworkID), strings.TrimSpace(selection.NetworkID)) {
			continue
		}
		if activeLocalPeerID != "" && !strings.EqualFold(strings.TrimSpace(candidate.LocalPeerID), activeLocalPeerID) {
			continue
		}
		if !a.gatewaySelectionMatchesConnectionLocked(selection, candidate) {
			continue
		}
		if best == nil || betterGatewayConnection(candidate, "", best, "") {
			best = candidate
		}
	}
	return best
}

func (a *Agent) connectionForGatewayPeerLocked(networkID, remotePeerID string) *ConnectionStatus {
	for idx := range a.connections {
		connection := &a.connections[idx]
		if connection.NetworkID == networkID && connection.RemotePeerID == remotePeerID {
			return connection
		}
	}
	return nil
}

func (a *Agent) gatewayUserIDForSelectionLocked(networkID, remotePeerID string) string {
	remotePeerID = strings.TrimSpace(remotePeerID)
	if remotePeerID == "" {
		return ""
	}
	if connection := a.connectionForGatewayPeerLocked(networkID, remotePeerID); connection != nil {
		return strings.TrimSpace(firstNonEmptyString(connection.RemoteUserID, a.peerUserIDInNetworkUnlocked(networkID, remotePeerID)))
	}
	return strings.TrimSpace(a.peerUserIDInNetworkUnlocked(networkID, remotePeerID))
}

func (a *Agent) gatewayVirtualIPForSelectionLocked(networkID, remotePeerID string) string {
	remotePeerID = strings.TrimSpace(remotePeerID)
	if remotePeerID == "" {
		return ""
	}
	if connection := a.connectionForGatewayPeerLocked(networkID, remotePeerID); connection != nil {
		if remoteVirtualIP := a.connectionRemoteVirtualIPUnlocked(connection); remoteVirtualIP != "" {
			return remoteVirtualIP
		}
	}
	for _, peer := range a.discoveredPeers[networkID] {
		if strings.EqualFold(strings.TrimSpace(peer.ID), remotePeerID) {
			return strings.TrimSpace(peer.VirtualIP)
		}
	}
	return ""
}

func currentGatewayPolicyStatus(config virtualadapter.NetworkConfig) string {
	if statusHint := strings.ToUpper(strings.TrimSpace(config.PolicyStatusHint)); statusHint != "" {
		return statusHint
	}
	if strings.EqualFold(strings.TrimSpace(config.GatewayRole), "GATEWAY") {
		return "ACTIVE"
	}
	if strings.EqualFold(strings.TrimSpace(config.GatewayRole), "CLIENT") && strings.TrimSpace(config.GatewayPeerID) != "" {
		return "ACTIVE"
	}
	return "PENDING_GATEWAY"
}

func gatewayPathForConnection(connection *ConnectionStatus) string {
	if connection == nil {
		return "PENDING"
	}
	if strings.EqualFold(connection.TransportMode, "DIRECT") || strings.EqualFold(connection.Reachability, "DIRECT") {
		return "DIRECT"
	}
	if strings.EqualFold(connection.TransportMode, "RELAY") || strings.EqualFold(connection.Reachability, "RELAY") {
		return "RELAY"
	}
	if strings.TrimSpace(connection.TransportMode) != "" {
		return strings.ToUpper(strings.TrimSpace(connection.TransportMode))
	}
	if strings.TrimSpace(connection.Reachability) != "" {
		return strings.ToUpper(strings.TrimSpace(connection.Reachability))
	}
	return "PENDING"
}

func gatewaySelectionEqual(left, right gatewaySelectionState) bool {
	return left.NetworkID == right.NetworkID &&
		left.GatewayRole == right.GatewayRole &&
		sameGatewaySelectionTarget(left, right) &&
		left.Path == right.Path &&
		left.PolicyStatus == right.PolicyStatus
}

func sameGatewaySelectionTarget(left, right gatewaySelectionState) bool {
	if left.GatewayPeerID == right.GatewayPeerID {
		return true
	}
	leftUserID := strings.TrimSpace(left.GatewayUserID)
	rightUserID := strings.TrimSpace(right.GatewayUserID)
	leftVirtualIP := strings.TrimSpace(left.GatewayVirtualIP)
	rightVirtualIP := strings.TrimSpace(right.GatewayVirtualIP)
	if leftVirtualIP == "" || rightVirtualIP == "" || !strings.EqualFold(leftVirtualIP, rightVirtualIP) {
		return false
	}
	if leftUserID != "" && rightUserID != "" && !strings.EqualFold(leftUserID, rightUserID) {
		return false
	}
	return true
}

func shouldRecordInitialGatewayChange(selection gatewaySelectionState) bool {
	return strings.TrimSpace(selection.GatewayRole) != "" || strings.TrimSpace(selection.GatewayPeerID) != ""
}

func shouldRecordGatewayRemoval(selection gatewaySelectionState) bool {
	return strings.TrimSpace(selection.GatewayRole) != "" || strings.TrimSpace(selection.GatewayPeerID) != ""
}

func classifyGatewayChange(previous, current gatewaySelectionState) string {
	switch {
	case previous.NetworkID == "" && strings.EqualFold(current.GatewayRole, "GATEWAY"):
		return "LOCAL_GATEWAY_ACTIVE"
	case previous.NetworkID == "" && strings.TrimSpace(current.GatewayPeerID) != "":
		return "SELECTED"
	case strings.EqualFold(previous.GatewayRole, "GATEWAY") && !strings.EqualFold(current.GatewayRole, "GATEWAY"):
		return "LOCAL_GATEWAY_RELEASED"
	case !strings.EqualFold(previous.GatewayRole, "GATEWAY") && strings.EqualFold(current.GatewayRole, "GATEWAY"):
		return "LOCAL_GATEWAY_ACTIVE"
	case previous.GatewayPeerID != "" && current.GatewayPeerID != "" && previous.GatewayPeerID != current.GatewayPeerID && !sameGatewaySelectionTarget(previous, current):
		if gatewayRolePreference(current.GatewayTargetRole) > gatewayRolePreference(previous.GatewayTargetRole) {
			return "FAILBACK"
		}
		return "FAILOVER"
	case previous.GatewayPeerID == "" && current.GatewayPeerID != "":
		return "SELECTED"
	case previous.GatewayPeerID != "" && current.GatewayPeerID == "":
		return "LOST"
	case isStandbyGatewayPromotion(previous, current):
		return "PROMOTED"
	case isStandbyGatewayDemotion(previous, current):
		return "DEMOTED"
	case previous.Path != current.Path:
		return "PATH_CHANGED"
	case previous.PolicyStatus != current.PolicyStatus:
		return "STATUS_CHANGED"
	default:
		return "CHANGED"
	}
}

func isStandbyGatewayPromotion(previous, current gatewaySelectionState) bool {
	return sameGatewaySelectionTarget(previous, current) &&
		strings.EqualFold(previous.PolicyStatus, "STANDBY_GATEWAY") &&
		strings.EqualFold(current.PolicyStatus, "ACTIVE")
}

func isStandbyGatewayDemotion(previous, current gatewaySelectionState) bool {
	return sameGatewaySelectionTarget(previous, current) &&
		strings.EqualFold(previous.PolicyStatus, "ACTIVE") &&
		strings.EqualFold(current.PolicyStatus, "STANDBY_GATEWAY")
}

func (a *Agent) appendGatewayChangeLocked(eventType string, previous, current gatewaySelectionState, changedAt time.Time) {
	event := GatewayChangeEvent{
		NetworkID:             firstNonEmptyString(current.NetworkID, previous.NetworkID),
		Event:                 eventType,
		PreviousGatewayRole:   previous.GatewayRole,
		PreviousGatewayPeerID: previous.GatewayPeerID,
		PreviousPath:          previous.Path,
		PreviousPolicyStatus:  previous.PolicyStatus,
		CurrentGatewayRole:    current.GatewayRole,
		CurrentGatewayPeerID:  current.GatewayPeerID,
		CurrentPath:           current.Path,
		CurrentPolicyStatus:   current.PolicyStatus,
		ChangedAtUnix:         changedAt.Unix(),
	}
	a.gatewayHistory = append([]GatewayChangeEvent{event}, a.gatewayHistory...)
	limit := a.gatewayHistoryLimit
	if limit <= 0 {
		limit = defaultGatewayHistoryLimit
	}
	if len(a.gatewayHistory) > limit {
		a.gatewayHistory = a.gatewayHistory[:limit]
	}
}

func (a *Agent) reconcileRelayBindingsLocked() error {
	return a.reconcileRelayBindingsWithCredentialsLocked(nil)
}

func (a *Agent) reconcileRelayBindingsWithCredentialsLocked(credentials map[string]*transportauth.Credentials) error {
	if a.relayManager == nil {
		return nil
	}
	if a.recoveryPaused.Load() != nil {
		a.invalidateForwardingRoutesLocked() // Relay rebinding affects more than the recovering pair.
	}
	if a.currentUser == nil || a.deviceState == nil {
		return a.relayManager.Reconcile(nil)
	}
	managedPeers := a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	relayAddress := a.resolveRelayServerAddressLocked()
	accessToken := ""
	if a.currentSession != nil {
		accessToken = a.currentSession.AccessToken
	}
	bindings := make([]relaytransport.Binding, 0, len(managedPeers))
	if relayAddress != "" && accessToken != "" {
		for _, peer := range managedPeers {
			var peerCredentials *transportauth.Credentials
			if credentials != nil {
				peerCredentials = credentials[peer.PeerID]
			} else {
				peerCredentials = a.transportCredentialsLocked(peer)
			}
			bindings = append(bindings, relaytransport.Binding{
				Credentials:  peerCredentials,
				PeerID:       peer.PeerID,
				RelayAddress: relayAddress,
				AccessToken:  accessToken,
			})
		}
	}
	if err := a.relayManager.Reconcile(bindings); err != nil {
		return err
	}
	for _, binding := range bindings {
		if err := a.relayManager.SetExchangeHandler(binding.PeerID, a.transportExchangeHandler(binding.PeerID)); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) handleLifecycleErrorLocked(err error) {
	if err == nil {
		a.lastLifecycleError = ""
		return
	}
	a.lastLifecycleError = err.Error()
	a.logErrorf("lifecycle error: %v", err)
	if isUnauthorizedError(err) {
		userID := ""
		if a.currentUser != nil {
			userID = a.currentUser.ID
		}
		if a.deviceState != nil {
			a.deviceState.ClearSession(a.remote.BaseURL())
			if userID != "" {
				a.deviceState.ClearManagedPeers(a.remote.BaseURL(), userID)
				a.deviceState.ClearFileTransferSources(a.remote.BaseURL(), userID)
				a.deviceState.ClearFileTransferCaches(a.remote.BaseURL(), userID)
			}
			_ = a.savePersistentStateLocked()
		}
		a.clearInMemorySessionLocked()
		_ = a.reconcileManagedRuntimeLocked()
	}
}

func shouldClearPersistedSession(err error) bool {
	return isUnauthorizedError(err) || isNotFoundError(err)
}

func lifecycleUnixOrZero(state *PersistentState, selector func(ServiceLifecycleState) int64) int64 {
	if state == nil || selector == nil {
		return 0
	}
	return selector(state.Lifecycle)
}

func timeFromUnixOrZero(unix int64) time.Time {
	if unix <= 0 {
		return time.Time{}
	}
	return time.Unix(unix, 0)
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func unixMilliOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func durationMillis(value time.Duration) int64 {
	if value <= 0 {
		return 0
	}
	ms := value.Milliseconds()
	if ms <= 0 {
		return 1
	}
	return ms
}

func isUnauthorizedError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "unauthorized")
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstPositiveInt64(values ...int64) int64 {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func parseRelayServerAddresses(value string) []string {
	value = strings.NewReplacer(";", ",", "\n", ",", "\r", ",").Replace(value)
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		address := strings.TrimSpace(part)
		if address == "" {
			continue
		}
		key := strings.ToLower(address)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, address)
	}
	return out
}

func containsFold(values []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), target) {
			return true
		}
	}
	return false
}

func routeConfigForManagedPeer(peer ManagedPeerState) (string, int, error) {
	if routePrefix, prefixLength, err := routeConfigFromCIDR(peer.OverlayCIDR); err == nil {
		return routePrefix, prefixLength, nil
	}
	routePrefix, err := routePrefixForVirtualIP(peer.VirtualIP)
	if err != nil {
		return "", 0, err
	}
	return routePrefix, 24, nil
}

func (a *Agent) gatewayConnectionForNetworkLocked(network controlclient.Network, localPeerID string) *ConnectionStatus {
	var bestEligible *ConnectionStatus
	bestEligibleRole := ""
	for idx := range a.connections {
		connection := &a.connections[idx]
		if connection.NetworkID != network.ID || connection.LocalPeerID != localPeerID || !connection.TransportReady {
			continue
		}
		if strings.TrimSpace(connection.TransportMode) == "" {
			continue
		}
		role := a.remotePeerGatewayRoleForConnectionLocked(network, connection.RemotePeerID)
		if gatewayEligibleRole(role) {
			if bestEligible == nil || betterGatewayConnection(connection, role, bestEligible, bestEligibleRole) {
				bestEligible = connection
				bestEligibleRole = role
			}
		}
	}
	currentSelection, currentRole := a.currentSelectedGatewayConnectionForNetworkLocked(network, localPeerID)
	if currentSelection != nil && bestEligible != nil && !a.sameTransportRoutingTargetLocked(currentSelection, bestEligible) {
		if !materiallyBetterPrimaryFullTunnelGatewayConnection(bestEligible, bestEligibleRole, currentSelection, currentRole) &&
			!materiallyBetterPrimaryFullTunnelGatewayConnection(currentSelection, currentRole, bestEligible, bestEligibleRole) {
			return currentSelection
		}
	}
	return bestEligible
}

func (a *Agent) currentSelectedGatewayConnectionForNetworkLocked(network controlclient.Network, localPeerID string) (*ConnectionStatus, string) {
	selection, ok := a.gatewaySelections[network.ID]
	if !ok {
		return nil, ""
	}
	remotePeerID := strings.TrimSpace(selection.GatewayPeerID)
	if remotePeerID == "" {
		return nil, ""
	}
	connection := a.connectionByPeersLocked(network.ID, localPeerID, remotePeerID)
	if connection != nil && connection.TransportReady && strings.TrimSpace(connection.TransportMode) != "" {
		role := a.remotePeerGatewayRoleForConnectionLocked(network, connection.RemotePeerID)
		if gatewayEligibleRole(role) {
			return connection, role
		}
	}
	var best *ConnectionStatus
	bestRole := ""
	for idx := range a.connections {
		candidate := &a.connections[idx]
		if candidate.NetworkID != network.ID || candidate.LocalPeerID != localPeerID || !candidate.TransportReady || strings.TrimSpace(candidate.TransportMode) == "" {
			continue
		}
		if !a.gatewaySelectionMatchesConnectionLocked(selection, candidate) {
			continue
		}
		role := a.remotePeerGatewayRoleForConnectionLocked(network, candidate.RemotePeerID)
		if !gatewayEligibleRole(role) {
			continue
		}
		if best == nil || betterGatewayConnection(candidate, role, best, bestRole) {
			best = candidate
			bestRole = role
		}
	}
	if best == nil {
		return nil, ""
	}
	return best, bestRole
}

func remotePeerUserIDForConnection(peers []controlclient.Peer, remotePeerID string) string {
	for _, peer := range peers {
		if peer.ID == remotePeerID {
			return peer.UserID
		}
	}
	return ""
}

func remotePeerVirtualIPForConnection(peers []controlclient.Peer, remotePeerID string) string {
	for _, peer := range peers {
		if peer.ID == remotePeerID {
			return peer.VirtualIP
		}
	}
	return ""
}

func (a *Agent) peerUserIDInNetwork(networkID, peerID string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.peerUserIDInNetworkUnlocked(networkID, peerID)
}

func (a *Agent) peerUserIDInNetworkUnlocked(networkID, peerID string) string {
	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return ""
	}
	if a.currentUser != nil && a.deviceState != nil {
		for _, managedPeer := range a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID) {
			if managedPeer.NetworkID == networkID && managedPeer.PeerID == peerID {
				return a.currentUser.ID
			}
		}
	}
	return firstNonEmptyString(
		remotePeerUserIDForConnection(a.discoveredPeers[networkID], peerID),
		a.connectionRemoteUserIDUnlocked(networkID, peerID),
	)
}

func (a *Agent) remotePeerGatewayRoleForConnectionLocked(network controlclient.Network, remotePeerID string) string {
	remoteUserID := strings.TrimSpace(a.peerUserIDInNetworkUnlocked(network.ID, remotePeerID))
	if remoteUserID == "" {
		if connection := a.connectionForGatewayPeerLocked(network.ID, remotePeerID); connection != nil {
			if role := a.gatewaySelectionFallbackRoleForConnectionLocked(network, connection); gatewayEligibleRole(role) {
				return role
			}
		}
		return ""
	}
	return networkRoleForUser(network, remoteUserID)
}

func (a *Agent) gatewaySelectionFallbackRoleForConnectionLocked(network controlclient.Network, connection *ConnectionStatus) string {
	if connection == nil {
		return ""
	}
	selection, ok := a.gatewaySelections[network.ID]
	if !ok || !strings.EqualFold(strings.TrimSpace(selection.GatewayRole), "CLIENT") {
		return ""
	}
	if !a.gatewaySelectionMatchesConnectionLocked(selection, connection) {
		return ""
	}
	if role := strings.ToUpper(strings.TrimSpace(selection.GatewayTargetRole)); gatewayEligibleRole(role) {
		return role
	}
	return networkRoleForUser(network, strings.TrimSpace(selection.GatewayUserID))
}

func (a *Agent) gatewaySelectionMatchesConnectionLocked(selection gatewaySelectionState, connection *ConnectionStatus) bool {
	if connection == nil {
		return false
	}
	if selection.NetworkID != "" && !strings.EqualFold(strings.TrimSpace(selection.NetworkID), strings.TrimSpace(connection.NetworkID)) {
		return false
	}
	activeLocalPeerID := strings.TrimSpace(a.currentManagedPeerIDForNetworkLocked(selection.NetworkID))
	if activeLocalPeerID != "" && !strings.EqualFold(strings.TrimSpace(connection.LocalPeerID), activeLocalPeerID) {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(selection.GatewayPeerID), strings.TrimSpace(connection.RemotePeerID)) {
		return true
	}
	selectionVirtualIP := strings.TrimSpace(selection.GatewayVirtualIP)
	connectionVirtualIP := a.connectionRemoteVirtualIPUnlocked(connection)
	selectionUserID := strings.TrimSpace(selection.GatewayUserID)
	connectionUserID := strings.TrimSpace(firstNonEmptyString(connection.RemoteUserID, a.peerUserIDInNetworkUnlocked(connection.NetworkID, connection.RemotePeerID)))
	if selectionVirtualIP == "" {
		return a.gatewaySelectionEndpointContinuityMatchLocked(selection, connection, selectionUserID, selectionVirtualIP)
	}
	if connectionVirtualIP == "" {
		if a.uniqueSameUserGatewaySelectionMatchLocked(selection, connection, selectionUserID, connectionUserID, selectionVirtualIP) {
			return true
		}
		return a.gatewaySelectionEndpointContinuityMatchLocked(selection, connection, selectionUserID, selectionVirtualIP)
	}
	if !strings.EqualFold(selectionVirtualIP, connectionVirtualIP) {
		return false
	}
	if selectionUserID != "" && connectionUserID != "" && !strings.EqualFold(selectionUserID, connectionUserID) {
		return false
	}
	return true
}

func (a *Agent) gatewaySelectionEndpointContinuityMatchLocked(selection gatewaySelectionState, connection *ConnectionStatus, selectionUserID, selectionVirtualIP string) bool {
	if connection == nil {
		return false
	}
	candidateParts := endpointContinuityParts(strings.TrimSpace(connection.RemoteEndpoint), connection.RemoteCandidates)
	if len(candidateParts) == 0 {
		return false
	}
	selectionPeerID := strings.TrimSpace(selection.GatewayPeerID)
	if selectionPeerID == "" {
		return false
	}
	selectionParts := endpointContinuityPartsFromKey(strings.TrimSpace(selection.GatewayEndpointKey))
	activeLocalPeerID := strings.TrimSpace(a.currentManagedPeerIDForNetworkLocked(selection.NetworkID))
	if activeLocalPeerID != "" && !strings.EqualFold(strings.TrimSpace(connection.LocalPeerID), activeLocalPeerID) {
		return false
	}
	matchedSelectionKey := endpointContinuityPartsOverlap(selectionParts, candidateParts)
	for idx := range a.connections {
		candidate := &a.connections[idx]
		if candidate == connection {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(candidate.NetworkID), strings.TrimSpace(connection.NetworkID)) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(candidate.RemotePeerID), selectionPeerID) {
			continue
		}
		if !endpointContinuityPartsOverlap(candidateParts, endpointContinuityParts(strings.TrimSpace(candidate.RemoteEndpoint), candidate.RemoteCandidates)) {
			continue
		}
		matchedSelectionKey = true
		break
	}
	if !matchedSelectionKey {
		return false
	}
	referenceParts := mergeEndpointContinuityParts(selectionParts, candidateParts)
	for idx := range a.connections {
		other := &a.connections[idx]
		if other == connection {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(other.NetworkID), strings.TrimSpace(connection.NetworkID)) {
			continue
		}
		if !endpointContinuityPartsOverlap(referenceParts, endpointContinuityParts(strings.TrimSpace(other.RemoteEndpoint), other.RemoteCandidates)) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(other.RemotePeerID), selectionPeerID) {
			continue
		}
		otherVirtualIP := strings.TrimSpace(a.connectionRemoteVirtualIPUnlocked(other))
		otherUserID := strings.TrimSpace(firstNonEmptyString(other.RemoteUserID, a.peerUserIDInNetworkUnlocked(other.NetworkID, other.RemotePeerID)))
		if selectionVirtualIP != "" && otherVirtualIP != "" && !strings.EqualFold(selectionVirtualIP, otherVirtualIP) {
			return false
		}
		if selectionUserID != "" && otherUserID != "" && !strings.EqualFold(selectionUserID, otherUserID) {
			return false
		}
		if otherVirtualIP == "" && otherUserID == "" {
			return false
		}
	}
	return true
}

func (a *Agent) uniqueSameUserGatewaySelectionMatchLocked(selection gatewaySelectionState, connection *ConnectionStatus, selectionUserID, connectionUserID, selectionVirtualIP string) bool {
	if selectionUserID == "" || connectionUserID == "" || !strings.EqualFold(selectionUserID, connectionUserID) {
		return false
	}
	activeLocalPeerID := strings.TrimSpace(connection.LocalPeerID)
	if activeLocalPeerID == "" {
		activeLocalPeerID = strings.TrimSpace(a.currentManagedPeerIDForNetworkLocked(selection.NetworkID))
	}
	for idx := range a.connections {
		candidate := &a.connections[idx]
		if candidate == connection {
			continue
		}
		if selection.NetworkID != "" && !strings.EqualFold(strings.TrimSpace(selection.NetworkID), strings.TrimSpace(candidate.NetworkID)) {
			continue
		}
		if activeLocalPeerID != "" && !strings.EqualFold(strings.TrimSpace(candidate.LocalPeerID), activeLocalPeerID) {
			continue
		}
		candidateUserID := strings.TrimSpace(firstNonEmptyString(candidate.RemoteUserID, a.peerUserIDInNetworkUnlocked(candidate.NetworkID, candidate.RemotePeerID)))
		if candidateUserID == "" || !strings.EqualFold(candidateUserID, selectionUserID) {
			continue
		}
		candidateVirtualIP := a.connectionRemoteVirtualIPUnlocked(candidate)
		if candidateVirtualIP == "" {
			return false
		}
		if !strings.EqualFold(candidateVirtualIP, selectionVirtualIP) {
			continue
		}
	}
	return true
}

func (a *Agent) sameUserPeerInNetwork(networkID, peerID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sameUserPeerInNetworkUnlocked(networkID, peerID)
}

func (a *Agent) connectionRemoteUserIDUnlocked(networkID, peerID string) string {
	for idx := range a.connections {
		connection := &a.connections[idx]
		if !strings.EqualFold(strings.TrimSpace(connection.NetworkID), strings.TrimSpace(networkID)) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(connection.RemotePeerID), strings.TrimSpace(peerID)) {
			continue
		}
		if strings.TrimSpace(connection.RemoteUserID) != "" {
			return strings.TrimSpace(connection.RemoteUserID)
		}
	}
	return ""
}

func (a *Agent) sameUserPeerInNetworkUnlocked(networkID, peerID string) bool {
	if a.currentUser == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(a.peerUserIDInNetworkUnlocked(networkID, peerID)), strings.TrimSpace(a.currentUser.ID))
}

func (a *Agent) transferTargetsCurrentUserLocked(transfer controlclient.FileTransfer) bool {
	if a.currentUser == nil {
		return false
	}
	if strings.TrimSpace(transfer.ToUserID) != "" {
		return strings.EqualFold(strings.TrimSpace(transfer.ToUserID), strings.TrimSpace(a.currentUser.ID))
	}
	return a.sameUserPeerInNetworkUnlocked(transfer.NetworkID, transfer.ToPeerID)
}

func localUserCanActAsGateway(network controlclient.Network, userID string) bool {
	return gatewayEligibleRole(networkRoleForUser(network, userID))
}

func gatewayEligiblePeerForConnection(network controlclient.Network, peers []controlclient.Peer, remotePeerID string) bool {
	return gatewayEligibleRole(remotePeerGatewayRoleForConnection(network, peers, remotePeerID))
}

func remotePeerGatewayRoleForConnection(network controlclient.Network, peers []controlclient.Peer, remotePeerID string) string {
	remoteUserID := remotePeerUserIDForConnection(peers, remotePeerID)
	if strings.TrimSpace(remoteUserID) == "" {
		return ""
	}
	return networkRoleForUser(network, remoteUserID)
}

func networkRoleForUser(network controlclient.Network, userID string) string {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return ""
	}
	if network.OwnerID != "" && userID == network.OwnerID {
		return "OWNER"
	}
	if network.MemberRoles == nil {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(network.MemberRoles[userID]))
}

func gatewayEligibleRole(role string) bool {
	switch strings.ToUpper(strings.TrimSpace(role)) {
	case "OWNER", "ADMIN":
		return true
	default:
		return false
	}
}

func betterGatewayConnection(candidate *ConnectionStatus, candidateRole string, current *ConnectionStatus, currentRole string) bool {
	if materiallyBetterGatewayConnection(candidate, candidateRole, current, currentRole) {
		return true
	}
	if materiallyBetterGatewayConnection(current, currentRole, candidate, candidateRole) {
		return false
	}
	if fresherTransportConnection(candidate, current) {
		return true
	}
	if fresherTransportConnection(current, candidate) {
		return false
	}
	return strings.Compare(strings.TrimSpace(candidate.RemotePeerID), strings.TrimSpace(current.RemotePeerID)) < 0
}

const fullTunnelPrimaryGatewayRTTHysteresisMillis int64 = 5
const fullTunnelGatewayRoleQualityRTTHysteresisMillis int64 = 15

func materiallyBetterPrimaryFullTunnelGatewayConnection(candidate *ConnectionStatus, candidateRole string, current *ConnectionStatus, currentRole string) bool {
	if candidate == nil {
		return false
	}
	if current == nil {
		return true
	}
	if gatewayTransportPreference(candidate.TransportMode) != gatewayTransportPreference(current.TransportMode) {
		return gatewayTransportPreference(candidate.TransportMode) > gatewayTransportPreference(current.TransportMode)
	}
	if gatewayReachabilityPreference(candidate.Reachability) != gatewayReachabilityPreference(current.Reachability) {
		return gatewayReachabilityPreference(candidate.Reachability) > gatewayReachabilityPreference(current.Reachability)
	}
	if gatewayRolePreference(candidateRole) != gatewayRolePreference(currentRole) {
		if materiallyBetterGatewayQualityBeforeRole(candidate, current) {
			return true
		}
		if materiallyBetterGatewayQualityBeforeRole(current, candidate) {
			return false
		}
		return gatewayRolePreference(candidateRole) > gatewayRolePreference(currentRole)
	}
	if gatewayLossPreference(candidate.ConsecutiveLosses) != gatewayLossPreference(current.ConsecutiveLosses) {
		return materiallyBetterPrimaryFullTunnelGatewayLoss(candidate.ConsecutiveLosses, current.ConsecutiveLosses)
	}
	candidateRTT := gatewayPreferredRTTMillis(candidate.AverageRTTMillis, candidate.LastRTTMillis)
	currentRTT := gatewayPreferredRTTMillis(current.AverageRTTMillis, current.LastRTTMillis)
	if candidateRTT > 0 && currentRTT > 0 {
		return candidateRTT+fullTunnelPrimaryGatewayRTTHysteresisMillis < currentRTT
	}
	if gatewayRTTScore(candidate.AverageRTTMillis, candidate.LastRTTMillis) != gatewayRTTScore(current.AverageRTTMillis, current.LastRTTMillis) {
		return gatewayRTTScore(candidate.AverageRTTMillis, candidate.LastRTTMillis) > gatewayRTTScore(current.AverageRTTMillis, current.LastRTTMillis)
	}
	return false
}

func materiallyBetterPrimaryFullTunnelGatewayLoss(candidateLosses, currentLosses int) bool {
	if gatewayLossPreference(candidateLosses) <= gatewayLossPreference(currentLosses) {
		return false
	}
	// A single missed keepalive on the current active FULL path is not enough to
	// hand the default route to another equal-quality network.
	if candidateLosses <= 0 && currentLosses == 1 {
		return false
	}
	return true
}

func materiallyBetterGatewayQualityBeforeRole(candidate *ConnectionStatus, current *ConnectionStatus) bool {
	if candidate == nil {
		return false
	}
	if current == nil {
		return true
	}
	if gatewayLossPreference(candidate.ConsecutiveLosses) != gatewayLossPreference(current.ConsecutiveLosses) {
		return materiallyBetterPrimaryFullTunnelGatewayLoss(candidate.ConsecutiveLosses, current.ConsecutiveLosses)
	}
	candidateRTT := gatewayPreferredRTTMillis(candidate.AverageRTTMillis, candidate.LastRTTMillis)
	currentRTT := gatewayPreferredRTTMillis(current.AverageRTTMillis, current.LastRTTMillis)
	if candidateRTT > 0 && currentRTT > 0 {
		return candidateRTT+fullTunnelGatewayRoleQualityRTTHysteresisMillis < currentRTT
	}
	return false
}

func materiallyBetterGatewayConnection(candidate *ConnectionStatus, candidateRole string, current *ConnectionStatus, currentRole string) bool {
	if candidate == nil {
		return false
	}
	if current == nil {
		return true
	}
	if gatewayTransportPreference(candidate.TransportMode) != gatewayTransportPreference(current.TransportMode) {
		return gatewayTransportPreference(candidate.TransportMode) > gatewayTransportPreference(current.TransportMode)
	}
	if gatewayReachabilityPreference(candidate.Reachability) != gatewayReachabilityPreference(current.Reachability) {
		return gatewayReachabilityPreference(candidate.Reachability) > gatewayReachabilityPreference(current.Reachability)
	}
	// For practical FULL exit routing, prefer the healthier live path before breaking
	// ties by gateway role, so an owner stuck on relay does not outrank a direct admin.
	if gatewayRolePreference(candidateRole) != gatewayRolePreference(currentRole) {
		if materiallyBetterGatewayQualityBeforeRole(candidate, current) {
			return true
		}
		if materiallyBetterGatewayQualityBeforeRole(current, candidate) {
			return false
		}
		return gatewayRolePreference(candidateRole) > gatewayRolePreference(currentRole)
	}
	if gatewayLossPreference(candidate.ConsecutiveLosses) != gatewayLossPreference(current.ConsecutiveLosses) {
		return gatewayLossPreference(candidate.ConsecutiveLosses) > gatewayLossPreference(current.ConsecutiveLosses)
	}
	if gatewayRTTScore(candidate.AverageRTTMillis, candidate.LastRTTMillis) != gatewayRTTScore(current.AverageRTTMillis, current.LastRTTMillis) {
		return gatewayRTTScore(candidate.AverageRTTMillis, candidate.LastRTTMillis) > gatewayRTTScore(current.AverageRTTMillis, current.LastRTTMillis)
	}
	return false
}

func gatewayRolePreference(role string) int {
	switch strings.ToUpper(strings.TrimSpace(role)) {
	case "OWNER":
		return 2
	case "ADMIN":
		return 1
	default:
		return 0
	}
}

func gatewayTransportPreference(mode string) int {
	switch strings.ToUpper(strings.TrimSpace(mode)) {
	case "DIRECT":
		return 2
	case "RELAY":
		return 1
	default:
		return 0
	}
}

func gatewayReachabilityPreference(reachability string) int {
	switch strings.ToUpper(strings.TrimSpace(reachability)) {
	case "DIRECT":
		return 2
	case "RELAY":
		return 1
	default:
		return 0
	}
}

func gatewayLossPreference(losses int) int {
	switch {
	case losses <= 0:
		return 2
	case losses == 1:
		return 1
	default:
		return 0
	}
}

func gatewayRTTScore(averageRTTMillis, lastRTTMillis int64) int64 {
	if averageRTTMillis > 0 {
		return -averageRTTMillis
	}
	if lastRTTMillis > 0 {
		return -lastRTTMillis
	}
	return 0
}

func gatewayPreferredRTTMillis(averageRTTMillis, lastRTTMillis int64) int64 {
	if averageRTTMillis > 0 {
		return averageRTTMillis
	}
	if lastRTTMillis > 0 {
		return lastRTTMillis
	}
	return 0
}

func fresherTransportConnection(candidate, current *ConnectionStatus) bool {
	if candidate == nil {
		return false
	}
	if current == nil {
		return true
	}
	if candidate.LastTransportUnix != current.LastTransportUnix {
		return candidate.LastTransportUnix > current.LastTransportUnix
	}
	if candidate.TransportEstablishedUnix != current.TransportEstablishedUnix {
		return candidate.TransportEstablishedUnix > current.TransportEstablishedUnix
	}
	if candidate.LastKeepaliveUnix != current.LastKeepaliveUnix {
		return candidate.LastKeepaliveUnix > current.LastKeepaliveUnix
	}
	if candidate.TransportPacketCount != current.TransportPacketCount {
		return candidate.TransportPacketCount > current.TransportPacketCount
	}
	return false
}

func routeConfigFromCIDR(cidr string) (string, int, error) {
	_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || network == nil {
		return "", 0, fmt.Errorf("invalid overlay CIDR %q", cidr)
	}
	ones, _ := network.Mask.Size()
	return network.String(), ones, nil
}

func routePrefixForVirtualIP(virtualIP string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(virtualIP)).To4()
	if ip == nil {
		return "", fmt.Errorf("invalid virtual IP %q", virtualIP)
	}
	return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2]), nil
}

func ipv4PacketEndpoints(packet []byte) (string, string, error) {
	if len(packet) < 20 {
		return "", "", fmt.Errorf("packet too short")
	}
	version := packet[0] >> 4
	headerLength := int(packet[0]&0x0f) * 4
	if version != 4 || headerLength < 20 || len(packet) < headerLength {
		return "", "", fmt.Errorf("invalid ipv4 header")
	}
	source := net.IPv4(packet[12], packet[13], packet[14], packet[15]).String()
	destination := net.IPv4(packet[16], packet[17], packet[18], packet[19]).String()
	return source, destination, nil
}

func managedPeerByNetwork(peers []ManagedPeerState, networkID string) ManagedPeerState {
	for _, peer := range peers {
		if peer.NetworkID == networkID {
			return peer
		}
	}
	return ManagedPeerState{}
}

func destinationWithinOverlay(overlayCIDR, destinationIP string) bool {
	ip := net.ParseIP(strings.TrimSpace(destinationIP)).To4()
	if ip == nil {
		return false
	}
	_, network, err := net.ParseCIDR(strings.TrimSpace(overlayCIDR))
	if err != nil || network == nil {
		return false
	}
	return network.Contains(ip)
}

func ipUsesLocalIPv4Semantics(candidateIP string) bool {
	ip := net.ParseIP(strings.TrimSpace(candidateIP)).To4()
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

func ipWithinAnyManagedOverlay(managedPeers []ManagedPeerState, candidateIP string) bool {
	for _, peer := range managedPeers {
		if destinationWithinOverlay(peer.OverlayCIDR, candidateIP) {
			return true
		}
	}
	return false
}

func isIPv4MulticastOrBroadcast(overlayCIDR, destinationIP string) bool {
	return groupTrafficKind(overlayCIDR, destinationIP) != ""
}

func groupTrafficKind(overlayCIDR, destinationIP string) string {
	ip := net.ParseIP(strings.TrimSpace(destinationIP)).To4()
	if ip == nil {
		return ""
	}
	if ip.Equal(net.IPv4bcast) {
		return "broadcast"
	}
	if ip[0] >= 224 && ip[0] <= 239 {
		return "multicast"
	}
	_, network, err := net.ParseCIDR(strings.TrimSpace(overlayCIDR))
	if err != nil || network == nil {
		return ""
	}
	broadcast := make(net.IP, len(network.IP.To4()))
	copy(broadcast, network.IP.To4())
	mask := network.Mask
	if len(broadcast) != len(mask) {
		return ""
	}
	for idx := range broadcast {
		broadcast[idx] = broadcast[idx] | ^mask[idx]
	}
	if ip.Equal(broadcast) {
		return "broadcast"
	}
	return ""
}

func (a *Agent) refreshSTUNLocked(now time.Time) error {
	serverAddress := a.resolveSTUNServerAddressLocked()
	if serverAddress == "" {
		return nil
	}
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return err
	}
	if a.currentUser == nil {
		return nil
	}
	managedPeers := state.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	for _, managedPeer := range managedPeers {
		endpoint := strings.TrimSpace(managedPeer.Endpoint)
		if endpoint == "" {
			continue
		}
		return a.refreshSTUNForEndpointLocked(now, managedPeer.PeerID, endpoint)
	}
	return nil
}

func (a *Agent) resolveSTUNServerAddressLocked() string {
	return strings.TrimSpace(a.runtime.STUNServerAddress)
}

func (a *Agent) resolveRelayServerAddressLocked() string {
	addresses := a.resolveRelayServerAddressesLocked()
	if len(addresses) == 0 {
		a.activeRelayServer = ""
		return ""
	}
	if containsFold(addresses, a.activeRelayServer) {
		return a.activeRelayServer
	}
	a.activeRelayServer = addresses[0]
	return a.activeRelayServer
}

func (a *Agent) resolveRelayServerAddressesLocked() []string {
	addresses := parseRelayServerAddresses(a.runtime.RelayServerAddress)
	if len(addresses) == 0 {
		a.activeRelayServer = ""
		return nil
	}
	if !containsFold(addresses, a.activeRelayServer) {
		a.activeRelayServer = addresses[0]
	}
	return append([]string(nil), addresses...)
}

func (a *Agent) refreshSTUNForEndpointLocked(now time.Time, localPeerID, endpoint string) error {
	serverAddress := a.resolveSTUNServerAddressLocked()
	if serverAddress == "" {
		return nil
	}
	previousEndpoint := strings.TrimSpace(a.localSTUNEndpoint)
	previousPublicEndpoint := strings.TrimSpace(a.publicEndpoint)
	var (
		result          stun.ProbeResult
		err             error
		reboundListener bool
	)
	if prober, ok := a.directManager.(directSTUNProber); ok && strings.TrimSpace(localPeerID) != "" {
		result, err = prober.ProbeSTUN(localPeerID, serverAddress, stun.DefaultTimeout)
		if err != nil && isDirectListenerUnavailable(err) {
			if a.hasManagedPeerLocked(localPeerID) {
				if rebindErr := a.reconcileManagedRuntimeLocked(); rebindErr == nil {
					reboundListener = true
					result, err = prober.ProbeSTUN(localPeerID, serverAddress, stun.DefaultTimeout)
				} else {
					err = rebindErr
				}
			} else {
				result, err = stun.Probe(serverAddress, endpoint, stun.DefaultTimeout)
			}
		}
	} else {
		result, err = stun.Probe(serverAddress, endpoint, stun.DefaultTimeout)
	}
	a.lastSTUNProbeAt = now
	a.localSTUNEndpoint = endpoint
	if err != nil {
		a.natType = result.NATType
		a.publicEndpoint = ""
		return err
	}
	a.natType = result.NATType
	a.publicEndpoint = result.MappedAddress
	if reboundListener {
		a.triggerImmediateDirectFailbackLocked(localPeerID)
	}
	if strings.EqualFold(strings.TrimSpace(endpoint), previousEndpoint) && previousPublicEndpoint != "" && !strings.EqualFold(previousPublicEndpoint, strings.TrimSpace(result.MappedAddress)) {
		a.handleManagedPeerPublicEndpointChangeLocked(endpoint, previousPublicEndpoint, result.MappedAddress)
	}
	return nil
}

func (a *Agent) handleManagedPeerPublicEndpointChangeLocked(endpoint, previousPublicEndpoint, currentPublicEndpoint string) {
	if a.currentUser == nil || a.deviceState == nil {
		return
	}
	endpoint = strings.TrimSpace(endpoint)
	previousPublicEndpoint = strings.TrimSpace(previousPublicEndpoint)
	currentPublicEndpoint = strings.TrimSpace(currentPublicEndpoint)
	if endpoint == "" || previousPublicEndpoint == "" || currentPublicEndpoint == "" || strings.EqualFold(previousPublicEndpoint, currentPublicEndpoint) {
		return
	}
	managedPeers := a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	preferredKeys := a.preferredTransportLifecycleConnectionKeysLocked()
	resetCount := 0
	for idx := range a.connections {
		connection := &a.connections[idx]
		if _, ok := preferredKeys[connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)]; !ok {
			continue
		}
		localPeer := managedPeerByNetwork(managedPeers, connection.NetworkID)
		if localPeer.PeerID == "" || !strings.EqualFold(strings.TrimSpace(localPeer.Endpoint), endpoint) || !strings.EqualFold(strings.TrimSpace(connection.LocalPeerID), strings.TrimSpace(localPeer.PeerID)) {
			continue
		}
		key := connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)
		attempt := a.directAttempts[key]
		if strings.TrimSpace(attempt.LocalEndpoint) == "" && strings.TrimSpace(attempt.RemoteEndpointKey) == "" && strings.TrimSpace(attempt.TransportSessionID) == "" && attempt.AttemptCount == 0 {
			continue
		}
		a.resetAttemptForEndpointChangeLocked(connection, &attempt, endpoint, remoteEndpointKey(*connection), "local public endpoint changed")
		a.directAttempts[key] = attempt
		a.applyAttemptStateToConnection(connection, attempt)
		resetCount++
	}
	if resetCount > 0 {
		a.logInfow("managed_peer.public_endpoint_changed", "managed peer public endpoint changed", "endpoint", endpoint, "previousPublicEndpoint", previousPublicEndpoint, "currentPublicEndpoint", currentPublicEndpoint, "connectionCount", resetCount)
	}
}

func (a *Agent) handleManagedPeerRoamingLocked(managedPeer ManagedPeerState, endpoint string, now time.Time) error {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil
	}
	if a.resolveSTUNServerAddressLocked() != "" && !strings.EqualFold(endpoint, strings.TrimSpace(a.localSTUNEndpoint)) {
		if err := a.refreshSTUNForEndpointLocked(now, managedPeer.PeerID, endpoint); err != nil {
			return err
		}
	}
	preferredKeys := a.preferredTransportLifecycleConnectionKeysLocked()
	for idx := range a.connections {
		connection := &a.connections[idx]
		if connection.NetworkID != managedPeer.NetworkID || connection.LocalPeerID != managedPeer.PeerID {
			continue
		}
		if _, ok := preferredKeys[connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)]; !ok {
			continue
		}
		key := connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)
		attempt := a.directAttempts[key]
		if !strings.EqualFold(strings.TrimSpace(attempt.LocalEndpoint), endpoint) {
			a.resetAttemptForEndpointChangeLocked(connection, &attempt, endpoint, remoteEndpointKey(*connection), "local endpoint changed")
			a.directAttempts[key] = attempt
			a.applyAttemptStateToConnection(connection, attempt)
		}
	}
	a.logInfof("managed peer roamed to endpoint %s on network %s", endpoint, managedPeer.NetworkID)
	return nil
}

func (a *Agent) triggerImmediateDirectFailbackLocked(localPeerID string) {
	localPeerID = strings.TrimSpace(localPeerID)
	if localPeerID == "" {
		return
	}
	preferredKeys := a.preferredTransportLifecycleConnectionKeysLocked()
	for idx := range a.connections {
		connection := &a.connections[idx]
		if !strings.EqualFold(strings.TrimSpace(connection.LocalPeerID), localPeerID) {
			continue
		}
		if _, ok := preferredKeys[connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)]; !ok {
			continue
		}
		key := connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)
		attempt := a.directAttempts[key]
		if !attempt.DirectReady || !strings.EqualFold(strings.TrimSpace(attempt.TransportMode), "RELAY") {
			continue
		}
		attempt.NextFailbackAt = time.Time{}
		if strings.TrimSpace(attempt.LastError) == "" {
			attempt.LastError = "local listener rebound; retrying direct path"
		}
		a.directAttempts[key] = attempt
		a.applyAttemptStateToConnection(connection, attempt)
	}
}

func (a *Agent) negotiateDirectConnectionsLocked(now time.Time) error {
	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return err
	}
	if a.currentUser == nil {
		a.directAttempts = map[string]DirectAttemptState{}
		return nil
	}

	managedPeers := state.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	preferredConnections := a.preferredTransportLifecycleConnectionsLocked()
	a.clearSupersededTransportAttemptsLocked(preferredConnections)
	activeKeys := map[string]struct{}{}
	for _, connection := range preferredConnections {
		key := connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)
		activeKeys[key] = struct{}{}
		attempt := a.directAttempts[key]
		a.syncAttemptEndpointsLocked(connection, &attempt, managedPeers)
		persistAttempt := func() {
			a.directAttempts[key] = attempt
			a.applyAttemptStateToConnection(connection, attempt)
		}
		if a.shouldRekeyTransportLocked(attempt, now) {
			a.dropTransportSessionLocked(connection.LocalPeerID, connection.RemotePeerID, attempt.TransportMode)
			attempt.DirectReady = false
			attempt.TransportMode = ""
			attempt.TransportSessionID = ""
			attempt.TransportStartedAt = time.Time{}
			attempt.TransportPacketCount = 0
			attempt.LastError = "transport rekey requested"
			attempt.NextAttemptAt = time.Time{}
			attempt.NextFailbackAt = time.Time{}
			persistAttempt()
		}
		if !isTransportEligibleConnection(*connection) {
			a.resetAttemptForReachabilityLossLocked(connection, &attempt, "remote peer is offline or unavailable")
			persistAttempt()
			continue
		}
		if attempt.DirectReady {
			if a.shouldAttemptDirectFailbackLocked(*connection, attempt, now) {
				if err := a.promoteRelayConnectionToDirectLocked(connection, &attempt, now); err != nil {
					attempt.LastError = "direct failback failed: " + err.Error()
					attempt.LastAttemptAt = now
					attempt.NextFailbackAt = now.Add(a.runtime.RelayFailbackPeriod)
				}
				persistAttempt()
				continue
			}
			if strings.EqualFold(attempt.TransportMode, "RELAY") {
				connection.Reachability = "RELAY"
			} else {
				connection.Reachability = "DIRECT"
			}
			connection.State = "CONNECTED"
			persistAttempt()
			continue
		}
		if len(connection.RemoteCandidates) == 0 {
			persistAttempt()
			continue
		}
		if attempt.AttemptCount >= a.runtime.DirectMaxAttempts {
			connection.Reachability = "RELAY"
			connection.State = "RELAY_READY"
			persistAttempt()
			continue
		}
		if !attempt.NextAttemptAt.IsZero() && now.Before(attempt.NextAttemptAt) {
			persistAttempt()
			continue
		}
		probeErr := a.establishPreferredTransportLocked(connection, &attempt, now)
		if probeErr != nil {
			attempt.DirectReady = false
			attempt.LastError = probeErr.Error()
			attempt.SelectedCandidate = ""
			attempt.TransportMode = ""
			attempt.TransportSessionID = ""
			attempt.TransportStartedAt = time.Time{}
			attempt.TransportPacketCount = 0
			attempt.LastTransportAt = time.Time{}
			attempt.NextFailbackAt = time.Time{}
			if connection.State == "CONNECTED" {
				if strings.EqualFold(connection.Reachability, "RELAY") {
					connection.State = "RELAY_READY"
				} else {
					connection.State = "DIRECT_CANDIDATE"
				}
			}
			if attempt.AttemptCount >= a.runtime.DirectMaxAttempts {
				if a.canUseRelayLocked(connection) {
					connection.Reachability = "RELAY"
					connection.State = "RELAY_READY"
				} else {
					connection.Reachability = "RELAY"
					connection.State = "RELAY_READY"
				}
				attempt.NextAttemptAt = time.Time{}
			} else {
				attempt.NextAttemptAt = now.Add(directRetryDelay(a.runtime.DirectRetryBase, a.runtime.DirectRetryMax, attempt.AttemptCount))
				connection.Reachability = "DIRECT"
				connection.State = "DIRECT_CANDIDATE"
			}
		}
		persistAttempt()
	}

	filtered := make(map[string]DirectAttemptState, len(activeKeys))
	for key := range activeKeys {
		if attempt, ok := a.directAttempts[key]; ok {
			filtered[key] = attempt
		}
	}
	a.directAttempts = filtered

	for _, managedPeer := range managedPeers {
		reachability, connectionState := summarizeNetworkSignaling(managedPeer.PeerID, managedPeer.NetworkID, a.connections)
		if err := a.outboundControlIOLocked(func() error {
			_, err := a.remote.UpdatePeerSignaling(managedPeer.PeerID, reachability, connectionState)
			return err
		}); err != nil {
			return err
		}
	}
	return a.reconcileNegotiatedRuntimeLocked()
}

func (a *Agent) cleanupRemovedConnectionsLocked(previous, current []ConnectionStatus) {
	if len(previous) == 0 {
		return
	}
	activeKeys := make(map[string]struct{}, len(current))
	for _, connection := range current {
		activeKeys[connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)] = struct{}{}
	}
	for _, connection := range previous {
		key := connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)
		if _, ok := activeKeys[key]; ok {
			continue
		}
		replacement := a.replacementConnectionForRemovedLocked(connection, current)
		if replacement != nil {
			adoptRemovedConnectionContinuity(connection, replacement)
		}
		if replacement == nil && strings.TrimSpace(connection.TunnelID) != "" && (strings.EqualFold(connection.TunnelState, "NEGOTIATING") || strings.EqualFold(connection.TunnelState, "OPEN")) {
			if _, err := a.remote.UpdateTunnelState(connection.TunnelID, "CLOSED"); err != nil && !isNotFoundError(err) {
				a.logErrorf("close removed connection tunnel %s failed: %v", connection.TunnelID, err)
			}
		}
		attempt, ok := a.directAttempts[key]
		if !ok {
			continue
		}
		if attempt.DirectReady || strings.TrimSpace(attempt.TransportMode) != "" || strings.TrimSpace(attempt.TransportSessionID) != "" {
			a.dropTransportSessionLocked(connection.LocalPeerID, connection.RemotePeerID, attempt.TransportMode)
		}
		delete(a.directAttempts, key)
	}
}

func (a *Agent) replacementConnectionForRemovedLocked(removed ConnectionStatus, current []ConnectionStatus) *ConnectionStatus {
	var best *ConnectionStatus
	endpointCandidates := connectionStatusPointers(current)
	for idx := range current {
		candidate := &current[idx]
		if !strings.EqualFold(strings.TrimSpace(candidate.NetworkID), strings.TrimSpace(removed.NetworkID)) {
			continue
		}
		if !a.sameTransportLifecycleTargetWithEndpointCandidatesLocked(&removed, candidate, endpointCandidates) {
			continue
		}
		if best == nil || a.betterTransportLifecycleConnectionLocked(candidate, best) {
			best = candidate
		}
	}
	return best
}

func (a *Agent) replacementConnectionForPeerRefreshLocked(networkID, localPeerID string, remotePeer controlclient.Peer, candidates []controlclient.SignalCandidate) *ConnectionStatus {
	networkID = strings.TrimSpace(networkID)
	if networkID == "" {
		return nil
	}
	target := controlclient.Peer{
		ID:        strings.TrimSpace(remotePeer.ID),
		NetworkID: networkID,
		UserID:    strings.TrimSpace(remotePeer.UserID),
		VirtualIP: strings.TrimSpace(remotePeer.VirtualIP),
	}
	if strings.TrimSpace(target.ID) == "" {
		return nil
	}
	endpointContinuityKey := peerRefreshEndpointContinuityKey(remotePeer, candidates)
	var best *ConnectionStatus
	matchedByEndpoint := false
	for idx := range a.connections {
		candidate := &a.connections[idx]
		if !strings.EqualFold(strings.TrimSpace(candidate.NetworkID), networkID) {
			continue
		}
		candidateTarget := controlclient.Peer{
			ID:        strings.TrimSpace(candidate.RemotePeerID),
			NetworkID: networkID,
			UserID:    strings.TrimSpace(firstNonEmptyString(candidate.RemoteUserID, a.peerUserIDInNetworkUnlocked(candidate.NetworkID, candidate.RemotePeerID))),
			VirtualIP: strings.TrimSpace(a.connectionRemoteVirtualIPUnlocked(candidate)),
		}
		switch {
		case sameOverlayPeerTarget(target, candidateTarget):
		case endpointContinuityKey != "" && peerRefreshEndpointContinuityMatch(endpointContinuityKey, candidate):
			if matchedByEndpoint && best != nil && !a.sameTransportRoutingTargetLocked(best, candidate) {
				return nil
			}
			matchedByEndpoint = true
		default:
			continue
		}
		if best == nil || a.betterTransportLifecycleConnectionLocked(candidate, best) {
			best = candidate
		}
	}
	return best
}

func peerRefreshEndpointContinuityKey(remotePeer controlclient.Peer, candidates []controlclient.SignalCandidate) string {
	if strings.TrimSpace(remotePeer.UserID) != "" || strings.TrimSpace(remotePeer.VirtualIP) != "" {
		return ""
	}
	return normalizedEndpointContinuityKey(strings.TrimSpace(remotePeer.Endpoint), candidateAddresses(candidates))
}

func peerRefreshEndpointContinuityMatch(expectedKey string, candidate *ConnectionStatus) bool {
	if candidate == nil {
		return false
	}
	if expectedKey == "" {
		return false
	}
	return endpointContinuityPartsOverlap(
		endpointContinuityPartsFromKey(expectedKey),
		endpointContinuityParts(strings.TrimSpace(candidate.RemoteEndpoint), candidate.RemoteCandidates),
	)
}

func normalizedEndpointContinuityKey(endpoint string, candidates []string) string {
	parts := endpointContinuityParts(endpoint, candidates)
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "|")
}

func endpointContinuityParts(endpoint string, candidates []string) []string {
	parts := make([]string, 0, len(candidates)+1)
	seen := map[string]struct{}{}
	appendPart := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		parts = append(parts, value)
	}
	appendPart(endpoint)
	for _, candidate := range candidates {
		appendPart(candidate)
	}
	if len(parts) == 0 {
		return nil
	}
	sort.Strings(parts)
	return parts
}

func endpointContinuityPartsFromKey(key string) []string {
	if strings.TrimSpace(key) == "" {
		return nil
	}
	return endpointContinuityParts("", strings.Split(key, "|"))
}

func endpointContinuityPartsOverlap(left, right []string) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(left))
	for _, value := range left {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		seen[value] = struct{}{}
	}
	for _, value := range right {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			return true
		}
	}
	return false
}

func mergeEndpointContinuityParts(parts ...[]string) []string {
	merged := make([]string, 0)
	seen := map[string]struct{}{}
	for _, group := range parts {
		for _, value := range group {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			merged = append(merged, value)
		}
	}
	if len(merged) == 0 {
		return nil
	}
	sort.Strings(merged)
	return merged
}

func adoptRemovedConnectionContinuity(removed ConnectionStatus, replacement *ConnectionStatus) {
	if replacement == nil {
		return
	}
	if strings.TrimSpace(replacement.RemoteUserID) == "" {
		replacement.RemoteUserID = strings.TrimSpace(removed.RemoteUserID)
	}
	if strings.TrimSpace(replacement.RemoteVirtualIP) == "" {
		replacement.RemoteVirtualIP = strings.TrimSpace(removed.RemoteVirtualIP)
	}
	if strings.TrimSpace(replacement.TunnelID) == "" {
		replacement.TunnelID = strings.TrimSpace(removed.TunnelID)
	}
	if strings.TrimSpace(replacement.TunnelMode) == "" {
		replacement.TunnelMode = strings.TrimSpace(removed.TunnelMode)
	}
	if strings.TrimSpace(replacement.TunnelState) == "" {
		replacement.TunnelState = strings.TrimSpace(removed.TunnelState)
	}
}

func (a *Agent) applyAttemptStateToConnection(connection *ConnectionStatus, attempt DirectAttemptState) {
	if connection == nil {
		return
	}
	connection.SelectedCandidate = attempt.SelectedCandidate
	connection.AttemptCount = attempt.AttemptCount
	connection.LastAttemptUnix = unixOrZero(attempt.LastAttemptAt)
	connection.NextRetryUnix = unixOrZero(a.nextTransportTransitionAtLocked(attempt))
	connection.LastError = attempt.LastError
	connection.TransportReady = attempt.DirectReady
	connection.TransportMode = attempt.TransportMode
	connection.TransportSessionID = attempt.TransportSessionID
	connection.TransportEstablishedUnix = unixOrZero(attempt.TransportStartedAt)
	connection.TransportPacketCount = attempt.TransportPacketCount
	connection.TransportRekeyDueUnix = unixOrZero(a.transportRekeyDueLocked(attempt))
	connection.LastTransportUnix = unixOrZero(attempt.LastTransportAt)
	connection.LastKeepaliveUnix = unixOrZero(attempt.LastKeepaliveAt)
	connection.LastRTTMillis = durationMillis(attempt.LastRTT)
	connection.AverageRTTMillis = durationMillis(attempt.AverageRTT)
	connection.ConsecutiveLosses = attempt.ConsecutiveLosses
	connection.GroupTrafficPacketCopies = attempt.GroupTrafficPacketCopies
	connection.GroupBroadcastCopies = attempt.GroupBroadcastCopies
	connection.GroupMulticastCopies = attempt.GroupMulticastCopies
	connection.LastGroupTrafficUnix = unixOrZero(attempt.LastGroupTrafficAt)
}

func (a *Agent) syncAttemptEndpointsLocked(connection *ConnectionStatus, attempt *DirectAttemptState, managedPeers []ManagedPeerState) {
	if connection == nil || attempt == nil {
		return
	}
	localPeer := managedPeerByNetwork(managedPeers, connection.NetworkID)
	localEndpoint := strings.TrimSpace(localPeer.Endpoint)
	remoteKey := remoteEndpointKey(*connection)
	if attempt.LocalEndpoint == "" && localEndpoint != "" {
		attempt.LocalEndpoint = localEndpoint
	}
	if attempt.RemoteEndpointKey == "" && remoteKey != "" {
		attempt.RemoteEndpointKey = remoteKey
	}
	if localEndpoint != "" && !strings.EqualFold(strings.TrimSpace(attempt.LocalEndpoint), localEndpoint) {
		a.resetAttemptForEndpointChangeLocked(connection, attempt, localEndpoint, remoteKey, "local endpoint changed")
		return
	}
	if remoteKey != "" && attempt.RemoteEndpointKey != "" && attempt.RemoteEndpointKey != remoteKey {
		a.resetAttemptForEndpointChangeLocked(connection, attempt, localEndpoint, remoteKey, "remote endpoint changed")
		return
	}
	attempt.LocalEndpoint = localEndpoint
	attempt.RemoteEndpointKey = remoteKey
}

func (a *Agent) resetAttemptForEndpointChangeLocked(connection *ConnectionStatus, attempt *DirectAttemptState, localEndpoint, remoteKey, reason string) {
	if connection == nil || attempt == nil {
		return
	}
	if strings.EqualFold(strings.TrimSpace(attempt.TransportMode), "DIRECT") && strings.TrimSpace(attempt.TransportSessionID) != "" {
		a.dropTransportSessionLocked(connection.LocalPeerID, connection.RemotePeerID, attempt.TransportMode)
	}
	attempt.AttemptCount = 0
	attempt.LastAttemptAt = time.Time{}
	attempt.NextAttemptAt = time.Time{}
	attempt.SelectedCandidate = ""
	attempt.LastTransportAt = time.Time{}
	attempt.LastKeepaliveAt = time.Time{}
	attempt.LastRTT = 0
	attempt.AverageRTT = 0
	attempt.ConsecutiveLosses = 0
	attempt.LocalEndpoint = localEndpoint
	attempt.RemoteEndpointKey = remoteKey
	if strings.EqualFold(strings.TrimSpace(attempt.TransportMode), "RELAY") && attempt.DirectReady {
		attempt.LastError = reason + "; retrying direct path"
		attempt.NextFailbackAt = time.Time{}
	} else {
		attempt.DirectReady = false
		attempt.TransportMode = ""
		attempt.TransportSessionID = ""
		attempt.TransportStartedAt = time.Time{}
		attempt.TransportPacketCount = 0
		attempt.NextFailbackAt = time.Time{}
		attempt.LastError = reason + "; renegotiating"
	}
}

func (a *Agent) resetAttemptForReachabilityLossLocked(connection *ConnectionStatus, attempt *DirectAttemptState, reason string) {
	if connection == nil || attempt == nil {
		return
	}
	if attempt.DirectReady || strings.TrimSpace(attempt.TransportMode) != "" || strings.TrimSpace(attempt.TransportSessionID) != "" {
		a.dropTransportSessionLocked(connection.LocalPeerID, connection.RemotePeerID, attempt.TransportMode)
	}
	attempt.DirectReady = false
	attempt.TransportMode = ""
	attempt.TransportSessionID = ""
	attempt.TransportStartedAt = time.Time{}
	attempt.TransportPacketCount = 0
	attempt.LastTransportAt = time.Time{}
	attempt.LastKeepaliveAt = time.Time{}
	attempt.LastRTT = 0
	attempt.AverageRTT = 0
	attempt.ConsecutiveLosses = 0
	attempt.SelectedCandidate = ""
	attempt.AttemptCount = 0
	attempt.LastAttemptAt = time.Time{}
	attempt.NextAttemptAt = time.Time{}
	attempt.NextFailbackAt = time.Time{}
	attempt.LastError = reason
}

func (a *Agent) shouldRekeyTransportLocked(attempt DirectAttemptState, now time.Time) bool {
	if !attempt.DirectReady || attempt.TransportSessionID == "" || strings.TrimSpace(attempt.TransportMode) == "" {
		return false
	}
	if !attempt.TransportStartedAt.IsZero() && now.Sub(attempt.TransportStartedAt) >= a.runtime.TransportSessionTTL {
		return true
	}
	return a.runtime.TransportRekeyAfter > 0 && attempt.TransportPacketCount >= a.runtime.TransportRekeyAfter
}

func (a *Agent) transportRekeyDueLocked(attempt DirectAttemptState) time.Time {
	if attempt.TransportStartedAt.IsZero() || a.runtime.TransportSessionTTL <= 0 {
		return time.Time{}
	}
	return attempt.TransportStartedAt.Add(a.runtime.TransportSessionTTL)
}

func (a *Agent) nextTransportTransitionAtLocked(attempt DirectAttemptState) time.Time {
	if attempt.DirectReady && strings.EqualFold(attempt.TransportMode, "RELAY") {
		return attempt.NextFailbackAt
	}
	return attempt.NextAttemptAt
}

func (a *Agent) forwardTransportPacketsLocked(now time.Time) error {
	packetIO, ok := a.adapterManager.(virtualadapter.PacketIO)
	if !ok || packetIO == nil || a.currentUser == nil || a.deviceState == nil {
		return nil
	}

	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return err
	}
	managedPeers := state.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	managedPeers = a.dedupeManagedPeersForRuntime(managedPeers)
	if len(managedPeers) == 0 {
		return nil
	}

	// Wintun reads are destructive. Obtain the policy before dequeuing either
	// direction so an HTTP/decode failure cannot silently discard an adapter batch.
	networksByID, err := a.forwardingNetworksLocked()
	if err != nil {
		return err
	}
	eligible := make([]ManagedPeerState, 0, len(managedPeers))
	for _, peer := range managedPeers {
		if _, present := networksByID[peer.NetworkID]; present {
			eligible = append(eligible, peer)
		}
	}
	managedPeers = eligible
	if len(managedPeers) == 0 {
		return nil
	}
	routing := a.publishForwardingRoutesLocked(networksByID)
	if routing == nil {
		return nil
	}
	var outbound []virtualadapter.Packet
	if a.outboundPump == nil {
		outbound, err = packetIO.ReadPackets(32)
		if err != nil {
			return err
		}
	}
	for _, packet := range outbound {
		sourceIP, destinationIP, parseErr := ipv4PacketEndpoints(packet.Data)
		if parseErr != nil {
			continue
		}
		managedPeer := managedPeerForSourceIP(managedPeers, sourceIP)
		groupKind := ""
		groupPolicy := ""
		if managedPeer.PeerID != "" {
			groupKind = groupTrafficKind(managedPeer.OverlayCIDR, destinationIP)
			groupPolicy = networkGroupTrafficPolicyOrDefault(networksByID[managedPeer.NetworkID])
		}
		connections := routing.routes(sourceIP, destinationIP)
		if len(connections) == 0 {
			if managedPeer.PeerID != "" && groupKind != "" && strings.EqualFold(groupPolicy, "BLOCKED") {
				a.recordBlockedGroupTrafficLocked(managedPeer.NetworkID, groupPolicy, groupKind, now)
			}
			continue
		}
		successCopies := 0
		for _, route := range connections {
			connection := a.connectionByPeersLocked(route.NetworkID, route.LocalPeerID, route.RemotePeerID)
			if connection == nil || !connection.TransportReady {
				continue
			}
			key := connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)
			attempt := a.directAttempts[key]
			if err := a.sendTransportPacketLocked(connection, &attempt, packet.Data, now); err != nil {
				attempt.LastError = err.Error()
				a.directAttempts[key] = attempt
				a.applyAttemptStateToConnection(connection, attempt)
				continue
			}
			a.directAttempts[key] = attempt
			a.applyAttemptStateToConnection(connection, attempt)
			connection.LastTransportUnix = now.Unix()
			a.bumpTransportPacketCountLocked(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID, 1, now)
			if groupKind != "" {
				a.bumpConnectionGroupTrafficLocked(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID, groupKind, now)
				successCopies++
			}
		}
		if managedPeer.PeerID != "" && groupKind != "" && successCopies > 0 {
			a.recordFloodGroupTrafficLocked(managedPeer.NetworkID, groupPolicy, groupKind, successCopies, now)
		}
	}

	if a.inboundPump != nil {
		return nil // The independent pump is the sole inbound consumer.
	}
	inbound := make([]virtualadapter.Packet, 0)
	for _, managedPeer := range managedPeers {
		inbound = a.collectInboundTransportPacketsLocked(inbound, managedPeer, managedPeers, networksByID, now)
	}
	if len(inbound) == 0 {
		return nil
	}
	return packetIO.WritePackets(inbound)
}

func managedPeerForSourceIP(managedPeers []ManagedPeerState, sourceIP string) ManagedPeerState {
	for _, peer := range managedPeers {
		if strings.EqualFold(strings.TrimSpace(peer.VirtualIP), strings.TrimSpace(sourceIP)) {
			return peer
		}
	}
	return ManagedPeerState{}
}

func (a *Agent) recordBlockedGroupTrafficLocked(networkID, policy, kind string, now time.Time) {
	if strings.TrimSpace(networkID) == "" || strings.TrimSpace(kind) == "" {
		return
	}
	previousPolicy := a.groupTrafficDiagnostics[networkID].Policy
	diagnostics := a.ensureGroupTrafficDiagnosticsLocked(networkID, policy)
	diagnostics.BlockedPacketCount++
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "broadcast":
		diagnostics.BroadcastPacketCount++
	case "multicast":
		diagnostics.MulticastPacketCount++
	}
	if now.Unix() >= diagnostics.LastPacketUnix {
		diagnostics.LastPacketUnix = now.Unix()
		diagnostics.LastAction = "BLOCKED"
	} else {
		diagnostics.Policy = previousPolicy
	}
	a.groupTrafficDiagnostics[networkID] = diagnostics
}

func (a *Agent) recordFloodGroupTrafficLocked(networkID, policy, kind string, fanoutCopies int, now time.Time) {
	if strings.TrimSpace(networkID) == "" || strings.TrimSpace(kind) == "" || fanoutCopies <= 0 {
		return
	}
	diagnostics := a.ensureGroupTrafficDiagnosticsLocked(networkID, policy)
	diagnostics.FloodPacketCount++
	diagnostics.FanoutCopyCount += fanoutCopies
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "broadcast":
		diagnostics.BroadcastPacketCount++
	case "multicast":
		diagnostics.MulticastPacketCount++
	}
	diagnostics.LastPacketUnix = now.Unix()
	diagnostics.LastAction = "FLOOD"
	a.groupTrafficDiagnostics[networkID] = diagnostics
}

func (a *Agent) ensureGroupTrafficDiagnosticsLocked(networkID, policy string) GroupTrafficDiagnostics {
	if a.groupTrafficDiagnostics == nil {
		a.groupTrafficDiagnostics = map[string]GroupTrafficDiagnostics{}
	}
	diagnostics := a.groupTrafficDiagnostics[networkID]
	diagnostics.NetworkID = strings.TrimSpace(networkID)
	diagnostics.Policy = firstNonEmptyString(strings.ToUpper(strings.TrimSpace(policy)), "BLOCKED")
	return diagnostics
}

func (a *Agent) bumpConnectionGroupTrafficLocked(networkID, localPeerID, remotePeerID, kind string, now time.Time) {
	key := connectionKey(networkID, localPeerID, remotePeerID)
	attempt, ok := a.directAttempts[key]
	if !ok {
		return
	}
	attempt.GroupTrafficPacketCopies++
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "broadcast":
		attempt.GroupBroadcastCopies++
	case "multicast":
		attempt.GroupMulticastCopies++
	}
	attempt.LastGroupTrafficAt = now
	a.directAttempts[key] = attempt
}

func (a *Agent) sendTransportPacketLocked(connection *ConnectionStatus, attempt *DirectAttemptState, payload []byte, now time.Time) error {
	if connection == nil {
		return fmt.Errorf("connection is required")
	}
	manager := a.transportManagerForConnectionLocked(*connection)
	if manager == nil {
		return fmt.Errorf("transport manager is unavailable")
	}
	if err := a.sendPacketOnCurrentSessionLocked(connection, manager, payload); err != nil {
		connection.LastError = err.Error()
		if attempt == nil {
			return err
		}
		if strings.EqualFold(attempt.TransportMode, "DIRECT") &&
			isImmediateTransportSessionLoss(attempt.TransportMode, err) {
			a.dropTransportSessionLocked(connection.LocalPeerID, connection.RemotePeerID, attempt.TransportMode)
			a.clearTransportAttemptLocked(attempt)
			if isDirectListenerUnavailable(err) {
				if rebindErr := a.reconcileManagedRuntimeLocked(); rebindErr != nil {
					attempt.LastError = rebindErr.Error()
				}
			}
			if len(connection.RemoteCandidates) > 0 && a.directManager != nil {
				if reestablishErr := a.tryDirectTransportLocked(connection, attempt, now, false); reestablishErr == nil {
					a.applyAttemptStateToConnection(connection, *attempt)
					manager = a.transportManagerForConnectionLocked(*connection)
					if manager == nil {
						return fmt.Errorf("transport manager is unavailable")
					}
					if retryErr := a.sendPacketOnCurrentSessionLocked(connection, manager, payload); retryErr != nil {
						connection.LastError = retryErr.Error()
						return retryErr
					}
					connection.LastError = ""
					return nil
				} else {
					attempt.LastError = reestablishErr.Error()
				}
			}
			if a.canUseRelayLocked(connection) {
				if fallbackErr := a.establishRelayTransportLocked(connection, attempt, now, ""); fallbackErr != nil {
					return fallbackErr
				}
				a.applyAttemptStateToConnection(connection, *attempt)
				manager = a.transportManagerForConnectionLocked(*connection)
				if manager == nil {
					return fmt.Errorf("transport manager is unavailable")
				}
				if retryErr := a.sendPacketOnCurrentSessionLocked(connection, manager, payload); retryErr != nil {
					connection.LastError = retryErr.Error()
					return retryErr
				}
				connection.LastError = ""
				return nil
			}
			return err
		}
		if strings.EqualFold(attempt.TransportMode, "RELAY") {
			if failoverErr := a.failoverRelayTransportLocked(connection, attempt, now, err); failoverErr != nil {
				return failoverErr
			}
			a.applyAttemptStateToConnection(connection, *attempt)
			manager = a.transportManagerForConnectionLocked(*connection)
			if manager == nil {
				return fmt.Errorf("transport manager is unavailable")
			}
			if retryErr := a.sendPacketOnCurrentSessionLocked(connection, manager, payload); retryErr != nil {
				connection.LastError = retryErr.Error()
				return retryErr
			}
			connection.LastError = ""
			return nil
		}
		return err
	}
	connection.LastError = ""
	return nil
}

func (a *Agent) clearTransportAttemptLocked(attempt *DirectAttemptState) {
	if attempt == nil {
		return
	}
	attempt.DirectReady = false
	attempt.TransportMode = ""
	attempt.TransportSessionID = ""
	attempt.TransportStartedAt = time.Time{}
	attempt.TransportPacketCount = 0
	attempt.LastTransportAt = time.Time{}
	attempt.LastKeepaliveAt = time.Time{}
	attempt.LastRTT = 0
	attempt.AverageRTT = 0
	attempt.ConsecutiveLosses = 0
	attempt.AttemptCount = 0
	attempt.LastAttemptAt = time.Time{}
	attempt.NextAttemptAt = time.Time{}
	attempt.NextFailbackAt = time.Time{}
	attempt.SelectedCandidate = ""
}

func isDirectListenerUnavailable(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(err.Error())), "no direct-probe listener for peer")
}

func (a *Agent) maintainTransportQualityLocked(now time.Time) error {
	if a.currentUser == nil || a.deviceState == nil {
		return nil
	}
	for _, connection := range a.preferredTransportLifecycleConnectionsLocked() {
		if !connection.TransportReady || strings.TrimSpace(connection.TransportSessionID) == "" {
			continue
		}
		key := connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)
		attempt := a.directAttempts[key]
		if !a.shouldSendKeepaliveLocked(attempt, now) {
			a.applyAttemptStateToConnection(connection, attempt)
			continue
		}
		manager := a.transportManagerForConnectionLocked(*connection)
		if manager == nil {
			continue
		}
		startedAt := time.Now()
		var ackPayload []byte
		err := a.outboundControlIOLocked(func() error {
			var exchangeErr error
			ackPayload, exchangeErr = manager.Exchange(connection.LocalPeerID, connection.RemotePeerID, []byte("ole-keepalive"), a.runtime.DirectProbeTimeout)
			return exchangeErr
		})
		// Packets continue during Exchange. Reload after merging their reports so
		// the pre-Exchange copy cannot overwrite packet/group counters or activity.
		a.mergeInboundReportsLocked()
		a.mergeOutboundReportsLocked(false)
		attempt = a.directAttempts[key]
		if err != nil {
			attempt.ConsecutiveLosses++
			attempt.LastError = "transport keepalive failed: " + err.Error()
			attempt.LastKeepaliveAt = now
			if strings.EqualFold(attempt.TransportMode, "DIRECT") &&
				isImmediateTransportSessionLoss(attempt.TransportMode, err) {
				a.dropTransportSessionLocked(connection.LocalPeerID, connection.RemotePeerID, attempt.TransportMode)
				a.clearTransportAttemptLocked(&attempt)
				if isDirectListenerUnavailable(err) {
					if rebindErr := a.reconcileManagedRuntimeLocked(); rebindErr != nil {
						attempt.LastError = "transport keepalive failed: " + rebindErr.Error()
					}
				}
				if len(connection.RemoteCandidates) > 0 && a.directManager != nil {
					if reestablishErr := a.tryDirectTransportLocked(connection, &attempt, now, false); reestablishErr == nil {
						a.directAttempts[key] = attempt
						a.applyAttemptStateToConnection(connection, attempt)
						continue
					} else {
						attempt.LastError = "transport keepalive failed: " + reestablishErr.Error()
					}
				}
				if a.canUseRelayLocked(connection) {
					if fallbackErr := a.establishRelayTransportLocked(connection, &attempt, now, ""); fallbackErr == nil {
						a.directAttempts[key] = attempt
						a.applyAttemptStateToConnection(connection, attempt)
						continue
					} else {
						attempt.LastError = "transport keepalive failed: " + fallbackErr.Error()
					}
				}
				a.directAttempts[key] = attempt
				a.applyAttemptStateToConnection(connection, attempt)
				continue
			}
			if strings.EqualFold(attempt.TransportMode, "RELAY") &&
				isImmediateTransportSessionLoss(attempt.TransportMode, err) {
				if failoverErr := a.failoverRelayTransportLocked(connection, &attempt, now, err); failoverErr == nil {
					a.directAttempts[key] = attempt
					a.applyAttemptStateToConnection(connection, attempt)
					continue
				} else {
					attempt.LastError = "transport keepalive failed: " + failoverErr.Error()
				}
			}
			if attempt.ConsecutiveLosses >= a.runtime.TransportLossLimit {
				if strings.EqualFold(attempt.TransportMode, "RELAY") {
					if failoverErr := a.failoverRelayTransportLocked(connection, &attempt, now, err); failoverErr == nil {
						a.directAttempts[key] = attempt
						a.applyAttemptStateToConnection(connection, attempt)
						continue
					}
				}
				a.dropTransportSessionLocked(connection.LocalPeerID, connection.RemotePeerID, attempt.TransportMode)
				attempt.DirectReady = false
				attempt.TransportMode = ""
				attempt.TransportSessionID = ""
				attempt.TransportStartedAt = time.Time{}
				attempt.TransportPacketCount = 0
				attempt.LastTransportAt = time.Time{}
				attempt.NextFailbackAt = time.Time{}
				if strings.EqualFold(connection.Reachability, "DIRECT") {
					attempt.NextAttemptAt = time.Time{}
				} else {
					attempt.NextAttemptAt = time.Time{}
				}
			}
			a.directAttempts[key] = attempt
			a.applyAttemptStateToConnection(connection, attempt)
			continue
		}
		if string(ackPayload) != "ack:ole-keepalive" {
			attempt.ConsecutiveLosses++
			attempt.LastError = fmt.Sprintf("unexpected keepalive ack %q", string(ackPayload))
			attempt.LastKeepaliveAt = now
			a.directAttempts[key] = attempt
			a.applyAttemptStateToConnection(connection, attempt)
			continue
		}
		rtt := time.Since(startedAt)
		if rtt <= 0 {
			rtt = time.Millisecond
		}
		attempt.LastKeepaliveAt = now
		if now.After(attempt.LastTransportAt) {
			attempt.LastTransportAt = now
		}
		attempt.LastRTT = rtt
		if attempt.AverageRTT <= 0 {
			attempt.AverageRTT = rtt
		} else {
			attempt.AverageRTT = ((attempt.AverageRTT * 3) + rtt) / 4
		}
		attempt.TransportPacketCount++
		attempt.ConsecutiveLosses = 0
		attempt.LastError = ""
		a.directAttempts[key] = attempt
		a.applyAttemptStateToConnection(connection, attempt)
	}
	return nil
}

func isImmediateTransportSessionLoss(transportMode string, err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	switch strings.ToUpper(strings.TrimSpace(transportMode)) {
	case "DIRECT":
		return strings.Contains(message, "no encrypted session for peer") ||
			strings.Contains(message, "no authenticated session for peer") ||
			strings.Contains(message, "no direct-probe listener for peer")
	case "RELAY":
		return strings.Contains(message, "no relay session for peer") ||
			strings.Contains(message, "no authenticated session for peer") ||
			strings.Contains(message, "no relay listener for peer")
	default:
		return false
	}
}

func (a *Agent) shouldSendKeepaliveLocked(attempt DirectAttemptState, now time.Time) bool {
	if !attempt.DirectReady || a.runtime.TransportKeepalive <= 0 {
		return false
	}
	lastActivity := attempt.LastTransportAt
	if !attempt.LastKeepaliveAt.IsZero() && attempt.LastKeepaliveAt.After(lastActivity) {
		lastActivity = attempt.LastKeepaliveAt
	}
	return lastActivity.IsZero() || now.Sub(lastActivity) >= a.runtime.TransportKeepalive
}

func (a *Agent) bumpTransportPacketCountLocked(networkID, localPeerID, remotePeerID string, delta int, now time.Time) {
	key := connectionKey(networkID, localPeerID, remotePeerID)
	attempt := a.directAttempts[key]
	attempt.TransportPacketCount += delta
	if attempt.LastTransportAt.IsZero() || now.After(attempt.LastTransportAt) {
		attempt.LastTransportAt = now
	}
	a.directAttempts[key] = attempt
}

func (a *Agent) establishPreferredTransportLocked(connection *ConnectionStatus, attempt *DirectAttemptState, now time.Time) error {
	if connection == nil || attempt == nil {
		return nil
	}
	if len(connection.RemoteCandidates) > 0 && a.directManager != nil && attempt.AttemptCount < a.runtime.DirectMaxAttempts {
		probeErr := a.tryDirectTransportLocked(connection, attempt, now, true)
		if probeErr == nil {
			return nil
		}
		if attempt.AttemptCount < a.runtime.DirectMaxAttempts {
			return probeErr
		}
	}

	if a.canUseRelayLocked(connection) && a.relayManager != nil {
		if err := a.establishRelayTransportLocked(connection, attempt, now, ""); err == nil {
			return nil
		} else if len(connection.RemoteCandidates) == 0 {
			return err
		}
	}

	if len(connection.RemoteCandidates) == 0 {
		return fmt.Errorf("no remote candidates available")
	}
	return fmt.Errorf("direct path unavailable")
}

func (a *Agent) establishRelayTransportLocked(connection *ConnectionStatus, attempt *DirectAttemptState, now time.Time, failedAddress string) error {
	if connection == nil || attempt == nil || a.relayManager == nil {
		return fmt.Errorf("relay manager is unavailable")
	}
	wasRelay := strings.EqualFold(attempt.TransportMode, "RELAY")
	initialRelayAddress := a.resolveRelayServerAddressLocked()
	relayAddresses := a.relayOrderLocked(failedAddress)
	if len(relayAddresses) == 0 {
		return fmt.Errorf("no relay servers configured")
	}
	var lastErr error
	for _, relayAddress := range relayAddresses {
		if err := a.switchRelayServerLocked(relayAddress); err != nil {
			lastErr = err
			continue
		}
		session, err := a.relayManager.Establish(connection.LocalPeerID, connection.RemotePeerID, a.runtime.DirectProbeTimeout)
		if err != nil {
			lastErr = fmt.Errorf("relay %s establish failed: %w", relayAddress, err)
			continue
		}
		ackPayload, err := a.relayManager.Exchange(connection.LocalPeerID, connection.RemotePeerID, []byte("ole-handshake"), a.runtime.DirectProbeTimeout)
		if err != nil {
			lastErr = fmt.Errorf("relay %s handshake failed: %w", relayAddress, err)
			continue
		}
		if string(ackPayload) != "ack:ole-handshake" {
			lastErr = fmt.Errorf("relay %s returned unexpected handshake ack %q", relayAddress, string(ackPayload))
			continue
		}
		attempt.DirectReady = true
		attempt.TransportMode = "RELAY"
		attempt.LastError = ""
		attempt.NextAttemptAt = time.Time{}
		attempt.NextFailbackAt = time.Time{}
		attempt.SelectedCandidate = relayAddress
		attempt.TransportSessionID = session.SessionID
		attempt.TransportStartedAt = now
		attempt.TransportPacketCount = 0
		attempt.LastTransportAt = now
		attempt.AttemptCount = 0
		attempt.ConsecutiveLosses = 0
		if len(connection.RemoteCandidates) > 0 {
			attempt.NextFailbackAt = now.Add(a.runtime.RelayFailbackPeriod)
		}
		if initialRelayAddress != "" && !strings.EqualFold(initialRelayAddress, relayAddress) {
			a.relayFailoverCount++
			a.logInfof("relay failover switched from %s to %s", initialRelayAddress, relayAddress)
		}
		connection.Reachability = "RELAY"
		connection.State = "CONNECTED"
		connection.LastError = ""
		if !wasRelay {
			a.recordRelayFallbackLocked(now)
		}
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("relay path unavailable")
	}
	return lastErr
}

func (a *Agent) failoverRelayTransportLocked(connection *ConnectionStatus, attempt *DirectAttemptState, now time.Time, cause error) error {
	if connection == nil || attempt == nil {
		if cause != nil {
			return cause
		}
		return fmt.Errorf("relay failover unavailable")
	}
	failedAddress := firstNonEmptyString(attempt.SelectedCandidate, a.resolveRelayServerAddressLocked())
	a.dropTransportSessionLocked(connection.LocalPeerID, connection.RemotePeerID, "RELAY")
	if err := a.establishRelayTransportLocked(connection, attempt, now, failedAddress); err != nil {
		if cause != nil {
			return fmt.Errorf("%v; relay failover: %w", cause, err)
		}
		return err
	}
	return nil
}

func (a *Agent) relayOrderLocked(failedAddress string) []string {
	addresses := a.resolveRelayServerAddressesLocked()
	if len(addresses) == 0 {
		return nil
	}
	preferred := a.resolveRelayServerAddressLocked()
	if strings.TrimSpace(failedAddress) != "" {
		preferred = ""
	}
	out := make([]string, 0, len(addresses))
	if preferred != "" && containsFold(addresses, preferred) && !strings.EqualFold(preferred, failedAddress) {
		out = append(out, preferred)
	}
	for _, address := range addresses {
		if containsFold(out, address) || strings.EqualFold(address, failedAddress) {
			continue
		}
		out = append(out, address)
	}
	return out
}

func (a *Agent) switchRelayServerLocked(relayAddress string) error {
	relayAddress = strings.TrimSpace(relayAddress)
	if relayAddress == "" {
		a.activeRelayServer = ""
		return a.reconcileRelayBindingsLocked()
	}
	if strings.EqualFold(a.activeRelayServer, relayAddress) {
		return nil
	}
	a.activeRelayServer = relayAddress
	return a.reconcileRelayBindingsLocked()
}

func (a *Agent) recordDirectAttemptLocked(now time.Time) {
	a.directMetrics.AttemptCount++
	a.directMetrics.LastAttemptUnix = now.Unix()
	a.refreshDirectSuccessRateLocked()
}

func (a *Agent) recordDirectSuccessLocked(now time.Time, candidate string, failback bool) {
	a.directMetrics.SuccessCount++
	a.directMetrics.LastSuccessUnix = now.Unix()
	a.directMetrics.LastSuccessCandidate = strings.TrimSpace(candidate)
	if failback {
		a.directMetrics.FailbackSuccessCount++
		a.directMetrics.LastFailbackUnix = now.Unix()
	}
	a.refreshDirectSuccessRateLocked()
}

func (a *Agent) recordDirectFailureLocked(now time.Time) {
	a.directMetrics.FailureCount++
	a.directMetrics.LastFailureUnix = now.Unix()
	a.refreshDirectSuccessRateLocked()
}

func (a *Agent) recordRelayFallbackLocked(now time.Time) {
	a.directMetrics.RelayFallbackCount++
	a.directMetrics.LastFallbackUnix = now.Unix()
}

func (a *Agent) refreshDirectSuccessRateLocked() {
	if a.directMetrics.AttemptCount <= 0 {
		a.directMetrics.SuccessRatePct = 0
		return
	}
	a.directMetrics.SuccessRatePct = (100 * a.directMetrics.SuccessCount) / a.directMetrics.AttemptCount
}

func (a *Agent) tryDirectTransportLocked(connection *ConnectionStatus, attempt *DirectAttemptState, now time.Time, countAttempt bool) error {
	return a.recoveryDirectIOLocked(connection, func() error { return a.tryDirectTransportSessionLocked(connection, attempt, now, countAttempt) })
}

func (a *Agent) tryDirectTransportSessionLocked(connection *ConnectionStatus, attempt *DirectAttemptState, now time.Time, countAttempt bool) error {
	if connection == nil || attempt == nil {
		return nil
	}
	if a.directManager == nil {
		return fmt.Errorf("direct manager is unavailable")
	}
	if len(connection.RemoteCandidates) == 0 {
		return fmt.Errorf("no remote candidates available")
	}
	result, probeErr := a.directManager.Attempt(connection.LocalPeerID, connection.RemotePeerID, connection.RemoteCandidates, a.runtime.DirectProbeTimeout)
	attempt.LastAttemptAt = now
	a.lastDirectProbeAt = now
	if countAttempt {
		attempt.AttemptCount++
	}
	failback := !countAttempt && strings.EqualFold(attempt.TransportMode, "RELAY")
	a.recordDirectAttemptLocked(now)
	if probeErr != nil {
		a.recordDirectFailureLocked(now)
		return probeErr
	}
	session, transportErr := a.directManager.Establish(connection.LocalPeerID, connection.RemotePeerID, []string{result.RemoteAddress}, a.runtime.DirectProbeTimeout)
	if transportErr != nil {
		a.recordDirectFailureLocked(now)
		return transportErr
	}
	ackPayload, exchangeErr := a.directManager.Exchange(connection.LocalPeerID, connection.RemotePeerID, []byte("ole-handshake"), a.runtime.DirectProbeTimeout)
	if exchangeErr != nil {
		a.recordDirectFailureLocked(now)
		return exchangeErr
	}
	if string(ackPayload) != "ack:ole-handshake" {
		a.recordDirectFailureLocked(now)
		return fmt.Errorf("unexpected encrypted transport ack %q", string(ackPayload))
	}
	attempt.DirectReady = true
	attempt.TransportMode = "DIRECT"
	attempt.LastError = ""
	attempt.NextAttemptAt = time.Time{}
	attempt.NextFailbackAt = time.Time{}
	attempt.SelectedCandidate = result.RemoteAddress
	if strings.TrimSpace(session.RemoteAddress) != "" {
		attempt.SelectedCandidate = session.RemoteAddress
	}
	attempt.TransportSessionID = session.SessionID
	attempt.TransportStartedAt = now
	attempt.TransportPacketCount = 0
	attempt.LastTransportAt = now
	connection.Reachability = "DIRECT"
	connection.State = "CONNECTED"
	a.recordDirectSuccessLocked(now, attempt.SelectedCandidate, failback)
	return nil
}

func (a *Agent) shouldAttemptDirectFailbackLocked(connection ConnectionStatus, attempt DirectAttemptState, now time.Time) bool {
	if !attempt.DirectReady || !strings.EqualFold(attempt.TransportMode, "RELAY") {
		return false
	}
	if len(connection.RemoteCandidates) == 0 || a.directManager == nil {
		return false
	}
	return attempt.NextFailbackAt.IsZero() || !now.Before(attempt.NextFailbackAt)
}

func (a *Agent) promoteRelayConnectionToDirectLocked(connection *ConnectionStatus, attempt *DirectAttemptState, now time.Time) error {
	if connection == nil || attempt == nil {
		return nil
	}
	if !strings.EqualFold(attempt.TransportMode, "RELAY") {
		return nil
	}
	if err := a.tryDirectTransportLocked(connection, attempt, now, false); err != nil {
		return err
	}
	if a.relayManager != nil {
		a.relayManager.DropSession(connection.LocalPeerID, connection.RemotePeerID)
	}
	return nil
}

func (a *Agent) canUseRelayLocked(connection *ConnectionStatus) bool {
	if connection == nil || a.relayManager == nil {
		return false
	}
	return len(a.resolveRelayServerAddressesLocked()) > 0
}

func (a *Agent) dropTransportSessionLocked(localPeerID, remotePeerID, transportMode string) {
	switch strings.ToUpper(strings.TrimSpace(transportMode)) {
	case "RELAY":
		if a.relayManager != nil {
			a.relayManager.DropSession(localPeerID, remotePeerID)
		}
	default:
		if a.directManager != nil {
			a.directManager.DropSession(localPeerID, remotePeerID)
		}
	}
}

type packetTransportManager interface {
	SendPacket(localPeerID, remotePeerID string, payload []byte) error
	DrainInbound(localPeerID string, limit int) []relaytransport.Packet
}

func (a *Agent) transportManagerForConnectionLocked(connection ConnectionStatus) transportManagerForPackets {
	switch strings.ToUpper(strings.TrimSpace(connection.TransportMode)) {
	case "RELAY":
		if a.relayManager == nil {
			return nil
		}
		return relayPacketAdapter{manager: a.relayManager}
	default:
		if a.directManager == nil {
			return nil
		}
		return directPacketAdapter{manager: a.directManager}
	}
}

type transportManagerForPackets interface {
	Exchange(localPeerID, remotePeerID string, payload []byte, timeout time.Duration) ([]byte, error)
	SendPacket(localPeerID, remotePeerID string, payload []byte) error
	DrainInbound(localPeerID string, limit int) []transportInboundPacket
}

type transportInboundPacket struct {
	RemotePeerID string
	Payload      []byte
}

type directPacketAdapter struct {
	manager directprobe.Manager
}

func (a directPacketAdapter) SendPacket(localPeerID, remotePeerID string, payload []byte) error {
	return a.manager.SendPacket(localPeerID, remotePeerID, payload)
}

func (a directPacketAdapter) Exchange(localPeerID, remotePeerID string, payload []byte, timeout time.Duration) ([]byte, error) {
	return a.manager.Exchange(localPeerID, remotePeerID, payload, timeout)
}

func (a directPacketAdapter) DrainInbound(localPeerID string, limit int) []transportInboundPacket {
	source := a.manager.DrainInbound(localPeerID, limit)
	out := make([]transportInboundPacket, 0, len(source))
	for _, packet := range source {
		out = append(out, transportInboundPacket{RemotePeerID: packet.RemotePeerID, Payload: append([]byte(nil), packet.Payload...)})
	}
	return out
}

type relayPacketAdapter struct {
	manager relaytransport.Manager
}

func (a relayPacketAdapter) SendPacket(localPeerID, remotePeerID string, payload []byte) error {
	return a.manager.SendPacket(localPeerID, remotePeerID, payload)
}

func (a relayPacketAdapter) Exchange(localPeerID, remotePeerID string, payload []byte, timeout time.Duration) ([]byte, error) {
	return a.manager.Exchange(localPeerID, remotePeerID, payload, timeout)
}

func (a relayPacketAdapter) DrainInbound(localPeerID string, limit int) []transportInboundPacket {
	source := a.manager.DrainInbound(localPeerID, limit)
	out := make([]transportInboundPacket, 0, len(source))
	for _, packet := range source {
		out = append(out, transportInboundPacket{RemotePeerID: packet.RemotePeerID, Payload: append([]byte(nil), packet.Payload...)})
	}
	return out
}

func (a *Agent) collectInboundTransportPacketsLocked(inbound []virtualadapter.Packet, managedPeer ManagedPeerState, managedPeers []ManagedPeerState, networksByID map[string]controlclient.Network, now time.Time) []virtualadapter.Packet {
	transports := []transportManagerForPackets{}
	if a.directManager != nil {
		transports = append(transports, directPacketAdapter{manager: a.directManager})
	}
	if a.relayManager != nil {
		transports = append(transports, relayPacketAdapter{manager: a.relayManager})
	}
	primaryFullTunnelClientNetworkID := a.primaryFullTunnelClientNetworkLocked(managedPeers, networksByID)
	drainLocalPeerIDs := a.inboundDrainLocalPeerIDsForManagedPeerLocked(managedPeer)
	for _, transport := range transports {
		for _, localPeerID := range drainLocalPeerIDs {
			packets := transport.DrainInbound(localPeerID, 32)
			for _, packet := range packets {
				accepted, connection := a.shouldAcceptInboundTransportPacketViaLocalPeerLocked(managedPeer, managedPeers, networksByID[managedPeer.NetworkID], primaryFullTunnelClientNetworkID, localPeerID, packet.RemotePeerID, packet.Payload, now)
				if !accepted {
					continue
				}
				inbound = append(inbound, virtualadapter.Packet{Data: append([]byte(nil), packet.Payload...)})
				if connection != nil {
					connection.LastTransportUnix = now.Unix()
					a.bumpTransportPacketCountLocked(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID, 1, now)
				}
			}
		}
	}
	return inbound
}

func (a *Agent) inboundDrainLocalPeerIDsForManagedPeerLocked(managedPeer ManagedPeerState) []string {
	return a.routingLocalPeerIDsForManagedPeerLocked(managedPeer)
}

func (a *Agent) routingLocalPeerIDsForManagedPeerLocked(managedPeer ManagedPeerState) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 2)
	appendPeerID := func(peerID string) {
		peerID = strings.TrimSpace(peerID)
		if peerID == "" {
			return
		}
		if _, ok := seen[peerID]; ok {
			return
		}
		seen[peerID] = struct{}{}
		out = append(out, peerID)
	}
	appendPeerID(managedPeer.PeerID)
	if a.currentUser == nil || a.deviceState == nil {
		return out
	}
	for _, candidate := range a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID) {
		if !strings.EqualFold(strings.TrimSpace(candidate.NetworkID), strings.TrimSpace(managedPeer.NetworkID)) {
			continue
		}
		appendPeerID(candidate.PeerID)
	}
	return out
}

func (a *Agent) managedPeerRoutingIncludesLocalPeerLocked(managedPeer ManagedPeerState, localPeerID string) bool {
	localPeerID = strings.TrimSpace(localPeerID)
	if localPeerID == "" {
		return false
	}
	for _, candidate := range a.routingLocalPeerIDsForManagedPeerLocked(managedPeer) {
		if strings.EqualFold(strings.TrimSpace(candidate), localPeerID) {
			return true
		}
	}
	return false
}

func (a *Agent) inboundTransportConnectionLocked(managedPeer ManagedPeerState, localPeerID, remotePeerID string) *ConnectionStatus {
	localPeerID = strings.TrimSpace(localPeerID)
	connection := a.connectionByPeersLocked(managedPeer.NetworkID, localPeerID, remotePeerID)
	if connection == nil {
		return nil
	}
	activeLocalPeerID := strings.TrimSpace(a.currentManagedPeerIDForNetworkLocked(managedPeer.NetworkID))
	if activeLocalPeerID == "" {
		activeLocalPeerID = strings.TrimSpace(managedPeer.PeerID)
	}
	if activeLocalPeerID == "" {
		return connection
	}
	preferred := a.preferredTransportConnectionForLocalPeerLocked(managedPeer.NetworkID, activeLocalPeerID, connection)
	if preferred == nil {
		if strings.EqualFold(localPeerID, activeLocalPeerID) {
			return connection
		}
		return nil
	}
	return preferred
}

func (a *Agent) shouldAcceptInboundTransportPacketViaLocalPeerLocked(managedPeer ManagedPeerState, managedPeers []ManagedPeerState, network controlclient.Network, primaryFullTunnelClientNetworkID, localPeerID, remotePeerID string, payload []byte, now time.Time) (bool, *ConnectionStatus) {
	accepted, connection, blocked := a.evaluateInboundTransportPacketViaLocalPeerLocked(managedPeer, managedPeers, network, primaryFullTunnelClientNetworkID, localPeerID, remotePeerID, payload)
	if blocked {
		_, destination, _ := ipv4PacketEndpoints(payload)
		a.recordBlockedGroupTrafficLocked(managedPeer.NetworkID, networkGroupTrafficPolicyOrDefault(network), groupTrafficKind(managedPeer.OverlayCIDR, destination), now)
	}
	return accepted, connection
}
func (a *Agent) evaluateInboundTransportPacketViaLocalPeerLocked(managedPeer ManagedPeerState, managedPeers []ManagedPeerState, network controlclient.Network, primaryFullTunnelClientNetworkID, localPeerID, remotePeerID string, payload []byte) (bool, *ConnectionStatus, bool) {
	exactConnection := a.connectionByPeersLocked(managedPeer.NetworkID, strings.TrimSpace(localPeerID), remotePeerID)
	connection := a.inboundTransportConnectionLocked(managedPeer, localPeerID, remotePeerID)
	if managedPeer.NetworkID == "" || len(payload) == 0 {
		return true, connection, false
	}
	sourceIP, destinationIP, err := ipv4PacketEndpoints(payload)
	if err != nil {
		return true, connection, false
	}
	if connection == nil {
		return false, nil, false
	}
	activeLocalPeerID := strings.TrimSpace(a.currentManagedPeerIDForNetworkLocked(managedPeer.NetworkID))
	if activeLocalPeerID == "" {
		activeLocalPeerID = strings.TrimSpace(managedPeer.PeerID)
	}
	if exactConnection != nil &&
		strings.EqualFold(strings.TrimSpace(localPeerID), activeLocalPeerID) &&
		!strings.EqualFold(strings.TrimSpace(connection.RemotePeerID), strings.TrimSpace(exactConnection.RemotePeerID)) {
		return false, nil, false
	}
	groupKind := groupTrafficKind(managedPeer.OverlayCIDR, destinationIP)
	if a.inboundTransportSourceMatchesConnectionLocked(connection, sourceIP) {
		if groupKind == "" {
			return strings.EqualFold(strings.TrimSpace(destinationIP), strings.TrimSpace(managedPeer.VirtualIP)), connection, false
		}
		groupPolicy := networkGroupTrafficPolicyOrDefault(network)
		if strings.EqualFold(groupPolicy, "FLOOD") {
			return true, connection, false
		}
		return false, nil, true
	}
	if groupKind != "" {
		return false, nil, false
	}
	return a.shouldAcceptInboundGatewayReturnPacketLocked(managedPeer, managedPeers, network, connection, primaryFullTunnelClientNetworkID, sourceIP, destinationIP), connection, false
}

func (a *Agent) shouldAcceptInboundTransportPacketLocked(managedPeer ManagedPeerState, managedPeers []ManagedPeerState, network controlclient.Network, primaryFullTunnelClientNetworkID, remotePeerID string, payload []byte, now time.Time) bool {
	accepted, _ := a.shouldAcceptInboundTransportPacketViaLocalPeerLocked(managedPeer, managedPeers, network, primaryFullTunnelClientNetworkID, managedPeer.PeerID, remotePeerID, payload, now)
	return accepted
}

func (a *Agent) preferredTransportConnectionLocked(networkID, localPeerID string, current *ConnectionStatus) *ConnectionStatus {
	if current == nil {
		return nil
	}
	best := current
	for idx := range a.connections {
		candidate := &a.connections[idx]
		if candidate.NetworkID != networkID || candidate.LocalPeerID != localPeerID || !candidate.TransportReady {
			continue
		}
		if !a.sameTransportRoutingTargetLocked(best, candidate) {
			continue
		}
		if betterGatewayConnection(candidate, "", best, "") {
			best = candidate
		}
	}
	return best
}

func (a *Agent) preferredTransportConnectionForLocalPeerLocked(networkID, localPeerID string, current *ConnectionStatus) *ConnectionStatus {
	if current == nil {
		return nil
	}
	localPeerID = strings.TrimSpace(localPeerID)
	if localPeerID == "" {
		return nil
	}
	var best *ConnectionStatus
	for idx := range a.connections {
		candidate := &a.connections[idx]
		if candidate.NetworkID != networkID || candidate.LocalPeerID != localPeerID || !candidate.TransportReady {
			continue
		}
		if !a.sameTransportRoutingTargetLocked(current, candidate) &&
			!a.transportRoutingMetadataGapReplacementMatchLocked(current, candidate) &&
			!a.transportRoutingEndpointContinuityReplacementMatchLocked(current, candidate) {
			continue
		}
		if best == nil || a.betterDestinationRoutingConnectionLocked(candidate, best) {
			best = candidate
		}
	}
	return best
}

func (a *Agent) inboundTransportSourceMatchesConnectionLocked(connection *ConnectionStatus, sourceIP string) bool {
	if connection == nil {
		return false
	}
	sourceIP = strings.TrimSpace(sourceIP)
	if sourceIP == "" {
		return false
	}
	if strings.EqualFold(sourceIP, a.connectionRemoteVirtualIPUnlocked(connection)) {
		return true
	}
	for idx := range a.connections {
		candidate := &a.connections[idx]
		if candidate == connection || !candidate.TransportReady {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(candidate.NetworkID), strings.TrimSpace(connection.NetworkID)) {
			continue
		}
		if !strings.EqualFold(sourceIP, a.connectionRemoteVirtualIPUnlocked(candidate)) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(candidate.LocalPeerID), strings.TrimSpace(connection.LocalPeerID)) &&
			!a.transportRoutingMetadataGapReplacementMatchLocked(candidate, connection) &&
			!a.transportRoutingEndpointContinuityReplacementMatchLocked(candidate, connection) {
			continue
		}
		if a.transportRoutingMetadataGapReplacementMatchLocked(candidate, connection) ||
			a.transportRoutingEndpointContinuityReplacementMatchLocked(candidate, connection) {
			return true
		}
	}
	return false
}

func (a *Agent) shouldAcceptInboundGatewayReturnPacketLocked(managedPeer ManagedPeerState, managedPeers []ManagedPeerState, network controlclient.Network, connection *ConnectionStatus, primaryFullTunnelClientNetworkID, sourceIP, destinationIP string) bool {
	if connection == nil {
		return false
	}
	if !strings.EqualFold(networkRoutingPolicyOrDefault(network), "FULL") {
		return false
	}
	if managedPeer.NetworkID != primaryFullTunnelClientNetworkID {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(destinationIP), strings.TrimSpace(managedPeer.VirtualIP)) {
		return false
	}
	gateway := a.gatewayConnectionForNetworkLocked(network, managedPeer.PeerID)
	if gateway == nil || !strings.EqualFold(strings.TrimSpace(gateway.RemotePeerID), strings.TrimSpace(connection.RemotePeerID)) {
		return false
	}
	if ipUsesLocalIPv4Semantics(sourceIP) || ipWithinAnyManagedOverlay(managedPeers, sourceIP) {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(sourceIP), a.connectionRemoteVirtualIPUnlocked(connection)) {
		return false
	}
	if groupTrafficKind(managedPeer.OverlayCIDR, destinationIP) != "" {
		return false
	}
	return true
}

func (a *Agent) connectionsForPacketLocked(managedPeers []ManagedPeerState, networksByID map[string]controlclient.Network, primaryFullTunnelClientNetworkID, sourceIP, destinationIP string) []*ConnectionStatus {
	overlayCandidates := make([]*ConnectionStatus, 0)
	for idx := range a.connections {
		connection := &a.connections[idx]
		managedPeer := managedPeerByNetwork(managedPeers, connection.NetworkID)
		if managedPeer.PeerID == "" || managedPeer.VirtualIP != sourceIP || !a.managedPeerRoutingIncludesLocalPeerLocked(managedPeer, connection.LocalPeerID) {
			continue
		}
		if !destinationWithinOverlay(managedPeer.OverlayCIDR, destinationIP) {
			continue
		}
		overlayCandidates = append(overlayCandidates, connection)
	}
	overlayConnection := a.preferredDestinationConnectionLocked(overlayCandidates, destinationIP)
	if overlayConnection != nil {
		return []*ConnectionStatus{overlayConnection}
	}
	if gatewayConnection := a.gatewayHostConnectionForDestinationLocked(managedPeers, networksByID, sourceIP, destinationIP); gatewayConnection != nil {
		return []*ConnectionStatus{gatewayConnection}
	}
	for _, managedPeer := range managedPeers {
		if managedPeer.VirtualIP != sourceIP {
			continue
		}
		network := networksByID[managedPeer.NetworkID]
		groupPolicy := networkGroupTrafficPolicyOrDefault(network)
		groupKind := groupTrafficKind(managedPeer.OverlayCIDR, destinationIP)
		if groupKind != "" {
			if strings.EqualFold(groupPolicy, "FLOOD") {
				return a.transportReadyConnectionsForManagedPeerLocked(managedPeer)
			}
			continue
		}
		if !strings.EqualFold(networkRoutingPolicyOrDefault(network), "FULL") {
			continue
		}
		if destinationWithinOverlay(managedPeer.OverlayCIDR, destinationIP) {
			continue
		}
		if ipUsesLocalIPv4Semantics(destinationIP) {
			continue
		}
		if managedPeer.NetworkID != primaryFullTunnelClientNetworkID {
			continue
		}
		if gateway := a.gatewayConnectionForNetworkLocked(network, managedPeer.PeerID); gateway != nil {
			return []*ConnectionStatus{gateway}
		}
	}
	return nil
}

func (a *Agent) gatewayHostConnectionForDestinationLocked(managedPeers []ManagedPeerState, networksByID map[string]controlclient.Network, sourceIP, destinationIP string) *ConnectionStatus {
	candidates := make([]*ConnectionStatus, 0)
	for idx := range a.connections {
		connection := &a.connections[idx]
		if !connection.TransportReady {
			continue
		}
		managedPeer := managedPeerByNetwork(managedPeers, connection.NetworkID)
		if managedPeer.PeerID == "" || !a.managedPeerRoutingIncludesLocalPeerLocked(managedPeer, connection.LocalPeerID) {
			continue
		}
		network := networksByID[connection.NetworkID]
		if !strings.EqualFold(networkRoutingPolicyOrDefault(network), "FULL") || a.currentUser == nil || !localUserCanActAsGateway(network, a.currentUser.ID) {
			continue
		}
		if ipUsesLocalIPv4Semantics(sourceIP) || ipWithinAnyManagedOverlay(managedPeers, sourceIP) || strings.EqualFold(strings.TrimSpace(managedPeer.VirtualIP), strings.TrimSpace(sourceIP)) {
			continue
		}
		candidates = append(candidates, connection)
	}
	return a.preferredDestinationConnectionLocked(candidates, destinationIP)
}

func (a *Agent) preferredDestinationConnectionLocked(candidates []*ConnectionStatus, destinationIP string) *ConnectionStatus {
	destinationIP = strings.TrimSpace(destinationIP)
	if destinationIP == "" {
		return nil
	}
	var selected *ConnectionStatus
	for _, connection := range candidates {
		if connection == nil || !strings.EqualFold(a.connectionRemoteVirtualIPUnlocked(connection), destinationIP) {
			continue
		}
		if selected != nil {
			if !a.sameTransportRoutingTargetLocked(selected, connection) {
				return nil
			}
			if a.betterDestinationRoutingConnectionWithCandidatesLocked(connection, selected, candidates) {
				selected = connection
			}
			continue
		}
		selected = connection
	}
	if selected == nil {
		return nil
	}
	for _, connection := range candidates {
		if connection == nil || connection == selected {
			continue
		}
		if !a.routingMetadataGapReplacementMatchLocked(selected, connection, destinationIP) &&
			!a.routingEndpointContinuityReplacementMatchLocked(selected, connection, candidates, destinationIP) {
			continue
		}
		if a.betterDestinationRoutingConnectionWithCandidatesLocked(connection, selected, candidates) {
			selected = connection
		}
	}
	return selected
}

func (a *Agent) betterDestinationRoutingConnectionLocked(candidate, current *ConnectionStatus) bool {
	return a.betterDestinationRoutingConnectionWithCandidatesLocked(candidate, current, a.transportReadyConnectionPointersLocked())
}

func (a *Agent) betterDestinationRoutingConnectionWithCandidatesLocked(candidate, current *ConnectionStatus, candidates []*ConnectionStatus) bool {
	if candidate == nil {
		return false
	}
	if current == nil {
		return true
	}
	if (a.sameTransportRoutingTargetLocked(current, candidate) ||
		a.transportRoutingMetadataGapReplacementMatchLocked(current, candidate) ||
		a.transportRoutingEndpointContinuityReplacementMatchWithCandidatesLocked(current, candidate, candidates)) &&
		a.localPeerMatchesActiveManagedPeerLocked(candidate.NetworkID, candidate.LocalPeerID) != a.localPeerMatchesActiveManagedPeerLocked(current.NetworkID, current.LocalPeerID) {
		return a.localPeerMatchesActiveManagedPeerLocked(candidate.NetworkID, candidate.LocalPeerID)
	}
	return betterGatewayConnection(candidate, "", current, "")
}

func (a *Agent) routingMetadataGapReplacementMatchLocked(reference, candidate *ConnectionStatus, destinationIP string) bool {
	if reference == nil || candidate == nil || !candidate.TransportReady {
		return false
	}
	destinationIP = strings.TrimSpace(destinationIP)
	if destinationIP == "" || !strings.EqualFold(a.connectionRemoteVirtualIPUnlocked(reference), destinationIP) {
		return false
	}
	if strings.TrimSpace(a.connectionRemoteVirtualIPUnlocked(candidate)) != "" {
		return false
	}
	return a.transportRoutingMetadataGapReplacementMatchLocked(reference, candidate)
}

func (a *Agent) routingEndpointContinuityReplacementMatchLocked(reference, candidate *ConnectionStatus, candidates []*ConnectionStatus, destinationIP string) bool {
	if reference == nil || candidate == nil || !candidate.TransportReady {
		return false
	}
	destinationIP = strings.TrimSpace(destinationIP)
	if destinationIP == "" || !strings.EqualFold(a.connectionRemoteVirtualIPUnlocked(reference), destinationIP) {
		return false
	}
	if strings.TrimSpace(a.connectionRemoteVirtualIPUnlocked(candidate)) != "" {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(reference.NetworkID), strings.TrimSpace(candidate.NetworkID)) {
		return false
	}
	referenceLocalPeerID := strings.TrimSpace(reference.LocalPeerID)
	candidateLocalPeerID := strings.TrimSpace(candidate.LocalPeerID)
	if referenceLocalPeerID == "" || candidateLocalPeerID == "" {
		return false
	}
	sameLocalPeer := strings.EqualFold(referenceLocalPeerID, candidateLocalPeerID)
	if !sameLocalPeer {
		activeLocalPeerID := strings.TrimSpace(a.currentManagedPeerIDForNetworkLocked(reference.NetworkID))
		if activeLocalPeerID == "" {
			return false
		}
		referenceActive := strings.EqualFold(referenceLocalPeerID, activeLocalPeerID)
		candidateActive := strings.EqualFold(candidateLocalPeerID, activeLocalPeerID)
		if referenceActive == candidateActive {
			return false
		}
	}
	referenceParts := endpointContinuityParts(strings.TrimSpace(reference.RemoteEndpoint), reference.RemoteCandidates)
	candidateParts := endpointContinuityParts(strings.TrimSpace(candidate.RemoteEndpoint), candidate.RemoteCandidates)
	if !endpointContinuityPartsOverlap(referenceParts, candidateParts) {
		return false
	}
	targetUserID := strings.TrimSpace(firstNonEmptyString(reference.RemoteUserID, a.peerUserIDInNetworkUnlocked(reference.NetworkID, reference.RemotePeerID)))
	mergedParts := mergeEndpointContinuityParts(referenceParts, candidateParts)
	for _, other := range candidates {
		if other == nil || other == reference || other == candidate || !other.TransportReady {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(other.NetworkID), strings.TrimSpace(reference.NetworkID)) {
			continue
		}
		otherLocalPeerID := strings.TrimSpace(other.LocalPeerID)
		if sameLocalPeer {
			if !strings.EqualFold(otherLocalPeerID, referenceLocalPeerID) {
				continue
			}
		} else if !strings.EqualFold(otherLocalPeerID, referenceLocalPeerID) && !strings.EqualFold(otherLocalPeerID, candidateLocalPeerID) {
			continue
		}
		if !endpointContinuityPartsOverlap(mergedParts, endpointContinuityParts(strings.TrimSpace(other.RemoteEndpoint), other.RemoteCandidates)) {
			continue
		}
		if a.sameTransportRoutingTargetLocked(reference, other) || a.transportRoutingMetadataGapReplacementMatchLocked(reference, other) {
			continue
		}
		otherVirtualIP := strings.TrimSpace(a.connectionRemoteVirtualIPUnlocked(other))
		otherUserID := strings.TrimSpace(firstNonEmptyString(other.RemoteUserID, a.peerUserIDInNetworkUnlocked(other.NetworkID, other.RemotePeerID)))
		if otherVirtualIP != "" && !strings.EqualFold(otherVirtualIP, destinationIP) {
			return false
		}
		if targetUserID != "" && otherUserID != "" && !strings.EqualFold(otherUserID, targetUserID) {
			return false
		}
		if otherVirtualIP == "" && otherUserID == "" {
			return false
		}
	}
	return true
}

func (a *Agent) sameTransportRoutingTargetLocked(current, candidate *ConnectionStatus) bool {
	if current == nil || candidate == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(current.NetworkID), strings.TrimSpace(candidate.NetworkID)) {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(current.RemotePeerID), strings.TrimSpace(candidate.RemotePeerID)) {
		return true
	}
	currentVirtualIP := a.connectionRemoteVirtualIPUnlocked(current)
	candidateVirtualIP := a.connectionRemoteVirtualIPUnlocked(candidate)
	if currentVirtualIP != "" || candidateVirtualIP != "" {
		if currentVirtualIP == "" || candidateVirtualIP == "" || !strings.EqualFold(currentVirtualIP, candidateVirtualIP) {
			return false
		}
		currentUserID := strings.TrimSpace(firstNonEmptyString(current.RemoteUserID, a.peerUserIDInNetworkUnlocked(current.NetworkID, current.RemotePeerID)))
		candidateUserID := strings.TrimSpace(firstNonEmptyString(candidate.RemoteUserID, a.peerUserIDInNetworkUnlocked(candidate.NetworkID, candidate.RemotePeerID)))
		if currentUserID != "" && candidateUserID != "" && !strings.EqualFold(currentUserID, candidateUserID) {
			return false
		}
		return true
	}
	return false
}

func (a *Agent) connectionByPeersLocked(networkID, localPeerID, remotePeerID string) *ConnectionStatus {
	for idx := range a.connections {
		connection := &a.connections[idx]
		if connection.NetworkID != networkID {
			continue
		}
		if connection.LocalPeerID == localPeerID && connection.RemotePeerID == remotePeerID {
			return connection
		}
	}
	return nil
}

func (a *Agent) transportReadyConnectionForTransferDownloadLocked(transfer controlclient.FileTransfer) *ConnectionStatus {
	connections := a.transportReadyConnectionsForTransferDownloadLocked(transfer)
	if len(connections) == 0 {
		return nil
	}
	return connections[0]
}

func (a *Agent) transportReadyConnectionsForTransferDownloadLocked(transfer controlclient.FileTransfer) []*ConnectionStatus {
	connections := make([]*ConnectionStatus, 0)
	seen := map[string]struct{}{}
	for idx := range a.connections {
		connection := &a.connections[idx]
		if connection.NetworkID != transfer.NetworkID || !connection.TransportReady {
			continue
		}
		if connection.LocalPeerID == transfer.ToPeerID && connection.RemotePeerID == transfer.FromPeerID {
			key := connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)
			seen[key] = struct{}{}
			connections = append(connections, connection)
		}
	}
	if !a.transferTargetsCurrentUserLocked(transfer) || strings.TrimSpace(transfer.FromUserID) == "" {
		return connections
	}
	for idx := range a.connections {
		connection := &a.connections[idx]
		if connection.NetworkID != transfer.NetworkID || !connection.TransportReady {
			continue
		}
		if !a.hasManagedPeerLocked(connection.LocalPeerID) {
			continue
		}
		if !a.transferDownloadConnectionMatchesLocked(transfer, connection) {
			continue
		}
		key := connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		connections = append(connections, connection)
	}
	sort.SliceStable(connections, func(i, j int) bool {
		return a.betterTransferDownloadConnectionLocked(connections[i], connections[j], transfer)
	})
	return connections
}

func (a *Agent) transportReadyConnectionsForTransferReceiverCacheLocked(transfer controlclient.FileTransfer) []*ConnectionStatus {
	connections := make([]*ConnectionStatus, 0)
	if a.currentUser == nil {
		return connections
	}
	for idx := range a.connections {
		connection := &a.connections[idx]
		if connection.NetworkID != transfer.NetworkID || !connection.TransportReady {
			continue
		}
		if connection.RemotePeerID == transfer.FromPeerID {
			continue
		}
		if !a.transferReceiverCacheConnectionMatchesLocked(transfer, connection) {
			continue
		}
		connections = append(connections, connection)
	}
	sort.SliceStable(connections, func(i, j int) bool {
		return a.betterTransferReceiverCacheConnectionLocked(connections[i], connections[j])
	})
	return connections
}

func (a *Agent) betterTransferDownloadConnectionLocked(candidate, current *ConnectionStatus, transfer controlclient.FileTransfer) bool {
	candidateManaged := candidate != nil && a.hasManagedPeerLocked(candidate.LocalPeerID)
	currentManaged := current != nil && a.hasManagedPeerLocked(current.LocalPeerID)
	if candidateManaged != currentManaged {
		return candidateManaged
	}
	if betterSignalingConnection(candidate, current) {
		return true
	}
	if betterSignalingConnection(current, candidate) {
		return false
	}
	candidateExact := candidate != nil &&
		strings.EqualFold(strings.TrimSpace(candidate.LocalPeerID), strings.TrimSpace(transfer.ToPeerID)) &&
		strings.EqualFold(strings.TrimSpace(candidate.RemotePeerID), strings.TrimSpace(transfer.FromPeerID))
	currentExact := current != nil &&
		strings.EqualFold(strings.TrimSpace(current.LocalPeerID), strings.TrimSpace(transfer.ToPeerID)) &&
		strings.EqualFold(strings.TrimSpace(current.RemotePeerID), strings.TrimSpace(transfer.FromPeerID))
	if candidateExact != currentExact {
		return candidateExact
	}
	return false
}

func (a *Agent) betterTransferReceiverCacheConnectionLocked(candidate, current *ConnectionStatus) bool {
	candidateManaged := candidate != nil && a.hasManagedPeerLocked(candidate.LocalPeerID)
	currentManaged := current != nil && a.hasManagedPeerLocked(current.LocalPeerID)
	if candidateManaged != currentManaged {
		return candidateManaged
	}
	if betterSignalingConnection(candidate, current) {
		return true
	}
	if betterSignalingConnection(current, candidate) {
		return false
	}
	return false
}

func (a *Agent) transferDownloadConnectionMatchesLocked(transfer controlclient.FileTransfer, connection *ConnectionStatus) bool {
	if connection == nil {
		return false
	}
	expectedRemoteUserID := strings.TrimSpace(transfer.FromUserID)
	if expectedRemoteUserID != "" {
		remoteUserID := strings.TrimSpace(firstNonEmptyString(connection.RemoteUserID, a.peerUserIDInNetworkUnlocked(transfer.NetworkID, connection.RemotePeerID)))
		if remoteUserID != "" {
			return strings.EqualFold(remoteUserID, expectedRemoteUserID)
		}
	}
	return a.connectionMatchesRemotePeerTargetLocked(transfer.NetworkID, transfer.FromPeerID, expectedRemoteUserID, connection)
}

func (a *Agent) transferReceiverCacheConnectionMatchesLocked(transfer controlclient.FileTransfer, connection *ConnectionStatus) bool {
	if connection == nil {
		return false
	}
	allowedRemoteUserID := ""
	if a.currentUser != nil {
		allowedRemoteUserID = strings.TrimSpace(a.currentUser.ID)
	}
	if strings.TrimSpace(transfer.ToUserID) != "" {
		allowedRemoteUserID = strings.TrimSpace(transfer.ToUserID)
	}
	remoteUserID := strings.TrimSpace(firstNonEmptyString(connection.RemoteUserID, a.peerUserIDInNetworkUnlocked(transfer.NetworkID, connection.RemotePeerID)))
	if remoteUserID != "" {
		return allowedRemoteUserID != "" && strings.EqualFold(remoteUserID, allowedRemoteUserID)
	}
	return a.connectionMatchesRemotePeerTargetLocked(transfer.NetworkID, transfer.ToPeerID, allowedRemoteUserID, connection)
}

func (a *Agent) fileTransferCacheRequesterMatchesLocked(localPeerID string, cache localFileTransferCache, remotePeerID string) bool {
	if a.sameUserPeerInNetworkUnlocked(cache.NetworkID, remotePeerID) {
		return true
	}
	if a.currentUser == nil {
		return false
	}
	connection := a.connectionByPeersLocked(cache.NetworkID, localPeerID, remotePeerID)
	if connection == nil {
		return false
	}
	return a.connectionMatchesRemotePeerTargetLocked(cache.NetworkID, cache.RemotePeerID, a.currentUser.ID, connection)
}

func (a *Agent) fileTransferSourceRequesterMatchesLocked(localPeerID string, source localFileTransferSource, remotePeerID string) (bool, string) {
	expectedRemoteUserID := strings.TrimSpace(firstNonEmptyString(source.RemoteUserID, a.peerUserIDInNetworkUnlocked(source.NetworkID, source.RemotePeerID)))
	remoteUserID := strings.TrimSpace(a.peerUserIDInNetworkUnlocked(source.NetworkID, remotePeerID))
	if expectedRemoteUserID != "" && remoteUserID != "" && strings.EqualFold(expectedRemoteUserID, remoteUserID) {
		return true, remoteUserID
	}
	connection := a.connectionByPeersLocked(source.NetworkID, localPeerID, remotePeerID)
	if !a.connectionMatchesRemotePeerTargetLocked(source.NetworkID, source.RemotePeerID, expectedRemoteUserID, connection) {
		return false, ""
	}
	if connection != nil {
		remoteUserID = strings.TrimSpace(firstNonEmptyString(connection.RemoteUserID, a.peerUserIDInNetworkUnlocked(source.NetworkID, remotePeerID)))
	}
	return true, remoteUserID
}

func (a *Agent) connectionMatchesRemotePeerTargetLocked(networkID, expectedPeerID, expectedUserID string, connection *ConnectionStatus) bool {
	if connection == nil || !strings.EqualFold(strings.TrimSpace(connection.NetworkID), strings.TrimSpace(networkID)) {
		return false
	}
	expectedPeerID = strings.TrimSpace(expectedPeerID)
	expectedUserID = strings.TrimSpace(expectedUserID)
	connectionRemotePeerID := strings.TrimSpace(connection.RemotePeerID)
	connectionRemoteUserID := strings.TrimSpace(firstNonEmptyString(connection.RemoteUserID, a.peerUserIDInNetworkUnlocked(networkID, connection.RemotePeerID)))
	if expectedPeerID != "" && strings.EqualFold(expectedPeerID, connectionRemotePeerID) {
		return expectedUserID == "" || connectionRemoteUserID == "" || strings.EqualFold(connectionRemoteUserID, expectedUserID)
	}
	if expectedPeerID == "" {
		return false
	}
	target := a.peerTargetInNetworkUnlocked(networkID, expectedPeerID)
	if strings.TrimSpace(target.ID) == "" || strings.TrimSpace(target.VirtualIP) == "" {
		return false
	}
	candidate := controlclient.Peer{
		ID:        connectionRemotePeerID,
		NetworkID: strings.TrimSpace(connection.NetworkID),
		UserID:    connectionRemoteUserID,
		VirtualIP: a.connectionRemoteVirtualIPUnlocked(connection),
	}
	if !sameOverlayPeerTarget(target, candidate) {
		return a.connectionMatchesRemotePeerEndpointContinuityTargetLocked(networkID, expectedPeerID, expectedUserID, connection)
	}
	return expectedUserID == "" || candidate.UserID == "" || strings.EqualFold(strings.TrimSpace(candidate.UserID), expectedUserID)
}

func (a *Agent) connectionMatchesRemotePeerEndpointContinuityTargetLocked(networkID, expectedPeerID, expectedUserID string, connection *ConnectionStatus) bool {
	if connection == nil || !connection.TransportReady || !strings.EqualFold(strings.TrimSpace(connection.NetworkID), strings.TrimSpace(networkID)) {
		return false
	}
	expectedPeerID = strings.TrimSpace(expectedPeerID)
	if expectedPeerID == "" {
		return false
	}
	expectedUserID = strings.TrimSpace(expectedUserID)
	target := a.peerTargetInNetworkUnlocked(networkID, expectedPeerID)
	endpointCandidates := a.transportReadyConnectionPointersLocked()
	for _, reference := range endpointCandidates {
		if reference == nil || reference == connection {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(reference.NetworkID), strings.TrimSpace(networkID)) {
			continue
		}
		referencePeerID := strings.TrimSpace(reference.RemotePeerID)
		referenceUserID := strings.TrimSpace(firstNonEmptyString(reference.RemoteUserID, a.peerUserIDInNetworkUnlocked(networkID, reference.RemotePeerID)))
		referenceMatches := false
		if referencePeerID != "" && strings.EqualFold(referencePeerID, expectedPeerID) {
			referenceMatches = expectedUserID == "" || referenceUserID == "" || strings.EqualFold(referenceUserID, expectedUserID)
		}
		if !referenceMatches && strings.TrimSpace(target.ID) != "" && strings.TrimSpace(target.VirtualIP) != "" {
			referenceTarget := controlclient.Peer{
				ID:        referencePeerID,
				NetworkID: strings.TrimSpace(reference.NetworkID),
				UserID:    referenceUserID,
				VirtualIP: a.connectionRemoteVirtualIPUnlocked(reference),
			}
			referenceMatches = sameOverlayPeerTarget(target, referenceTarget) &&
				(expectedUserID == "" || referenceTarget.UserID == "" || strings.EqualFold(strings.TrimSpace(referenceTarget.UserID), expectedUserID))
		}
		if !referenceMatches {
			continue
		}
		if a.transportRoutingEndpointContinuityReplacementMatchWithCandidatesLocked(reference, connection, endpointCandidates) {
			return true
		}
	}
	return false
}

func (a *Agent) peerTargetInNetworkUnlocked(networkID, peerID string) controlclient.Peer {
	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return controlclient.Peer{}
	}
	for _, peer := range a.discoveredPeers[networkID] {
		if strings.EqualFold(strings.TrimSpace(peer.ID), peerID) {
			return peer
		}
	}
	return controlclient.Peer{
		ID:        peerID,
		NetworkID: strings.TrimSpace(networkID),
		UserID:    strings.TrimSpace(a.peerUserIDInNetworkUnlocked(networkID, peerID)),
		VirtualIP: strings.TrimSpace(a.peerVirtualIPInNetworkUnlocked(networkID, peerID)),
	}
}

func (a *Agent) peerVirtualIPInNetworkUnlocked(networkID, peerID string) string {
	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return ""
	}
	for _, peer := range a.discoveredPeers[networkID] {
		if strings.EqualFold(strings.TrimSpace(peer.ID), peerID) {
			return strings.TrimSpace(peer.VirtualIP)
		}
	}
	for idx := range a.connections {
		connection := &a.connections[idx]
		if !strings.EqualFold(strings.TrimSpace(connection.NetworkID), strings.TrimSpace(networkID)) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(connection.RemotePeerID), peerID) {
			continue
		}
		if strings.TrimSpace(connection.RemoteVirtualIP) != "" {
			return strings.TrimSpace(connection.RemoteVirtualIP)
		}
	}
	return ""
}

func (a *Agent) connectionRemoteVirtualIPUnlocked(connection *ConnectionStatus) string {
	if connection == nil {
		return ""
	}
	if remoteVirtualIP := strings.TrimSpace(connection.RemoteVirtualIP); remoteVirtualIP != "" {
		return remoteVirtualIP
	}
	return strings.TrimSpace(a.peerVirtualIPInNetworkUnlocked(connection.NetworkID, connection.RemotePeerID))
}

func (a *Agent) transportReadyConnectionsForNetworkLocked(networkID, localPeerID string) []*ConnectionStatus {
	connections := make([]*ConnectionStatus, 0)
	for idx := range a.connections {
		connection := &a.connections[idx]
		if connection.NetworkID != networkID || connection.LocalPeerID != localPeerID || !connection.TransportReady {
			continue
		}
		replaced := false
		for existingIdx, current := range connections {
			if !a.sameTransportRoutingTargetLocked(current, connection) &&
				!a.transportRoutingMetadataGapReplacementMatchLocked(current, connection) &&
				!a.transportRoutingEndpointContinuityReplacementMatchLocked(current, connection) {
				continue
			}
			if betterGatewayConnection(connection, "", current, "") {
				connections[existingIdx] = connection
			}
			replaced = true
			break
		}
		if replaced {
			continue
		}
		connections = append(connections, connection)
	}
	return connections
}

func (a *Agent) transportReadyConnectionsForManagedPeerLocked(managedPeer ManagedPeerState) []*ConnectionStatus {
	connections := make([]*ConnectionStatus, 0)
	for _, localPeerID := range a.routingLocalPeerIDsForManagedPeerLocked(managedPeer) {
		for _, connection := range a.transportReadyConnectionsForNetworkLocked(managedPeer.NetworkID, localPeerID) {
			replaced := false
			for existingIdx, current := range connections {
				if !a.sameTransportRoutingTargetLocked(current, connection) &&
					!a.transportRoutingMetadataGapReplacementMatchLocked(current, connection) &&
					!a.transportRoutingEndpointContinuityReplacementMatchLocked(current, connection) {
					continue
				}
				if a.betterDestinationRoutingConnectionLocked(connection, current) {
					connections[existingIdx] = connection
				}
				replaced = true
				break
			}
			if replaced {
				continue
			}
			connections = append(connections, connection)
		}
	}
	return connections
}

func (a *Agent) transportRoutingMetadataGapReplacementMatchLocked(current, candidate *ConnectionStatus) bool {
	if current == nil || candidate == nil || !candidate.TransportReady {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(current.NetworkID), strings.TrimSpace(candidate.NetworkID)) {
		return false
	}
	currentLocalPeerID := strings.TrimSpace(current.LocalPeerID)
	candidateLocalPeerID := strings.TrimSpace(candidate.LocalPeerID)
	if currentLocalPeerID == "" || candidateLocalPeerID == "" {
		return false
	}
	sameLocalPeer := strings.EqualFold(currentLocalPeerID, candidateLocalPeerID)
	if !sameLocalPeer {
		activeLocalPeerID := strings.TrimSpace(a.currentManagedPeerIDForNetworkLocked(current.NetworkID))
		if activeLocalPeerID == "" {
			return false
		}
		currentActive := strings.EqualFold(currentLocalPeerID, activeLocalPeerID)
		candidateActive := strings.EqualFold(candidateLocalPeerID, activeLocalPeerID)
		if currentActive == candidateActive {
			return false
		}
	}
	currentVirtualIP := strings.TrimSpace(a.connectionRemoteVirtualIPUnlocked(current))
	candidateVirtualIP := strings.TrimSpace(a.connectionRemoteVirtualIPUnlocked(candidate))
	switch {
	case currentVirtualIP == "" && candidateVirtualIP == "":
		return false
	case currentVirtualIP != "" && candidateVirtualIP != "":
		return false
	}
	targetVirtualIP := currentVirtualIP
	if targetVirtualIP == "" {
		targetVirtualIP = candidateVirtualIP
	}
	currentUserID := strings.TrimSpace(firstNonEmptyString(current.RemoteUserID, a.peerUserIDInNetworkUnlocked(current.NetworkID, current.RemotePeerID)))
	candidateUserID := strings.TrimSpace(firstNonEmptyString(candidate.RemoteUserID, a.peerUserIDInNetworkUnlocked(candidate.NetworkID, candidate.RemotePeerID)))
	if currentUserID == "" || candidateUserID == "" || !strings.EqualFold(currentUserID, candidateUserID) {
		return false
	}
	for idx := range a.connections {
		other := &a.connections[idx]
		if other == current || other == candidate || !other.TransportReady {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(other.NetworkID), strings.TrimSpace(current.NetworkID)) {
			continue
		}
		otherLocalPeerID := strings.TrimSpace(other.LocalPeerID)
		if sameLocalPeer {
			if !strings.EqualFold(otherLocalPeerID, currentLocalPeerID) {
				continue
			}
		} else if !strings.EqualFold(otherLocalPeerID, currentLocalPeerID) && !strings.EqualFold(otherLocalPeerID, candidateLocalPeerID) {
			continue
		}
		otherUserID := strings.TrimSpace(firstNonEmptyString(other.RemoteUserID, a.peerUserIDInNetworkUnlocked(other.NetworkID, other.RemotePeerID)))
		if otherUserID == "" || !strings.EqualFold(otherUserID, currentUserID) {
			continue
		}
		otherVirtualIP := strings.TrimSpace(a.connectionRemoteVirtualIPUnlocked(other))
		if otherVirtualIP == "" || !strings.EqualFold(otherVirtualIP, targetVirtualIP) {
			return false
		}
	}
	return true
}

func (a *Agent) transportRoutingEndpointContinuityReplacementMatchLocked(current, candidate *ConnectionStatus) bool {
	return a.transportRoutingEndpointContinuityReplacementMatchWithCandidatesLocked(current, candidate, a.transportReadyConnectionPointersLocked())
}

func (a *Agent) transportRoutingEndpointContinuityReplacementMatchWithCandidatesLocked(current, candidate *ConnectionStatus, candidates []*ConnectionStatus) bool {
	if current == nil || candidate == nil || !candidate.TransportReady {
		return false
	}
	currentVirtualIP := strings.TrimSpace(a.connectionRemoteVirtualIPUnlocked(current))
	candidateVirtualIP := strings.TrimSpace(a.connectionRemoteVirtualIPUnlocked(candidate))
	switch {
	case currentVirtualIP != "" && candidateVirtualIP == "":
		return a.routingEndpointContinuityReplacementMatchLocked(current, candidate, candidates, currentVirtualIP)
	case currentVirtualIP == "" && candidateVirtualIP != "":
		return a.routingEndpointContinuityReplacementMatchLocked(candidate, current, candidates, candidateVirtualIP)
	default:
		return false
	}
}

func (a *Agent) transportReadyConnectionPointersLocked() []*ConnectionStatus {
	connections := make([]*ConnectionStatus, 0, len(a.connections))
	for idx := range a.connections {
		if !a.connections[idx].TransportReady {
			continue
		}
		connections = append(connections, &a.connections[idx])
	}
	return connections
}

func connectionStatusPointers(connections []ConnectionStatus) []*ConnectionStatus {
	out := make([]*ConnectionStatus, 0, len(connections))
	for idx := range connections {
		out = append(out, &connections[idx])
	}
	return out
}

func (a *Agent) sameTransportLifecycleTargetLocked(current, candidate *ConnectionStatus) bool {
	return a.sameTransportLifecycleTargetWithEndpointCandidatesLocked(current, candidate, a.transportReadyConnectionPointersLocked())
}

func (a *Agent) sameTransportLifecycleTargetWithEndpointCandidatesLocked(current, candidate *ConnectionStatus, endpointCandidates []*ConnectionStatus) bool {
	if current == nil || candidate == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(current.NetworkID), strings.TrimSpace(candidate.NetworkID)) {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(current.LocalPeerID), strings.TrimSpace(candidate.LocalPeerID)) {
		return a.sameTransportRoutingTargetLocked(current, candidate) ||
			a.transportRoutingMetadataGapReplacementMatchLocked(current, candidate) ||
			a.transportRoutingEndpointContinuityReplacementMatchWithCandidatesLocked(current, candidate, endpointCandidates)
	}
	activeLocalPeerID := strings.TrimSpace(a.currentManagedPeerIDForNetworkLocked(current.NetworkID))
	if activeLocalPeerID == "" {
		return false
	}
	currentActive := strings.EqualFold(strings.TrimSpace(current.LocalPeerID), activeLocalPeerID)
	candidateActive := strings.EqualFold(strings.TrimSpace(candidate.LocalPeerID), activeLocalPeerID)
	if currentActive == candidateActive {
		return false
	}
	return a.sameTransportRoutingTargetLocked(current, candidate) ||
		a.transportLifecycleMetadataGapReplacementMatchLocked(current, candidate, activeLocalPeerID) ||
		a.transportRoutingEndpointContinuityReplacementMatchWithCandidatesLocked(current, candidate, endpointCandidates)
}

func (a *Agent) transportLifecycleMetadataGapReplacementMatchLocked(current, candidate *ConnectionStatus, activeLocalPeerID string) bool {
	if current == nil || candidate == nil || !candidate.TransportReady {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(current.NetworkID), strings.TrimSpace(candidate.NetworkID)) {
		return false
	}
	activeLocalPeerID = strings.TrimSpace(activeLocalPeerID)
	if activeLocalPeerID == "" {
		activeLocalPeerID = strings.TrimSpace(a.currentManagedPeerIDForNetworkLocked(current.NetworkID))
	}
	if activeLocalPeerID == "" {
		return false
	}
	currentLocalPeerID := strings.TrimSpace(current.LocalPeerID)
	candidateLocalPeerID := strings.TrimSpace(candidate.LocalPeerID)
	if currentLocalPeerID == "" || candidateLocalPeerID == "" || strings.EqualFold(currentLocalPeerID, candidateLocalPeerID) {
		return false
	}
	currentActive := strings.EqualFold(currentLocalPeerID, activeLocalPeerID)
	candidateActive := strings.EqualFold(candidateLocalPeerID, activeLocalPeerID)
	if currentActive == candidateActive {
		return false
	}
	currentVirtualIP := strings.TrimSpace(a.connectionRemoteVirtualIPUnlocked(current))
	candidateVirtualIP := strings.TrimSpace(a.connectionRemoteVirtualIPUnlocked(candidate))
	switch {
	case currentVirtualIP == "" && candidateVirtualIP == "":
		return false
	case currentVirtualIP != "" && candidateVirtualIP != "":
		return false
	}
	targetVirtualIP := currentVirtualIP
	if targetVirtualIP == "" {
		targetVirtualIP = candidateVirtualIP
	}
	currentUserID := strings.TrimSpace(firstNonEmptyString(current.RemoteUserID, a.peerUserIDInNetworkUnlocked(current.NetworkID, current.RemotePeerID)))
	candidateUserID := strings.TrimSpace(firstNonEmptyString(candidate.RemoteUserID, a.peerUserIDInNetworkUnlocked(candidate.NetworkID, candidate.RemotePeerID)))
	if currentUserID == "" || candidateUserID == "" || !strings.EqualFold(currentUserID, candidateUserID) {
		return false
	}
	for idx := range a.connections {
		other := &a.connections[idx]
		if other == current || other == candidate || !other.TransportReady {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(other.NetworkID), strings.TrimSpace(current.NetworkID)) {
			continue
		}
		otherLocalPeerID := strings.TrimSpace(other.LocalPeerID)
		if !strings.EqualFold(otherLocalPeerID, currentLocalPeerID) && !strings.EqualFold(otherLocalPeerID, candidateLocalPeerID) {
			continue
		}
		otherUserID := strings.TrimSpace(firstNonEmptyString(other.RemoteUserID, a.peerUserIDInNetworkUnlocked(other.NetworkID, other.RemotePeerID)))
		if otherUserID == "" || !strings.EqualFold(otherUserID, currentUserID) {
			continue
		}
		otherVirtualIP := strings.TrimSpace(a.connectionRemoteVirtualIPUnlocked(other))
		if otherVirtualIP == "" || !strings.EqualFold(otherVirtualIP, targetVirtualIP) {
			return false
		}
	}
	return true
}

func (a *Agent) betterTransportLifecycleConnectionLocked(candidate, current *ConnectionStatus) bool {
	if candidate == nil {
		return false
	}
	if current == nil {
		return true
	}
	candidateActive := a.localPeerMatchesActiveManagedPeerLocked(candidate.NetworkID, candidate.LocalPeerID)
	currentActive := a.localPeerMatchesActiveManagedPeerLocked(current.NetworkID, current.LocalPeerID)
	if candidateActive != currentActive {
		return candidateActive
	}
	return betterSignalingConnection(candidate, current)
}

func (a *Agent) preferredTransportLifecycleConnectionsLocked() []*ConnectionStatus {
	connections := make([]*ConnectionStatus, 0, len(a.connections))
	for idx := range a.connections {
		connection := &a.connections[idx]
		replaced := false
		for existingIdx, current := range connections {
			if !a.sameTransportLifecycleTargetLocked(current, connection) {
				continue
			}
			if a.betterTransportLifecycleConnectionLocked(connection, current) {
				connections[existingIdx] = connection
			}
			replaced = true
			break
		}
		if replaced {
			continue
		}
		connections = append(connections, connection)
	}
	return connections
}

func (a *Agent) preferredTransportLifecycleConnectionKeysLocked() map[string]struct{} {
	preferred := a.preferredTransportLifecycleConnectionsLocked()
	keys := make(map[string]struct{}, len(preferred))
	for _, connection := range preferred {
		if connection == nil {
			continue
		}
		keys[connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)] = struct{}{}
	}
	return keys
}

func (a *Agent) clearSupersededTransportAttemptsLocked(preferred []*ConnectionStatus) {
	if len(preferred) == 0 {
		return
	}
	preferredKeys := make(map[string]struct{}, len(preferred))
	for _, connection := range preferred {
		if connection == nil {
			continue
		}
		preferredKeys[connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)] = struct{}{}
	}
	for idx := range a.connections {
		connection := &a.connections[idx]
		key := connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)
		if _, ok := preferredKeys[key]; ok {
			continue
		}
		superseded := false
		for _, current := range preferred {
			if a.sameTransportLifecycleTargetLocked(current, connection) {
				superseded = true
				break
			}
		}
		if !superseded {
			continue
		}
		attempt, ok := a.directAttempts[key]
		if ok {
			if attempt.DirectReady || strings.TrimSpace(attempt.TransportMode) != "" || strings.TrimSpace(attempt.TransportSessionID) != "" {
				a.dropTransportSessionLocked(connection.LocalPeerID, connection.RemotePeerID, attempt.TransportMode)
			}
			a.clearTransportAttemptLocked(&attempt)
			attempt.LastError = "superseded by replacement transport"
			a.applyAttemptStateToConnection(connection, attempt)
			delete(a.directAttempts, key)
			continue
		}
		if connection.TransportReady || strings.TrimSpace(connection.TransportMode) != "" || strings.TrimSpace(connection.TransportSessionID) != "" {
			a.dropTransportSessionLocked(connection.LocalPeerID, connection.RemotePeerID, connection.TransportMode)
		}
		connection.TransportReady = false
		connection.TransportMode = ""
		connection.TransportSessionID = ""
		connection.TransportEstablishedUnix = 0
		connection.TransportPacketCount = 0
		connection.TransportRekeyDueUnix = 0
		connection.LastTransportUnix = 0
		connection.LastKeepaliveUnix = 0
		connection.LastRTTMillis = 0
		connection.AverageRTTMillis = 0
		connection.ConsecutiveLosses = 0
		connection.LastError = "superseded by replacement transport"
	}
}

func (a *Agent) tunnelNegotiationConnectionsLocked() []*ConnectionStatus {
	connections := make([]*ConnectionStatus, 0)
	for idx := range a.connections {
		connection := &a.connections[idx]
		if desiredTunnelMode(*connection) == "" {
			continue
		}
		replaced := false
		for existingIdx, current := range connections {
			if !a.sameTransportLifecycleTargetLocked(current, connection) {
				continue
			}
			if a.betterTransportLifecycleConnectionLocked(connection, current) {
				connections[existingIdx] = connection
			}
			replaced = true
			break
		}
		if replaced {
			continue
		}
		connections = append(connections, connection)
	}
	return connections
}

func (a *Agent) reconcileNegotiationTunnelsLocked() error {
	if a.currentUser == nil {
		return nil
	}
	desiredByNetwork := map[string]map[string]controlclient.Tunnel{}
	desiredTunnelIDsByNetwork := map[string]map[string]struct{}{}
	desiredConnectionsByNetwork := map[string][]*ConnectionStatus{}
	for _, connection := range a.tunnelNegotiationConnectionsLocked() {
		mode := desiredTunnelMode(*connection)
		if mode == "" {
			continue
		}
		desiredConnectionsByNetwork[connection.NetworkID] = append(desiredConnectionsByNetwork[connection.NetworkID], connection)
		tunnel, err := a.remote.CreateTunnel(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID, mode)
		if err != nil {
			fallback, ok := fallbackNegotiationTunnelForConnection(connection, mode)
			if !ok || !isNotFoundError(err) {
				return err
			}
			tunnel = fallback
		}
		if connection.State == "CONNECTED" && tunnel.State != "OPEN" {
			tunnel, err = a.remote.UpdateTunnelState(tunnel.ID, "OPEN")
			if err != nil {
				return err
			}
		}
		if desiredByNetwork[connection.NetworkID] == nil {
			desiredByNetwork[connection.NetworkID] = map[string]controlclient.Tunnel{}
		}
		if desiredTunnelIDsByNetwork[connection.NetworkID] == nil {
			desiredTunnelIDsByNetwork[connection.NetworkID] = map[string]struct{}{}
		}
		desiredByNetwork[connection.NetworkID][connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)] = *tunnel
		if tunnelID := strings.TrimSpace(tunnel.ID); tunnelID != "" {
			desiredTunnelIDsByNetwork[connection.NetworkID][tunnelID] = struct{}{}
		}
	}

	state, err := a.ensurePersistentStateLocked()
	if err != nil {
		return err
	}
	managedPeers := state.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	for networkID, peerIDs := range managedPeerIDsByNetwork(managedPeers) {
		tunnels, err := a.remote.ListTunnels(networkID)
		if err != nil {
			return err
		}
		for _, tunnel := range tunnels {
			if tunnel.State != "NEGOTIATING" && tunnel.State != "OPEN" {
				continue
			}
			if desiredTunnelIDsByNetwork[tunnel.NetworkID] != nil {
				if _, ok := desiredTunnelIDsByNetwork[tunnel.NetworkID][strings.TrimSpace(tunnel.ID)]; ok {
					key := connectionKey(tunnel.NetworkID, tunnel.PeerAID, tunnel.PeerBID)
					if desiredByNetwork[tunnel.NetworkID] != nil {
						if desired, ok := desiredByNetwork[tunnel.NetworkID][key]; ok {
							a.attachTunnelToConnections(desired)
						}
					}
					continue
				}
			}
			key := connectionKey(tunnel.NetworkID, tunnel.PeerAID, tunnel.PeerBID)
			if desiredByNetwork[tunnel.NetworkID] != nil {
				if desired, ok := desiredByNetwork[tunnel.NetworkID][key]; ok {
					a.attachTunnelToConnections(desired)
					continue
				}
			}
			if !tunnelTouchesManagedPeerIDs(tunnel, peerIDs) &&
				!a.staleReplacementTunnelMatchesDesiredConnectionLocked(tunnel, desiredConnectionsByNetwork[tunnel.NetworkID]) {
				continue
			}
			if _, err := a.remote.UpdateTunnelState(tunnel.ID, "CLOSED"); err != nil {
				return err
			}
		}
	}
	for _, tunnels := range desiredByNetwork {
		for _, tunnel := range tunnels {
			a.attachTunnelToConnections(tunnel)
		}
	}
	return nil
}

func (a *Agent) staleReplacementTunnelMatchesDesiredConnectionLocked(tunnel controlclient.Tunnel, desired []*ConnectionStatus) bool {
	if len(desired) == 0 {
		return false
	}
	current := &ConnectionStatus{
		NetworkID:    strings.TrimSpace(tunnel.NetworkID),
		LocalPeerID:  strings.TrimSpace(tunnel.PeerAID),
		RemotePeerID: strings.TrimSpace(tunnel.PeerBID),
		TunnelID:     strings.TrimSpace(tunnel.ID),
		TunnelMode:   strings.TrimSpace(tunnel.Mode),
		TunnelState:  strings.TrimSpace(tunnel.State),
	}
	for _, candidate := range desired {
		if candidate == nil {
			continue
		}
		if !a.sameTransportLifecycleTargetLocked(current, candidate) {
			continue
		}
		if a.betterTransportLifecycleConnectionLocked(candidate, current) {
			return true
		}
	}
	return false
}

func fallbackNegotiationTunnelForConnection(connection *ConnectionStatus, mode string) (*controlclient.Tunnel, bool) {
	if connection == nil {
		return nil, false
	}
	tunnelID := strings.TrimSpace(connection.TunnelID)
	tunnelState := strings.ToUpper(strings.TrimSpace(connection.TunnelState))
	if tunnelID == "" {
		return nil, false
	}
	if tunnelState != "OPEN" && tunnelState != "NEGOTIATING" {
		return nil, false
	}
	return &controlclient.Tunnel{
		ID:        tunnelID,
		NetworkID: strings.TrimSpace(connection.NetworkID),
		PeerAID:   strings.TrimSpace(connection.LocalPeerID),
		PeerBID:   strings.TrimSpace(connection.RemotePeerID),
		Mode:      firstNonEmptyString(strings.ToUpper(strings.TrimSpace(connection.TunnelMode)), strings.ToUpper(strings.TrimSpace(mode)), "P2P"),
		State:     tunnelState,
	}, true
}

func (a *Agent) closeManagedNegotiationTunnelsLocked(managedPeers []ManagedPeerState) error {
	for networkID, peerIDs := range managedPeerIDsByNetwork(managedPeers) {
		tunnels, err := a.remote.ListTunnels(networkID)
		if err != nil {
			return err
		}
		for _, tunnel := range tunnels {
			if tunnel.State != "NEGOTIATING" && tunnel.State != "OPEN" {
				continue
			}
			if !tunnelTouchesManagedPeerIDs(tunnel, peerIDs) {
				continue
			}
			if _, err := a.remote.UpdateTunnelState(tunnel.ID, "CLOSED"); err != nil {
				return err
			}
		}
	}
	return nil
}

func managedPeerIDsByNetwork(peers []ManagedPeerState) map[string]map[string]struct{} {
	out := make(map[string]map[string]struct{}, len(peers))
	for _, peer := range peers {
		networkID := strings.TrimSpace(peer.NetworkID)
		peerID := strings.TrimSpace(peer.PeerID)
		if networkID == "" || peerID == "" {
			continue
		}
		if out[networkID] == nil {
			out[networkID] = map[string]struct{}{}
		}
		out[networkID][peerID] = struct{}{}
	}
	return out
}

func tunnelTouchesManagedPeerIDs(tunnel controlclient.Tunnel, peerIDs map[string]struct{}) bool {
	if len(peerIDs) == 0 {
		return false
	}
	if _, ok := peerIDs[strings.TrimSpace(tunnel.PeerAID)]; ok {
		return true
	}
	if _, ok := peerIDs[strings.TrimSpace(tunnel.PeerBID)]; ok {
		return true
	}
	return false
}

func (a *Agent) attachTunnelToConnections(tunnel controlclient.Tunnel) {
	exactMatches := make([]*ConnectionStatus, 0, 1)
	for idx := range a.connections {
		connection := &a.connections[idx]
		if connection.NetworkID != tunnel.NetworkID {
			continue
		}
		if samePeerPair(connection.LocalPeerID, connection.RemotePeerID, tunnel.PeerAID, tunnel.PeerBID) {
			connection.TunnelID = tunnel.ID
			connection.TunnelMode = tunnel.Mode
			connection.TunnelState = tunnel.State
			exactMatches = append(exactMatches, connection)
		}
	}
	for _, exact := range exactMatches {
		if exact == nil {
			continue
		}
		preferred := exact
		for idx := range a.connections {
			candidate := &a.connections[idx]
			if candidate.NetworkID != tunnel.NetworkID {
				continue
			}
			if !a.sameTransportRoutingTargetLocked(exact, candidate) &&
				!a.sameTransportLifecycleTargetLocked(exact, candidate) {
				continue
			}
			if betterSignalingConnection(candidate, preferred) {
				preferred = candidate
			}
		}
		if preferred != nil {
			preferred.TunnelID = tunnel.ID
			preferred.TunnelMode = tunnel.Mode
			preferred.TunnelState = tunnel.State
		}
	}
}

func summarizeNetworkSignaling(localPeerID, networkID string, connections []ConnectionStatus) (string, string) {
	var best *ConnectionStatus
	for idx := range connections {
		connection := &connections[idx]
		if connection.LocalPeerID != localPeerID || connection.NetworkID != networkID {
			continue
		}
		if best == nil || betterSignalingConnection(connection, best) {
			best = connection
		}
	}
	if best == nil {
		return "UNKNOWN", "IDLE"
	}
	switch best.State {
	case "CONNECTED":
		if strings.EqualFold(best.Reachability, "RELAY") {
			return "RELAY", "CONNECTED"
		}
		return "DIRECT", "CONNECTED"
	case "NEGOTIATING":
		return "DIRECT", "NEGOTIATING"
	case "DIRECT_CANDIDATE":
		return "DIRECT", "DIRECT_CANDIDATE"
	case "RELAY_READY":
		return "RELAY", "RELAY_READY"
	case "DISCOVERING":
		return "UNKNOWN", "DISCOVERING"
	default:
		return "UNKNOWN", "IDLE"
	}
}

func betterSignalingConnection(candidate, current *ConnectionStatus) bool {
	if candidate == nil {
		return false
	}
	if current == nil {
		return true
	}
	if signalingStatePreference(candidate.State) != signalingStatePreference(current.State) {
		return signalingStatePreference(candidate.State) > signalingStatePreference(current.State)
	}
	return betterGatewayConnection(candidate, "", current, "")
}

func signalingStatePreference(state string) int {
	switch strings.ToUpper(strings.TrimSpace(state)) {
	case "CONNECTED":
		return 5
	case "NEGOTIATING":
		return 4
	case "DIRECT_CANDIDATE":
		return 3
	case "RELAY_READY":
		return 2
	case "DISCOVERING":
		return 1
	default:
		return 0
	}
}

func directRetryDelay(base, max time.Duration, attemptCount int) time.Duration {
	if attemptCount <= 1 {
		return base
	}
	delay := base
	for i := 1; i < attemptCount; i++ {
		delay *= 2
		if delay >= max {
			return max
		}
	}
	if delay > max {
		return max
	}
	return delay
}

func connectionKey(networkID, localPeerID, remotePeerID string) string {
	left := localPeerID
	right := remotePeerID
	if strings.Compare(left, right) > 0 {
		left, right = right, left
	}
	return networkID + "|" + left + "|" + right
}

func desiredTunnelMode(connection ConnectionStatus) string {
	switch connection.State {
	case "CONNECTED":
		if strings.EqualFold(connection.Reachability, "RELAY") {
			return "RELAY"
		}
		return "P2P"
	case "NEGOTIATING":
		return "P2P"
	case "RELAY_READY":
		return "RELAY"
	default:
		return ""
	}
}

func samePeerPair(a1, b1, a2, b2 string) bool {
	return (a1 == a2 && b1 == b2) || (a1 == b2 && b1 == a2)
}

func buildConnectionStatus(networkID, localPeerID string, remotePeer controlclient.Peer, candidates []controlclient.SignalCandidate, previous *ConnectionStatus) ConnectionStatus {
	reachability := "UNKNOWN"
	state := "IDLE"
	remoteCandidates := candidateAddresses(candidates)
	if len(remoteCandidates) == 0 {
		remoteCandidates = previousConnectionCandidates(previous)
	}
	relayCandidates := relayCandidateAddresses(candidates)
	if strings.EqualFold(remotePeer.Status, "ONLINE") {
		switch {
		case len(remoteCandidates) > 0:
			reachability = "DIRECT"
			state = "DIRECT_CANDIDATE"
		case len(relayCandidates) > 0:
			reachability = "RELAY"
			state = "RELAY_READY"
		case strings.TrimSpace(remotePeer.Endpoint) != "":
			state = "DISCOVERING"
		default:
			reachability = "RELAY"
			state = "RELAY_READY"
		}
	}
	return ConnectionStatus{
		NetworkID:            networkID,
		LocalPeerID:          localPeerID,
		RemotePeerID:         remotePeer.ID,
		RemoteUserID:         firstNonEmptyString(strings.TrimSpace(remotePeer.UserID), previousConnectionUserID(previous)),
		RemoteVirtualIP:      firstNonEmptyString(strings.TrimSpace(remotePeer.VirtualIP), previousConnectionVirtualIP(previous)),
		RemoteEndpoint:       remotePeer.Endpoint,
		RemoteCandidateCount: len(remoteCandidates),
		RemoteCandidates:     remoteCandidates,
		Reachability:         reachability,
		State:                state,
	}
}

func buildNeighborStatus(networkID, localPeerID string, remotePeer controlclient.Peer, candidates []controlclient.SignalCandidate, connection ConnectionStatus) NeighborStatus {
	presence := "offline"
	if strings.EqualFold(remotePeer.Status, "ONLINE") {
		presence = "online"
	}
	neighborState := firstNonEmptyString(connection.State, strings.TrimSpace(remotePeer.ConnectionState))
	if neighborState == "" {
		neighborState = "IDLE"
	}
	return NeighborStatus{
		NetworkID:          networkID,
		LocalPeerID:        localPeerID,
		RemotePeerID:       remotePeer.ID,
		RemoteUserID:       firstNonEmptyString(strings.TrimSpace(remotePeer.UserID), strings.TrimSpace(connection.RemoteUserID)),
		RemoteVirtualIP:    firstNonEmptyString(strings.TrimSpace(remotePeer.VirtualIP), strings.TrimSpace(connection.RemoteVirtualIP)),
		RemoteEndpoint:     remotePeer.Endpoint,
		OverlayCIDR:        remotePeer.OverlayCIDR,
		Presence:           presence,
		NeighborState:      neighborState,
		Reachability:       firstNonEmptyString(connection.Reachability, strings.TrimSpace(remotePeer.Reachability)),
		CandidateCount:     len(candidates),
		TransportReady:     connection.TransportReady,
		TransportMode:      connection.TransportMode,
		LastSeenUnix:       remotePeer.LastSeenUnix,
		LastSignaledAtUnix: remotePeer.LastSignaledAtUnix,
	}
}

func previousConnectionUserID(previous *ConnectionStatus) string {
	if previous == nil {
		return ""
	}
	return strings.TrimSpace(previous.RemoteUserID)
}

func previousConnectionVirtualIP(previous *ConnectionStatus) string {
	if previous == nil {
		return ""
	}
	return strings.TrimSpace(previous.RemoteVirtualIP)
}

func previousConnectionCandidates(previous *ConnectionStatus) []string {
	if previous == nil || len(previous.RemoteCandidates) == 0 {
		return nil
	}
	out := make([]string, 0, len(previous.RemoteCandidates))
	seen := make(map[string]struct{}, len(previous.RemoteCandidates))
	for _, candidate := range previous.RemoteCandidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func remoteEndpointKey(connection ConnectionStatus) string {
	parts := make([]string, 0, len(connection.RemoteCandidates)+1)
	if endpoint := strings.TrimSpace(connection.RemoteEndpoint); endpoint != "" {
		parts = append(parts, endpoint)
	}
	for _, candidate := range connection.RemoteCandidates {
		if address := strings.TrimSpace(candidate); address != "" {
			parts = append(parts, address)
		}
	}
	return strings.Join(parts, "|")
}

func candidateAddresses(candidates []controlclient.SignalCandidate) []string {
	if len(candidates) == 0 {
		return nil
	}
	sorted := append([]controlclient.SignalCandidate(nil), candidates...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Preference != sorted[j].Preference {
			return sorted[i].Preference > sorted[j].Preference
		}
		return sorted[i].CreatedAtUnix > sorted[j].CreatedAtUnix
	})
	out := make([]string, 0, len(sorted))
	for _, candidate := range sorted {
		if strings.EqualFold(strings.TrimSpace(candidate.Type), "RELAY") {
			continue
		}
		address := strings.TrimSpace(candidate.Address)
		if address != "" {
			out = append(out, address)
		}
	}
	return out
}

func relayCandidateAddresses(candidates []controlclient.SignalCandidate) []string {
	if len(candidates) == 0 {
		return nil
	}
	sorted := append([]controlclient.SignalCandidate(nil), candidates...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Preference != sorted[j].Preference {
			return sorted[i].Preference > sorted[j].Preference
		}
		return sorted[i].CreatedAtUnix > sorted[j].CreatedAtUnix
	})
	out := make([]string, 0, len(sorted))
	for _, candidate := range sorted {
		if !strings.EqualFold(strings.TrimSpace(candidate.Type), "RELAY") {
			continue
		}
		address := strings.TrimSpace(candidate.Address)
		if address != "" {
			out = append(out, address)
		}
	}
	return out
}

func isTransportEligibleConnection(connection ConnectionStatus) bool {
	return !strings.EqualFold(strings.TrimSpace(connection.State), "IDLE")
}
