package clientagent

import (
	"Ole/internal/transportauth"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type StateStore struct {
	path string
}

type PersistentState struct {
	DeviceName          string                    `json:"deviceName"`
	PublicKey           string                    `json:"publicKey"`
	PrivateKey          string                    `json:"privateKey"`
	AdapterMTU          int                       `json:"adapterMtu"`
	UpdateChannel       string                    `json:"updateChannel"`
	Lifecycle           ServiceLifecycleState     `json:"lifecycle"`
	AuditPresets        []AuditFilterPreset       `json:"auditPresets"`
	Enrollments         []DeviceEnrollment        `json:"enrollments"`
	Sessions            []SessionState            `json:"sessions"`
	ManagedPeers        []ManagedPeerState        `json:"managedPeers"`
	FileTransferSources []FileTransferSourceState `json:"fileTransferSources"`
	FileTransferCaches  []FileTransferCacheState  `json:"fileTransferCaches"`
}

type ServiceLifecycleState struct {
	Dirty                    bool   `json:"dirty"`
	LastStartUnix            int64  `json:"lastStartUnix"`
	LastCleanShutdownUnix    int64  `json:"lastCleanShutdownUnix"`
	LastCrashRecoveryUnix    int64  `json:"lastCrashRecoveryUnix"`
	CrashRecoveryCount       int    `json:"crashRecoveryCount"`
	ReconnectAttemptCount    int    `json:"reconnectAttemptCount"`
	LastReconnectAttemptUnix int64  `json:"lastReconnectAttemptUnix"`
	NextReconnectAttemptUnix int64  `json:"nextReconnectAttemptUnix"`
	LastReconnectError       string `json:"lastReconnectError"`
}

type DeviceEnrollment struct {
	ServerBaseURL string `json:"serverBaseUrl"`
	UserID        string `json:"userId"`
	DeviceID      string `json:"deviceId"`
}

type SessionState struct {
	ServerBaseURL string `json:"serverBaseUrl"`
	UserID        string `json:"userId"`
	DeviceID      string `json:"deviceId"`
	AccessToken   string `json:"accessToken"`
	RefreshToken  string `json:"refreshToken"`
	ExpiresAtUnix int64  `json:"expiresAtUnix"`
}

type ManagedPeerState struct {
	ServerBaseURL string `json:"serverBaseUrl"`
	UserID        string `json:"userId"`
	NetworkID     string `json:"networkId"`
	PeerID        string `json:"peerId"`
	Endpoint      string `json:"endpoint"`
	OverlayCIDR   string `json:"overlayCidr"`
	VirtualIP     string `json:"virtualIp"`
}

type FileTransferSourceState struct {
	ServerBaseURL  string `json:"serverBaseUrl"`
	UserID         string `json:"userId"`
	TransferID     string `json:"transferId"`
	NetworkID      string `json:"networkId"`
	LocalPeerID    string `json:"localPeerId"`
	RemotePeerID   string `json:"remotePeerId"`
	RemoteUserID   string `json:"remoteUserId"`
	SourcePath     string `json:"sourcePath"`
	FileName       string `json:"fileName"`
	ContentType    string `json:"contentType"`
	PayloadSHA256  string `json:"payloadSha256"`
	SizeBytes      int64  `json:"sizeBytes"`
	UploadedAtUnix int64  `json:"uploadedAtUnix"`
}

type FileTransferCacheState struct {
	ServerBaseURL  string `json:"serverBaseUrl"`
	UserID         string `json:"userId"`
	TransferID     string `json:"transferId"`
	NetworkID      string `json:"networkId"`
	LocalPeerID    string `json:"localPeerId"`
	RemotePeerID   string `json:"remotePeerId"`
	CachePath      string `json:"cachePath"`
	FileName       string `json:"fileName"`
	ContentType    string `json:"contentType"`
	PayloadSHA256  string `json:"payloadSha256"`
	SizeBytes      int64  `json:"sizeBytes"`
	CachedBytes    int64  `json:"cachedBytes"`
	UploadedAtUnix int64  `json:"uploadedAtUnix"`
}

func NewStateStore(path string) *StateStore {
	normalized := strings.TrimSpace(path)
	if normalized == "" {
		normalized = DefaultStatePath()
	}
	return &StateStore{path: normalized}
}

func DefaultStatePath() string {
	override := strings.TrimSpace(os.Getenv("OLE_AGENT_STATE_PATH"))
	if override != "" {
		return override
	}
	configDir, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(configDir) == "" {
		return "ole-agent-state.json"
	}
	return filepath.Join(configDir, "Ole", "agent-state.json")
}

func (s *StateStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

func (s *StateStore) Load() (*PersistentState, error) {
	if s == nil {
		return defaultPersistentState(), nil
	}
	lock := stateFileLock(s.path)
	lock.RLock()
	defer lock.RUnlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultPersistentState(), nil
		}
		return nil, err
	}
	var state PersistentState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode agent state: %w", err)
	}
	state.normalize()
	return &state, nil
}

func (s *StateStore) Save(state *PersistentState) error {
	if s == nil || state == nil {
		return nil
	}
	lock := stateFileLock(s.path)
	lock.Lock()
	defer lock.Unlock()
	state.normalize()
	if dir := filepath.Dir(s.path); strings.TrimSpace(dir) != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return replaceStateFile(s.path, data)
}

func defaultPersistentState() *PersistentState {
	return &PersistentState{
		DeviceName: defaultDeviceName(),
		AdapterMTU: transportauth.DefaultAdapterMTU,
	}
}

func defaultDeviceName() string {
	hostname, err := os.Hostname()
	if err == nil && strings.TrimSpace(hostname) != "" {
		return strings.TrimSpace(hostname)
	}
	return "Ole Desktop"
}

func (s *PersistentState) normalize() {
	if strings.TrimSpace(s.DeviceName) == "" {
		s.DeviceName = defaultDeviceName()
	}
	if s.AdapterMTU < 576 {
		s.AdapterMTU = transportauth.DefaultAdapterMTU
	}
	if s.AdapterMTU > transportauth.MaxMessageBytes {
		s.AdapterMTU = transportauth.MaxMessageBytes
	}
	s.UpdateChannel = strings.ToLower(strings.TrimSpace(s.UpdateChannel))
	if s.Lifecycle.CrashRecoveryCount < 0 {
		s.Lifecycle.CrashRecoveryCount = 0
	}
	if s.Lifecycle.ReconnectAttemptCount < 0 {
		s.Lifecycle.ReconnectAttemptCount = 0
	}
	s.AuditPresets = normalizeAuditFilterPresets(s.AuditPresets)
	if s.Enrollments == nil {
		s.Enrollments = []DeviceEnrollment{}
	}
	if s.Sessions == nil {
		s.Sessions = []SessionState{}
	}
	if s.ManagedPeers == nil {
		s.ManagedPeers = []ManagedPeerState{}
	}
	if s.FileTransferSources == nil {
		s.FileTransferSources = []FileTransferSourceState{}
	} else {
		filtered := s.FileTransferSources[:0]
		for _, source := range s.FileTransferSources {
			source.ServerBaseURL = strings.TrimSpace(source.ServerBaseURL)
			source.UserID = strings.TrimSpace(source.UserID)
			source.TransferID = strings.TrimSpace(source.TransferID)
			source.NetworkID = strings.TrimSpace(source.NetworkID)
			source.LocalPeerID = strings.TrimSpace(source.LocalPeerID)
			source.RemotePeerID = strings.TrimSpace(source.RemotePeerID)
			source.RemoteUserID = strings.TrimSpace(source.RemoteUserID)
			source.SourcePath = strings.TrimSpace(source.SourcePath)
			source.FileName = strings.TrimSpace(source.FileName)
			source.ContentType = strings.TrimSpace(source.ContentType)
			source.PayloadSHA256 = strings.TrimSpace(source.PayloadSHA256)
			if source.SizeBytes < 0 {
				source.SizeBytes = 0
			}
			if source.ServerBaseURL == "" || source.UserID == "" || source.TransferID == "" || source.NetworkID == "" || source.LocalPeerID == "" || source.RemotePeerID == "" || source.SourcePath == "" {
				continue
			}
			filtered = append(filtered, source)
		}
		s.FileTransferSources = filtered
	}
	if s.FileTransferCaches == nil {
		s.FileTransferCaches = []FileTransferCacheState{}
	} else {
		filtered := s.FileTransferCaches[:0]
		for _, cache := range s.FileTransferCaches {
			cache.ServerBaseURL = strings.TrimSpace(cache.ServerBaseURL)
			cache.UserID = strings.TrimSpace(cache.UserID)
			cache.TransferID = strings.TrimSpace(cache.TransferID)
			cache.NetworkID = strings.TrimSpace(cache.NetworkID)
			cache.LocalPeerID = strings.TrimSpace(cache.LocalPeerID)
			cache.RemotePeerID = strings.TrimSpace(cache.RemotePeerID)
			cache.CachePath = strings.TrimSpace(cache.CachePath)
			cache.FileName = strings.TrimSpace(cache.FileName)
			cache.ContentType = strings.TrimSpace(cache.ContentType)
			cache.PayloadSHA256 = strings.TrimSpace(cache.PayloadSHA256)
			if cache.SizeBytes < 0 {
				cache.SizeBytes = 0
			}
			if cache.CachedBytes < 0 {
				cache.CachedBytes = 0
			}
			if cache.CachedBytes > cache.SizeBytes && cache.SizeBytes > 0 {
				cache.CachedBytes = cache.SizeBytes
			}
			if cache.ServerBaseURL == "" || cache.UserID == "" || cache.TransferID == "" || cache.NetworkID == "" || cache.LocalPeerID == "" || cache.RemotePeerID == "" || cache.CachePath == "" {
				continue
			}
			filtered = append(filtered, cache)
		}
		s.FileTransferCaches = filtered
	}
}

func (s *PersistentState) MarkServiceStarted(nowUnix int64) bool {
	s.normalize()
	unclean := s.Lifecycle.Dirty
	s.Lifecycle.Dirty = true
	s.Lifecycle.LastStartUnix = nowUnix
	if unclean {
		s.Lifecycle.LastCrashRecoveryUnix = nowUnix
		s.Lifecycle.CrashRecoveryCount++
	}
	return unclean
}

func (s *PersistentState) MarkServiceStopped(nowUnix int64) {
	s.normalize()
	s.Lifecycle.Dirty = false
	s.Lifecycle.LastCleanShutdownUnix = nowUnix
}

func (s *PersistentState) SetReconnectLifecycle(attemptCount int, lastAttemptUnix, nextAttemptUnix int64, lastError string) {
	s.normalize()
	if attemptCount < 0 {
		attemptCount = 0
	}
	s.Lifecycle.ReconnectAttemptCount = attemptCount
	s.Lifecycle.LastReconnectAttemptUnix = lastAttemptUnix
	s.Lifecycle.NextReconnectAttemptUnix = nextAttemptUnix
	s.Lifecycle.LastReconnectError = strings.TrimSpace(lastError)
}

func (s *PersistentState) ClearReconnectLifecycle() {
	s.SetReconnectLifecycle(0, 0, 0, "")
}

func (s *PersistentState) EnsureKeyPair() (bool, error) {
	s.normalize()
	if s.PublicKey != "" && s.PrivateKey != "" {
		return false, nil
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false, err
	}
	s.PublicKey = base64.StdEncoding.EncodeToString(publicKey)
	s.PrivateKey = base64.StdEncoding.EncodeToString(privateKey)
	return true, nil
}

func (s *PersistentState) UpdateChannelOrDefault(defaultChannel string) string {
	s.normalize()
	if strings.TrimSpace(s.UpdateChannel) != "" {
		return s.UpdateChannel
	}
	return strings.ToLower(strings.TrimSpace(defaultChannel))
}

func (s *PersistentState) SetUpdateChannel(channel string) {
	s.normalize()
	s.UpdateChannel = strings.ToLower(strings.TrimSpace(channel))
}

func (s *PersistentState) EnrollmentFor(serverBaseURL, userID string) *DeviceEnrollment {
	for idx := range s.Enrollments {
		if s.Enrollments[idx].ServerBaseURL == serverBaseURL && s.Enrollments[idx].UserID == userID {
			return &s.Enrollments[idx]
		}
	}
	return nil
}

func (s *PersistentState) SetEnrollment(serverBaseURL, userID, deviceID string) {
	for idx := range s.Enrollments {
		if s.Enrollments[idx].ServerBaseURL == serverBaseURL && s.Enrollments[idx].UserID == userID {
			s.Enrollments[idx].DeviceID = deviceID
			return
		}
	}
	s.Enrollments = append(s.Enrollments, DeviceEnrollment{
		ServerBaseURL: serverBaseURL,
		UserID:        userID,
		DeviceID:      deviceID,
	})
}

func (s *PersistentState) SessionFor(serverBaseURL string) *SessionState {
	for idx := range s.Sessions {
		if s.Sessions[idx].ServerBaseURL == serverBaseURL {
			return &s.Sessions[idx]
		}
	}
	return nil
}

func (s *PersistentState) SetSession(serverBaseURL, userID, deviceID string, session *SessionState) {
	if session == nil {
		return
	}
	next := *session
	next.ServerBaseURL = serverBaseURL
	next.UserID = userID
	next.DeviceID = deviceID
	for idx := range s.Sessions {
		if s.Sessions[idx].ServerBaseURL == serverBaseURL {
			s.Sessions[idx] = next
			return
		}
	}
	s.Sessions = append(s.Sessions, next)
}

func (s *PersistentState) ClearSession(serverBaseURL string) {
	filtered := s.Sessions[:0]
	for _, session := range s.Sessions {
		if session.ServerBaseURL != serverBaseURL {
			filtered = append(filtered, session)
		}
	}
	s.Sessions = filtered
}

func (s *PersistentState) ManagedPeersFor(serverBaseURL, userID string) []ManagedPeerState {
	peers := make([]ManagedPeerState, 0, len(s.ManagedPeers))
	for _, peer := range s.ManagedPeers {
		if peer.ServerBaseURL == serverBaseURL && peer.UserID == userID {
			peers = append(peers, peer)
		}
	}
	return peers
}

func (s *PersistentState) SetManagedPeer(serverBaseURL, userID, networkID, peerID, endpoint, overlayCIDR, virtualIP string) {
	for idx := range s.ManagedPeers {
		peer := &s.ManagedPeers[idx]
		if peer.ServerBaseURL == serverBaseURL && peer.UserID == userID && peer.NetworkID == networkID {
			peer.PeerID = peerID
			peer.Endpoint = endpoint
			peer.OverlayCIDR = overlayCIDR
			peer.VirtualIP = virtualIP
			return
		}
	}
	s.ManagedPeers = append(s.ManagedPeers, ManagedPeerState{
		ServerBaseURL: serverBaseURL,
		UserID:        userID,
		NetworkID:     networkID,
		PeerID:        peerID,
		Endpoint:      endpoint,
		OverlayCIDR:   overlayCIDR,
		VirtualIP:     virtualIP,
	})
}

func (s *PersistentState) UpdateManagedPeer(serverBaseURL, userID, peerID, endpoint, overlayCIDR, virtualIP string) {
	for idx := range s.ManagedPeers {
		peer := &s.ManagedPeers[idx]
		if peer.ServerBaseURL == serverBaseURL && peer.UserID == userID && peer.PeerID == peerID {
			peer.Endpoint = endpoint
			if strings.TrimSpace(overlayCIDR) != "" {
				peer.OverlayCIDR = overlayCIDR
			}
			if strings.TrimSpace(virtualIP) != "" {
				peer.VirtualIP = virtualIP
			}
			return
		}
	}
}

func (s *PersistentState) RemoveManagedPeer(serverBaseURL, peerID string) {
	filtered := s.ManagedPeers[:0]
	for _, peer := range s.ManagedPeers {
		if !(peer.ServerBaseURL == serverBaseURL && peer.PeerID == peerID) {
			filtered = append(filtered, peer)
		}
	}
	s.ManagedPeers = filtered
}

func (s *PersistentState) ClearManagedPeers(serverBaseURL, userID string) {
	filtered := s.ManagedPeers[:0]
	for _, peer := range s.ManagedPeers {
		if !(peer.ServerBaseURL == serverBaseURL && peer.UserID == userID) {
			filtered = append(filtered, peer)
		}
	}
	s.ManagedPeers = filtered
}

func (s *PersistentState) FileTransferSourcesFor(serverBaseURL, userID string) []FileTransferSourceState {
	sources := make([]FileTransferSourceState, 0, len(s.FileTransferSources))
	for _, source := range s.FileTransferSources {
		if source.ServerBaseURL == serverBaseURL && source.UserID == userID {
			sources = append(sources, source)
		}
	}
	return sources
}

func (s *PersistentState) SetFileTransferSource(source FileTransferSourceState) {
	source.ServerBaseURL = strings.TrimSpace(source.ServerBaseURL)
	source.UserID = strings.TrimSpace(source.UserID)
	source.TransferID = strings.TrimSpace(source.TransferID)
	source.NetworkID = strings.TrimSpace(source.NetworkID)
	source.LocalPeerID = strings.TrimSpace(source.LocalPeerID)
	source.RemotePeerID = strings.TrimSpace(source.RemotePeerID)
	source.RemoteUserID = strings.TrimSpace(source.RemoteUserID)
	source.SourcePath = strings.TrimSpace(source.SourcePath)
	source.FileName = strings.TrimSpace(source.FileName)
	source.ContentType = strings.TrimSpace(source.ContentType)
	source.PayloadSHA256 = strings.TrimSpace(source.PayloadSHA256)
	if source.ServerBaseURL == "" || source.UserID == "" || source.TransferID == "" || source.NetworkID == "" || source.LocalPeerID == "" || source.RemotePeerID == "" || source.SourcePath == "" {
		return
	}
	if source.SizeBytes < 0 {
		source.SizeBytes = 0
	}
	for idx := range s.FileTransferSources {
		existing := &s.FileTransferSources[idx]
		if existing.ServerBaseURL == source.ServerBaseURL && existing.UserID == source.UserID && existing.TransferID == source.TransferID {
			*existing = source
			return
		}
	}
	s.FileTransferSources = append(s.FileTransferSources, source)
}

func (s *PersistentState) DeleteFileTransferSource(serverBaseURL, userID, transferID string) bool {
	serverBaseURL = strings.TrimSpace(serverBaseURL)
	userID = strings.TrimSpace(userID)
	transferID = strings.TrimSpace(transferID)
	filtered := s.FileTransferSources[:0]
	removed := false
	for _, source := range s.FileTransferSources {
		if source.ServerBaseURL == serverBaseURL && source.UserID == userID && source.TransferID == transferID {
			removed = true
			continue
		}
		filtered = append(filtered, source)
	}
	s.FileTransferSources = filtered
	return removed
}

func (s *PersistentState) ClearFileTransferSources(serverBaseURL, userID string) {
	filtered := s.FileTransferSources[:0]
	for _, source := range s.FileTransferSources {
		if !(source.ServerBaseURL == serverBaseURL && source.UserID == userID) {
			filtered = append(filtered, source)
		}
	}
	s.FileTransferSources = filtered
}

func (s *PersistentState) PruneFileTransferSources(serverBaseURL, userID string, allowedPeerKeys map[string]struct{}) bool {
	serverBaseURL = strings.TrimSpace(serverBaseURL)
	userID = strings.TrimSpace(userID)
	if len(allowedPeerKeys) == 0 {
		before := len(s.FileTransferSources)
		s.ClearFileTransferSources(serverBaseURL, userID)
		return before != len(s.FileTransferSources)
	}
	filtered := s.FileTransferSources[:0]
	changed := false
	for _, source := range s.FileTransferSources {
		if source.ServerBaseURL != serverBaseURL || source.UserID != userID {
			filtered = append(filtered, source)
			continue
		}
		if _, ok := allowedPeerKeys[source.NetworkID+"|"+source.LocalPeerID]; ok {
			filtered = append(filtered, source)
			continue
		}
		changed = true
	}
	s.FileTransferSources = filtered
	return changed
}

func (s *PersistentState) FileTransferCachesFor(serverBaseURL, userID string) []FileTransferCacheState {
	caches := make([]FileTransferCacheState, 0, len(s.FileTransferCaches))
	for _, cache := range s.FileTransferCaches {
		if cache.ServerBaseURL == serverBaseURL && cache.UserID == userID {
			caches = append(caches, cache)
		}
	}
	return caches
}

func (s *PersistentState) SetFileTransferCache(cache FileTransferCacheState) {
	cache.ServerBaseURL = strings.TrimSpace(cache.ServerBaseURL)
	cache.UserID = strings.TrimSpace(cache.UserID)
	cache.TransferID = strings.TrimSpace(cache.TransferID)
	cache.NetworkID = strings.TrimSpace(cache.NetworkID)
	cache.LocalPeerID = strings.TrimSpace(cache.LocalPeerID)
	cache.RemotePeerID = strings.TrimSpace(cache.RemotePeerID)
	cache.CachePath = strings.TrimSpace(cache.CachePath)
	cache.FileName = strings.TrimSpace(cache.FileName)
	cache.ContentType = strings.TrimSpace(cache.ContentType)
	cache.PayloadSHA256 = strings.TrimSpace(cache.PayloadSHA256)
	if cache.ServerBaseURL == "" || cache.UserID == "" || cache.TransferID == "" || cache.NetworkID == "" || cache.LocalPeerID == "" || cache.RemotePeerID == "" || cache.CachePath == "" {
		return
	}
	if cache.SizeBytes < 0 {
		cache.SizeBytes = 0
	}
	if cache.CachedBytes < 0 {
		cache.CachedBytes = 0
	}
	if cache.CachedBytes > cache.SizeBytes && cache.SizeBytes > 0 {
		cache.CachedBytes = cache.SizeBytes
	}
	for idx := range s.FileTransferCaches {
		existing := &s.FileTransferCaches[idx]
		if existing.ServerBaseURL == cache.ServerBaseURL && existing.UserID == cache.UserID && existing.TransferID == cache.TransferID {
			*existing = cache
			return
		}
	}
	s.FileTransferCaches = append(s.FileTransferCaches, cache)
}

func (s *PersistentState) DeleteFileTransferCache(serverBaseURL, userID, transferID string) bool {
	serverBaseURL = strings.TrimSpace(serverBaseURL)
	userID = strings.TrimSpace(userID)
	transferID = strings.TrimSpace(transferID)
	filtered := s.FileTransferCaches[:0]
	removed := false
	for _, cache := range s.FileTransferCaches {
		if cache.ServerBaseURL == serverBaseURL && cache.UserID == userID && cache.TransferID == transferID {
			removed = true
			continue
		}
		filtered = append(filtered, cache)
	}
	s.FileTransferCaches = filtered
	return removed
}

func (s *PersistentState) ClearFileTransferCaches(serverBaseURL, userID string) {
	filtered := s.FileTransferCaches[:0]
	for _, cache := range s.FileTransferCaches {
		if !(cache.ServerBaseURL == serverBaseURL && cache.UserID == userID) {
			filtered = append(filtered, cache)
		}
	}
	s.FileTransferCaches = filtered
}

func (s *PersistentState) PruneFileTransferCaches(serverBaseURL, userID string, allowedPeerKeys map[string]struct{}) bool {
	serverBaseURL = strings.TrimSpace(serverBaseURL)
	userID = strings.TrimSpace(userID)
	if len(allowedPeerKeys) == 0 {
		before := len(s.FileTransferCaches)
		s.ClearFileTransferCaches(serverBaseURL, userID)
		return before != len(s.FileTransferCaches)
	}
	filtered := s.FileTransferCaches[:0]
	changed := false
	for _, cache := range s.FileTransferCaches {
		if cache.ServerBaseURL != serverBaseURL || cache.UserID != userID {
			filtered = append(filtered, cache)
			continue
		}
		if _, ok := allowedPeerKeys[cache.NetworkID+"|"+cache.LocalPeerID]; ok {
			filtered = append(filtered, cache)
			continue
		}
		changed = true
	}
	s.FileTransferCaches = filtered
	return changed
}
