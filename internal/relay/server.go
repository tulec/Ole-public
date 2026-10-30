package relay

import (
	"Ole/internal/structuredlog"
	"Ole/internal/transportauth"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const protocolMagic = transportauth.RelayMagic

type Authorizer interface {
	AuthorizeBind(accessToken, peerID string) error
	AuthorizeSend(accessToken, sourcePeerID, targetPeerID string) error
}

type Config struct {
	QuotaWindow             time.Duration
	MaxPacketsPerPeerWindow int
	MaxBytesPerPeerWindow   int64
	AbuseWindow             time.Duration
	AbuseThreshold          int
	AbuseBlockDuration      time.Duration
}

type PeerUsageSnapshot struct {
	PeerID                  string `json:"peerId"`
	WindowStartedAtUnix     int64  `json:"windowStartedAtUnix"`
	WindowEndsAtUnix        int64  `json:"windowEndsAtUnix"`
	ForwardedPackets        int    `json:"forwardedPackets"`
	ForwardedBytes          int64  `json:"forwardedBytes"`
	QuotaExceededCount      int    `json:"quotaExceededCount"`
	LastForwardedAtUnix     int64  `json:"lastForwardedAtUnix"`
	LastQuotaExceededAtUnix int64  `json:"lastQuotaExceededAtUnix"`
}

type StatusSnapshot struct {
	OversizedPackets        uint64                `json:"oversizedPackets"`
	ListenAddress           string                `json:"listenAddress"`
	StartedAtUnix           int64                 `json:"startedAtUnix"`
	ActiveBindings          int                   `json:"activeBindings"`
	TotalBindRequests       int                   `json:"totalBindRequests"`
	SuccessfulBinds         int                   `json:"successfulBinds"`
	BindDenials             int                   `json:"bindDenials"`
	TotalSendRequests       int                   `json:"totalSendRequests"`
	ForwardedPackets        int                   `json:"forwardedPackets"`
	ForwardedBytes          int64                 `json:"forwardedBytes"`
	SendDenials             int                   `json:"sendDenials"`
	QuotaDenials            int                   `json:"quotaDenials"`
	QuotaWindowSeconds      int64                 `json:"quotaWindowSeconds"`
	MaxPacketsPerPeerWindow int                   `json:"maxPacketsPerPeerWindow"`
	MaxBytesPerPeerWindow   int64                 `json:"maxBytesPerPeerWindow"`
	MalformedPackets        int                   `json:"malformedPackets"`
	AbuseDenials            int                   `json:"abuseDenials"`
	AbuseAlerts             int                   `json:"abuseAlerts"`
	AbuseBlockedSources     int                   `json:"abuseBlockedSources"`
	AbuseWindowSeconds      int64                 `json:"abuseWindowSeconds"`
	AbuseThreshold          int                   `json:"abuseThreshold"`
	AbuseBlockSeconds       int64                 `json:"abuseBlockSeconds"`
	Peers                   []PeerUsageSnapshot   `json:"peers"`
	Sources                 []SourceAbuseSnapshot `json:"sources"`
}

type SourceAbuseSnapshot struct {
	SourceIP            string `json:"sourceIp"`
	WindowStartedAtUnix int64  `json:"windowStartedAtUnix"`
	WindowEndsAtUnix    int64  `json:"windowEndsAtUnix"`
	Strikes             int    `json:"strikes"`
	MalformedCount      int    `json:"malformedCount"`
	AuthDeniedCount     int    `json:"authDeniedCount"`
	QuotaDeniedCount    int    `json:"quotaDeniedCount"`
	BlockedCount        int    `json:"blockedCount"`
	BlockedUntilUnix    int64  `json:"blockedUntilUnix"`
	LastReason          string `json:"lastReason"`
	LastDetectedAtUnix  int64  `json:"lastDetectedAtUnix"`
}

type peerUsage struct {
	windowStartedAt     time.Time
	forwardedPackets    int
	forwardedBytes      int64
	quotaExceededCount  int
	lastForwardedAt     time.Time
	lastQuotaExceededAt time.Time
}

type sourceAbuse struct {
	windowStartedAt  time.Time
	strikes          int
	malformedCount   int
	authDeniedCount  int
	quotaDeniedCount int
	blockedCount     int
	blockedUntil     time.Time
	lastReason       string
	lastDetectedAt   time.Time
}

type Server struct {
	oversizedPackets uint64
	conn             *net.UDPConn
	authorizer       Authorizer
	config           Config
	startedAt        time.Time
	logger           *structuredlog.Logger

	mu                sync.Mutex
	bindings          map[string]*net.UDPAddr
	peerUsage         map[string]*peerUsage
	sourceAbuse       map[string]*sourceAbuse
	totalBindRequests int
	successfulBinds   int
	bindDenials       int
	totalSendRequests int
	forwardedPackets  int
	forwardedBytes    int64
	sendDenials       int
	quotaDenials      int
	malformedPackets  int
	abuseDenials      int
	abuseAlerts       int
	shutdown          chan struct{}
}

func Listen(address string, authorizer Authorizer) (*Server, error) {
	return ListenWithConfig(address, authorizer, Config{})
}

func ListenWithConfig(address string, authorizer Authorizer, config Config) (*Server, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", strings.TrimSpace(address))
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	server := &Server{
		conn:        conn,
		authorizer:  authorizer,
		config:      normalizeConfig(config),
		startedAt:   time.Now(),
		logger:      structuredlog.New("server.relay"),
		bindings:    map[string]*net.UDPAddr{},
		peerUsage:   map[string]*peerUsage{},
		sourceAbuse: map[string]*sourceAbuse{},
		shutdown:    make(chan struct{}),
	}
	if server.logger != nil {
		server.logger.Info("relay server listening", "listenAddress", conn.LocalAddr().String())
	}
	go server.serve()
	return server, nil
}

func (s *Server) LocalAddr() net.Addr {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

func (s *Server) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	close(s.shutdown)
	return s.conn.Close()
}

func (s *Server) Snapshot() StatusSnapshot {
	if s == nil {
		return StatusSnapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot := StatusSnapshot{
		OversizedPackets:        s.oversizedPackets,
		StartedAtUnix:           s.startedAt.Unix(),
		ActiveBindings:          len(s.bindings),
		TotalBindRequests:       s.totalBindRequests,
		SuccessfulBinds:         s.successfulBinds,
		BindDenials:             s.bindDenials,
		TotalSendRequests:       s.totalSendRequests,
		ForwardedPackets:        s.forwardedPackets,
		ForwardedBytes:          s.forwardedBytes,
		SendDenials:             s.sendDenials,
		QuotaDenials:            s.quotaDenials,
		QuotaWindowSeconds:      int64(s.config.QuotaWindow / time.Second),
		MaxPacketsPerPeerWindow: s.config.MaxPacketsPerPeerWindow,
		MaxBytesPerPeerWindow:   s.config.MaxBytesPerPeerWindow,
		MalformedPackets:        s.malformedPackets,
		AbuseDenials:            s.abuseDenials,
		AbuseAlerts:             s.abuseAlerts,
		AbuseWindowSeconds:      int64(s.config.AbuseWindow / time.Second),
		AbuseThreshold:          s.config.AbuseThreshold,
		AbuseBlockSeconds:       int64(s.config.AbuseBlockDuration / time.Second),
		Peers:                   make([]PeerUsageSnapshot, 0, len(s.peerUsage)),
		Sources:                 make([]SourceAbuseSnapshot, 0, len(s.sourceAbuse)),
	}
	if s.conn != nil && s.conn.LocalAddr() != nil {
		snapshot.ListenAddress = s.conn.LocalAddr().String()
	}
	for peerID, usage := range s.peerUsage {
		if usage == nil {
			continue
		}
		item := PeerUsageSnapshot{
			PeerID:             peerID,
			ForwardedPackets:   usage.forwardedPackets,
			ForwardedBytes:     usage.forwardedBytes,
			QuotaExceededCount: usage.quotaExceededCount,
		}
		if !usage.windowStartedAt.IsZero() {
			item.WindowStartedAtUnix = usage.windowStartedAt.Unix()
			if s.config.QuotaWindow > 0 {
				item.WindowEndsAtUnix = usage.windowStartedAt.Add(s.config.QuotaWindow).Unix()
			}
		}
		if !usage.lastForwardedAt.IsZero() {
			item.LastForwardedAtUnix = usage.lastForwardedAt.Unix()
		}
		if !usage.lastQuotaExceededAt.IsZero() {
			item.LastQuotaExceededAtUnix = usage.lastQuotaExceededAt.Unix()
		}
		snapshot.Peers = append(snapshot.Peers, item)
	}
	for sourceIP, abuse := range s.sourceAbuse {
		if abuse == nil {
			continue
		}
		item := SourceAbuseSnapshot{
			SourceIP:         sourceIP,
			Strikes:          abuse.strikes,
			MalformedCount:   abuse.malformedCount,
			AuthDeniedCount:  abuse.authDeniedCount,
			QuotaDeniedCount: abuse.quotaDeniedCount,
			BlockedCount:     abuse.blockedCount,
			LastReason:       abuse.lastReason,
		}
		if !abuse.windowStartedAt.IsZero() {
			item.WindowStartedAtUnix = abuse.windowStartedAt.Unix()
			if s.config.AbuseWindow > 0 {
				item.WindowEndsAtUnix = abuse.windowStartedAt.Add(s.config.AbuseWindow).Unix()
			}
		}
		if !abuse.lastDetectedAt.IsZero() {
			item.LastDetectedAtUnix = abuse.lastDetectedAt.Unix()
		}
		if !abuse.blockedUntil.IsZero() {
			item.BlockedUntilUnix = abuse.blockedUntil.Unix()
			if abuse.blockedUntil.After(time.Now()) {
				snapshot.AbuseBlockedSources++
			}
		}
		snapshot.Sources = append(snapshot.Sources, item)
	}
	sort.Slice(snapshot.Peers, func(i, j int) bool {
		return snapshot.Peers[i].PeerID < snapshot.Peers[j].PeerID
	})
	sort.Slice(snapshot.Sources, func(i, j int) bool {
		return snapshot.Sources[i].SourceIP < snapshot.Sources[j].SourceIP
	})
	return snapshot
}

func (s *Server) serve() {
	buffer := make([]byte, transportauth.DatagramBudget+1)
	for {
		n, remoteAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			if transportauth.IsMessageSizeError(err) {
				s.mu.Lock()
				s.oversizedPackets++
				s.mu.Unlock()
				continue
			}
			select {
			case <-s.shutdown:
				return
			default:
				return
			}
		}
		if remoteAddr == nil {
			continue
		}
		if n > transportauth.DatagramBudget {
			s.mu.Lock()
			s.oversizedPackets++
			s.mu.Unlock()
			continue
		}
		now := time.Now()
		sourceIP := sourceIPFromAddr(remoteAddr)
		parts, decodeErr := transportauth.DecodeRelay(buffer[:n])
		if decodeErr != nil {
			s.observeAbuse(sourceIP, abuseReasonMalformed, now)
			continue
		}
		switch parts[0] {
		case "bind":
			s.handleBind(parts, remoteAddr, sourceIP, now)
		case "send":
			s.handleSend(parts, remoteAddr, sourceIP, now)
		default:
			s.observeAbuse(sourceIP, abuseReasonMalformed, now)
		}
	}
}

func (s *Server) handleBind(parts []string, remoteAddr *net.UDPAddr, sourceIP string, now time.Time) {
	if len(parts) != 4 {
		s.observeAbuse(sourceIP, abuseReasonMalformed, now)
		return
	}
	if s.isBlocked(sourceIP, now) {
		_ = s.sendMessage(remoteAddr.String(), formatMessage("error", "source_blocked", "", "relay source is temporarily blocked"))
		return
	}
	accessToken := strings.TrimSpace(parts[1])
	peerID := strings.TrimSpace(parts[2])
	nonce := strings.TrimSpace(parts[3])
	if peerID == "" || nonce == "" {
		s.observeAbuse(sourceIP, abuseReasonMalformed, now)
		return
	}
	s.mu.Lock()
	s.totalBindRequests++
	s.mu.Unlock()
	if s.authorizer != nil {
		if err := s.authorizer.AuthorizeBind(accessToken, peerID); err != nil {
			s.mu.Lock()
			s.bindDenials++
			s.mu.Unlock()
			s.observeAbuse(sourceIP, abuseReasonAuthDenied, now)
			_ = s.sendMessage(remoteAddr.String(), formatMessage("error", "bind_denied", peerID, err.Error()))
			return
		}
	}

	s.mu.Lock()
	s.bindings[peerID] = cloneUDPAddr(remoteAddr)
	s.successfulBinds++
	s.mu.Unlock()
	_ = s.sendMessage(remoteAddr.String(), formatMessage("bound", peerID, nonce))
}

func (s *Server) handleSend(parts []string, remoteAddr *net.UDPAddr, sourceIP string, now time.Time) {
	if len(parts) != 5 {
		s.observeAbuse(sourceIP, abuseReasonMalformed, now)
		return
	}
	if s.isBlocked(sourceIP, now) {
		_ = s.sendMessage(remoteAddr.String(), formatMessage("error", "source_blocked", "", "relay source is temporarily blocked"))
		return
	}
	accessToken := strings.TrimSpace(parts[1])
	sourcePeerID := strings.TrimSpace(parts[2])
	targetPeerID := strings.TrimSpace(parts[3])
	payloadHex := strings.TrimSpace(parts[4])
	if sourcePeerID == "" || targetPeerID == "" || payloadHex == "" {
		s.observeAbuse(sourceIP, abuseReasonMalformed, now)
		return
	}
	s.mu.Lock()
	s.totalSendRequests++
	s.mu.Unlock()
	if s.authorizer != nil {
		if err := s.authorizer.AuthorizeSend(accessToken, sourcePeerID, targetPeerID); err != nil {
			s.mu.Lock()
			s.sendDenials++
			s.mu.Unlock()
			s.observeAbuse(sourceIP, abuseReasonAuthDenied, now)
			_ = s.sendMessage(remoteAddr.String(), formatMessage("error", "send_denied", targetPeerID, err.Error()))
			return
		}
	}
	payload, err := hex.DecodeString(payloadHex)
	if err != nil {
		s.mu.Lock()
		s.sendDenials++
		s.mu.Unlock()
		s.observeAbuse(sourceIP, abuseReasonMalformed, now)
		_ = s.sendMessage(remoteAddr.String(), formatMessage("error", "invalid_payload", targetPeerID, err.Error()))
		return
	}

	payloadBytes, sizeErr := transportauth.RelayPayloadBytes(payload)
	if sizeErr != nil {
		s.observeAbuse(sourceIP, abuseReasonMalformed, now)
		return
	}
	s.mu.Lock()
	s.bindings[sourcePeerID] = cloneUDPAddr(remoteAddr)
	targetAddr := cloneUDPAddr(s.bindings[targetPeerID])
	if quotaErr := s.consumeQuotaLocked(sourcePeerID, int64(payloadBytes), now); quotaErr != nil {
		s.quotaDenials++
		s.mu.Unlock()
		s.observeAbuse(sourceIP, abuseReasonQuotaDenied, now)
		_ = s.sendMessage(remoteAddr.String(), formatMessage("error", "quota_exceeded", targetPeerID, quotaErr.Error()))
		return
	}
	s.forwardedPackets++
	s.forwardedBytes += int64(payloadBytes)
	s.mu.Unlock()
	if targetAddr == nil {
		s.mu.Lock()
		s.sendDenials++
		s.forwardedPackets--
		s.forwardedBytes -= int64(payloadBytes)
		s.rollbackQuotaLocked(sourcePeerID, int64(payloadBytes))
		s.mu.Unlock()
		_ = s.sendMessage(remoteAddr.String(), formatMessage("error", "target_unbound", targetPeerID, "target peer is not bound"))
		return
	}
	_ = s.sendMessage(targetAddr.String(), formatMessage("deliver", sourcePeerID, hex.EncodeToString(payload)))
}

func normalizeConfig(config Config) Config {
	if config.QuotaWindow < 0 {
		config.QuotaWindow = 0
	}
	if config.MaxPacketsPerPeerWindow < 0 {
		config.MaxPacketsPerPeerWindow = 0
	}
	if config.MaxBytesPerPeerWindow < 0 {
		config.MaxBytesPerPeerWindow = 0
	}
	if config.QuotaWindow == 0 && (config.MaxPacketsPerPeerWindow > 0 || config.MaxBytesPerPeerWindow > 0) {
		config.QuotaWindow = time.Minute
	}
	if config.AbuseWindow < 0 {
		config.AbuseWindow = 0
	}
	if config.AbuseThreshold < 0 {
		config.AbuseThreshold = 0
	}
	if config.AbuseBlockDuration < 0 {
		config.AbuseBlockDuration = 0
	}
	if config.AbuseThreshold > 0 && config.AbuseWindow == 0 {
		config.AbuseWindow = time.Minute
	}
	if config.AbuseThreshold > 0 && config.AbuseBlockDuration == 0 {
		config.AbuseBlockDuration = 5 * time.Minute
	}
	return config
}

func (s *Server) consumeQuotaLocked(peerID string, payloadBytes int64, now time.Time) error {
	if s == nil {
		return nil
	}
	usage := s.ensurePeerUsageLocked(peerID, now)
	if s.config.quotasEnabled() && s.config.MaxPacketsPerPeerWindow > 0 && usage.forwardedPackets+1 > s.config.MaxPacketsPerPeerWindow {
		usage.quotaExceededCount++
		usage.lastQuotaExceededAt = now
		return fmt.Errorf("packet quota exceeded")
	}
	if s.config.quotasEnabled() && s.config.MaxBytesPerPeerWindow > 0 && usage.forwardedBytes+payloadBytes > s.config.MaxBytesPerPeerWindow {
		usage.quotaExceededCount++
		usage.lastQuotaExceededAt = now
		return fmt.Errorf("byte quota exceeded")
	}
	usage.forwardedPackets++
	usage.forwardedBytes += payloadBytes
	usage.lastForwardedAt = now
	return nil
}

func (s *Server) rollbackQuotaLocked(peerID string, payloadBytes int64) {
	if s == nil {
		return
	}
	usage := s.peerUsage[peerID]
	if usage == nil {
		return
	}
	if usage.forwardedPackets > 0 {
		usage.forwardedPackets--
	}
	if usage.forwardedBytes >= payloadBytes {
		usage.forwardedBytes -= payloadBytes
	} else {
		usage.forwardedBytes = 0
	}
}

func (s *Server) ensurePeerUsageLocked(peerID string, now time.Time) *peerUsage {
	usage := s.peerUsage[peerID]
	if usage == nil {
		usage = &peerUsage{}
		s.peerUsage[peerID] = usage
	}
	if usage.windowStartedAt.IsZero() {
		usage.windowStartedAt = now
	}
	if s.config.quotasEnabled() && s.config.QuotaWindow > 0 && now.Sub(usage.windowStartedAt) >= s.config.QuotaWindow {
		usage.windowStartedAt = now
		usage.forwardedPackets = 0
		usage.forwardedBytes = 0
	}
	return usage
}

func (c Config) quotasEnabled() bool {
	return c.QuotaWindow > 0 && (c.MaxPacketsPerPeerWindow > 0 || c.MaxBytesPerPeerWindow > 0)
}

func (c Config) abuseControlsEnabled() bool {
	return c.AbuseWindow > 0 && c.AbuseThreshold > 0 && c.AbuseBlockDuration > 0
}

type abuseReason string

const (
	abuseReasonMalformed   abuseReason = "malformed"
	abuseReasonAuthDenied  abuseReason = "auth_denied"
	abuseReasonQuotaDenied abuseReason = "quota_denied"
)

func (s *Server) isBlocked(sourceIP string, now time.Time) bool {
	if s == nil || sourceIP == "" || !s.config.abuseControlsEnabled() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	abuse := s.ensureSourceAbuseLocked(sourceIP, now)
	if abuse == nil || abuse.blockedUntil.IsZero() || !abuse.blockedUntil.After(now) {
		return false
	}
	s.abuseDenials++
	return true
}

func (s *Server) observeAbuse(sourceIP string, reason abuseReason, now time.Time) {
	if s == nil || sourceIP == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if reason == abuseReasonMalformed {
		s.malformedPackets++
	}
	abuse := s.ensureSourceAbuseLocked(sourceIP, now)
	if abuse == nil {
		return
	}
	switch reason {
	case abuseReasonMalformed:
		abuse.malformedCount++
	case abuseReasonAuthDenied:
		abuse.authDeniedCount++
	case abuseReasonQuotaDenied:
		abuse.quotaDeniedCount++
	}
	abuse.strikes++
	abuse.lastReason = string(reason)
	abuse.lastDetectedAt = now
	if s.config.abuseControlsEnabled() && abuse.strikes >= s.config.AbuseThreshold && !abuse.blockedUntil.After(now) {
		abuse.blockedCount++
		abuse.blockedUntil = now.Add(s.config.AbuseBlockDuration)
		s.abuseAlerts++
		if s.logger != nil {
			s.logger.Info("relay abuse alert raised", "sourceIp", sourceIP, "reason", reason, "strikes", abuse.strikes, "blockedUntilUnix", abuse.blockedUntil.Unix())
		}
	}
}

func (s *Server) ensureSourceAbuseLocked(sourceIP string, now time.Time) *sourceAbuse {
	if sourceIP == "" {
		return nil
	}
	abuse := s.sourceAbuse[sourceIP]
	if abuse == nil {
		abuse = &sourceAbuse{}
		s.sourceAbuse[sourceIP] = abuse
	}
	if abuse.windowStartedAt.IsZero() {
		abuse.windowStartedAt = now
	}
	if s.config.abuseControlsEnabled() && now.Sub(abuse.windowStartedAt) >= s.config.AbuseWindow {
		blockedCount := abuse.blockedCount
		blockedUntil := abuse.blockedUntil
		*abuse = sourceAbuse{
			windowStartedAt: now,
			blockedCount:    blockedCount,
			blockedUntil:    blockedUntil,
		}
	}
	if !abuse.blockedUntil.IsZero() && !abuse.blockedUntil.After(now) && abuse.lastDetectedAt.Add(s.config.AbuseWindow).Before(now) {
		delete(s.sourceAbuse, sourceIP)
		return nil
	}
	return abuse
}

func sourceIPFromAddr(addr *net.UDPAddr) string {
	if addr == nil || addr.IP == nil {
		return ""
	}
	return addr.IP.String()
}

func (s *Server) sendMessage(remoteCandidate, message string) error {
	remoteAddr, err := net.ResolveUDPAddr("udp", strings.TrimSpace(remoteCandidate))
	if err != nil {
		return err
	}
	data, encodeErr := transportauth.EncodeRelay(message)
	if encodeErr != nil {
		return encodeErr
	}
	_, err = s.conn.WriteToUDP(data, remoteAddr)
	return err
}

func formatMessage(parts ...string) string {
	return strings.Join(append([]string{protocolMagic}, parts...), "|")
}

func parseMessage(message string) ([]string, bool) {
	parts := strings.Split(strings.TrimSpace(message), "|")
	if len(parts) < 2 || parts[0] != protocolMagic {
		return nil, false
	}
	return parts[1:], true
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	copy := *addr
	if addr.IP != nil {
		copy.IP = append(net.IP(nil), addr.IP...)
	}
	return &copy
}

type StaticAuthorizer struct{}

func (StaticAuthorizer) AuthorizeBind(_, _ string) error {
	return nil
}

func (StaticAuthorizer) AuthorizeSend(_, _, _ string) error {
	return nil
}

func WaitForPacket(conn *net.UDPConn, timeout time.Duration) (string, error) {
	if conn == nil {
		return "", fmt.Errorf("udp conn is required")
	}
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}
	buffer := make([]byte, transportauth.DatagramBudget+1)
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return "", err
	}
	parts, decodeErr := transportauth.DecodeRelay(buffer[:n])
	if decodeErr != nil {
		return "", decodeErr
	}
	return transportauth.RelayText(parts), nil
}
