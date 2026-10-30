package directprobe

import (
	"Ole/internal/stun"
	"Ole/internal/transportauth"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const protocolMagic = transportauth.Magic

type Binding struct {
	Credentials   *transportauth.Credentials `json:"-"`
	PeerID        string
	ListenAddress string
}

type Result struct {
	RemoteAddress string
}

type Session struct {
	SessionID         string
	RemoteAddress     string
	EstablishedAtUnix int64
}

type Packet struct {
	identityProof  string
	sessionID      string
	RemotePeerID   string
	Payload        []byte
	ReceivedAtUnix int64
}

type ExchangeHandler func(remotePeerID string, payload []byte) []byte

type Manager interface {
	Reconcile(bindings []Binding) error
	Attempt(localPeerID, remotePeerID string, remoteCandidates []string, timeout time.Duration) (Result, error)
	Establish(localPeerID, remotePeerID string, remoteCandidates []string, timeout time.Duration) (Session, error)
	Exchange(localPeerID, remotePeerID string, payload []byte, timeout time.Duration) ([]byte, error)
	SetExchangeHandler(localPeerID string, handler ExchangeHandler) error
	SendPacket(localPeerID, remotePeerID string, payload []byte) error
	DrainInbound(localPeerID string, limit int) []Packet
	DropSession(localPeerID, remotePeerID string)
	Close() error
}

type pendingHandshake struct {
	remotePeerID string
	waitCh       chan Session
}

type cryptoSession struct {
	identityProof string
	mu            sync.Mutex
	sessionID     string
	remotePeerID  string
	remoteAddr    string
	established   time.Time
	records       *transportauth.Records
}

type listener struct {
	reassembly         *transportauth.ReassemblyPool
	wireStats          transportauth.WireStats
	rejectedHandshakes uint64 // Protected by mu.
	auth               *transportauth.Handshaker
	peerID             string
	address            string
	conn               *net.UDPConn
	mu                 sync.Mutex
	pendingProbes      map[string]chan struct{}
	pendingHandshakes  map[string]pendingHandshake
	pendingDataAcks    map[string]chan []byte
	pendingSTUN        map[string]chan *net.UDPAddr
	sessions           map[string]*cryptoSession
	inbound            transportauth.PacketQueue[Packet]
	recordStats        transportauth.RecordStats
	exchangeHandler    ExchangeHandler
	shutdown           chan struct{}
}

type manager struct {
	mu        sync.Mutex
	listeners map[string]*listener
}

func New() Manager {
	return &manager{
		listeners: map[string]*listener{},
	}
}

func (m *manager) Reconcile(bindings []Binding) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	desired := map[string]Binding{}
	for _, binding := range bindings {
		peerID := strings.TrimSpace(binding.PeerID)
		listenAddress := strings.TrimSpace(binding.ListenAddress)
		if peerID == "" || listenAddress == "" {
			continue
		}
		binding.PeerID, binding.ListenAddress = peerID, listenAddress
		desired[peerID] = binding
	}

	for peerID, existing := range m.listeners {
		binding, ok := desired[peerID]
		if ok && existing.address == binding.ListenAddress {
			if err := existing.updateCredentials(binding.Credentials); err != nil {
				return err
			}
			delete(desired, peerID)
			continue
		}
		_ = existing.close()
		delete(m.listeners, peerID)
	}

	for peerID, binding := range desired {
		udpAddr, err := net.ResolveUDPAddr("udp", binding.ListenAddress)
		if err != nil {
			return err
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return err
		}
		item := &listener{
			reassembly:        transportauth.NewReassemblyPool(),
			auth:              transportauth.New("DIRECT"),
			peerID:            peerID,
			address:           binding.ListenAddress,
			conn:              conn,
			pendingProbes:     map[string]chan struct{}{},
			pendingHandshakes: map[string]pendingHandshake{},
			pendingDataAcks:   map[string]chan []byte{},
			pendingSTUN:       map[string]chan *net.UDPAddr{},
			sessions:          map[string]*cryptoSession{},
			shutdown:          make(chan struct{}),
		}
		if err := item.updateCredentials(binding.Credentials); err != nil {
			item.close()
			return err
		}
		m.listeners[peerID] = item
		go item.serve()
	}

	return nil
}

func (m *manager) Attempt(localPeerID, remotePeerID string, remoteCandidates []string, timeout time.Duration) (Result, error) {
	item, err := m.listenerFor(localPeerID)
	if err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(remotePeerID) == "" {
		return Result{}, fmt.Errorf("remote peer id is required")
	}
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}

	var lastErr error
	for _, candidate := range remoteCandidates {
		address := strings.TrimSpace(candidate)
		if address == "" {
			continue
		}
		nonce, err := newNonce()
		if err != nil {
			return Result{}, err
		}
		waitCh := make(chan struct{}, 1)
		item.registerPendingProbe(nonce, waitCh)
		if err := item.sendProbe(remotePeerID, address, nonce); err != nil {
			item.unregisterPendingProbe(nonce)
			lastErr = err
			continue
		}
		select {
		case <-waitCh:
			item.unregisterPendingProbe(nonce)
			return Result{RemoteAddress: address}, nil
		case <-time.After(timeout):
			item.unregisterPendingProbe(nonce)
			lastErr = fmt.Errorf("direct probe timeout to %s", address)
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no remote candidates available")
	}
	return Result{}, lastErr
}

func (m *manager) Establish(localPeerID, remotePeerID string, remoteCandidates []string, timeout time.Duration) (Session, error) {
	item, err := m.listenerFor(localPeerID)
	if err != nil {
		return Session{}, err
	}
	if strings.TrimSpace(remotePeerID) == "" {
		return Session{}, fmt.Errorf("remote peer id is required")
	}
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}

	if session, ok := item.sessionForRemote(remotePeerID); ok {
		return session.snapshot(), nil
	}

	var lastErr error
	for _, candidate := range remoteCandidates {
		address := strings.TrimSpace(candidate)
		if address == "" {
			continue
		}
		session, err := item.establish(remotePeerID, address, timeout)
		if err == nil {
			return session, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no remote candidates available")
	}
	return Session{}, lastErr
}

func (m *manager) Exchange(localPeerID, remotePeerID string, payload []byte, timeout time.Duration) ([]byte, error) {
	item, err := m.listenerFor(localPeerID)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}

	session, ok := item.sessionForRemote(strings.TrimSpace(remotePeerID))
	if !ok {
		return nil, fmt.Errorf("no authenticated session for peer %s", remotePeerID)
	}
	counter, ciphertext, err := item.sealRecord(session, "data", 0, payload)
	if err != nil {
		return nil, err
	}
	pendingKey := ackKey(session.sessionID, counter)
	waitCh := make(chan []byte, 1)
	item.registerPendingAck(pendingKey, waitCh)
	defer item.unregisterPendingAck(pendingKey)
	if err := item.sendRecord(session, "data", counter, 0, ciphertext); err != nil {
		return nil, err
	}
	select {
	case response := <-waitCh:
		return response, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("authenticated exchange timeout")
	}
}

func (m *manager) ProbeSTUN(localPeerID, serverAddress string, timeout time.Duration) (stun.ProbeResult, error) {
	item, err := m.listenerFor(localPeerID)
	if err != nil {
		return stun.ProbeResult{
			ServerAddress: strings.TrimSpace(serverAddress),
			NATType:       stun.NATTypeUnknown,
		}, err
	}
	return item.probeSTUN(serverAddress, timeout)
}

func (m *manager) SendPacket(localPeerID, remotePeerID string, payload []byte) error {
	item, err := m.listenerFor(localPeerID)
	if err != nil {
		return err
	}

	session, ok := item.sessionForRemote(strings.TrimSpace(remotePeerID))
	if !ok {
		return fmt.Errorf("no authenticated session for peer %s", remotePeerID)
	}
	counter, ciphertext, err := item.sealRecord(session, "packet", 0, payload)
	if err != nil {
		return err
	}
	return item.sendRecord(session, "packet", counter, 0, ciphertext)
}

func (m *manager) SetExchangeHandler(localPeerID string, handler ExchangeHandler) error {
	item, err := m.listenerFor(localPeerID)
	if err != nil {
		return err
	}
	item.mu.Lock()
	defer item.mu.Unlock()
	item.exchangeHandler = handler
	return nil
}

func (m *manager) DrainInbound(localPeerID string, limit int) []Packet {
	item, err := m.listenerFor(localPeerID)
	if err != nil {
		return nil
	}
	return item.drainInbound(limit)
}

func (m *manager) DropSession(localPeerID, remotePeerID string) {
	item, err := m.listenerFor(localPeerID)
	if err != nil {
		return
	}
	item.dropSession(strings.TrimSpace(remotePeerID))
}

func (m *manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for peerID, item := range m.listeners {
		_ = item.close()
		delete(m.listeners, peerID)
	}
	return nil
}

func (m *manager) UpdateCredentials(peerID string, c *transportauth.Credentials) error {
	l, err := m.listenerFor(peerID)
	if err != nil {
		return err
	}
	return l.updateCredentials(c)
}

func (m *manager) listenerFor(localPeerID string) (*listener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	item := m.listeners[strings.TrimSpace(localPeerID)]
	if item == nil {
		return nil, fmt.Errorf("no direct-probe listener for peer %s", localPeerID)
	}
	return item, nil
}

func (l *listener) serve() {
	buffer := make([]byte, transportauth.DatagramBudget+1)
	for {
		l.reassembly.Prune()
		if err := l.conn.SetReadDeadline(time.Now().Add(transportauth.AssemblyTTL)); err != nil {
			return
		}
		n, remoteAddr, err := l.conn.ReadFromUDP(buffer)
		if err != nil {
			if transportauth.IsMessageSizeError(err) {
				l.mu.Lock()
				l.wireStats.OversizedInbound++
				l.mu.Unlock()
				continue
			}
			if e, ok := err.(net.Error); ok && e.Timeout() {
				continue
			}
			select {
			case <-l.shutdown:
				return
			default:
				return
			}
		}
		if n > transportauth.DatagramBudget {
			l.mu.Lock()
			l.wireStats.OversizedInbound++
			l.mu.Unlock()
			continue
		}
		if l.handleSTUNResponse(buffer[:n]) {
			continue
		}
		parts, decodeErr := transportauth.DecodeTransport(buffer[:n])
		if decodeErr != nil || remoteAddr == nil {
			l.mu.Lock()
			l.wireStats.MalformedInbound++
			l.mu.Unlock()
			continue
		}
		switch parts[0] {
		case "probe":
			l.handleProbe(parts, remoteAddr)
		case "ack":
			l.handleProbeAck(parts)
		case "hello", "welcome", "finish", "ready":
			l.handleHandshake(parts, remoteAddr)
		case "data":
			l.handleData(parts, remoteAddr)
		case "dataack":
			l.handleDataAck(parts)
		case "fragment":
			l.handleFragment(parts, remoteAddr)
		case "packet":
			l.handlePacket(parts, remoteAddr)
		}
	}
}

func (l *listener) probeSTUN(serverAddress string, timeout time.Duration) (stun.ProbeResult, error) {
	result := stun.ProbeResult{
		ServerAddress: strings.TrimSpace(serverAddress),
		NATType:       stun.NATTypeUnknown,
	}
	if timeout <= 0 {
		timeout = stun.DefaultTimeout
	}
	serverAddr, err := net.ResolveUDPAddr("udp", result.ServerAddress)
	if err != nil {
		return result, err
	}
	transactionID, err := stun.NewBindingTransactionID()
	if err != nil {
		return result, err
	}
	key := stunTransactionKey(transactionID)
	waitCh := make(chan *net.UDPAddr, 1)
	l.mu.Lock()
	l.pendingSTUN[key] = waitCh
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		delete(l.pendingSTUN, key)
		l.mu.Unlock()
	}()
	if _, err := l.conn.WriteToUDP(stun.EncodeBindingRequest(transactionID), serverAddr); err != nil {
		result.NATType = stun.NATTypeUDPBlocked
		return result, err
	}
	select {
	case mappedAddr := <-waitCh:
		boundAddr, _ := l.conn.LocalAddr().(*net.UDPAddr)
		if boundAddr != nil {
			result.LocalAddress = boundAddr.String()
		}
		if mappedAddr != nil {
			result.MappedAddress = mappedAddr.String()
		}
		result.NATType = stun.ClassifyNAT(boundAddr, mappedAddr)
		return result, nil
	case <-time.After(timeout):
		result.NATType = stun.NATTypeUDPBlocked
		return result, fmt.Errorf("stun probe timeout to %s", result.ServerAddress)
	}
}

func (l *listener) handleSTUNResponse(message []byte) bool {
	transactionID, ok := decodeSTUNBindingTransactionID(message)
	if !ok {
		return false
	}
	key := stunTransactionKey(transactionID)
	l.mu.Lock()
	waitCh := l.pendingSTUN[key]
	l.mu.Unlock()
	if waitCh == nil {
		return false
	}
	mappedAddr, err := stun.DecodeBindingSuccessResponse(message, transactionID)
	if err != nil {
		return true
	}
	select {
	case waitCh <- mappedAddr:
	default:
	}
	return true
}

func (l *listener) handleProbe(parts []string, remoteAddr *net.UDPAddr) {
	if len(parts) != 4 {
		return
	}
	sourcePeerID := parts[1]
	targetPeerID := parts[2]
	nonce := parts[3]
	if targetPeerID != l.peerID {
		return
	}
	_ = l.sendAck(sourcePeerID, remoteAddr, nonce)
}

func (l *listener) handleProbeAck(parts []string) {
	if len(parts) != 4 {
		return
	}
	targetPeerID := parts[2]
	nonce := parts[3]
	if targetPeerID != l.peerID {
		return
	}
	l.mu.Lock()
	waitCh := l.pendingProbes[nonce]
	l.mu.Unlock()
	if waitCh != nil {
		select {
		case waitCh <- struct{}{}:
		default:
		}
	}
}

func (l *listener) handleData(parts []string, remoteAddr *net.UDPAddr) {
	if len(parts) != 6 {
		return
	}
	sourcePeerID := parts[1]
	targetPeerID := parts[2]
	sessionID := parts[3]
	if targetPeerID != l.peerID {
		return
	}
	counter, err := parseUint(parts[4])
	if err != nil {
		return
	}
	var reference uint64

	ciphertext, err := hex.DecodeString(parts[len(parts)-1])
	if err != nil {
		return
	}
	session, ok := l.sessionForRemote(sourcePeerID)
	if !ok || session.sessionID != sessionID {
		return
	}
	plaintext, err := l.openRecord(session, "data", counter, reference, ciphertext)
	if err != nil {
		return
	}
	l.deliverRecord(session, "data", counter, reference, plaintext, remoteAddr)
}

func (l *listener) handleDataAck(parts []string) {
	if len(parts) != 7 {
		return
	}
	sourcePeerID := parts[1]
	targetPeerID := parts[2]
	sessionID := parts[3]
	if targetPeerID != l.peerID {
		return
	}
	counter, err := parseUint(parts[5])
	if err != nil {
		return
	}
	var reference uint64
	reference, err = parseUint(parts[4])
	if err != nil {
		return
	}
	ciphertext, err := hex.DecodeString(parts[len(parts)-1])
	if err != nil {
		return
	}
	session, ok := l.sessionForRemote(sourcePeerID)
	if !ok || session.sessionID != sessionID {
		return
	}
	plaintext, err := l.openRecord(session, "dataack", counter, reference, ciphertext)
	if err != nil {
		return
	}
	l.deliverRecord(session, "dataack", counter, reference, plaintext, nil)
}

func (l *listener) handlePacket(parts []string, remoteAddr *net.UDPAddr) {
	if len(parts) != 6 {
		return
	}
	sourcePeerID := parts[1]
	targetPeerID := parts[2]
	sessionID := parts[3]
	if targetPeerID != l.peerID {
		return
	}
	counter, err := parseUint(parts[4])
	if err != nil {
		return
	}
	var reference uint64

	ciphertext, err := hex.DecodeString(parts[len(parts)-1])
	if err != nil {
		return
	}
	session, ok := l.sessionForRemote(sourcePeerID)
	if !ok || session.sessionID != sessionID {
		return
	}
	plaintext, err := l.openRecord(session, "packet", counter, reference, ciphertext)
	if err != nil {
		return
	}
	l.deliverRecord(session, "packet", counter, reference, plaintext, remoteAddr)
}

func (l *listener) establish(remotePeerID, remoteCandidate string, timeout time.Duration) (Session, error) {
	waitID, err := newNonce()
	if err != nil {
		return Session{}, err
	}
	l.mu.Lock()
	if active := l.sessions[remotePeerID]; active != nil && l.auth.Allows(remotePeerID, active.identityProof) {
		l.mu.Unlock()
		return active.snapshot(), nil
	}
	message, err := l.auth.Begin(remotePeerID)
	if err != nil {
		l.mu.Unlock()
		return Session{}, err
	}
	waitCh := make(chan Session, 1)
	l.pendingHandshakes[waitID] = pendingHandshake{remotePeerID: remotePeerID, waitCh: waitCh}
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		delete(l.pendingHandshakes, waitID)
		for _, other := range l.pendingHandshakes {
			if other.remotePeerID == remotePeerID {
				return
			}
		}
		if message.Wire != "" {
			l.auth.Cancel(message.SessionID)
		}
	}()
	if message.Wire != "" {
		if err := l.sendMessage(remoteCandidate, message.Wire); err != nil {
			return Session{}, err
		}
	}
	select {
	case session := <-waitCh:
		return session, nil
	case <-time.After(timeout):
		return Session{}, fmt.Errorf("authenticated handshake timeout")
	}
}

func (l *listener) sendProbe(remotePeerID, remoteCandidate, nonce string) error {
	return l.sendMessage(remoteCandidate, formatMessage("probe", l.peerID, remotePeerID, nonce))
}

func (l *listener) sendAck(sourcePeerID string, remoteAddr *net.UDPAddr, nonce string) error {
	if remoteAddr == nil {
		return nil
	}
	return l.sendMessage(remoteAddr.String(), formatMessage("ack", l.peerID, sourcePeerID, nonce))
}

func (l *listener) sendData(remotePeerID, remoteCandidate, sessionID string, counter uint64, ciphertext []byte) error {
	return l.sendMessage(remoteCandidate, formatMessage("data", l.peerID, remotePeerID, sessionID, fmt.Sprintf("%d", counter), hex.EncodeToString(ciphertext)))
}

func (l *listener) sendDataAck(sourcePeerID, remoteCandidate, sessionID string, requestCounter, responseCounter uint64, ciphertext []byte) error {
	return l.sendMessage(remoteCandidate, formatMessage("dataack", l.peerID, sourcePeerID, sessionID, fmt.Sprintf("%d", requestCounter), fmt.Sprintf("%d", responseCounter), hex.EncodeToString(ciphertext)))
}

func (l *listener) sendPacket(remotePeerID, remoteCandidate, sessionID string, counter uint64, ciphertext []byte) error {
	return l.sendMessage(remoteCandidate, formatMessage("packet", l.peerID, remotePeerID, sessionID, fmt.Sprintf("%d", counter), hex.EncodeToString(ciphertext)))
}

func (l *listener) sendMessage(remoteCandidate, message string) error {
	remoteAddr, err := net.ResolveUDPAddr("udp", remoteCandidate)
	if err != nil {
		return err
	}
	data, encodeErr := transportauth.EncodeTransport(message)
	if encodeErr != nil {
		l.mu.Lock()
		l.wireStats.RejectedOutbound++
		l.mu.Unlock()
		return encodeErr
	}
	_, err = l.conn.WriteToUDP(data, remoteAddr)
	return err
}

func (l *listener) registerPendingProbe(nonce string, waitCh chan struct{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pendingProbes[nonce] = waitCh
}

func (l *listener) unregisterPendingProbe(nonce string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.pendingProbes, nonce)
}

func (l *listener) registerPendingAck(key string, waitCh chan []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pendingDataAcks[key] = waitCh
}

func (l *listener) unregisterPendingAck(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.pendingDataAcks, key)
}

func (l *listener) enqueueInbound(packet Packet) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.validPacketLocked(packet) {
		l.inbound.Push(packet, len(packet.Payload))
	}
}

func (l *listener) drainInbound(limit int) []Packet {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneInboundLocked()
	return l.inbound.Drain(limit)
}

func (l *listener) sessionForRemote(remotePeerID string) (*cryptoSession, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	session := l.sessions[remotePeerID]
	return session, session != nil && l.auth.Allows(remotePeerID, session.identityProof)
}

func (l *listener) dropSession(remotePeerID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if old := l.sessions[remotePeerID]; old != nil {
		old.records.Disable()
	}
	delete(l.sessions, remotePeerID)
	l.pruneInboundLocked()
}

func (l *listener) close() error {
	_ = l.updateCredentials(nil)
	close(l.shutdown)
	return l.conn.Close()
}

func stunTransactionKey(transactionID [12]byte) string {
	return string(transactionID[:])
}

func decodeSTUNBindingTransactionID(message []byte) ([12]byte, bool) {
	var transactionID [12]byte
	if len(message) < 20 {
		return transactionID, false
	}
	if message[0] != 0x01 || message[1] != 0x01 {
		return transactionID, false
	}
	if message[4] != 0x21 || message[5] != 0x12 || message[6] != 0xA4 || message[7] != 0x42 {
		return transactionID, false
	}
	copy(transactionID[:], message[8:20])
	return transactionID, true
}

func (s *cryptoSession) snapshot() Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Session{
		SessionID:         s.sessionID,
		RemoteAddress:     s.remoteAddr,
		EstablishedAtUnix: s.established.Unix(),
	}
}

func (s *cryptoSession) setRemoteAddr(remoteAddr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(remoteAddr) != "" {
		s.remoteAddr = remoteAddr
	}
}

func newCryptoSession(localPeerID, sessionID, remotePeerID, remoteAddr string, secret []byte, initiator bool, pool *transportauth.ReassemblyPool) (*cryptoSession, error) {
	records, err := transportauth.NewRecords("DIRECT", sessionID, localPeerID, remotePeerID, secret, initiator, pool)
	if err != nil {
		return nil, err
	}
	return &cryptoSession{sessionID: sessionID, remotePeerID: remotePeerID, remoteAddr: remoteAddr, established: time.Now(), records: records}, nil
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

func ackKey(sessionID string, requestCounter uint64) string {
	return sessionID + "|" + fmt.Sprintf("%d", requestCounter)
}

func decodeHex(value string) []byte {
	decoded, _ := hex.DecodeString(strings.TrimSpace(value))
	return decoded
}

func parseUint(value string) (uint64, error) {
	return strconv.ParseUint(strings.TrimSpace(value), 10, 64)
}

func newNonce() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func (l *listener) updateCredentials(c *transportauth.Credentials) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c != nil && c.PeerID != l.peerID {
		_ = l.auth.Update(nil)
		for _, old := range l.sessions {
			old.records.Disable()
		}
		clear(l.sessions)
		l.pruneInboundLocked()
		return fmt.Errorf("transport credentials belong to another local peer")
	}
	err := l.auth.Update(c)
	for id, s := range l.sessions {
		if !l.auth.Allows(id, s.identityProof) {
			s.records.Disable()
			delete(l.sessions, id)
		}
	}
	l.pruneInboundLocked()
	return err
}
func (l *listener) handleHandshake(parts []string, remoteAddr *net.UDPAddr) {
	if remoteAddr == nil {
		return
	}
	l.mu.Lock()
	response, established, err := l.auth.Handle(parts)
	if err != nil {
		l.rejectedHandshakes++
		l.mu.Unlock()
		return
	}
	var session *cryptoSession
	var waiters []chan Session
	if established != nil {
		session, err = newCryptoSession(l.peerID, established.SessionID, established.RemotePeerID, remoteAddr.String(), established.Secret, established.Initiator, l.reassembly)
		if err != nil {
			l.mu.Unlock()
			return
		}
		session.identityProof = established.Proof
		if !l.auth.Allows(established.RemotePeerID, established.Proof) {
			l.mu.Unlock()
			return
		}
		if old := l.sessions[established.RemotePeerID]; old != nil {
			old.records.Disable()
		}
		l.sessions[established.RemotePeerID] = session
		l.pruneInboundLocked()
		for _, p := range l.pendingHandshakes {
			if p.remotePeerID == established.RemotePeerID {
				waiters = append(waiters, p.waitCh)
			}
		}
	}
	l.mu.Unlock()
	if response.Wire != "" {
		if err := l.sendMessage(remoteAddr.String(), response.Wire); err != nil {
			return
		}
	}
	if session != nil {
		for _, waitCh := range waiters {
			select {
			case waitCh <- session.snapshot():
			default:
			}
		}
	}
}

func (l *listener) pruneInboundLocked() {
	l.inbound.Prune(l.validPacketLocked)
}
func (l *listener) openRecord(session *cryptoSession, kind string, counter, requestCounter uint64, ciphertext []byte) ([]byte, error) {
	plaintext, err := session.records.Open(kind, counter, requestCounter, ciphertext)
	l.mu.Lock()
	l.recordStats.Observe(err)
	l.mu.Unlock()
	return plaintext, err
}
func (l *listener) sealRecord(session *cryptoSession, kind string, requestCounter uint64, payload []byte) (uint64, []byte, error) {
	counter, ciphertext, err := session.records.Seal(kind, requestCounter, payload)
	if err != nil {
		l.mu.Lock()
		l.recordStats.Observe(err)
		l.wireStats.RejectedOutbound++
		l.mu.Unlock()
	}
	return counter, ciphertext, err
}
func (m *manager) DataPlaneStats(peerID string) transportauth.DataPlaneStats {
	l, err := m.listenerFor(peerID)
	if err != nil {
		return transportauth.DataPlaneStats{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return transportauth.DataPlaneStats{Records: l.recordStats, Queue: l.inbound.Stats(), Wire: l.wireStats, Assembly: l.reassembly.Stats()}
}

func (s *cryptoSession) remoteAddress() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.remoteAddr
}

func (l *listener) validPacketLocked(packet Packet) bool {
	session := l.sessions[packet.RemotePeerID]
	return session != nil && packet.identityProof == session.identityProof && packet.sessionID == session.sessionID && l.auth.Allows(packet.RemotePeerID, session.identityProof)
}

func (l *listener) sendRecord(session *cryptoSession, kind string, counter, reference uint64, ciphertext []byte) error {
	if len(ciphertext) <= transportauth.FragmentBytes {
		switch kind {
		case "packet":
			return l.sendPacket(session.remotePeerID, session.remoteAddress(), session.sessionID, counter, ciphertext)
		case "data":
			return l.sendData(session.remotePeerID, session.remoteAddress(), session.sessionID, counter, ciphertext)
		case "dataack":
			return l.sendDataAck(session.remotePeerID, session.remoteAddress(), session.sessionID, reference, counter, ciphertext)
		}
	}
	fragments, err := session.records.Fragments(kind, counter, reference, ciphertext)
	if err != nil {
		return err
	}
	for _, f := range fragments {
		message := transportauth.FragmentText(l.peerID, session.remotePeerID, session.sessionID, f)
		if err := l.sendMessage(session.remoteAddress(), message); err != nil {
			return err
		}
	}
	return nil
}
func (l *listener) handleFragment(parts []string, remoteAddr *net.UDPAddr) {
	if len(parts) != 12 || parts[2] != l.peerID {
		return
	}
	session, ok := l.sessionForRemote(parts[1])
	if !ok || session.sessionID != parts[3] {
		return
	}
	f, err := transportauth.ParseFragment(parts)
	if err != nil {
		return
	}
	plaintext, complete, err := session.records.OpenFragment(f)
	if err != nil || complete {
		l.mu.Lock()
		l.recordStats.Observe(err)
		l.mu.Unlock()
	}
	if err != nil || !complete {
		return
	}
	l.deliverRecord(session, f.Kind, f.Counter, f.Reference, plaintext, remoteAddr)
}
func (l *listener) deliverRecord(session *cryptoSession, kind string, counter, reference uint64, plaintext []byte, remoteAddr *net.UDPAddr) {
	if remoteAddr != nil {
		session.setRemoteAddr(remoteAddr.String())
	}
	switch kind {
	case "packet":
		l.enqueueInbound(Packet{identityProof: session.identityProof, sessionID: session.sessionID, RemotePeerID: session.remotePeerID, Payload: append([]byte(nil), plaintext...), ReceivedAtUnix: time.Now().Unix()})
	case "dataack":
		l.mu.Lock()
		waitCh := l.pendingDataAcks[ackKey(session.sessionID, reference)]
		l.mu.Unlock()
		if waitCh != nil {
			select {
			case waitCh <- plaintext:
			default:
			}
		}
	case "data":
		response := []byte("ack:" + string(plaintext))
		l.mu.Lock()
		handler := l.exchangeHandler
		l.mu.Unlock()
		if handler != nil {
			if custom := handler(session.remotePeerID, append([]byte(nil), plaintext...)); custom != nil {
				response = custom
			}
		}
		responseCounter, ciphertext, err := l.sealRecord(session, "dataack", counter, response)
		if err != nil {
			return
		}
		_ = l.sendRecord(session, "dataack", responseCounter, counter, ciphertext)
	}
}
