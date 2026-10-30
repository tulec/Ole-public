package relaytransport

import (
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

const (
	relayMagic     = transportauth.RelayMagic
	transportMagic = transportauth.Magic
)

type Binding struct {
	Credentials  *transportauth.Credentials `json:"-"`
	PeerID       string
	RelayAddress string
	AccessToken  string
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
	Establish(localPeerID, remotePeerID string, timeout time.Duration) (Session, error)
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
	established   time.Time
	records       *transportauth.Records
}

type listener struct {
	reassembly         *transportauth.ReassemblyPool
	wireStats          transportauth.WireStats
	rejectedHandshakes uint64 // Protected by mu.
	auth               *transportauth.Handshaker
	peerID             string
	relayAddress       string
	accessToken        string
	conn               *net.UDPConn

	mu                sync.Mutex
	bound             bool
	pendingBinds      map[string]chan struct{}
	pendingHandshakes map[string]pendingHandshake
	pendingDataAcks   map[string]chan []byte
	sessions          map[string]*cryptoSession
	inbound           transportauth.PacketQueue[Packet]
	recordStats       transportauth.RecordStats
	exchangeHandler   ExchangeHandler
	shutdown          chan struct{}
}

type manager struct {
	mu        sync.Mutex
	listeners map[string]*listener
}

func New() Manager {
	return &manager{listeners: map[string]*listener{}}
}

func (m *manager) Reconcile(bindings []Binding) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	desired := map[string]Binding{}
	for _, binding := range bindings {
		peerID := strings.TrimSpace(binding.PeerID)
		relayAddress := strings.TrimSpace(binding.RelayAddress)
		accessToken := strings.TrimSpace(binding.AccessToken)
		if peerID == "" || relayAddress == "" || accessToken == "" {
			continue
		}
		desired[peerID] = Binding{
			PeerID:       peerID,
			RelayAddress: relayAddress,
			AccessToken:  accessToken,
			Credentials:  binding.Credentials,
		}
	}

	for peerID, existing := range m.listeners {
		binding, ok := desired[peerID]
		if ok && existing.relayAddress == binding.RelayAddress && existing.accessToken == binding.AccessToken {
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
		conn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return err
		}
		item := &listener{
			reassembly:        transportauth.NewReassemblyPool(),
			auth:              transportauth.New("RELAY"),
			peerID:            peerID,
			relayAddress:      binding.RelayAddress,
			accessToken:       binding.AccessToken,
			conn:              conn,
			pendingBinds:      map[string]chan struct{}{},
			pendingHandshakes: map[string]pendingHandshake{},
			pendingDataAcks:   map[string]chan []byte{},
			sessions:          map[string]*cryptoSession{},
			shutdown:          make(chan struct{}),
		}
		if err := item.updateCredentials(binding.Credentials); err != nil {
			item.close()
			return err
		}
		m.listeners[peerID] = item
		go item.serve()
		if err := item.ensureBound(300 * time.Millisecond); err != nil {
			_ = item.close()
			delete(m.listeners, peerID)
			return err
		}
	}
	return nil
}

func (m *manager) Establish(localPeerID, remotePeerID string, timeout time.Duration) (Session, error) {
	item, err := m.listenerFor(localPeerID)
	if err != nil {
		return Session{}, err
	}
	remotePeerID = strings.TrimSpace(remotePeerID)
	if remotePeerID == "" {
		return Session{}, fmt.Errorf("remote peer id is required")
	}
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}
	if err := item.ensureBound(timeout); err != nil {
		return Session{}, err
	}
	if session, ok := item.sessionForRemote(remotePeerID); ok {
		return session.snapshot(), nil
	}
	return item.establish(remotePeerID, timeout)
}

func (m *manager) Exchange(localPeerID, remotePeerID string, payload []byte, timeout time.Duration) ([]byte, error) {
	item, err := m.listenerFor(localPeerID)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}
	if err := item.ensureBound(timeout); err != nil {
		return nil, err
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

func (m *manager) SendPacket(localPeerID, remotePeerID string, payload []byte) error {
	item, err := m.listenerFor(localPeerID)
	if err != nil {
		return err
	}
	if err := item.ensureBound(300 * time.Millisecond); err != nil {
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
		return nil, fmt.Errorf("no relay listener for peer %s", localPeerID)
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
		n, _, err := l.conn.ReadFromUDP(buffer)
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
		parts, decodeErr := transportauth.DecodeRelay(buffer[:n])
		if decodeErr != nil {
			l.mu.Lock()
			l.wireStats.MalformedInbound++
			l.mu.Unlock()
			continue
		}
		switch parts[0] {
		case "bound":
			l.handleBound(parts)
		case "deliver":
			l.handleDeliver(parts)
		case "error":
			l.handleError(parts)
		}
	}
}

func (l *listener) handleBound(parts []string) {
	if len(parts) != 3 {
		return
	}
	peerID := parts[1]
	nonce := parts[2]
	if peerID != l.peerID {
		return
	}
	l.mu.Lock()
	l.bound = true
	waitCh := l.pendingBinds[nonce]
	l.mu.Unlock()
	if waitCh != nil {
		select {
		case waitCh <- struct{}{}:
		default:
		}
	}
}

func (l *listener) handleError(parts []string) {
	if len(parts) < 4 {
		return
	}
	code := parts[1]
	target := parts[2]
	if code == "bind_denied" && target == l.peerID {
		l.mu.Lock()
		l.bound = false
		l.mu.Unlock()
	}
}

func (l *listener) handleDeliver(parts []string) {
	if len(parts) != 3 {
		return
	}
	sourcePeerID := parts[1]
	payload, err := hex.DecodeString(parts[2])
	if err != nil {
		return
	}
	innerParts, ok := parseTransportMessage(string(payload))
	if !ok {
		return
	}
	switch innerParts[0] {
	case "hello", "welcome", "finish", "ready":
		l.handleHandshake(innerParts, sourcePeerID)
	case "data":
		l.handleData(innerParts, sourcePeerID)
	case "dataack":
		l.handleDataAck(innerParts, sourcePeerID)
	case "fragment":
		l.handleFragment(innerParts, sourcePeerID)
	case "packet":
		l.handlePacket(innerParts, sourcePeerID)
	}
}

func (l *listener) ensureBound(timeout time.Duration) error {
	l.mu.Lock()
	if l.bound {
		l.mu.Unlock()
		return nil
	}
	l.mu.Unlock()
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}
	nonce, err := newNonce()
	if err != nil {
		return err
	}
	waitCh := make(chan struct{}, 1)
	l.mu.Lock()
	l.pendingBinds[nonce] = waitCh
	l.mu.Unlock()
	if err := l.sendRelay("bind", l.accessToken, l.peerID, nonce); err != nil {
		l.mu.Lock()
		delete(l.pendingBinds, nonce)
		l.mu.Unlock()
		return err
	}
	select {
	case <-waitCh:
		l.mu.Lock()
		delete(l.pendingBinds, nonce)
		l.bound = true
		l.mu.Unlock()
		return nil
	case <-time.After(timeout):
		l.mu.Lock()
		delete(l.pendingBinds, nonce)
		l.mu.Unlock()
		return fmt.Errorf("relay bind timeout for peer %s", l.peerID)
	}
}

func (l *listener) establish(remotePeerID string, timeout time.Duration) (Session, error) {
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
		if err := l.sendInner(remotePeerID, message.Wire); err != nil {
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

func (l *listener) handleData(parts []string, sourcePeerID string) {
	if len(parts) != 6 {
		return
	}

	targetPeerID := parts[2]
	sessionID := parts[3]
	if targetPeerID != l.peerID || sourcePeerID != parts[1] {
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
	l.deliverRecord(session, "data", counter, reference, plaintext)
}

func (l *listener) handleDataAck(parts []string, sourcePeerID string) {
	if len(parts) != 7 {
		return
	}

	targetPeerID := parts[2]
	sessionID := parts[3]
	if targetPeerID != l.peerID || sourcePeerID != parts[1] {
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
	l.deliverRecord(session, "dataack", counter, reference, plaintext)
}

func (l *listener) handlePacket(parts []string, sourcePeerID string) {
	if len(parts) != 6 {
		return
	}

	targetPeerID := parts[2]
	sessionID := parts[3]
	if targetPeerID != l.peerID || sourcePeerID != parts[1] {
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
	l.deliverRecord(session, "packet", counter, reference, plaintext)
}

func (l *listener) sendData(remotePeerID, sessionID string, counter uint64, ciphertext []byte) error {
	return l.sendInner(remotePeerID, formatTransportMessage("data", l.peerID, remotePeerID, sessionID, fmt.Sprintf("%d", counter), hex.EncodeToString(ciphertext)))
}

func (l *listener) sendDataAck(sourcePeerID, sessionID string, requestCounter, responseCounter uint64, ciphertext []byte) error {
	return l.sendInner(sourcePeerID, formatTransportMessage("dataack", l.peerID, sourcePeerID, sessionID, fmt.Sprintf("%d", requestCounter), fmt.Sprintf("%d", responseCounter), hex.EncodeToString(ciphertext)))
}

func (l *listener) sendPacket(remotePeerID, sessionID string, counter uint64, ciphertext []byte) error {
	return l.sendInner(remotePeerID, formatTransportMessage("packet", l.peerID, remotePeerID, sessionID, fmt.Sprintf("%d", counter), hex.EncodeToString(ciphertext)))
}

func (l *listener) sendInner(remotePeerID, inner string) error {
	return l.sendRelay("send", l.accessToken, l.peerID, remotePeerID, hex.EncodeToString([]byte(inner)))
}

func (l *listener) sendRelay(parts ...string) error {
	remoteAddr, err := net.ResolveUDPAddr("udp", l.relayAddress)
	if err != nil {
		return err
	}
	message := strings.Join(append([]string{relayMagic}, parts...), "|")
	data, encodeErr := transportauth.EncodeRelay(message)
	if encodeErr != nil {
		l.mu.Lock()
		l.wireStats.RejectedOutbound++
		l.mu.Unlock()
		return encodeErr
	}
	_, err = l.conn.WriteToUDP(data, remoteAddr)
	return err
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

func (l *listener) close() error {
	_ = l.updateCredentials(nil)
	close(l.shutdown)
	return l.conn.Close()
}

func (s *cryptoSession) snapshot() Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Session{
		SessionID:         s.sessionID,
		RemoteAddress:     "relay",
		EstablishedAtUnix: s.established.Unix(),
	}
}

func newCryptoSession(localPeerID, sessionID, remotePeerID string, secret []byte, initiator bool, pool *transportauth.ReassemblyPool) (*cryptoSession, error) {
	records, err := transportauth.NewRecords("RELAY", sessionID, localPeerID, remotePeerID, secret, initiator, pool)
	if err != nil {
		return nil, err
	}
	return &cryptoSession{sessionID: sessionID, remotePeerID: remotePeerID, established: time.Now(), records: records}, nil
}

func formatTransportMessage(parts ...string) string {
	return strings.Join(append([]string{transportMagic}, parts...), "|")
}

func parseTransportMessage(message string) ([]string, bool) {
	parts := strings.Split(strings.TrimSpace(message), "|")
	if len(parts) < 2 || parts[0] != transportMagic {
		return nil, false
	}
	return parts[1:], true
}

func parseRelayMessage(message string) ([]string, bool) {
	parts := strings.Split(strings.TrimSpace(message), "|")
	if len(parts) < 2 || parts[0] != relayMagic {
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
func (l *listener) handleHandshake(parts []string, sourcePeerID string) {
	if len(parts) < 2 || parts[1] != sourcePeerID {
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
		session, err = newCryptoSession(l.peerID, established.SessionID, established.RemotePeerID, established.Secret, established.Initiator, l.reassembly)
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
		if err := l.sendInner(response.PeerID, response.Wire); err != nil {
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

func (l *listener) validPacketLocked(packet Packet) bool {
	session := l.sessions[packet.RemotePeerID]
	return session != nil && packet.identityProof == session.identityProof && packet.sessionID == session.sessionID && l.auth.Allows(packet.RemotePeerID, session.identityProof)
}

func (l *listener) sendRecord(session *cryptoSession, kind string, counter, reference uint64, ciphertext []byte) error {
	if len(ciphertext) <= transportauth.FragmentBytes {
		switch kind {
		case "packet":
			return l.sendPacket(session.remotePeerID, session.sessionID, counter, ciphertext)
		case "data":
			return l.sendData(session.remotePeerID, session.sessionID, counter, ciphertext)
		case "dataack":
			return l.sendDataAck(session.remotePeerID, session.sessionID, reference, counter, ciphertext)
		}
	}
	fragments, err := session.records.Fragments(kind, counter, reference, ciphertext)
	if err != nil {
		return err
	}
	for _, f := range fragments {
		message := transportauth.FragmentText(l.peerID, session.remotePeerID, session.sessionID, f)
		if err := l.sendInner(session.remotePeerID, message); err != nil {
			return err
		}
	}
	return nil
}
func (l *listener) handleFragment(parts []string, sourcePeerID string) {
	if len(parts) != 12 || parts[2] != l.peerID || parts[1] != sourcePeerID {
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
	l.deliverRecord(session, f.Kind, f.Counter, f.Reference, plaintext)
}
func (l *listener) deliverRecord(session *cryptoSession, kind string, counter, reference uint64, plaintext []byte) {

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
