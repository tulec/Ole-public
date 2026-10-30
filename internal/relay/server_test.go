package relay_test

import (
	"Ole/internal/relay"
	"Ole/internal/transportauth"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRelayServerBindsAndForwardsPackets(t *testing.T) {
	server, err := relay.Listen("127.0.0.1:0", relay.StaticAuthorizer{})
	if err != nil {
		t.Fatalf("listen relay server: %v", err)
	}
	defer server.Close()

	peerA := mustListenUDP(t)
	defer peerA.Close()
	peerB := mustListenUDP(t)
	defer peerB.Close()

	sendRelayMessage(t, peerA, server.LocalAddr().String(), "OLER2|bind|token-a|peer-a|nonce-a")
	sendRelayMessage(t, peerB, server.LocalAddr().String(), "OLER2|bind|token-b|peer-b|nonce-b")

	if packet, err := relay.WaitForPacket(peerA, time.Second); err != nil || packet != "OLER2|bound|peer-a|nonce-a" {
		t.Fatalf("expected peer-a bind ack, got packet=%q err=%v", packet, err)
	}
	if packet, err := relay.WaitForPacket(peerB, time.Second); err != nil || packet != "OLER2|bound|peer-b|nonce-b" {
		t.Fatalf("expected peer-b bind ack, got packet=%q err=%v", packet, err)
	}

	sendRelayMessage(t, peerA, server.LocalAddr().String(), "OLER2|send|token-a|peer-a|peer-b|68656c6c6f")

	packet, err := relay.WaitForPacket(peerB, time.Second)
	if err != nil {
		t.Fatalf("wait for forwarded packet: %v", err)
	}
	if packet != "OLER2|deliver|peer-a|68656c6c6f" {
		t.Fatalf("unexpected relay delivery packet: %q", packet)
	}
}

func TestRelayServerRejectsUnauthorizedPackets(t *testing.T) {
	auth := &recordingAuthorizer{
		bindErrForPeer: map[string]error{"peer-a": errDenied},
		sendErrForPair: map[string]error{"peer-a|peer-b": errDenied},
	}
	server, err := relay.Listen("127.0.0.1:0", auth)
	if err != nil {
		t.Fatalf("listen relay server: %v", err)
	}
	defer server.Close()

	peerA := mustListenUDP(t)
	defer peerA.Close()

	sendRelayMessage(t, peerA, server.LocalAddr().String(), "OLER2|bind|token-a|peer-a|nonce-a")
	packet, err := relay.WaitForPacket(peerA, time.Second)
	if err != nil {
		t.Fatalf("wait for bind denial: %v", err)
	}
	if !strings.Contains(packet, "bind_denied") {
		t.Fatalf("expected bind denial packet, got %q", packet)
	}

	auth.bindErrForPeer = map[string]error{}
	sendRelayMessage(t, peerA, server.LocalAddr().String(), "OLER2|bind|token-a|peer-a|nonce-b")
	if _, err := relay.WaitForPacket(peerA, time.Second); err != nil {
		t.Fatalf("wait for bind success: %v", err)
	}

	sendRelayMessage(t, peerA, server.LocalAddr().String(), "OLER2|send|token-a|peer-a|peer-b|68656c6c6f")
	packet, err = relay.WaitForPacket(peerA, time.Second)
	if err != nil {
		t.Fatalf("wait for send denial: %v", err)
	}
	if !strings.Contains(packet, "send_denied") {
		t.Fatalf("expected send denial packet, got %q", packet)
	}
}

func TestRelayServerEnforcesQuotaAndTracksUsage(t *testing.T) {
	server, err := relay.ListenWithConfig("127.0.0.1:0", relay.StaticAuthorizer{}, relay.Config{
		QuotaWindow:             time.Minute,
		MaxPacketsPerPeerWindow: 1,
		MaxBytesPerPeerWindow:   5,
	})
	if err != nil {
		t.Fatalf("listen relay server: %v", err)
	}
	defer server.Close()

	peerA := mustListenUDP(t)
	defer peerA.Close()
	peerB := mustListenUDP(t)
	defer peerB.Close()

	sendRelayMessage(t, peerA, server.LocalAddr().String(), "OLER2|bind|token-a|peer-a|nonce-a")
	sendRelayMessage(t, peerB, server.LocalAddr().String(), "OLER2|bind|token-b|peer-b|nonce-b")
	if _, err := relay.WaitForPacket(peerA, time.Second); err != nil {
		t.Fatalf("wait for peer-a bind ack: %v", err)
	}
	if _, err := relay.WaitForPacket(peerB, time.Second); err != nil {
		t.Fatalf("wait for peer-b bind ack: %v", err)
	}

	sendRelayMessage(t, peerA, server.LocalAddr().String(), "OLER2|send|token-a|peer-a|peer-b|68656c6c6f")
	if packet, err := relay.WaitForPacket(peerB, time.Second); err != nil || packet != "OLER2|deliver|peer-a|68656c6c6f" {
		t.Fatalf("expected first forwarded packet, got packet=%q err=%v", packet, err)
	}

	sendRelayMessage(t, peerA, server.LocalAddr().String(), "OLER2|send|token-a|peer-a|peer-b|776f726c64")
	packet, err := relay.WaitForPacket(peerA, time.Second)
	if err != nil {
		t.Fatalf("wait for quota denial: %v", err)
	}
	if !strings.Contains(packet, "quota_exceeded") {
		t.Fatalf("expected quota denial packet, got %q", packet)
	}

	snapshot := server.Snapshot()
	if snapshot.ForwardedPackets != 1 || snapshot.ForwardedBytes != 5 {
		t.Fatalf("unexpected forwarded accounting: %+v", snapshot)
	}
	if snapshot.QuotaDenials != 1 {
		t.Fatalf("expected 1 quota denial, got %d", snapshot.QuotaDenials)
	}
	if len(snapshot.Peers) != 1 {
		t.Fatalf("expected one peer usage entry, got %d", len(snapshot.Peers))
	}
	peerUsage := snapshot.Peers[0]
	if peerUsage.PeerID != "peer-a" {
		t.Fatalf("expected peer-a usage entry, got %+v", peerUsage)
	}
	if peerUsage.ForwardedPackets != 1 || peerUsage.ForwardedBytes != 5 || peerUsage.QuotaExceededCount != 1 {
		t.Fatalf("unexpected peer usage accounting: %+v", peerUsage)
	}
}

func TestRelayServerBlocksAbusiveSourceAfterRepeatedDenials(t *testing.T) {
	auth := &recordingAuthorizer{
		bindErrForPeer: map[string]error{"peer-a": errDenied},
	}
	server, err := relay.ListenWithConfig("127.0.0.1:0", auth, relay.Config{
		AbuseWindow:        time.Minute,
		AbuseThreshold:     2,
		AbuseBlockDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("listen relay server: %v", err)
	}
	defer server.Close()

	peerA := mustListenUDP(t)
	defer peerA.Close()

	sendRelayMessage(t, peerA, server.LocalAddr().String(), "OLER2|bind|token-a|peer-a|nonce-a")
	packet, err := relay.WaitForPacket(peerA, time.Second)
	if err != nil {
		t.Fatalf("wait for first bind denial: %v", err)
	}
	if !strings.Contains(packet, "bind_denied") {
		t.Fatalf("expected bind denial packet, got %q", packet)
	}

	sendRelayMessage(t, peerA, server.LocalAddr().String(), "OLER2|bind|token-a|peer-a|nonce-b")
	packet, err = relay.WaitForPacket(peerA, time.Second)
	if err != nil {
		t.Fatalf("wait for second bind denial: %v", err)
	}
	if !strings.Contains(packet, "bind_denied") {
		t.Fatalf("expected second bind denial packet, got %q", packet)
	}

	auth.bindErrForPeer = map[string]error{}
	sendRelayMessage(t, peerA, server.LocalAddr().String(), "OLER2|bind|token-a|peer-a|nonce-c")
	packet, err = relay.WaitForPacket(peerA, time.Second)
	if err != nil {
		t.Fatalf("wait for source blocked reply: %v", err)
	}
	if !strings.Contains(packet, "source_blocked") {
		t.Fatalf("expected source_blocked packet, got %q", packet)
	}

	snapshot := server.Snapshot()
	if snapshot.AbuseAlerts != 1 || snapshot.AbuseBlockedSources != 1 || snapshot.AbuseDenials != 1 {
		t.Fatalf("unexpected abuse snapshot: %+v", snapshot)
	}
	if len(snapshot.Sources) != 1 {
		t.Fatalf("expected one abusive source snapshot, got %d", len(snapshot.Sources))
	}
	if snapshot.Sources[0].AuthDeniedCount != 2 || snapshot.Sources[0].BlockedCount != 1 {
		t.Fatalf("unexpected abusive source counters: %+v", snapshot.Sources[0])
	}
}

func TestRelayServerTracksMalformedPacketsAsAbuse(t *testing.T) {
	server, err := relay.ListenWithConfig("127.0.0.1:0", relay.StaticAuthorizer{}, relay.Config{
		AbuseWindow:        time.Minute,
		AbuseThreshold:     2,
		AbuseBlockDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("listen relay server: %v", err)
	}
	defer server.Close()

	peerA := mustListenUDP(t)
	defer peerA.Close()

	sendRelayMessage(t, peerA, server.LocalAddr().String(), "not-a-relay-message")
	time.Sleep(50 * time.Millisecond)
	sendRelayMessage(t, peerA, server.LocalAddr().String(), "still-bad")
	time.Sleep(50 * time.Millisecond)
	sendRelayMessage(t, peerA, server.LocalAddr().String(), "OLER2|bind|token-a|peer-a|nonce-a")

	packet, err := relay.WaitForPacket(peerA, time.Second)
	if err != nil {
		t.Fatalf("wait for blocked reply after malformed abuse: %v", err)
	}
	if !strings.Contains(packet, "source_blocked") {
		t.Fatalf("expected source_blocked packet after malformed abuse, got %q", packet)
	}

	snapshot := server.Snapshot()
	if snapshot.MalformedPackets != 2 || snapshot.AbuseAlerts != 1 {
		t.Fatalf("unexpected malformed abuse snapshot: %+v", snapshot)
	}
	if len(snapshot.Sources) != 1 || snapshot.Sources[0].MalformedCount != 2 {
		t.Fatalf("unexpected malformed source details: %+v", snapshot.Sources)
	}
}

func mustListenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	return conn
}

func sendRelayMessage(t *testing.T, conn *net.UDPConn, serverAddress, message string) {
	t.Helper()
	remoteAddr, err := net.ResolveUDPAddr("udp", serverAddress)
	if err != nil {
		t.Fatalf("resolve relay addr: %v", err)
	}
	data, encodeErr := transportauth.EncodeRelay(message)
	if encodeErr != nil {
		data = []byte(message)
	}
	if _, err := conn.WriteToUDP(data, remoteAddr); err != nil {
		t.Fatalf("write relay message: %v", err)
	}
}

var errDenied = &net.AddrError{Err: "denied", Addr: "relay"}

type recordingAuthorizer struct {
	mu             sync.Mutex
	bindErrForPeer map[string]error
	sendErrForPair map[string]error
}

func (a *recordingAuthorizer) AuthorizeBind(_ string, peerID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.bindErrForPeer[peerID]
}

func (a *recordingAuthorizer) AuthorizeSend(_ string, sourcePeerID, targetPeerID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sendErrForPair[sourcePeerID+"|"+targetPeerID]
}
