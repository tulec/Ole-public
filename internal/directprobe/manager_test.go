package directprobe

import (
	"Ole/internal/stun"
	"Ole/internal/transportauth"
	"crypto/ed25519"
	"crypto/sha256"
	"net"
	"strconv"
	"testing"
	"time"
)

func testCredentials(peerID string) *transportauth.Credentials {
	seed := sha256.Sum256([]byte("test-only-" + peerID))
	keys := map[string]transportauth.Identity{}
	for _, id := range []string{"peer-left", "peer-right"} {
		keySeed := sha256.Sum256([]byte("test-only-" + id))
		keys[id] = transportauth.Identity{DeviceID: "device-" + id, PublicKey: ed25519.NewKeyFromSeed(keySeed[:]).Public().(ed25519.PublicKey)}
	}
	return &transportauth.Credentials{NetworkID: "test-network", PeerID: peerID, DeviceID: "device-" + peerID, PrivateKey: ed25519.NewKeyFromSeed(seed[:]), Peers: keys, ExpiresAt: time.Now().Add(transportauth.SnapshotTTL)}
}

func TestManagersCanDirectProbeEachOther(t *testing.T) {
	leftAddr := reserveUDPAddress(t)
	rightAddr := reserveUDPAddress(t)

	left := New()
	defer left.Close()
	right := New()
	defer right.Close()

	if err := left.Reconcile([]Binding{{Credentials: testCredentials("peer-left"), PeerID: "peer-left", ListenAddress: leftAddr}}); err != nil {
		t.Fatalf("left reconcile: %v", err)
	}
	if err := right.Reconcile([]Binding{{Credentials: testCredentials("peer-right"), PeerID: "peer-right", ListenAddress: rightAddr}}); err != nil {
		t.Fatalf("right reconcile: %v", err)
	}

	result, err := left.Attempt("peer-left", "peer-right", []string{rightAddr}, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("direct probe attempt: %v", err)
	}
	if result.RemoteAddress != rightAddr {
		t.Fatalf("expected remote address to be returned, got %#v", result)
	}
}

func TestManagersCanEstablishEncryptedSessionAndExchangePackets(t *testing.T) {
	leftAddr := reserveUDPAddress(t)
	rightAddr := reserveUDPAddress(t)

	left := New()
	defer left.Close()
	right := New()
	defer right.Close()

	if err := left.Reconcile([]Binding{{Credentials: testCredentials("peer-left"), PeerID: "peer-left", ListenAddress: leftAddr}}); err != nil {
		t.Fatalf("left reconcile: %v", err)
	}
	if err := right.Reconcile([]Binding{{Credentials: testCredentials("peer-right"), PeerID: "peer-right", ListenAddress: rightAddr}}); err != nil {
		t.Fatalf("right reconcile: %v", err)
	}

	session, err := left.Establish("peer-left", "peer-right", []string{rightAddr}, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("establish encrypted session: %v", err)
	}
	if session.SessionID == "" || session.RemoteAddress == "" || session.EstablishedAtUnix == 0 {
		t.Fatalf("expected established session metadata, got %#v", session)
	}

	response, err := left.Exchange("peer-left", "peer-right", []byte("hello-ole"), 500*time.Millisecond)
	if err != nil {
		t.Fatalf("exchange encrypted payload: %v", err)
	}
	if string(response) != "ack:hello-ole" {
		t.Fatalf("expected encrypted ack payload, got %q", string(response))
	}

	payload := []byte{1, 2, 3, 4}
	if err := left.SendPacket("peer-left", "peer-right", payload); err != nil {
		t.Fatalf("send encrypted packet: %v", err)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		inbound := right.DrainInbound("peer-right", 1)
		if len(inbound) == 1 {
			if inbound[0].RemotePeerID != "peer-left" {
				t.Fatalf("expected remote peer id peer-left, got %#v", inbound[0])
			}
			if string(inbound[0].Payload) != string(payload) {
				t.Fatalf("expected encrypted packet payload to round-trip, got %#v", inbound[0])
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected inbound encrypted packet to be delivered")
}

func TestManagersSupportCustomExchangeHandlers(t *testing.T) {
	leftAddr := reserveUDPAddress(t)
	rightAddr := reserveUDPAddress(t)

	left := New()
	defer left.Close()
	right := New()
	defer right.Close()

	if err := left.Reconcile([]Binding{{Credentials: testCredentials("peer-left"), PeerID: "peer-left", ListenAddress: leftAddr}}); err != nil {
		t.Fatalf("left reconcile: %v", err)
	}
	if err := right.Reconcile([]Binding{{Credentials: testCredentials("peer-right"), PeerID: "peer-right", ListenAddress: rightAddr}}); err != nil {
		t.Fatalf("right reconcile: %v", err)
	}
	if err := right.SetExchangeHandler("peer-right", func(remotePeerID string, payload []byte) []byte {
		if remotePeerID != "peer-left" {
			t.Fatalf("expected remote peer-left, got %q", remotePeerID)
		}
		return []byte("custom:" + string(payload))
	}); err != nil {
		t.Fatalf("set exchange handler: %v", err)
	}
	if _, err := left.Establish("peer-left", "peer-right", []string{rightAddr}, 500*time.Millisecond); err != nil {
		t.Fatalf("establish encrypted session: %v", err)
	}
	response, err := left.Exchange("peer-left", "peer-right", []byte("hello-handler"), 500*time.Millisecond)
	if err != nil {
		t.Fatalf("exchange encrypted payload with custom handler: %v", err)
	}
	if string(response) != "custom:hello-handler" {
		t.Fatalf("expected custom exchange response, got %q", string(response))
	}
}

func TestAttemptFailsWhenNoPeerBindingExists(t *testing.T) {
	manager := New()
	defer manager.Close()

	if _, err := manager.Attempt("missing", "peer-right", []string{"127.0.0.1:41002"}, 50*time.Millisecond); err == nil {
		t.Fatalf("expected missing binding error")
	}
}

func TestManagerCanProbeSTUNUsingExistingListener(t *testing.T) {
	listenAddr := reserveUDPAddress(t)
	manager := New()
	defer manager.Close()

	if err := manager.Reconcile([]Binding{{Credentials: testCredentials("peer-left"), PeerID: "peer-left", ListenAddress: listenAddr}}); err != nil {
		t.Fatalf("reconcile listener: %v", err)
	}
	stunServer, err := stun.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen stun server: %v", err)
	}
	defer stunServer.Close()

	prober, ok := manager.(interface {
		ProbeSTUN(localPeerID, serverAddress string, timeout time.Duration) (stun.ProbeResult, error)
	})
	if !ok {
		t.Fatalf("manager does not implement STUN probe helper")
	}

	result, err := prober.ProbeSTUN("peer-left", stunServer.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatalf("probe STUN through bound listener: %v", err)
	}
	if result.LocalAddress != listenAddr {
		t.Fatalf("expected local address %q, got %#v", listenAddr, result)
	}
	if result.MappedAddress == "" {
		t.Fatalf("expected mapped address, got %#v", result)
	}
	if result.NATType != stun.NATTypeOpenInternet {
		t.Fatalf("expected NAT type %q, got %#v", stun.NATTypeOpenInternet, result)
	}
}

func reserveUDPAddress(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("reserve udp address: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	if err := conn.Close(); err != nil {
		t.Fatalf("close reserved udp address: %v", err)
	}
	return "127.0.0.1:" + strconv.Itoa(port)
}
