package relaytransport_test

import (
	"Ole/internal/relay"
	"Ole/internal/relaytransport"
	"Ole/internal/transportauth"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"
)

func testCredentials(peerID string) *transportauth.Credentials {
	seed := sha256.Sum256([]byte("test-only-" + peerID))
	keys := map[string]transportauth.Identity{}
	for _, id := range []string{"peer-a", "peer-b"} {
		keySeed := sha256.Sum256([]byte("test-only-" + id))
		keys[id] = transportauth.Identity{DeviceID: "device-" + id, PublicKey: ed25519.NewKeyFromSeed(keySeed[:]).Public().(ed25519.PublicKey)}
	}
	return &transportauth.Credentials{NetworkID: "test-network", PeerID: peerID, DeviceID: "device-" + peerID, PrivateKey: ed25519.NewKeyFromSeed(seed[:]), Peers: keys, ExpiresAt: time.Now().Add(transportauth.SnapshotTTL)}
}

func TestRelayTransportEstablishesAndForwardsPackets(t *testing.T) {
	server, err := relay.Listen("127.0.0.1:0", relay.StaticAuthorizer{})
	if err != nil {
		t.Fatalf("listen relay server: %v", err)
	}
	defer server.Close()

	manager := relaytransport.New()
	defer manager.Close()

	if err := manager.Reconcile([]relaytransport.Binding{
		{Credentials: testCredentials("peer-a"), PeerID: "peer-a", RelayAddress: server.LocalAddr().String(), AccessToken: "token-a"},
		{Credentials: testCredentials("peer-b"), PeerID: "peer-b", RelayAddress: server.LocalAddr().String(), AccessToken: "token-b"},
	}); err != nil {
		t.Fatalf("reconcile relay manager: %v", err)
	}

	if _, err := manager.Establish("peer-a", "peer-b", time.Second); err != nil {
		t.Fatalf("establish relay session from peer-a: %v", err)
	}
	waitForCondition(t, time.Second, func() bool {
		_, err := manager.Establish("peer-b", "peer-a", time.Second)
		return err == nil
	})

	ack, err := manager.Exchange("peer-a", "peer-b", []byte("hello"), time.Second)
	if err != nil {
		t.Fatalf("relay exchange: %v", err)
	}
	if string(ack) != "ack:hello" {
		t.Fatalf("unexpected relay exchange ack: %q", string(ack))
	}

	if err := manager.SendPacket("peer-a", "peer-b", []byte("payload")); err != nil {
		t.Fatalf("relay send packet: %v", err)
	}
	waitForCondition(t, time.Second, func() bool {
		packets := manager.DrainInbound("peer-b", 1)
		return len(packets) == 1 && string(packets[0].Payload) == "payload"
	})
}

func TestRelayTransportSupportsCustomExchangeHandlers(t *testing.T) {
	server, err := relay.Listen("127.0.0.1:0", relay.StaticAuthorizer{})
	if err != nil {
		t.Fatalf("listen relay server: %v", err)
	}
	defer server.Close()

	manager := relaytransport.New()
	defer manager.Close()

	if err := manager.Reconcile([]relaytransport.Binding{
		{Credentials: testCredentials("peer-a"), PeerID: "peer-a", RelayAddress: server.LocalAddr().String(), AccessToken: "token-a"},
		{Credentials: testCredentials("peer-b"), PeerID: "peer-b", RelayAddress: server.LocalAddr().String(), AccessToken: "token-b"},
	}); err != nil {
		t.Fatalf("reconcile relay manager: %v", err)
	}
	if err := manager.SetExchangeHandler("peer-b", func(remotePeerID string, payload []byte) []byte {
		if remotePeerID != "peer-a" {
			t.Fatalf("expected remote peer-a, got %q", remotePeerID)
		}
		return []byte("relay-custom:" + string(payload))
	}); err != nil {
		t.Fatalf("set relay exchange handler: %v", err)
	}

	if _, err := manager.Establish("peer-a", "peer-b", time.Second); err != nil {
		t.Fatalf("establish relay session from peer-a: %v", err)
	}
	waitForCondition(t, time.Second, func() bool {
		_, err := manager.Establish("peer-b", "peer-a", time.Second)
		return err == nil
	})

	ack, err := manager.Exchange("peer-a", "peer-b", []byte("hello-handler"), time.Second)
	if err != nil {
		t.Fatalf("relay exchange with custom handler: %v", err)
	}
	if string(ack) != "relay-custom:hello-handler" {
		t.Fatalf("unexpected relay custom exchange ack: %q", string(ack))
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not satisfied within %s", timeout)
}
