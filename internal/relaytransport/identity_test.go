package relaytransport

import (
	"Ole/internal/relay"
	"Ole/internal/transportauth"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestForgedRelayDeliveryCannotReplaceWorkingSession(t *testing.T) {
	server, err := relay.Listen("127.0.0.1:0", relay.StaticAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	_, leftKey, _ := ed25519.GenerateKey(rand.Reader)
	_, rightKey, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]transportauth.Identity{"a": {DeviceID: "da", PublicKey: leftKey.Public().(ed25519.PublicKey)}, "b": {DeviceID: "db", PublicKey: rightKey.Public().(ed25519.PublicKey)}}
	c := func(id, device string, key ed25519.PrivateKey) *transportauth.Credentials {
		return &transportauth.Credentials{NetworkID: "network", PeerID: id, DeviceID: device, PrivateKey: key, Peers: keys, ExpiresAt: time.Now().Add(transportauth.SnapshotTTL)}
	}
	m := New()
	defer m.Close()
	if err := m.Reconcile([]Binding{{PeerID: "a", RelayAddress: server.LocalAddr().String(), AccessToken: "a", Credentials: c("a", "da", leftKey)}, {PeerID: "b", RelayAddress: server.LocalAddr().String(), AccessToken: "b", Credentials: c("b", "db", rightKey)}}); err != nil {
		t.Fatal(err)
	}
	session, err := m.Establish("a", "b", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	right, err := m.(*manager).listenerFor("b")
	if err != nil {
		t.Fatal(err)
	}
	_, attackerKey, _ := ed25519.GenerateKey(rand.Reader)
	attacker := transportauth.New("RELAY")
	if err := attacker.Update(c("a", "da", attackerKey)); err != nil {
		t.Fatal(err)
	}
	forged, err := attacker.Begin("b")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: right.conn.LocalAddr().(*net.UDPAddr).Port})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	encoded, encodeErr := transportauth.EncodeRelay(fmt.Sprintf("OLER2|deliver|a|%s", hex.EncodeToString([]byte(forged.Wire))))
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	if _, err := conn.Write(encoded); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		right.mu.Lock()
		rejected := right.rejectedHandshakes > 0
		right.mu.Unlock()
		if rejected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("forged delivery was not processed and rejected")
		}
		time.Sleep(time.Millisecond)
	}
	if response, err := m.Exchange("a", "b", []byte("still-legitimate"), time.Second); err != nil || string(response) != "ack:still-legitimate" {
		t.Fatal("forgery disrupted working relay session", err)
	}
	if active, ok := right.sessionForRemote("a"); !ok || active.sessionID != session.SessionID {
		t.Fatal("forged UDP delivery replaced the relay session")
	}
}
