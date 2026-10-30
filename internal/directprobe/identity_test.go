package directprobe

import (
	"crypto/ed25519"
	"crypto/sha256"
	"sync"
	"testing"
	"time"
)

func TestPeerImpersonationCannotReplaceWorkingSession(t *testing.T) {
	left, right, attacker := New(), New(), New()
	t.Cleanup(func() { left.Close(); right.Close(); attacker.Close() })
	leftAddr, rightAddr, attackerAddr := reserveUDPAddress(t), reserveUDPAddress(t), reserveUDPAddress(t)
	for _, item := range []struct {
		manager  Manager
		id, addr string
	}{
		{left, "peer-left", leftAddr}, {right, "peer-right", rightAddr}, {attacker, "peer-left", attackerAddr},
	} {
		credentials := testCredentials(item.id)
		if item.manager == attacker {
			seed := sha256.Sum256([]byte("attacker"))
			credentials.PrivateKey = ed25519.NewKeyFromSeed(seed[:])
		}
		if err := item.manager.Reconcile([]Binding{{Credentials: credentials, PeerID: item.id, ListenAddress: item.addr}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := left.Establish("peer-left", "peer-right", []string{rightAddr}, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := attacker.Establish("peer-left", "peer-right", []string{rightAddr}, 100*time.Millisecond); err == nil {
		t.Error("attacker established a session using another peer's identity")
		if response, err := attacker.Exchange("peer-left", "peer-right", []byte("attacker-payload"), time.Second); err == nil {
			t.Errorf("receiver accepted impersonated traffic: %s", response)
		}
	}
	response, err := left.Exchange("peer-left", "peer-right", []byte("legitimate"), 200*time.Millisecond)
	if err != nil || string(response) != "ack:legitimate" {
		t.Error("attack disrupted the legitimate session")
	}
}

func TestSimultaneousAuthenticatedHandshakesConverge(t *testing.T) {
	left, right := New(), New()
	defer left.Close()
	defer right.Close()
	leftAddr, rightAddr := reserveUDPAddress(t), reserveUDPAddress(t)
	if err := left.Reconcile([]Binding{{PeerID: "peer-left", ListenAddress: leftAddr, Credentials: testCredentials("peer-left")}}); err != nil {
		t.Fatal(err)
	}
	if err := right.Reconcile([]Binding{{PeerID: "peer-right", ListenAddress: rightAddr, Credentials: testCredentials("peer-right")}}); err != nil {
		t.Fatal(err)
	}
	var sessions [2]Session
	var errors [2]error
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		sessions[0], errors[0] = left.Establish("peer-left", "peer-right", []string{rightAddr}, time.Second)
	}()
	go func() {
		defer wg.Done()
		<-start
		sessions[1], errors[1] = right.Establish("peer-right", "peer-left", []string{leftAddr}, time.Second)
	}()
	close(start)
	wg.Wait()
	if errors[0] != nil || errors[1] != nil || sessions[0].SessionID != sessions[1].SessionID {
		t.Fatalf("simultaneous handshakes did not converge: %v", errors)
	}
	if response, err := left.Exchange("peer-left", "peer-right", []byte("after-overlap"), time.Second); err != nil || string(response) != "ack:after-overlap" {
		t.Fatal("overlap broke traffic", err)
	}
}

func TestExpiredIdentityBlocksActiveAndQueuedTraffic(t *testing.T) {
	left, right := New(), New()
	defer left.Close()
	defer right.Close()
	leftAddr, rightAddr := reserveUDPAddress(t), reserveUDPAddress(t)
	for _, item := range []struct {
		m        Manager
		id, addr string
	}{{left, "peer-left", leftAddr}, {right, "peer-right", rightAddr}} {
		if err := item.m.Reconcile([]Binding{{PeerID: item.id, ListenAddress: item.addr, Credentials: testCredentials(item.id)}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := left.Establish("peer-left", "peer-right", []string{rightAddr}, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := left.SendPacket("peer-left", "peer-right", []byte("queued")); err != nil {
		t.Fatal(err)
	}
	r, err := right.(*manager).listenerFor("peer-right")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		r.mu.Lock()
		queued := r.inbound.Stats().Packets > 0
		r.mu.Unlock()
		if queued {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("packet was not queued")
		}
		time.Sleep(time.Millisecond)
	}
	c := testCredentials("peer-right")
	c.ExpiresAt = time.Now().Add(20 * time.Millisecond)
	if err := r.updateCredentials(c); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(c.ExpiresAt) + time.Millisecond)
	if err := right.SendPacket("peer-right", "peer-left", []byte("expired")); err == nil {
		t.Fatal("expired identity sent traffic")
	}
	if len(right.DrainInbound("peer-right", 10)) != 0 {
		t.Fatal("expired identity delivered queued traffic")
	}
	if _, err := left.Exchange("peer-left", "peer-right", []byte("expired"), 50*time.Millisecond); err == nil {
		t.Fatal("expired identity received traffic")
	}
}
