package transportauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func credentials(id string) *Credentials {
	key := func(id string) ed25519.PrivateKey {
		seed := sha256.Sum256([]byte("test-only-" + id))
		return ed25519.NewKeyFromSeed(seed[:])
	}
	c := &Credentials{NetworkID: "network", PeerID: id, DeviceID: "device-" + id, PrivateKey: key(id), ExpiresAt: time.Now().Add(SnapshotTTL), Peers: map[string]Identity{}}
	for _, id := range []string{"a", "b", "c"} {
		c.Peers[id] = Identity{DeviceID: "device-" + id, PublicKey: key(id).Public().(ed25519.PublicKey)}
	}
	return c
}

func pair(t *testing.T) (*Handshaker, *Handshaker) {
	t.Helper()
	a, b := New("DIRECT"), New("DIRECT")
	if err := a.Update(credentials("a")); err != nil {
		t.Fatal(err)
	}
	if err := b.Update(credentials("b")); err != nil {
		t.Fatal(err)
	}
	return a, b
}

func parts(m Message) []string { return strings.Split(m.Wire, "|")[1:] }

func complete(t *testing.T, a, b *Handshaker) (*Established, *Established, Message) {
	t.Helper()
	hello, err := a.Begin("b")
	if err != nil {
		t.Fatal(err)
	}
	welcome, session, err := b.Handle(parts(hello))
	if err != nil || session != nil {
		t.Fatal("HELLO must not install a session", err)
	}
	finish, session, err := a.Handle(parts(welcome))
	if err != nil || session != nil {
		t.Fatal("WELCOME must not install a session", err)
	}
	ready, right, err := b.Handle(parts(finish))
	if err != nil || right == nil {
		t.Fatal("FINISH must authenticate initiator", err)
	}
	_, left, err := a.Handle(parts(ready))
	if err != nil || left == nil {
		t.Fatal("READY must authenticate responder", err)
	}
	return left, right, hello
}

func TestAuthenticatedHandshakeAndReplay(t *testing.T) {
	a, b := pair(t)
	left, right, hello := complete(t, a, b)
	if left.SessionID != right.SessionID || !bytes.Equal(left.Secret, right.Secret) || !left.Initiator || right.Initiator {
		t.Fatal("session key agreement failed")
	}
	if !a.Allows("b", left.Proof) || !b.Allows("a", right.Proof) {
		t.Fatal("authenticated sessions lost their trusted identities")
	}
	// An old signed HELLO can solicit a fresh challenge, but cannot install a
	// session without a new signature over that responder's ephemeral key.
	welcome, session, err := b.Handle(parts(hello))
	if err != nil || session != nil {
		t.Fatal("replayed HELLO installed a session")
	}
	if welcome.Wire == "" {
		t.Fatal("expected fresh challenge")
	}
	if !b.Allows("a", right.Proof) {
		t.Fatal("replay revoked the legitimate identity")
	}
	_, _, err = a.Handle(parts(welcome))
	if err == nil {
		t.Fatal("unsolicited WELCOME was accepted")
	}
}

func TestHandshakeRejectsTamperingWithoutConsumingPending(t *testing.T) {
	for _, field := range []string{"source", "target", "session", "network", "initiator", "responder", "initiator-device", "responder-device", "initiator-key", "responder-key", "signature"} {
		t.Run(field, func(t *testing.T) {
			a, b := pair(t)
			hello, _ := a.Begin("b")
			welcome, _, err := b.Handle(parts(hello))
			if err != nil {
				t.Fatal(err)
			}
			p := parts(welcome)
			raw, _ := base64.StdEncoding.DecodeString(p[4])
			var body transcript
			_ = json.Unmarshal(raw, &body)
			switch field {
			case "source":
				p[1] = "c"
			case "target":
				p[2] = "c"
			case "session":
				p[3] = strings.Repeat("a", 32)
			case "network":
				body.Network = "another-network"
			case "initiator":
				body.Initiator = "c"
			case "responder":
				body.Responder = "c"
			case "initiator-device":
				body.InitiatorDevice = "other-device"
			case "responder-device":
				body.ResponderDevice = "other-device"
			case "initiator-key":
				body.InitiatorKey = body.ResponderKey
			case "responder-key":
				body.ResponderKey = body.InitiatorKey
			case "signature":
				body.Signature = strings.Repeat("A", 88)
			}
			raw, _ = json.Marshal(body)
			p[4] = base64.StdEncoding.EncodeToString(raw)
			if _, s, err := a.Handle(p); err == nil || s != nil {
				t.Fatal("tampered handshake was accepted")
			}
			finish, _, err := a.Handle(parts(welcome))
			if err != nil {
				t.Fatal("attack consumed legitimate pending handshake", err)
			}
			ready, _, err := b.Handle(parts(finish))
			if err != nil {
				t.Fatal(err)
			}
			if _, s, err := a.Handle(parts(ready)); err != nil || s == nil {
				t.Fatal("legitimate handshake failed after attack", err)
			}
		})
	}
}

func TestSignedWelcomeMustMatchInitiatorTranscript(t *testing.T) {
	a, b := pair(t)
	hello, _ := a.Begin("b")
	welcome, _, _ := b.Handle(parts(hello))
	raw, _ := base64.StdEncoding.DecodeString(parts(welcome)[4])
	var body transcript
	_ = json.Unmarshal(raw, &body)
	body.InitiatorKey = body.ResponderKey
	forged := b.sign("welcome", body)
	if _, s, err := a.Handle(parts(forged)); err == nil || s != nil {
		t.Fatal("signed response changed the initiator's ephemeral key")
	}
	if _, _, err := a.Handle(parts(welcome)); err != nil {
		t.Fatal("invalid response consumed pending handshake")
	}
}

func TestHandshakeDomainSeparationAndMissingTrust(t *testing.T) {
	a, b := pair(t)
	hello, _ := a.Begin("b")
	b.path = "RELAY"
	if _, s, err := b.Handle(parts(hello)); err == nil || s != nil {
		t.Fatal("DIRECT signature accepted in RELAY")
	}
	if _, err := New("DIRECT").Begin("b"); err == nil {
		t.Fatal("missing credentials permitted a handshake")
	}
	if _, err := a.Begin("unknown"); err == nil {
		t.Fatal("unknown peer permitted")
	}
	if _, err := a.Begin("a"); err == nil {
		t.Fatal("self handshake permitted")
	}
	b.path = "DIRECT"
	c := credentials("b")
	delete(c.Peers, "a")
	if err := b.Update(c); err != nil {
		t.Fatal(err)
	}
	if _, s, err := b.Handle(parts(hello)); err == nil || s != nil {
		t.Fatal("removed peer permitted")
	}
}

func TestCredentialsRotationRevocationAndExpiry(t *testing.T) {
	a, b := pair(t)
	left, right, _ := complete(t, a, b)
	c := credentials("a")
	if err := a.Update(c); err != nil {
		t.Fatal(err)
	}
	if !a.Allows("b", left.Proof) {
		t.Fatal("same-key refresh broke working identity")
	}
	seed := sha256.Sum256([]byte("rotated-b"))
	key := ed25519.NewKeyFromSeed(seed[:])
	c.Peers["b"] = Identity{DeviceID: "device-b", PublicKey: key.Public().(ed25519.PublicKey)}
	if err := a.Update(c); err != nil {
		t.Fatal(err)
	}
	if a.Allows("b", left.Proof) {
		t.Fatal("rotated key left old session authorized")
	}
	cb := credentials("b")
	cb.PrivateKey = key
	if err := b.Update(cb); err != nil {
		t.Fatal(err)
	}
	newLeft, newRight, _ := complete(t, a, b)
	if bytes.Equal(newLeft.Secret, left.Secret) || !bytes.Equal(newLeft.Secret, newRight.Secret) {
		t.Fatal("rotation did not negotiate a fresh key")
	}
	if err := b.Update(nil); err != nil {
		t.Fatal(err)
	}
	if b.Allows("a", right.Proof) || b.Allows("a", newRight.Proof) {
		t.Fatal("revoked credentials remained active")
	}
	a.credentials.ExpiresAt = time.Now().Add(-time.Second)
	if a.Allows("b", newLeft.Proof) {
		t.Fatal("expired credentials remained active")
	}
	if _, err := a.Begin("b"); err == nil {
		t.Fatal("expired credentials permitted a new handshake")
	}
}

func TestHelloReplayAndPendingBounds(t *testing.T) {
	a, b := pair(t)
	hello, _ := a.Begin("b")
	welcome, _, err := b.Handle(parts(hello))
	if err != nil {
		t.Fatal(err)
	}
	repeated, s, err := b.Handle(parts(hello))
	if err != nil || s != nil || repeated.Wire != welcome.Wire {
		t.Fatal("duplicate HELLO reset the responder challenge")
	}
	for i := 1; i < maxPending; i++ {
		a.Cancel(hello.SessionID)
		m, err := a.Begin("b")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = b.Handle(parts(m)); err != nil {
			t.Fatal(err)
		}
		hello = m
	}
	if len(a.pending) != 1 || len(b.pending) != maxPending {
		t.Fatal("unexpected pending count")
	}
	a.Cancel(hello.SessionID)
	next, err := a.Begin("b")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Handle(parts(next)); err == nil {
		t.Fatal("pending limit not enforced")
	}
	for id, p := range b.pending {
		p.created = time.Now().Add(-pendingTTL)
		b.pending[id] = p
	}
	if _, _, err := b.Handle(parts(next)); err != nil {
		t.Fatal("expired pending entries were not removed", err)
	}
}

func TestReplayedFinishCannotCompleteFreshChallenge(t *testing.T) {
	a, b := pair(t)
	hello, _ := a.Begin("b")
	welcome, _, _ := b.Handle(parts(hello))
	finish, _, _ := a.Handle(parts(welcome))
	ready, _, _ := b.Handle(parts(finish))
	_, _, _ = a.Handle(parts(ready))
	if _, s, err := b.Handle(parts(finish)); err == nil || s != nil {
		t.Fatal("replayed FINISH installed a session")
	}
	_, s, err := b.Handle(parts(hello))
	if err != nil || s != nil {
		t.Fatal("replayed HELLO installed a session")
	}
	if _, s, err := b.Handle(parts(finish)); err == nil || s != nil {
		t.Fatal("old FINISH completed a new responder challenge")
	}
}

func TestTransportSecretsAreExcludedFromJSON(t *testing.T) {
	c := credentials("a")
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(base64.StdEncoding.EncodeToString(c.PrivateKey))) || bytes.Contains(b, []byte("PrivateKey")) {
		t.Fatal("JSON disclosed private signing key")
	}
	b, err = json.Marshal(Established{Secret: []byte("private-session-material")})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("Secret")) {
		t.Fatal("JSON disclosed session material")
	}
}

func TestPreviousWireVersionCannotAuthenticate(t *testing.T) {
	a, b := pair(t)
	hello, err := a.Begin("b")
	if err != nil {
		t.Fatal(err)
	}
	p := parts(hello)
	raw, err := base64.StdEncoding.DecodeString(p[4])
	if err != nil {
		t.Fatal(err)
	}
	var body transcript
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	oldTranscript, err := json.Marshal([]string{"OLEP2", "DIRECT", "hello", body.Network, body.ID, body.Initiator, body.Responder, body.InitiatorDevice, body.ResponderDevice, body.InitiatorKey, body.ResponderKey})
	if err != nil {
		t.Fatal(err)
	}
	body.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(a.credentials.PrivateKey, oldTranscript))
	raw, err = json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	p[4] = base64.StdEncoding.EncodeToString(raw)
	if _, session, err := b.Handle(p); err == nil || session != nil {
		t.Fatal("rewritten old-version handshake authenticated")
	}
}
