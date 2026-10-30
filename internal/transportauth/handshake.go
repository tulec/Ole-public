// Package transportauth authenticates the OLEP4 handshake against short-lived
// control-plane key snapshots. It does not trust keys advertised by UDP peers.
package transportauth

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

const Magic = "OLEP4"
const SnapshotTTL = 30 * time.Second
const pendingTTL = 5 * time.Second
const maxPending = 64

type Identity struct {
	DeviceID  string
	PublicKey ed25519.PublicKey
}

type Credentials struct {
	NetworkID, PeerID, DeviceID string
	PrivateKey                  ed25519.PrivateKey `json:"-"`
	Peers                       map[string]Identity
	ExpiresAt                   time.Time
}

type Established struct {
	SessionID, RemotePeerID, Proof string
	Secret                         []byte `json:"-"`
	Initiator                      bool
}

type Message struct {
	PeerID, SessionID, Wire string
}

type transcript struct {
	Network         string `json:"n"`
	ID              string `json:"s"`
	Initiator       string `json:"i"`
	Responder       string `json:"r"`
	InitiatorDevice string `json:"id"`
	ResponderDevice string `json:"rd"`
	InitiatorKey    string `json:"ik"`
	ResponderKey    string `json:"rk,omitempty"`
	Signature       string `json:"sig"`
}

type pending struct {
	transcript transcript
	private    *ecdh.PrivateKey
	initiator  bool
	proof      string
	created    time.Time
}

type Handshaker struct {
	mu          sync.Mutex
	path        string
	credentials *Credentials
	pending     map[string]pending
}

func New(path string) *Handshaker {
	return &Handshaker{path: path, pending: make(map[string]pending)}
}

// Update copies all key material. A nil snapshot disables authenticated traffic.
func (h *Handshaker) Update(c *Credentials) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c == nil {
		h.credentials = nil
		clear(h.pending)
		return nil
	}
	if !atom(c.NetworkID) || !atom(c.PeerID) || len(c.PeerID) > MaxPeerIDBytes || !atom(c.DeviceID) || len(c.PrivateKey) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(c.PrivateKey[:32]), c.PrivateKey) || !c.ExpiresAt.After(time.Now()) || time.Until(c.ExpiresAt) > SnapshotTTL {
		h.credentials = nil
		clear(h.pending)
		return errors.New("invalid transport credentials")
	}
	copy := *c
	copy.PrivateKey = bytes.Clone(c.PrivateKey)
	copy.Peers = make(map[string]Identity, len(c.Peers))
	for id, identity := range c.Peers {
		if !atom(id) || len(id) > MaxPeerIDBytes || !atom(identity.DeviceID) || len(identity.PublicKey) != ed25519.PublicKeySize {
			h.credentials = nil
			clear(h.pending)
			return errors.New("invalid transport peer credentials")
		}
		copy.Peers[id] = Identity{DeviceID: identity.DeviceID, PublicKey: bytes.Clone(identity.PublicKey)}
	}
	h.credentials = &copy
	h.prune()
	return nil
}

func (h *Handshaker) Allows(peerID, proof string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return proof != "" && proof == h.proof(peerID)
}

func (h *Handshaker) proof(peerID string) string {
	c := h.credentials
	if c == nil || !time.Now().Before(c.ExpiresAt) || peerID == c.PeerID {
		return ""
	}
	r, ok := c.Peers[peerID]
	if !ok {
		return ""
	}
	b, _ := json.Marshal([]string{Magic, h.path, c.NetworkID, c.PeerID, c.DeviceID, base64.StdEncoding.EncodeToString(c.PrivateKey.Public().(ed25519.PublicKey)), peerID, r.DeviceID, base64.StdEncoding.EncodeToString(r.PublicKey)})
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (h *Handshaker) prune() {
	for id, p := range h.pending {
		if time.Since(p.created) >= pendingTTL || p.proof != h.proof(p.remote()) {
			delete(h.pending, id)
		}
	}
}

func (p pending) remote() string {
	if p.initiator {
		return p.transcript.Responder
	}
	return p.transcript.Initiator
}

func (h *Handshaker) Begin(peerID string) (Message, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.prune()
	proof := h.proof(peerID)
	if proof == "" {
		return Message{}, errors.New("trusted transport identity is unavailable or expired")
	}
	for id, p := range h.pending {
		if p.remote() == peerID {
			if !p.initiator {
				return Message{PeerID: peerID, SessionID: id}, nil
			}
			kind := "hello"
			if p.transcript.ResponderKey != "" {
				kind = "finish"
			}
			return h.sign(kind, p.transcript), nil
		}
	}
	if len(h.pending) >= maxPending {
		return Message{}, errors.New("too many pending transport handshakes")
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Message{}, err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return Message{}, err
	}
	c := h.credentials
	t := transcript{Network: c.NetworkID, ID: hex.EncodeToString(nonce[:]), Initiator: c.PeerID, Responder: peerID, InitiatorDevice: c.DeviceID, ResponderDevice: c.Peers[peerID].DeviceID, InitiatorKey: base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())}
	h.pending[t.ID] = pending{transcript: t, private: private, initiator: true, proof: proof, created: time.Now()}
	return h.sign("hello", t), nil
}

// Handle authenticates before changing pending state. Only FINISH/READY produce
// a session, so replaying a signed HELLO cannot replace a working session.
func (h *Handshaker) Handle(parts []string) (Message, *Established, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.prune()
	bad := errors.New("invalid authenticated handshake")
	// Compact wire identifiers can expand to HTML-escaped JSON during decode.
	// The 1200-byte ingress and 64/128-byte fields still bound the transcript.
	if len(parts) != 5 || len(parts[4]) > 8192 {
		return Message{}, nil, bad
	}
	kind, source, target, id := parts[0], parts[1], parts[2], parts[3]
	if h.proof(source) == "" || target != h.credentials.PeerID {
		return Message{}, nil, bad
	}
	data, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return Message{}, nil, bad
	}
	var t transcript
	if err = json.Unmarshal(data, &t); err != nil || t.ID != id || len(id) != 32 {
		return Message{}, nil, bad
	}
	if _, err = hex.DecodeString(id); err != nil {
		return Message{}, nil, bad
	}
	c := h.credentials
	initiator := t.Initiator == c.PeerID
	if t.Network != c.NetworkID || t.Initiator == t.Responder {
		return Message{}, nil, bad
	}
	if initiator {
		if t.Responder != source || t.InitiatorDevice != c.DeviceID || t.ResponderDevice != c.Peers[source].DeviceID {
			return Message{}, nil, bad
		}
	} else {
		if t.Initiator != source || t.Responder != c.PeerID || t.ResponderDevice != c.DeviceID || t.InitiatorDevice != c.Peers[source].DeviceID {
			return Message{}, nil, bad
		}
	}
	sig, err := base64.StdEncoding.DecodeString(t.Signature)
	if err != nil || !ed25519.Verify(c.Peers[source].PublicKey, h.signedBytes(kind, t), sig) {
		return Message{}, nil, bad
	}
	if kind == "hello" {
		if initiator || t.ResponderKey != "" {
			return Message{}, nil, bad
		}
		if _, err = decodeKey(t.InitiatorKey); err != nil {
			return Message{}, nil, bad
		}
		if old, ok := h.pending[id]; ok {
			base := old.transcript
			base.ResponderKey = ""
			if old.initiator || !same(base, t) {
				return Message{}, nil, bad
			}
			return h.sign("welcome", old.transcript), nil, nil
		}
		// Simultaneous initiation converges on the lexicographically first peer.
		for _, p := range h.pending {
			if p.initiator && p.remote() == source && c.PeerID < source {
				return Message{}, nil, bad
			}
		}
		if len(h.pending) >= maxPending {
			return Message{}, nil, bad
		}
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return Message{}, nil, err
		}
		t.ResponderKey = base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
		h.pending[id] = pending{transcript: t, private: private, proof: h.proof(source), created: time.Now()}
		return h.sign("welcome", t), nil, nil
	}
	p, ok := h.pending[id]
	if !ok || p.remote() != source || p.initiator != initiator {
		return Message{}, nil, bad
	}
	switch kind {
	case "welcome":
		if !initiator {
			return Message{}, nil, bad
		}
		base := t
		base.ResponderKey = ""
		old := p.transcript
		old.ResponderKey = ""
		if !same(base, old) || (p.transcript.ResponderKey != "" && !same(t, p.transcript)) {
			return Message{}, nil, bad
		}
		for _, other := range h.pending {
			if !other.initiator && other.remote() == source && c.PeerID > source {
				return Message{}, nil, bad
			}
		}
		if _, err = decodeKey(t.ResponderKey); err != nil {
			return Message{}, nil, bad
		}
		p.transcript = t
		h.pending[id] = p
		return h.sign("finish", t), nil, nil
	case "finish", "ready":
		if (kind == "ready") != initiator || !same(t, p.transcript) {
			return Message{}, nil, bad
		}
		key := t.InitiatorKey
		if initiator {
			key = t.ResponderKey
		}
		public, err := decodeKey(key)
		if err != nil {
			return Message{}, nil, bad
		}
		secret, err := p.private.ECDH(public)
		if err != nil {
			return Message{}, nil, bad
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write(h.signedBytes("session", t))
		result := &Established{SessionID: id, RemotePeerID: source, Proof: p.proof, Secret: mac.Sum(nil), Initiator: initiator}
		// Cancel losing attempts before notifying either transport. A delayed
		// WELCOME from a simultaneous attempt must not create a second session.
		for pendingID, other := range h.pending {
			if other.remote() == source {
				delete(h.pending, pendingID)
			}
		}
		if kind == "finish" {
			return h.sign("ready", t), result, nil
		}
		return Message{}, result, nil
	default:
		return Message{}, nil, bad
	}
}

func (h *Handshaker) Cancel(id string) { h.mu.Lock(); defer h.mu.Unlock(); delete(h.pending, id) }

func (h *Handshaker) signedBytes(kind string, t transcript) []byte {
	b, _ := json.Marshal([]string{Magic, h.path, kind, t.Network, t.ID, t.Initiator, t.Responder, t.InitiatorDevice, t.ResponderDevice, t.InitiatorKey, t.ResponderKey})
	return b
}

func (h *Handshaker) sign(kind string, t transcript) Message {
	t.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(h.credentials.PrivateKey, h.signedBytes(kind, t)))
	b, _ := json.Marshal(t)
	peer := t.Initiator
	if peer == h.credentials.PeerID {
		peer = t.Responder
	}
	return Message{PeerID: peer, SessionID: t.ID, Wire: strings.Join([]string{Magic, kind, h.credentials.PeerID, peer, t.ID, base64.StdEncoding.EncodeToString(b)}, "|")}
}

func same(a, b transcript) bool { a.Signature = ""; b.Signature = ""; return a == b }
func decodeKey(s string) (*ecdh.PublicKey, error) {
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil {
		return nil, e
	}
	return ecdh.X25519().NewPublicKey(b)
}
func atom(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r < '!' || r > '~' || r == '|' {
			return false
		}
	}
	return true
}
