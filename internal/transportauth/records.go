package transportauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"sync"
)

const ReplayWindowSize = 256

var (
	ErrInvalidRecord    = errors.New("invalid authenticated transport record")
	ErrDuplicateRecord  = errors.New("duplicate transport record")
	ErrRecordTooOld     = errors.New("transport record is outside the receive window")
	ErrCounterExhausted = errors.New("transport counter exhausted; rekey required")
)

type RecordStats struct {
	Accepted           uint64 `json:"accepted"`
	Duplicates         uint64 `json:"duplicates"`
	TooOld             uint64 `json:"tooOld"`
	Invalid            uint64 `json:"invalid"`
	CounterExhaustions uint64 `json:"counterExhaustions"`
}

// Observe is called under the owning listener's lock. Counters survive rekey.
func (s *RecordStats) Observe(err error) {
	switch {
	case err == nil:
		s.Accepted++
	case errors.Is(err, ErrDuplicateRecord):
		s.Duplicates++
	case errors.Is(err, ErrRecordTooOld):
		s.TooOld++
	case errors.Is(err, ErrCounterExhausted):
		s.CounterExhaustions++
	default:
		s.Invalid++
	}
}

type DataPlaneStats struct {
	Records  RecordStats   `json:"records"`
	Queue    QueueStats    `json:"queue"`
	Wire     WireStats     `json:"wire"`
	Assembly AssemblyStats `json:"assembly"`
}

type replayWindow struct {
	highest uint64
	seen    [ReplayWindowSize / 64]uint64
}

func (w *replayWindow) check(counter uint64) error {
	if counter == 0 {
		return ErrInvalidRecord
	}
	if counter > w.highest {
		return nil
	}
	distance := w.highest - counter
	if distance >= ReplayWindowSize {
		return ErrRecordTooOld
	}
	if w.seen[distance/64]&(uint64(1)<<(distance%64)) != 0 {
		return ErrDuplicateRecord
	}
	return nil
}

// accept is called only after successful AEAD authentication, under Records.mu.
func (w *replayWindow) accept(counter uint64) error {
	if counter == 0 {
		return ErrInvalidRecord
	}
	if counter > w.highest {
		shift := counter - w.highest
		var shifted [ReplayWindowSize / 64]uint64
		if shift < ReplayWindowSize {
			words, bits := int(shift/64), uint(shift%64)
			for dst := len(shifted) - 1; dst >= 0; dst-- {
				src := dst - words
				if src >= 0 {
					shifted[dst] = w.seen[src] << bits
					if bits > 0 && src > 0 {
						shifted[dst] |= w.seen[src-1] >> (64 - bits)
					}
				}
			}
		}
		w.seen = shifted
		w.highest = counter
		w.seen[0] |= 1
		return nil
	}
	distance := w.highest - counter
	if distance >= ReplayWindowSize {
		return ErrRecordTooOld
	}
	word, bit := int(distance/64), uint(distance%64)
	mask := uint64(1) << bit
	if w.seen[word]&mask != 0 {
		return ErrDuplicateRecord
	}
	w.seen[word] |= mask
	return nil
}

// Records owns both directional counters and AEADs of one authenticated session.
// One receive window covers packet, data and dataack together.
type Records struct {
	fragmentSend, fragmentReceive              []byte
	contextID                                  string
	pool                                       *ReassemblyPool
	disabled                                   bool
	mu                                         sync.Mutex
	path, sessionID, localPeerID, remotePeerID string
	send, receive                              cipher.AEAD
	sendCounter                                uint64
	replay                                     replayWindow
}

func NewRecords(path, sessionID, localPeerID, remotePeerID string, secret []byte, initiator bool, pools ...*ReassemblyPool) (*Records, error) {
	if (path != "DIRECT" && path != "RELAY") || sessionID == "" || localPeerID == "" || remotePeerID == "" || localPeerID == remotePeerID || len(secret) != sha256.Size {
		return nil, ErrInvalidRecord
	}
	sendLabel, receiveLabel := "responder->initiator", "initiator->responder"
	if initiator {
		sendLabel, receiveLabel = receiveLabel, sendLabel
	}
	makeAEAD := func(label string) (cipher.AEAD, error) {
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(Magic + "|" + sessionID + "|" + label))
		block, err := aes.NewCipher(mac.Sum(nil))
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
	send, err := makeAEAD(sendLabel)
	if err != nil {
		return nil, err
	}
	receive, err := makeAEAD(receiveLabel)
	if err != nil {
		return nil, err
	}
	deriveFragment := func(label string) []byte {
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(Magic + "|" + sessionID + "|fragment|" + label))
		return mac.Sum(nil)
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	pool := NewReassemblyPool()
	if len(pools) > 0 && pools[0] != nil {
		pool = pools[0]
	}
	return &Records{path: path, sessionID: sessionID, localPeerID: localPeerID, remotePeerID: remotePeerID, send: send, receive: receive, fragmentSend: deriveFragment(sendLabel), fragmentReceive: deriveFragment(receiveLabel), contextID: hex.EncodeToString(id[:]), pool: pool}, nil
}

func (r *Records) Seal(kind string, requestCounter uint64, payload []byte) (uint64, []byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(payload) > recordLimit(kind) {
		return 0, nil, ErrMessageTooLarge
	}
	if r.disabled {
		return 0, nil, ErrInvalidRecord
	}
	if !recordKind(kind, requestCounter) {
		return 0, nil, ErrInvalidRecord
	}
	if r.sendCounter == math.MaxUint64 {
		return 0, nil, ErrCounterExhausted
	}
	r.sendCounter++
	counter := r.sendCounter
	return counter, r.send.Seal(nil, recordNonce(counter), payload, r.aad(kind, r.localPeerID, r.remotePeerID, counter, requestCounter)), nil
}

func (r *Records) Open(kind string, counter, requestCounter uint64, ciphertext []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.disabled || len(ciphertext) > recordLimit(kind)+16 {
		return nil, ErrInvalidRecord
	}
	if counter == 0 || !recordKind(kind, requestCounter) {
		return nil, ErrInvalidRecord
	}
	plaintext, err := r.receive.Open(nil, recordNonce(counter), ciphertext, r.aad(kind, r.remotePeerID, r.localPeerID, counter, requestCounter))
	if err != nil {
		return nil, ErrInvalidRecord
	}
	if err := r.replay.accept(counter); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func recordLimit(kind string) int {
	if kind == "dataack" {
		return MaxResponseBytes
	}
	return MaxMessageBytes
}

func recordKind(kind string, requestCounter uint64) bool {
	switch kind {
	case "packet", "data":
		return requestCounter == 0
	case "dataack":
		return requestCounter != 0
	default:
		return false
	}
}

func recordNonce(counter uint64) []byte {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce[:]
}

func (r *Records) aad(kind, source, target string, counter, requestCounter uint64) []byte {
	b, _ := json.Marshal([]string{Magic, "record", r.path, kind, source, target, r.sessionID, strconv.FormatUint(counter, 10), strconv.FormatUint(requestCounter, 10)})
	return b
}
