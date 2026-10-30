package transportauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

const DatagramBudget = 1200
const MaxMessageBytes = 1500

// MaxResponseBytes includes the default Exchange handler's "ack:" prefix.
const MaxResponseBytes = MaxMessageBytes + 4
const DefaultAdapterMTU = 1280
const MaxPeerIDBytes = 64
const MaxTokenBytes = 512
const FragmentBytes = 448
const MaxCipherBytes = MaxResponseBytes + 16
const MaxAssemblies = 32
const MaxAssemblyBytes = MaxAssemblies * MaxCipherBytes
const AssemblyTTL = 2 * time.Second

var ErrMessageTooLarge = errors.New("transport message exceeds its size limit")
var ErrAssemblyBudget = errors.New("transport reassembly budget exhausted")

type Fragment struct {
	Kind                string
	Counter, Reference  uint64
	Index, Count, Total int
	Tag, Data           []byte
}

type WireStats struct {
	OversizedInbound uint64 `json:"oversizedInbound"`
	RejectedOutbound uint64 `json:"rejectedOutbound"`
	MalformedInbound uint64 `json:"malformedInbound"`
}
type AssemblyStats struct {
	Pending    int    `json:"pending"`
	Bytes      int    `json:"bytes"`
	Completed  uint64 `json:"completed"`
	Expired    uint64 `json:"expired"`
	Overflow   uint64 `json:"overflow"`
	Duplicates uint64 `json:"duplicates"`
	Conflicts  uint64 `json:"conflicts"`
}
type assemblyKey struct {
	context string
	counter uint64
}
type assembly struct {
	kind         string
	reference    uint64
	count, total int
	data         []byte
	seen         uint8
	created      time.Time
}
type ReassemblyPool struct {
	mu     sync.Mutex
	groups map[assemblyKey]*assembly
	bytes  int
	stats  AssemblyStats
}

func NewReassemblyPool() *ReassemblyPool { return &ReassemblyPool{groups: map[assemblyKey]*assembly{}} }
func (p *ReassemblyPool) pruneLocked() {
	for key, g := range p.groups {
		if time.Since(g.created) >= AssemblyTTL {
			p.bytes -= g.total
			delete(p.groups, key)
			p.stats.Expired++
		}
	}
}
func (p *ReassemblyPool) Prune() { p.mu.Lock(); defer p.mu.Unlock(); p.pruneLocked() }
func (p *ReassemblyPool) Drop(context string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, g := range p.groups {
		if key.context == context {
			p.bytes -= g.total
			delete(p.groups, key)
		}
	}
}
func (p *ReassemblyPool) Stats() AssemblyStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked()
	s := p.stats
	s.Pending = len(p.groups)
	s.Bytes = p.bytes
	return s
}

func (p *ReassemblyPool) add(context string, f Fragment) ([]byte, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked()
	key := assemblyKey{context, f.Counter}
	g := p.groups[key]
	if g == nil {
		if len(p.groups) >= MaxAssemblies || f.Total > MaxAssemblyBytes-p.bytes {
			p.stats.Overflow++
			return nil, false, ErrAssemblyBudget
		}
		g = &assembly{kind: f.Kind, reference: f.Reference, count: f.Count, total: f.Total, data: make([]byte, f.Total), created: time.Now()}
		p.groups[key] = g
		p.bytes += f.Total
	}
	if g.kind != f.Kind || g.reference != f.Reference || g.count != f.Count || g.total != f.Total {
		p.bytes -= g.total
		delete(p.groups, key)
		p.stats.Conflicts++
		return nil, false, ErrInvalidRecord
	}
	bit := uint8(1) << f.Index
	if g.seen&bit != 0 {
		p.stats.Duplicates++
		return nil, false, nil
	}
	copy(g.data[f.Index*FragmentBytes:], f.Data)
	g.seen |= bit
	if g.seen != (1<<g.count)-1 {
		return nil, false, nil
	}
	p.bytes -= g.total
	delete(p.groups, key)
	p.stats.Completed++
	return g.data, true, nil
}

func validFragment(f Fragment) bool {
	if !recordKind(f.Kind, f.Reference) || f.Counter == 0 || f.Total <= FragmentBytes || f.Total > recordLimit(f.Kind)+16 || f.Count != (f.Total+FragmentBytes-1)/FragmentBytes || f.Index < 0 || f.Index >= f.Count || len(f.Tag) != 16 {
		return false
	}
	expected := FragmentBytes
	if f.Index == f.Count-1 {
		expected = f.Total - f.Index*FragmentBytes
	}
	return len(f.Data) == expected
}

func fragmentMAC(key, aad []byte, f Fragment) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(Magic + "/fragment"))
	var header [8]byte
	binary.BigEndian.PutUint16(header[:2], uint16(len(aad)))
	binary.BigEndian.PutUint16(header[2:4], uint16(f.Index))
	binary.BigEndian.PutUint16(header[4:6], uint16(f.Count))
	binary.BigEndian.PutUint16(header[6:8], uint16(f.Total))
	mac.Write(header[:])
	mac.Write(aad)
	mac.Write(f.Data)
	return mac.Sum(nil)[:16]
}

func (r *Records) Fragments(kind string, counter, reference uint64, ciphertext []byte) ([]Fragment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.disabled || counter == 0 || !recordKind(kind, reference) || len(ciphertext) > recordLimit(kind)+16 || len(ciphertext) <= FragmentBytes {
		return nil, ErrInvalidRecord
	}
	count := (len(ciphertext) + FragmentBytes - 1) / FragmentBytes
	result := make([]Fragment, 0, count)
	for i := 0; i < count; i++ {
		end := (i + 1) * FragmentBytes
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		f := Fragment{Kind: kind, Counter: counter, Reference: reference, Index: i, Count: count, Total: len(ciphertext), Data: ciphertext[i*FragmentBytes : end]}
		f.Tag = fragmentMAC(r.fragmentSend, r.aad(kind, r.localPeerID, r.remotePeerID, counter, reference), f)
		result = append(result, f)
	}
	return result, nil
}

func (r *Records) OpenFragment(f Fragment) ([]byte, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.disabled || !validFragment(f) || !hmac.Equal(f.Tag, fragmentMAC(r.fragmentReceive, r.aad(f.Kind, r.remotePeerID, r.localPeerID, f.Counter, f.Reference), f)) {
		return nil, false, ErrInvalidRecord
	}
	if err := r.replay.check(f.Counter); err != nil {
		return nil, false, err
	}
	ciphertext, complete, err := r.pool.add(r.contextID, f)
	if err != nil || !complete {
		return nil, false, err
	}
	plaintext, err := r.receive.Open(nil, recordNonce(f.Counter), ciphertext, r.aad(f.Kind, r.remotePeerID, r.localPeerID, f.Counter, f.Reference))
	if err != nil {
		return nil, false, ErrInvalidRecord
	}
	if err := r.replay.accept(f.Counter); err != nil {
		return nil, false, err
	}
	return plaintext, true, nil
}

func (r *Records) Disable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.disabled = true
	r.pool.Drop(r.contextID)
}
