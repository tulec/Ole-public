package transportauth

import (
	"bytes"
	"errors"
	"strconv"
	"testing"
	"time"
)

func fragmentPair(t *testing.T, path string, pool *ReassemblyPool) (*Records, *Records) {
	t.Helper()
	key := bytes.Repeat([]byte{19}, 32)
	left, err := NewRecords(path, "session", "left", "right", key, true)
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewRecords(path, "session", "right", "left", key, false, pool)
	if err != nil {
		t.Fatal(err)
	}
	return left, right
}
func sealedFragments(t *testing.T, sender *Records, kind string, ref uint64, payload []byte) []Fragment {
	t.Helper()
	n, c, err := sender.Seal(kind, ref, payload)
	if err != nil {
		t.Fatal(err)
	}
	f, err := sender.Fragments(kind, n, ref, c)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFragmentsAuthenticateReorderAndReplay(t *testing.T) {
	for _, path := range []string{"DIRECT", "RELAY"} {
		for _, kind := range []string{"packet", "data", "dataack"} {
			t.Run(path+"/"+kind, func(t *testing.T) {
				pool := NewReassemblyPool()
				left, right := fragmentPair(t, path, pool)
				ref := uint64(0)
				if kind == "dataack" {
					ref = 37
				}
				payload := bytes.Repeat([]byte{71}, MaxMessageBytes)
				parts := sealedFragments(t, left, kind, ref, payload)
				if len(parts) != 4 {
					t.Fatal("1500 bytes must fit four bounded fragments")
				}
				if _, complete, err := right.OpenFragment(parts[3]); err != nil || complete {
					t.Fatal("partial message delivered", err)
				}
				if _, complete, err := right.OpenFragment(parts[3]); err != nil || complete {
					t.Fatal("duplicate partial fragment changed assembly", err)
				}
				for _, i := range []int{1, 2} {
					if _, complete, err := right.OpenFragment(parts[i]); err != nil || complete {
						t.Fatal("incomplete message delivered", err)
					}
				}
				result, complete, err := right.OpenFragment(parts[0])
				if err != nil || !complete || !bytes.Equal(result, payload) {
					t.Fatal("reordered reassembly failed", err)
				}
				for _, f := range parts {
					if _, complete, err := right.OpenFragment(f); !errors.Is(err, ErrDuplicateRecord) || complete {
						t.Fatal("completed fragmented message replayed")
					}
				}
				stats := pool.Stats()
				if stats.Pending != 0 || stats.Bytes != 0 || stats.Completed != 1 || stats.Duplicates != 1 {
					t.Fatal("incorrect assembly accounting")
				}
			})
		}
	}
}

func TestFragmentTamperingAllocatesNothingAndDoesNotConsumeNonce(t *testing.T) {
	for _, field := range []string{"kind", "reference", "counter", "index", "count", "total", "tag", "data", "length"} {
		t.Run(field, func(t *testing.T) {
			pool := NewReassemblyPool()
			left, right := fragmentPair(t, "DIRECT", pool)
			parts := sealedFragments(t, left, "packet", 0, make([]byte, 1500))
			f := parts[0]
			f.Tag = bytes.Clone(f.Tag)
			f.Data = bytes.Clone(f.Data)
			switch field {
			case "kind":
				f.Kind = "data"
			case "reference":
				f.Reference = 4
			case "counter":
				f.Counter = 1 << 60
			case "index":
				f.Index = 1
			case "count":
				f.Count--
			case "total":
				f.Total--
			case "tag":
				f.Tag[0] ^= 1
			case "data":
				f.Data[0] ^= 1
			case "length":
				f.Data = f.Data[:len(f.Data)-1]
			}
			if _, complete, err := right.OpenFragment(f); err == nil || complete {
				t.Fatal("forged fragment accepted")
			}
			if stats := pool.Stats(); stats.Bytes != 0 || stats.Pending != 0 {
				t.Fatal("forgery allocated reassembly state")
			}
			if right.replay.highest != 0 {
				t.Fatal("forgery consumed record counter")
			}
			for i, f := range parts {
				_, complete, err := right.OpenFragment(f)
				if err != nil || complete != (i == len(parts)-1) {
					t.Fatal("valid message failed after tampering", err)
				}
			}
		})
	}
}

func TestValidFragmentMACDoesNotReplaceWholeRecordAEAD(t *testing.T) {
	pool := NewReassemblyPool()
	left, right := fragmentPair(t, "DIRECT", pool)
	parts := sealedFragments(t, left, "packet", 0, make([]byte, 1500))
	bad := append([]Fragment(nil), parts...)
	bad[0].Data = bytes.Clone(parts[0].Data)
	bad[0].Data[0] ^= 1
	bad[0].Tag = fragmentMAC(left.fragmentSend, left.aad("packet", "left", "right", bad[0].Counter, 0), bad[0])
	for i, f := range bad {
		_, complete, err := right.OpenFragment(f)
		if complete {
			t.Fatal("corrupt ciphertext delivered")
		}
		if i == len(bad)-1 && !errors.Is(err, ErrInvalidRecord) {
			t.Fatal("whole-record AEAD was not checked", err)
		}
	}
	if right.replay.highest != 0 || pool.Stats().Bytes != 0 {
		t.Fatal("failed AEAD retained state or advanced replay window")
	}
	for i, f := range parts {
		_, complete, err := right.OpenFragment(f)
		if err != nil || complete != (i == len(parts)-1) {
			t.Fatal("valid retry lost after failed AEAD", err)
		}
	}
}

func TestReassemblyBudgetExpiryAndSessionIsolation(t *testing.T) {
	pool := NewReassemblyPool()
	left, right := fragmentPair(t, "DIRECT", pool)
	for i := 0; i < MaxAssemblies; i++ {
		parts := sealedFragments(t, left, "dataack", 1, make([]byte, MaxResponseBytes))
		if _, complete, err := right.OpenFragment(parts[0]); err != nil || complete {
			t.Fatal(err)
		}
	}
	stats := pool.Stats()
	if stats.Pending != MaxAssemblies || stats.Bytes != MaxAssemblyBytes {
		t.Fatal("reassembly budget accounting incorrect", stats)
	}
	extra := sealedFragments(t, left, "packet", 0, make([]byte, 1500))
	if _, _, err := right.OpenFragment(extra[0]); !errors.Is(err, ErrAssemblyBudget) {
		t.Fatal("reassembly count limit bypassed")
	}
	pool.mu.Lock()
	for _, g := range pool.groups {
		g.created = time.Now().Add(-AssemblyTTL)
	}
	pool.mu.Unlock()
	pool.Prune()
	if stats := pool.Stats(); stats.Pending != 0 || stats.Bytes != 0 || stats.Expired != MaxAssemblies {
		t.Fatal("expired assemblies retained memory")
	}
	if _, _, err := right.OpenFragment(extra[0]); err != nil {
		t.Fatal(err)
	}
	_, newReceiver := fragmentPair(t, "DIRECT", pool)
	if _, complete, err := newReceiver.OpenFragment(extra[1]); err != nil || complete {
		t.Fatal("record contexts mixed")
	}
	if pool.Stats().Pending != 2 {
		t.Fatal("different sessions shared reassembly")
	}
	right.Disable()
	if pool.Stats().Pending != 1 {
		t.Fatal("session revoke did not release its assemblies")
	}
	if _, _, err := right.OpenFragment(extra[1]); !errors.Is(err, ErrInvalidRecord) {
		t.Fatal("disabled session reallocated fragments")
	}
	newReceiver.Disable()
	if pool.Stats().Bytes != 0 {
		t.Fatal("replaced session retained buffers")
	}
}

func TestIncompleteFragmentsDoNotResetExpiry(t *testing.T) {
	pool := NewReassemblyPool()
	left, right := fragmentPair(t, "DIRECT", pool)
	parts := sealedFragments(t, left, "packet", 0, make([]byte, 1500))
	if _, _, err := right.OpenFragment(parts[0]); err != nil {
		t.Fatal(err)
	}
	pool.mu.Lock()
	g := pool.groups[assemblyKey{right.contextID, parts[0].Counter}]
	created := g.created
	pool.mu.Unlock()
	if _, _, err := right.OpenFragment(parts[0]); err != nil {
		t.Fatal(err)
	}
	pool.mu.Lock()
	unchanged := g.created.Equal(created)
	pool.mu.Unlock()
	if !unchanged {
		t.Fatal("duplicate extended assembly lifetime")
	}
}

func TestFragmentContextAndMessageLimit(t *testing.T) {
	for _, field := range []string{"path", "local", "remote", "session"} {
		t.Run(field, func(t *testing.T) {
			pool := NewReassemblyPool()
			left, right := fragmentPair(t, "DIRECT", pool)
			parts := sealedFragments(t, left, "packet", 0, make([]byte, 1500))
			switch field {
			case "path":
				right.path = "RELAY"
			case "local":
				right.localPeerID = "other"
			case "remote":
				right.remotePeerID = "other"
			case "session":
				right.sessionID = "other"
			}
			if _, _, err := right.OpenFragment(parts[0]); err == nil || pool.Stats().Pending != 0 {
				t.Fatal("fragment context substitution accepted")
			}
		})
	}
	left, _ := fragmentPair(t, "DIRECT", NewReassemblyPool())
	if _, _, err := left.Seal("packet", 0, make([]byte, 1501)); !errors.Is(err, ErrMessageTooLarge) || left.sendCounter != 0 {
		t.Fatal("oversize was not rejected before counter allocation")
	}
	if _, _, err := left.Seal("packet", 0, []byte(strconv.Itoa(MaxMessageBytes))); err != nil {
		t.Fatal("oversize rejection damaged cipher", err)
	}
}

func TestRecordKindSizeLimits(t *testing.T) {
	for _, kind := range []string{"packet", "data", "dataack"} {
		t.Run(kind, func(t *testing.T) {
			left, right := fragmentPair(t, "DIRECT", NewReassemblyPool())
			ref := uint64(0)
			if kind == "dataack" {
				ref = 1
			}
			limit := MaxMessageBytes
			if kind == "dataack" {
				limit = MaxResponseBytes
			}
			parts := sealedFragments(t, left, kind, ref, make([]byte, limit))
			for i, f := range parts {
				payload, complete, err := right.OpenFragment(f)
				if err != nil || complete != (i == len(parts)-1) || (complete && len(payload) != limit) {
					t.Fatal("maximum message was not delivered", err)
				}
			}
			if _, _, err := left.Seal(kind, ref, make([]byte, limit+1)); !errors.Is(err, ErrMessageTooLarge) || left.sendCounter != 1 {
				t.Fatal("oversize send consumed counter or was accepted")
			}
			// A peer with valid keys must still obey the per-kind receive limit.
			ciphertext := left.send.Seal(nil, recordNonce(2), make([]byte, limit+1), left.aad(kind, "left", "right", 2, ref))
			if _, err := right.Open(kind, 2, ref, ciphertext); !errors.Is(err, ErrInvalidRecord) || right.replay.highest != 1 {
				t.Fatal("oversize receive consumed counter or was accepted")
			}
			if _, err := left.Fragments(kind, 2, ref, ciphertext); !errors.Is(err, ErrInvalidRecord) {
				t.Fatal("oversize fragment send accepted")
			}
			f := Fragment{Kind: kind, Counter: 2, Reference: ref, Count: 4, Total: len(ciphertext), Data: ciphertext[:FragmentBytes]}
			f.Tag = fragmentMAC(left.fragmentSend, left.aad(kind, "left", "right", 2, ref), f)
			if _, _, err := right.OpenFragment(f); !errors.Is(err, ErrInvalidRecord) || right.pool.Stats().Bytes != 0 {
				t.Fatal("oversize fragment allocated receive state")
			}
		})
	}
}
