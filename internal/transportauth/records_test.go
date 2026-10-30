package transportauth

import (
	"bytes"
	"errors"
	"math"
	"math/rand"
	"sync"
	"testing"
)

func recordPair(t *testing.T, path string) (*Records, *Records) {
	t.Helper()
	secret := bytes.Repeat([]byte{7}, 32)
	left, err := NewRecords(path, "session", "a", "b", secret, true)
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewRecords(path, "session", "b", "a", secret, false)
	if err != nil {
		t.Fatal(err)
	}
	return left, right
}

func TestReplayWindowMatchesReceivedSet(t *testing.T) {
	for _, shift := range []uint64{1, 63, 64, 65, 127, 128, 129, 255, 256, 257, math.MaxUint64 - 1} {
		var w replayWindow
		if err := w.accept(1); err != nil {
			t.Fatal(err)
		}
		if err := w.accept(1 + shift); err != nil {
			t.Fatal(err)
		}
		want := ErrDuplicateRecord
		if shift >= ReplayWindowSize {
			want = ErrRecordTooOld
		}
		if err := w.accept(1); !errors.Is(err, want) {
			t.Fatalf("shift %d: %v", shift, err)
		}
	}
	var w replayWindow
	seen := map[uint64]bool{}
	var highest uint64
	random := rand.New(rand.NewSource(20261026))
	for i := 0; i < 5000; i++ {
		var counter uint64
		if random.Intn(3) == 0 {
			counter = highest + uint64(random.Intn(300)+1)
		} else {
			distance := uint64(random.Intn(512))
			if highest > distance {
				counter = highest - distance
			} else {
				counter = 1
			}
		}
		var want error
		if counter <= highest && highest-counter >= ReplayWindowSize {
			want = ErrRecordTooOld
		} else if seen[counter] {
			want = ErrDuplicateRecord
		}
		err := w.accept(counter)
		if !errors.Is(err, want) {
			t.Fatalf("counter %d/highest %d: got %v, want %v", counter, highest, err, want)
		}
		if want == nil {
			seen[counter] = true
			if counter > highest {
				highest = counter
			}
		}
		if w.highest != highest {
			t.Fatal("receive window moved incorrectly")
		}
	}
}

func TestInvalidRecordsCannotAdvanceReceiveWindow(t *testing.T) {
	for _, path := range []string{"DIRECT", "RELAY"} {
		t.Run(path, func(t *testing.T) {
			left, right := recordPair(t, path)
			n, ciphertext, err := left.Seal("dataack", 7, []byte("reply"))
			if err != nil {
				t.Fatal(err)
			}
			for _, attempt := range []struct {
				kind         string
				counter, ref uint64
				ciphertext   []byte
			}{
				{"packet", n, 0, ciphertext}, {"data", n, 0, ciphertext}, {"dataack", n, 8, ciphertext},
				{"dataack", math.MaxUint64, 7, ciphertext}, {"dataack", 0, 7, ciphertext}, {"unknown", n, 7, ciphertext},
				{"dataack", n, 7, append([]byte(nil), ciphertext[:len(ciphertext)-1]...)},
			} {
				if _, err := right.Open(attempt.kind, attempt.counter, attempt.ref, attempt.ciphertext); err == nil {
					t.Fatal("invalid record was accepted")
				}
				if right.replay.highest != 0 {
					t.Fatal("invalid AEAD moved replay window")
				}
			}
			payload, err := right.Open("dataack", n, 7, ciphertext)
			if err != nil || string(payload) != "reply" {
				t.Fatal("valid ACK lost after forged records", err)
			}
			if _, err := right.Open("dataack", n, 7, ciphertext); !errors.Is(err, ErrDuplicateRecord) {
				t.Fatal("ACK replay accepted")
			}
		})
	}
}

func TestAuthenticatedZeroCounterAndContextSubstitutionRejected(t *testing.T) {
	left, right := recordPair(t, "DIRECT")
	zero := left.send.Seal(nil, recordNonce(0), []byte("zero"), left.aad("packet", "a", "b", 0, 0))
	if _, err := right.Open("packet", 0, 0, zero); !errors.Is(err, ErrInvalidRecord) {
		t.Fatal("zero nonce accepted")
	}
	for _, mutate := range []func(*Records){
		func(r *Records) { r.path = "RELAY" }, func(r *Records) { r.sessionID = "another" },
		func(r *Records) { r.localPeerID = "c" }, func(r *Records) { r.remotePeerID = "c" },
	} {
		_, receiver := recordPair(t, "DIRECT")
		mutate(receiver)
		n, c, err := left.Seal("packet", 0, []byte("bound"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := receiver.Open("packet", n, 0, c); err == nil {
			t.Fatal("record context substitution accepted")
		}
		if receiver.replay.highest != 0 {
			t.Fatal("wrong context moved replay window")
		}
	}
}

func TestReceiveWindowSharedAcrossMessageKindsAndConcurrentOpens(t *testing.T) {
	left, right := recordPair(t, "DIRECT")
	var first []byte
	var firstCounter uint64
	for i := 0; i <= ReplayWindowSize; i++ {
		kind, ref := "packet", uint64(0)
		if i == ReplayWindowSize {
			kind, ref = "dataack", 99
		}
		n, c, err := left.Seal(kind, ref, []byte("record"))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first, firstCounter = c, n
			continue
		}
		if i == ReplayWindowSize {
			if _, err := right.Open(kind, n, ref, c); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := right.Open("packet", firstCounter, 0, first); !errors.Is(err, ErrRecordTooOld) {
		t.Fatal("receive window was split by message type")
	}
	left, right = recordPair(t, "DIRECT")
	n, c, err := left.Seal("packet", 0, []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 50)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := right.Open("packet", n, 0, c); results <- err }()
	}
	wg.Wait()
	close(results)
	accepted, duplicates := 0, 0
	for err := range results {
		if err == nil {
			accepted++
		} else if errors.Is(err, ErrDuplicateRecord) {
			duplicates++
		} else {
			t.Fatal(err)
		}
	}
	if accepted != 1 || duplicates != 49 {
		t.Fatal("concurrent replay was delivered more than once")
	}
}

func TestSendCounterCannotWrap(t *testing.T) {
	left, right := recordPair(t, "DIRECT")
	left.sendCounter = math.MaxUint64 - 1
	n, c, err := left.Seal("packet", 0, []byte("last nonce"))
	if err != nil || n != math.MaxUint64 {
		t.Fatal("last counter failed", err)
	}
	if _, err := right.Open("packet", n, 0, c); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		n, c, err := left.Seal("packet", 0, nil)
		if !errors.Is(err, ErrCounterExhausted) || n != 0 || c != nil {
			t.Fatal("send counter wrapped")
		}
	}
	if left.sendCounter != math.MaxUint64 {
		t.Fatal("exhausted counter changed")
	}
}
