package transportauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"
)

func wireWorstHandshakers(t *testing.T) (*Handshaker, *Handshaker) {
	return wireHandshakers(t, "DIRECT", false)
}

func wireHandshakers(t *testing.T, path string, escaped bool) (*Handshaker, *Handshaker) {
	t.Helper()
	leftID, rightID := strings.Repeat("a", MaxPeerIDBytes), strings.Repeat("b", MaxPeerIDBytes)
	network, leftDevice, rightDevice := strings.Repeat("n", 128), strings.Repeat("i", 128), strings.Repeat("r", 128)
	if escaped {
		// All are valid printable atoms, but expand in JSON before Base64 encoding.
		leftID, rightID = strings.Repeat(`"`, MaxPeerIDBytes), strings.Repeat(`\`, MaxPeerIDBytes)
		network, leftDevice, rightDevice = strings.Repeat("<", 128), strings.Repeat("&", 128), strings.Repeat(">", 128)
	}
	leftKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	rightKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	keys := map[string]Identity{
		leftID:  {DeviceID: leftDevice, PublicKey: leftKey.Public().(ed25519.PublicKey)},
		rightID: {DeviceID: rightDevice, PublicKey: rightKey.Public().(ed25519.PublicKey)},
	}
	left, right := New(path), New(path)
	for _, entry := range []struct {
		h   *Handshaker
		id  string
		key ed25519.PrivateKey
	}{{left, leftID, leftKey}, {right, rightID, rightKey}} {
		c := &Credentials{NetworkID: network, PeerID: entry.id, DeviceID: keys[entry.id].DeviceID,
			PrivateKey: entry.key, Peers: keys, ExpiresAt: time.Now().Add(SnapshotTTL)}
		if err := entry.h.Update(c); err != nil {
			t.Fatal(err)
		}
	}
	return left, right
}

func wireAssertTransportRoundTrip(t *testing.T, message string) ([]byte, []string) {
	t.Helper()
	encoded, err := EncodeTransport(message)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > DatagramBudget {
		t.Fatalf("transport datagram is %d bytes", len(encoded))
	}
	decoded, err := DecodeTransport(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got := TransportText(decoded); got != message {
		t.Fatalf("transport roundtrip changed %q into %q", message, got)
	}
	return encoded, decoded
}

func wireAssertRelayRoundTrip(t *testing.T, parts []string) []byte {
	t.Helper()
	message := RelayText(parts)
	encoded, err := EncodeRelay(message)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > DatagramBudget {
		t.Fatalf("relay datagram is %d bytes", len(encoded))
	}
	decoded, err := DecodeRelay(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, parts) {
		t.Fatalf("relay roundtrip changed %q into %q", parts, decoded)
	}
	return encoded
}

func wireAssertRelayDirections(t *testing.T, message string, parts []string) (int, int) {
	t.Helper()
	payload := hex.EncodeToString([]byte(message))
	send := wireAssertRelayRoundTrip(t, []string{"send", strings.Repeat("T", MaxTokenBytes), parts[1], parts[2], payload})
	deliver := wireAssertRelayRoundTrip(t, []string{"deliver", parts[1], payload})
	return len(send), len(deliver)
}

func TestWireWorstCaseHandshakeRoundTripAndBudgets(t *testing.T) {
	left, right := wireWorstHandshakers(t)
	message, err := left.Begin(right.credentials.PeerID)
	if err != nil {
		t.Fatal(err)
	}
	for step, receiver := range []*Handshaker{right, left, right, left} {
		encoded, decoded := wireAssertTransportRoundTrip(t, message.Wire)
		send, deliver := wireAssertRelayDirections(t, message.Wire, decoded)
		t.Logf("%s: direct=%d, relay client->server=%d, relay server->client=%d bytes", decoded[0], len(encoded), send, deliver)
		next, established, err := receiver.Handle(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if (step >= 2) != (established != nil) {
			t.Fatal("wire conversion changed handshake state transitions")
		}
		message = next
	}
}

func TestWireEscapedMetadataHandshakeEstablishesSharedKeys(t *testing.T) {
	for _, path := range []string{"DIRECT", "RELAY"} {
		t.Run(path, func(t *testing.T) {
			left, right := wireHandshakers(t, path, true)
			message, err := left.Begin(right.credentials.PeerID)
			if err != nil {
				t.Fatal(err)
			}
			var sessions []*Established
			for step, receiver := range []*Handshaker{right, left, right, left} {
				direct, decoded := wireAssertTransportRoundTrip(t, message.Wire)
				if path == "RELAY" {
					payload := hex.EncodeToString([]byte(message.Wire))
					send := wireAssertRelayRoundTrip(t, []string{"send", strings.Repeat("T", MaxTokenBytes), decoded[1], decoded[2], payload})
					sent, err := DecodeRelay(send)
					if err != nil {
						t.Fatal(err)
					}
					// The relay forwards the decoded source and payload in DELIVER.
					deliver := wireAssertRelayRoundTrip(t, []string{"deliver", sent[2], sent[4]})
					delivered, err := DecodeRelay(deliver)
					if err != nil {
						t.Fatal(err)
					}
					body, err := hex.DecodeString(delivered[2])
					if err != nil {
						t.Fatal(err)
					}
					decoded = strings.Split(string(body), "|")[1:]
					t.Logf("%s: direct=%d, send=%d, deliver=%d, reconstructed body=%d bytes", decoded[0], len(direct), len(send), len(deliver), len(decoded[4]))
				}
				next, established, err := receiver.Handle(decoded)
				if err != nil {
					t.Fatalf("phase %d (%s), body %d bytes: %v", step, decoded[0], len(decoded[4]), err)
				}
				if (step >= 2) != (established != nil) {
					t.Fatal("unexpected handshake state transition")
				}
				if established != nil {
					sessions = append(sessions, established)
				}
				message = next
			}
			responder, initiator := sessions[0], sessions[1]
			if responder.Initiator || !initiator.Initiator || len(initiator.Secret) != 32 || !bytes.Equal(responder.Secret, initiator.Secret) || responder.SessionID != initiator.SessionID {
				t.Fatal("wire handshake failed to establish matching directional sessions")
			}
			if responder.RemotePeerID != left.credentials.PeerID || initiator.RemotePeerID != right.credentials.PeerID || !left.Allows(initiator.RemotePeerID, initiator.Proof) || !right.Allows(responder.RemotePeerID, responder.Proof) {
				t.Fatal("wire handshake changed authenticated identities or proofs")
			}
			sender, err := NewRecords(path, initiator.SessionID, left.credentials.PeerID, right.credentials.PeerID, initiator.Secret, true)
			if err != nil {
				t.Fatal(err)
			}
			receiver, err := NewRecords(path, responder.SessionID, right.credentials.PeerID, left.credentials.PeerID, responder.Secret, false)
			if err != nil {
				t.Fatal(err)
			}
			plaintext := []byte("keys established through the binary wire codec")
			counter, ciphertext, err := sender.Seal("packet", 0, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := receiver.Open("packet", counter, 0, ciphertext)
			if err != nil || !bytes.Equal(opened, plaintext) {
				t.Fatalf("established keys cannot authenticate a record: %v", err)
			}
		})
	}
}

func TestWireRecordAndFragmentRoundTripBudgets(t *testing.T) {
	source, target := strings.Repeat("a", MaxPeerIDBytes), strings.Repeat("b", MaxPeerIDBytes)
	session := strings.Repeat("0", 32)
	for _, kind := range []string{"packet", "data", "dataack"} {
		t.Run(kind, func(t *testing.T) {
			r, err := NewRecords("RELAY", session, source, target, bytes.Repeat([]byte{7}, 32), true)
			if err != nil {
				t.Fatal(err)
			}
			r.sendCounter = math.MaxUint64 - 1
			var ref uint64
			if kind == "dataack" {
				ref = math.MaxUint64
			}
			n, ciphertext, err := r.Seal(kind, ref, make([]byte, FragmentBytes-16))
			if err != nil {
				t.Fatal(err)
			}
			parts := []string{kind, source, target, session}
			if kind == "dataack" {
				parts = append(parts, fmt.Sprint(ref))
			}
			parts = append(parts, fmt.Sprint(n), hex.EncodeToString(ciphertext))
			message := TransportText(parts)
			encoded, decoded := wireAssertTransportRoundTrip(t, message)
			send, deliver := wireAssertRelayDirections(t, message, decoded)
			t.Logf("%s small: direct=%d, relay send=%d, relay deliver=%d bytes", kind, len(encoded), send, deliver)
		})
	}
	r, err := NewRecords("RELAY", session, source, target, bytes.Repeat([]byte{7}, 32), true)
	if err != nil {
		t.Fatal(err)
	}
	n, ciphertext, err := r.Seal("packet", 0, bytes.Repeat([]byte{0xfe}, MaxMessageBytes))
	if err != nil {
		t.Fatal(err)
	}
	fragments, err := r.Fragments("packet", n, 0, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if len(fragments) != 4 {
		t.Fatalf("1500-byte record produced %d fragments", len(fragments))
	}
	for index, fragment := range fragments {
		message := FragmentText(source, target, session, fragment)
		encoded, decoded := wireAssertTransportRoundTrip(t, message)
		parsed, err := ParseFragment(decoded)
		if err != nil || !reflect.DeepEqual(parsed, fragment) {
			t.Fatalf("fragment %d changed in the wire codec: %v", index, err)
		}
		send, deliver := wireAssertRelayDirections(t, message, decoded)
		t.Logf("fragment %d: direct=%d, relay send=%d, relay deliver=%d bytes", index, len(encoded), send, deliver)
	}
}

func TestWireControlAndOpaqueRelayRoundTrips(t *testing.T) {
	for _, kind := range []string{"probe", "ack"} {
		wireAssertTransportRoundTrip(t, TransportText([]string{kind, "a", "b", "nonce"}))
	}
	for _, parts := range [][]string{
		{"bind", strings.Repeat("T", MaxTokenBytes), strings.Repeat("a", MaxPeerIDBytes), strings.Repeat("N", 64)},
		{"bound", strings.Repeat("a", MaxPeerIDBytes), strings.Repeat("N", 64)},
		{"error", "send_denied", "a", "denied | with a reason"},
		{"error", "source_blocked", "", ""},
		{"send", "token", "a", "b", hex.EncodeToString([]byte{0, 1, 0xff})},
		{"deliver", "a", hex.EncodeToString([]byte{0, 1, 0xff})},
	} {
		wireAssertRelayRoundTrip(t, parts)
	}
	// Opaque payloads consume the full budget including their routing metadata.
	maxRaw := bytes.Repeat([]byte{0xff}, 550)
	parts := []string{"send", strings.Repeat("T", MaxTokenBytes), strings.Repeat("a", MaxPeerIDBytes), strings.Repeat("b", MaxPeerIDBytes), hex.EncodeToString(maxRaw)}
	if size := len(wireAssertRelayRoundTrip(t, parts)); size != DatagramBudget {
		t.Fatalf("full-budget opaque send is %d bytes", size)
	}
	parts[4] = hex.EncodeToString(append(maxRaw, 0xff))
	if _, err := EncodeRelay(RelayText(parts)); !errors.Is(err, ErrDatagramTooLarge) {
		t.Fatalf("oversized opaque send: %v", err)
	}
}

func TestWireEncodersRejectMalformedFieldsAndRouteMismatch(t *testing.T) {
	validRecord := []string{"packet", "a", "b", strings.Repeat("0", 32), "1", strings.Repeat("00", 16)}
	for _, mutate := range []func([]string){
		func(p []string) { p[1] = "" },
		func(p []string) { p[1] = strings.Repeat("a", MaxPeerIDBytes+1) },
		func(p []string) { p[3] = "not-hex" },
		func(p []string) { p[4] = "0" },
		func(p []string) { p[4] = "18446744073709551616" },
		func(p []string) { p[5] = "00" },
		func(p []string) { p[5] = "odd" },
	} {
		parts := append([]string(nil), validRecord...)
		mutate(parts)
		if _, err := EncodeTransport(TransportText(parts)); err == nil {
			t.Fatalf("invalid record encoded: %q", parts)
		}
	}
	for _, message := range []string{"OLEP3|probe|a|b|nonce", Magic + "|unknown|a|b", Magic + "|dataack|a|b|" + strings.Repeat("0", 32) + "|0|1|" + strings.Repeat("00", 16)} {
		if _, err := EncodeTransport(message); err == nil {
			t.Fatal("invalid or legacy transport accepted")
		}
	}
	payload := hex.EncodeToString([]byte(TransportText(validRecord)))
	for _, parts := range [][]string{
		{"send", "token", "wrong-source", "b", payload},
		{"send", "token", "a", "wrong-target", payload},
		{"deliver", "wrong-source", payload},
		{"bind", strings.Repeat("T", MaxTokenBytes+1), "a", "nonce"},
		{"bind", "token", strings.Repeat("a", MaxPeerIDBytes+1), "nonce"},
		{"bound", "a", strings.Repeat("N", 65)},
		{"send", "token", "a", "b", "odd"},
	} {
		if _, err := EncodeRelay(RelayText(parts)); err == nil {
			t.Fatalf("invalid relay message encoded: %q", parts)
		}
	}
	if _, err := EncodeRelay("OLER1|bind|token|a|nonce"); err == nil {
		t.Fatal("legacy relay text accepted")
	}
}

func TestWireDecodersRejectTruncationBadLengthsAndTrailingData(t *testing.T) {
	left, right := wireWorstHandshakers(t)
	hello, err := left.Begin(right.credentials.PeerID)
	if err != nil {
		t.Fatal(err)
	}
	transport, _ := wireAssertTransportRoundTrip(t, hello.Wire)
	probe, _ := wireAssertTransportRoundTrip(t, TransportText([]string{"probe", "a", "b", "nonce"}))
	record, _ := wireAssertTransportRoundTrip(t, TransportText([]string{"packet", "a", "b", strings.Repeat("0", 32), "1", strings.Repeat("00", 16)}))
	bound := wireAssertRelayRoundTrip(t, []string{"bound", "a", "nonce"})
	for _, entry := range []struct {
		name   string
		data   []byte
		decode func([]byte) ([]string, error)
	}{
		{"hello", transport, DecodeTransport}, {"probe", probe, DecodeTransport}, {"minimal record", record, DecodeTransport}, {"bound", bound, DecodeRelay},
	} {
		t.Run(entry.name, func(t *testing.T) {
			for end := 0; end < len(entry.data); end++ {
				if _, err := entry.decode(entry.data[:end]); err == nil {
					t.Fatalf("truncated prefix %d/%d accepted", end, len(entry.data))
				}
			}
		})
	}
	if _, err := DecodeTransport(append(append([]byte(nil), transport...), 0)); err == nil {
		t.Fatal("trailing handshake byte accepted")
	}
	badPeer := append([]byte(nil), probe...)
	badPeer[5] = MaxPeerIDBytes + 1
	if _, err := DecodeTransport(badPeer); err == nil {
		t.Fatal("peer length above limit accepted")
	}
	bind := wireAssertRelayRoundTrip(t, []string{"bind", "token", "a", "nonce"})
	binary.BigEndian.PutUint16(bind[5:7], MaxTokenBytes+1)
	if _, err := DecodeRelay(bind); err == nil {
		t.Fatal("token length above limit accepted")
	}
	for _, decode := range []func([]byte) ([]string, error){DecodeTransport, DecodeRelay} {
		if _, err := decode(make([]byte, DatagramBudget+1)); !errors.Is(err, ErrDatagramTooLarge) {
			t.Fatalf("oversized input: %v", err)
		}
	}
	for _, old := range []string{"OLEP3|packet|a|b", "OLEP4|probe|a|b|nonce", "OLER1|bind|token|a|nonce", "OLER2|bind|token|a|nonce"} {
		if _, err := DecodeTransport([]byte(old)); err == nil {
			t.Fatal("text/legacy wire accepted as binary transport")
		}
		if _, err := DecodeRelay([]byte(old)); err == nil {
			t.Fatal("text/legacy wire accepted as binary relay")
		}
	}
}

func TestWireFragmentCodecRejectsInvalidMetadata(t *testing.T) {
	valid := Fragment{Kind: "packet", Counter: 1, Count: 4, Total: MaxMessageBytes + 16, Tag: make([]byte, 16), Data: make([]byte, FragmentBytes)}
	for _, entry := range []struct {
		name   string
		mutate func(*Fragment)
	}{
		{"kind", func(f *Fragment) { f.Kind = "probe" }},
		{"zero counter", func(f *Fragment) { f.Counter = 0 }},
		{"unexpected reference", func(f *Fragment) { f.Reference = 1 }},
		{"index beyond count", func(f *Fragment) { f.Index = f.Count }},
		{"negative index", func(f *Fragment) { f.Index = -1 }},
		{"incorrect count", func(f *Fragment) { f.Count-- }},
		{"total too small", func(f *Fragment) { f.Total = FragmentBytes }},
		{"total too large", func(f *Fragment) { f.Total = MaxCipherBytes + 1 }},
		{"short tag", func(f *Fragment) { f.Tag = f.Tag[:15] }},
		{"short chunk", func(f *Fragment) { f.Data = f.Data[:FragmentBytes-1] }},
	} {
		t.Run(entry.name, func(t *testing.T) {
			fragment := valid
			entry.mutate(&fragment)
			if _, err := EncodeTransport(FragmentText("a", "b", strings.Repeat("0", 32), fragment)); err == nil {
				t.Fatal("invalid fragment metadata encoded")
			}
		})
	}

	encoded, err := EncodeTransport(FragmentText("a", "b", strings.Repeat("0", 32), valid))
	if err != nil {
		t.Fatal(err)
	}
	for end := 0; end < len(encoded); end++ {
		if _, err := DecodeTransport(encoded[:end]); err == nil {
			t.Fatalf("truncated fragment prefix %d/%d accepted", end, len(encoded))
		}
	}
	// OLP4, kind, two one-byte peers, session, record kind, counter, reference.
	const indexAt = 4 + 1 + 2 + 2 + 16 + 1 + 8 + 8
	for _, entry := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"index", func(b []byte) { b[indexAt] = 4 }},
		{"count", func(b []byte) { b[indexAt+1] = 3 }},
		{"total", func(b []byte) { binary.BigEndian.PutUint16(b[indexAt+2:indexAt+4], MaxCipherBytes+1) }},
	} {
		t.Run("decode "+entry.name, func(t *testing.T) {
			bad := append([]byte(nil), encoded...)
			entry.mutate(bad)
			if _, err := DecodeTransport(bad); err == nil {
				t.Fatal("invalid binary fragment metadata accepted")
			}
		})
	}
}

func TestWirePerKindFragmentPayloadBoundaries(t *testing.T) {
	for _, entry := range []struct {
		kind  string
		limit int
		ref   uint64
	}{
		{"packet", MaxMessageBytes, 0},
		{"data", MaxMessageBytes, 0},
		{"dataack", MaxResponseBytes, 1},
	} {
		t.Run(entry.kind, func(t *testing.T) {
			source, target := strings.Repeat("a", MaxPeerIDBytes), strings.Repeat("b", MaxPeerIDBytes)
			session := strings.Repeat("0", 32)
			records, err := NewRecords("RELAY", session, source, target, bytes.Repeat([]byte{7}, 32), true)
			if err != nil {
				t.Fatal(err)
			}
			counter, ciphertext, err := records.Seal(entry.kind, entry.ref, make([]byte, entry.limit))
			if err != nil {
				t.Fatal(err)
			}
			if len(ciphertext) != entry.limit+16 {
				t.Fatalf("ciphertext size=%d, want %d", len(ciphertext), entry.limit+16)
			}
			fragments, err := records.Fragments(entry.kind, counter, entry.ref, ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			for _, fragment := range fragments {
				message := FragmentText(source, target, session, fragment)
				encoded, decoded := wireAssertTransportRoundTrip(t, message)
				send, deliver := wireAssertRelayDirections(t, message, decoded)
				t.Logf("%s %d-byte boundary, fragment %d: direct=%d, send=%d, deliver=%d bytes", entry.kind, entry.limit, fragment.Index, len(encoded), send, deliver)
			}
			if _, _, err := records.Seal(entry.kind, entry.ref, make([]byte, entry.limit+1)); !errors.Is(err, ErrMessageTooLarge) {
				t.Fatalf("%d-byte %s payload was not rejected: %v", entry.limit+1, entry.kind, err)
			}
			if _, err := records.Fragments(entry.kind, counter, entry.ref, make([]byte, entry.limit+17)); err == nil {
				t.Fatal("oversized ciphertext fragmented")
			}
			bad := fragments[0]
			bad.Total = entry.limit + 17
			if _, err := EncodeTransport(FragmentText(source, target, session, bad)); err == nil {
				t.Fatal("oversized per-kind fragment total encoded")
			}
		})
	}
}

func TestWireDecodersArbitraryBoundedInputsDoNotPanic(t *testing.T) {
	random := rand.New(rand.NewSource(20261027))
	for i := 0; i < 5000; i++ {
		data := make([]byte, random.Intn(DatagramBudget+2))
		_, _ = random.Read(data)
		if i%3 == 0 && len(data) >= 4 {
			copy(data, "OLP4")
		}
		if i%3 == 1 && len(data) >= 4 {
			copy(data, "OLR2")
		}
		_, _ = DecodeTransport(data)
		_, _ = DecodeRelay(data)
	}
}
