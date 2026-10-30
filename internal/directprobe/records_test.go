package directprobe

import (
	"encoding/hex"
	"strconv"
	"testing"
	"time"
)

func recordFixture(t *testing.T) (Manager, *listener, *cryptoSession, string) {
	t.Helper()
	left, right := New(), New()
	t.Cleanup(func() { left.Close(); right.Close() })
	la, ra := reserveUDPAddress(t), reserveUDPAddress(t)
	if err := left.Reconcile([]Binding{{PeerID: "peer-left", ListenAddress: la, Credentials: testCredentials("peer-left")}}); err != nil {
		t.Fatal(err)
	}
	if err := right.Reconcile([]Binding{{PeerID: "peer-right", ListenAddress: ra, Credentials: testCredentials("peer-right")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := left.Establish("peer-left", "peer-right", []string{ra}, time.Second); err != nil {
		t.Fatal(err)
	}
	ll, _ := left.(*manager).listenerFor("peer-left")
	rr, _ := right.(*manager).listenerFor("peer-right")
	s, _ := ll.sessionForRemote("peer-right")
	return left, rr, s, ra
}

func sealRecordForTest(t *testing.T, s *cryptoSession, kind string, ref uint64, payload []byte) (uint64, []byte) {
	t.Helper()
	counter, ciphertext, err := s.records.Seal(kind, ref, payload)
	if err != nil {
		t.Fatal(err)
	}
	return counter, ciphertext
}
func recordParts(kind string, s *cryptoSession, counter, ref uint64, ciphertext []byte) []string {
	p := []string{kind, "peer-left", "peer-right", s.sessionID, strconv.FormatUint(counter, 10), hex.EncodeToString(ciphertext)}
	if kind == "dataack" {
		p = []string{kind, "peer-left", "peer-right", s.sessionID, strconv.FormatUint(ref, 10), strconv.FormatUint(counter, 10), hex.EncodeToString(ciphertext)}
	}
	return p
}
func injectRecord(l *listener, p []string) {
	switch p[0] {
	case "packet":
		l.handlePacket(p, nil)
	case "data":
		l.handleData(p, nil)
	case "dataack":
		l.handleDataAck(p)
	}
}
func TestRecordReplayAndQueueBoundaries(t *testing.T) {
	t.Run("packet duplicate", func(t *testing.T) {
		_, r, s, _ := recordFixture(t)
		n, c := sealRecordForTest(t, s, "packet", 0, []byte("once"))
		p := recordParts("packet", s, n, 0, c)
		injectRecord(r, p)
		injectRecord(r, p)
		if got := len(r.drainInbound(0)); got != 1 {
			t.Errorf("duplicate delivered %d packets, want 1", got)
		}
		if r.recordStats.Duplicates != 1 {
			t.Fatal("duplicate counter was not recorded")
		}
	})
	t.Run("message type substitution", func(t *testing.T) {
		_, r, s, _ := recordFixture(t)
		n, c := sealRecordForTest(t, s, "data", 0, []byte("typed"))
		injectRecord(r, recordParts("packet", s, n, 0, c))
		if len(r.drainInbound(0)) != 0 {
			t.Error("data ciphertext was accepted as packet")
		}
		calls := 0
		r.exchangeHandler = func(string, []byte) []byte { calls++; return []byte("reply") }
		injectRecord(r, recordParts("data", s, n, 0, c))
		if calls != 1 {
			t.Error("type forgery consumed valid record")
		}
	})
	t.Run("exchange replay", func(t *testing.T) {
		_, r, s, _ := recordFixture(t)
		calls := 0
		r.exchangeHandler = func(string, []byte) []byte { calls++; return []byte("reply") }
		n, c := sealRecordForTest(t, s, "data", 0, []byte("execute-once"))
		p := recordParts("data", s, n, 0, c)
		injectRecord(r, p)
		injectRecord(r, p)
		if calls != 1 {
			t.Errorf("replayed exchange executed %d times", calls)
		}
	})
	t.Run("ack correlation and replay", func(t *testing.T) {
		_, r, s, _ := recordFixture(t)
		n, c := sealRecordForTest(t, s, "dataack", 7, []byte("reply"))
		forged := make(chan []byte, 1)
		r.registerPendingAck(ackKey(s.sessionID, 8), forged)
		injectRecord(r, recordParts("dataack", s, n, 8, c))
		if len(forged) != 0 {
			t.Error("ack request reference was not authenticated")
		}
		valid := make(chan []byte, 1)
		r.registerPendingAck(ackKey(s.sessionID, 7), valid)
		p := recordParts("dataack", s, n, 7, c)
		injectRecord(r, p)
		if len(valid) != 1 {
			t.Fatal("valid ACK was lost after forged reference")
		}
		<-valid
		injectRecord(r, p)
		if len(valid) != 0 {
			t.Error("ACK was delivered twice")
		}
	})
	t.Run("reorder and invalid high counter", func(t *testing.T) {
		_, r, s, _ := recordFixture(t)
		var records [][]string
		for _, payload := range []string{"one", "two", "three"} {
			n, c := sealRecordForTest(t, s, "packet", 0, []byte(payload))
			records = append(records, recordParts("packet", s, n, 0, c))
		}
		forged := append([]string(nil), records[0]...)
		forged[4] = "18446744073709551615"
		injectRecord(r, forged)
		for _, i := range []int{2, 0, 1} {
			injectRecord(r, records[i])
		}
		packets := r.drainInbound(0)
		if len(packets) != 3 {
			t.Fatal("invalid AEAD advanced receive window")
		}
		for i, want := range []string{"three", "one", "two"} {
			if string(packets[i].Payload) != want {
				t.Fatal("in-window reordering failed")
			}
		}
		injectRecord(r, records[0])
		if len(r.drainInbound(0)) != 0 {
			t.Error("reordered record replayed")
		}
	})
	t.Run("too old across message kinds", func(t *testing.T) {
		_, r, s, _ := recordFixture(t)
		firstN, first := sealRecordForTest(t, s, "packet", 0, []byte("old"))
		var lastN uint64
		var last []byte
		for i := 0; i < 256; i++ {
			lastN, last = sealRecordForTest(t, s, "dataack", 9, []byte("new"))
		}
		injectRecord(r, recordParts("dataack", s, lastN, 9, last))
		injectRecord(r, recordParts("packet", s, firstN, 0, first))
		if len(r.drainInbound(0)) != 0 || r.recordStats.TooOld != 1 {
			t.Fatal("too-old packet passed a window shared with dataack")
		}
	})
	for _, size := range []int{1, 4096} {
		t.Run("queue budget "+strconv.Itoa(size), func(t *testing.T) {
			_, r, s, _ := recordFixture(t)
			receiver, _ := r.sessionForRemote("peer-left")
			for i := 0; i < 400; i++ {
				r.enqueueInbound(Packet{identityProof: receiver.identityProof, sessionID: s.sessionID, RemotePeerID: "peer-left", Payload: make([]byte, size)})
			}
			packets := r.drainInbound(0)
			stats := r.inbound.Stats()
			if stats.OverflowPackets != uint64(400-len(packets)) || stats.OverflowBytes != uint64((400-len(packets))*size) || stats.Bytes != 0 || stats.Packets != 0 {
				t.Fatal("queue overflow metrics or drain budget incorrect")
			}
			if len(packets) > 256 || len(packets)*size > 256*1024 {
				t.Errorf("queue retained %d packets / %d bytes", len(packets), len(packets)*size)
			}
		})
	}
}
func TestRealUDPReplayDeliveredOnce(t *testing.T) {
	m, r, s, address := recordFixture(t)
	n, c := sealRecordForTest(t, s, "packet", 0, []byte("udp-once"))
	l, _ := m.(*manager).listenerFor("peer-left")
	for i := 0; i < 2; i++ {
		if err := l.sendPacket("peer-right", address, s.sessionID, n, c); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Exchange("peer-left", "peer-right", []byte("barrier"), time.Second); err != nil {
		t.Fatal(err)
	}
	if got := len(r.drainInbound(0)); got != 1 {
		t.Errorf("real UDP replay delivered %d times", got)
	}
	r.mu.Lock()
	duplicates := r.recordStats.Duplicates
	r.mu.Unlock()
	if duplicates != 1 {
		t.Fatal("real UDP duplicate was not observed by the receiver")
	}
}
