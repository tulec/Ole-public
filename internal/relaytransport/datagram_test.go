package relaytransport

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestIPPacketSizesAndFollowingTraffic(t *testing.T) {
	for _, size := range []int{576, 1280, 1400, 1500} {
		t.Run(stringSize(size), func(t *testing.T) {
			m, r, _, _ := recordFixture(t)
			payload := bytes.Repeat([]byte{byte(size)}, size)
			if err := m.SendPacket("a", "b", payload); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Exchange("a", "b", []byte("following"), 300*time.Millisecond); err != nil {
				t.Errorf("reader died after %d-byte packet: %v", size, err)
				return
			}
			packets := r.drainInbound(0)
			if len(packets) != 1 || !bytes.Equal(packets[0].Payload, payload) {
				t.Errorf("%d-byte IP packet was not delivered intact", size)
			}
		})
	}
}
func stringSize(n int) string { return fmt.Sprint(n) }
func TestOversizedPayloadRejectedBeforeSend(t *testing.T) {
	m, r, _, _ := recordFixture(t)
	if err := m.SendPacket("a", "b", make([]byte, 1501)); err == nil {
		t.Error("unsupported payload returned success")
	}
	if _, err := m.Exchange("a", "b", []byte("after-rejection"), 300*time.Millisecond); err != nil {
		t.Error("rejection damaged reader", err)
	}
	if len(r.drainInbound(0)) != 0 {
		t.Error("unsupported payload reached inbound queue")
	}
}
func TestOversizedDatagramDoesNotStopReader(t *testing.T) {
	m, r, _, _ := recordFixture(t)
	address := r.conn.LocalAddr().(*net.UDPAddr)
	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: address.Port}
	conn, err := net.DialUDP("udp", nil, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(make([]byte, 20000)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		r.mu.Lock()
		seen := r.wireStats.OversizedInbound > 0
		r.mu.Unlock()
		if seen {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("oversized datagram was not processed")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := m.Exchange("a", "b", []byte("still-alive"), 300*time.Millisecond); err != nil {
		t.Fatal("oversized datagram killed reader", err)
	}
}

func TestFragmentedExchangeAndReversePacket(t *testing.T) {
	m, r, _, _ := recordFixture(t)
	r.mu.Lock()
	r.exchangeHandler = func(_ string, b []byte) []byte { return b }
	r.mu.Unlock()
	for _, size := range []int{576, 1280, 1400, 1500} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		response, err := m.Exchange("a", "b", payload, time.Second)
		if err != nil || !bytes.Equal(response, payload) {
			t.Fatalf("fragmented request/response size%d: %v", size, err)
		}
	}
	payload := bytes.Repeat([]byte{91}, 1500)
	if err := m.SendPacket("b", "a", payload); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Exchange("b", "a", []byte("barrier"), time.Second); err != nil {
		t.Fatal(err)
	}
	packets := m.DrainInbound("a", 0)
	if len(packets) != 1 || !bytes.Equal(packets[0].Payload, payload) {
		t.Fatal("reverse large packet lost")
	}
}

func TestDefaultExchangeAtMessageLimit(t *testing.T) {
	m, _, _, _ := recordFixture(t)
	for _, size := range []int{1496, 1497, 1500} {
		payload := bytes.Repeat([]byte{37}, size)
		response, err := m.Exchange("a", "b", payload, time.Second)
		if err != nil || !bytes.Equal(response, append([]byte("ack:"), payload...)) {
			t.Fatalf("default response for %d-byte request: %v", size, err)
		}
	}
}
