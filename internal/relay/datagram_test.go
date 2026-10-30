package relay_test

import (
	"Ole/internal/relay"
	"net"
	"testing"
	"time"
)

func TestOversizedDatagramDoesNotStopRelayServer(t *testing.T) {
	server, err := relay.Listen("127.0.0.1:0", relay.StaticAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	bad, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	if _, err := bad.Write(make([]byte, 20000)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for server.Snapshot().OversizedPackets == 0 {
		if time.Now().After(deadline) {
			t.Fatal("oversized datagram not processed")
		}
		time.Sleep(time.Millisecond)
	}
	a, b := mustListenUDP(t), mustListenUDP(t)
	defer a.Close()
	defer b.Close()
	sendRelayMessage(t, a, server.LocalAddr().String(), "OLER2|bind|a|a|nonce-a")
	sendRelayMessage(t, b, server.LocalAddr().String(), "OLER2|bind|b|b|nonce-b")
	if _, err := relay.WaitForPacket(a, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.WaitForPacket(b, time.Second); err != nil {
		t.Fatal(err)
	}
	sendRelayMessage(t, a, server.LocalAddr().String(), "OLER2|send|a|a|b|6f6b")
	if packet, err := relay.WaitForPacket(b, time.Second); err != nil || packet != "OLER2|deliver|a|6f6b" {
		t.Fatal("relay did not recover", err)
	}
}
