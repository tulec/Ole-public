package stun

import (
	"net"
	"testing"
	"time"
)

func TestProbeAgainstLocalServer(t *testing.T) {
	server, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen stun server: %v", err)
	}
	defer server.Close()

	result, err := Probe(server.LocalAddr().String(), "127.0.0.1:0", time.Second)
	if err != nil {
		t.Fatalf("probe stun server: %v", err)
	}
	if result.ServerAddress != server.LocalAddr().String() {
		t.Fatalf("expected server address %q, got %q", server.LocalAddr().String(), result.ServerAddress)
	}
	if result.LocalAddress == "" {
		t.Fatalf("expected local address in probe result")
	}
	if result.MappedAddress == "" {
		t.Fatalf("expected mapped address in probe result")
	}
	if result.NATType != NATTypeOpenInternet {
		t.Fatalf("expected NAT type %q, got %q", NATTypeOpenInternet, result.NATType)
	}
}

func TestEncodeDecodeBindingSuccessResponse(t *testing.T) {
	transactionID := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	mappedAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.10").To4(), Port: 54321}

	message, err := EncodeBindingSuccessResponse(transactionID, mappedAddr)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	decoded, err := DecodeBindingSuccessResponse(message, transactionID)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if decoded.String() != mappedAddr.String() {
		t.Fatalf("expected decoded mapped addr %q, got %q", mappedAddr.String(), decoded.String())
	}
}
