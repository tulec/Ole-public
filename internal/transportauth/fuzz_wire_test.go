package transportauth

import (
	"encoding/hex"
	"strings"
	"testing"
)

func FuzzWireDecoders(f *testing.F) {
	for _, seed := range [][]byte{nil, []byte("OLP4"), []byte("OLR2"), []byte("OLEP3|probe|a|b|nonce"), make([]byte, DatagramBudget+1)} {
		f.Add(seed)
	}
	probe, err := EncodeTransport(TransportText([]string{"probe", "a", "b", "nonce"}))
	if err != nil {
		f.Fatal(err)
	}
	bound, err := EncodeRelay(RelayText([]string{"bound", "a", "nonce"}))
	if err != nil {
		f.Fatal(err)
	}
	fragment, err := EncodeTransport(FragmentText("a", "b", strings.Repeat("0", 32), Fragment{Kind: "packet", Counter: 1, Count: 4, Total: MaxMessageBytes + 16, Tag: make([]byte, 16), Data: make([]byte, FragmentBytes)}))
	if err != nil {
		f.Fatal(err)
	}
	send, err := EncodeRelay(RelayText([]string{"send", "token", "a", "b", hex.EncodeToString([]byte(TransportText([]string{"probe", "a", "b", "nonce"})))}))
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{probe, bound, fragment, send} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > DatagramBudget+1 {
			return
		}
		// Malformed and truncated inputs must return errors without panicking.
		_, _ = DecodeTransport(data)
		_, _ = DecodeRelay(data)
	})
}
