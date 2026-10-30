//go:build windows

package virtualadapter

import "testing"

func TestAdapterMTULimitsMatchTransport(t *testing.T) {
	for _, mtu := range []int{576, 1280, 1400, 1500} {
		got, err := desiredMTUFromConfigs([]NetworkConfig{{MTU: mtu}})
		if err != nil || got != mtu {
			t.Fatalf("valid MTU%d rejected: %v", mtu, err)
		}
	}
	for _, mtu := range []int{575, 1501, 65535} {
		if _, err := desiredMTUFromConfigs([]NetworkConfig{{MTU: mtu}}); err == nil {
			t.Fatalf("unsupported MTU%d accepted", mtu)
		}
	}
}
