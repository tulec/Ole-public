package clientagent

import (
	"testing"
	"time"
)

func TestDefaultRuntimeConfigUsesInteractiveLifecycleCadence(t *testing.T) {
	runtime := DefaultRuntimeConfig()
	if runtime.LifecycleInterval != time.Second {
		t.Fatalf("expected lifecycle interval %v, got %v", time.Second, runtime.LifecycleInterval)
	}
	if runtime.HeartbeatInterval != 10*time.Second {
		t.Fatalf("expected heartbeat interval %v, got %v", 10*time.Second, runtime.HeartbeatInterval)
	}
	if runtime.PeerDiscoveryPeriod != 10*time.Second {
		t.Fatalf("expected peer discovery period %v, got %v", 10*time.Second, runtime.PeerDiscoveryPeriod)
	}
	if runtime.STUNProbePeriod != 10*time.Second {
		t.Fatalf("expected STUN probe period %v, got %v", 10*time.Second, runtime.STUNProbePeriod)
	}
	if runtime.TransportKeepalive != 5*time.Second {
		t.Fatalf("expected transport keepalive %v, got %v", 5*time.Second, runtime.TransportKeepalive)
	}
	if runtime.RelayFailbackPeriod != 10*time.Second {
		t.Fatalf("expected relay failback period %v, got %v", 10*time.Second, runtime.RelayFailbackPeriod)
	}
}

func TestNormalizeRuntimeConfigDefaultsLifecycleToInteractiveCadence(t *testing.T) {
	runtime := normalizeRuntimeConfig(RuntimeConfig{})
	if runtime.LifecycleInterval != time.Second {
		t.Fatalf("expected normalized lifecycle interval %v, got %v", time.Second, runtime.LifecycleInterval)
	}
	if runtime.HeartbeatInterval != 10*time.Second {
		t.Fatalf("expected normalized heartbeat interval %v, got %v", 10*time.Second, runtime.HeartbeatInterval)
	}
	if runtime.PeerDiscoveryPeriod != 10*time.Second {
		t.Fatalf("expected normalized peer discovery period %v, got %v", 10*time.Second, runtime.PeerDiscoveryPeriod)
	}
	if runtime.STUNProbePeriod != 10*time.Second {
		t.Fatalf("expected normalized STUN probe period %v, got %v", 10*time.Second, runtime.STUNProbePeriod)
	}
	if runtime.TransportKeepalive != 5*time.Second {
		t.Fatalf("expected normalized transport keepalive %v, got %v", 5*time.Second, runtime.TransportKeepalive)
	}
	if runtime.RelayFailbackPeriod != 10*time.Second {
		t.Fatalf("expected normalized relay failback period %v, got %v", 10*time.Second, runtime.RelayFailbackPeriod)
	}
}
