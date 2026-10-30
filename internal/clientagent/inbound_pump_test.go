package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/virtualadapter"
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestInboundPumpReceivesWhileLifecycleWaitsForHTTP(t *testing.T) {
	for _, mode := range []string{"DIRECT", "RELAY"} {
		for _, enabled := range []bool{false, true} {
			name := mode + "/legacy"
			if enabled {
				name = mode + "/pump"
			}
			t.Run(name, func(t *testing.T) {
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				var gated atomic.Bool
				unblock := func() { gated.Store(false); once.Do(func() { close(release) }) }
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if gated.Load() {
						select {
						case <-entered:
						default:
							close(entered)
						}
						<-release
						http.Error(w, "offline", http.StatusServiceUnavailable)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": []controlclient.Network{{ID: "network", RoutingPolicy: "SPLIT"}}})
				}))
				defer server.Close()
				defer unblock()
				a, adapter, transport := newForwardingAgent(t, mode, server.URL)
				adapter.outbound = nil
				a.runtime = DefaultRuntimeConfig()
				a.lastSessionRefreshAt, a.lastSecurityRefreshAt, a.lastHeartbeatAt = time.Now(), time.Now(), time.Now()
				if _, err := a.forwardingNetworksLocked(); err != nil {
					t.Fatal(err)
				}
				a.refreshForwardingRoutesLocked()
				if enabled {
					a.startInboundPacketPump()
					defer a.inboundPump.stop()
				}
				gated.Store(true)
				done := make(chan struct{})
				go func() { defer close(done); a.runLifecycle() }()
				defer func() {
					unblock()
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Error("lifecycle did not stop")
					}
				}()
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("lifecycle HTTP did not start")
				}
				for sequence := range 64 {
					if err := transport.SendPacket("remote", "local", forwardingIPv4Packet("10.0.0.3", "10.0.0.2", sequence)); err != nil {
						t.Fatal(err)
					}
				}
				want := 0
				if enabled {
					want = 64
				}
				deadline := time.Now().Add(time.Second)
				for enabled && inboundWritten(adapter) < want && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if !enabled {
					time.Sleep(50 * time.Millisecond)
				}
				adapter.mu.Lock()
				written := append([]virtualadapter.Packet(nil), adapter.written...)
				adapter.mu.Unlock()
				if len(written) != want {
					t.Fatalf("while lifecycle HTTP is blocked: received %d/%d", len(written), want)
				}
				for sequence, packet := range written {
					if !bytes.Equal(packet.Data, forwardingIPv4Packet("10.0.0.3", "10.0.0.2", sequence)) {
						t.Fatal("packet order/content changed")
					}
				}
				if enabled {
					stopped := make(chan struct{})
					go func() { a.inboundPump.stop(); close(stopped) }()
					select {
					case <-stopped:
					case <-time.After(250 * time.Millisecond):
						t.Fatal("pump stop waited for lifecycle HTTP")
					}
				}
				unblock()
				<-done
				if enabled {
					a.mu.Lock()
					a.mergeInboundReportsLocked()
					count := a.directAttempts[connectionKey("network", "local", "remote")].TransportPacketCount
					a.mu.Unlock()
					if count != 64 {
						t.Fatalf("reported %d/64 received packets", count)
					}
				}
			})
		}
	}
}

func inboundWritten(adapter *forwardingAdapter) int {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return len(adapter.written)
}

func TestInboundPumpBoundsAndRetirement(t *testing.T) {
	for _, scenario := range []string{"backpressure", "expiry", "invalidate", "stop"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": []controlclient.Network{{ID: "network", RoutingPolicy: "SPLIT"}}})
			}))
			defer server.Close()
			a, adapter, transport := newForwardingAgent(t, "DIRECT", server.URL)
			adapter.outbound = nil
			a.startInboundPacketPump()
			defer a.inboundPump.stop()
			if scenario == "backpressure" {
				for range inboundPumpReports {
					a.inboundPump.reports <- inboundReport{}
				}
			}
			if _, err := a.forwardingNetworksLocked(); err != nil {
				t.Fatal(err)
			}
			snapshot := a.publishForwardingRoutesLocked(a.forwardingPolicy.networks)
			switch scenario {
			case "expiry":
				// Publish an already expired replacement, never mutate a published deadline.
				a.inboundPump.stop()
				snapshot.expires = time.Now().Add(-time.Second)
				a.startInboundPacketPump()
				defer a.inboundPump.stop()
			case "invalidate":
				a.invalidateForwardingRoutesLocked()
			case "stop":
				a.inboundPump.stop()
			}
			for sequence := range 64 {
				if err := transport.SendPacket("remote", "local", forwardingIPv4Packet("10.0.0.3", "10.0.0.2", sequence)); err != nil {
					t.Fatal(err)
				}
			}
			time.Sleep(50 * time.Millisecond)
			if inboundWritten(adapter) != 0 {
				t.Fatal("inactive/paused pump delivered packets")
			}
			if scenario == "backpressure" {
				if len(a.inboundPump.reports) != inboundPumpReports {
					t.Fatal("unbounded telemetry")
				}
				a.mergeInboundReportsLocked()
				deadline := time.Now().Add(time.Second)
				for inboundWritten(adapter) < 64 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if inboundWritten(adapter) != 64 {
					t.Fatal("backpressure lost retained transport packets")
				}
			}
			if scenario == "stop" {
				if err := a.forwardTransportPacketsLocked(time.Now()); err != nil {
					t.Fatal(err)
				}
				if inboundWritten(adapter) != 0 {
					t.Fatal("legacy path became a second inbound consumer")
				}
			}
		})
	}
}

type failingInboundAdapter struct{ *forwardingAdapter }

func (a *failingInboundAdapter) WritePackets([]virtualadapter.Packet) error {
	return errors.New("injected adapter failure")
}

func TestInboundPumpReportsWriteFailureWithoutCountingDelivery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []controlclient.Network{{ID: "network", RoutingPolicy: "SPLIT"}}})
	}))
	defer server.Close()
	a, adapter, transport := newForwardingAgent(t, "DIRECT", server.URL)
	a.adapterManager = &failingInboundAdapter{adapter}
	if _, err := a.forwardingNetworksLocked(); err != nil {
		t.Fatal(err)
	}
	a.refreshForwardingRoutesLocked()
	a.startInboundPacketPump()
	defer a.inboundPump.stop()
	if err := transport.SendPacket("remote", "local", forwardingIPv4Packet("10.0.0.3", "10.0.0.2", 1)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(a.inboundPump.reports) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	a.inboundPump.stop()
	a.mergeInboundReportsLocked()
	if a.lastLifecycleError != "inbound adapter write failed" || inboundWritten(adapter) != 0 || a.directAttempts[connectionKey("network", "local", "remote")].TransportPacketCount != 0 {
		t.Fatal("write failure was hidden or counted as successful delivery")
	}
}
