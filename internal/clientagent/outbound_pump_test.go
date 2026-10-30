package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/virtualadapter"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPacketPumpsForwardBothWaysDuringLifecycleHTTP(t *testing.T) {
	for _, mode := range []string{"DIRECT", "RELAY"} {
		for _, variant := range []string{"legacy", "pumps", "large-mixed"} {
			enabled := variant != "legacy"
			packetCount := 64
			if variant == "large-mixed" {
				packetCount = 1024
			}
			name := mode + "/" + variant
			t.Run(name, func(t *testing.T) {
				entered, release := make(chan struct{}), make(chan struct{})
				var gate atomic.Bool
				var once sync.Once
				unblock := func() { gate.Store(false); once.Do(func() { close(release) }) }
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if gate.Load() {
						select {
						case <-entered:
						default:
							close(entered)
						}
						<-release
						http.Error(w, "offline", 503)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": []controlclient.Network{{ID: "network", RoutingPolicy: "SPLIT", GroupTrafficPolicy: "FLOOD"}}})
				}))
				defer server.Close()
				defer unblock()
				a, adapter, transport := newForwardingAgent(t, mode, server.URL)
				destinationFor := func(sequence int) string {
					if variant == "large-mixed" {
						switch sequence % 3 {
						case 1:
							return "10.0.0.255"
						case 2:
							return "239.1.2.3"
						}
					}
					return "10.0.0.3"
				}
				adapter.outbound = nil
				for sequence := range packetCount {
					adapter.outbound = append(adapter.outbound, virtualadapter.Packet{Data: forwardingIPv4Packet("10.0.0.2", destinationFor(sequence), sequence)})
				}
				a.runtime = DefaultRuntimeConfig()
				a.lastSessionRefreshAt, a.lastSecurityRefreshAt, a.lastHeartbeatAt = time.Now(), time.Now(), time.Now()
				if _, err := a.forwardingNetworksLocked(); err != nil {
					t.Fatal(err)
				}
				a.refreshForwardingRoutesLocked()
				if enabled {
					a.startInboundPacketPump()
					a.startOutboundPacketPump()
					defer a.inboundPump.stop()
					defer a.outboundPump.stop()
				}
				gate.Store(true)
				done := make(chan struct{})
				go func() { defer close(done); a.runLifecycle() }()
				defer func() {
					unblock()
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Error("lifecycle did not return")
					}
				}()
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("HTTP did not start")
				}
				burstStarted := time.Now()
				for sequence := range 64 {
					if err := transport.SendPacket("remote", "local", forwardingIPv4Packet("10.0.0.3", "10.0.0.2", sequence)); err != nil {
						t.Fatal(err)
					}
				}
				want, wantInbound := 0, 0
				if enabled {
					want, wantInbound = packetCount, 64
				}
				var sent []transportInboundPacket
				deadline := time.Now().Add(time.Second)
				for enabled && (len(sent) < want || inboundWritten(adapter) < wantInbound) && time.Now().Before(deadline) {
					sent = append(sent, transport.DrainInbound("remote", 256)...)
					time.Sleep(time.Millisecond)
				}
				if !enabled {
					time.Sleep(50 * time.Millisecond)
					sent = transport.DrainInbound("remote", 256)
				}
				if len(sent) != want || inboundWritten(adapter) != wantInbound {
					t.Fatalf("HTTP stall: sent=%d/%d received=%d/%d", len(sent), want, inboundWritten(adapter), wantInbound)
				}
				if variant == "large-mixed" {
					t.Logf("HTTP stall: 1024 mixed TX + 64 RX in %s (includes observation polling)", time.Since(burstStarted))
					if a.outboundPump.successSlots.Load() != 3 || len(a.outboundPump.reports) != 0 {
						t.Fatal("mixed successes did not retain just three payload-free report entries")
					}
				}
				for sequence, packet := range sent {
					if !bytes.Equal(packet.Payload, forwardingIPv4Packet("10.0.0.2", destinationFor(sequence), sequence)) {
						t.Fatal("outbound order/content changed")
					}
				}
				if enabled {
					stopped := make(chan struct{})
					go func() { a.outboundPump.stop(); a.inboundPump.stop(); close(stopped) }()
					select {
					case <-stopped:
					case <-time.After(250 * time.Millisecond):
						t.Fatal("stop waited for HTTP")
					}
				}
				unblock()
				<-done
				if enabled {
					a.mergeInboundReportsLocked()
					a.mergeOutboundReportsLocked(false)
					attempt := a.directAttempts[connectionKey("network", "local", "remote")]
					if attempt.TransportPacketCount != want+wantInbound {
						t.Fatalf("counters=%d want=%d", attempt.TransportPacketCount, want+wantInbound)
					}
					if variant == "large-mixed" {
						diag := a.groupTrafficDiagnostics["network"]
						if attempt.GroupBroadcastCopies != 341 || attempt.GroupMulticastCopies != 341 || attempt.GroupTrafficPacketCopies != 682 || diag.FloodPacketCount != 682 || diag.FanoutCopyCount != 682 || diag.BroadcastPacketCount != 341 || diag.MulticastPacketCount != 341 {
							t.Fatalf("mixed group counters lost: attempt=%+v diag=%+v", attempt, diag)
						}
					}
				}
			})
		}
	}
}

type partialOutboundAdapter struct{ *forwardingAdapter }

func (a *partialOutboundAdapter) ReadPackets(limit int) ([]virtualadapter.Packet, error) {
	packets, err := a.forwardingAdapter.ReadPackets(limit)
	if len(packets) > 0 {
		return packets, errors.New("injected partial read")
	}
	return packets, err
}

func TestOutboundPumpPreservesPartialAdapterRead(t *testing.T) {
	server := outboundPolicyServer(t)
	a, adapter, transport := newForwardingAgent(t, "DIRECT", server.URL)
	adapter.outbound = adapter.outbound[:1]
	a.adapterManager = &partialOutboundAdapter{adapter}
	if _, err := a.forwardingNetworksLocked(); err != nil {
		t.Fatal(err)
	}
	a.refreshForwardingRoutesLocked()
	a.startOutboundPacketPump()
	defer a.outboundPump.stop()
	var packets []transportInboundPacket
	deadline := time.Now().Add(time.Second)
	for len(packets) == 0 && time.Now().Before(deadline) {
		packets = transport.DrainInbound("remote", 256)
		time.Sleep(time.Millisecond)
	}
	if len(packets) != 1 || !bytes.Equal(packets[0].Payload, forwardingIPv4Packet("10.0.0.2", "10.0.0.3", 0)) {
		t.Fatal("partial ReadPackets result was discarded")
	}
	a.outboundPump.stop()
	a.mergeOutboundReportsLocked(false)
	if a.lastLifecycleError != "outbound adapter read failed" || a.directAttempts[connectionKey("network", "local", "remote")].TransportPacketCount != 1 {
		t.Fatal("read error hidden or successful packet miscounted")
	}
}

func TestOutboundPumpRetainsBatchAcrossPublicationWithoutCrossingScope(t *testing.T) {
	for _, changedScope := range []bool{false, true} {
		name := "publication"
		if changedScope {
			name = "new-scope"
		}
		t.Run(name, func(t *testing.T) {
			server := outboundPolicyServer(t)
			a, adapter, transport := newForwardingAgent(t, "DIRECT", server.URL)
			a.startOutboundPacketPump()
			defer a.outboundPump.stop()
			a.outboundPump.ioMu.Lock()
			locked := true
			defer func() {
				if locked {
					a.outboundPump.ioMu.Unlock()
				}
			}()
			if _, err := a.forwardingNetworksLocked(); err != nil {
				t.Fatal(err)
			}
			a.refreshForwardingRoutesLocked()
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				reads, _ := adapter.pending()
				if reads > 0 {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if reads, pending := adapter.pending(); reads != 1 || pending != 32 {
				t.Fatal("test did not capture one adapter batch", reads, pending)
			}
			a.invalidateForwardingRoutesLocked()
			a.outboundPump.ioMu.Unlock()
			locked = false
			time.Sleep(30 * time.Millisecond)
			if changedScope {
				a.currentSession.AccessToken = "new-token"
				a.publishForwardingPolicyLocked(a.forwardingPolicy.networks, time.Now())
			}
			a.refreshForwardingRoutesLocked()
			want := 64
			if changedScope {
				want = 32
			}
			var received []transportInboundPacket
			deadline = time.Now().Add(time.Second)
			for len(received) < want && time.Now().Before(deadline) {
				received = append(received, transport.DrainInbound("remote", 256)...)
				time.Sleep(time.Millisecond)
			}
			if len(received) != want {
				t.Fatalf("received %d/%d", len(received), want)
			}
			for index, packet := range received {
				sequence := index
				if changedScope {
					sequence += 32
				}
				if !bytes.Equal(packet.Payload, forwardingIPv4Packet("10.0.0.2", "10.0.0.3", sequence)) {
					t.Fatal("batch lost/duplicated or crossed authentication scope")
				}
			}
		})
	}
}

func outboundPolicyServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []controlclient.Network{{ID: "network", RoutingPolicy: "SPLIT"}}})
	}))
	t.Cleanup(server.Close)
	return server
}

func TestOutboundPumpBackpressureAndSingleConsumer(t *testing.T) {
	for _, scenario := range []string{"backpressure", "deferred-recovery", "successes", "mixed-reports", "stop", "expiry"} {
		t.Run(scenario, func(t *testing.T) {
			server := outboundPolicyServer(t)
			a, adapter, transport := newForwardingAgent(t, "DIRECT", server.URL)
			a.startOutboundPacketPump()
			defer a.outboundPump.stop()
			if scenario == "successes" || scenario == "mixed-reports" {
				for index := range outboundPumpReports {
					if scenario == "mixed-reports" && index%2 == 0 {
						a.outboundPump.reports <- outboundReport{}
					} else {
						a.outboundPump.recordSuccess(outboundReport{route: ConnectionStatus{RemotePeerID: fmt.Sprint(index)}})
					}
				}
			}
			if scenario == "backpressure" || scenario == "deferred-recovery" {
				for range outboundPumpReports {
					report := outboundReport{}
					if scenario == "deferred-recovery" {
						report.scope = a.forwardingScopeLocked()
						report.expires = time.Now().Add(time.Second)
						report.payload = forwardingIPv4Packet("10.0.0.2", "10.0.0.3", 0)
					}
					a.outboundPump.reports <- report
				}
				if scenario == "deferred-recovery" {
					a.mergeOutboundReportsLocked(false)
					if len(a.outboundPump.recoveries) != outboundPumpReports || a.outboundPump.heldReports.Load() != outboundPumpReports || len(a.outboundPump.reports) != 0 {
						t.Fatal("deferred failures lost the shared 128-slot budget")
					}
				}
			}
			if scenario == "stop" {
				a.outboundPump.stop()
			}
			if _, err := a.forwardingNetworksLocked(); err != nil {
				t.Fatal(err)
			}
			if scenario == "expiry" {
				a.forwardingPolicy.expires = time.Now().Add(-time.Second)
			}
			a.refreshForwardingRoutesLocked()
			time.Sleep(50 * time.Millisecond)
			if reads, pending := adapter.pending(); reads != 0 || pending != 64 {
				t.Fatal("paused/stopped pump dequeued adapter packets", reads, pending)
			}
			if scenario == "deferred-recovery" {
				a.outboundPump.stop()
				a.mergeOutboundReportsLocked(false)
				if len(a.outboundPump.recoveries) != 0 || a.outboundPump.heldReports.Load() != 0 {
					t.Fatal("stop retained deferred recovery payloads")
				}
			}
			if scenario == "stop" {
				if err := a.forwardTransportPacketsLocked(time.Now()); err != nil {
					t.Fatal(err)
				}
				if reads, _ := adapter.pending(); reads != 0 {
					t.Fatal("legacy became a second adapter consumer")
				}
			}
			if scenario == "backpressure" || scenario == "successes" || scenario == "mixed-reports" {
				a.mergeOutboundReportsLocked(true)
				deadline, count := time.Now().Add(time.Second), 0
				for count < 64 && time.Now().Before(deadline) {
					count += len(transport.DrainInbound("remote", 256))
					time.Sleep(time.Millisecond)
				}
				if count != 64 {
					t.Fatalf("after backpressure received %d/64", count)
				}
			}
		})
	}
}

func TestOutboundPumpRecoversRealDirectSession(t *testing.T) {
	for _, name := range []string{"retry", "new-auth-scope", "stop"} {
		t.Run(name, func(t *testing.T) {
			revoke := name == "new-auth-scope"
			stop := name == "stop"
			server := outboundPolicyServer(t)
			a, adapter, transport := newForwardingAgent(t, "DIRECT", server.URL)
			adapter.outbound = adapter.outbound[:1]
			session, err := a.directManager.Establish("local", "remote", nil, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			a.connections[0].RemoteCandidates = []string{session.RemoteAddress}
			a.runtime = DefaultRuntimeConfig()
			a.directManager.DropSession("local", "remote")
			if _, err := a.forwardingNetworksLocked(); err != nil {
				t.Fatal(err)
			}
			a.refreshForwardingRoutesLocked()
			a.startOutboundPacketPump()
			defer a.outboundPump.stop()
			deadline := time.Now().Add(time.Second)
			for len(a.outboundPump.reports) == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if len(a.outboundPump.reports) == 0 {
				t.Fatal("failed packet was not handed to lifecycle")
			}
			a.mergeOutboundReportsLocked(false) // Same non-network merge used by Status.
			if len(a.outboundPump.recoveries) != 1 || a.outboundPump.heldReports.Load() != 1 {
				t.Fatal("Status lost the failed packet or its shared capacity reservation")
			}
			if got := transport.DrainInbound("remote", 256); len(got) != 0 {
				t.Fatal("Status executed network recovery")
			}
			if revoke {
				a.currentSession.AccessToken = "new-token"
				a.invalidateForwardingRoutesLocked()
			}
			if stop {
				a.outboundPump.stop()
			}
			a.mergeOutboundReportsLocked(!stop)
			if len(a.outboundPump.recoveries) != 0 || a.outboundPump.heldReports.Load() != 0 {
				t.Fatal("completed/revoked/stopped recovery retained payload capacity")
			}
			var received []transportInboundPacket
			deadline = time.Now().Add(time.Second)
			for !revoke && !stop && len(received) == 0 && time.Now().Before(deadline) {
				received = transport.DrainInbound("remote", 256)
				time.Sleep(time.Millisecond)
			}
			if revoke || stop {
				time.Sleep(30 * time.Millisecond)
				received = transport.DrainInbound("remote", 256)
			}
			want := 1
			if revoke || stop {
				want = 0
			}
			if len(received) != want {
				t.Fatalf("recovery deliveries=%d want=%d", len(received), want)
			}
			if !revoke && !stop && !bytes.Equal(received[0].Payload, forwardingIPv4Packet("10.0.0.2", "10.0.0.3", 0)) {
				t.Fatal("recovery changed payload")
			}
		})
	}
}

func TestOutboundDeliveredCountersSurviveAccessTokenRotation(t *testing.T) {
	server := outboundPolicyServer(t)
	a, adapter, transport := newForwardingAgent(t, "DIRECT", server.URL)
	adapter.outbound = adapter.outbound[:1]
	if _, err := a.forwardingNetworksLocked(); err != nil {
		t.Fatal(err)
	}
	a.refreshForwardingRoutesLocked()
	a.startOutboundPacketPump()
	defer a.outboundPump.stop()
	deadline := time.Now().Add(time.Second)
	var packets []transportInboundPacket
	for len(packets) == 0 && time.Now().Before(deadline) {
		packets = transport.DrainInbound("remote", 256)
		time.Sleep(time.Millisecond)
	}
	if len(packets) != 1 {
		t.Fatal("packet did not reach peer")
	}
	a.outboundPump.stop()
	a.currentSession.AccessToken = "rotated-access-token"
	a.mergeOutboundReportsLocked(false)
	if count := a.directAttempts[connectionKey("network", "local", "remote")].TransportPacketCount; count != 1 {
		t.Fatal("successful send counter was lost during token rotation", count)
	}
}
