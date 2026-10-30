package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/directprobe"
	"Ole/internal/overlaydns"
	"Ole/internal/relaytransport"
	"Ole/internal/transportauth"
	"Ole/internal/virtualadapter"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type reconcilePacketAdapter struct{ *forwardingAdapter }

func (a *reconcilePacketAdapter) Reconcile([]virtualadapter.NetworkConfig) (virtualadapter.Status, error) {
	return virtualadapter.Status{}, nil
}

// Isolate the apply barrier from actual binding replacement; real session
// replacement is covered by TestOutboundControlHoldsSessionReplacement.
type gatedReconcileDirect struct {
	directprobe.Manager
	wait func()
}

func (m gatedReconcileDirect) Reconcile([]directprobe.Binding) error { m.wait(); return nil }

type gatedReconcileRelay struct {
	relaytransport.Manager
	wait func()
}

func (m gatedReconcileRelay) Reconcile([]relaytransport.Binding) error { m.wait(); return nil }

func TestReconcilePreparedInputsApplyUnderBarrier(t *testing.T) {
	for _, mode := range []string{"DIRECT", "RELAY"} {
		t.Run(mode, func(t *testing.T) {
			var networkReads atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPatch {
					_ = json.NewEncoder(w).Encode(map[string]any{"data": controlclient.Peer{ID: "local"}})
					return
				}
				networkReads.Add(1)
				_ = json.NewEncoder(w).Encode(map[string]any{"data": []controlclient.Network{{ID: "network", RoutingPolicy: "SPLIT"}}})
			}))
			defer server.Close()
			a, adapter, transport := newForwardingAgent(t, mode, server.URL)
			a.adapterManager = &reconcilePacketAdapter{adapter}
			packets := adapter.outbound
			adapter.outbound = nil
			a.runtime = DefaultRuntimeConfig()
			a.runtime.RelayServerAddress = "127.0.0.1:1"
			a.overlayDNS = overlaydns.New("", "ole.test")
			sessionID, _ := forwardingSession(t, a, mode)
			key := connectionKey("network", "local", "remote")
			attempt := a.directAttempts[key]
			attempt.TransportSessionID, attempt.TransportStartedAt = sessionID, time.Now()
			a.directAttempts[key] = attempt
			a.applyAttemptStateToConnection(&a.connections[0], attempt)
			if _, err := a.forwardingNetworksLocked(); err != nil {
				t.Fatal(err)
			}
			a.refreshForwardingRoutesLocked()
			networkReads.Store(0)
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			wait := func() { close(entered); <-release }
			if mode == "DIRECT" {
				a.directManager = gatedReconcileDirect{a.directManager, wait}
			} else {
				a.relayManager = gatedReconcileRelay{a.relayManager, wait}
			}
			a.startInboundPacketPump()
			a.startOutboundPacketPump()
			defer a.inboundPump.stop()
			defer a.outboundPump.stop()
			done := make(chan error, 1)
			go func() {
				a.mu.Lock()
				defer a.mu.Unlock()
				done <- a.outboundControlLocked(func() error { return a.negotiateDirectConnectionsLocked(time.Now()) })
			}()
			var finishOnce sync.Once
			finish := func() {
				unblock()
				finishOnce.Do(func() {
					select {
					case err := <-done:
						if err != nil {
							t.Errorf("reconcile apply: %v", err)
						}
					case <-time.After(2 * time.Second):
						t.Error("reconcile apply did not finish")
					}
				})
			}
			defer finish()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("binding apply did not start")
			}
			adapter.mu.Lock()
			adapter.outbound = packets
			adapter.mu.Unlock()
			time.Sleep(30 * time.Millisecond)
			if len(transport.DrainInbound("remote", 256)) != 0 {
				t.Fatal("binding apply released the send barrier")
			}
			finish()
			var sent []transportInboundPacket
			deadline := time.Now().Add(time.Second)
			for len(sent) < 64 && time.Now().Before(deadline) {
				sent = append(sent, transport.DrainInbound("remote", 256)...)
				time.Sleep(time.Millisecond)
			}
			a.outboundPump.stop()
			a.mergeOutboundReportsLocked(false)
			if len(sent) != 64 || a.directAttempts[key].TransportPacketCount != 64 || networkReads.Load() != 1 {
				t.Fatalf("apply: packets=%d counter=%d networkReads=%d; want 64,64,1", len(sent), a.directAttempts[key].TransportPacketCount, networkReads.Load())
			}
			for index, packet := range sent {
				if !bytes.Equal(packet.Payload, packets[index].Data) {
					t.Fatal("apply lost/duplicated adapter batch")
				}
			}
		})
	}
}

func TestReconcileHTTPWaitKeepsCoherentTrafficAndRecoveryBarrier(t *testing.T) {
	for _, mode := range []string{"DIRECT", "RELAY"} {
		for _, stage := range []string{"networks", "identities", "recovery-networks"} {
			t.Run(mode+"/"+stage, func(t *testing.T) {
				entered, release := make(chan struct{}), make(chan struct{})
				var armed atomic.Bool
				var enterOnce, releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					identity := strings.HasSuffix(r.URL.Path, "/transport-identities")
					if armed.Load() && r.Method == http.MethodGet && (identity == (stage == "identities")) {
						enterOnce.Do(func() { close(entered) })
						<-release
						http.Error(w, "read unavailable", http.StatusServiceUnavailable)
						return
					}
					if r.Method == http.MethodPatch {
						_ = json.NewEncoder(w).Encode(map[string]any{"data": controlclient.Peer{ID: "local"}})
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": []controlclient.Network{{ID: "network", RoutingPolicy: "SPLIT"}}})
				}))
				defer server.Close()
				defer unblock()
				a, adapter, transport := newForwardingAgent(t, mode, server.URL)
				a.adapterManager = &reconcilePacketAdapter{adapter}
				packets := adapter.outbound
				adapter.outbound = nil
				a.runtime = DefaultRuntimeConfig()
				// Only needs to be nonempty: the identity wait precedes rebinding.
				a.runtime.RelayServerAddress = "127.0.0.1:1"
				if stage != "identities" {
					a.overlayDNS = overlaydns.New("", "ole.test")
				}
				sessionID, _ := forwardingSession(t, a, mode)
				key := connectionKey("network", "local", "remote")
				attempt := a.directAttempts[key]
				attempt.TransportSessionID, attempt.TransportStartedAt = sessionID, time.Now()
				a.directAttempts[key] = attempt
				a.applyAttemptStateToConnection(&a.connections[0], attempt)
				if _, err := a.forwardingNetworksLocked(); err != nil {
					t.Fatal(err)
				}
				a.forwardingPolicy.expires = time.Now().Add(600 * time.Millisecond)
				if stage == "identities" {
					// A longer policy must not extend a previously known credential
					// deadline when the refresh clears its owner-side cache entry.
					a.forwardingPolicy.expires = time.Now().Add(5 * time.Second)
					a.transportCredentials = map[string]cachedTransportCredentials{
						server.URL + "|user|local": {credentials: &transportauth.Credentials{ExpiresAt: time.Now().Add(600 * time.Millisecond)}, refreshAt: time.Now().Add(-time.Second)},
					}
				}
				held := a.publishForwardingRoutesLocked(a.forwardingPolicy.networks)
				a.startInboundPacketPump()
				a.startOutboundPacketPump()
				defer a.inboundPump.stop()
				defer a.outboundPump.stop()
				armed.Store(true)
				done := make(chan error, 1)
				go func() {
					a.mu.Lock()
					defer a.mu.Unlock()
					done <- a.outboundControlLocked(func() error {
						if stage == "recovery-networks" {
							return a.reconcileManagedRuntimeLocked()
						}
						return a.negotiateDirectConnectionsLocked(time.Now())
					})
				}()
				var finishOnce sync.Once
				finish := func() {
					unblock()
					finishOnce.Do(func() {
						select {
						case err := <-done:
							if err == nil {
								t.Error("expected failed read")
							}
						case <-time.After(2 * time.Second):
							t.Error("reconcile wait did not return")
						}
					})
				}
				defer finish()
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("reconcile read did not start")
				}
				adapter.mu.Lock()
				adapter.outbound = packets
				adapter.mu.Unlock()
				for sequence := range 64 {
					if err := transport.SendPacket("remote", "local", forwardingIPv4Packet("10.0.0.3", "10.0.0.2", sequence)); err != nil {
						t.Fatal(err)
					}
				}
				want := 64
				if stage == "recovery-networks" {
					want = 0
				}
				var sent []transportInboundPacket
				deadline := time.Now().Add(300 * time.Millisecond)
				for time.Now().Before(deadline) && (len(sent) < want || inboundWritten(adapter) < 64 || want == 0) {
					sent = append(sent, transport.DrainInbound("remote", 256)...)
					time.Sleep(time.Millisecond)
				}
				if len(sent) != want || inboundWritten(adapter) != 64 {
					t.Fatalf("%s wait: sent=%d/%d received=%d/64", stage, len(sent), want, inboundWritten(adapter))
				}
				for index, packet := range sent {
					if !bytes.Equal(packet.Payload, packets[index].Data) {
						t.Fatal("reconcile read lost/duplicated payload")
					}
				}
				if snapshot := a.forwardingRoutes.Load(); snapshot == nil || !snapshot.expires.Equal(held.expires) {
					t.Fatal("pending reconcile read changed the original lease")
				}
				if delay := time.Until(held.expires); delay > 0 {
					time.Sleep(delay + 10*time.Millisecond)
				}
				adapter.mu.Lock()
				adapter.outbound = append(adapter.outbound, virtualadapter.Packet{Data: forwardingIPv4Packet("10.0.0.2", "10.0.0.3", 64)})
				adapter.mu.Unlock()
				_ = transport.SendPacket("remote", "local", forwardingIPv4Packet("10.0.0.3", "10.0.0.2", 64))
				time.Sleep(30 * time.Millisecond)
				if len(transport.DrainInbound("remote", 256)) != 0 || inboundWritten(adapter) != 64 {
					t.Fatal("reconcile read forwarded after lease expiry")
				}
				a.outboundPump.stop()
				a.inboundPump.stop()
				finish()
				a.mergeInboundReportsLocked()
				a.mergeOutboundReportsLocked(false)
				if got := a.directAttempts[key].TransportPacketCount; got != want+64 {
					t.Fatalf("reconcile counters=%d want=%d", got, want+64)
				}
				if snapshot := a.forwardingRoutes.Load(); snapshot != nil && snapshot.valid.Load() {
					t.Fatal("failed reconcile read left valid routing")
				}
				if stage == "identities" {
					manager := a.transportManagerForConnectionLocked(a.connections[0])
					if err := manager.SendPacket("local", "remote", forwardingIPv4Packet("10.0.0.2", "10.0.0.3", 65)); err == nil {
						t.Fatal("failed identity refresh retained an authenticated sender")
					}
				}
			})
		}
	}
}
