package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/directprobe"
	"Ole/internal/relaytransport"
	"Ole/internal/virtualadapter"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Delay only Exchange, leaving the real UDP readers and packet crypto running.
// Blocking a remote ExchangeHandler would also block that remote UDP reader.
type delayedQualityDirect struct {
	directprobe.Manager
	wait func()
}

func (m delayedQualityDirect) Exchange(local, remote string, payload []byte, timeout time.Duration) ([]byte, error) {
	if string(payload) == "ole-keepalive" {
		m.wait()
	}
	return m.Manager.Exchange(local, remote, payload, timeout)
}

type delayedQualityRelay struct {
	relaytransport.Manager
	wait func()
}

func (m delayedQualityRelay) Exchange(local, remote string, payload []byte, timeout time.Duration) ([]byte, error) {
	if string(payload) == "ole-keepalive" {
		m.wait()
	}
	return m.Manager.Exchange(local, remote, payload, timeout)
}

func forwardingSession(t *testing.T, a *Agent, mode string) (string, string) {
	t.Helper()
	if mode == "DIRECT" {
		session, err := a.directManager.Establish("local", "remote", nil, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return session.SessionID, session.RemoteAddress
	}
	session, err := a.relayManager.Establish("local", "remote", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return session.SessionID, session.RemoteAddress
}

func TestPacketPumpsForwardDuringSignalingAndQualityWait(t *testing.T) {
	for _, mode := range []string{"DIRECT", "RELAY"} {
		for _, stage := range []string{"signaling", "quality"} {
			t.Run(mode+"/"+stage, func(t *testing.T) {
				entered, release := make(chan struct{}), make(chan struct{})
				var enterOnce, releaseOnce sync.Once
				wait := func() { enterOnce.Do(func() { close(entered) }); <-release }
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPatch {
						wait()
						http.Error(w, "signaling unavailable", http.StatusServiceUnavailable)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": []controlclient.Network{{ID: "network", RoutingPolicy: "SPLIT"}}})
				}))
				defer server.Close()
				defer unblock()
				a, adapter, transport := newForwardingAgent(t, mode, server.URL)
				packets := adapter.outbound
				adapter.outbound = nil
				a.runtime = DefaultRuntimeConfig()
				sessionID, _ := forwardingSession(t, a, mode)
				key := connectionKey("network", "local", "remote")
				attempt := a.directAttempts[key]
				attempt.TransportSessionID, attempt.TransportStartedAt = sessionID, time.Now()
				a.directAttempts[key] = attempt
				a.applyAttemptStateToConnection(&a.connections[0], attempt)
				if stage == "quality" {
					if mode == "DIRECT" {
						a.directManager = delayedQualityDirect{a.directManager, wait}
					} else {
						a.relayManager = delayedQualityRelay{a.relayManager, wait}
					}
				}
				if _, err := a.forwardingNetworksLocked(); err != nil {
					t.Fatal(err)
				}
				a.forwardingPolicy.expires = time.Now().Add(600 * time.Millisecond)
				a.refreshForwardingRoutesLocked()
				originalDeadline := a.forwardingRoutes.Load().expires
				a.startInboundPacketPump()
				a.startOutboundPacketPump()
				defer a.inboundPump.stop()
				defer a.outboundPump.stop()
				done := make(chan error, 1)
				go func() {
					a.mu.Lock()
					defer a.mu.Unlock()
					done <- a.outboundControlLocked(func() error {
						if stage == "signaling" {
							return a.negotiateDirectConnectionsLocked(time.Now())
						}
						return a.maintainTransportQualityLocked(time.Now())
					})
				}()
				defer func() {
					unblock()
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Error("control wait did not finish")
					}
				}()
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("control wait did not start")
				}
				burstStarted := time.Now()
				adapter.mu.Lock()
				adapter.outbound = packets
				adapter.mu.Unlock()
				for sequence := range 64 {
					if err := transport.SendPacket("remote", "local", forwardingIPv4Packet("10.0.0.3", "10.0.0.2", sequence)); err != nil {
						t.Fatal(err)
					}
				}
				var sent []transportInboundPacket
				deadline := time.Now().Add(400 * time.Millisecond)
				for (len(sent) < 64 || inboundWritten(adapter) < 64) && time.Now().Before(deadline) {
					sent = append(sent, transport.DrainInbound("remote", 256)...)
					time.Sleep(time.Millisecond)
				}
				if len(sent) != 64 || inboundWritten(adapter) != 64 {
					t.Fatalf("%s wait: sent=%d received=%d, want 64 each", stage, len(sent), inboundWritten(adapter))
				}
				t.Logf("64 packets each direction during %s wait: %s (includes 1 ms observation polling)", stage, time.Since(burstStarted))
				for index, packet := range sent {
					if !bytes.Equal(packet.Payload, packets[index].Data) {
						t.Fatal("control wait changed packet order/content")
					}
				}
				if snapshot := a.forwardingRoutes.Load(); snapshot == nil || !snapshot.expires.Equal(originalDeadline) {
					t.Fatal("control wait extended the policy lease")
				}
				if delay := time.Until(originalDeadline); delay > 0 {
					time.Sleep(delay + 10*time.Millisecond)
				}
				adapter.mu.Lock()
				adapter.outbound = append(adapter.outbound, virtualadapter.Packet{Data: forwardingIPv4Packet("10.0.0.2", "10.0.0.3", 64)})
				adapter.mu.Unlock()
				if err := transport.SendPacket("remote", "local", forwardingIPv4Packet("10.0.0.3", "10.0.0.2", 64)); err != nil {
					t.Fatal(err)
				}
				time.Sleep(30 * time.Millisecond)
				if _, pending := adapter.pending(); pending != 1 || len(transport.DrainInbound("remote", 256)) != 0 || inboundWritten(adapter) != 64 {
					t.Fatal("control wait forwarded after original lease expiry")
				}
				a.outboundPump.stop()
				a.inboundPump.stop()
				unblock()
				err := <-done
				done <- err // Leave the result for deferred cleanup.
				if (stage == "signaling") != (err != nil) {
					t.Fatalf("unexpected control result: %v", err)
				}
				a.mergeInboundReportsLocked()
				a.mergeOutboundReportsLocked(false)
				want := 128
				if stage == "quality" {
					want++ // Successful keepalive Exchange.
				}
				if got := a.directAttempts[key].TransportPacketCount; got != want {
					t.Fatalf("control wait counters=%d want=%d", got, want)
				}
			})
		}
	}
}

func TestOutboundControlHoldsSessionReplacement(t *testing.T) {
	for _, mode := range []string{"DIRECT", "RELAY"} {
		t.Run(mode, func(t *testing.T) {
			server := outboundPolicyServer(t)
			a, adapter, transport := newForwardingAgent(t, mode, server.URL)
			packets := adapter.outbound
			adapter.outbound = nil
			a.runtime = DefaultRuntimeConfig()
			oldID, remoteAddress := forwardingSession(t, a, mode)
			key := connectionKey("network", "local", "remote")
			attempt := a.directAttempts[key]
			attempt.TransportSessionID, attempt.TransportStartedAt = oldID, time.Now()
			a.directAttempts[key] = attempt
			a.applyAttemptStateToConnection(&a.connections[0], attempt)
			if _, err := a.forwardingNetworksLocked(); err != nil {
				t.Fatal(err)
			}
			a.refreshForwardingRoutesLocked()
			a.startOutboundPacketPump()
			defer a.outboundPump.stop()
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			done := make(chan error, 1)
			go func() {
				a.mu.Lock()
				defer a.mu.Unlock()
				done <- a.outboundControlLocked(func() error {
					close(entered)
					<-release
					a.dropTransportSessionLocked("local", "remote", mode)
					var newID string
					if mode == "DIRECT" {
						session, err := a.directManager.Establish("local", "remote", []string{remoteAddress}, time.Second)
						if err != nil {
							return err
						}
						newID = session.SessionID
					} else {
						session, err := a.relayManager.Establish("local", "remote", time.Second)
						if err != nil {
							return err
						}
						newID = session.SessionID
					}
					attempt.TransportSessionID, attempt.TransportStartedAt = newID, time.Now()
					a.directAttempts[key] = attempt
					a.applyAttemptStateToConnection(&a.connections[0], attempt)
					return nil
				})
			}()
			var finishOnce sync.Once
			finish := func() {
				unblock()
				finishOnce.Do(func() {
					select {
					case err := <-done:
						if err != nil {
							t.Errorf("session replacement: %v", err)
						}
					case <-time.After(2 * time.Second):
						t.Error("session replacement did not finish")
					}
				})
			}
			defer finish()
			<-entered
			adapter.mu.Lock()
			adapter.outbound = packets
			adapter.mu.Unlock()
			time.Sleep(30 * time.Millisecond)
			if got := transport.DrainInbound("remote", 256); len(got) != 0 {
				t.Fatal("pump sent while session replacement held the barrier")
			}
			finish()
			var received []transportInboundPacket
			deadline := time.Now().Add(time.Second)
			for len(received) < 64 && time.Now().Before(deadline) {
				received = append(received, transport.DrainInbound("remote", 256)...)
				time.Sleep(time.Millisecond)
			}
			a.outboundPump.stop()
			a.mergeOutboundReportsLocked(false)
			if len(received) != 64 || a.directAttempts[key].TransportPacketCount != 64 || a.directAttempts[key].TransportSessionID == oldID {
				t.Fatalf("replacement: delivered=%d counter=%d changedSession=%v", len(received), a.directAttempts[key].TransportPacketCount, a.directAttempts[key].TransportSessionID != oldID)
			}
			for index, packet := range received {
				if !bytes.Equal(packet.Payload, packets[index].Data) {
					t.Fatal("replacement lost/duplicated adapter batch")
				}
			}
		})
	}
}
