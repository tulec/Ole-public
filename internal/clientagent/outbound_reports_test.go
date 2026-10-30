package clientagent

import (
	"Ole/internal/virtualadapter"
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestOutboundReportsPreserveLatestGroupActivity(t *testing.T) {
	for _, blockedIsLatest := range []bool{false, true} {
		t.Run(fmt.Sprint(blockedIsLatest), func(t *testing.T) {
			server := outboundPolicyServer(t)
			a, _, _ := newForwardingAgent(t, "DIRECT", server.URL)
			p := &outboundPacketPump{reports: make(chan outboundReport, outboundPumpReports)}
			a.outboundPump = p
			blockedAt, successAt := time.Now(), time.Now().Add(2*time.Second)
			if blockedIsLatest {
				blockedAt, successAt = successAt, blockedAt
			}
			p.reports <- outboundReport{server: server.URL, user: "user", route: a.connections[0], blocked: true, policy: "BLOCKED", kind: "broadcast", at: blockedAt}
			p.recordSuccess(outboundReport{server: server.URL, user: "user", route: a.connections[0], policy: "FLOOD", kind: "multicast", first: true, at: successAt})
			a.mergeOutboundReportsLocked(false)
			diag := a.groupTrafficDiagnostics["network"]
			latest, action := successAt, "FLOOD"
			if blockedIsLatest {
				latest, action = blockedAt, "BLOCKED"
			}
			policy := "FLOOD"
			if blockedIsLatest {
				policy = "BLOCKED"
			}
			if diag.LastPacketUnix != latest.Unix() || diag.LastAction != action || diag.Policy != policy || diag.BlockedPacketCount != 1 || diag.FloodPacketCount != 1 || diag.FanoutCopyCount != 1 || diag.BroadcastPacketCount != 1 || diag.MulticastPacketCount != 1 {
				t.Fatalf("out-of-order reports regressed activity or lost counters: %+v", diag)
			}
		})
	}
}

func TestOutboundReportsConcurrentMergeAndRekeyLimit(t *testing.T) {
	for _, mode := range []string{"DIRECT", "RELAY"} {
		for _, scenario := range []string{"concurrent-merge", "rekey-limit"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				server := outboundPolicyServer(t)
				a, adapter, transport := newForwardingAgent(t, mode, server.URL)
				adapter.outbound = nil
				for sequence := range 1024 {
					adapter.outbound = append(adapter.outbound, virtualadapter.Packet{Data: forwardingIPv4Packet("10.0.0.2", "10.0.0.3", sequence)})
				}
				a.runtime = DefaultRuntimeConfig()
				sessionID, _ := forwardingSession(t, a, mode)
				key := connectionKey("network", "local", "remote")
				attempt := a.directAttempts[key]
				attempt.TransportSessionID, attempt.TransportStartedAt = sessionID, time.Now()
				a.directAttempts[key] = attempt
				a.applyAttemptStateToConnection(&a.connections[0], attempt)
				want := 1024
				if scenario == "rekey-limit" {
					want = 267 // Not a batch/report boundary.
					a.runtime.TransportRekeyAfter = want
				}
				if _, err := a.forwardingNetworksLocked(); err != nil {
					t.Fatal(err)
				}
				a.refreshForwardingRoutesLocked()
				a.startOutboundPacketPump()
				defer a.outboundPump.stop()
				var received []transportInboundPacket
				deadline := time.Now().Add(time.Second)
				for len(received) < want && time.Now().Before(deadline) {
					received = append(received, transport.DrainInbound("remote", 256)...)
					if scenario == "concurrent-merge" {
						a.mu.Lock()
						a.mergeOutboundReportsLocked(false)
						a.refreshForwardingRoutesLocked()
						a.mu.Unlock()
					}
					time.Sleep(time.Millisecond)
				}
				if scenario == "rekey-limit" {
					time.Sleep(30 * time.Millisecond)
					received = append(received, transport.DrainInbound("remote", 256)...)
				}
				a.outboundPump.stop()
				if scenario == "rekey-limit" && a.outboundPump.successSlots.Load() != 1 {
					t.Fatal("unmerged successes were not aggregated by session")
				}
				for _, report := range a.outboundPump.successes {
					if report.payload != nil || report.group != nil || len(report.route.RemoteCandidates) != 0 || report.scope != [32]byte{} {
						t.Fatal("success metadata retained payload, group tracker, candidates or token scope")
					}
				}
				a.mergeOutboundReportsLocked(false)
				if len(received) != want || a.directAttempts[key].TransportPacketCount != want {
					t.Fatalf("packets=%d counter=%d want=%d", len(received), a.directAttempts[key].TransportPacketCount, want)
				}
				if a.outboundPump.reportLoad() != 0 || len(a.outboundPump.successes) != 0 {
					t.Fatal("merge/stop retained report capacity")
				}
				for index, packet := range received {
					if !bytes.Equal(packet.Payload, forwardingIPv4Packet("10.0.0.2", "10.0.0.3", index)) {
						t.Fatal("merge/rekey lost or duplicated packets")
					}
				}
			})
		}
	}
}
