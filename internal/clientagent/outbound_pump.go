package clientagent

import (
	"Ole/internal/virtualadapter"
	"context"
	"sync"
	"sync/atomic"
	"time"
)

const outboundPumpBatch = 32
const outboundPumpReports = 128

type outboundGroup struct{ reported atomic.Bool }

type outboundReport struct {
	server, user                  string
	scope                         [32]byte
	route                         ConnectionStatus
	at, expires                   time.Time
	payload                       []byte // Only failed sends retain data, at most 1500 bytes.
	group                         *outboundGroup
	kind, policy                  string
	first, blocked, adapterFailed bool
	count, floods                 int // Aggregated successes; zero count means one legacy/retry event.
}

type outboundWork struct {
	data                []byte
	scope               [32]byte
	expires             time.Time
	source, destination string
	routes              []ConnectionStatus
	next                int
	group               *outboundGroup
	revision            *forwardingRoutes
	kind, policy        string
}

type outboundPacketPump struct {
	cancel       context.CancelFunc
	done         chan struct{}
	once         sync.Once
	closed       atomic.Bool
	ioMu         sync.Mutex // Control-plane session replacement vs one packet send.
	controlHeld  bool       // Agent.mu only; allows yielding during non-mutating I/O.
	reports      chan outboundReport
	heldReports  atomic.Int32
	recoveries   []outboundReport // Agent.mu only; shares the 128-slot budget.
	successMu    sync.Mutex
	successes    map[outboundSuccessKey]outboundReport
	successSlots atomic.Int32
}

func (p *outboundPacketPump) stop() {
	if p == nil {
		return
	}
	p.once.Do(func() { p.closed.Store(true); p.cancel() })
	<-p.done
}

func sameOutboundTarget(left, right ConnectionStatus) bool {
	return left.NetworkID == right.NetworkID && left.LocalPeerID == right.LocalPeerID && left.RemotePeerID == right.RemotePeerID
}

func (a *Agent) startOutboundPacketPump() {
	io, ok := a.adapterManager.(virtualadapter.PacketIO)
	if !ok || io == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &outboundPacketPump{cancel: cancel, done: make(chan struct{}), reports: make(chan outboundReport, outboundPumpReports)}
	a.outboundPump = p
	go func() {
		defer close(p.done)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		var pending []outboundWork // At most 32 adapter packets (48,000 payload bytes).
		var readRetryAt time.Time
		// Per-session budgets, bounded by the current routing table, not traffic.
		absolute := make(map[string]int)
		var budgetRevision *forwardingRoutes
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				snapshot := a.forwardingRoutes.Load()
				if !snapshot.active() {
					// Publication/session recovery may temporarily remove routing.
					// Retain the bounded adapter batch until its original lease ends.
					for index := 0; index < len(pending); {
						if !time.Now().Before(pending[index].expires) {
							pending = removeOutboundWork(pending, index)
						} else {
							index++
						}
					}
					continue
				}
				if snapshot != budgetRevision {
					live := make(map[string]int)
					for _, route := range snapshot.view.connections {
						key := connectionKey(route.NetworkID, route.LocalPeerID, route.RemotePeerID) + "|" + route.TransportSessionID
						live[key] = max(absolute[key], route.TransportPacketCount)
					}
					absolute, budgetRevision = live, snapshot
				}
				free := cap(p.reports) - p.reportLoad()
				if free <= 0 {
					continue
				}
				if len(pending) < outboundPumpBatch && !time.Now().Before(readRetryAt) {
					packets, err := io.ReadPackets(min(outboundPumpBatch-len(pending), free))
					if err != nil {
						readRetryAt = time.Now().Add(time.Second)
						p.reports <- outboundReport{server: snapshot.view.remote.BaseURL(), user: snapshot.view.currentUser.ID, scope: snapshot.scope, adapterFailed: true, at: time.Now()}
					}
					for _, packet := range packets {
						if len(packet.Data) > 1500 {
							continue
						}
						source, destination, err := ipv4PacketEndpoints(packet.Data)
						if err != nil {
							continue
						}
						pending = append(pending, outboundWork{data: append([]byte(nil), packet.Data...), scope: snapshot.scope, expires: snapshot.expires, source: source, destination: destination, group: &outboundGroup{}})
					}
				}
				for sent, index := 0, 0; sent < outboundPumpBatch && index < len(pending) && p.reportLoad() < cap(p.reports); {
					work := &pending[index]
					if ctx.Err() != nil {
						return
					}
					if !snapshot.active() {
						break
					}
					if snapshot.scope != work.scope || !time.Now().Before(work.expires) {
						pending = removeOutboundWork(pending, index)
						continue
					}
					if work.revision != snapshot {
						fresh := snapshot.routes(work.source, work.destination)
						if !snapshot.active() {
							break // Invalidation during selection is not an empty route decision.
						}
						if work.revision == nil {
							work.routes = fresh
							peer := managedPeerForSourceIP(snapshot.managed, work.source)
							work.kind = groupTrafficKind(peer.OverlayCIDR, work.destination)
							work.policy = networkGroupTrafficPolicyOrDefault(snapshot.networks[peer.NetworkID])
							if len(fresh) == 0 && peer.PeerID != "" && work.kind != "" && work.policy == "BLOCKED" {
								p.reports <- outboundReport{server: snapshot.view.remote.BaseURL(), user: snapshot.view.currentUser.ID, scope: work.scope, route: ConnectionStatus{NetworkID: peer.NetworkID}, at: time.Now(), kind: work.kind, policy: work.policy, blocked: true}
							}
						} else {
							// Do not resend completed fanout copies after publication.
							for index := work.next; index < len(work.routes); index++ {
								old := work.routes[index]
								work.routes[index].TransportReady = false
								for _, current := range fresh {
									if sameOutboundTarget(old, current) {
										work.routes[index] = current
										break
									}
								}
							}
						}
						work.revision = snapshot
					}
					if work.next == len(work.routes) {
						pending = removeOutboundWork(pending, index)
						continue
					}
					routeIndex := work.next
					for routeIndex < len(work.routes) && a.recoveryPaused.Load().blocksRoute(work.routes[routeIndex]) {
						routeIndex++
					}
					if routeIndex == len(work.routes) {
						index++ // Retain this work in FIFO order, service other peers.
						continue
					}
					work.routes[work.next], work.routes[routeIndex] = work.routes[routeIndex], work.routes[work.next]
					route := work.routes[work.next]
					if !route.TransportReady {
						work.next++
						continue
					}
					key := connectionKey(route.NetworkID, route.LocalPeerID, route.RemotePeerID) + "|" + route.TransportSessionID
					if snapshot.view.runtime.TransportRekeyAfter > 0 && absolute[key] >= snapshot.view.runtime.TransportRekeyAfter {
						index++
						continue
					}
					attempt := snapshot.view.directAttempts[connectionKey(route.NetworkID, route.LocalPeerID, route.RemotePeerID)]
					if snapshot.view.runtime.TransportSessionTTL > 0 && !attempt.TransportStartedAt.IsZero() && !time.Now().Before(attempt.TransportStartedAt.Add(snapshot.view.runtime.TransportSessionTTL)) {
						index++
						continue
					}
					if !p.ioMu.TryLock() {
						break
					}
					if !snapshot.active() || ctx.Err() != nil {
						p.ioMu.Unlock()
						break
					}
					if a.recoveryPaused.Load().blocksRoute(route) {
						p.ioMu.Unlock()
						continue
					}
					manager := a.transportManagerForConnectionLocked(route) // Only immutable manager references are read.
					if manager == nil {
						p.ioMu.Unlock()
						work.next++
						continue
					}
					err := manager.SendPacket(route.LocalPeerID, route.RemotePeerID, work.data)
					p.ioMu.Unlock()
					report := outboundReport{server: snapshot.view.remote.BaseURL(), user: snapshot.view.currentUser.ID, scope: work.scope, route: route, at: time.Now(), expires: work.expires, group: work.group, kind: work.kind, policy: work.policy}
					if err != nil {
						report.payload = work.data
						p.reports <- report
					} else {
						absolute[key]++
						report.first = work.kind != "" && work.group.reported.CompareAndSwap(false, true)
						p.recordSuccess(report)
					}
					work.next++
					sent++
					if work.next == len(work.routes) {
						pending = removeOutboundWork(pending, index)
					}
				}
			}
		}
	}()
}

func removeOutboundWork(pending []outboundWork, index int) []outboundWork {
	copy(pending[index:], pending[index+1:])
	pending[len(pending)-1] = outboundWork{}
	return pending[:len(pending)-1]
}

// Session-mutating control-plane operations may wait; the pump never waits on
// this mutex and never runs the operation itself.
func (a *Agent) outboundControlLocked(operation func() error) error {
	p := a.outboundPump
	if p == nil || p.controlHeld {
		return operation()
	}
	p.ioMu.Lock()
	defer p.ioMu.Unlock()
	p.controlHeld = true
	defer func() { p.controlHeld = false }()
	defer a.refreshForwardingRoutesLocked()
	return operation()
}

// Only for I/O that cannot replace/drop sessions or publish/invalidate routes.
// Owner-only input caches may change: Agent.mu stays held, workers use detached
// snapshots. Publish completed state before letting the worker send again;
// reacquire the barrier before the caller applies the result or mutates sessions.
func (a *Agent) outboundControlIOLocked(operation func() error) error {
	p := a.outboundPump
	if p == nil || !p.controlHeld {
		return operation()
	}
	a.mergeInboundReportsLocked()
	a.mergeOutboundReportsLocked(false)
	a.refreshForwardingRoutesLocked()
	p.ioMu.Unlock()
	defer p.ioMu.Lock()
	return operation()
}

func (a *Agent) mergeOutboundReportsLocked(recoverPackets bool) {
	p := a.outboundPump
	if p == nil {
		return
	}
	for _, report := range p.takeSuccessReports() {
		a.applyOutboundReportLocked(report, false)
		p.heldReports.Add(-1)
	}
	recovered := 0
	for range outboundPumpReports {
		var report outboundReport
		if (recoverPackets || p.closed.Load()) && len(p.recoveries) > 0 {
			report = p.recoveries[0]
			p.recoveries[0] = outboundReport{}
			p.recoveries = p.recoveries[1:]
		} else {
			// Reserve before receive: moving an event to recovery must not
			// temporarily create extra capacity for the producer.
			p.heldReports.Add(1)
			select {
			case report = <-p.reports:
			default:
				p.heldReports.Add(-1)
				return
			}
		}
		if report.payload != nil && !recoverPackets && !p.closed.Load() && a.currentUser != nil && report.scope == a.forwardingScopeLocked() && time.Now().Before(report.expires) {
			p.recoveries = append(p.recoveries, report)
			continue
		}
		if a.applyOutboundReportLocked(report, recoverPackets) {
			recovered++
		}
		p.heldReports.Add(-1)
		if recovered >= 4 {
			return
		}
	}
}

// Returns whether this event attempted recovery. Status never executes it.
func (a *Agent) applyOutboundReportLocked(report outboundReport, recoverPackets bool) bool {
	p := a.outboundPump
	if a.currentUser == nil || report.server != a.remote.BaseURL() || report.user != a.currentUser.ID {
		return false
	}
	if report.adapterFailed {
		a.lastLifecycleError = "outbound adapter read failed"
		a.logErrorf("outbound adapter read failed")
		return false
	}
	if report.blocked {
		a.recordBlockedGroupTrafficLocked(report.route.NetworkID, report.policy, report.kind, report.at)
		return false
	}
	connection := a.connectionByPeersLocked(report.route.NetworkID, report.route.LocalPeerID, report.route.RemotePeerID)
	if connection == nil {
		return false
	}
	key := connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)
	if report.payload == nil {
		if connection.TransportSessionID == report.route.TransportSessionID {
			a.applyOutboundDeliveryLocked(report, connection)
		}
		return false
	}
	if !recoverPackets || p.closed.Load() || report.scope != a.forwardingScopeLocked() || !time.Now().Before(report.expires) {
		return false
	}
	snapshot := a.forwardingRoutes.Load()
	if !snapshot.active() || snapshot.scope != report.scope {
		return false
	}
	source, destination, err := ipv4PacketEndpoints(report.payload)
	if err != nil {
		return false
	}
	allowed := false
	for _, route := range snapshot.routes(source, destination) {
		if sameOutboundTarget(route, *connection) {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}
	attempt := a.directAttempts[key]
	_ = a.outboundControlLocked(func() error {
		return a.withRecoveryPauseLocked(report, func() error {
			sendErr := a.sendTransportPacketLocked(connection, &attempt, report.payload, time.Now())
			if sendErr != nil {
				attempt.LastError = sendErr.Error()
			} else {
				attempt.LastError = ""
			}
			a.directAttempts[key] = attempt
			a.applyAttemptStateToConnection(connection, attempt)
			if sendErr == nil {
				report.route = cloneRoutingConnection(*connection)
				report.at = time.Now()
				report.first = report.kind != "" && report.group.reported.CompareAndSwap(false, true)
				a.applyOutboundDeliveryLocked(report, connection)
			}
			return sendErr
		})
	})
	return true
}
func (a *Agent) applyOutboundDeliveryLocked(report outboundReport, connection *ConnectionStatus) {
	count, floods := max(1, report.count), report.floods
	if report.first {
		floods++
	}
	a.bumpTransportPacketCountLocked(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID, count, report.at)
	if report.kind != "" {
		key := connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)
		attempt := a.directAttempts[key]
		attempt.GroupTrafficPacketCopies += count
		if report.kind == "broadcast" {
			attempt.GroupBroadcastCopies += count
		} else if report.kind == "multicast" {
			attempt.GroupMulticastCopies += count
		}
		if report.at.After(attempt.LastGroupTrafficAt) {
			attempt.LastGroupTrafficAt = report.at
		}
		a.directAttempts[key] = attempt
		previousPolicy := a.groupTrafficDiagnostics[connection.NetworkID].Policy
		diag := a.ensureGroupTrafficDiagnosticsLocked(connection.NetworkID, report.policy)
		diag.FloodPacketCount += floods
		if report.kind == "broadcast" {
			diag.BroadcastPacketCount += floods
		} else if report.kind == "multicast" {
			diag.MulticastPacketCount += floods
		}
		diag.FanoutCopyCount += count
		if report.at.Unix() >= diag.LastPacketUnix {
			diag.LastPacketUnix = report.at.Unix()
			diag.LastAction = "FLOOD"
		} else {
			diag.Policy = previousPolicy
		}
		a.groupTrafficDiagnostics[connection.NetworkID] = diag
	}
	a.applyAttemptStateToConnection(connection, a.directAttempts[connectionKey(connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID)])
}
