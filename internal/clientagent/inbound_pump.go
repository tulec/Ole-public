package clientagent

import (
	"Ole/internal/virtualadapter"
	"context"
	"sync"
	"sync/atomic"
	"time"
)

const inboundPumpBatch = 32
const inboundPumpReports = 128

type inboundTarget struct {
	peer  ManagedPeerState
	local string
	relay bool
}

type inboundReportKey struct {
	server, user, network, local, remote, session, blockedKind, policy string
}

type inboundReport struct {
	key         inboundReportKey
	count       int
	at          time.Time
	writeFailed bool
}

type inboundPacketPump struct {
	cancel  context.CancelFunc
	done    chan struct{}
	once    sync.Once
	reports chan inboundReport // One producer; no packet payloads retained here.
	pause   *atomic.Pointer[recoveryPause]
}

func (p *inboundPacketPump) stop() {
	if p == nil {
		return
	}
	p.once.Do(p.cancel)
	<-p.done
}

func (a *Agent) startInboundPacketPump() {
	io, ok := a.adapterManager.(virtualadapter.PacketIO)
	if !ok || io == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &inboundPacketPump{cancel: cancel, done: make(chan struct{}), reports: make(chan inboundReport, inboundPumpReports), pause: &a.recoveryPaused}
	a.inboundPump = p // Initialized once, before starting the lifecycle goroutine.
	go func() {
		defer close(p.done)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		cursor := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				snapshot := a.forwardingRoutes.Load()
				if !snapshot.active() || len(snapshot.inboundTargets) == 0 {
					continue
				}
				// At most one report per drained packet plus a write error. Pause
				// draining when telemetry is full rather than losing rekey counts.
				limit := cap(p.reports) - len(p.reports) - 1
				if limit <= 0 {
					continue
				}
				if limit > inboundPumpBatch {
					limit = inboundPumpBatch
				}
				target := snapshot.inboundTargets[cursor%len(snapshot.inboundTargets)]
				cursor++
				var transport transportManagerForPackets
				if target.relay && a.relayManager != nil {
					transport = relayPacketAdapter{a.relayManager}
				}
				if !target.relay && a.directManager != nil {
					transport = directPacketAdapter{a.directManager}
				}
				if transport == nil {
					continue
				}
				packets := transport.DrainInbound(target.local, limit)
				p.deliver(ctx, snapshot, target, packets, io)
			}
		}
	}()
}

func (p *inboundPacketPump) deliver(ctx context.Context, snapshot *forwardingRoutes, target inboundTarget, packets []transportInboundPacket, io virtualadapter.PacketIO) {
	if len(packets) == 0 || !snapshot.active() || ctx.Err() != nil {
		return
	}
	now := time.Now()
	accepted := make([]virtualadapter.Packet, 0, len(packets))
	counts := make(map[inboundReportKey]int)
	blocked := make(map[inboundReportKey]int)
	for _, packet := range packets {
		if p.pause != nil && p.pause.Load().blocks(target.peer.NetworkID, target.local, packet.RemotePeerID) {
			continue // Never accept a new session under the uncommitted old metadata.
		}
		// Packet transport is IPv4; malformed/oversized records must not reach
		// Wintun even if the transport peer is authenticated.
		if len(packet.Payload) > 1500 {
			continue
		}
		_, destination, err := ipv4PacketEndpoints(packet.Payload)
		if err != nil {
			continue
		}
		ok, connection, groupBlocked := snapshot.view.evaluateInboundTransportPacketViaLocalPeerLocked(target.peer, snapshot.managed, snapshot.networks[target.peer.NetworkID], snapshot.primary, target.local, packet.RemotePeerID, packet.Payload)
		key := inboundReportKey{server: snapshot.view.remote.BaseURL(), user: snapshot.view.currentUser.ID, network: target.peer.NetworkID, local: target.local, remote: packet.RemotePeerID}
		if groupBlocked {
			key.blockedKind = groupTrafficKind(target.peer.OverlayCIDR, destination)
			key.policy = networkGroupTrafficPolicyOrDefault(snapshot.networks[target.peer.NetworkID])
			blocked[key]++
		}
		if !ok || connection == nil || !connection.TransportReady {
			continue
		}
		key.local, key.remote, key.session = connection.LocalPeerID, connection.RemotePeerID, connection.TransportSessionID
		counts[key]++
		accepted = append(accepted, virtualadapter.Packet{Data: packet.Payload})
	}
	if !snapshot.active() || ctx.Err() != nil {
		return
	}
	for key, count := range blocked {
		p.reports <- inboundReport{key: key, count: count, at: now}
	}
	if len(accepted) == 0 {
		return
	}
	if err := io.WritePackets(accepted); err != nil {
		p.reports <- inboundReport{key: inboundReportKey{server: snapshot.view.remote.BaseURL(), user: snapshot.view.currentUser.ID}, at: now, writeFailed: true}
		return
	}
	for key, count := range counts {
		p.reports <- inboundReport{key: key, count: count, at: now}
	}
}

// Called only with Agent.mu. No transport/storage/network calls here.
func (a *Agent) mergeInboundReportsLocked() {
	p := a.inboundPump
	if p == nil {
		return
	}
	for range inboundPumpReports {
		var report inboundReport
		select {
		case report = <-p.reports:
		default:
			return
		}
		key := report.key
		if a.currentUser == nil || key.server != a.remote.BaseURL() || key.user != a.currentUser.ID {
			continue
		}
		if report.writeFailed {
			a.lastLifecycleError = "inbound adapter write failed"
			a.logErrorf("inbound adapter write failed")
			continue
		}
		if key.blockedKind != "" {
			for range report.count {
				a.recordBlockedGroupTrafficLocked(key.network, key.policy, key.blockedKind, report.at)
			}
			continue
		}
		connection := a.connectionByPeersLocked(key.network, key.local, key.remote)
		attemptKey := connectionKey(key.network, key.local, key.remote)
		attempt, exists := a.directAttempts[attemptKey]
		if connection == nil || connection.TransportSessionID != key.session || !exists || attempt.TransportSessionID != key.session {
			continue
		}
		a.bumpTransportPacketCountLocked(key.network, key.local, key.remote, report.count, report.at)
		a.applyAttemptStateToConnection(connection, a.directAttempts[attemptKey])
	}
}
