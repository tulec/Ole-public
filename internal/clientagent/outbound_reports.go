package clientagent

// Successful traffic keeps only counters, never packet payloads, candidates or
// group trackers. Token rotation may merge successes from the same wire session;
// failed packets still retain their original token scope and deadline.
type outboundSuccessKey struct {
	server, user, network, local, remote, session, mode, kind, policy string
}

// One producer. The caller checks for a free shared slot before each send, so a
// failure always has room even when a success could reuse an existing entry.
func (p *outboundPacketPump) recordSuccess(report outboundReport) {
	key := outboundSuccessKey{
		server: report.server, user: report.user, network: report.route.NetworkID,
		local: report.route.LocalPeerID, remote: report.route.RemotePeerID,
		session: report.route.TransportSessionID, mode: report.route.TransportMode,
		kind: report.kind, policy: report.policy,
	}
	p.successMu.Lock()
	defer p.successMu.Unlock()
	if p.successes == nil {
		p.successes = make(map[outboundSuccessKey]outboundReport)
	}
	previous, exists := p.successes[key]
	if !exists {
		p.successSlots.Add(1)
		previous = outboundReport{
			server: report.server, user: report.user, kind: report.kind, policy: report.policy,
			route: ConnectionStatus{NetworkID: key.network, LocalPeerID: key.local, RemotePeerID: key.remote, TransportSessionID: key.session, TransportMode: key.mode},
		}
	}
	previous.count++
	if report.first {
		previous.floods++
	}
	if report.at.After(previous.at) {
		previous.at = report.at
	}
	p.successes[key] = previous
}

func (p *outboundPacketPump) reportLoad() int {
	// Read producer storage before held slots: both channel/map transfers reserve
	// held slots first, then remove producer storage. The opposite order could
	// undercount a concurrent transfer and admit more than the shared budget.
	return len(p.reports) + int(p.successSlots.Load()) + int(p.heldReports.Load())
}

// Called under Agent.mu. Moving a detached map into the owner reserves its slots
// before freeing the producer's map, just like the channel-to-recovery handoff.
// No Agent/transport/network calls run while successMu is held.
func (p *outboundPacketPump) takeSuccessReports() map[outboundSuccessKey]outboundReport {
	p.successMu.Lock()
	defer p.successMu.Unlock()
	if len(p.successes) == 0 {
		return nil
	}
	reports := p.successes
	p.heldReports.Add(int32(len(reports)))
	p.successes = nil
	p.successSlots.Add(-int32(len(reports)))
	return reports
}
