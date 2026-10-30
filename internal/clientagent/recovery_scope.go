package clientagent

import (
	"fmt"
	"time"
)

// One owner recovery at a time. Pauses both transports for this actual peer pair;
// it contains no credentials and never extends the failed packet's original lease.
type recoveryPause struct {
	network, local, remote string
	scope                  [32]byte
	expires                time.Time
}

func (p *recoveryPause) blocks(_ string, local, remote string) bool {
	// The managers key sessions by actual peer IDs. A stale network alias must
	// not bypass the pause for the same underlying transport session.
	return p != nil && p.local == local && p.remote == remote
}

func (p *recoveryPause) blocksRoute(route ConnectionStatus) bool {
	return p.blocks(route.NetworkID, route.LocalPeerID, route.RemotePeerID)
}

// Called inside outboundControlLocked. Keep the immutable old snapshot for other
// peers; publish committed state before making this pair eligible again.
func (a *Agent) withRecoveryPauseLocked(report outboundReport, operation func() error) error {
	pause := &recoveryPause{network: report.route.NetworkID, local: report.route.LocalPeerID, remote: report.route.RemotePeerID, scope: report.scope, expires: report.expires}
	previous := a.recoveryPaused.Swap(pause)
	defer func() {
		a.refreshForwardingRoutesLocked()
		a.recoveryPaused.Store(previous)
	}()
	return operation()
}

// Only peer-local DIRECT probe/handshake I/O may use this. Rebinding listeners,
// switching relay servers and HTTP reconciliation still need the global barrier.
// No intermediate attempt/connection state is published while I/O runs.
func (a *Agent) recoveryDirectIOLocked(connection *ConnectionStatus, operation func() error) error {
	p := a.outboundPump
	if p == nil || !p.controlHeld || connection == nil || !a.recoveryPaused.Load().blocksRoute(*connection) {
		return operation()
	}
	p.ioMu.Unlock()
	defer p.ioMu.Lock()
	return operation()
}

// Called for every owner send/retry, including after a slow handshake. Normal
// legacy sends have no active recovery scope and retain their existing behavior.
func (a *Agent) sendPacketOnCurrentSessionLocked(connection *ConnectionStatus, manager transportManagerForPackets, payload []byte) error {
	if pause := a.recoveryPaused.Load(); pause.blocksRoute(*connection) {
		policy := a.forwardingPolicy
		if policy == nil || pause.scope != a.forwardingScopeLocked() || !time.Now().Before(pause.expires) ||
			!time.Now().Before(a.forwardingPolicyDeadlineLocked(policy.expires)) || policy.server != a.remote.BaseURL() ||
			a.currentUser == nil || a.currentSession == nil || policy.user != a.currentUser.ID || policy.token != a.currentSession.AccessToken {
			return fmt.Errorf("forwarding authorization expired or changed during recovery")
		}
		source, destination, err := ipv4PacketEndpoints(payload)
		if err != nil {
			return err
		}
		managed := a.dedupeManagedPeersForRuntime(a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID))
		primary := a.primaryFullTunnelClientNetworkLocked(managed, policy.networks)
		allowed := false
		for _, route := range a.connectionsForPacketLocked(managed, policy.networks, primary, source, destination) {
			if route != nil && route.TransportReady && sameOutboundTarget(*route, *connection) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("forwarding route changed during recovery")
		}
	}
	return manager.SendPacket(connection.LocalPeerID, connection.RemotePeerID, payload)
}
