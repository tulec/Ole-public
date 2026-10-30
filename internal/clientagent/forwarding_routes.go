package clientagent

import (
	"Ole/internal/controlclient"
	"crypto/sha256"
	"sync/atomic"
	"time"
)

// routingView owns every mutable field used by the existing routing helpers.
// It contains neither transport/adapter managers nor device/session secrets.
// Once published it is read-only; results never expose its backing storage.
type forwardingRoutes struct {
	view           Agent
	managed        []ManagedPeerState
	networks       map[string]controlclient.Network
	primary        string
	expires        time.Time
	valid          atomic.Bool
	inboundTargets []inboundTarget
	scope          [32]byte
}

func (a *Agent) forwardingScopeLocked() [32]byte {
	if a.currentUser == nil || a.currentSession == nil {
		return [32]byte{}
	}
	return sha256.Sum256([]byte(a.remote.BaseURL() + "\x00" + a.currentUser.ID + "\x00" + a.currentSession.AccessToken))
}

func (s *forwardingRoutes) active() bool {
	return s != nil && s.valid.Load() && time.Now().Before(s.expires)
}

func cloneRoutingConnection(connection ConnectionStatus) ConnectionStatus {
	connection.RemoteCandidates = append([]string(nil), connection.RemoteCandidates...)
	return connection
}

func (a *Agent) invalidateForwardingRoutesLocked() {
	if previous := a.forwardingRoutes.Swap(nil); previous != nil {
		previous.valid.Store(false)
	}
}

func (a *Agent) refreshForwardingRoutesLocked() {
	if a.forwardingPolicy == nil {
		a.invalidateForwardingRoutesLocked()
		return
	}
	a.publishForwardingRoutesLocked(a.forwardingPolicy.networks)
}

// Called under Agent.mu. Construction performs no network or storage I/O.
func (a *Agent) publishForwardingRoutesLocked(networks map[string]controlclient.Network) *forwardingRoutes {
	a.invalidateForwardingRoutesLocked()
	if a.packetPumpsClosed.Load() || a.forwardingPolicy == nil || a.currentUser == nil || a.deviceState == nil || a.currentSession == nil ||
		a.forwardingPolicy.server != a.remote.BaseURL() || a.forwardingPolicy.user != a.currentUser.ID || a.forwardingPolicy.token != a.currentSession.AccessToken {
		return nil
	}
	deadline := a.forwardingPolicyDeadlineLocked(a.forwardingPolicy.expires)
	if !time.Now().Before(deadline) {
		return nil
	}
	snapshot := &forwardingRoutes{expires: deadline, networks: cloneForwardingNetworks(networks)}
	snapshot.scope = a.forwardingScopeLocked()
	view := &snapshot.view
	view.runtime.TransportRekeyAfter = a.runtime.TransportRekeyAfter
	view.runtime.TransportSessionTTL = a.runtime.TransportSessionTTL
	view.remote = controlclient.New(a.remote.BaseURL())
	view.currentUser = cloneUser(a.currentUser)
	view.deviceState = &PersistentState{ManagedPeers: append([]ManagedPeerState(nil), a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)...)}
	view.connections = make([]ConnectionStatus, len(a.connections))
	for index, connection := range a.connections {
		view.connections[index] = cloneRoutingConnection(connection)
	}
	view.discoveredPeers = make(map[string][]controlclient.Peer, len(a.discoveredPeers))
	for network, peers := range a.discoveredPeers {
		copied := append([]controlclient.Peer(nil), peers...)
		view.discoveredPeers[network] = copied
	}
	view.gatewaySelections = make(map[string]gatewaySelectionState, len(a.gatewaySelections))
	for key, selection := range a.gatewaySelections {
		view.gatewaySelections[key] = selection
	}
	view.directAttempts = make(map[string]DirectAttemptState, len(a.directAttempts))
	for key, attempt := range a.directAttempts {
		view.directAttempts[key] = attempt
	}
	for _, peer := range view.dedupeManagedPeersForRuntime(view.deviceState.ManagedPeersFor(view.remote.BaseURL(), view.currentUser.ID)) {
		if _, present := snapshot.networks[peer.NetworkID]; present {
			snapshot.managed = append(snapshot.managed, peer)
		}
	}
	snapshot.primary = view.primaryFullTunnelClientNetworkLocked(snapshot.managed, snapshot.networks)
	for _, peer := range snapshot.managed {
		for _, local := range view.routingLocalPeerIDsForManagedPeerLocked(peer) {
			snapshot.inboundTargets = append(snapshot.inboundTargets, inboundTarget{peer: peer, local: local}, inboundTarget{peer: peer, local: local, relay: true})
		}
	}
	snapshot.valid.Store(true)
	a.forwardingRoutes.Store(snapshot)
	return snapshot
}

// Safe without Agent.mu, including while the control plane is blocked in HTTP.
// It selects routes only: sending and recovery remain owned by the caller.
func (s *forwardingRoutes) routes(sourceIP, destinationIP string) []ConnectionStatus {
	if s == nil || !s.valid.Load() || !time.Now().Before(s.expires) {
		return nil
	}
	selected := s.view.connectionsForPacketLocked(s.managed, s.networks, s.primary, sourceIP, destinationIP)
	result := make([]ConnectionStatus, 0, len(selected))
	for _, connection := range selected {
		if connection != nil && connection.TransportReady {
			result = append(result, cloneRoutingConnection(*connection))
		}
	}
	if !s.valid.Load() || !time.Now().Before(s.expires) {
		return nil
	}
	return result
}
