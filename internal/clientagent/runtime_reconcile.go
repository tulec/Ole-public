package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/transportauth"
	"fmt"
	"strings"
	"time"
)

type runtimeReconcileInputs struct {
	networks    map[string]controlclient.Network
	credentials map[string]*transportauth.Credentials
}

// Only after negotiation has persisted every attempt/connection. Recovery calls
// reconcileManagedRuntimeLocked instead: its in-flight attempt may be uncommitted.
// Read inputs without changing managers or publishing intermediate authorization.
func (a *Agent) reconcileNegotiatedRuntimeLocked() error {
	if a.currentUser == nil || a.deviceState == nil {
		return a.reconcileManagedRuntimeLocked()
	}
	managed := a.dedupeManagedPeersForRuntime(a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID))
	inputs := &runtimeReconcileInputs{credentials: make(map[string]*transportauth.Credentials)}
	needsNetworks := a.adapterManager != nil || a.overlayDNS != nil && a.overlayDNS.Domain() != ""
	relayEnabled := a.relayManager != nil && a.currentSession != nil && a.currentSession.AccessToken != "" && a.resolveRelayServerAddressLocked() != ""
	_, directAuth := a.directManager.(credentialsUpdater)
	_, relayAuth := a.relayManager.(credentialsUpdater)
	var started time.Time
	err := a.outboundControlIOLocked(func() error {
		if needsNetworks {
			started = time.Now()
			networks, err := a.remote.ListNetworks()
			if err != nil {
				return err
			}
			inputs.networks = make(map[string]controlclient.Network, len(networks))
			for _, network := range networks {
				inputs.networks[network.ID] = network
			}
		}
		seenDirect := make(map[string]bool)
		for _, peer := range managed {
			directEnabled := a.directManager != nil && strings.TrimSpace(peer.NetworkID) != "" && strings.TrimSpace(peer.Endpoint) != "" && !seenDirect[peer.NetworkID]
			if directEnabled {
				seenDirect[peer.NetworkID] = true
			}
			if !directEnabled && !relayEnabled {
				continue
			}
			credentials := a.transportCredentialsLocked(peer)
			inputs.credentials[peer.PeerID] = credentials
			if credentials == nil && (directEnabled && directAuth || relayEnabled && relayAuth) {
				// Do not wait for another HTTP request after a known auth failure.
				return fmt.Errorf("transport identity unavailable for peer %s", peer.PeerID)
			}
		}
		return nil
	})
	if err != nil {
		a.invalidateForwardingRoutesLocked()
		a.forwardingPolicy = nil
		for peer, credentials := range inputs.credentials {
			if credentials != nil {
				continue
			}
			if manager, ok := a.directManager.(credentialsUpdater); ok {
				_ = manager.UpdateCredentials(peer, nil)
			}
			if manager, ok := a.relayManager.(credentialsUpdater); ok {
				_ = manager.UpdateCredentials(peer, nil)
			}
		}
		return err
	}
	if needsNetworks {
		a.publishForwardingPolicyLocked(inputs.networks, started)
	}
	return a.reconcileManagedRuntimeWithInputsLocked(inputs)
}

func (a *Agent) runtimeCredentialsLocked(peer ManagedPeerState, inputs *runtimeReconcileInputs) *transportauth.Credentials {
	if inputs != nil {
		return inputs.credentials[peer.PeerID]
	}
	return a.transportCredentialsLocked(peer)
}
