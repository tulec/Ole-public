package clientagent

import (
	"Ole/internal/transportauth"
	"sort"
)

type TransportDataPlaneMetrics struct {
	NetworkID   string                        `json:"networkId"`
	LocalPeerID string                        `json:"localPeerId"`
	Direct      *transportauth.DataPlaneStats `json:"direct,omitempty"`
	Relay       *transportauth.DataPlaneStats `json:"relay,omitempty"`
}

type dataPlaneStatsProvider interface {
	DataPlaneStats(string) transportauth.DataPlaneStats
}

func (a *Agent) transportDataPlaneMetricsLocked() []TransportDataPlaneMetrics {
	if a.currentUser == nil || a.deviceState == nil || a.remote == nil {
		return nil
	}
	managed := a.dedupeManagedPeersForRuntime(a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID))
	result := make([]TransportDataPlaneMetrics, 0, len(managed))
	for _, peer := range managed {
		item := TransportDataPlaneMetrics{NetworkID: peer.NetworkID, LocalPeerID: peer.PeerID}
		if provider, ok := a.directManager.(dataPlaneStatsProvider); ok {
			stats := provider.DataPlaneStats(peer.PeerID)
			item.Direct = &stats
		}
		if provider, ok := a.relayManager.(dataPlaneStatsProvider); ok {
			stats := provider.DataPlaneStats(peer.PeerID)
			item.Relay = &stats
		}
		if item.Direct != nil || item.Relay != nil {
			result = append(result, item)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].NetworkID == result[j].NetworkID {
			return result[i].LocalPeerID < result[j].LocalPeerID
		}
		return result[i].NetworkID < result[j].NetworkID
	})
	return result
}
