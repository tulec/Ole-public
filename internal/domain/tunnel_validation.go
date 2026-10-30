package domain

import "fmt"

// Raw internal operations still enforce network boundaries. User-scoped
// operations additionally require a configured network repository and ownership.
func (c *TunnelCoordinator) tunnelPeers(networkID NetworkID, a, b PeerID) (*Peer, *Peer, error) {
	if networkID.String() == "" || a.String() == "" || b.String() == "" || a == b {
		return nil, nil, fmt.Errorf("a network and two distinct peer IDs are required")
	}
	peerA, err := c.peerRepo.FindByID(a)
	if err != nil {
		return nil, nil, err
	}
	if peerA == nil {
		return nil, nil, ErrNotFound
	}
	peerB, err := c.peerRepo.FindByID(b)
	if err != nil {
		return nil, nil, err
	}
	if peerB == nil {
		return nil, nil, ErrNotFound
	}
	if peerA.NetworkID != networkID || peerB.NetworkID != networkID {
		return nil, nil, ErrUnauthorized
	}
	if c.networkRepo != nil {
		network, err := c.networkRepo.FindByID(networkID)
		if err != nil {
			return nil, nil, err
		}
		if network == nil {
			return nil, nil, ErrNotFound
		}
		for _, peer := range []*Peer{peerA, peerB} {
			if err := network.AuthorizeOperation(peer.UserID, NetworkOperationRequestTunnel); err != nil {
				return nil, nil, err
			}
		}
	}
	return peerA, peerB, nil
}
