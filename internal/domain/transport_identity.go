package domain

import (
	"Ole/internal/transportauth"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"
)

type TransportPeerIdentity struct {
	PeerID    string `json:"peerId"`
	DeviceID  string `json:"deviceId"`
	PublicKey string `json:"publicKey"`
}

type TransportIdentitySnapshot struct {
	NetworkID     string                  `json:"networkId"`
	Local         TransportPeerIdentity   `json:"local"`
	Peers         []TransportPeerIdentity `json:"peers"`
	ExpiresAtUnix int64                   `json:"expiresAtUnix"`
}

// TransportIdentities returns current eligible keys, never keys supplied by UDP.
// The caller must own the local peer; both sides must still be allowed to connect.
func (d *PeerDirectory) TransportIdentities(userID UserID, peerID PeerID, now time.Time) (*TransportIdentitySnapshot, error) {
	if d.userRepo == nil || d.peerRepo == nil || d.networkRepo == nil || d.deviceRepo == nil || d.virtualIPPoolRepo == nil {
		return nil, errors.New("transport identity user repository is unavailable")
	}
	local, err := d.GetOwnedPeer(userID, peerID)
	if err != nil {
		return nil, err
	}
	network, err := d.networkRepo.FindByID(local.NetworkID)
	if err != nil {
		return nil, err
	}
	if network == nil {
		return nil, ErrNotFound
	}
	identity, err := d.transportIdentity(network, local)
	if err != nil {
		return nil, err
	}
	peers, err := d.peerRepo.ListByNetwork(network.ID)
	if err != nil {
		return nil, err
	}
	result := &TransportIdentitySnapshot{NetworkID: network.ID.String(), Local: identity, Peers: []TransportPeerIdentity{}, ExpiresAtUnix: now.Add(transportauth.SnapshotTTL).Unix()}
	for _, peer := range peers {
		if peer.ID == local.ID {
			continue
		}
		identity, err := d.transportIdentity(network, peer)
		if err != nil {
			if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrDeviceNotActive) || errors.Is(err, ErrDeviceApprovalRequired) {
				continue
			}
			return nil, err
		}
		result.Peers = append(result.Peers, identity)
	}
	return result, nil
}

func (d *PeerDirectory) transportIdentity(network *Network, peer *Peer) (TransportPeerIdentity, error) {
	user, err := d.userRepo.FindByID(peer.UserID)
	if err != nil {
		return TransportPeerIdentity{}, err
	}
	if user == nil || !user.CanLogin() {
		return TransportPeerIdentity{}, ErrUnauthorized
	}
	if peer.NetworkID != network.ID || peer.Status != PeerStatusOnline {
		return TransportPeerIdentity{}, ErrUnauthorized
	}
	if err := network.AuthorizeOperation(peer.UserID, NetworkOperationRequestTunnel); err != nil {
		return TransportPeerIdentity{}, ErrUnauthorized
	}
	device, err := d.deviceRepo.FindByID(peer.DeviceID)
	if err != nil {
		return TransportPeerIdentity{}, err
	}
	if device == nil {
		return TransportPeerIdentity{}, ErrNotFound
	}
	if device.UserID != peer.UserID {
		return TransportPeerIdentity{}, ErrUnauthorized
	}
	if !device.IsActive() {
		return TransportPeerIdentity{}, ErrDeviceNotActive
	}
	if network.DeviceApprovalRequired && !network.IsOwner(peer.UserID) && !network.IsDeviceApproved(device.ID) {
		return TransportPeerIdentity{}, ErrDeviceApprovalRequired
	}
	if len(device.PublicKey) != base64.StdEncoding.EncodedLen(ed25519.PublicKeySize) {
		return TransportPeerIdentity{}, ErrUnauthorized
	}
	key, err := base64.StdEncoding.DecodeString(device.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return TransportPeerIdentity{}, ErrUnauthorized
	}
	return TransportPeerIdentity{PeerID: peer.ID.String(), DeviceID: device.ID.String(), PublicKey: device.PublicKey}, nil
}
