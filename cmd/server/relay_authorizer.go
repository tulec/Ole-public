package main

import (
	"Ole/internal/app"
	"Ole/internal/domain"
	"fmt"
)

type appRelayAuthorizer struct{ app *app.App }

func (a appRelayAuthorizer) AuthorizeBind(accessToken, peerID string) error {
	_, _, err := a.authorizedRelaySource(accessToken, peerID)
	return err
}

func (a appRelayAuthorizer) authorizedRelaySource(accessToken, peerID string) (*domain.Peer, *domain.Network, error) {
	if a.app == nil || a.app.AuthService == nil || a.app.PeerRepo == nil || a.app.NetworkRepo == nil || a.app.DeviceRepo == nil {
		return nil, nil, fmt.Errorf("relay authorizer is unavailable")
	}
	userID, err := a.app.AuthService.ValidateAccessToken(accessToken)
	if err != nil {
		return nil, nil, err
	}
	peer, err := a.app.PeerRepo.FindByID(domain.PeerID{Value: peerID})
	if err != nil {
		return nil, nil, err
	}
	if peer == nil {
		return nil, nil, domain.ErrNotFound
	}
	if peer.UserID != userID {
		return nil, nil, domain.ErrUnauthorized
	}
	network, err := a.app.NetworkRepo.FindByID(peer.NetworkID)
	if err != nil {
		return nil, nil, err
	}
	if network == nil {
		return nil, nil, domain.ErrNotFound
	}
	if err := a.validateRelayPeer(network, peer); err != nil {
		return nil, nil, err
	}
	return peer, network, nil
}

func (a appRelayAuthorizer) validateRelayPeer(network *domain.Network, peer *domain.Peer) error {
	if peer.NetworkID != network.ID || peer.Status != domain.PeerStatusOnline {
		return domain.ErrUnauthorized
	}
	if err := network.AuthorizeOperation(peer.UserID, domain.NetworkOperationRequestTunnel); err != nil {
		return err
	}
	device, err := a.app.DeviceRepo.FindByID(peer.DeviceID)
	if err != nil {
		return err
	}
	if device == nil {
		return domain.ErrNotFound
	}
	if device.UserID != peer.UserID {
		return domain.ErrUnauthorized
	}
	if !device.IsActive() {
		return domain.ErrDeviceNotActive
	}
	if network.DeviceApprovalRequired && !network.IsOwner(peer.UserID) && !network.IsDeviceApproved(device.ID) {
		return domain.ErrDeviceApprovalRequired
	}
	return nil
}

func (a appRelayAuthorizer) AuthorizeSend(accessToken, sourcePeerID, targetPeerID string) error {
	source, network, err := a.authorizedRelaySource(accessToken, sourcePeerID)
	if err != nil {
		return err
	}
	if a.app.TunnelRepo == nil {
		return fmt.Errorf("relay authorizer is unavailable")
	}
	if sourcePeerID == targetPeerID {
		return domain.ErrUnauthorized
	}
	target, err := a.app.PeerRepo.FindByID(domain.PeerID{Value: targetPeerID})
	if err != nil {
		return err
	}
	if target == nil {
		return domain.ErrNotFound
	}
	if err := a.validateRelayPeer(network, target); err != nil {
		return err
	}
	tunnel, err := a.app.TunnelRepo.FindByPeers(network.ID, source.ID, target.ID)
	if err != nil {
		return err
	}
	if tunnel == nil || tunnel.NetworkID != network.ID || !((tunnel.A == source.ID && tunnel.B == target.ID) || (tunnel.A == target.ID && tunnel.B == source.ID)) {
		return domain.ErrUnauthorized
	}
	if tunnel.Mode != domain.TunnelModeRelay || (tunnel.State != domain.TunnelStateNegotiating && tunnel.State != domain.TunnelStateOpen) {
		return domain.ErrUnauthorized
	}
	return nil
}
