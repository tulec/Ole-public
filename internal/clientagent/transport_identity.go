package clientagent

import (
	"Ole/internal/transportauth"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"time"
)

type credentialsUpdater interface {
	UpdateCredentials(string, *transportauth.Credentials) error
}

type cachedTransportCredentials struct {
	credentials *transportauth.Credentials
	refreshAt   time.Time
}

func (a *Agent) transportCredentialsLocked(peer ManagedPeerState) *transportauth.Credentials {
	_, direct := a.directManager.(credentialsUpdater)
	_, relay := a.relayManager.(credentialsUpdater)
	if !direct && !relay || a.currentSession == nil || a.currentUser == nil || a.deviceState == nil {
		return nil
	}
	if a.transportCredentials == nil {
		a.transportCredentials = make(map[string]cachedTransportCredentials)
	}
	key := a.remote.BaseURL() + "|" + a.currentUser.ID + "|" + peer.PeerID
	now := time.Now()
	if cached, ok := a.transportCredentials[key]; ok && now.Before(cached.refreshAt) {
		if cached.credentials != nil && !now.Before(cached.credentials.ExpiresAt) {
			return nil
		}
		return cached.credentials
	}
	// Any failed refresh drops the previous snapshot. Retry is bounded and old
	// credentials expire inside the transports even if the lifecycle stalls.
	a.transportCredentials[key] = cachedTransportCredentials{refreshAt: now.Add(5 * time.Second)}
	snapshot, err := a.remote.TransportIdentities(peer.PeerID)
	if err != nil || snapshot.NetworkID != peer.NetworkID || snapshot.Local.PeerID != peer.PeerID || snapshot.Local.DeviceID != a.currentEnrolledDeviceIDLocked() {
		return nil
	}
	private, err := base64.StdEncoding.DecodeString(a.deviceState.PrivateKey)
	if err != nil || len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private[:32]), private) {
		return nil
	}
	public, err := base64.StdEncoding.DecodeString(snapshot.Local.PublicKey)
	if err != nil || !bytes.Equal(ed25519.PrivateKey(private).Public().(ed25519.PublicKey), public) {
		return nil
	}
	expires := time.Unix(snapshot.ExpiresAtUnix, 0)
	if expires.After(now.Add(transportauth.SnapshotTTL)) {
		expires = now.Add(transportauth.SnapshotTTL)
	}
	if !expires.After(time.Now()) {
		return nil
	}
	expires = now.Add(expires.Sub(now)) // Preserve a local monotonic deadline.
	c := &transportauth.Credentials{NetworkID: peer.NetworkID, PeerID: peer.PeerID, DeviceID: snapshot.Local.DeviceID, PrivateKey: private, ExpiresAt: expires, Peers: make(map[string]transportauth.Identity)}
	for _, identity := range snapshot.Peers {
		public, err := base64.StdEncoding.DecodeString(identity.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize || identity.PeerID == peer.PeerID {
			return nil
		}
		if _, exists := c.Peers[identity.PeerID]; exists {
			return nil
		}
		c.Peers[identity.PeerID] = transportauth.Identity{DeviceID: identity.DeviceID, PublicKey: public}
	}
	a.transportCredentials[key] = cachedTransportCredentials{credentials: c, refreshAt: now.Add(10 * time.Second)}
	return c
}

func (a *Agent) refreshTransportCredentialsLocked() {
	if a.currentUser == nil || a.deviceState == nil {
		return
	}
	managed := a.deviceState.ManagedPeersFor(a.remote.BaseURL(), a.currentUser.ID)
	live := make(map[string]bool, len(managed))
	for _, peer := range managed {
		live[a.remote.BaseURL()+"|"+a.currentUser.ID+"|"+peer.PeerID] = true
		credentials := a.transportCredentialsLocked(peer)
		if manager, ok := a.directManager.(credentialsUpdater); ok {
			_ = manager.UpdateCredentials(peer.PeerID, credentials)
		}
		if manager, ok := a.relayManager.(credentialsUpdater); ok {
			_ = manager.UpdateCredentials(peer.PeerID, credentials)
		}
	}
	for key := range a.transportCredentials {
		if !live[key] {
			delete(a.transportCredentials, key)
		}
	}
}
