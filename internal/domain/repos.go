package domain

type UserRepo interface {
	// Create must reject existing IDs or emails without updating their owner.
	Create(u *User) error
	Save(u *User) error
	// CompareAndSwapPassword changes only the password, if the verified hash still matches.
	CompareAndSwapPassword(userID UserID, oldHash, newHash string) (bool, error)
	FindByEmail(email string) (*User, error)
	FindByID(id UserID) (*User, error)
}

type DeviceRepo interface {
	Save(d *Device) error
	FindByID(id DeviceID) (*Device, error)
	ListByUserID(userID UserID, limit, offset int) ([]*Device, int, error)
}

type NetworkRepo interface {
	Save(n *Network) error
	FindByID(id NetworkID) (*Network, error)
	Delete(id NetworkID) error
	List() ([]*Network, error)
}

type PeerRepo interface {
	Save(p *Peer) error
	FindByID(id PeerID) (*Peer, error)
	ListByNetwork(networkID NetworkID) ([]*Peer, error)
}

type MessageRepo interface {
	Save(m *Message) error
	FindByID(id string) (*Message, error)
	ListByNetwork(networkID NetworkID) ([]*Message, error)
}

type FileTransferRepo interface {
	Save(f *FileTransfer) error
	FindByID(id string) (*FileTransfer, error)
	ListByNetwork(networkID NetworkID) ([]*FileTransfer, error)
}

type FileTransferPayloadRepo interface {
	Save(payload *FileTransferPayload) error
	FindByTransferID(transferID string) (*FileTransferPayload, error)
}

type SignalCandidateRepo interface {
	Save(candidate *SignalCandidate) error
	ListByPeerID(peerID PeerID) ([]*SignalCandidate, error)
	DeleteExpired(nowUnix int64) error
}

type TunnelRepo interface {
	Save(t *Tunnel) error
	FindByID(id TunnelID) (*Tunnel, error)
	FindByPeers(networkID NetworkID, a, b PeerID) (*Tunnel, error)
	ListByNetwork(networkID NetworkID) ([]*Tunnel, error)
}

type InviteRepo interface {
	Save(i *Invite) error
	FindByCode(code string) (*Invite, error)
	DeleteStale(nowUnix int64) error
}

type AuditRepo interface {
	Append(e *AuditEvent) error
	ListRecent(limit int) ([]*AuditEvent, error)
	// ListVisible applies access scope before its limit. Network IDs are authorized by the service.
	ListVisible(userID UserID, networkIDs []NetworkID, limit int) ([]*AuditEvent, error)
	ListByNetworkID(networkID NetworkID, limit int) ([]*AuditEvent, error)
}

type VirtualIPPoolRepo interface {
	Save(pool *VirtualIPPool) error
	FindByNetworkID(networkID NetworkID) (*VirtualIPPool, error)
	List() ([]*VirtualIPPool, error)
}

type SessionRepo interface {
	Create(session *SessionToken) error
	Update(session *SessionToken) error
	// TouchLastUsed never changes security state and fails for revoked/expired sessions.
	TouchLastUsed(accessToken string, nowUnix int64) (bool, error)
	// Rotate atomically revokes the old session and inserts the next one, serialized with revocation.
	Rotate(refreshToken string, next *SessionToken, nowUnix int64) error
	FindByRefreshToken(refreshToken string) (*SessionToken, error)
	FindByAccessToken(accessToken string) (*SessionToken, error)
	ListByUserID(userID UserID, limit, offset int) ([]*SessionToken, int, error)
	// RevokeBySessionID resolves historical IDs and revokes exactly one user's family,
	// serialized with rotation. Missing/ambiguous IDs return ErrNotFound without changes.
	RevokeBySessionID(userID UserID, sessionID string, nowUnix int64) error
	RevokeByAccessToken(accessToken string, nowUnix int64) error
	RevokeByRefreshToken(refreshToken string, replacedByToken string, nowUnix int64) error
	RevokeByUserID(userID UserID, nowUnix int64) error
	RevokeFamily(userID UserID, familyID string, nowUnix int64, reuseDetected bool) error
	DeleteExpired(nowUnix int64) error
}
