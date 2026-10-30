package memory

import (
	"Ole/internal/domain"
	"strings"
	"sync"
)

type UserRepo struct {
	mu      sync.RWMutex
	byID    map[string]*domain.User
	byEmail map[string]*domain.User
}

func NewUserRepo() *UserRepo {
	return &UserRepo{
		byID:    map[string]*domain.User{},
		byEmail: map[string]*domain.User{},
	}
}

func (r *UserRepo) Create(u *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	email := strings.ToLower(u.Email)
	if _, exists := r.byID[u.ID.String()]; exists {
		return domain.ErrAlreadyExists
	}
	if _, exists := r.byEmail[email]; exists {
		return domain.ErrAlreadyExists
	}
	clone := *u
	r.byID[u.ID.String()] = &clone
	r.byEmail[email] = &clone
	return nil
}

func (r *UserRepo) Save(u *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *u
	r.byID[u.ID.String()] = &clone
	r.byEmail[strings.ToLower(u.Email)] = &clone
	return nil
}

func (r *UserRepo) CompareAndSwapPassword(userID domain.UserID, oldHash, newHash string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	user := r.byID[userID.String()]
	if user == nil || user.PasswordHash != oldHash {
		return false, nil
	}
	user.PasswordHash = newHash
	return true, nil
}

func (r *UserRepo) FindByEmail(email string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	user, ok := r.byEmail[strings.ToLower(email)]
	if !ok {
		return nil, nil
	}
	clone := *user
	return &clone, nil
}

func (r *UserRepo) FindByID(id domain.UserID) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	user, ok := r.byID[id.String()]
	if !ok {
		return nil, nil
	}
	clone := *user
	return &clone, nil
}

type DeviceRepo struct {
	mu   sync.RWMutex
	data map[string]*domain.Device
}

func NewDeviceRepo() *DeviceRepo {
	return &DeviceRepo{data: map[string]*domain.Device{}}
}

func (r *DeviceRepo) Save(d *domain.Device) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *d
	r.data[d.ID.String()] = &clone
	return nil
}

func (r *DeviceRepo) FindByID(id domain.DeviceID) (*domain.Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	device, ok := r.data[id.String()]
	if !ok {
		return nil, nil
	}
	clone := *device
	return &clone, nil
}

func (r *DeviceRepo) ListByUserID(userID domain.UserID, limit, offset int) ([]*domain.Device, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	all := make([]*domain.Device, 0)
	for _, device := range r.data {
		if device.UserID == userID {
			clone := *device
			all = append(all, &clone)
		}
	}
	total := len(all)
	if offset > total {
		return []*domain.Device{}, total, nil
	}
	if limit <= 0 {
		limit = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return all[offset:end], total, nil
}

type NetworkRepo struct {
	mu   sync.RWMutex
	data map[string]*domain.Network
}

func NewNetworkRepo() *NetworkRepo {
	return &NetworkRepo{data: map[string]*domain.Network{}}
}

func (r *NetworkRepo) Save(n *domain.Network) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[n.ID.String()] = cloneNetwork(n)
	return nil
}

func (r *NetworkRepo) FindByID(id domain.NetworkID) (*domain.Network, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n, ok := r.data[id.String()]
	if !ok {
		return nil, nil
	}
	return cloneNetwork(n), nil
}

func (r *NetworkRepo) Delete(id domain.NetworkID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.data, id.String())
	return nil
}

func (r *NetworkRepo) List() ([]*domain.Network, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.Network, 0, len(r.data))
	for _, item := range r.data {
		out = append(out, cloneNetwork(item))
	}
	return out, nil
}

type PeerRepo struct {
	mu   sync.RWMutex
	data map[string]*domain.Peer
}

func NewPeerRepo() *PeerRepo {
	return &PeerRepo{data: map[string]*domain.Peer{}}
}

func (r *PeerRepo) Save(p *domain.Peer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *p
	r.data[p.ID.String()] = &clone
	return nil
}

func (r *PeerRepo) FindByID(id domain.PeerID) (*domain.Peer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.data[id.String()]
	if !ok {
		return nil, nil
	}
	clone := *p
	return &clone, nil
}

func (r *PeerRepo) ListByNetwork(networkID domain.NetworkID) ([]*domain.Peer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []*domain.Peer{}
	for _, p := range r.data {
		if p.NetworkID == networkID {
			clone := *p
			out = append(out, &clone)
		}
	}
	return out, nil
}

type MessageRepo struct {
	mu   sync.RWMutex
	data map[string]*domain.Message
}

func NewMessageRepo() *MessageRepo {
	return &MessageRepo{data: map[string]*domain.Message{}}
}

func (r *MessageRepo) Save(message *domain.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *message
	r.data[message.ID] = &clone
	return nil
}

func (r *MessageRepo) FindByID(id string) (*domain.Message, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	message, ok := r.data[id]
	if !ok {
		return nil, nil
	}
	clone := *message
	return &clone, nil
}

func (r *MessageRepo) ListByNetwork(networkID domain.NetworkID) ([]*domain.Message, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []*domain.Message{}
	for _, message := range r.data {
		if message.NetworkID == networkID {
			clone := *message
			out = append(out, &clone)
		}
	}
	return out, nil
}

type FileTransferRepo struct {
	mu   sync.RWMutex
	data map[string]*domain.FileTransfer
}

func NewFileTransferRepo() *FileTransferRepo {
	return &FileTransferRepo{data: map[string]*domain.FileTransfer{}}
}

func (r *FileTransferRepo) Save(transfer *domain.FileTransfer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *transfer
	r.data[transfer.ID] = &clone
	return nil
}

func (r *FileTransferRepo) FindByID(id string) (*domain.FileTransfer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	transfer, ok := r.data[id]
	if !ok {
		return nil, nil
	}
	clone := *transfer
	return &clone, nil
}

func (r *FileTransferRepo) ListByNetwork(networkID domain.NetworkID) ([]*domain.FileTransfer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []*domain.FileTransfer{}
	for _, transfer := range r.data {
		if transfer.NetworkID == networkID {
			clone := *transfer
			out = append(out, &clone)
		}
	}
	return out, nil
}

type FileTransferPayloadRepo struct {
	mu   sync.RWMutex
	data map[string]*domain.FileTransferPayload
}

func NewFileTransferPayloadRepo() *FileTransferPayloadRepo {
	return &FileTransferPayloadRepo{data: map[string]*domain.FileTransferPayload{}}
}

func (r *FileTransferPayloadRepo) Save(payload *domain.FileTransferPayload) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *payload
	clone.Payload = append([]byte(nil), payload.Payload...)
	r.data[payload.TransferID] = &clone
	return nil
}

func (r *FileTransferPayloadRepo) FindByTransferID(transferID string) (*domain.FileTransferPayload, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	payload, ok := r.data[transferID]
	if !ok {
		return nil, nil
	}
	clone := *payload
	clone.Payload = append([]byte(nil), payload.Payload...)
	return &clone, nil
}

type SignalCandidateRepo struct {
	mu   sync.RWMutex
	data map[string]*domain.SignalCandidate
}

func NewSignalCandidateRepo() *SignalCandidateRepo {
	return &SignalCandidateRepo{data: map[string]*domain.SignalCandidate{}}
}

func (r *SignalCandidateRepo) Save(candidate *domain.SignalCandidate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *candidate
	r.data[candidate.ID] = &clone
	return nil
}

func (r *SignalCandidateRepo) ListByPeerID(peerID domain.PeerID) ([]*domain.SignalCandidate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []*domain.SignalCandidate{}
	for _, candidate := range r.data {
		if candidate.PeerID == peerID {
			clone := *candidate
			out = append(out, &clone)
		}
	}
	return out, nil
}

func (r *SignalCandidateRepo) DeleteExpired(nowUnix int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, candidate := range r.data {
		if candidate.IsExpired(nowUnix) {
			delete(r.data, id)
		}
	}
	return nil
}

type TunnelRepo struct {
	mu   sync.RWMutex
	data map[string]*domain.Tunnel
}

func NewTunnelRepo() *TunnelRepo {
	return &TunnelRepo{data: map[string]*domain.Tunnel{}}
}

func (r *TunnelRepo) Save(t *domain.Tunnel) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *t
	r.data[t.ID.String()] = &clone
	return nil
}

func (r *TunnelRepo) FindByID(id domain.TunnelID) (*domain.Tunnel, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.data[id.String()]
	if !ok {
		return nil, nil
	}
	clone := *t
	return &clone, nil
}

func (r *TunnelRepo) FindByPeers(networkID domain.NetworkID, a, b domain.PeerID) (*domain.Tunnel, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, tunnel := range r.data {
		if tunnel.NetworkID != networkID {
			continue
		}
		if (tunnel.A == a && tunnel.B == b) || (tunnel.A == b && tunnel.B == a) {
			clone := *tunnel
			return &clone, nil
		}
	}
	return nil, nil
}

func (r *TunnelRepo) ListByNetwork(networkID domain.NetworkID) ([]*domain.Tunnel, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []*domain.Tunnel{}
	for _, t := range r.data {
		if t.NetworkID == networkID {
			clone := *t
			out = append(out, &clone)
		}
	}
	return out, nil
}

type InviteRepo struct {
	mu   sync.RWMutex
	data map[string]*domain.Invite
}

func NewInviteRepo() *InviteRepo {
	return &InviteRepo{data: map[string]*domain.Invite{}}
}

func (r *InviteRepo) Save(i *domain.Invite) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *i
	r.data[i.Code] = &clone
	return nil
}

func (r *InviteRepo) FindByCode(code string) (*domain.Invite, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	i, ok := r.data[code]
	if !ok {
		return nil, nil
	}
	clone := *i
	return &clone, nil
}

func (r *InviteRepo) DeleteStale(nowUnix int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for code, invite := range r.data {
		if invite.IsExpired(nowUnix) || invite.IsExhausted() {
			delete(r.data, code)
		}
	}
	return nil
}

type SessionRepo struct {
	mu             sync.RWMutex
	byAccessToken  map[string]*domain.SessionToken
	byRefreshToken map[string]*domain.SessionToken
}

func NewSessionRepo() *SessionRepo {
	return &SessionRepo{
		byAccessToken:  map[string]*domain.SessionToken{},
		byRefreshToken: map[string]*domain.SessionToken{},
	}
}

type AuditRepo struct {
	mu     sync.RWMutex
	events []*domain.AuditEvent
}

func NewAuditRepo() *AuditRepo {
	return &AuditRepo{events: []*domain.AuditEvent{}}
}

func (r *AuditRepo) Append(e *domain.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *e
	r.events = append(r.events, &clone)
	return nil
}

func (r *AuditRepo) ListRecent(limit int) ([]*domain.AuditEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 || limit > len(r.events) {
		limit = len(r.events)
	}
	out := make([]*domain.AuditEvent, 0, limit)
	for idx := len(r.events) - 1; idx >= 0 && len(out) < limit; idx-- {
		clone := *r.events[idx]
		out = append(out, &clone)
	}
	return out, nil
}

func (r *AuditRepo) ListByNetworkID(networkID domain.NetworkID, limit int) ([]*domain.AuditEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.AuditEvent, 0, len(r.events))
	for idx := len(r.events) - 1; idx >= 0; idx-- {
		if r.events[idx].NetworkID != networkID {
			continue
		}
		clone := *r.events[idx]
		out = append(out, &clone)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

type VirtualIPPoolRepo struct {
	mu   sync.RWMutex
	data map[string]*domain.VirtualIPPool
}

func NewVirtualIPPoolRepo() *VirtualIPPoolRepo {
	return &VirtualIPPoolRepo{data: map[string]*domain.VirtualIPPool{}}
}

func (r *VirtualIPPoolRepo) Save(pool *domain.VirtualIPPool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[pool.NetworkID.String()] = clonePool(pool)
	return nil
}

func (r *VirtualIPPoolRepo) FindByNetworkID(networkID domain.NetworkID) (*domain.VirtualIPPool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pool, ok := r.data[networkID.String()]
	if !ok {
		return nil, nil
	}
	return clonePool(pool), nil
}

func (r *VirtualIPPoolRepo) List() ([]*domain.VirtualIPPool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.VirtualIPPool, 0, len(r.data))
	for _, pool := range r.data {
		out = append(out, clonePool(pool))
	}
	return out, nil
}

func cloneNetwork(n *domain.Network) *domain.Network {
	clone := *n
	clone.Members = make(map[string]domain.NetworkRole, len(n.Members))
	for k, v := range n.Members {
		clone.Members[k] = v
	}
	clone.ApprovedDevices = make(map[string]bool, len(n.ApprovedDevices))
	for k, v := range n.ApprovedDevices {
		clone.ApprovedDevices[k] = v
	}
	return &clone
}

func clonePool(pool *domain.VirtualIPPool) *domain.VirtualIPPool {
	clone := *pool
	clone.Leases = make(map[string]domain.PeerID, len(pool.Leases))
	for k, v := range pool.Leases {
		clone.Leases[k] = v
	}
	return &clone
}
