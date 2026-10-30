package domain

import (
	"Ole/internal/passwordhash"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	ErrAlreadyExists      = errors.New("entity already exists")
	ErrNotFound           = errors.New("entity not found")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type AuthService struct {
	userRepo          UserRepo
	auditRepo         AuditRepo
	sessionRepo       SessionRepo
	sessionTTL        int64
	jwtSecret         []byte
	jwtIssuer         string
	sessionsByAccess  map[string]*SessionToken
	sessionsByRefresh map[string]*SessionToken
	mu                sync.RWMutex
}

func NewAuthService(userRepo UserRepo, auditRepo AuditRepo, sessionRepo SessionRepo, jwtSecret, jwtIssuer string) *AuthService {
	return &AuthService{
		userRepo:          userRepo,
		auditRepo:         auditRepo,
		sessionRepo:       sessionRepo,
		sessionTTL:        24 * 60 * 60,
		jwtSecret:         []byte(jwtSecret),
		jwtIssuer:         jwtIssuer,
		sessionsByAccess:  map[string]*SessionToken{},
		sessionsByRefresh: map[string]*SessionToken{},
	}
}

func (s *AuthService) Register(email, password string) (*User, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" || password == "" {
		return nil, fmt.Errorf("email and password are required")
	}
	existing, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrAlreadyExists
	}
	passwordHash, err := passwordhash.Hash(password)
	if err != nil {
		return nil, err
	}

	user := &User{
		ID:           UserID{Value: nextID("usr")},
		Email:        email,
		PasswordHash: passwordHash,
		Status:       UserStatusActive,
	}
	if err := s.userRepo.Create(user); err != nil {
		return nil, err
	}
	s.appendAudit(user.ID, "user.registered", email)
	return user, nil
}

func (s *AuthService) Logout(accessToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var session *SessionToken
	if s.sessionRepo != nil {
		var err error
		session, err = s.sessionRepo.FindByAccessToken(accessToken)
		if err != nil {
			return err
		}
	} else {
		session = s.sessionsByAccess[accessToken]
		if session == nil {
			// Refresh may already have moved the access token out of the live map.
			for _, previous := range s.sessionsByRefresh {
				if previous.AccessToken == accessToken {
					session = previous
					break
				}
			}
		}
	}
	if session == nil || session.FamilyID == "" {
		return ErrUnauthorized
	}
	// A concurrent refresh may have issued a child after middleware authorized
	// this request. Revoke the family under the repository's rotation lock.
	nowUnix := time.Now().Unix()
	if s.sessionRepo != nil {
		if err := s.sessionRepo.RevokeFamily(session.UserID, session.FamilyID, nowUnix, false); err != nil {
			return err
		}
	}
	s.revokeFamilyInMemory(session.UserID, session.FamilyID, nowUnix, false)
	return nil
}

func (s *AuthService) RevokeAllSessions(userID UserID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for accessToken, session := range s.sessionsByAccess {
		if session.UserID == userID {
			delete(s.sessionsByAccess, accessToken)
		}
	}
	for refreshToken, session := range s.sessionsByRefresh {
		if session.UserID == userID {
			delete(s.sessionsByRefresh, refreshToken)
		}
	}
	if s.sessionRepo != nil {
		return s.sessionRepo.RevokeByUserID(userID, time.Now().Unix())
	}
	return nil
}

func (s *AuthService) ListSessions(userID UserID, limit, offset int) ([]*SessionToken, int, error) {
	if limit <= 0 {
		limit = 20
	}
	if s.sessionRepo != nil {
		return s.sessionRepo.ListByUserID(userID, limit, offset)
	}
	return nil, 0, nil
}

func (s *AuthService) RevokeSession(userID UserID, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sessionID == "" {
		return ErrNotFound
	}
	if s.sessionRepo != nil {
		return s.sessionRepo.RevokeBySessionID(userID, sessionID, time.Now().Unix())
	}
	// Keep historical IDs usable after refresh, but never guess between legacy
	// duplicate IDs that belong to different families of the same user.
	familyID := ""
	for _, session := range s.sessionsByRefresh {
		if session.UserID == userID && session.ID == sessionID {
			if session.FamilyID == "" || (familyID != "" && familyID != session.FamilyID) {
				return ErrNotFound
			}
			familyID = session.FamilyID
		}
	}
	if familyID == "" {
		return ErrNotFound
	}
	s.revokeFamilyInMemory(userID, familyID, time.Now().Unix(), false)
	return nil
}

func (s *AuthService) appendAudit(userID UserID, eventType, details string) {
	if s.auditRepo == nil {
		return
	}
	_ = s.auditRepo.Append(&AuditEvent{
		ID:            nextID("aud"),
		ActorUserID:   userID,
		Type:          eventType,
		Details:       details,
		CreatedAtUnix: time.Now().Unix(),
	})
}

func (s *AuthService) CleanupExpiredSessions(nowUnix int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for accessToken, session := range s.sessionsByAccess {
		if session.IsExpired(nowUnix) {
			delete(s.sessionsByAccess, accessToken)
		}
	}
	for refreshToken, session := range s.sessionsByRefresh {
		if session.IsExpired(nowUnix) {
			delete(s.sessionsByRefresh, refreshToken)
		}
	}
	if s.sessionRepo != nil {
		return s.sessionRepo.DeleteExpired(nowUnix)
	}
	return nil
}

func (s *AuthService) revokeFamilyInMemory(userID UserID, familyID string, nowUnix int64, reuseDetected bool) {
	for accessToken, session := range s.sessionsByAccess {
		if session.UserID == userID && session.FamilyID == familyID {
			if reuseDetected {
				session.MarkReuseDetected(nowUnix)
			} else {
				session.RevokedAtUnix = nowUnix
			}
			delete(s.sessionsByAccess, accessToken)
		}
	}
	for refreshToken, session := range s.sessionsByRefresh {
		if session.UserID == userID && session.FamilyID == familyID {
			if reuseDetected {
				session.MarkReuseDetected(nowUnix)
			} else {
				session.RevokedAtUnix = nowUnix
			}
			delete(s.sessionsByRefresh, refreshToken)
		}
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

type DeviceService struct {
	deviceRepo DeviceRepo
	auditRepo  AuditRepo
}

func NewDeviceService(deviceRepo DeviceRepo, auditRepo AuditRepo) *DeviceService {
	return &DeviceService{deviceRepo: deviceRepo, auditRepo: auditRepo}
}

func (s *DeviceService) Enroll(userID UserID, name, publicKey string, nowUnix int64) (*Device, error) {
	device := NewDevice(DeviceID{Value: nextID("dev")}, userID, name, publicKey, nowUnix)
	if err := s.deviceRepo.Save(device); err != nil {
		return nil, err
	}
	s.appendAudit(userID, "device.enrolled", device.ID.String())
	return device, nil
}

func (s *DeviceService) Get(userID UserID, deviceID DeviceID) (*Device, error) {
	device, err := s.deviceRepo.FindByID(deviceID)
	if err != nil {
		return nil, err
	}
	if device == nil {
		return nil, ErrNotFound
	}
	if device.UserID != userID {
		return nil, ErrUnauthorized
	}
	return device, nil
}

func (s *DeviceService) List(userID UserID, limit, offset int) ([]*Device, int, error) {
	return s.deviceRepo.ListByUserID(userID, limit, offset)
}

func (s *DeviceService) Rename(userID UserID, deviceID DeviceID, name string) (*Device, error) {
	device, err := s.Get(userID, deviceID)
	if err != nil {
		return nil, err
	}
	device.Rename(name)
	if err := s.deviceRepo.Save(device); err != nil {
		return nil, err
	}
	s.appendAudit(userID, "device.renamed", device.ID.String())
	return device, nil
}

func (s *DeviceService) SetStatus(userID UserID, deviceID DeviceID, status DeviceStatus) (*Device, error) {
	device, err := s.Get(userID, deviceID)
	if err != nil {
		return nil, err
	}
	switch status {
	case DeviceStatusActive:
		if err := device.Activate(); err != nil {
			return nil, err
		}
	case DeviceStatusDisabled:
		if err := device.Disable(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported device status: %s", status)
	}
	if err := s.deviceRepo.Save(device); err != nil {
		return nil, err
	}
	s.appendAudit(userID, "device.status_changed", device.ID.String()+":"+string(device.Status))
	return device, nil
}

func (s *DeviceService) Revoke(userID UserID, deviceID DeviceID, nowUnix int64) error {
	device, err := s.Get(userID, deviceID)
	if err != nil {
		return err
	}
	if err := device.Revoke(nowUnix); err != nil {
		return err
	}
	if err := s.deviceRepo.Save(device); err != nil {
		return err
	}
	s.appendAudit(userID, "device.revoked", device.ID.String())
	return nil
}

func (s *DeviceService) appendAudit(userID UserID, eventType, details string) {
	if s.auditRepo == nil {
		return
	}
	_ = s.auditRepo.Append(&AuditEvent{
		ID:            nextID("aud"),
		ActorUserID:   userID,
		Type:          eventType,
		Details:       details,
		CreatedAtUnix: time.Now().Unix(),
	})
}

type NetworkService struct {
	networkRepo NetworkRepo
	inviteRepo  InviteRepo
	auditRepo   AuditRepo
}

type NetworkCreateOptions struct {
	DeviceApprovalRequired  bool
	RoutingPolicy           NetworkRoutingPolicy
	GroupTrafficPolicy      NetworkGroupTrafficPolicy
	NameResolutionMode      NetworkNameResolutionMode
	DNSLabel                string
	FileTransfersEnabledSet bool
	FileTransfersEnabled    bool
	FileTransferMaxBytes    int64
}

func NewNetworkService(networkRepo NetworkRepo, inviteRepo InviteRepo, auditRepo AuditRepo) *NetworkService {
	return &NetworkService{networkRepo: networkRepo, inviteRepo: inviteRepo, auditRepo: auditRepo}
}

func (s *NetworkService) CreateNetwork(ownerID UserID, name string, access NetworkAccess) (*Network, error) {
	return s.CreateNetworkWithOptions(ownerID, name, access, NetworkCreateOptions{})
}

func (s *NetworkService) CreateNetworkWithPolicy(ownerID UserID, name string, access NetworkAccess, deviceApprovalRequired bool) (*Network, error) {
	return s.CreateNetworkWithOptions(ownerID, name, access, NetworkCreateOptions{DeviceApprovalRequired: deviceApprovalRequired})
}

func (s *NetworkService) CreateNetworkWithOptions(ownerID UserID, name string, access NetworkAccess, options NetworkCreateOptions) (*Network, error) {
	network := NewNetwork(NetworkID{Value: nextID("net")}, ownerID, name, access, options.DeviceApprovalRequired)
	if err := network.SetRoutingPolicy(options.RoutingPolicy); err != nil {
		return nil, err
	}
	if err := network.SetGroupTrafficPolicy(options.GroupTrafficPolicy); err != nil {
		return nil, err
	}
	if err := network.SetNameResolutionPolicy(options.NameResolutionMode, options.DNSLabel); err != nil {
		return nil, err
	}
	fileTransfersEnabled := true
	if options.FileTransfersEnabledSet {
		fileTransfersEnabled = options.FileTransfersEnabled
	}
	if err := network.SetFileTransferPolicy(fileTransfersEnabled, options.FileTransferMaxBytes); err != nil {
		return nil, err
	}
	if err := s.networkRepo.Save(network); err != nil {
		return nil, err
	}
	s.appendAudit(ownerID, network.ID, "network.created", network.ID.String())
	return network, nil
}

func (s *NetworkService) ListVisibleNetworks(userID UserID) ([]*Network, error) {
	networks, err := s.networkRepo.List()
	if err != nil {
		return nil, err
	}
	visible := make([]*Network, 0, len(networks))
	for _, network := range networks {
		if network != nil && network.AuthorizeOperation(userID, NetworkOperationViewNetwork) == nil {
			visible = append(visible, network)
		}
	}
	return visible, nil
}

func (s *NetworkService) GetNetwork(userID UserID, networkID NetworkID) (*Network, error) {
	network, err := s.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationViewNetwork); err != nil {
		return nil, err
	}
	return network, nil
}

func (s *NetworkService) ListAuditEventsForUser(userID UserID, networkID NetworkID, limit int) ([]*AuditEvent, error) {
	network, err := s.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationViewNetworkAudit); err != nil {
		return nil, err
	}
	if s.auditRepo == nil {
		return []*AuditEvent{}, nil
	}
	events, err := s.auditRepo.ListByNetworkID(networkID, limit)
	if err != nil {
		return nil, err
	}
	return auditEventsForRead(events), nil
}

func (s *NetworkService) UpdateRoutingPolicy(requestorID UserID, networkID NetworkID, policy NetworkRoutingPolicy) (*Network, error) {
	network, err := s.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(requestorID, NetworkOperationUpdateRoutingPolicy); err != nil {
		return nil, err
	}
	if err := network.SetRoutingPolicy(policy); err != nil {
		return nil, err
	}
	if err := s.networkRepo.Save(network); err != nil {
		return nil, err
	}
	s.appendAudit(requestorID, networkID, "network.routing_policy_updated", fmt.Sprintf("%s:%s", networkID.String(), network.RoutingPolicy))
	return network, nil
}

func (s *NetworkService) UpdateNameResolutionPolicy(requestorID UserID, networkID NetworkID, mode NetworkNameResolutionMode, dnsLabel string) (*Network, error) {
	network, err := s.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(requestorID, NetworkOperationUpdateNameResolution); err != nil {
		return nil, err
	}
	if err := network.SetNameResolutionPolicy(mode, dnsLabel); err != nil {
		return nil, err
	}
	if err := s.networkRepo.Save(network); err != nil {
		return nil, err
	}
	s.appendAudit(requestorID, networkID, "network.name_resolution_updated", fmt.Sprintf("%s:%s:%s", networkID.String(), network.NameResolutionMode, network.DNSLabel))
	return network, nil
}

func (s *NetworkService) UpdateGroupTrafficPolicy(requestorID UserID, networkID NetworkID, policy NetworkGroupTrafficPolicy) (*Network, error) {
	network, err := s.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(requestorID, NetworkOperationUpdateGroupTraffic); err != nil {
		return nil, err
	}
	if err := network.SetGroupTrafficPolicy(policy); err != nil {
		return nil, err
	}
	if err := s.networkRepo.Save(network); err != nil {
		return nil, err
	}
	s.appendAudit(requestorID, networkID, "network.group_traffic_updated", fmt.Sprintf("%s:%s", networkID.String(), network.GroupTrafficPolicy))
	return network, nil
}

func (s *NetworkService) UpdateFileTransferPolicy(requestorID UserID, networkID NetworkID, enabled bool, maxBytes int64) (*Network, error) {
	network, err := s.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(requestorID, NetworkOperationUpdateFileTransfers); err != nil {
		return nil, err
	}
	if err := network.SetFileTransferPolicy(enabled, maxBytes); err != nil {
		return nil, err
	}
	if err := s.networkRepo.Save(network); err != nil {
		return nil, err
	}
	s.appendAudit(requestorID, networkID, "network.file_transfer_policy_updated", fmt.Sprintf("%s:%t:%d", networkID.String(), network.FileTransfersEnabled, network.FileTransferMaxBytes))
	return network, nil
}

func (s *NetworkService) DeleteNetwork(requestorID UserID, networkID NetworkID) error {
	network, err := s.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return ErrNotFound
	}
	if err := network.AuthorizeOperation(requestorID, NetworkOperationDeleteNetwork); err != nil {
		return err
	}
	s.appendAudit(requestorID, networkID, "network.deleted", networkID.String())
	return s.networkRepo.Delete(networkID)
}

func (s *NetworkService) JoinByInvite(userID UserID, code string, nowUnix int64) (*Network, error) {
	invite, err := s.inviteRepo.FindByCode(code)
	if err != nil || invite == nil {
		return nil, ErrNotFound
	}
	if err := invite.UseOnce(nowUnix); err != nil {
		return nil, err
	}
	network, err := s.networkRepo.FindByID(invite.NetworkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AddMember(userID); err != nil && !errors.Is(err, ErrUserAlreadyMember) {
		return nil, err
	}
	if err := s.networkRepo.Save(network); err != nil {
		return nil, err
	}
	if err := s.inviteRepo.Save(invite); err != nil {
		return nil, err
	}
	s.appendAudit(userID, network.ID, "network.joined", network.ID.String())
	return network, nil
}

func (s *NetworkService) AddMember(ownerID UserID, networkID NetworkID, memberID UserID) error {
	network, err := s.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return ErrNotFound
	}
	if err := network.AuthorizeOperation(ownerID, NetworkOperationAddMember); err != nil {
		return err
	}
	if err := network.AddMember(memberID); err != nil {
		return err
	}
	if err := s.networkRepo.Save(network); err != nil {
		return err
	}
	s.appendAudit(ownerID, networkID, "network.member_added", memberID.String())
	return nil
}

func (s *NetworkService) ApproveDevice(requestorID UserID, networkID NetworkID, deviceID DeviceID, nowUnix int64) (*Network, error) {
	network, err := s.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(requestorID, NetworkOperationApproveDevice); err != nil {
		return nil, err
	}
	network.ApproveDevice(deviceID)
	if err := s.networkRepo.Save(network); err != nil {
		return nil, err
	}
	s.appendAudit(requestorID, networkID, "network.device_approved", fmt.Sprintf("%s:%s:%d", networkID.String(), deviceID.String(), nowUnix))
	return network, nil
}

func (s *NetworkService) RevokeDeviceApproval(requestorID UserID, networkID NetworkID, deviceID DeviceID, nowUnix int64) (*Network, error) {
	network, err := s.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(requestorID, NetworkOperationRevokeDeviceApproval); err != nil {
		return nil, err
	}
	network.RevokeDeviceApproval(deviceID)
	if err := s.networkRepo.Save(network); err != nil {
		return nil, err
	}
	s.appendAudit(requestorID, networkID, "network.device_approval_revoked", fmt.Sprintf("%s:%s:%d", networkID.String(), deviceID.String(), nowUnix))
	return network, nil
}

func (s *NetworkService) RemoveMember(ownerID UserID, networkID NetworkID, memberID UserID) error {
	network, err := s.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return ErrNotFound
	}
	if err := network.AuthorizeOperation(ownerID, NetworkOperationRemoveMember); err != nil {
		return err
	}
	if memberID == network.OwnerID {
		return ErrOnlyOwnerCanManage
	}
	if err := network.RemoveMember(memberID); err != nil {
		return err
	}
	if err := s.networkRepo.Save(network); err != nil {
		return err
	}
	s.appendAudit(ownerID, networkID, "network.member_removed", memberID.String())
	return nil
}

func (s *NetworkService) GenerateInvite(ownerID UserID, networkID NetworkID, ttlSec int64, maxUses int, nowUnix int64) (*Invite, error) {
	network, err := s.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(ownerID, NetworkOperationGenerateInvite); err != nil {
		return nil, err
	}
	invite := &Invite{
		Code:          secureToken("inv"),
		NetworkID:     networkID,
		ExpiresAtUnix: nowUnix + ttlSec,
		MaxUses:       maxUses,
	}
	if err := s.inviteRepo.Save(invite); err != nil {
		return nil, err
	}
	s.appendAudit(ownerID, networkID, "network.invite_generated", "invitation created")
	return invite, nil
}

func (s *NetworkService) ChangeMemberRole(requestorID UserID, networkID NetworkID, memberID UserID, role NetworkRole) error {
	network, err := s.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return ErrNotFound
	}
	if err := network.AuthorizeOperation(requestorID, NetworkOperationChangeMemberRole); err != nil {
		return err
	}
	if err := network.ChangeMemberRole(requestorID, memberID, role); err != nil {
		return err
	}
	if err := s.networkRepo.Save(network); err != nil {
		return err
	}
	s.appendAudit(requestorID, networkID, "network.member_role_changed", memberID.String()+":"+string(role))
	return nil
}

func (s *NetworkService) appendAudit(userID UserID, networkID NetworkID, eventType, details string) {
	if s.auditRepo == nil {
		return
	}
	_ = s.auditRepo.Append(&AuditEvent{
		ID:            nextID("aud"),
		ActorUserID:   userID,
		NetworkID:     networkID,
		Type:          eventType,
		Details:       details,
		CreatedAtUnix: time.Now().Unix(),
	})
}

type PeerDirectory struct {
	userRepo          UserRepo
	peerRepo          PeerRepo
	networkRepo       NetworkRepo
	virtualIPPoolRepo VirtualIPPoolRepo
	deviceRepo        DeviceRepo
	auditRepo         AuditRepo
}

func NewPeerDirectory(peerRepo PeerRepo, networkRepo NetworkRepo, virtualIPPoolRepo VirtualIPPoolRepo, deviceRepo DeviceRepo, auditRepo AuditRepo, users ...UserRepo) *PeerDirectory {
	var userRepo UserRepo
	if len(users) > 0 {
		userRepo = users[0]
	}
	return &PeerDirectory{
		userRepo:          userRepo,
		peerRepo:          peerRepo,
		networkRepo:       networkRepo,
		virtualIPPoolRepo: virtualIPPoolRepo,
		deviceRepo:        deviceRepo,
		auditRepo:         auditRepo,
	}
}

func (d *PeerDirectory) RegisterPeer(userID UserID, deviceID DeviceID, networkID NetworkID, endpoint string, nowUnix int64) (*Peer, error) {
	network, err := d.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationRegisterPeer); err != nil {
		return nil, err
	}
	if deviceID.String() == "" {
		return nil, fmt.Errorf("device id is required")
	}
	device, err := d.deviceRepo.FindByID(deviceID)
	if err != nil {
		return nil, err
	}
	if device == nil {
		return nil, ErrNotFound
	}
	if device.UserID != userID {
		return nil, ErrUnauthorized
	}
	if !device.IsActive() {
		return nil, ErrDeviceNotActive
	}
	if network.DeviceApprovalRequired && !network.IsOwner(userID) && !network.IsDeviceApproved(deviceID) {
		return nil, ErrDeviceApprovalRequired
	}

	pool, err := d.virtualIPPoolRepo.FindByNetworkID(networkID)
	if err != nil {
		return nil, err
	}
	if pool == nil {
		pool, err = d.allocatePoolForNetwork(networkID)
		if err != nil {
			return nil, err
		}
	}

	peer := &Peer{
		ID:              PeerID{Value: nextID("peer")},
		UserID:          userID,
		DeviceID:        deviceID,
		NetworkID:       networkID,
		Endpoint:        endpoint,
		Status:          PeerStatusConnecting,
		Reachability:    PeerReachabilityUnknown,
		ConnectionState: ConnectionStateIdle,
		LastSeenUnix:    nowUnix,
	}
	ip, err := pool.Allocate(peer.ID)
	if err != nil {
		return nil, err
	}
	peer.SetOverlayCIDR(pool.CIDR)
	peer.AssignVirtualIP(ip)
	peer.MarkOnline(nowUnix)

	if err := d.peerRepo.Save(peer); err != nil {
		return nil, err
	}
	if err := d.virtualIPPoolRepo.Save(pool); err != nil {
		return nil, err
	}
	d.appendAudit(userID, peer.NetworkID, "peer.registered", peer.ID.String())
	return peer, nil
}

func (d *PeerDirectory) Heartbeat(peerID PeerID, endpoint string, nowUnix int64) error {
	peer, err := d.peerRepo.FindByID(peerID)
	if err != nil || peer == nil {
		return ErrNotFound
	}
	peer.UpdateEndpoint(endpoint)
	peer.MarkOnline(nowUnix)
	if err := d.peerRepo.Save(peer); err != nil {
		return err
	}
	d.appendAudit(peer.UserID, peer.NetworkID, "peer.heartbeat", peer.ID.String())
	return nil
}

func (d *PeerDirectory) GetOwnedPeer(userID UserID, peerID PeerID) (*Peer, error) {
	peer, err := d.peerRepo.FindByID(peerID)
	if err != nil || peer == nil {
		return nil, ErrNotFound
	}
	if peer.UserID != userID {
		return nil, ErrUnauthorized
	}
	if err := d.attachOverlayCIDR(peer); err != nil {
		return nil, err
	}
	return peer, nil
}

func (d *PeerDirectory) getOwnedPeerForOperation(userID UserID, peerID PeerID, operation NetworkOperation) (*Peer, error) {
	peer, err := d.GetOwnedPeer(userID, peerID)
	if err != nil {
		return nil, err
	}
	network, err := d.networkRepo.FindByID(peer.NetworkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, operation); err != nil {
		return nil, err
	}
	return peer, nil
}

func (d *PeerDirectory) HeartbeatForUser(userID UserID, peerID PeerID, endpoint string, nowUnix int64) error {
	if _, err := d.getOwnedPeerForOperation(userID, peerID, NetworkOperationHeartbeatPeer); err != nil {
		return err
	}
	return d.Heartbeat(peerID, endpoint, nowUnix)
}

func (d *PeerDirectory) ListPeers(networkID NetworkID) ([]*Peer, error) {
	peers, err := d.peerRepo.ListByNetwork(networkID)
	if err != nil {
		return nil, err
	}
	for _, peer := range peers {
		if err := d.attachOverlayCIDR(peer); err != nil {
			return nil, err
		}
	}
	return peers, nil
}

func (d *PeerDirectory) ListPeersForUser(userID UserID, networkID NetworkID) ([]*Peer, error) {
	network, err := d.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationViewPeers); err != nil {
		return nil, err
	}
	return d.ListPeers(networkID)
}

func (d *PeerDirectory) GetPeer(peerID PeerID) (*Peer, error) {
	peer, err := d.peerRepo.FindByID(peerID)
	if err != nil || peer == nil {
		return nil, ErrNotFound
	}
	if err := d.attachOverlayCIDR(peer); err != nil {
		return nil, err
	}
	return peer, nil
}

func (d *PeerDirectory) GetPeerForUser(userID UserID, peerID PeerID) (*Peer, error) {
	peer, err := d.GetPeer(peerID)
	if err != nil {
		return nil, err
	}
	network, err := d.networkRepo.FindByID(peer.NetworkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationViewPeer); err != nil {
		return nil, err
	}
	return peer, nil
}

func (d *PeerDirectory) Disconnect(peerID PeerID, nowUnix int64) error {
	peer, err := d.peerRepo.FindByID(peerID)
	if err != nil || peer == nil {
		return ErrNotFound
	}
	peer.MarkOffline(nowUnix)
	peer.UpdateReachability(PeerReachabilityUnknown, ConnectionStateIdle, nowUnix)
	if err := d.peerRepo.Save(peer); err != nil {
		return err
	}
	d.appendAudit(peer.UserID, peer.NetworkID, "peer.disconnected", peer.ID.String())
	return nil
}

func (d *PeerDirectory) DisconnectForUser(userID UserID, peerID PeerID, nowUnix int64) error {
	if _, err := d.getOwnedPeerForOperation(userID, peerID, NetworkOperationDisconnectPeer); err != nil {
		return err
	}
	return d.Disconnect(peerID, nowUnix)
}

func (d *PeerDirectory) CleanupStalePeers(nowUnix, ttlSec int64) error {
	if d == nil || d.networkRepo == nil || d.peerRepo == nil || ttlSec <= 0 {
		return nil
	}
	networks, err := d.networkRepo.List()
	if err != nil {
		return err
	}
	for _, network := range networks {
		if network == nil {
			continue
		}
		peers, err := d.peerRepo.ListByNetwork(network.ID)
		if err != nil {
			return err
		}
		for _, peer := range peers {
			if peer == nil || peer.Status == PeerStatusOffline || !peer.IsStale(nowUnix, ttlSec) {
				continue
			}
			peer.Status = PeerStatusOffline
			peer.Reachability = PeerReachabilityUnknown
			peer.ConnectionState = ConnectionStateIdle
			if err := d.peerRepo.Save(peer); err != nil {
				return err
			}
			d.appendAudit(peer.UserID, peer.NetworkID, "peer.expired", fmt.Sprintf("%s:%d", peer.ID.String(), peer.LastSeenUnix))
		}
	}
	return nil
}

func (d *PeerDirectory) UpdateSignaling(userID UserID, peerID PeerID, reachability PeerReachability, connectionState ConnectionState, nowUnix int64) (*Peer, error) {
	peer, err := d.getOwnedPeerForOperation(userID, peerID, NetworkOperationUpdatePeerSignaling)
	if err != nil {
		return nil, err
	}
	peer.UpdateReachability(reachability, connectionState, nowUnix)
	if err := d.peerRepo.Save(peer); err != nil {
		return nil, err
	}
	d.appendAudit(peer.UserID, peer.NetworkID, "peer.signaling_updated", peer.ID.String()+":"+string(peer.Reachability)+":"+string(peer.ConnectionState))
	return peer, nil
}

func (d *PeerDirectory) appendAudit(userID UserID, networkID NetworkID, eventType, details string) {
	if d.auditRepo == nil {
		return
	}
	_ = d.auditRepo.Append(&AuditEvent{
		ID:            nextID("aud"),
		ActorUserID:   userID,
		NetworkID:     networkID,
		Type:          eventType,
		Details:       details,
		CreatedAtUnix: time.Now().Unix(),
	})
}

type SignalingService struct {
	peerRepo      PeerRepo
	networkRepo   NetworkRepo
	candidateRepo SignalCandidateRepo
	auditRepo     AuditRepo
}

func NewSignalingService(peerRepo PeerRepo, networkRepo NetworkRepo, candidateRepo SignalCandidateRepo, auditRepo AuditRepo) *SignalingService {
	return &SignalingService{
		peerRepo:      peerRepo,
		networkRepo:   networkRepo,
		candidateRepo: candidateRepo,
		auditRepo:     auditRepo,
	}
}

func (s *SignalingService) PublishCandidate(userID UserID, peerID PeerID, candidateType SignalCandidateType, protocol SignalCandidateProtocol, address string, preference int, reachable bool, ttlSec int64, nowUnix int64) (*SignalCandidate, error) {
	peer, err := s.peerRepo.FindByID(peerID)
	if err != nil || peer == nil {
		return nil, ErrNotFound
	}
	if peer.UserID != userID {
		return nil, ErrUnauthorized
	}
	network, err := s.networkRepo.FindByID(peer.NetworkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationPublishCandidate); err != nil {
		return nil, err
	}
	if ttlSec <= 0 {
		ttlSec = 120
	}
	candidate := &SignalCandidate{
		ID:            nextID("cand"),
		PeerID:        peer.ID,
		NetworkID:     peer.NetworkID,
		Type:          candidateType,
		Protocol:      protocol,
		Address:       strings.TrimSpace(address),
		Preference:    preference,
		Reachable:     reachable,
		CreatedAtUnix: nowUnix,
		ExpiresAtUnix: nowUnix + ttlSec,
	}
	if candidate.Type == "" {
		candidate.Type = SignalCandidateTypeHost
	}
	if candidate.Protocol == "" {
		candidate.Protocol = SignalCandidateProtocolUDP
	}
	if candidate.Address == "" {
		return nil, fmt.Errorf("candidate address is required")
	}
	if err := s.candidateRepo.Save(candidate); err != nil {
		return nil, err
	}
	if s.auditRepo != nil {
		_ = s.auditRepo.Append(&AuditEvent{
			ID:            nextID("aud"),
			ActorUserID:   userID,
			NetworkID:     peer.NetworkID,
			Type:          "signal.candidate_published",
			Details:       peerID.String(),
			CreatedAtUnix: nowUnix,
		})
	}
	return candidate, nil
}

func (s *SignalingService) ListCandidates(userID UserID, peerID PeerID, nowUnix int64) ([]*SignalCandidate, error) {
	peer, err := s.peerRepo.FindByID(peerID)
	if err != nil || peer == nil {
		return nil, ErrNotFound
	}
	network, err := s.networkRepo.FindByID(peer.NetworkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationListCandidates); err != nil {
		return nil, err
	}
	candidates, err := s.candidateRepo.ListByPeerID(peerID)
	if err != nil {
		return nil, err
	}
	active := make([]*SignalCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if !candidate.IsExpired(nowUnix) {
			active = append(active, candidate)
		}
	}
	return active, nil
}

type TunnelCoordinator struct {
	tunnelRepo  TunnelRepo
	peerRepo    PeerRepo
	networkRepo NetworkRepo
	auditRepo   AuditRepo
}

func NewTunnelCoordinator(tunnelRepo TunnelRepo, peerRepo PeerRepo, auditRepo AuditRepo, networkRepo ...NetworkRepo) *TunnelCoordinator {
	var scopedNetworkRepo NetworkRepo
	if len(networkRepo) > 0 {
		scopedNetworkRepo = networkRepo[0]
	}
	return &TunnelCoordinator{tunnelRepo: tunnelRepo, peerRepo: peerRepo, networkRepo: scopedNetworkRepo, auditRepo: auditRepo}
}

func (c *TunnelCoordinator) RequestTunnel(networkID NetworkID, a, b PeerID, preferredMode TunnelMode, nowUnix int64) (*Tunnel, error) {
	peerA, peerB, err := c.tunnelPeers(networkID, a, b)
	if err != nil {
		return nil, err
	}
	return c.requestTunnel(networkID, peerA, peerB, preferredMode, nowUnix)
}

func (c *TunnelCoordinator) requestTunnel(networkID NetworkID, peerA, peerB *Peer, preferredMode TunnelMode, nowUnix int64) (*Tunnel, error) {
	mode := preferredMode
	if mode == "" {
		mode = c.ChooseMode(peerA.Endpoint, peerB.Endpoint)
	}
	if mode != TunnelModeP2P && mode != TunnelModeRelay {
		return nil, fmt.Errorf("tunnel mode must be P2P or RELAY")
	}
	a, b := peerA.ID, peerB.ID
	existing, err := c.tunnelRepo.FindByPeers(networkID, a, b)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		existing.BeginNegotiation(mode)
		if err := c.tunnelRepo.Save(existing); err != nil {
			return nil, err
		}
		c.appendAudit(peerA.UserID, networkID, "tunnel.negotiation_updated", existing.ID.String()+":"+string(existing.Mode))
		return existing, nil
	}
	tunnel := &Tunnel{
		ID:            TunnelID{Value: nextID("tun")},
		NetworkID:     networkID,
		A:             a,
		B:             b,
		CreatedAtUnix: nowUnix,
	}
	tunnel.BeginNegotiation(mode)
	if err := c.tunnelRepo.Save(tunnel); err != nil {
		return nil, err
	}
	c.appendAudit(peerA.UserID, networkID, "tunnel.negotiation_started", tunnel.ID.String()+":"+string(tunnel.Mode))
	return tunnel, nil
}

func (c *TunnelCoordinator) RequestTunnelForUser(userID UserID, networkID NetworkID, a, b PeerID, preferredMode TunnelMode, nowUnix int64) (*Tunnel, error) {
	if c.networkRepo == nil {
		return nil, ErrUnauthorized
	}
	network, err := c.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationRequestTunnel); err != nil {
		return nil, err
	}
	peerA, peerB, err := c.tunnelPeers(networkID, a, b)
	if err != nil {
		return nil, err
	}
	if peerA.UserID != userID && peerB.UserID != userID {
		return nil, ErrUnauthorized
	}
	return c.requestTunnel(networkID, peerA, peerB, preferredMode, nowUnix)
}

func (c *TunnelCoordinator) CloseTunnel(tunnelID TunnelID) error {
	tunnel, err := c.tunnelRepo.FindByID(tunnelID)
	if err != nil || tunnel == nil {
		return ErrNotFound
	}
	tunnel.Close()
	return c.tunnelRepo.Save(tunnel)
}

func (c *TunnelCoordinator) CloseTunnelForUser(userID UserID, tunnelID TunnelID) error {
	if _, err := c.authorizeTunnelOperation(userID, tunnelID, NetworkOperationUpdateTunnelState); err != nil {
		return err
	}
	return c.CloseTunnel(tunnelID)
}

func (c *TunnelCoordinator) MarkFailed(tunnelID TunnelID) error {
	tunnel, err := c.tunnelRepo.FindByID(tunnelID)
	if err != nil || tunnel == nil {
		return ErrNotFound
	}
	tunnel.MarkFailed()
	return c.tunnelRepo.Save(tunnel)
}

func (c *TunnelCoordinator) MarkFailedForUser(userID UserID, tunnelID TunnelID) error {
	if _, err := c.authorizeTunnelOperation(userID, tunnelID, NetworkOperationUpdateTunnelState); err != nil {
		return err
	}
	return c.MarkFailed(tunnelID)
}

func (c *TunnelCoordinator) OpenTunnel(tunnelID TunnelID) error {
	tunnel, err := c.tunnelRepo.FindByID(tunnelID)
	if err != nil || tunnel == nil {
		return ErrNotFound
	}
	if _, _, err := c.tunnelPeers(tunnel.NetworkID, tunnel.A, tunnel.B); err != nil {
		return err
	}
	if tunnel.Mode != TunnelModeP2P && tunnel.Mode != TunnelModeRelay {
		return fmt.Errorf("tunnel mode must be P2P or RELAY")
	}
	tunnel.Open(tunnel.Mode)
	return c.tunnelRepo.Save(tunnel)
}

func (c *TunnelCoordinator) OpenTunnelForUser(userID UserID, tunnelID TunnelID) error {
	if _, err := c.authorizeTunnelOperation(userID, tunnelID, NetworkOperationUpdateTunnelState); err != nil {
		return err
	}
	return c.OpenTunnel(tunnelID)
}

func (c *TunnelCoordinator) ChooseMode(aEndpoint, bEndpoint string) TunnelMode {
	if strings.TrimSpace(aEndpoint) != "" && strings.TrimSpace(bEndpoint) != "" {
		return TunnelModeP2P
	}
	return TunnelModeRelay
}

func (c *TunnelCoordinator) ListTunnels(networkID NetworkID) ([]*Tunnel, error) {
	return c.tunnelRepo.ListByNetwork(networkID)
}

func (c *TunnelCoordinator) ListTunnelsForUser(userID UserID, networkID NetworkID) ([]*Tunnel, error) {
	if c.networkRepo == nil {
		return nil, ErrUnauthorized
	}
	network, err := c.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationViewTunnels); err != nil {
		return nil, err
	}
	return c.ListTunnels(networkID)
}

func (c *TunnelCoordinator) GetTunnelForUser(userID UserID, tunnelID TunnelID) (*Tunnel, error) {
	if c.networkRepo == nil {
		return nil, ErrUnauthorized
	}
	tunnel, err := c.tunnelRepo.FindByID(tunnelID)
	if err != nil || tunnel == nil {
		return nil, ErrNotFound
	}
	network, err := c.networkRepo.FindByID(tunnel.NetworkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationViewTunnel); err != nil {
		return nil, err
	}
	return tunnel, nil
}

func (c *TunnelCoordinator) authorizeTunnelOperation(userID UserID, tunnelID TunnelID, operation NetworkOperation) (*Tunnel, error) {
	tunnel, err := c.tunnelRepo.FindByID(tunnelID)
	if err != nil || tunnel == nil {
		return nil, ErrNotFound
	}
	if c.networkRepo == nil {
		return nil, ErrUnauthorized
	}
	network, err := c.networkRepo.FindByID(tunnel.NetworkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, operation); err != nil {
		return nil, err
	}
	peerA, peerB, err := c.tunnelPeers(tunnel.NetworkID, tunnel.A, tunnel.B)
	if err != nil {
		return nil, err
	}
	if peerA.UserID != userID && peerB.UserID != userID {
		return nil, ErrUnauthorized
	}
	return tunnel, nil
}

func (c *TunnelCoordinator) appendAudit(userID UserID, networkID NetworkID, eventType, details string) {
	if c.auditRepo == nil {
		return
	}
	_ = c.auditRepo.Append(&AuditEvent{
		ID:            nextID("aud"),
		ActorUserID:   userID,
		NetworkID:     networkID,
		Type:          eventType,
		Details:       details,
		CreatedAtUnix: time.Now().Unix(),
	})
}

type MessagingService struct {
	messageRepo MessageRepo
	peerRepo    PeerRepo
	networkRepo NetworkRepo
	auditRepo   AuditRepo
}

func NewMessagingService(messageRepo MessageRepo, peerRepo PeerRepo, networkRepo NetworkRepo, auditRepo AuditRepo) *MessagingService {
	return &MessagingService{
		messageRepo: messageRepo,
		peerRepo:    peerRepo,
		networkRepo: networkRepo,
		auditRepo:   auditRepo,
	}
}

func (s *MessagingService) SendMessage(userID UserID, networkID NetworkID, fromPeerID PeerID, text string, nowUnix int64) (*Message, error) {
	network, err := s.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationSendMessage); err != nil {
		return nil, err
	}
	peer, err := s.peerRepo.FindByID(fromPeerID)
	if err != nil || peer == nil {
		return nil, ErrNotFound
	}
	if peer.NetworkID != networkID {
		return nil, ErrUnauthorized
	}
	if peer.UserID != userID {
		return nil, ErrUnauthorized
	}

	message := &Message{
		ID:         nextID("msg"),
		NetworkID:  networkID,
		FromPeerID: fromPeerID,
		Text:       strings.TrimSpace(text),
		SentAtUnix: nowUnix,
	}
	if err := message.Validate(); err != nil {
		return nil, err
	}
	if err := s.messageRepo.Save(message); err != nil {
		return nil, err
	}
	s.appendAudit(userID, networkID, "message.sent", message.ID)
	return message, nil
}

func (s *MessagingService) ListMessagesForUser(userID UserID, networkID NetworkID) ([]*Message, error) {
	network, err := s.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationViewMessages); err != nil {
		return nil, err
	}
	return s.messageRepo.ListByNetwork(networkID)
}

func (s *MessagingService) GetMessageForUser(userID UserID, messageID string) (*Message, error) {
	message, err := s.messageRepo.FindByID(messageID)
	if err != nil || message == nil {
		return nil, ErrNotFound
	}
	network, err := s.networkRepo.FindByID(message.NetworkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationViewMessages); err != nil {
		return nil, err
	}
	return message, nil
}

func (s *MessagingService) appendAudit(userID UserID, networkID NetworkID, eventType, details string) {
	if s.auditRepo == nil {
		return
	}
	_ = s.auditRepo.Append(&AuditEvent{
		ID:            nextID("aud"),
		ActorUserID:   userID,
		NetworkID:     networkID,
		Type:          eventType,
		Details:       details,
		CreatedAtUnix: time.Now().Unix(),
	})
}

type FileTransferService struct {
	fileTransferRepo        FileTransferRepo
	payloadRepo             FileTransferPayloadRepo
	peerRepo                PeerRepo
	networkRepo             NetworkRepo
	auditRepo               AuditRepo
	maxPayloadBytes         int64
	maxMirroredPayloadBytes int64
	maxChunkBytes           int64
}

func NewFileTransferService(fileTransferRepo FileTransferRepo, peerRepo PeerRepo, networkRepo NetworkRepo, auditRepo AuditRepo, payloadRepo ...FileTransferPayloadRepo) *FileTransferService {
	var scopedPayloadRepo FileTransferPayloadRepo
	if len(payloadRepo) > 0 {
		scopedPayloadRepo = payloadRepo[0]
	}
	return &FileTransferService{
		fileTransferRepo:        fileTransferRepo,
		payloadRepo:             scopedPayloadRepo,
		peerRepo:                peerRepo,
		networkRepo:             networkRepo,
		auditRepo:               auditRepo,
		maxPayloadBytes:         DefaultControlPlaneFileTransferPayloadMaxBytes,
		maxMirroredPayloadBytes: DefaultMirroredFileTransferPayloadMaxBytes,
		maxChunkBytes:           MaxFileTransferChunkBytes,
	}
}

func (s *FileTransferService) CreateTransfer(userID UserID, networkID NetworkID, fromPeerID, toPeerID PeerID, fileName string, sizeBytes int64) (*FileTransfer, error) {
	network, err := s.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationCreateFileTransfer); err != nil {
		return nil, err
	}
	if !network.FileTransfersEnabled {
		return nil, ErrFileTransfersDisabled
	}
	if network.FileTransferMaxBytes > 0 && sizeBytes > network.FileTransferMaxBytes {
		return nil, ErrTransferPolicyExceeded
	}
	fromPeer, err := s.peerRepo.FindByID(fromPeerID)
	if err != nil || fromPeer == nil {
		return nil, ErrNotFound
	}
	toPeer, err := s.peerRepo.FindByID(toPeerID)
	if err != nil || toPeer == nil {
		return nil, ErrNotFound
	}
	if fromPeer.NetworkID != networkID || toPeer.NetworkID != networkID {
		return nil, ErrUnauthorized
	}
	if fromPeer.UserID != userID {
		return nil, ErrUnauthorized
	}
	if strings.TrimSpace(fileName) == "" || sizeBytes < 0 {
		return nil, fmt.Errorf("file name and size are required")
	}

	transfer := &FileTransfer{
		ID:              nextID("xfer"),
		NetworkID:       networkID,
		FromPeerID:      fromPeerID,
		FromUserID:      fromPeer.UserID,
		ToPeerID:        toPeerID,
		ToUserID:        toPeer.UserID,
		FileName:        strings.TrimSpace(fileName),
		SizeBytes:       sizeBytes,
		Status:          TransferStatusInit,
		ProgressPercent: 0,
	}
	if err := s.fileTransferRepo.Save(transfer); err != nil {
		return nil, err
	}
	s.appendAudit(userID, networkID, "file_transfer.created", transfer.ID)
	return transfer, nil
}

func (s *FileTransferService) ListTransfersForUser(userID UserID, networkID NetworkID) ([]*FileTransfer, error) {
	network, err := s.networkRepo.FindByID(networkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationViewFileTransfers); err != nil {
		return nil, err
	}
	return s.fileTransferRepo.ListByNetwork(networkID)
}

func (s *FileTransferService) GetTransferForUser(userID UserID, transferID string) (*FileTransfer, error) {
	transfer, err := s.fileTransferRepo.FindByID(transferID)
	if err != nil || transfer == nil {
		return nil, ErrNotFound
	}
	network, err := s.networkRepo.FindByID(transfer.NetworkID)
	if err != nil || network == nil {
		return nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationViewFileTransfers); err != nil {
		return nil, err
	}
	return transfer, nil
}

func (s *FileTransferService) AcceptTransfer(userID UserID, transferID string) (*FileTransfer, error) {
	transfer, network, err := s.getAuthorizedTransfer(userID, transferID, NetworkOperationAcceptFileTransfer, true)
	if err != nil {
		return nil, err
	}
	transfer.Accept()
	if err := s.fileTransferRepo.Save(transfer); err != nil {
		return nil, err
	}
	s.appendAudit(userID, network.ID, "file_transfer.accepted", transfer.ID)
	return transfer, nil
}

func (s *FileTransferService) CancelTransfer(userID UserID, transferID, reason string) (*FileTransfer, error) {
	transfer, network, err := s.getAuthorizedTransfer(userID, transferID, NetworkOperationCancelFileTransfer, false)
	if err != nil {
		return nil, err
	}
	transfer.Cancel(reason)
	if err := s.fileTransferRepo.Save(transfer); err != nil {
		return nil, err
	}
	s.appendAudit(userID, network.ID, "file_transfer.canceled", transfer.ID)
	return transfer, nil
}

func (s *FileTransferService) UpdateTransferProgress(userID UserID, transferID string, percent int) (*FileTransfer, error) {
	transfer, network, err := s.getAuthorizedTransfer(userID, transferID, NetworkOperationUpdateTransferProgress, false)
	if err != nil {
		return nil, err
	}
	if err := transfer.Progress(percent); err != nil {
		return nil, err
	}
	if err := s.fileTransferRepo.Save(transfer); err != nil {
		return nil, err
	}
	s.appendAudit(userID, network.ID, "file_transfer.progress_updated", fmt.Sprintf("%s:%d", transfer.ID, percent))
	return transfer, nil
}

func (s *FileTransferService) UploadTransferPayload(userID UserID, transferID, contentType string, payload []byte, nowUnix int64) (*FileTransfer, error) {
	transfer, err := s.UploadTransferPayloadChunk(userID, transferID, contentType, 0, payload, nowUnix)
	if err != nil {
		return nil, err
	}
	if !transfer.PayloadReady {
		return nil, fmt.Errorf("file transfer payload upload is incomplete")
	}
	return transfer, nil
}

func (s *FileTransferService) UploadTransferPayloadChunk(userID UserID, transferID, contentType string, offsetBytes int64, payload []byte, nowUnix int64) (*FileTransfer, error) {
	if s.payloadRepo == nil {
		return nil, fmt.Errorf("file transfer payload storage is not configured")
	}
	transfer, network, err := s.getAuthorizedTransferForUpload(userID, transferID, NetworkOperationUploadFileTransferContent)
	if err != nil {
		return nil, err
	}
	if transfer.IsTerminal() {
		return nil, fmt.Errorf("cannot upload payload for a terminal file transfer")
	}
	if !network.FileTransfersEnabled {
		return nil, ErrFileTransfersDisabled
	}
	if offsetBytes < 0 {
		return nil, ErrTransferPayloadOffsetMismatch
	}
	if s.maxChunkBytes > 0 && int64(len(payload)) > s.maxChunkBytes {
		return nil, ErrTransferPayloadTooLarge
	}
	if network.FileTransferMaxBytes > 0 && transfer.SizeBytes > network.FileTransferMaxBytes {
		return nil, ErrTransferPolicyExceeded
	}
	if s.maxPayloadBytes > 0 && transfer.SizeBytes > s.maxPayloadBytes {
		receiverMirrorUpload, err := s.receiverMayMirrorTransferPayload(userID, transfer)
		if err != nil {
			return nil, err
		}
		if !receiverMirrorUpload || (s.maxMirroredPayloadBytes > 0 && transfer.SizeBytes > s.maxMirroredPayloadBytes) {
			return nil, ErrTransferPayloadTooLarge
		}
	}
	storedPayload, err := s.payloadRepo.FindByTransferID(transfer.ID)
	if err != nil {
		return nil, err
	}
	currentPayload := []byte(nil)
	if storedPayload != nil {
		currentPayload = append(currentPayload, storedPayload.Payload...)
	}
	if int64(len(currentPayload)) != transfer.PayloadUploadedBytes {
		transfer.PayloadUploadedBytes = int64(len(currentPayload))
	}
	if offsetBytes != int64(len(currentPayload)) {
		return nil, ErrTransferPayloadOffsetMismatch
	}
	if offsetBytes+int64(len(payload)) > transfer.SizeBytes {
		return nil, fmt.Errorf("file transfer payload size mismatch: expected %d bytes, got %d", transfer.SizeBytes, offsetBytes+int64(len(payload)))
	}
	currentPayload = append(currentPayload, payload...)
	checksum := sha256.Sum256(currentPayload)
	checksumHex := hex.EncodeToString(checksum[:])
	if transfer.PayloadReady {
		if strings.EqualFold(strings.TrimSpace(transfer.PayloadSHA256), checksumHex) && offsetBytes+int64(len(payload)) == transfer.SizeBytes {
			return transfer, nil
		}
		return nil, ErrTransferPayloadUploaded
	}

	storedPayload = &FileTransferPayload{
		TransferID:       transfer.ID,
		ContentType:      normalizeTransferContentType(contentType),
		SizeBytes:        int64(len(currentPayload)),
		SHA256:           "",
		Payload:          append([]byte(nil), currentPayload...),
		UploadedAtUnix:   0,
		DownloadedAtUnix: transfer.DownloadedAtUnix,
	}
	if int64(len(currentPayload)) == transfer.SizeBytes {
		storedPayload.SHA256 = checksumHex
		storedPayload.UploadedAtUnix = nowUnix
	}
	if err := s.payloadRepo.Save(storedPayload); err != nil {
		return nil, err
	}

	transfer.UpdatePayloadUploadState(storedPayload.ContentType, int64(len(currentPayload)))
	if int64(len(currentPayload)) == transfer.SizeBytes {
		transfer.AttachPayload(storedPayload.ContentType, checksumHex, nowUnix)
	}
	if err := s.fileTransferRepo.Save(transfer); err != nil {
		return nil, err
	}
	if transfer.PayloadReady {
		s.appendAudit(userID, network.ID, "file_transfer.payload_uploaded", transfer.ID)
	} else {
		s.appendAudit(userID, network.ID, "file_transfer.payload_chunk_uploaded", fmt.Sprintf("%s:%d", transfer.ID, transfer.PayloadUploadedBytes))
	}
	return transfer, nil
}

func (s *FileTransferService) DownloadTransferPayload(userID UserID, transferID string, nowUnix int64) (*FileTransferPayload, *FileTransfer, error) {
	if s.payloadRepo == nil {
		return nil, nil, fmt.Errorf("file transfer payload storage is not configured")
	}
	transfer, network, err := s.getAuthorizedTransfer(userID, transferID, NetworkOperationDownloadFileTransferContent, false)
	if err != nil {
		return nil, nil, err
	}
	if !transfer.PayloadReady {
		return nil, nil, ErrTransferPayloadMissing
	}
	payload, err := s.payloadRepo.FindByTransferID(transfer.ID)
	if err != nil {
		return nil, nil, err
	}
	if payload == nil {
		return nil, nil, ErrTransferPayloadMissing
	}

	if receiverOwnsTransfer, ownErr := s.userOwnsTransferParticipant(userID, transfer.ToUserID, transfer.ToPeerID); ownErr != nil {
		return nil, nil, ownErr
	} else if receiverOwnsTransfer && !transfer.IsTerminal() {
		transfer.CompleteDownload(nowUnix)
		payload.DownloadedAtUnix = nowUnix
		if err := s.fileTransferRepo.Save(transfer); err != nil {
			return nil, nil, err
		}
	}
	s.appendAudit(userID, network.ID, "file_transfer.payload_downloaded", transfer.ID)
	payload.ContentType = firstNonEmpty(strings.TrimSpace(payload.ContentType), strings.TrimSpace(transfer.ContentType), "application/octet-stream")
	payload.SizeBytes = transfer.SizeBytes
	payload.SHA256 = firstNonEmpty(strings.TrimSpace(payload.SHA256), strings.TrimSpace(transfer.PayloadSHA256))
	payload.DownloadedAtUnix = transfer.DownloadedAtUnix
	return payload, transfer, nil
}

func (s *FileTransferService) DownloadTransferPayloadChunk(userID UserID, transferID string, offsetBytes, limitBytes int64, nowUnix int64) (*FileTransferPayloadChunk, *FileTransfer, error) {
	if s.payloadRepo == nil {
		return nil, nil, fmt.Errorf("file transfer payload storage is not configured")
	}
	transfer, network, err := s.getAuthorizedTransfer(userID, transferID, NetworkOperationDownloadFileTransferContent, false)
	if err != nil {
		return nil, nil, err
	}
	if !transfer.PayloadReady {
		return nil, nil, ErrTransferPayloadMissing
	}
	payload, err := s.payloadRepo.FindByTransferID(transfer.ID)
	if err != nil {
		return nil, nil, err
	}
	if payload == nil {
		return nil, nil, ErrTransferPayloadMissing
	}
	if offsetBytes < 0 || offsetBytes > int64(len(payload.Payload)) {
		return nil, nil, ErrTransferPayloadOffsetMismatch
	}
	if limitBytes <= 0 {
		limitBytes = DefaultFileTransferChunkBytes
	}
	if s.maxChunkBytes > 0 && limitBytes > s.maxChunkBytes {
		return nil, nil, ErrTransferPayloadTooLarge
	}
	end := offsetBytes + limitBytes
	if end > int64(len(payload.Payload)) {
		end = int64(len(payload.Payload))
	}
	chunkBytes := append([]byte(nil), payload.Payload[offsetBytes:end]...)
	complete := end >= int64(len(payload.Payload))
	if receiverOwnsTransfer, ownErr := s.userOwnsTransferParticipant(userID, transfer.ToUserID, transfer.ToPeerID); ownErr != nil {
		return nil, nil, ownErr
	} else if receiverOwnsTransfer && complete && !transfer.IsTerminal() {
		transfer.CompleteDownload(nowUnix)
		payload.DownloadedAtUnix = nowUnix
		if err := s.fileTransferRepo.Save(transfer); err != nil {
			return nil, nil, err
		}
	}
	s.appendAudit(userID, network.ID, "file_transfer.payload_chunk_downloaded", fmt.Sprintf("%s:%d:%d", transfer.ID, offsetBytes, end))
	result := &FileTransferPayloadChunk{
		Transfer:         transfer,
		ContentType:      firstNonEmpty(strings.TrimSpace(payload.ContentType), strings.TrimSpace(transfer.ContentType), "application/octet-stream"),
		SHA256:           firstNonEmpty(strings.TrimSpace(payload.SHA256), strings.TrimSpace(transfer.PayloadSHA256)),
		Payload:          chunkBytes,
		OffsetBytes:      offsetBytes,
		NextOffsetBytes:  end,
		TotalSizeBytes:   transfer.SizeBytes,
		UploadedAtUnix:   transfer.UploadedAtUnix,
		DownloadedAtUnix: transfer.DownloadedAtUnix,
		Complete:         complete,
	}
	return result, transfer, nil
}

func (s *FileTransferService) getAuthorizedTransfer(userID UserID, transferID string, operation NetworkOperation, receiverOnly bool) (*FileTransfer, *Network, error) {
	transfer, err := s.fileTransferRepo.FindByID(transferID)
	if err != nil || transfer == nil {
		return nil, nil, ErrNotFound
	}
	network, err := s.networkRepo.FindByID(transfer.NetworkID)
	if err != nil || network == nil {
		return nil, nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationManageFileTransfers); err == nil {
		return transfer, network, nil
	} else if !errors.Is(err, ErrUnauthorized) && !errors.Is(err, ErrInsufficientNetworkRole) {
		return nil, nil, err
	}
	if err := network.AuthorizeOperation(userID, operation); err != nil {
		return nil, nil, err
	}

	ownsFromPeer, err := s.userOwnsTransferParticipant(userID, transfer.FromUserID, transfer.FromPeerID)
	if err != nil {
		return nil, nil, err
	}
	ownsToPeer, err := s.userOwnsTransferParticipant(userID, transfer.ToUserID, transfer.ToPeerID)
	if err != nil {
		return nil, nil, err
	}
	if receiverOnly {
		if ownsToPeer {
			return transfer, network, nil
		}
		return nil, nil, ErrInsufficientNetworkRole
	}
	if ownsFromPeer || ownsToPeer {
		return transfer, network, nil
	}
	return nil, nil, ErrInsufficientNetworkRole
}

func (s *FileTransferService) getAuthorizedTransferForUpload(userID UserID, transferID string, operation NetworkOperation) (*FileTransfer, *Network, error) {
	transfer, err := s.fileTransferRepo.FindByID(transferID)
	if err != nil || transfer == nil {
		return nil, nil, ErrNotFound
	}
	network, err := s.networkRepo.FindByID(transfer.NetworkID)
	if err != nil || network == nil {
		return nil, nil, ErrNotFound
	}
	if err := network.AuthorizeOperation(userID, NetworkOperationManageFileTransfers); err == nil {
		return transfer, network, nil
	} else if !errors.Is(err, ErrUnauthorized) && !errors.Is(err, ErrInsufficientNetworkRole) {
		return nil, nil, err
	}
	if err := network.AuthorizeOperation(userID, operation); err != nil {
		return nil, nil, err
	}
	ownsFromPeer, err := s.userOwnsTransferParticipant(userID, transfer.FromUserID, transfer.FromPeerID)
	if err != nil {
		return nil, nil, err
	}
	if ownsFromPeer {
		return transfer, network, nil
	}
	ownsToPeer, err := s.userOwnsTransferParticipant(userID, transfer.ToUserID, transfer.ToPeerID)
	if err != nil {
		return nil, nil, err
	}
	if ownsToPeer && transfer.Status != TransferStatusInit {
		return transfer, network, nil
	}
	return nil, nil, ErrInsufficientNetworkRole
}

func (s *FileTransferService) userOwnsTransferParticipant(userID, participantUserID UserID, peerID PeerID) (bool, error) {
	if participantUserID.String() != "" {
		return participantUserID == userID, nil
	}
	return s.userOwnsPeer(userID, peerID)
}

func (s *FileTransferService) userOwnsPeer(userID UserID, peerID PeerID) (bool, error) {
	peer, err := s.peerRepo.FindByID(peerID)
	if err != nil {
		return false, err
	}
	if peer == nil {
		return false, ErrNotFound
	}
	return peer.UserID == userID, nil
}

func (s *FileTransferService) receiverMayMirrorTransferPayload(userID UserID, transfer *FileTransfer) (bool, error) {
	if transfer == nil || transfer.Status == TransferStatusInit {
		return false, nil
	}
	return s.userOwnsTransferParticipant(userID, transfer.ToUserID, transfer.ToPeerID)
}

func (s *FileTransferService) appendAudit(userID UserID, networkID NetworkID, eventType, details string) {
	if s.auditRepo == nil {
		return
	}
	_ = s.auditRepo.Append(&AuditEvent{
		ID:            nextID("aud"),
		ActorUserID:   userID,
		NetworkID:     networkID,
		Type:          eventType,
		Details:       details,
		CreatedAtUnix: time.Now().Unix(),
	})
}

func normalizeTransferContentType(contentType string) string {
	contentType = strings.TrimSpace(contentType)
	if contentType == "" {
		return "application/octet-stream"
	}
	return contentType
}

func nextID(prefix string) string {
	// Independent processes must not reuse identifiers after a restart.
	return prefix + "-" + rand.Text()
}

func secureToken(prefix string) string {
	// rand.Text provides at least 128 random bits without a predictable fallback.
	return prefix + "-" + rand.Text()
}

func deriveCIDR(networkID NetworkID) string {
	hash := sha256.Sum256([]byte(networkID.String()))
	index := (int(hash[0]) << 16) | (int(hash[1]) << 8) | int(hash[2])
	return cidrForIndex(index % totalRFC1918PoolCandidates)
}

func (d *PeerDirectory) allocatePoolForNetwork(networkID NetworkID) (*VirtualIPPool, error) {
	if d.virtualIPPoolRepo == nil {
		return NewVirtualIPPool(networkID, deriveCIDR(networkID)), nil
	}
	pools, err := d.virtualIPPoolRepo.List()
	if err != nil {
		return nil, err
	}
	return NewVirtualIPPool(networkID, chooseUniqueCIDR(networkID, pools)), nil
}

func (d *PeerDirectory) attachOverlayCIDR(peer *Peer) error {
	if peer == nil || strings.TrimSpace(peer.OverlayCIDR) != "" || d.virtualIPPoolRepo == nil {
		return nil
	}
	pool, err := d.virtualIPPoolRepo.FindByNetworkID(peer.NetworkID)
	if err != nil || pool == nil {
		return err
	}
	peer.SetOverlayCIDR(pool.CIDR)
	return nil
}

func chooseUniqueCIDR(networkID NetworkID, pools []*VirtualIPPool) string {
	hash := sha256.Sum256([]byte(networkID.String()))
	start := ((int(hash[0]) << 16) | (int(hash[1]) << 8) | int(hash[2])) % totalRFC1918PoolCandidates
	for offset := 0; offset < totalRFC1918PoolCandidates; offset++ {
		index := (start + offset) % totalRFC1918PoolCandidates
		candidate := cidrForIndex(index)
		if !cidrOverlapsPools(candidate, pools) {
			return candidate
		}
	}
	return deriveCIDR(networkID)
}

const (
	total10PoolCandidates      = 1 << 16
	total172PoolCandidates     = 16 << 8
	total192PoolCandidates     = 1 << 8
	totalRFC1918PoolCandidates = total10PoolCandidates + total172PoolCandidates + total192PoolCandidates
)

func cidrForIndex(index int) string {
	if index < 0 {
		index = -index
	}
	index = index % totalRFC1918PoolCandidates
	switch {
	case index < total10PoolCandidates:
		second := (index >> 8) & 0xff
		third := index & 0xff
		return fmt.Sprintf("10.%d.%d.0/24", second, third)
	case index < total10PoolCandidates+total172PoolCandidates:
		index -= total10PoolCandidates
		second := 16 + ((index >> 8) & 0x0f)
		third := index & 0xff
		return fmt.Sprintf("172.%d.%d.0/24", second, third)
	default:
		index -= total10PoolCandidates + total172PoolCandidates
		return fmt.Sprintf("192.168.%d.0/24", index&0xff)
	}
}

func cidrOverlapsPools(candidate string, pools []*VirtualIPPool) bool {
	for _, pool := range pools {
		if pool == nil || strings.TrimSpace(pool.CIDR) == "" {
			continue
		}
		if cidrsOverlap(candidate, pool.CIDR) {
			return true
		}
	}
	return false
}

func cidrsOverlap(left, right string) bool {
	_, leftNet, err := net.ParseCIDR(strings.TrimSpace(left))
	if err != nil || leftNet == nil {
		return false
	}
	_, rightNet, err := net.ParseCIDR(strings.TrimSpace(right))
	if err != nil || rightNet == nil {
		return false
	}
	return leftNet.Contains(rightNet.IP) || rightNet.Contains(leftNet.IP)
}
