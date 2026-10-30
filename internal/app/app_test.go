package app

import (
	"Ole/internal/domain"
	"Ole/internal/store/memory"
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunCleanupCycleRemovesExpiredSessionsAndStaleInvites(t *testing.T) {
	userRepo := memory.NewUserRepo()
	inviteRepo := memory.NewInviteRepo()
	sessionRepo := memory.NewSessionRepo()

	auth := domain.NewAuthService(userRepo, nil, sessionRepo, "test-secret", "ole-test")
	user, err := auth.Register("cleanup@example.com", "secret")
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	session, err := auth.Login(user.Email, "secret", domain.SessionMetadata{DeviceName: "cleanup"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	session.ExpiresAtUnix = 10
	if err := sessionRepo.Update(session); err != nil {
		t.Fatalf("persist expired session: %v", err)
	}

	activeInvite := &domain.Invite{
		Code:          "active",
		NetworkID:     domain.NetworkID{Value: "net-1"},
		ExpiresAtUnix: 100,
		MaxUses:       2,
		Uses:          0,
	}
	expiredInvite := &domain.Invite{
		Code:          "expired",
		NetworkID:     domain.NetworkID{Value: "net-1"},
		ExpiresAtUnix: 10,
		MaxUses:       2,
		Uses:          0,
	}
	exhaustedInvite := &domain.Invite{
		Code:          "exhausted",
		NetworkID:     domain.NetworkID{Value: "net-1"},
		ExpiresAtUnix: 100,
		MaxUses:       1,
		Uses:          1,
	}
	for _, invite := range []*domain.Invite{activeInvite, expiredInvite, exhaustedInvite} {
		if err := inviteRepo.Save(invite); err != nil {
			t.Fatalf("save invite %s: %v", invite.Code, err)
		}
	}

	application := &App{
		AuthService: auth,
		InviteRepo:  inviteRepo,
		SessionRepo: sessionRepo,
	}

	if err := application.RunCleanupCycle(10); err != nil {
		t.Fatalf("run cleanup cycle: %v", err)
	}

	if _, err := auth.ValidateAccessToken(session.AccessToken); err == nil {
		t.Fatalf("expected expired session to be invalid after cleanup")
	}
	if stored, err := sessionRepo.FindByAccessToken(session.AccessToken); err != nil || stored != nil {
		t.Fatalf("expected expired session to be deleted from repo, got %#v err=%v", stored, err)
	}

	if invite, err := inviteRepo.FindByCode(activeInvite.Code); err != nil || invite == nil {
		t.Fatalf("expected active invite to remain, got %#v err=%v", invite, err)
	}
	if invite, err := inviteRepo.FindByCode(expiredInvite.Code); err != nil || invite != nil {
		t.Fatalf("expected expired invite to be deleted, got %#v err=%v", invite, err)
	}
	if invite, err := inviteRepo.FindByCode(exhaustedInvite.Code); err != nil || invite != nil {
		t.Fatalf("expected exhausted invite to be deleted, got %#v err=%v", invite, err)
	}
}

func TestRunCleanupCycleExpiresStalePeers(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	peerRepo := memory.NewPeerRepo()
	sessionRepo := memory.NewSessionRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	devices := domain.NewDeviceService(deviceRepo, auditRepo)
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)
	peers := domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo)

	user, err := auth.Register("cleanup-peer@example.com", "secret")
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	device, err := devices.Enroll(user.ID, "cleanup-device", "cleanup-key", 1)
	if err != nil {
		t.Fatalf("enroll device: %v", err)
	}
	network, err := networks.CreateNetwork(user.ID, "cleanup", domain.NetworkAccessPrivate)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	peer, err := peers.RegisterPeer(user.ID, device.ID, network.ID, "127.0.0.1:4000", 5)
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}
	if _, err := peers.UpdateSignaling(user.ID, peer.ID, domain.PeerReachabilityDirect, domain.ConnectionStateConnected, 6); err != nil {
		t.Fatalf("update signaling: %v", err)
	}

	application := &App{
		AuthService:         auth,
		InviteRepo:          inviteRepo,
		SessionRepo:         sessionRepo,
		PeerDirectory:       peers,
		SignalCandidateRepo: memory.NewSignalCandidateRepo(),
		peerHeartbeatTTL:    time.Minute,
	}

	if err := application.RunCleanupCycle(200); err != nil {
		t.Fatalf("run cleanup cycle: %v", err)
	}

	stored, err := peers.GetPeer(peer.ID)
	if err != nil {
		t.Fatalf("get peer after cleanup: %v", err)
	}
	if stored.Status != domain.PeerStatusOffline || stored.ConnectionState != domain.ConnectionStateIdle {
		t.Fatalf("expected stale peer to be expired by cleanup cycle, got %#v", stored)
	}
}

func TestReadinessSnapshotDefaultsReadyWithoutCheck(t *testing.T) {
	application := &App{}
	snapshot := application.ReadinessSnapshot(context.Background())
	if !snapshot.Ready || !snapshot.DatabaseReachable || snapshot.Error != "" {
		t.Fatalf("expected empty app readiness to be ready, got %#v", snapshot)
	}
}

func TestReadinessSnapshotReportsFailureFromCheck(t *testing.T) {
	application := &App{
		ReadinessCheck: func(context.Context) error {
			return errors.New("database unavailable")
		},
	}
	snapshot := application.ReadinessSnapshot(context.Background())
	if snapshot.Ready || snapshot.DatabaseReachable {
		t.Fatalf("expected readiness failure, got %#v", snapshot)
	}
	if snapshot.Error != "database unavailable" {
		t.Fatalf("expected readiness error detail, got %#v", snapshot)
	}
}
