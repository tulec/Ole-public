package postgres_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/postgres"
	"testing"
)

func TestPostgresTunnelNetworkBoundaries(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()
	auth := domain.NewAuthService(postgres.NewUserRepo(db), nil, nil, "test-secret", "ole-test")
	owner, err := auth.Register("tunnel-owner@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	devices := domain.NewDeviceService(postgres.NewDeviceRepo(db), nil)
	device, err := devices.Enroll(owner.ID, "device", "public-key", 100)
	if err != nil {
		t.Fatal(err)
	}
	networkRepo := postgres.NewNetworkRepo(db)
	networks := domain.NewNetworkService(networkRepo, postgres.NewInviteRepo(db), nil)
	first, err := networks.CreateNetwork(owner.ID, "first", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatal(err)
	}
	second, err := networks.CreateNetwork(owner.ID, "second", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatal(err)
	}
	peerRepo := postgres.NewPeerRepo(db)
	peers := domain.NewPeerDirectory(peerRepo, networkRepo, postgres.NewVirtualIPPoolRepo(db), postgres.NewDeviceRepo(db), nil)
	a, err := peers.RegisterPeer(owner.ID, device.ID, first.ID, "127.0.0.1:10001", 101)
	if err != nil {
		t.Fatal(err)
	}
	b, err := peers.RegisterPeer(owner.ID, device.ID, second.ID, "127.0.0.1:10002", 102)
	if err != nil {
		t.Fatal(err)
	}
	tunnelRepo := postgres.NewTunnelRepo(db)
	coordinator := domain.NewTunnelCoordinator(tunnelRepo, peerRepo, nil, networkRepo)
	if tunnel, err := coordinator.RequestTunnelForUser(owner.ID, first.ID, a.ID, b.ID, domain.TunnelModeRelay, 103); err == nil || tunnel != nil {
		t.Fatal("cross-network tunnel accepted")
	}
	stored, err := tunnelRepo.ListByNetwork(first.ID)
	if err != nil || len(stored) != 0 {
		t.Fatal("rejected request wrote a tunnel")
	}
	legacy := &domain.Tunnel{ID: domain.TunnelID{Value: "legacy-cross-network"}, NetworkID: first.ID, A: a.ID, B: b.ID, Mode: domain.TunnelModeRelay, State: domain.TunnelStateNegotiating, CreatedAtUnix: 104}
	if err := tunnelRepo.Save(legacy); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.OpenTunnelForUser(owner.ID, legacy.ID); err == nil {
		t.Fatal("legacy cross-network tunnel was opened")
	}
	storedLegacy, err := tunnelRepo.FindByID(legacy.ID)
	if err != nil || storedLegacy.State != domain.TunnelStateNegotiating {
		t.Fatal("rejected legacy open modified the tunnel")
	}
}
