package domain_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/memory"
	"testing"
)

type flakyPeerRepo struct {
	base    domain.PeerRepo
	missing map[string]struct{}
}

func (r *flakyPeerRepo) Save(p *domain.Peer) error {
	return r.base.Save(p)
}

func (r *flakyPeerRepo) FindByID(id domain.PeerID) (*domain.Peer, error) {
	if _, ok := r.missing[id.String()]; ok {
		return nil, nil
	}
	return r.base.FindByID(id)
}

func (r *flakyPeerRepo) ListByNetwork(networkID domain.NetworkID) ([]*domain.Peer, error) {
	return r.base.ListByNetwork(networkID)
}

func TestFileTransferServiceKeepsParticipantAccessWhenPeerRecordsDisappear(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	basePeerRepo := memory.NewPeerRepo()
	peerRepo := &flakyPeerRepo{base: basePeerRepo, missing: map[string]struct{}{}}
	transferRepo := memory.NewFileTransferRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, memory.NewSessionRepo(), "secret", "issuer")
	devices := domain.NewDeviceService(deviceRepo, auditRepo)
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)
	peers := domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo)
	transfers := domain.NewFileTransferService(transferRepo, peerRepo, networkRepo, auditRepo)

	sender, err := auth.Register("sender-peer-loss@example.com", "secret")
	if err != nil {
		t.Fatalf("register sender: %v", err)
	}
	receiver, err := auth.Register("receiver-peer-loss@example.com", "secret")
	if err != nil {
		t.Fatalf("register receiver: %v", err)
	}
	senderDevice, err := devices.Enroll(sender.ID, "sender-device", "sender-pub", 100)
	if err != nil {
		t.Fatalf("enroll sender device: %v", err)
	}
	receiverDevice, err := devices.Enroll(receiver.ID, "receiver-device", "receiver-pub", 101)
	if err != nil {
		t.Fatalf("enroll receiver device: %v", err)
	}
	network, err := networks.CreateNetwork(sender.ID, "peer-loss", domain.NetworkAccessPrivate)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if err := networks.AddMember(sender.ID, network.ID, receiver.ID); err != nil {
		t.Fatalf("add receiver member: %v", err)
	}
	senderPeer, err := peers.RegisterPeer(sender.ID, senderDevice.ID, network.ID, "127.0.0.1:4100", 102)
	if err != nil {
		t.Fatalf("register sender peer: %v", err)
	}
	receiverPeer, err := peers.RegisterPeer(receiver.ID, receiverDevice.ID, network.ID, "127.0.0.1:4200", 103)
	if err != nil {
		t.Fatalf("register receiver peer: %v", err)
	}

	transfer, err := transfers.CreateTransfer(sender.ID, network.ID, senderPeer.ID, receiverPeer.ID, "peer-loss.bin", 7)
	if err != nil {
		t.Fatalf("create transfer: %v", err)
	}
	if transfer.FromUserID != sender.ID || transfer.ToUserID != receiver.ID {
		t.Fatalf("expected transfer to persist participant users, got %#v", transfer)
	}

	peerRepo.missing[senderPeer.ID.String()] = struct{}{}
	peerRepo.missing[receiverPeer.ID.String()] = struct{}{}

	if _, err := transfers.GetTransferForUser(sender.ID, transfer.ID); err != nil {
		t.Fatalf("sender should still fetch transfer after peer loss: %v", err)
	}
	if _, err := transfers.AcceptTransfer(receiver.ID, transfer.ID); err != nil {
		t.Fatalf("receiver should still accept transfer after peer loss: %v", err)
	}
	if _, err := transfers.CancelTransfer(sender.ID, transfer.ID, "sender aborted"); err != nil {
		t.Fatalf("sender should still cancel transfer after peer loss: %v", err)
	}
}
