package domain_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/memory"
	"bytes"
	"testing"
)

func TestFileTransferServiceKeepsReceiverPayloadDownloadWhenPeerRecordsDisappear(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	basePeerRepo := memory.NewPeerRepo()
	peerRepo := &flakyPeerRepo{base: basePeerRepo, missing: map[string]struct{}{}}
	transferRepo := memory.NewFileTransferRepo()
	payloadRepo := memory.NewFileTransferPayloadRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, memory.NewSessionRepo(), "secret", "issuer")
	devices := domain.NewDeviceService(deviceRepo, auditRepo)
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)
	peers := domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo)
	transfers := domain.NewFileTransferService(transferRepo, peerRepo, networkRepo, auditRepo, payloadRepo)

	sender, err := auth.Register("sender-download-loss@example.com", "secret")
	if err != nil {
		t.Fatalf("register sender: %v", err)
	}
	receiver, err := auth.Register("receiver-download-loss@example.com", "secret")
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
	network, err := networks.CreateNetwork(sender.ID, "download-loss", domain.NetworkAccessPrivate)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if err := networks.AddMember(sender.ID, network.ID, receiver.ID); err != nil {
		t.Fatalf("add receiver member: %v", err)
	}
	senderPeer, err := peers.RegisterPeer(sender.ID, senderDevice.ID, network.ID, "127.0.0.1:4300", 102)
	if err != nil {
		t.Fatalf("register sender peer: %v", err)
	}
	receiverPeer, err := peers.RegisterPeer(receiver.ID, receiverDevice.ID, network.ID, "127.0.0.1:4301", 103)
	if err != nil {
		t.Fatalf("register receiver peer: %v", err)
	}

	payload := []byte("hello")
	transfer, err := transfers.CreateTransfer(sender.ID, network.ID, senderPeer.ID, receiverPeer.ID, "download.bin", int64(len(payload)))
	if err != nil {
		t.Fatalf("create transfer: %v", err)
	}
	if _, err := transfers.UploadTransferPayload(sender.ID, transfer.ID, "application/octet-stream", payload, 200); err != nil {
		t.Fatalf("upload payload: %v", err)
	}
	if _, err := transfers.AcceptTransfer(receiver.ID, transfer.ID); err != nil {
		t.Fatalf("accept transfer: %v", err)
	}

	peerRepo.missing[senderPeer.ID.String()] = struct{}{}
	peerRepo.missing[receiverPeer.ID.String()] = struct{}{}

	downloaded, storedTransfer, err := transfers.DownloadTransferPayload(receiver.ID, transfer.ID, 201)
	if err != nil {
		t.Fatalf("receiver download after peer loss: %v", err)
	}
	if !bytes.Equal(downloaded.Payload, payload) {
		t.Fatalf("expected payload bytes after peer loss, got %q", string(downloaded.Payload))
	}
	if storedTransfer.DownloadedAtUnix != 201 || storedTransfer.Status != domain.TransferStatusDone {
		t.Fatalf("expected receiver download to complete transfer after peer loss, got %#v", storedTransfer)
	}
}

func TestFileTransferServiceKeepsReceiverChunkDownloadWhenPeerRecordsDisappear(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	basePeerRepo := memory.NewPeerRepo()
	peerRepo := &flakyPeerRepo{base: basePeerRepo, missing: map[string]struct{}{}}
	transferRepo := memory.NewFileTransferRepo()
	payloadRepo := memory.NewFileTransferPayloadRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, memory.NewSessionRepo(), "secret", "issuer")
	devices := domain.NewDeviceService(deviceRepo, auditRepo)
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)
	peers := domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo)
	transfers := domain.NewFileTransferService(transferRepo, peerRepo, networkRepo, auditRepo, payloadRepo)

	sender, err := auth.Register("sender-chunk-loss@example.com", "secret")
	if err != nil {
		t.Fatalf("register sender: %v", err)
	}
	receiver, err := auth.Register("receiver-chunk-loss@example.com", "secret")
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
	network, err := networks.CreateNetwork(sender.ID, "chunk-loss", domain.NetworkAccessPrivate)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if err := networks.AddMember(sender.ID, network.ID, receiver.ID); err != nil {
		t.Fatalf("add receiver member: %v", err)
	}
	senderPeer, err := peers.RegisterPeer(sender.ID, senderDevice.ID, network.ID, "127.0.0.1:4310", 102)
	if err != nil {
		t.Fatalf("register sender peer: %v", err)
	}
	receiverPeer, err := peers.RegisterPeer(receiver.ID, receiverDevice.ID, network.ID, "127.0.0.1:4311", 103)
	if err != nil {
		t.Fatalf("register receiver peer: %v", err)
	}

	payload := []byte("chunked")
	transfer, err := transfers.CreateTransfer(sender.ID, network.ID, senderPeer.ID, receiverPeer.ID, "chunk.bin", int64(len(payload)))
	if err != nil {
		t.Fatalf("create transfer: %v", err)
	}
	if _, err := transfers.UploadTransferPayload(sender.ID, transfer.ID, "application/octet-stream", payload, 200); err != nil {
		t.Fatalf("upload payload: %v", err)
	}
	if _, err := transfers.AcceptTransfer(receiver.ID, transfer.ID); err != nil {
		t.Fatalf("accept transfer: %v", err)
	}

	peerRepo.missing[senderPeer.ID.String()] = struct{}{}
	peerRepo.missing[receiverPeer.ID.String()] = struct{}{}

	chunk, storedTransfer, err := transfers.DownloadTransferPayloadChunk(receiver.ID, transfer.ID, 0, int64(len(payload)), 201)
	if err != nil {
		t.Fatalf("receiver chunk download after peer loss: %v", err)
	}
	if !bytes.Equal(chunk.Payload, payload) || !chunk.Complete {
		t.Fatalf("expected complete chunk payload after peer loss, got %#v", chunk)
	}
	if storedTransfer.DownloadedAtUnix != 201 || storedTransfer.Status != domain.TransferStatusDone {
		t.Fatalf("expected receiver chunk download to complete transfer after peer loss, got %#v", storedTransfer)
	}
}

func TestFileTransferServiceKeepsReceiverMirrorUploadWhenPeerRecordsDisappear(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	basePeerRepo := memory.NewPeerRepo()
	peerRepo := &flakyPeerRepo{base: basePeerRepo, missing: map[string]struct{}{}}
	transferRepo := memory.NewFileTransferRepo()
	payloadRepo := memory.NewFileTransferPayloadRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, memory.NewSessionRepo(), "secret", "issuer")
	devices := domain.NewDeviceService(deviceRepo, auditRepo)
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)
	peers := domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo)
	transfers := domain.NewFileTransferService(transferRepo, peerRepo, networkRepo, auditRepo, payloadRepo)

	sender, err := auth.Register("sender-mirror-loss@example.com", "secret")
	if err != nil {
		t.Fatalf("register sender: %v", err)
	}
	receiver, err := auth.Register("receiver-mirror-loss@example.com", "secret")
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
	transferSize := domain.DefaultControlPlaneFileTransferPayloadMaxBytes + 1
	network, err := networks.CreateNetworkWithOptions(sender.ID, "mirror-loss", domain.NetworkAccessPrivate, domain.NetworkCreateOptions{
		FileTransferMaxBytes: transferSize,
	})
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if err := networks.AddMember(sender.ID, network.ID, receiver.ID); err != nil {
		t.Fatalf("add receiver member: %v", err)
	}
	senderPeer, err := peers.RegisterPeer(sender.ID, senderDevice.ID, network.ID, "127.0.0.1:4320", 102)
	if err != nil {
		t.Fatalf("register sender peer: %v", err)
	}
	receiverPeer, err := peers.RegisterPeer(receiver.ID, receiverDevice.ID, network.ID, "127.0.0.1:4321", 103)
	if err != nil {
		t.Fatalf("register receiver peer: %v", err)
	}

	transfer, err := transfers.CreateTransfer(sender.ID, network.ID, senderPeer.ID, receiverPeer.ID, "mirror.bin", transferSize)
	if err != nil {
		t.Fatalf("create transfer: %v", err)
	}
	if _, err := transfers.AcceptTransfer(receiver.ID, transfer.ID); err != nil {
		t.Fatalf("accept transfer: %v", err)
	}

	peerRepo.missing[senderPeer.ID.String()] = struct{}{}
	peerRepo.missing[receiverPeer.ID.String()] = struct{}{}

	mirrored, err := transfers.UploadTransferPayloadChunk(receiver.ID, transfer.ID, "application/octet-stream", 0, []byte("hello"), 201)
	if err != nil {
		t.Fatalf("receiver mirror upload after peer loss: %v", err)
	}
	if mirrored.PayloadUploadedBytes != 5 || mirrored.ContentType != "application/octet-stream" {
		t.Fatalf("expected receiver mirror upload to keep progressing after peer loss, got %#v", mirrored)
	}
}
