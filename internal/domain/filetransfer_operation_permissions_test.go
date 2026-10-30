package domain_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/memory"
	"bytes"
	"testing"
)

func TestFileTransferServiceParticipantAndContentOpsRespectPermissionBoundaries(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	peerRepo := memory.NewPeerRepo()
	sessionRepo := memory.NewSessionRepo()
	fileTransferRepo := memory.NewFileTransferRepo()
	payloadRepo := memory.NewFileTransferPayloadRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	devices := domain.NewDeviceService(deviceRepo, auditRepo)
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)
	peers := domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo)
	transfers := domain.NewFileTransferService(fileTransferRepo, peerRepo, networkRepo, auditRepo, payloadRepo)

	owner, _ := auth.Register("owner-transfer-ops@example.com", "secret")
	member, _ := auth.Register("member-transfer-ops@example.com", "secret")
	fileAdmin, _ := auth.Register("fileadmin-transfer-ops@example.com", "secret")
	readOnlyUser, _ := auth.Register("readonly-transfer-ops@example.com", "secret")
	outsider, _ := auth.Register("outsider-transfer-ops@example.com", "secret")

	ownerDevice, _ := devices.Enroll(owner.ID, "owner-device", "owner-pub", 100)
	memberDevice, _ := devices.Enroll(member.ID, "member-device", "member-pub", 101)
	fileAdminDevice, _ := devices.Enroll(fileAdmin.ID, "fileadmin-device", "fileadmin-pub", 102)

	network, err := networks.CreateNetwork(owner.ID, "transfer-ops", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	assignRole := func(userID domain.UserID, role domain.NetworkRole) {
		t.Helper()
		if err := networks.AddMember(owner.ID, network.ID, userID); err != nil {
			t.Fatalf("add member %s: %v", userID.String(), err)
		}
		if err := networks.ChangeMemberRole(owner.ID, network.ID, userID, role); err != nil {
			t.Fatalf("set role %s for %s: %v", role, userID.String(), err)
		}
	}
	assignRole(member.ID, domain.NetworkRoleMember)
	assignRole(fileAdmin.ID, domain.NetworkRoleFileAdmin)
	assignRole(readOnlyUser.ID, domain.NetworkRoleReadOnly)

	ownerPeer, err := peers.RegisterPeer(owner.ID, ownerDevice.ID, network.ID, "127.0.0.1:9910", 110)
	if err != nil {
		t.Fatalf("register owner peer: %v", err)
	}
	memberPeer, err := peers.RegisterPeer(member.ID, memberDevice.ID, network.ID, "127.0.0.1:9911", 111)
	if err != nil {
		t.Fatalf("register member peer: %v", err)
	}
	if _, err := peers.RegisterPeer(fileAdmin.ID, fileAdminDevice.ID, network.ID, "127.0.0.1:9912", 112); err != nil {
		t.Fatalf("register file-admin peer: %v", err)
	}

	payload := []byte("ole-transfer-ops")
	transfer, err := transfers.CreateTransfer(member.ID, network.ID, memberPeer.ID, ownerPeer.ID, "ops.txt", int64(len(payload)))
	if err != nil {
		t.Fatalf("create transfer: %v", err)
	}
	if _, err := transfers.UploadTransferPayload(member.ID, transfer.ID, "text/plain", payload, 120); err != nil {
		t.Fatalf("member upload payload: %v", err)
	}
	if _, err := transfers.UploadTransferPayload(readOnlyUser.ID, transfer.ID, "text/plain", payload, 121); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only upload to fail with insufficient role, got %v", err)
	}
	if _, err := transfers.UploadTransferPayload(outsider.ID, transfer.ID, "text/plain", payload, 122); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider upload to fail with unauthorized, got %v", err)
	}

	fileAdminPayload, fileAdminTransfer, err := transfers.DownloadTransferPayload(fileAdmin.ID, transfer.ID, 123)
	if err != nil {
		t.Fatalf("file-admin download payload: %v", err)
	}
	if !bytes.Equal(fileAdminPayload.Payload, payload) {
		t.Fatalf("expected file-admin payload download to round-trip, got %#v", fileAdminPayload)
	}
	if fileAdminTransfer.Status != domain.TransferStatusInit || fileAdminTransfer.DownloadedAtUnix != 0 {
		t.Fatalf("expected non-receiver admin download to avoid completion side effects, got %#v", fileAdminTransfer)
	}
	if _, _, err := transfers.DownloadTransferPayload(readOnlyUser.ID, transfer.ID, 124); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only payload download to fail with insufficient role, got %v", err)
	}
	if _, _, err := transfers.DownloadTransferPayload(outsider.ID, transfer.ID, 125); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider payload download to fail with unauthorized, got %v", err)
	}

	if _, err := transfers.AcceptTransfer(owner.ID, transfer.ID); err != nil {
		t.Fatalf("receiver accept transfer: %v", err)
	}
	if _, err := transfers.AcceptTransfer(readOnlyUser.ID, transfer.ID); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only accept to fail with insufficient role, got %v", err)
	}
	progressed, err := transfers.UpdateTransferProgress(member.ID, transfer.ID, 55)
	if err != nil {
		t.Fatalf("sender progress update: %v", err)
	}
	if progressed.ProgressPercent != 55 {
		t.Fatalf("expected sender progress update to stick, got %#v", progressed)
	}
	if _, err := transfers.UpdateTransferProgress(readOnlyUser.ID, transfer.ID, 60); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only progress update to fail with insufficient role, got %v", err)
	}
	if _, err := transfers.UpdateTransferProgress(outsider.ID, transfer.ID, 65); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider progress update to fail with unauthorized, got %v", err)
	}
}
