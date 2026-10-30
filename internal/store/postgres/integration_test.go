package postgres_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/postgres"
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresIntegrationEndToEndLifecycle(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()

	userRepo := postgres.NewUserRepo(db)
	deviceRepo := postgres.NewDeviceRepo(db)
	networkRepo := postgres.NewNetworkRepo(db)
	peerRepo := postgres.NewPeerRepo(db)
	candidateRepo := postgres.NewSignalCandidateRepo(db)
	tunnelRepo := postgres.NewTunnelRepo(db)
	inviteRepo := postgres.NewInviteRepo(db)
	auditRepo := postgres.NewAuditRepo(db)
	poolRepo := postgres.NewVirtualIPPoolRepo(db)
	sessionRepo := postgres.NewSessionRepo(db)

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	devices := domain.NewDeviceService(deviceRepo, auditRepo)
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)
	peers := domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo)
	signaling := domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo)
	tunnels := domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo)

	owner, err := auth.Register("owner@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	member, err := auth.Register("member@example.com", "secret")
	if err != nil {
		t.Fatalf("register member: %v", err)
	}

	session, err := auth.Login(owner.Email, "secret", domain.SessionMetadata{DeviceName: "owner-laptop"})
	if err != nil {
		t.Fatalf("login owner: %v", err)
	}
	if _, err := auth.ValidateAccessToken(session.AccessToken); err != nil {
		t.Fatalf("validate access token: %v", err)
	}

	ownerDevice, err := devices.Enroll(owner.ID, "owner-laptop", "owner-public-key", 100)
	if err != nil {
		t.Fatalf("enroll owner device: %v", err)
	}
	memberDevice, err := devices.Enroll(member.ID, "member-laptop", "member-public-key", 101)
	if err != nil {
		t.Fatalf("enroll member device: %v", err)
	}

	network, err := networks.CreateNetwork(owner.ID, "friends", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if role, ok := network.RoleOf(owner.ID); !ok || role != domain.NetworkRoleOwner {
		t.Fatalf("expected owner role to be persisted, got %q, ok=%v", role, ok)
	}

	invite, err := networks.GenerateInvite(owner.ID, network.ID, 3600, 1, 200)
	if err != nil {
		t.Fatalf("generate invite: %v", err)
	}
	joined, err := networks.JoinByInvite(member.ID, invite.Code, 250)
	if err != nil {
		t.Fatalf("join by invite: %v", err)
	}
	if !joined.HasMember(member.ID) {
		t.Fatalf("expected member to join the network")
	}

	peerA, err := peers.RegisterPeer(owner.ID, ownerDevice.ID, network.ID, "1.1.1.1:1111", 300)
	if err != nil {
		t.Fatalf("register peer A: %v", err)
	}
	peerB, err := peers.RegisterPeer(member.ID, memberDevice.ID, network.ID, "2.2.2.2:2222", 301)
	if err != nil {
		t.Fatalf("register peer B: %v", err)
	}
	if peerA.VirtualIP == peerB.VirtualIP {
		t.Fatalf("virtual IPs must be unique")
	}
	if _, err := signaling.PublishCandidate(owner.ID, peerA.ID, domain.SignalCandidateTypeHost, domain.SignalCandidateProtocolUDP, "1.1.1.1:1111", 100, true, 120, 305); err != nil {
		t.Fatalf("publish candidate: %v", err)
	}
	candidates, err := signaling.ListCandidates(member.ID, peerA.ID, 306)
	if err != nil {
		t.Fatalf("list candidates: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("expected one active candidate, got %d", len(candidates))
	}
	if _, err := peers.UpdateSignaling(owner.ID, peerA.ID, domain.PeerReachabilityDirect, domain.ConnectionStateDirectCandidate, 307); err != nil {
		t.Fatalf("update peer signaling: %v", err)
	}

	tunnel, err := tunnels.RequestTunnel(network.ID, peerA.ID, peerB.ID, "", 400)
	if err != nil {
		t.Fatalf("request tunnel: %v", err)
	}
	if tunnel.Mode != domain.TunnelModeP2P {
		t.Fatalf("expected p2p tunnel, got %s", tunnel.Mode)
	}
	if tunnel.State != domain.TunnelStateNegotiating {
		t.Fatalf("expected negotiating tunnel, got %s", tunnel.State)
	}
	if err := tunnels.OpenTunnel(tunnel.ID); err != nil {
		t.Fatalf("open tunnel: %v", err)
	}

	storedNetwork, err := networkRepo.FindByID(network.ID)
	if err != nil {
		t.Fatalf("reload network: %v", err)
	}
	if storedNetwork == nil || !storedNetwork.HasMember(member.ID) {
		t.Fatalf("expected stored network membership to include member")
	}

	storedDevices, totalDevices, err := deviceRepo.ListByUserID(owner.ID, 10, 0)
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if totalDevices != 1 || len(storedDevices) != 1 {
		t.Fatalf("expected one owner device, got total=%d len=%d", totalDevices, len(storedDevices))
	}

	storedPeers, err := peerRepo.ListByNetwork(network.ID)
	if err != nil {
		t.Fatalf("list peers: %v", err)
	}
	if len(storedPeers) != 2 {
		t.Fatalf("expected two peers, got %d", len(storedPeers))
	}
	if storedPeers[0].Reachability == "" || storedPeers[0].ConnectionState == "" {
		t.Fatalf("expected signaling metadata to be persisted on peers, got %#v", storedPeers[0])
	}

	pool, err := poolRepo.FindByNetworkID(network.ID)
	if err != nil {
		t.Fatalf("load virtual ip pool: %v", err)
	}
	if pool == nil || pool.CountLeases() != 2 {
		t.Fatalf("expected two virtual IP leases, got %#v", pool)
	}

	storedTunnels, err := tunnelRepo.ListByNetwork(network.ID)
	if err != nil {
		t.Fatalf("list tunnels: %v", err)
	}
	if len(storedTunnels) != 1 {
		t.Fatalf("expected one tunnel, got %d", len(storedTunnels))
	}
	if storedTunnels[0].State != domain.TunnelStateOpen {
		t.Fatalf("expected open tunnel to be persisted, got %#v", storedTunnels[0])
	}

	storedSessions, totalSessions, err := sessionRepo.ListByUserID(owner.ID, 10, 0)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if totalSessions != 1 || len(storedSessions) != 1 {
		t.Fatalf("expected one owner session family, got total=%d len=%d", totalSessions, len(storedSessions))
	}

	events, err := auditRepo.ListRecent(20)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) < 6 {
		t.Fatalf("expected audit trail to be persisted, got %d events", len(events))
	}
}

func TestPostgresPersistsMessagesAndFileTransfersWithACLs(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()

	userRepo := postgres.NewUserRepo(db)
	deviceRepo := postgres.NewDeviceRepo(db)
	networkRepo := postgres.NewNetworkRepo(db)
	peerRepo := postgres.NewPeerRepo(db)
	messageRepo := postgres.NewMessageRepo(db)
	fileTransferRepo := postgres.NewFileTransferRepo(db)
	fileTransferPayloadRepo := postgres.NewFileTransferPayloadRepo(db)
	inviteRepo := postgres.NewInviteRepo(db)
	auditRepo := postgres.NewAuditRepo(db)
	poolRepo := postgres.NewVirtualIPPoolRepo(db)
	sessionRepo := postgres.NewSessionRepo(db)

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	devices := domain.NewDeviceService(deviceRepo, auditRepo)
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)
	peers := domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo)
	messaging := domain.NewMessagingService(messageRepo, peerRepo, networkRepo, auditRepo)
	transfers := domain.NewFileTransferService(fileTransferRepo, peerRepo, networkRepo, auditRepo, fileTransferPayloadRepo)

	owner, err := auth.Register("owner-msg@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	member, err := auth.Register("member-msg@example.com", "secret")
	if err != nil {
		t.Fatalf("register member: %v", err)
	}
	readOnlyUser, err := auth.Register("readonly-msg@example.com", "secret")
	if err != nil {
		t.Fatalf("register read-only user: %v", err)
	}
	outsider, err := auth.Register("outsider-msg@example.com", "secret")
	if err != nil {
		t.Fatalf("register outsider: %v", err)
	}

	ownerDevice, err := devices.Enroll(owner.ID, "owner-msg-device", "owner-msg-pub", 10)
	if err != nil {
		t.Fatalf("enroll owner device: %v", err)
	}
	memberDevice, err := devices.Enroll(member.ID, "member-msg-device", "member-msg-pub", 11)
	if err != nil {
		t.Fatalf("enroll member device: %v", err)
	}
	network, err := networks.CreateNetwork(owner.ID, "messages-files", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if err := networks.AddMember(owner.ID, network.ID, member.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if err := networks.AddMember(owner.ID, network.ID, readOnlyUser.ID); err != nil {
		t.Fatalf("add read-only user: %v", err)
	}
	if err := networks.ChangeMemberRole(owner.ID, network.ID, readOnlyUser.ID, domain.NetworkRoleReadOnly); err != nil {
		t.Fatalf("set read-only role: %v", err)
	}

	ownerPeer, err := peers.RegisterPeer(owner.ID, ownerDevice.ID, network.ID, "127.0.0.1:4100", 20)
	if err != nil {
		t.Fatalf("register owner peer: %v", err)
	}
	memberPeer, err := peers.RegisterPeer(member.ID, memberDevice.ID, network.ID, "127.0.0.1:4101", 21)
	if err != nil {
		t.Fatalf("register member peer: %v", err)
	}
	message, err := messaging.SendMessage(member.ID, network.ID, memberPeer.ID, "hello postgres overlay", 30)
	if err != nil {
		t.Fatalf("send message: %v", err)
	}
	if _, err := messaging.SendMessage(readOnlyUser.ID, network.ID, memberPeer.ID, "blocked", 31); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only send to fail, got %v", err)
	}
	if _, err := messaging.ListMessagesForUser(readOnlyUser.ID, network.ID); err != nil {
		t.Fatalf("read-only list messages: %v", err)
	}
	if _, err := messaging.ListMessagesForUser(outsider.ID, network.ID); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider message list to fail, got %v", err)
	}

	storedMessage, err := messageRepo.FindByID(message.ID)
	if err != nil {
		t.Fatalf("find stored message: %v", err)
	}
	if storedMessage == nil || storedMessage.Text != "hello postgres overlay" {
		t.Fatalf("expected stored message text, got %#v", storedMessage)
	}

	transferPayload := []byte("postgres payload")
	transfer, err := transfers.CreateTransfer(member.ID, network.ID, memberPeer.ID, ownerPeer.ID, "notes.txt", int64(len(transferPayload)))
	if err != nil {
		t.Fatalf("create transfer: %v", err)
	}
	if _, err := transfers.CreateTransfer(readOnlyUser.ID, network.ID, memberPeer.ID, ownerPeer.ID, "blocked.txt", 64); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only transfer create to fail, got %v", err)
	}
	uploaded, err := transfers.UploadTransferPayload(member.ID, transfer.ID, "text/plain", transferPayload, 32)
	if err != nil {
		t.Fatalf("upload transfer payload: %v", err)
	}
	if !uploaded.PayloadReady || uploaded.PayloadSHA256 == "" || uploaded.ContentType != "text/plain" {
		t.Fatalf("expected uploaded transfer metadata, got %#v", uploaded)
	}
	accepted, err := transfers.AcceptTransfer(owner.ID, transfer.ID)
	if err != nil {
		t.Fatalf("accept transfer: %v", err)
	}
	if accepted.Status != domain.TransferStatusInProgress {
		t.Fatalf("expected accepted transfer to move in progress, got %#v", accepted)
	}
	downloadedPayload, completed, err := transfers.DownloadTransferPayload(owner.ID, transfer.ID, 33)
	if err != nil {
		t.Fatalf("download transfer payload: %v", err)
	}
	if !bytes.Equal(downloadedPayload.Payload, transferPayload) || downloadedPayload.ContentType != "text/plain" {
		t.Fatalf("expected persisted payload round-trip, got %#v", downloadedPayload)
	}
	if completed.Status != domain.TransferStatusDone || completed.ProgressPercent != 100 || completed.DownloadedAtUnix != 33 {
		t.Fatalf("expected completed transfer, got %#v", completed)
	}
	if _, err := transfers.ListTransfersForUser(readOnlyUser.ID, network.ID); err != nil {
		t.Fatalf("read-only list transfers: %v", err)
	}
	if _, err := transfers.ListTransfersForUser(outsider.ID, network.ID); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider transfer list to fail, got %v", err)
	}

	storedTransfer, err := fileTransferRepo.FindByID(transfer.ID)
	if err != nil {
		t.Fatalf("find stored transfer: %v", err)
	}
	if storedTransfer == nil || storedTransfer.Status != domain.TransferStatusDone || storedTransfer.ProgressPercent != 100 {
		t.Fatalf("expected stored completed transfer, got %#v", storedTransfer)
	}
	if !storedTransfer.PayloadReady || storedTransfer.ContentType != "text/plain" || storedTransfer.PayloadSHA256 == "" || storedTransfer.DownloadedAtUnix != 33 {
		t.Fatalf("expected stored payload metadata, got %#v", storedTransfer)
	}

	storedPayload, err := fileTransferPayloadRepo.FindByTransferID(transfer.ID)
	if err != nil {
		t.Fatalf("find stored payload: %v", err)
	}
	if storedPayload == nil || !bytes.Equal(storedPayload.Payload, transferPayload) || storedPayload.SHA256 == "" {
		t.Fatalf("expected stored payload bytes and checksum, got %#v", storedPayload)
	}

	events, err := auditRepo.ListRecent(20)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	foundMessageAudit := false
	foundTransferUploadAudit := false
	foundTransferDownloadAudit := false
	for _, event := range events {
		if event.Type == "message.sent" {
			foundMessageAudit = true
		}
		if event.Type == "file_transfer.payload_uploaded" {
			foundTransferUploadAudit = true
		}
		if event.Type == "file_transfer.payload_downloaded" {
			foundTransferDownloadAudit = true
		}
	}
	if !foundMessageAudit || !foundTransferUploadAudit || !foundTransferDownloadAudit {
		t.Fatalf("expected message and file-transfer audit events, got %#v", events)
	}
}

func TestPostgresSessionRepoLifecycle(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()

	userRepo := postgres.NewUserRepo(db)
	sessionRepo := postgres.NewSessionRepo(db)

	user := &domain.User{
		ID:           domain.UserID{Value: "usr-session"},
		Email:        "session@example.com",
		PasswordHash: "hash",
		Status:       domain.UserStatusActive,
	}
	if err := userRepo.Save(user); err != nil {
		t.Fatalf("save user: %v", err)
	}

	rotated := &domain.SessionToken{
		ID:             "ses-current",
		UserID:         user.ID,
		FamilyID:       "fam-1",
		AccessToken:    "acc-current",
		RefreshToken:   "ref-current",
		DeviceName:     "desktop",
		IP:             "127.0.0.1",
		UserAgent:      "ole-test",
		LastUsedAtUnix: 20,
		ExpiresAtUnix:  120,
	}
	old := &domain.SessionToken{
		ID:                  "ses-old",
		UserID:              user.ID,
		FamilyID:            "fam-1",
		AccessToken:         "acc-old",
		RefreshToken:        "ref-old",
		DeviceName:          "desktop",
		IP:                  "127.0.0.1",
		UserAgent:           "ole-test",
		LastUsedAtUnix:      10,
		ExpiresAtUnix:       100,
		ReplacedByToken:     rotated.RefreshToken,
		RevokedAtUnix:       20,
		ReuseDetectedAtUnix: 0,
	}
	secondFamily := &domain.SessionToken{
		ID:             "ses-second",
		UserID:         user.ID,
		FamilyID:       "fam-2",
		AccessToken:    "acc-second",
		RefreshToken:   "ref-second",
		DeviceName:     "phone",
		IP:             "127.0.0.2",
		UserAgent:      "ole-test",
		LastUsedAtUnix: 30,
		ExpiresAtUnix:  130,
	}
	expired := &domain.SessionToken{
		ID:             "ses-expired",
		UserID:         user.ID,
		FamilyID:       "fam-3",
		AccessToken:    "acc-expired",
		RefreshToken:   "ref-expired",
		DeviceName:     "tablet",
		IP:             "127.0.0.3",
		UserAgent:      "ole-test",
		LastUsedAtUnix: 1,
		ExpiresAtUnix:  2,
	}

	for _, session := range []*domain.SessionToken{old, rotated, secondFamily, expired} {
		if err := sessionRepo.Create(session); err != nil {
			t.Fatalf("create session %s: %v", session.ID, err)
		}
	}

	rotated.IP = "10.0.0.10"
	rotated.LastUsedAtUnix = 31
	if err := sessionRepo.Update(rotated); err != nil {
		t.Fatalf("update rotated session: %v", err)
	}

	storedByAccess, err := sessionRepo.FindByAccessToken(rotated.AccessToken)
	if err != nil {
		t.Fatalf("find by access token: %v", err)
	}
	if storedByAccess == nil || storedByAccess.IP != rotated.IP {
		t.Fatalf("expected updated session IP %q, got %#v", rotated.IP, storedByAccess)
	}

	storedByRefresh, err := sessionRepo.FindByRefreshToken(rotated.RefreshToken)
	if err != nil {
		t.Fatalf("find by refresh token: %v", err)
	}
	if storedByRefresh == nil || storedByRefresh.ID != rotated.ID {
		t.Fatalf("expected refreshed session %q, got %#v", rotated.ID, storedByRefresh)
	}

	sessions, total, err := sessionRepo.ListByUserID(user.ID, 10, 0)
	if err != nil {
		t.Fatalf("list by user id: %v", err)
	}
	if total != 3 {
		t.Fatalf("expected 3 distinct session families, got %d", total)
	}
	if len(sessions) != 3 {
		t.Fatalf("expected 3 listed sessions, got %d", len(sessions))
	}
	if !containsSessionID(sessions, rotated.ID) || !containsSessionID(sessions, secondFamily.ID) || !containsSessionID(sessions, expired.ID) {
		t.Fatalf("expected list to contain the latest session from each family")
	}

	if err := sessionRepo.RevokeFamily(rotated.UserID, rotated.FamilyID, 40, true); err != nil {
		t.Fatalf("revoke family: %v", err)
	}
	revoked, err := sessionRepo.FindByAccessToken(rotated.AccessToken)
	if err != nil {
		t.Fatalf("find revoked session: %v", err)
	}
	if revoked == nil || revoked.RevokedAtUnix != 40 || revoked.ReuseDetectedAtUnix != 40 {
		t.Fatalf("expected family revoke to set revoke and reuse flags, got %#v", revoked)
	}

	if err := sessionRepo.RevokeByUserID(user.ID, 50); err != nil {
		t.Fatalf("revoke by user id: %v", err)
	}
	secondStored, err := sessionRepo.FindByAccessToken(secondFamily.AccessToken)
	if err != nil {
		t.Fatalf("find second family after revoke: %v", err)
	}
	if secondStored == nil || secondStored.RevokedAtUnix != 50 {
		t.Fatalf("expected second family revoke timestamp 50, got %#v", secondStored)
	}

	if err := sessionRepo.DeleteExpired(3); err != nil {
		t.Fatalf("delete expired: %v", err)
	}
	deleted, err := sessionRepo.FindByAccessToken(expired.AccessToken)
	if err != nil {
		t.Fatalf("find expired session after delete: %v", err)
	}
	if deleted != nil {
		t.Fatalf("expected expired session to be deleted, got %#v", deleted)
	}
}

func TestPostgresCleanupDeletesExpiredSessionsAndStaleInvites(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()

	userRepo := postgres.NewUserRepo(db)
	networkRepo := postgres.NewNetworkRepo(db)
	sessionRepo := postgres.NewSessionRepo(db)
	inviteRepo := postgres.NewInviteRepo(db)
	candidateRepo := postgres.NewSignalCandidateRepo(db)
	peerRepo := postgres.NewPeerRepo(db)
	deviceRepo := postgres.NewDeviceRepo(db)
	poolRepo := postgres.NewVirtualIPPoolRepo(db)

	user := &domain.User{
		ID:           domain.UserID{Value: "usr-cleanup"},
		Email:        "cleanup@example.com",
		PasswordHash: "hash",
		Status:       domain.UserStatusActive,
	}
	if err := userRepo.Save(user); err != nil {
		t.Fatalf("save user: %v", err)
	}
	network := domain.NewNetwork(domain.NetworkID{Value: "net-cleanup"}, user.ID, "cleanup", domain.NetworkAccessInviteOnly, false)
	if err := networkRepo.Save(network); err != nil {
		t.Fatalf("save network: %v", err)
	}
	device := domain.NewDevice(domain.DeviceID{Value: "dev-cleanup"}, user.ID, "cleanup-device", "cleanup-key", 1)
	if err := deviceRepo.Save(device); err != nil {
		t.Fatalf("save device: %v", err)
	}
	peers := domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, nil)
	peer, err := peers.RegisterPeer(user.ID, device.ID, network.ID, "127.0.0.1:4000", 2)
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}
	session := &domain.SessionToken{
		ID:             "ses-cleanup",
		UserID:         user.ID,
		FamilyID:       "fam-cleanup",
		AccessToken:    "acc-cleanup",
		RefreshToken:   "ref-cleanup",
		DeviceName:     "desktop",
		IP:             "127.0.0.1",
		UserAgent:      "ole-test",
		LastUsedAtUnix: 5,
		ExpiresAtUnix:  10,
	}
	if err := sessionRepo.Create(session); err != nil {
		t.Fatalf("create session: %v", err)
	}

	expiredInvite := &domain.Invite{
		Code:          "inv-expired",
		NetworkID:     network.ID,
		ExpiresAtUnix: 10,
		MaxUses:       1,
		Uses:          0,
	}
	exhaustedInvite := &domain.Invite{
		Code:          "inv-exhausted",
		NetworkID:     network.ID,
		ExpiresAtUnix: 100,
		MaxUses:       1,
		Uses:          1,
	}
	activeInvite := &domain.Invite{
		Code:          "inv-active",
		NetworkID:     network.ID,
		ExpiresAtUnix: 100,
		MaxUses:       2,
		Uses:          1,
	}
	for _, invite := range []*domain.Invite{expiredInvite, exhaustedInvite, activeInvite} {
		if err := inviteRepo.Save(invite); err != nil {
			t.Fatalf("save invite %s: %v", invite.Code, err)
		}
	}
	expiredCandidate := &domain.SignalCandidate{
		ID:            "cand-expired",
		PeerID:        peer.ID,
		NetworkID:     network.ID,
		Type:          domain.SignalCandidateTypeHost,
		Protocol:      domain.SignalCandidateProtocolUDP,
		Address:       "127.0.0.1:4000",
		Preference:    100,
		Reachable:     true,
		CreatedAtUnix: 5,
		ExpiresAtUnix: 10,
	}
	activeCandidate := &domain.SignalCandidate{
		ID:            "cand-active",
		PeerID:        peer.ID,
		NetworkID:     network.ID,
		Type:          domain.SignalCandidateTypeHost,
		Protocol:      domain.SignalCandidateProtocolUDP,
		Address:       "127.0.0.1:4001",
		Preference:    90,
		Reachable:     true,
		CreatedAtUnix: 5,
		ExpiresAtUnix: 100,
	}
	for _, candidate := range []*domain.SignalCandidate{expiredCandidate, activeCandidate} {
		if err := candidateRepo.Save(candidate); err != nil {
			t.Fatalf("save candidate %s: %v", candidate.ID, err)
		}
	}

	if err := sessionRepo.DeleteExpired(10); err != nil {
		t.Fatalf("delete expired sessions: %v", err)
	}
	if err := inviteRepo.DeleteStale(10); err != nil {
		t.Fatalf("delete stale invites: %v", err)
	}
	if err := candidateRepo.DeleteExpired(10); err != nil {
		t.Fatalf("delete expired candidates: %v", err)
	}

	deletedSession, err := sessionRepo.FindByAccessToken(session.AccessToken)
	if err != nil {
		t.Fatalf("find deleted session: %v", err)
	}
	if deletedSession != nil {
		t.Fatalf("expected expired session to be deleted, got %#v", deletedSession)
	}

	for _, code := range []string{expiredInvite.Code, exhaustedInvite.Code} {
		invite, err := inviteRepo.FindByCode(code)
		if err != nil {
			t.Fatalf("find stale invite %s: %v", code, err)
		}
		if invite != nil {
			t.Fatalf("expected stale invite %s to be deleted, got %#v", code, invite)
		}
	}
	invite, err := inviteRepo.FindByCode(activeInvite.Code)
	if err != nil {
		t.Fatalf("find active invite: %v", err)
	}
	if invite == nil {
		t.Fatalf("expected active invite to remain")
	}
	candidates, err := candidateRepo.ListByPeerID(peer.ID)
	if err != nil {
		t.Fatalf("list candidates after cleanup: %v", err)
	}
	if len(candidates) != 1 || candidates[0].ID != activeCandidate.ID {
		t.Fatalf("expected only active candidate to remain, got %#v", candidates)
	}
}

func TestPostgresCleanupExpiresStalePeers(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()

	userRepo := postgres.NewUserRepo(db)
	networkRepo := postgres.NewNetworkRepo(db)
	deviceRepo := postgres.NewDeviceRepo(db)
	peerRepo := postgres.NewPeerRepo(db)
	poolRepo := postgres.NewVirtualIPPoolRepo(db)
	auditRepo := postgres.NewAuditRepo(db)

	user := &domain.User{
		ID:           domain.UserID{Value: "usr-peer-cleanup"},
		Email:        "peer-cleanup@example.com",
		PasswordHash: "hash",
		Status:       domain.UserStatusActive,
	}
	if err := userRepo.Save(user); err != nil {
		t.Fatalf("save user: %v", err)
	}
	network := domain.NewNetwork(domain.NetworkID{Value: "net-peer-cleanup"}, user.ID, "peer-cleanup", domain.NetworkAccessPrivate, false)
	if err := networkRepo.Save(network); err != nil {
		t.Fatalf("save network: %v", err)
	}
	device := domain.NewDevice(domain.DeviceID{Value: "dev-peer-cleanup"}, user.ID, "peer-cleanup-device", "peer-cleanup-key", 1)
	if err := deviceRepo.Save(device); err != nil {
		t.Fatalf("save device: %v", err)
	}

	peers := domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo)
	peer, err := peers.RegisterPeer(user.ID, device.ID, network.ID, "127.0.0.1:4000", 5)
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}
	if _, err := peers.UpdateSignaling(user.ID, peer.ID, domain.PeerReachabilityDirect, domain.ConnectionStateConnected, 6); err != nil {
		t.Fatalf("update signaling: %v", err)
	}

	if err := peers.CleanupStalePeers(200, 60); err != nil {
		t.Fatalf("cleanup stale peers: %v", err)
	}

	stored, err := peerRepo.FindByID(peer.ID)
	if err != nil {
		t.Fatalf("find peer after cleanup: %v", err)
	}
	if stored == nil {
		t.Fatalf("expected peer to remain persisted after cleanup")
	}
	if stored.Status != domain.PeerStatusOffline || stored.Reachability != domain.PeerReachabilityUnknown || stored.ConnectionState != domain.ConnectionStateIdle {
		t.Fatalf("expected peer to be persisted as offline after cleanup, got %#v", stored)
	}
	if stored.LastSeenUnix != 5 {
		t.Fatalf("expected last seen to remain unchanged after cleanup, got %d", stored.LastSeenUnix)
	}

	events, err := auditRepo.ListRecent(10)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	found := false
	for _, event := range events {
		if event.Type == "peer.expired" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected peer.expired audit event after cleanup")
	}
}

func TestPostgresPersistsSensitiveNetworkDeviceApprovals(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()

	userRepo := postgres.NewUserRepo(db)
	deviceRepo := postgres.NewDeviceRepo(db)
	networkRepo := postgres.NewNetworkRepo(db)
	inviteRepo := postgres.NewInviteRepo(db)
	auditRepo := postgres.NewAuditRepo(db)
	poolRepo := postgres.NewVirtualIPPoolRepo(db)
	peerRepo := postgres.NewPeerRepo(db)
	sessionRepo := postgres.NewSessionRepo(db)

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	devices := domain.NewDeviceService(deviceRepo, auditRepo)
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)
	peers := domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo)

	owner, err := auth.Register("owner-sensitive@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	member, err := auth.Register("member-sensitive@example.com", "secret")
	if err != nil {
		t.Fatalf("register member: %v", err)
	}
	memberDevice, err := devices.Enroll(member.ID, "member-sensitive", "member-sensitive-pub", 10)
	if err != nil {
		t.Fatalf("enroll member device: %v", err)
	}

	network, err := networks.CreateNetworkWithPolicy(owner.ID, "sensitive", domain.NetworkAccessInviteOnly, true)
	if err != nil {
		t.Fatalf("create sensitive network: %v", err)
	}
	if err := networks.AddMember(owner.ID, network.ID, member.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if _, err := peers.RegisterPeer(member.ID, memberDevice.ID, network.ID, "127.0.0.1:4013", 20); err != domain.ErrDeviceApprovalRequired {
		t.Fatalf("expected device approval requirement, got %v", err)
	}
	if _, err := networks.ApproveDevice(owner.ID, network.ID, memberDevice.ID, 21); err != nil {
		t.Fatalf("approve device: %v", err)
	}

	storedNetwork, err := networkRepo.FindByID(network.ID)
	if err != nil {
		t.Fatalf("reload network: %v", err)
	}
	if storedNetwork == nil || !storedNetwork.DeviceApprovalRequired || !storedNetwork.IsDeviceApproved(memberDevice.ID) {
		t.Fatalf("expected persisted sensitive-network approval, got %#v", storedNetwork)
	}

	if _, err := peers.RegisterPeer(member.ID, memberDevice.ID, network.ID, "127.0.0.1:4013", 22); err != nil {
		t.Fatalf("register approved member peer: %v", err)
	}
}

func TestPostgresPersistsNetworkNameResolutionPolicy(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()

	userRepo := postgres.NewUserRepo(db)
	networkRepo := postgres.NewNetworkRepo(db)
	inviteRepo := postgres.NewInviteRepo(db)
	auditRepo := postgres.NewAuditRepo(db)
	sessionRepo := postgres.NewSessionRepo(db)

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)

	owner, err := auth.Register("dns-postgres@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	network, err := networks.CreateNetworkWithOptions(owner.ID, "friends", domain.NetworkAccessInviteOnly, domain.NetworkCreateOptions{
		NameResolutionMode: domain.NetworkNameResolutionNetworkOnly,
		DNSLabel:           "friends-lan",
	})
	if err != nil {
		t.Fatalf("create network with dns policy: %v", err)
	}

	storedNetwork, err := networkRepo.FindByID(network.ID)
	if err != nil {
		t.Fatalf("reload network: %v", err)
	}
	if storedNetwork == nil || storedNetwork.NameResolutionMode != domain.NetworkNameResolutionNetworkOnly || storedNetwork.DNSLabel != "friends-lan" {
		t.Fatalf("expected persisted network dns policy, got %#v", storedNetwork)
	}

	updated, err := networks.UpdateNameResolutionPolicy(owner.ID, network.ID, domain.NetworkNameResolutionDisabled, "ignored")
	if err != nil {
		t.Fatalf("disable name resolution: %v", err)
	}
	if updated.NameResolutionMode != domain.NetworkNameResolutionDisabled || updated.DNSLabel != "" {
		t.Fatalf("expected disabled network dns policy, got %#v", updated)
	}
}

func TestPostgresPersistsNetworkRoutingPolicy(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()

	userRepo := postgres.NewUserRepo(db)
	networkRepo := postgres.NewNetworkRepo(db)
	inviteRepo := postgres.NewInviteRepo(db)
	auditRepo := postgres.NewAuditRepo(db)
	sessionRepo := postgres.NewSessionRepo(db)

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)

	owner, err := auth.Register("routing-postgres@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	network, err := networks.CreateNetworkWithOptions(owner.ID, "friends", domain.NetworkAccessInviteOnly, domain.NetworkCreateOptions{
		RoutingPolicy: domain.NetworkRoutingPolicyFull,
	})
	if err != nil {
		t.Fatalf("create network with routing policy: %v", err)
	}

	storedNetwork, err := networkRepo.FindByID(network.ID)
	if err != nil {
		t.Fatalf("reload network: %v", err)
	}
	if storedNetwork == nil || storedNetwork.RoutingPolicy != domain.NetworkRoutingPolicyFull {
		t.Fatalf("expected persisted network routing policy, got %#v", storedNetwork)
	}

	updated, err := networks.UpdateRoutingPolicy(owner.ID, network.ID, domain.NetworkRoutingPolicySplit)
	if err != nil {
		t.Fatalf("update routing policy: %v", err)
	}
	if updated.RoutingPolicy != domain.NetworkRoutingPolicySplit {
		t.Fatalf("expected split routing policy, got %#v", updated)
	}
}

func TestPostgresPersistsNetworkGroupTrafficPolicy(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()

	userRepo := postgres.NewUserRepo(db)
	networkRepo := postgres.NewNetworkRepo(db)
	inviteRepo := postgres.NewInviteRepo(db)
	auditRepo := postgres.NewAuditRepo(db)
	sessionRepo := postgres.NewSessionRepo(db)

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)

	owner, err := auth.Register("group-postgres@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	network, err := networks.CreateNetworkWithOptions(owner.ID, "friends", domain.NetworkAccessInviteOnly, domain.NetworkCreateOptions{
		GroupTrafficPolicy: domain.NetworkGroupTrafficPolicyFlood,
	})
	if err != nil {
		t.Fatalf("create network with group traffic policy: %v", err)
	}

	storedNetwork, err := networkRepo.FindByID(network.ID)
	if err != nil {
		t.Fatalf("reload network: %v", err)
	}
	if storedNetwork == nil || storedNetwork.GroupTrafficPolicy != domain.NetworkGroupTrafficPolicyFlood {
		t.Fatalf("expected persisted network group traffic policy, got %#v", storedNetwork)
	}

	updated, err := networks.UpdateGroupTrafficPolicy(owner.ID, network.ID, domain.NetworkGroupTrafficPolicyBlocked)
	if err != nil {
		t.Fatalf("update group traffic policy: %v", err)
	}
	if updated.GroupTrafficPolicy != domain.NetworkGroupTrafficPolicyBlocked {
		t.Fatalf("expected blocked group traffic policy, got %#v", updated)
	}
}

func TestPostgresPersistsNetworkFileTransferPolicy(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()

	userRepo := postgres.NewUserRepo(db)
	networkRepo := postgres.NewNetworkRepo(db)
	inviteRepo := postgres.NewInviteRepo(db)
	auditRepo := postgres.NewAuditRepo(db)
	sessionRepo := postgres.NewSessionRepo(db)

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)

	owner, err := auth.Register("file-policy@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	network, err := networks.CreateNetworkWithOptions(owner.ID, "friends", domain.NetworkAccessPrivate, domain.NetworkCreateOptions{
		FileTransfersEnabledSet: true,
		FileTransfersEnabled:    false,
		FileTransferMaxBytes:    2048,
	})
	if err != nil {
		t.Fatalf("create network with file-transfer policy: %v", err)
	}

	storedNetwork, err := networkRepo.FindByID(network.ID)
	if err != nil {
		t.Fatalf("find stored network: %v", err)
	}
	if storedNetwork == nil || storedNetwork.FileTransfersEnabled || storedNetwork.FileTransferMaxBytes != 2048 {
		t.Fatalf("expected persisted network file-transfer policy, got %#v", storedNetwork)
	}

	updated, err := networks.UpdateFileTransferPolicy(owner.ID, network.ID, true, 4096)
	if err != nil {
		t.Fatalf("update file-transfer policy: %v", err)
	}
	if !updated.FileTransfersEnabled || updated.FileTransferMaxBytes != 4096 {
		t.Fatalf("expected enabled network file-transfer policy, got %#v", updated)
	}
}

func TestPostgresPersistsChunkedFileTransferUploadState(t *testing.T) {
	db, cleanup := openIntegrationDB(t)
	defer cleanup()

	userRepo := postgres.NewUserRepo(db)
	deviceRepo := postgres.NewDeviceRepo(db)
	networkRepo := postgres.NewNetworkRepo(db)
	peerRepo := postgres.NewPeerRepo(db)
	fileTransferRepo := postgres.NewFileTransferRepo(db)
	fileTransferPayloadRepo := postgres.NewFileTransferPayloadRepo(db)
	inviteRepo := postgres.NewInviteRepo(db)
	auditRepo := postgres.NewAuditRepo(db)
	poolRepo := postgres.NewVirtualIPPoolRepo(db)
	sessionRepo := postgres.NewSessionRepo(db)

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	devices := domain.NewDeviceService(deviceRepo, auditRepo)
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)
	peers := domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo)
	transfers := domain.NewFileTransferService(fileTransferRepo, peerRepo, networkRepo, auditRepo, fileTransferPayloadRepo)

	owner, err := auth.Register("owner-chunk-postgres@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	member, err := auth.Register("member-chunk-postgres@example.com", "secret")
	if err != nil {
		t.Fatalf("register member: %v", err)
	}
	ownerDevice, _ := devices.Enroll(owner.ID, "owner-device", "owner-pub", 100)
	memberDevice, _ := devices.Enroll(member.ID, "member-device", "member-pub", 101)
	network, err := networks.CreateNetwork(owner.ID, "chunk-postgres", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if err := networks.AddMember(owner.ID, network.ID, member.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}
	ownerPeer, err := peers.RegisterPeer(owner.ID, ownerDevice.ID, network.ID, "127.0.0.1:9920", 102)
	if err != nil {
		t.Fatalf("register owner peer: %v", err)
	}
	memberPeer, err := peers.RegisterPeer(member.ID, memberDevice.ID, network.ID, "127.0.0.1:9921", 103)
	if err != nil {
		t.Fatalf("register member peer: %v", err)
	}

	payload := []byte("abcdefgh")
	transfer, err := transfers.CreateTransfer(member.ID, network.ID, memberPeer.ID, ownerPeer.ID, "chunked.bin", int64(len(payload)))
	if err != nil {
		t.Fatalf("create transfer: %v", err)
	}
	first, err := transfers.UploadTransferPayloadChunk(member.ID, transfer.ID, "application/octet-stream", 0, payload[:3], 120)
	if err != nil {
		t.Fatalf("upload first chunk: %v", err)
	}
	if first.PayloadReady || first.PayloadUploadedBytes != 3 {
		t.Fatalf("expected partial upload metadata after first chunk, got %#v", first)
	}
	storedTransfer, err := fileTransferRepo.FindByID(transfer.ID)
	if err != nil {
		t.Fatalf("find stored transfer after first chunk: %v", err)
	}
	if storedTransfer == nil || storedTransfer.PayloadReady || storedTransfer.PayloadUploadedBytes != 3 {
		t.Fatalf("expected persisted partial upload metadata, got %#v", storedTransfer)
	}

	final, err := transfers.UploadTransferPayloadChunk(member.ID, transfer.ID, "application/octet-stream", 3, payload[3:], 121)
	if err != nil {
		t.Fatalf("upload final chunk: %v", err)
	}
	if !final.PayloadReady || final.PayloadUploadedBytes != int64(len(payload)) || final.PayloadSHA256 == "" {
		t.Fatalf("expected completed upload metadata after final chunk, got %#v", final)
	}
}

func openIntegrationDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()

	adminDSN := strings.TrimSpace(os.Getenv("OLE_TEST_DATABASE_URL"))
	if adminDSN == "" {
		adminDSN = strings.TrimSpace(os.Getenv("OLE_DATABASE_URL"))
	}
	if adminDSN == "" {
		adminDSN = "postgres://postgres:postgres@localhost:5432/ole?sslmode=disable"
	}

	adminDB, err := sql.Open("pgx", adminDSN)
	if err != nil {
		t.Fatalf("open postgres admin connection: %v", err)
	}
	if err := postgres.Ping(adminDB); err != nil {
		_ = adminDB.Close()
		t.Skipf("postgres integration test skipped: %v", err)
	}

	schemaName := fmt.Sprintf("ole_test_%d", time.Now().UnixNano())
	if _, err := adminDB.ExecContext(context.Background(), "CREATE SCHEMA "+schemaName); err != nil {
		_ = adminDB.Close()
		t.Fatalf("create test schema %s: %v", schemaName, err)
	}

	testDSN := withSearchPath(adminDSN, schemaName)
	testDB, err := sql.Open("pgx", testDSN)
	if err != nil {
		_, _ = adminDB.ExecContext(context.Background(), "DROP SCHEMA "+schemaName+" CASCADE")
		_ = adminDB.Close()
		t.Fatalf("open postgres test connection: %v", err)
	}
	testDB.SetMaxOpenConns(1)

	if err := postgres.RunMigrations(context.Background(), testDB, migrationsDir(t)); err != nil {
		_ = testDB.Close()
		_, _ = adminDB.ExecContext(context.Background(), "DROP SCHEMA "+schemaName+" CASCADE")
		_ = adminDB.Close()
		t.Fatalf("run migrations: %v", err)
	}

	cleanup := func() {
		_ = testDB.Close()
		_, _ = adminDB.ExecContext(context.Background(), "DROP SCHEMA "+schemaName+" CASCADE")
		_ = adminDB.Close()
	}

	return testDB, cleanup
}

func withSearchPath(dsn, schemaName string) string {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}

	query := parsed.Query()
	searchPathOption := "-csearch_path=" + schemaName
	if existing := strings.TrimSpace(query.Get("options")); existing != "" {
		query.Set("options", existing+" "+searchPathOption)
	} else {
		query.Set("options", searchPathOption)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func migrationsDir(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve current file for migrations path")
	}
	return filepath.Join(filepath.Dir(file), "migrations")
}

func containsSessionID(sessions []*domain.SessionToken, target string) bool {
	for _, session := range sessions {
		if session.ID == target {
			return true
		}
	}
	return false
}
