package domain_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/memory"
	"bytes"
	"net"
	"testing"
)

func TestAuthAndNetworkInviteFlow(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	peerRepo := memory.NewPeerRepo()
	tunnelRepo := memory.NewTunnelRepo()
	sessionRepo := memory.NewSessionRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	devices := domain.NewDeviceService(deviceRepo, auditRepo)
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)
	peers := domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo)
	tunnels := domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo)

	owner, err := auth.Register("owner@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	member, err := auth.Register("member@example.com", "secret")
	if err != nil {
		t.Fatalf("register member: %v", err)
	}
	ownerDevice, err := devices.Enroll(owner.ID, "owner-laptop", "owner-pub", 10)
	if err != nil {
		t.Fatalf("enroll owner device: %v", err)
	}
	memberDevice, err := devices.Enroll(member.ID, "member-laptop", "member-pub", 11)
	if err != nil {
		t.Fatalf("enroll member device: %v", err)
	}

	network, err := networks.CreateNetwork(owner.ID, "team", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}

	invite, err := networks.GenerateInvite(owner.ID, network.ID, 3600, 1, 100)
	if err != nil {
		t.Fatalf("generate invite: %v", err)
	}

	joined, err := networks.JoinByInvite(member.ID, invite.Code, 200)
	if err != nil {
		t.Fatalf("join by invite: %v", err)
	}
	if !joined.HasMember(member.ID) {
		t.Fatalf("expected member to join network")
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
	if peerA.OverlayCIDR == "" || peerA.OverlayCIDR != peerB.OverlayCIDR {
		t.Fatalf("expected peers on same network to share overlay CIDR, got %q and %q", peerA.OverlayCIDR, peerB.OverlayCIDR)
	}

	tunnel, err := tunnels.RequestTunnel(network.ID, peerA.ID, peerB.ID, "", 400)
	if err != nil {
		t.Fatalf("request tunnel: %v", err)
	}
	if tunnel.Mode != domain.TunnelModeP2P {
		t.Fatalf("expected P2P tunnel, got %s", tunnel.Mode)
	}
	if tunnel.State != domain.TunnelStateNegotiating {
		t.Fatalf("expected tunnel to start in negotiating state, got %s", tunnel.State)
	}
	if err := tunnels.OpenTunnel(tunnel.ID); err != nil {
		t.Fatalf("open tunnel: %v", err)
	}
	opened, err := tunnelRepo.FindByID(tunnel.ID)
	if err != nil {
		t.Fatalf("reload opened tunnel: %v", err)
	}
	if opened == nil || opened.State != domain.TunnelStateOpen {
		t.Fatalf("expected open tunnel state, got %#v", opened)
	}
}

func TestInviteCannotBeOverused(t *testing.T) {
	invite := &domain.Invite{
		Code:          "abc",
		ExpiresAtUnix: 1000,
		MaxUses:       1,
	}
	if err := invite.UseOnce(100); err != nil {
		t.Fatalf("first use failed: %v", err)
	}
	if err := invite.UseOnce(101); err == nil {
		t.Fatalf("expected invite exhaustion")
	}
}

func TestRefreshTokenRotationAndRevokeAllSessions(t *testing.T) {
	userRepo := memory.NewUserRepo()
	auditRepo := memory.NewAuditRepo()
	sessionRepo := memory.NewSessionRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	user, err := auth.Register("rotate@example.com", "secret")
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	session, err := auth.Login(user.Email, "secret", domain.SessionMetadata{DeviceName: "test"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	oldRefresh := session.RefreshToken

	rotated, err := auth.Refresh(oldRefresh, domain.SessionMetadata{DeviceName: "test"})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if rotated.RefreshToken == oldRefresh {
		t.Fatalf("expected refresh token rotation")
	}
	if _, err := auth.Refresh(oldRefresh, domain.SessionMetadata{DeviceName: "test"}); err == nil {
		t.Fatalf("expected old refresh token to be invalid after rotation")
	}
	events, err := auditRepo.ListRecent(10)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	foundReuseAudit := false
	for _, event := range events {
		if event.Type == "session.reuse_detected" && event.ActorUserID == user.ID && event.Details == session.FamilyID {
			foundReuseAudit = true
			break
		}
	}
	if !foundReuseAudit {
		t.Fatalf("expected session.reuse_detected audit event, got %#v", events)
	}

	if err := auth.RevokeAllSessions(user.ID); err != nil {
		t.Fatalf("revoke all sessions: %v", err)
	}
	if _, err := auth.ValidateAccessToken(rotated.AccessToken); err == nil {
		t.Fatalf("expected revoked access token to be invalid")
	}
}

func TestDeviceLifecycleAndPeerBinding(t *testing.T) {
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

	user, err := auth.Register("device@example.com", "secret")
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	device, err := devices.Enroll(user.ID, "workstation", "pub-key", 100)
	if err != nil {
		t.Fatalf("enroll device: %v", err)
	}
	if device.Fingerprint == "" {
		t.Fatalf("expected fingerprint to be generated")
	}
	device, err = devices.Rename(user.ID, device.ID, "desk-pc")
	if err != nil {
		t.Fatalf("rename device: %v", err)
	}
	if device.Name != "desk-pc" {
		t.Fatalf("unexpected device name: %s", device.Name)
	}

	network, err := networks.CreateNetwork(user.ID, "ops", domain.NetworkAccessPrivate)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	peer, err := peers.RegisterPeer(user.ID, device.ID, network.ID, "127.0.0.1:9000", 120)
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}
	if peer.DeviceID != device.ID {
		t.Fatalf("expected peer device id %s, got %s", device.ID.String(), peer.DeviceID.String())
	}
	if peer.OverlayCIDR == "" {
		t.Fatalf("expected peer registration to expose overlay CIDR")
	}

	if err := devices.Revoke(user.ID, device.ID, 130); err != nil {
		t.Fatalf("revoke device: %v", err)
	}
	if _, err := peers.RegisterPeer(user.ID, device.ID, network.ID, "127.0.0.1:9001", 131); err == nil {
		t.Fatalf("expected revoked device to be rejected")
	}
}

func TestSensitiveNetworkRequiresApprovedDeviceForNonOwnerPeerRegistration(t *testing.T) {
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

	owner, err := auth.Register("owner-sensitive@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	member, err := auth.Register("member-sensitive@example.com", "secret")
	if err != nil {
		t.Fatalf("register member: %v", err)
	}
	memberDevice, err := devices.Enroll(member.ID, "member-laptop", "member-sensitive-pub", 100)
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

	if _, err := peers.RegisterPeer(member.ID, memberDevice.ID, network.ID, "127.0.0.1:9002", 110); err == nil {
		t.Fatalf("expected unapproved member device to be rejected")
	} else if err != domain.ErrDeviceApprovalRequired {
		t.Fatalf("expected device approval required, got %v", err)
	}

	if _, err := networks.ApproveDevice(owner.ID, network.ID, memberDevice.ID, 111); err != nil {
		t.Fatalf("approve device: %v", err)
	}
	peer, err := peers.RegisterPeer(member.ID, memberDevice.ID, network.ID, "127.0.0.1:9002", 112)
	if err != nil {
		t.Fatalf("register approved device peer: %v", err)
	}
	if peer.DeviceID != memberDevice.ID {
		t.Fatalf("expected approved peer to bind device %s, got %s", memberDevice.ID.String(), peer.DeviceID.String())
	}
}

func TestNetworkVisibilityAndPermissionBoundaries(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	peerRepo := memory.NewPeerRepo()
	tunnelRepo := memory.NewTunnelRepo()
	sessionRepo := memory.NewSessionRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	devices := domain.NewDeviceService(deviceRepo, auditRepo)
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)
	peers := domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo)
	tunnels := domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo)

	owner, err := auth.Register("owner-perms@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	readOnlyUser, err := auth.Register("readonly-perms@example.com", "secret")
	if err != nil {
		t.Fatalf("register read-only user: %v", err)
	}
	outsider, err := auth.Register("outsider-perms@example.com", "secret")
	if err != nil {
		t.Fatalf("register outsider: %v", err)
	}

	ownerDeviceA, err := devices.Enroll(owner.ID, "owner-device-a", "owner-perms-pub-a", 100)
	if err != nil {
		t.Fatalf("enroll owner device A: %v", err)
	}
	ownerDeviceB, err := devices.Enroll(owner.ID, "owner-device-b", "owner-perms-pub-b", 101)
	if err != nil {
		t.Fatalf("enroll owner device B: %v", err)
	}

	network, err := networks.CreateNetwork(owner.ID, "perms", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if err := networks.AddMember(owner.ID, network.ID, readOnlyUser.ID); err != nil {
		t.Fatalf("add read-only member: %v", err)
	}
	if err := networks.ChangeMemberRole(owner.ID, network.ID, readOnlyUser.ID, domain.NetworkRoleReadOnly); err != nil {
		t.Fatalf("change member role to read-only: %v", err)
	}

	peerA, err := peers.RegisterPeer(owner.ID, ownerDeviceA.ID, network.ID, "127.0.0.1:9100", 110)
	if err != nil {
		t.Fatalf("register peer A: %v", err)
	}
	peerB, err := peers.RegisterPeer(owner.ID, ownerDeviceB.ID, network.ID, "127.0.0.1:9101", 111)
	if err != nil {
		t.Fatalf("register peer B: %v", err)
	}
	tunnel, err := tunnels.RequestTunnelForUser(owner.ID, network.ID, peerA.ID, peerB.ID, domain.TunnelModeP2P, 120)
	if err != nil {
		t.Fatalf("request tunnel: %v", err)
	}

	visible, err := networks.ListVisibleNetworks(readOnlyUser.ID)
	if err != nil {
		t.Fatalf("list visible networks for read-only user: %v", err)
	}
	if len(visible) != 1 || visible[0].ID != network.ID {
		t.Fatalf("expected one visible network for read-only user, got %#v", visible)
	}
	visible, err = networks.ListVisibleNetworks(outsider.ID)
	if err != nil {
		t.Fatalf("list visible networks for outsider: %v", err)
	}
	if len(visible) != 0 {
		t.Fatalf("expected outsider to see no networks, got %#v", visible)
	}

	if _, err := networks.GetNetwork(readOnlyUser.ID, network.ID); err != nil {
		t.Fatalf("read-only member should be able to get network: %v", err)
	}
	if _, err := networks.GetNetwork(outsider.ID, network.ID); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider get network to fail with unauthorized, got %v", err)
	}

	listedPeers, err := peers.ListPeersForUser(readOnlyUser.ID, network.ID)
	if err != nil {
		t.Fatalf("read-only member should be able to list peers: %v", err)
	}
	if len(listedPeers) != 2 {
		t.Fatalf("expected two peers visible to read-only member, got %d", len(listedPeers))
	}
	if _, err := peers.ListPeersForUser(outsider.ID, network.ID); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider peer list to fail with unauthorized, got %v", err)
	}

	if _, err := peers.GetPeerForUser(readOnlyUser.ID, peerA.ID); err != nil {
		t.Fatalf("read-only member should be able to get peer: %v", err)
	}
	if _, err := peers.GetPeerForUser(outsider.ID, peerA.ID); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider get peer to fail with unauthorized, got %v", err)
	}

	listedTunnels, err := tunnels.ListTunnelsForUser(readOnlyUser.ID, network.ID)
	if err != nil {
		t.Fatalf("read-only member should be able to list tunnels: %v", err)
	}
	if len(listedTunnels) != 1 || listedTunnels[0].ID != tunnel.ID {
		t.Fatalf("expected one visible tunnel for read-only member, got %#v", listedTunnels)
	}
	if _, err := tunnels.ListTunnelsForUser(outsider.ID, network.ID); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider tunnel list to fail with unauthorized, got %v", err)
	}

	if _, err := tunnels.GetTunnelForUser(readOnlyUser.ID, tunnel.ID); err != nil {
		t.Fatalf("read-only member should be able to get tunnel: %v", err)
	}
	if _, err := tunnels.GetTunnelForUser(outsider.ID, tunnel.ID); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider get tunnel to fail with unauthorized, got %v", err)
	}

	if _, err := networks.UpdateRoutingPolicy(readOnlyUser.ID, network.ID, domain.NetworkRoutingPolicySplit); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only routing update to fail with insufficient role, got %v", err)
	}
}

func TestNetworkManagePermissionBoundaries(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	sessionRepo := memory.NewSessionRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	devices := domain.NewDeviceService(deviceRepo, auditRepo)
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)

	owner, err := auth.Register("owner-manage@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	adminUser, err := auth.Register("admin-manage@example.com", "secret")
	if err != nil {
		t.Fatalf("register admin: %v", err)
	}
	readOnlyUser, err := auth.Register("readonly-manage@example.com", "secret")
	if err != nil {
		t.Fatalf("register read-only: %v", err)
	}
	outsider, err := auth.Register("outsider-manage@example.com", "secret")
	if err != nil {
		t.Fatalf("register outsider: %v", err)
	}
	newMember, err := auth.Register("new-member-manage@example.com", "secret")
	if err != nil {
		t.Fatalf("register new member: %v", err)
	}

	adminDevice, err := devices.Enroll(adminUser.ID, "admin-device", "admin-manage-pub", 100)
	if err != nil {
		t.Fatalf("enroll admin device: %v", err)
	}

	network, err := networks.CreateNetworkWithPolicy(owner.ID, "manage-boundary", domain.NetworkAccessInviteOnly, true)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if err := networks.AddMember(owner.ID, network.ID, adminUser.ID); err != nil {
		t.Fatalf("add admin user: %v", err)
	}
	if err := networks.ChangeMemberRole(owner.ID, network.ID, adminUser.ID, domain.NetworkRoleAdmin); err != nil {
		t.Fatalf("set admin role: %v", err)
	}
	if err := networks.AddMember(owner.ID, network.ID, readOnlyUser.ID); err != nil {
		t.Fatalf("add read-only user: %v", err)
	}
	if err := networks.ChangeMemberRole(owner.ID, network.ID, readOnlyUser.ID, domain.NetworkRoleReadOnly); err != nil {
		t.Fatalf("set read-only role: %v", err)
	}

	if err := networks.AddMember(adminUser.ID, network.ID, newMember.ID); err != nil {
		t.Fatalf("admin should be able to add member: %v", err)
	}
	invite, err := networks.GenerateInvite(adminUser.ID, network.ID, 3600, 1, 110)
	if err != nil {
		t.Fatalf("admin should be able to generate invite: %v", err)
	}
	if invite.NetworkID != network.ID {
		t.Fatalf("expected invite for %s, got %s", network.ID.String(), invite.NetworkID.String())
	}
	if _, err := networks.ApproveDevice(adminUser.ID, network.ID, adminDevice.ID, 111); err != nil {
		t.Fatalf("admin should be able to approve device: %v", err)
	}

	if err := networks.AddMember(readOnlyUser.ID, network.ID, outsider.ID); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only add member to fail with insufficient role, got %v", err)
	}
	if _, err := networks.GenerateInvite(readOnlyUser.ID, network.ID, 3600, 1, 120); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only invite generation to fail with insufficient role, got %v", err)
	}
	if _, err := networks.ApproveDevice(readOnlyUser.ID, network.ID, adminDevice.ID, 121); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only device approval to fail with insufficient role, got %v", err)
	}

	if err := networks.AddMember(outsider.ID, network.ID, outsider.ID); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider add member to fail with unauthorized, got %v", err)
	}
	if _, err := networks.GenerateInvite(outsider.ID, network.ID, 3600, 1, 130); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider invite generation to fail with unauthorized, got %v", err)
	}
	if _, err := networks.ApproveDevice(outsider.ID, network.ID, adminDevice.ID, 131); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider device approval to fail with unauthorized, got %v", err)
	}
	if err := networks.ChangeMemberRole(adminUser.ID, network.ID, newMember.ID, domain.NetworkRoleModerator); err != domain.ErrOnlyOwnerCanManage {
		t.Fatalf("expected admin role change to remain owner-only, got %v", err)
	}
}

func TestNetworkAuditModerationBoundaries(t *testing.T) {
	userRepo := memory.NewUserRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	sessionRepo := memory.NewSessionRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)

	owner, err := auth.Register("owner-audit@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	adminUser, err := auth.Register("admin-audit@example.com", "secret")
	if err != nil {
		t.Fatalf("register admin: %v", err)
	}
	moderatorUser, err := auth.Register("moderator-audit@example.com", "secret")
	if err != nil {
		t.Fatalf("register moderator: %v", err)
	}
	fileAdminUser, err := auth.Register("file-admin-audit@example.com", "secret")
	if err != nil {
		t.Fatalf("register file admin: %v", err)
	}
	memberUser, err := auth.Register("member-audit@example.com", "secret")
	if err != nil {
		t.Fatalf("register member: %v", err)
	}
	readOnlyUser, err := auth.Register("readonly-audit@example.com", "secret")
	if err != nil {
		t.Fatalf("register read-only: %v", err)
	}
	outsider, err := auth.Register("outsider-audit@example.com", "secret")
	if err != nil {
		t.Fatalf("register outsider: %v", err)
	}

	network, err := networks.CreateNetwork(owner.ID, "audit-boundary", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	assignRole := func(user domain.UserID, role domain.NetworkRole) {
		if err := networks.AddMember(owner.ID, network.ID, user); err != nil {
			t.Fatalf("add member %s: %v", user.String(), err)
		}
		if role != domain.NetworkRoleMember {
			if err := networks.ChangeMemberRole(owner.ID, network.ID, user, role); err != nil {
				t.Fatalf("set role %s for %s: %v", role, user.String(), err)
			}
		}
	}
	assignRole(adminUser.ID, domain.NetworkRoleAdmin)
	assignRole(moderatorUser.ID, domain.NetworkRoleModerator)
	assignRole(fileAdminUser.ID, domain.NetworkRoleFileAdmin)
	assignRole(memberUser.ID, domain.NetworkRoleMember)
	assignRole(readOnlyUser.ID, domain.NetworkRoleReadOnly)

	_ = auditRepo.Append(&domain.AuditEvent{
		ID:            "aud-net-1",
		ActorUserID:   owner.ID,
		NetworkID:     network.ID,
		Type:          "network.member_added",
		Details:       memberUser.ID.String(),
		CreatedAtUnix: 100,
	})
	_ = auditRepo.Append(&domain.AuditEvent{
		ID:            "aud-net-2",
		ActorUserID:   moderatorUser.ID,
		NetworkID:     network.ID,
		Type:          "peer.registered",
		Details:       "peer-1",
		CreatedAtUnix: 101,
	})
	_ = auditRepo.Append(&domain.AuditEvent{
		ID:            "aud-other",
		ActorUserID:   outsider.ID,
		NetworkID:     domain.NetworkID{Value: "net-other"},
		Type:          "network.created",
		Details:       "net-other",
		CreatedAtUnix: 102,
	})

	adminEvents, err := networks.ListAuditEventsForUser(adminUser.ID, network.ID, 10)
	if err != nil {
		t.Fatalf("admin should be able to list network audit events: %v", err)
	}
	if len(adminEvents) == 0 {
		t.Fatalf("expected admin to see network audit events")
	}
	adminIDs := map[string]bool{}
	for _, event := range adminEvents {
		if event.NetworkID != network.ID {
			t.Fatalf("expected admin audit events to stay scoped to %s, got %#v", network.ID.String(), adminEvents)
		}
		adminIDs[event.ID] = true
	}
	if !adminIDs["aud-net-1"] || !adminIDs["aud-net-2"] {
		t.Fatalf("expected admin audit view to include inserted events, got %#v", adminEvents)
	}

	moderatorEvents, err := networks.ListAuditEventsForUser(moderatorUser.ID, network.ID, 10)
	if err != nil {
		t.Fatalf("moderator should be able to list network audit events: %v", err)
	}
	if len(moderatorEvents) == 0 {
		t.Fatalf("expected moderator to see network audit events")
	}
	for _, event := range moderatorEvents {
		if event.NetworkID != network.ID {
			t.Fatalf("expected moderator audit events to stay scoped to %s, got %#v", network.ID.String(), moderatorEvents)
		}
	}

	if _, err := networks.ListAuditEventsForUser(fileAdminUser.ID, network.ID, 10); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected file admin audit view to fail with insufficient role, got %v", err)
	}
	if _, err := networks.ListAuditEventsForUser(memberUser.ID, network.ID, 10); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected member audit view to fail with insufficient role, got %v", err)
	}
	if _, err := networks.ListAuditEventsForUser(readOnlyUser.ID, network.ID, 10); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only audit view to fail with insufficient role, got %v", err)
	}
	if _, err := networks.ListAuditEventsForUser(outsider.ID, network.ID, 10); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider audit view to fail with unauthorized, got %v", err)
	}
}

func TestPeerOwnershipBoundariesForHeartbeatAndDisconnect(t *testing.T) {
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

	owner, err := auth.Register("owner-peer-ops@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	outsider, err := auth.Register("outsider-peer-ops@example.com", "secret")
	if err != nil {
		t.Fatalf("register outsider: %v", err)
	}

	device, err := devices.Enroll(owner.ID, "owner-peer-device", "owner-peer-pub", 100)
	if err != nil {
		t.Fatalf("enroll owner device: %v", err)
	}
	network, err := networks.CreateNetwork(owner.ID, "peer-ops", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	peer, err := peers.RegisterPeer(owner.ID, device.ID, network.ID, "127.0.0.1:9300", 110)
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}

	if err := peers.HeartbeatForUser(outsider.ID, peer.ID, "127.0.0.1:9301", 120); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider heartbeat to fail with unauthorized, got %v", err)
	}
	if err := peers.DisconnectForUser(outsider.ID, peer.ID, 121); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider disconnect to fail with unauthorized, got %v", err)
	}

	if err := peers.HeartbeatForUser(owner.ID, peer.ID, "127.0.0.1:9301", 122); err != nil {
		t.Fatalf("expected owner heartbeat to succeed: %v", err)
	}
	updatedPeer, err := peers.GetPeer(peer.ID)
	if err != nil {
		t.Fatalf("reload peer after heartbeat: %v", err)
	}
	if updatedPeer.Endpoint != "127.0.0.1:9301" || updatedPeer.Status != domain.PeerStatusOnline {
		t.Fatalf("expected heartbeat to update endpoint/status, got %#v", updatedPeer)
	}

	if err := peers.DisconnectForUser(owner.ID, peer.ID, 123); err != nil {
		t.Fatalf("expected owner disconnect to succeed: %v", err)
	}
	updatedPeer, err = peers.GetPeer(peer.ID)
	if err != nil {
		t.Fatalf("reload peer after disconnect: %v", err)
	}
	if updatedPeer.Status != domain.PeerStatusOffline || updatedPeer.ConnectionState != domain.ConnectionStateIdle {
		t.Fatalf("expected disconnect to mark peer offline and idle, got %#v", updatedPeer)
	}
}

func TestDeleteNetworkPermissionBoundaries(t *testing.T) {
	userRepo := memory.NewUserRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	sessionRepo := memory.NewSessionRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)

	owner, err := auth.Register("owner-delete@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	adminUser, err := auth.Register("admin-delete@example.com", "secret")
	if err != nil {
		t.Fatalf("register admin: %v", err)
	}
	readOnlyUser, err := auth.Register("readonly-delete@example.com", "secret")
	if err != nil {
		t.Fatalf("register read-only: %v", err)
	}
	outsider, err := auth.Register("outsider-delete@example.com", "secret")
	if err != nil {
		t.Fatalf("register outsider: %v", err)
	}

	createFixture := func(name string) *domain.Network {
		network, err := networks.CreateNetwork(owner.ID, name, domain.NetworkAccessInviteOnly)
		if err != nil {
			t.Fatalf("create network %q: %v", name, err)
		}
		if err := networks.AddMember(owner.ID, network.ID, adminUser.ID); err != nil {
			t.Fatalf("add admin to %q: %v", name, err)
		}
		if err := networks.ChangeMemberRole(owner.ID, network.ID, adminUser.ID, domain.NetworkRoleAdmin); err != nil {
			t.Fatalf("set admin role on %q: %v", name, err)
		}
		if err := networks.AddMember(owner.ID, network.ID, readOnlyUser.ID); err != nil {
			t.Fatalf("add read-only to %q: %v", name, err)
		}
		if err := networks.ChangeMemberRole(owner.ID, network.ID, readOnlyUser.ID, domain.NetworkRoleReadOnly); err != nil {
			t.Fatalf("set read-only role on %q: %v", name, err)
		}
		return network
	}

	adminNetwork := createFixture("admin-delete-boundary")
	if err := networks.DeleteNetwork(adminUser.ID, adminNetwork.ID); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected admin delete to fail with insufficient role, got %v", err)
	}

	readOnlyNetwork := createFixture("readonly-delete-boundary")
	if err := networks.DeleteNetwork(readOnlyUser.ID, readOnlyNetwork.ID); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only delete to fail with insufficient role, got %v", err)
	}

	outsiderNetwork := createFixture("outsider-delete-boundary")
	if err := networks.DeleteNetwork(outsider.ID, outsiderNetwork.ID); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider delete to fail with unauthorized, got %v", err)
	}

	ownerNetwork := createFixture("owner-delete-boundary")
	if err := networks.DeleteNetwork(owner.ID, ownerNetwork.ID); err != nil {
		t.Fatalf("expected owner delete to succeed: %v", err)
	}
	if _, err := networks.GetNetwork(owner.ID, ownerNetwork.ID); err != domain.ErrNotFound {
		t.Fatalf("expected deleted network to be gone, got %v", err)
	}
}

func TestGetOwnedPeerEnforcesOwnership(t *testing.T) {
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

	owner, err := auth.Register("owner-owned-peer@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	outsider, err := auth.Register("outsider-owned-peer@example.com", "secret")
	if err != nil {
		t.Fatalf("register outsider: %v", err)
	}
	device, err := devices.Enroll(owner.ID, "owned-peer-device", "owned-peer-pub", 100)
	if err != nil {
		t.Fatalf("enroll device: %v", err)
	}
	network, err := networks.CreateNetwork(owner.ID, "owned-peer-net", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	peer, err := peers.RegisterPeer(owner.ID, device.ID, network.ID, "127.0.0.1:9500", 110)
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}

	if _, err := peers.GetOwnedPeer(outsider.ID, peer.ID); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider owned-peer lookup to fail with unauthorized, got %v", err)
	}
	ownedPeer, err := peers.GetOwnedPeer(owner.ID, peer.ID)
	if err != nil {
		t.Fatalf("expected owner owned-peer lookup to succeed: %v", err)
	}
	if ownedPeer.ID != peer.ID {
		t.Fatalf("expected peer %s, got %s", peer.ID.String(), ownedPeer.ID.String())
	}
}

func TestNetworkUsePermissionBoundaries(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	peerRepo := memory.NewPeerRepo()
	tunnelRepo := memory.NewTunnelRepo()
	sessionRepo := memory.NewSessionRepo()
	candidateRepo := memory.NewSignalCandidateRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	devices := domain.NewDeviceService(deviceRepo, auditRepo)
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)
	peers := domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo)
	signaling := domain.NewSignalingService(peerRepo, networkRepo, candidateRepo, auditRepo)
	tunnels := domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo)

	owner, err := auth.Register("owner-use@example.com", "secret")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	member, err := auth.Register("member-use@example.com", "secret")
	if err != nil {
		t.Fatalf("register member: %v", err)
	}
	readOnlyUser, err := auth.Register("readonly-use@example.com", "secret")
	if err != nil {
		t.Fatalf("register read-only: %v", err)
	}
	outsider, err := auth.Register("outsider-use@example.com", "secret")
	if err != nil {
		t.Fatalf("register outsider: %v", err)
	}

	ownerDevice, err := devices.Enroll(owner.ID, "owner-use-device", "owner-use-pub", 100)
	if err != nil {
		t.Fatalf("enroll owner device: %v", err)
	}
	memberDevice, err := devices.Enroll(member.ID, "member-use-device", "member-use-pub", 101)
	if err != nil {
		t.Fatalf("enroll member device: %v", err)
	}
	readOnlyDevice, err := devices.Enroll(readOnlyUser.ID, "readonly-use-device", "readonly-use-pub", 102)
	if err != nil {
		t.Fatalf("enroll read-only device: %v", err)
	}
	outsiderDevice, err := devices.Enroll(outsider.ID, "outsider-use-device", "outsider-use-pub", 103)
	if err != nil {
		t.Fatalf("enroll outsider device: %v", err)
	}

	network, err := networks.CreateNetwork(owner.ID, "use-boundary", domain.NetworkAccessInviteOnly)
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

	ownerPeer, err := peers.RegisterPeer(owner.ID, ownerDevice.ID, network.ID, "127.0.0.1:9700", 110)
	if err != nil {
		t.Fatalf("register owner peer: %v", err)
	}
	memberPeer, err := peers.RegisterPeer(member.ID, memberDevice.ID, network.ID, "127.0.0.1:9701", 111)
	if err != nil {
		t.Fatalf("register member peer: %v", err)
	}
	if _, err := peers.RegisterPeer(readOnlyUser.ID, readOnlyDevice.ID, network.ID, "127.0.0.1:9702", 112); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only register peer to fail with insufficient role, got %v", err)
	}
	if _, err := peers.RegisterPeer(outsider.ID, outsiderDevice.ID, network.ID, "127.0.0.1:9703", 113); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider register peer to fail with unauthorized, got %v", err)
	}

	if _, err := signaling.PublishCandidate(member.ID, memberPeer.ID, domain.SignalCandidateTypeHost, domain.SignalCandidateProtocolUDP, "127.0.0.1:9701", 100, true, 120, 114); err != nil {
		t.Fatalf("member should be able to publish candidate: %v", err)
	}
	if _, err := signaling.ListCandidates(member.ID, memberPeer.ID, 114); err != nil {
		t.Fatalf("member should be able to list candidates: %v", err)
	}
	if err := networks.ChangeMemberRole(owner.ID, network.ID, member.ID, domain.NetworkRoleReadOnly); err != nil {
		t.Fatalf("demote member to read-only: %v", err)
	}
	if _, err := signaling.PublishCandidate(member.ID, memberPeer.ID, domain.SignalCandidateTypeHost, domain.SignalCandidateProtocolUDP, "127.0.0.1:9701", 100, true, 120, 115); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only candidate publish to fail with insufficient role, got %v", err)
	}
	if _, err := signaling.ListCandidates(member.ID, memberPeer.ID, 115); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only candidate list to fail with insufficient role, got %v", err)
	}
	if _, err := signaling.ListCandidates(outsider.ID, memberPeer.ID, 115); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider candidate list to fail with unauthorized, got %v", err)
	}
	if err := peers.HeartbeatForUser(member.ID, memberPeer.ID, "127.0.0.1:9704", 116); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only heartbeat to fail with insufficient role, got %v", err)
	}

	if err := networks.ChangeMemberRole(owner.ID, network.ID, member.ID, domain.NetworkRoleMember); err != nil {
		t.Fatalf("restore member role: %v", err)
	}
	tunnel, err := tunnels.RequestTunnelForUser(member.ID, network.ID, ownerPeer.ID, memberPeer.ID, domain.TunnelModeP2P, 117)
	if err != nil {
		t.Fatalf("member should be able to request tunnel: %v", err)
	}
	if err := tunnels.OpenTunnelForUser(member.ID, tunnel.ID); err != nil {
		t.Fatalf("member should be able to open tunnel: %v", err)
	}
	if _, err := tunnels.RequestTunnelForUser(readOnlyUser.ID, network.ID, ownerPeer.ID, memberPeer.ID, domain.TunnelModeP2P, 118); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only tunnel request to fail with insufficient role, got %v", err)
	}
	if err := networks.ChangeMemberRole(owner.ID, network.ID, member.ID, domain.NetworkRoleReadOnly); err != nil {
		t.Fatalf("demote member again to read-only: %v", err)
	}
	if err := tunnels.CloseTunnelForUser(member.ID, tunnel.ID); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only tunnel close to fail with insufficient role, got %v", err)
	}
}

func TestPeerDirectoryAllocatesUniqueOverlayCIDRsAcrossNetworks(t *testing.T) {
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

	user, err := auth.Register("cidr@example.com", "secret")
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	device, err := devices.Enroll(user.ID, "workstation", "pub-key", 100)
	if err != nil {
		t.Fatalf("enroll device: %v", err)
	}
	networkA, err := networks.CreateNetwork(user.ID, "alpha", domain.NetworkAccessPrivate)
	if err != nil {
		t.Fatalf("create network A: %v", err)
	}
	networkB, err := networks.CreateNetwork(user.ID, "beta", domain.NetworkAccessPrivate)
	if err != nil {
		t.Fatalf("create network B: %v", err)
	}

	peerA, err := peers.RegisterPeer(user.ID, device.ID, networkA.ID, "127.0.0.1:9000", 120)
	if err != nil {
		t.Fatalf("register peer A: %v", err)
	}
	peerB, err := peers.RegisterPeer(user.ID, device.ID, networkB.ID, "127.0.0.1:9001", 121)
	if err != nil {
		t.Fatalf("register peer B: %v", err)
	}

	if peerA.OverlayCIDR == "" || peerB.OverlayCIDR == "" {
		t.Fatalf("expected both peers to expose overlay CIDRs, got %q and %q", peerA.OverlayCIDR, peerB.OverlayCIDR)
	}
	if peerA.OverlayCIDR == peerB.OverlayCIDR {
		t.Fatalf("expected unique overlay CIDRs across networks, got %q", peerA.OverlayCIDR)
	}
}

func TestPeerDirectoryAllocatesNonOverlappingOverlayCIDRAgainstExistingBroaderPool(t *testing.T) {
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

	if err := poolRepo.Save(domain.NewVirtualIPPool(domain.NetworkID{Value: "seed-net"}, "10.0.0.0/8")); err != nil {
		t.Fatalf("seed broad pool: %v", err)
	}

	user, err := auth.Register("overlap@example.com", "secret")
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	device, err := devices.Enroll(user.ID, "workstation", "pub-key", 100)
	if err != nil {
		t.Fatalf("enroll device: %v", err)
	}
	network, err := networks.CreateNetwork(user.ID, "gamma", domain.NetworkAccessPrivate)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}

	peer, err := peers.RegisterPeer(user.ID, device.ID, network.ID, "127.0.0.1:9002", 122)
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}
	if peer.OverlayCIDR == "" {
		t.Fatalf("expected peer registration to expose overlay CIDR")
	}
	if cidrsOverlapForTest(peer.OverlayCIDR, "10.0.0.0/8") {
		t.Fatalf("expected allocator to avoid overlap with existing broad pool, got %q", peer.OverlayCIDR)
	}
}

func TestNetworkServicePersistsNameResolutionPolicy(t *testing.T) {
	userRepo := memory.NewUserRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	sessionRepo := memory.NewSessionRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)

	user, err := auth.Register("dns-policy@example.com", "secret")
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	network, err := networks.CreateNetworkWithOptions(user.ID, "friends", domain.NetworkAccessPrivate, domain.NetworkCreateOptions{
		NameResolutionMode: domain.NetworkNameResolutionNetworkOnly,
		DNSLabel:           "friends-lan",
	})
	if err != nil {
		t.Fatalf("create network with dns policy: %v", err)
	}
	if network.NameResolutionMode != domain.NetworkNameResolutionNetworkOnly || network.DNSLabel != "friends-lan" {
		t.Fatalf("expected name-resolution policy to round-trip on create, got %#v", network)
	}

	updated, err := networks.UpdateNameResolutionPolicy(user.ID, network.ID, domain.NetworkNameResolutionDisabled, "ignored")
	if err != nil {
		t.Fatalf("update name resolution policy: %v", err)
	}
	if updated.NameResolutionMode != domain.NetworkNameResolutionDisabled || updated.DNSLabel != "" {
		t.Fatalf("expected disabled mode to clear dns label, got %#v", updated)
	}
}

func TestNetworkServicePersistsRoutingPolicy(t *testing.T) {
	userRepo := memory.NewUserRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	sessionRepo := memory.NewSessionRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)

	user, err := auth.Register("routing-policy@example.com", "secret")
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	network, err := networks.CreateNetworkWithOptions(user.ID, "friends", domain.NetworkAccessPrivate, domain.NetworkCreateOptions{
		RoutingPolicy: domain.NetworkRoutingPolicyFull,
	})
	if err != nil {
		t.Fatalf("create network with routing policy: %v", err)
	}
	if network.RoutingPolicy != domain.NetworkRoutingPolicyFull {
		t.Fatalf("expected routing policy to round-trip on create, got %#v", network)
	}

	updated, err := networks.UpdateRoutingPolicy(user.ID, network.ID, domain.NetworkRoutingPolicySplit)
	if err != nil {
		t.Fatalf("update routing policy: %v", err)
	}
	if updated.RoutingPolicy != domain.NetworkRoutingPolicySplit {
		t.Fatalf("expected split routing policy after update, got %#v", updated)
	}
}

func TestNetworkServicePersistsGroupTrafficPolicy(t *testing.T) {
	userRepo := memory.NewUserRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	sessionRepo := memory.NewSessionRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)

	user, err := auth.Register("group-traffic@example.com", "secret")
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	network, err := networks.CreateNetworkWithOptions(user.ID, "friends", domain.NetworkAccessPrivate, domain.NetworkCreateOptions{
		GroupTrafficPolicy: domain.NetworkGroupTrafficPolicyFlood,
	})
	if err != nil {
		t.Fatalf("create network with group traffic policy: %v", err)
	}
	if network.GroupTrafficPolicy != domain.NetworkGroupTrafficPolicyFlood {
		t.Fatalf("expected group traffic policy to round-trip on create, got %#v", network)
	}

	updated, err := networks.UpdateGroupTrafficPolicy(user.ID, network.ID, domain.NetworkGroupTrafficPolicyBlocked)
	if err != nil {
		t.Fatalf("update group traffic policy: %v", err)
	}
	if updated.GroupTrafficPolicy != domain.NetworkGroupTrafficPolicyBlocked {
		t.Fatalf("expected blocked group traffic policy after update, got %#v", updated)
	}
}

func TestNetworkServicePersistsFileTransferPolicy(t *testing.T) {
	userRepo := memory.NewUserRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	sessionRepo := memory.NewSessionRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)

	user, err := auth.Register("file-policy@example.com", "secret")
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	network, err := networks.CreateNetworkWithOptions(user.ID, "friends", domain.NetworkAccessPrivate, domain.NetworkCreateOptions{
		FileTransfersEnabledSet: true,
		FileTransfersEnabled:    false,
		FileTransferMaxBytes:    2048,
	})
	if err != nil {
		t.Fatalf("create network with file-transfer policy: %v", err)
	}
	if network.FileTransfersEnabled || network.FileTransferMaxBytes != 2048 {
		t.Fatalf("expected file-transfer policy to round-trip on create, got %#v", network)
	}

	updated, err := networks.UpdateFileTransferPolicy(user.ID, network.ID, true, 4096)
	if err != nil {
		t.Fatalf("update file-transfer policy: %v", err)
	}
	if !updated.FileTransfersEnabled || updated.FileTransferMaxBytes != 4096 {
		t.Fatalf("expected enabled file-transfer policy after update, got %#v", updated)
	}
}

func cidrsOverlapForTest(left, right string) bool {
	_, leftNet, err := net.ParseCIDR(left)
	if err != nil {
		return false
	}
	_, rightNet, err := net.ParseCIDR(right)
	if err != nil {
		return false
	}
	return leftNet.Contains(rightNet.IP) || rightNet.Contains(leftNet.IP)
}

func TestAuthCleanupExpiredSessions(t *testing.T) {
	userRepo := memory.NewUserRepo()
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
		t.Fatalf("update session repo: %v", err)
	}

	if err := auth.CleanupExpiredSessions(10); err != nil {
		t.Fatalf("cleanup expired sessions: %v", err)
	}
	if _, err := auth.ValidateAccessToken(session.AccessToken); err == nil {
		t.Fatalf("expected expired access token to be invalid after cleanup")
	}
	if stored, err := sessionRepo.FindByAccessToken(session.AccessToken); err != nil || stored != nil {
		t.Fatalf("expected session repo to delete expired session, got %#v err=%v", stored, err)
	}
}

func TestPeerDirectoryCleanupStalePeersMarksPeerOfflineAndClearsSignaling(t *testing.T) {
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

	user, err := auth.Register("peer-cleanup@example.com", "secret")
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	device, err := devices.Enroll(user.ID, "cleanup-device", "cleanup-pub", 1)
	if err != nil {
		t.Fatalf("enroll device: %v", err)
	}
	network, err := networks.CreateNetwork(user.ID, "cleanup", domain.NetworkAccessPrivate)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	peer, err := peers.RegisterPeer(user.ID, device.ID, network.ID, "127.0.0.1:4000", 10)
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}
	if _, err := peers.UpdateSignaling(user.ID, peer.ID, domain.PeerReachabilityDirect, domain.ConnectionStateConnected, 11); err != nil {
		t.Fatalf("update signaling: %v", err)
	}

	if err := peers.CleanupStalePeers(200, 60); err != nil {
		t.Fatalf("cleanup stale peers: %v", err)
	}

	stored, err := peers.GetPeer(peer.ID)
	if err != nil {
		t.Fatalf("get peer after cleanup: %v", err)
	}
	if stored.Status != domain.PeerStatusOffline {
		t.Fatalf("expected stale peer to become offline, got %#v", stored)
	}
	if stored.Reachability != domain.PeerReachabilityUnknown || stored.ConnectionState != domain.ConnectionStateIdle {
		t.Fatalf("expected stale peer signaling to reset, got %#v", stored)
	}
	if stored.LastSeenUnix != 10 {
		t.Fatalf("expected last seen timestamp to remain at last heartbeat, got %d", stored.LastSeenUnix)
	}

	events, err := auditRepo.ListRecent(10)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	found := false
	for _, event := range events {
		if event.Type == "peer.expired" && event.Details != "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected peer.expired audit event after cleanup")
	}
}

func TestMessagingAndFileTransferPermissionBoundaries(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	peerRepo := memory.NewPeerRepo()
	sessionRepo := memory.NewSessionRepo()
	messageRepo := memory.NewMessageRepo()
	fileTransferRepo := memory.NewFileTransferRepo()
	payloadRepo := memory.NewFileTransferPayloadRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, sessionRepo, "test-secret", "ole-test")
	devices := domain.NewDeviceService(deviceRepo, auditRepo)
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)
	peers := domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo)
	messages := domain.NewMessagingService(messageRepo, peerRepo, networkRepo, auditRepo)
	transfers := domain.NewFileTransferService(fileTransferRepo, peerRepo, networkRepo, auditRepo, payloadRepo)

	owner, _ := auth.Register("owner-msg@example.com", "secret")
	member, _ := auth.Register("member-msg@example.com", "secret")
	fileAdmin, _ := auth.Register("fileadmin-msg@example.com", "secret")
	readOnlyUser, _ := auth.Register("readonly-msg@example.com", "secret")
	outsider, _ := auth.Register("outsider-msg@example.com", "secret")

	ownerDevice, _ := devices.Enroll(owner.ID, "owner-device", "owner-pub", 100)
	memberDevice, _ := devices.Enroll(member.ID, "member-device", "member-pub", 101)
	fileAdminDevice, _ := devices.Enroll(fileAdmin.ID, "fileadmin-device", "fileadmin-pub", 102)
	readOnlyDevice, _ := devices.Enroll(readOnlyUser.ID, "readonly-device", "readonly-pub", 103)
	outsiderDevice, _ := devices.Enroll(outsider.ID, "outsider-device", "outsider-pub", 104)

	network, err := networks.CreateNetwork(owner.ID, "messages-files", domain.NetworkAccessInviteOnly)
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

	ownerPeer, err := peers.RegisterPeer(owner.ID, ownerDevice.ID, network.ID, "127.0.0.1:9800", 110)
	if err != nil {
		t.Fatalf("register owner peer: %v", err)
	}
	memberPeer, err := peers.RegisterPeer(member.ID, memberDevice.ID, network.ID, "127.0.0.1:9801", 111)
	if err != nil {
		t.Fatalf("register member peer: %v", err)
	}
	fileAdminPeer, err := peers.RegisterPeer(fileAdmin.ID, fileAdminDevice.ID, network.ID, "127.0.0.1:9802", 112)
	if err != nil {
		t.Fatalf("register file admin peer: %v", err)
	}
	if _, err := peers.RegisterPeer(readOnlyUser.ID, readOnlyDevice.ID, network.ID, "127.0.0.1:9803", 113); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only peer registration to fail, got %v", err)
	}
	if _, err := peers.RegisterPeer(outsider.ID, outsiderDevice.ID, network.ID, "127.0.0.1:9804", 114); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider peer registration to fail, got %v", err)
	}

	message, err := messages.SendMessage(member.ID, network.ID, memberPeer.ID, "hello overlay", 120)
	if err != nil {
		t.Fatalf("member should be able to send message: %v", err)
	}
	if message.Text != "hello overlay" {
		t.Fatalf("unexpected message text: %#v", message)
	}
	if _, err := messages.SendMessage(readOnlyUser.ID, network.ID, memberPeer.ID, "blocked", 121); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only message send to fail, got %v", err)
	}
	if _, err := messages.ListMessagesForUser(readOnlyUser.ID, network.ID); err != nil {
		t.Fatalf("read-only member should still be able to list messages: %v", err)
	}
	if _, err := messages.ListMessagesForUser(outsider.ID, network.ID); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider message list to fail, got %v", err)
	}

	payload := []byte("ole-file")
	transfer, err := transfers.CreateTransfer(member.ID, network.ID, memberPeer.ID, ownerPeer.ID, "readme.txt", int64(len(payload)))
	if err != nil {
		t.Fatalf("member should be able to create transfer: %v", err)
	}
	if transfer.Status != domain.TransferStatusInit {
		t.Fatalf("expected init transfer, got %#v", transfer)
	}
	uploaded, err := transfers.UploadTransferPayload(member.ID, transfer.ID, "text/plain", payload, 121)
	if err != nil {
		t.Fatalf("sender should be able to upload transfer payload: %v", err)
	}
	if !uploaded.PayloadReady || uploaded.PayloadSHA256 == "" {
		t.Fatalf("expected uploaded payload metadata, got %#v", uploaded)
	}
	if _, err := transfers.CreateTransfer(readOnlyUser.ID, network.ID, memberPeer.ID, ownerPeer.ID, "blocked.txt", 128); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only create transfer to fail, got %v", err)
	}

	if _, err := transfers.AcceptTransfer(owner.ID, transfer.ID); err != nil {
		t.Fatalf("receiver should be able to accept transfer: %v", err)
	}
	downloadedPayload, downloadedTransfer, err := transfers.DownloadTransferPayload(owner.ID, transfer.ID, 122)
	if err != nil {
		t.Fatalf("receiver should be able to download transfer payload: %v", err)
	}
	if !bytes.Equal(downloadedPayload.Payload, payload) {
		t.Fatalf("expected downloaded payload round-trip, got %#v", downloadedPayload)
	}
	if downloadedTransfer.Status != domain.TransferStatusDone || downloadedTransfer.ProgressPercent != 100 || downloadedTransfer.DownloadedAtUnix != 122 {
		t.Fatalf("expected download to complete transfer, got %#v", downloadedTransfer)
	}
	if _, err := transfers.CancelTransfer(fileAdmin.ID, transfer.ID, "policy stop"); err != nil {
		t.Fatalf("file admin should be able to cancel any transfer: %v", err)
	}
	if _, err := transfers.AcceptTransfer(member.ID, transfer.ID); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected sender accept to fail with insufficient role, got %v", err)
	}
	if _, err := transfers.CancelTransfer(readOnlyUser.ID, transfer.ID, "blocked"); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected read-only cancel to fail, got %v", err)
	}
	if _, err := transfers.ListTransfersForUser(outsider.ID, network.ID); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider transfer list to fail, got %v", err)
	}

	fileAdminTransfers, err := transfers.ListTransfersForUser(fileAdmin.ID, network.ID)
	if err != nil {
		t.Fatalf("file admin should be able to list transfers: %v", err)
	}
	if len(fileAdminTransfers) != 1 || fileAdminTransfers[0].ID != transfer.ID || fileAdminTransfers[0].Status != domain.TransferStatusCanceled {
		t.Fatalf("expected canceled transfer to be visible to file admin, got %#v", fileAdminTransfers)
	}

	_ = fileAdminPeer
}

func TestFileTransferServiceEnforcesNetworkPolicy(t *testing.T) {
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

	owner, _ := auth.Register("owner-file-policy@example.com", "secret")
	member, _ := auth.Register("member-file-policy@example.com", "secret")
	ownerDevice, _ := devices.Enroll(owner.ID, "owner-device", "owner-pub", 100)
	memberDevice, _ := devices.Enroll(member.ID, "member-device", "member-pub", 101)

	network, err := networks.CreateNetworkWithOptions(owner.ID, "files", domain.NetworkAccessInviteOnly, domain.NetworkCreateOptions{
		FileTransfersEnabledSet: true,
		FileTransfersEnabled:    true,
		FileTransferMaxBytes:    4,
	})
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if err := networks.AddMember(owner.ID, network.ID, member.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}
	ownerPeer, err := peers.RegisterPeer(owner.ID, ownerDevice.ID, network.ID, "127.0.0.1:9990", 102)
	if err != nil {
		t.Fatalf("register owner peer: %v", err)
	}
	memberPeer, err := peers.RegisterPeer(member.ID, memberDevice.ID, network.ID, "127.0.0.1:9991", 103)
	if err != nil {
		t.Fatalf("register member peer: %v", err)
	}

	if _, err := transfers.CreateTransfer(member.ID, network.ID, memberPeer.ID, ownerPeer.ID, "too-big.bin", 5); err != domain.ErrTransferPolicyExceeded {
		t.Fatalf("expected create transfer policy limit error, got %v", err)
	}

	transfer, err := transfers.CreateTransfer(member.ID, network.ID, memberPeer.ID, ownerPeer.ID, "fits.bin", 4)
	if err != nil {
		t.Fatalf("create transfer within limit: %v", err)
	}
	if _, err := networks.UpdateFileTransferPolicy(owner.ID, network.ID, false, 4); err != nil {
		t.Fatalf("disable file transfers: %v", err)
	}
	if _, err := transfers.UploadTransferPayload(member.ID, transfer.ID, "application/octet-stream", []byte("1234"), 120); err != domain.ErrFileTransfersDisabled {
		t.Fatalf("expected upload to fail when transfers are disabled, got %v", err)
	}
}

func TestFileTransferServiceAllowsNetworkPolicyAboveControlPlaneCeiling(t *testing.T) {
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

	owner, _ := auth.Register("owner-large-policy@example.com", "secret")
	member, _ := auth.Register("member-large-policy@example.com", "secret")
	ownerDevice, _ := devices.Enroll(owner.ID, "owner-device", "owner-pub", 100)
	memberDevice, _ := devices.Enroll(member.ID, "member-device", "member-pub", 101)

	networkLimit := domain.DefaultControlPlaneFileTransferPayloadMaxBytes + 1024
	network, err := networks.CreateNetworkWithOptions(owner.ID, "large-policy", domain.NetworkAccessInviteOnly, domain.NetworkCreateOptions{
		FileTransfersEnabledSet: true,
		FileTransfersEnabled:    true,
		FileTransferMaxBytes:    networkLimit,
	})
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if network.FileTransferMaxBytes != networkLimit {
		t.Fatalf("expected network file-transfer limit %d, got %#v", networkLimit, network)
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

	transferSize := domain.DefaultControlPlaneFileTransferPayloadMaxBytes + 1
	transfer, err := transfers.CreateTransfer(member.ID, network.ID, memberPeer.ID, ownerPeer.ID, "huge.bin", transferSize)
	if err != nil {
		t.Fatalf("create transfer above control-plane ceiling: %v", err)
	}
	if transfer.SizeBytes != transferSize {
		t.Fatalf("expected large transfer metadata, got %#v", transfer)
	}
	if _, err := transfers.UploadTransferPayloadChunk(member.ID, transfer.ID, "application/octet-stream", 0, []byte("x"), 104); err != domain.ErrTransferPayloadTooLarge {
		t.Fatalf("expected control-plane upload ceiling to remain enforced, got %v", err)
	}
}

func TestFileTransferServiceAllowsReceiverMirroringAboveSenderControlPlaneUploadCeiling(t *testing.T) {
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

	sender, _ := auth.Register("sender-large-mirror@example.com", "secret")
	receiver, _ := auth.Register("receiver-large-mirror@example.com", "secret")
	senderDevice, _ := devices.Enroll(sender.ID, "sender-device", "sender-pub", 100)
	receiverDevice, _ := devices.Enroll(receiver.ID, "receiver-device", "receiver-pub", 101)

	transferSize := domain.DefaultControlPlaneFileTransferPayloadMaxBytes + 1
	network, err := networks.CreateNetworkWithOptions(sender.ID, "large-mirror", domain.NetworkAccessInviteOnly, domain.NetworkCreateOptions{
		FileTransfersEnabledSet: true,
		FileTransfersEnabled:    true,
		FileTransferMaxBytes:    transferSize,
	})
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if err := networks.AddMember(sender.ID, network.ID, receiver.ID); err != nil {
		t.Fatalf("add receiver member: %v", err)
	}
	senderPeer, err := peers.RegisterPeer(sender.ID, senderDevice.ID, network.ID, "127.0.0.1:9930", 102)
	if err != nil {
		t.Fatalf("register sender peer: %v", err)
	}
	receiverPeer, err := peers.RegisterPeer(receiver.ID, receiverDevice.ID, network.ID, "127.0.0.1:9931", 103)
	if err != nil {
		t.Fatalf("register receiver peer: %v", err)
	}

	transfer, err := transfers.CreateTransfer(sender.ID, network.ID, senderPeer.ID, receiverPeer.ID, "large-mirror.bin", transferSize)
	if err != nil {
		t.Fatalf("create transfer: %v", err)
	}
	if _, err := transfers.UploadTransferPayloadChunk(sender.ID, transfer.ID, "application/octet-stream", 0, []byte("x"), 104); err != domain.ErrTransferPayloadTooLarge {
		t.Fatalf("expected sender-side control-plane upload ceiling to remain enforced, got %v", err)
	}
	if _, err := transfers.AcceptTransfer(receiver.ID, transfer.ID); err != nil {
		t.Fatalf("accept transfer: %v", err)
	}
	mirrored, err := transfers.UploadTransferPayloadChunk(receiver.ID, transfer.ID, "application/octet-stream", 0, []byte("hello"), 105)
	if err != nil {
		t.Fatalf("receiver mirror upload above sender control-plane ceiling: %v", err)
	}
	if mirrored.PayloadReady || mirrored.PayloadUploadedBytes != 5 || mirrored.ContentType != "application/octet-stream" {
		t.Fatalf("expected partial mirrored upload state, got %#v", mirrored)
	}
}

func TestFileTransferServiceSupportsChunkedResumeAndChunkedDownload(t *testing.T) {
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

	owner, _ := auth.Register("owner-chunks@example.com", "secret")
	member, _ := auth.Register("member-chunks@example.com", "secret")
	ownerDevice, _ := devices.Enroll(owner.ID, "owner-device", "owner-pub", 100)
	memberDevice, _ := devices.Enroll(member.ID, "member-device", "member-pub", 101)
	network, err := networks.CreateNetwork(owner.ID, "chunks", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if err := networks.AddMember(owner.ID, network.ID, member.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}
	ownerPeer, err := peers.RegisterPeer(owner.ID, ownerDevice.ID, network.ID, "127.0.0.1:9910", 102)
	if err != nil {
		t.Fatalf("register owner peer: %v", err)
	}
	memberPeer, err := peers.RegisterPeer(member.ID, memberDevice.ID, network.ID, "127.0.0.1:9911", 103)
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
		t.Fatalf("expected partial upload after first chunk, got %#v", first)
	}
	if _, err := transfers.UploadTransferPayloadChunk(member.ID, transfer.ID, "application/octet-stream", 0, payload[3:5], 121); err != domain.ErrTransferPayloadOffsetMismatch {
		t.Fatalf("expected offset mismatch on stale resume, got %v", err)
	}
	second, err := transfers.UploadTransferPayloadChunk(member.ID, transfer.ID, "application/octet-stream", 3, payload[3:], 122)
	if err != nil {
		t.Fatalf("upload resume chunk: %v", err)
	}
	if !second.PayloadReady || second.PayloadUploadedBytes != int64(len(payload)) || second.PayloadSHA256 == "" {
		t.Fatalf("expected completed chunked upload, got %#v", second)
	}
	if _, err := transfers.AcceptTransfer(owner.ID, transfer.ID); err != nil {
		t.Fatalf("accept transfer: %v", err)
	}

	chunkA, transferAfterChunkA, err := transfers.DownloadTransferPayloadChunk(owner.ID, transfer.ID, 0, 3, 123)
	if err != nil {
		t.Fatalf("download first chunk: %v", err)
	}
	if chunkA.Complete || chunkA.NextOffsetBytes != 3 || !bytes.Equal(chunkA.Payload, payload[:3]) {
		t.Fatalf("unexpected first download chunk: %#v", chunkA)
	}
	if transferAfterChunkA.Status != domain.TransferStatusInProgress {
		t.Fatalf("expected transfer to stay in progress before final chunk, got %#v", transferAfterChunkA)
	}
	chunkB, transferAfterChunkB, err := transfers.DownloadTransferPayloadChunk(owner.ID, transfer.ID, 3, 8, 124)
	if err != nil {
		t.Fatalf("download final chunk: %v", err)
	}
	if !chunkB.Complete || !bytes.Equal(append(chunkA.Payload, chunkB.Payload...), payload) {
		t.Fatalf("unexpected reconstructed payload from chunks: %#v %#v", chunkA, chunkB)
	}
	if transferAfterChunkB.Status != domain.TransferStatusDone || transferAfterChunkB.DownloadedAtUnix != 124 {
		t.Fatalf("expected final chunk download to complete transfer, got %#v", transferAfterChunkB)
	}
}

func TestFileTransferServiceAllowsReceiverMirroringChunkUploadAfterAccept(t *testing.T) {
	userRepo := memory.NewUserRepo()
	deviceRepo := memory.NewDeviceRepo()
	networkRepo := memory.NewNetworkRepo()
	inviteRepo := memory.NewInviteRepo()
	auditRepo := memory.NewAuditRepo()
	poolRepo := memory.NewVirtualIPPoolRepo()
	peerRepo := memory.NewPeerRepo()
	transferRepo := memory.NewFileTransferRepo()
	payloadRepo := memory.NewFileTransferPayloadRepo()

	auth := domain.NewAuthService(userRepo, auditRepo, memory.NewSessionRepo(), "secret", "issuer")
	devices := domain.NewDeviceService(deviceRepo, auditRepo)
	networks := domain.NewNetworkService(networkRepo, inviteRepo, auditRepo)
	peers := domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo)
	transfers := domain.NewFileTransferService(transferRepo, peerRepo, networkRepo, auditRepo, payloadRepo)

	sender, err := auth.Register("sender-mirror@example.com", "secret")
	if err != nil {
		t.Fatalf("register sender: %v", err)
	}
	receiver, err := auth.Register("receiver-mirror@example.com", "secret")
	if err != nil {
		t.Fatalf("register receiver: %v", err)
	}
	senderDevice, err := devices.Enroll(sender.ID, "sender-device", "sender-pub", 100)
	if err != nil {
		t.Fatalf("create sender device: %v", err)
	}
	receiverDevice, err := devices.Enroll(receiver.ID, "receiver-device", "receiver-pub", 101)
	if err != nil {
		t.Fatalf("create receiver device: %v", err)
	}
	network, err := networks.CreateNetwork(sender.ID, "mirror", domain.NetworkAccessPrivate)
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
	transfer, err := transfers.CreateTransfer(sender.ID, network.ID, senderPeer.ID, receiverPeer.ID, "mirror.bin", 5)
	if err != nil {
		t.Fatalf("create transfer: %v", err)
	}

	if _, err := transfers.UploadTransferPayloadChunk(receiver.ID, transfer.ID, "application/octet-stream", 0, []byte("hello"), 200); err != domain.ErrInsufficientNetworkRole {
		t.Fatalf("expected receiver upload before accept to be rejected, got %v", err)
	}
	if _, err := transfers.AcceptTransfer(receiver.ID, transfer.ID); err != nil {
		t.Fatalf("accept transfer: %v", err)
	}
	mirrored, err := transfers.UploadTransferPayloadChunk(receiver.ID, transfer.ID, "application/octet-stream", 0, []byte("hello"), 201)
	if err != nil {
		t.Fatalf("receiver mirror upload: %v", err)
	}
	if !mirrored.PayloadReady || mirrored.PayloadUploadedBytes != 5 || mirrored.PayloadSHA256 == "" {
		t.Fatalf("expected receiver mirror upload to complete payload, got %#v", mirrored)
	}
	payload, storedTransfer, err := transfers.DownloadTransferPayload(receiver.ID, transfer.ID, 202)
	if err != nil {
		t.Fatalf("download mirrored payload: %v", err)
	}
	if string(payload.Payload) != "hello" {
		t.Fatalf("expected mirrored payload bytes, got %q", string(payload.Payload))
	}
	if storedTransfer.DownloadedAtUnix != 202 {
		t.Fatalf("expected mirrored payload download to stamp download time, got %#v", storedTransfer)
	}
}
