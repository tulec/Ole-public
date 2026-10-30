package domain_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/memory"
	"testing"
)

func TestNetworkPeerAndTunnelViewsUseExplicitViewOperations(t *testing.T) {
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

	owner, _ := auth.Register("owner-view-ops@example.com", "secret")
	member, _ := auth.Register("member-view-ops@example.com", "secret")
	moderator, _ := auth.Register("moderator-view-ops@example.com", "secret")
	fileAdmin, _ := auth.Register("fileadmin-view-ops@example.com", "secret")
	readOnlyUser, _ := auth.Register("readonly-view-ops@example.com", "secret")
	outsider, _ := auth.Register("outsider-view-ops@example.com", "secret")

	ownerDevice, _ := devices.Enroll(owner.ID, "owner-device", "owner-pub", 100)
	memberDevice, _ := devices.Enroll(member.ID, "member-device", "member-pub", 101)

	network, err := networks.CreateNetwork(owner.ID, "view-ops", domain.NetworkAccessInviteOnly)
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
	assignRole(moderator.ID, domain.NetworkRoleModerator)
	assignRole(fileAdmin.ID, domain.NetworkRoleFileAdmin)
	assignRole(readOnlyUser.ID, domain.NetworkRoleReadOnly)

	ownerPeer, err := peers.RegisterPeer(owner.ID, ownerDevice.ID, network.ID, "127.0.0.1:9950", 110)
	if err != nil {
		t.Fatalf("register owner peer: %v", err)
	}
	memberPeer, err := peers.RegisterPeer(member.ID, memberDevice.ID, network.ID, "127.0.0.1:9951", 111)
	if err != nil {
		t.Fatalf("register member peer: %v", err)
	}
	tunnel, err := tunnels.RequestTunnel(network.ID, ownerPeer.ID, memberPeer.ID, domain.TunnelModeP2P, 120)
	if err != nil {
		t.Fatalf("request tunnel: %v", err)
	}

	for _, actor := range []struct {
		name string
		id   domain.UserID
	}{
		{name: "moderator", id: moderator.ID},
		{name: "file-admin", id: fileAdmin.ID},
		{name: "read-only", id: readOnlyUser.ID},
	} {
		visible, err := networks.ListVisibleNetworks(actor.id)
		if err != nil {
			t.Fatalf("%s list visible networks: %v", actor.name, err)
		}
		if len(visible) != 1 || visible[0].ID != network.ID {
			t.Fatalf("expected %s to see one network, got %#v", actor.name, visible)
		}
		if _, err := networks.GetNetwork(actor.id, network.ID); err != nil {
			t.Fatalf("%s get network: %v", actor.name, err)
		}
		if listedPeers, err := peers.ListPeersForUser(actor.id, network.ID); err != nil {
			t.Fatalf("%s list peers: %v", actor.name, err)
		} else if len(listedPeers) != 2 {
			t.Fatalf("expected %s to see two peers, got %#v", actor.name, listedPeers)
		}
		if _, err := peers.GetPeerForUser(actor.id, ownerPeer.ID); err != nil {
			t.Fatalf("%s get peer: %v", actor.name, err)
		}
		if listedTunnels, err := tunnels.ListTunnelsForUser(actor.id, network.ID); err != nil {
			t.Fatalf("%s list tunnels: %v", actor.name, err)
		} else if len(listedTunnels) != 1 || listedTunnels[0].ID != tunnel.ID {
			t.Fatalf("expected %s to see one tunnel, got %#v", actor.name, listedTunnels)
		}
		if _, err := tunnels.GetTunnelForUser(actor.id, tunnel.ID); err != nil {
			t.Fatalf("%s get tunnel: %v", actor.name, err)
		}
	}

	visible, err := networks.ListVisibleNetworks(outsider.ID)
	if err != nil {
		t.Fatalf("outsider list visible networks: %v", err)
	}
	if len(visible) != 0 {
		t.Fatalf("expected outsider to see no networks, got %#v", visible)
	}
	if _, err := networks.GetNetwork(outsider.ID, network.ID); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider get network to fail with unauthorized, got %v", err)
	}
	if _, err := peers.ListPeersForUser(outsider.ID, network.ID); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider peer list to fail with unauthorized, got %v", err)
	}
	if _, err := peers.GetPeerForUser(outsider.ID, ownerPeer.ID); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider peer get to fail with unauthorized, got %v", err)
	}
	if _, err := tunnels.ListTunnelsForUser(outsider.ID, network.ID); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider tunnel list to fail with unauthorized, got %v", err)
	}
	if _, err := tunnels.GetTunnelForUser(outsider.ID, tunnel.ID); err != domain.ErrUnauthorized {
		t.Fatalf("expected outsider tunnel get to fail with unauthorized, got %v", err)
	}
}
