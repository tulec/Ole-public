package domain_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/memory"
	"testing"
)

func TestTunnelRequestsRejectInvalidPeerPairs(t *testing.T) {
	owner := domain.UserID{Value: "owner"}
	member := domain.UserID{Value: "member"}
	unrelated := domain.UserID{Value: "unrelated-member"}
	networkID := domain.NetworkID{Value: "network-a"}
	foreignID := domain.NetworkID{Value: "network-b"}
	for _, tc := range []struct {
		name, a, b string
		actor      domain.UserID
		mode       domain.TunnelMode
	}{
		{"foreign target", "a", "foreign-a", owner, domain.TunnelModeRelay},
		{"foreign source", "foreign-a", "a", owner, domain.TunnelModeRelay},
		{"both peers foreign", "foreign-a", "foreign-b", owner, domain.TunnelModeRelay},
		{"same peer", "a", "a", owner, domain.TunnelModeRelay},
		{"invalid mode", "a", "b", owner, "UNKNOWN"},
		{"neither peer owned", "a", "b", unrelated, domain.TunnelModeRelay},
	} {
		t.Run(tc.name, func(t *testing.T) {
			networks := memory.NewNetworkRepo()
			network := domain.NewNetwork(networkID, owner, "private", domain.NetworkAccessInviteOnly, false)
			if err := network.AddMember(member); err != nil {
				t.Fatal(err)
			}
			if err := network.AddMember(unrelated); err != nil {
				t.Fatal(err)
			}
			if err := networks.Save(network); err != nil {
				t.Fatal(err)
			}
			peers := memory.NewPeerRepo()
			for _, p := range []*domain.Peer{
				{ID: domain.PeerID{Value: "a"}, UserID: owner, NetworkID: networkID},
				{ID: domain.PeerID{Value: "b"}, UserID: member, NetworkID: networkID},
				{ID: domain.PeerID{Value: "foreign-a"}, UserID: member, NetworkID: foreignID},
				{ID: domain.PeerID{Value: "foreign-b"}, UserID: member, NetworkID: foreignID},
			} {
				if err := peers.Save(p); err != nil {
					t.Fatal(err)
				}
			}
			repo := memory.NewTunnelRepo()
			coordinator := domain.NewTunnelCoordinator(repo, peers, nil, networks)
			tunnel, err := coordinator.RequestTunnelForUser(tc.actor, networkID, domain.PeerID{Value: tc.a}, domain.PeerID{Value: tc.b}, tc.mode, 100)
			if err == nil || tunnel != nil {
				t.Error("invalid tunnel request was accepted")
			}
			stored, err := repo.ListByNetwork(networkID)
			if err != nil || len(stored) != 0 {
				t.Errorf("invalid request wrote %d tunnel records: %v", len(stored), err)
			}
		})
	}
}

func TestTunnelRejectsLegacyCrossNetworkOpenAndUnconfiguredUserAccess(t *testing.T) {
	peers := memory.NewPeerRepo()
	repo := memory.NewTunnelRepo()
	networkID := domain.NetworkID{Value: "network-a"}
	for _, p := range []*domain.Peer{
		{ID: domain.PeerID{Value: "a"}, NetworkID: networkID},
		{ID: domain.PeerID{Value: "b"}, NetworkID: domain.NetworkID{Value: "network-b"}},
	} {
		if err := peers.Save(p); err != nil {
			t.Fatal(err)
		}
	}
	legacy := &domain.Tunnel{ID: domain.TunnelID{Value: "legacy"}, NetworkID: networkID, A: domain.PeerID{Value: "a"}, B: domain.PeerID{Value: "b"}, Mode: domain.TunnelModeRelay, State: domain.TunnelStateNegotiating}
	if err := repo.Save(legacy); err != nil {
		t.Fatal(err)
	}
	coordinator := domain.NewTunnelCoordinator(repo, peers, nil)
	if err := coordinator.OpenTunnel(legacy.ID); err == nil {
		t.Error("legacy cross-network tunnel was opened")
	}
	stored, err := repo.FindByID(legacy.ID)
	if err != nil || stored.State != domain.TunnelStateNegotiating {
		t.Error("rejected legacy tunnel was mutated")
	}
	// Use a structurally valid pair so only missing authorization prevents access.
	actor := domain.UserID{Value: "owner"}
	for _, id := range []domain.PeerID{legacy.A, legacy.B} {
		if err := peers.Save(&domain.Peer{ID: id, UserID: actor, NetworkID: networkID}); err != nil {
			t.Fatal(err)
		}
	}
	if tunnel, err := coordinator.RequestTunnelForUser(actor, networkID, legacy.A, legacy.B, domain.TunnelModeRelay, 100); err == nil || tunnel != nil {
		t.Error("user request bypassed missing network authorization repository")
	}
	if events, err := coordinator.ListTunnelsForUser(actor, networkID); err == nil || len(events) != 0 {
		t.Error("user list bypassed missing network authorization")
	}
	if tunnel, err := coordinator.GetTunnelForUser(actor, legacy.ID); err == nil || tunnel != nil {
		t.Error("user get bypassed missing network authorization")
	}
	for name, update := range map[string]func(domain.UserID, domain.TunnelID) error{"open": coordinator.OpenTunnelForUser, "close": coordinator.CloseTunnelForUser, "fail": coordinator.MarkFailedForUser} {
		if err := update(actor, legacy.ID); err == nil {
			t.Errorf("user %s bypassed missing network authorization", name)
		}
	}
	stored, err = repo.FindByID(legacy.ID)
	if err != nil || stored.State != domain.TunnelStateNegotiating {
		t.Error("unconfigured user operations changed tunnel state")
	}
}
