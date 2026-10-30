package clientagent

import (
	"Ole/internal/controlclient"
	"errors"
	"time"
)

const forwardingPolicyTTL = 10 * time.Second

// A preparatory policy lease for the packet pump. All access still requires
// Agent.mu. No caller may mutate networks after publication.
type forwardingPolicySnapshot struct {
	server, user, token string
	expires             time.Time
	networks            map[string]controlclient.Network
}

func cloneForwardingNetworks(networks map[string]controlclient.Network) map[string]controlclient.Network {
	result := make(map[string]controlclient.Network, len(networks))
	for id, network := range networks {
		network.Members = append([]string(nil), network.Members...)
		network.ApprovedDeviceIDs = append([]string(nil), network.ApprovedDeviceIDs...)
		roles := make(map[string]string, len(network.MemberRoles))
		for user, role := range network.MemberRoles {
			roles[user] = role
		}
		network.MemberRoles = roles
		result[id] = network
	}
	return result
}

func (a *Agent) forwardingPolicyDeadlineLocked(deadline time.Time) time.Time {
	if a.currentSession == nil || a.currentSession.AccessToken == "" || a.currentSession.ExpiresAtUnix <= 0 || a.currentSession.RevokedAtUnix != 0 {
		return time.Time{}
	}
	if sessionDeadline := time.Unix(a.currentSession.ExpiresAtUnix, 0); sessionDeadline.Before(deadline) {
		deadline = sessionDeadline
	}
	for _, cached := range a.transportCredentials {
		if cached.credentials != nil && cached.credentials.ExpiresAt.Before(deadline) {
			deadline = cached.credentials.ExpiresAt
		}
	}
	return deadline
}

func (a *Agent) publishForwardingPolicyLocked(networks map[string]controlclient.Network, started time.Time) {
	a.invalidateForwardingRoutesLocked()
	a.forwardingPolicy = nil
	deadline := a.forwardingPolicyDeadlineLocked(started.Add(forwardingPolicyTTL))
	if a.currentUser == nil || !time.Now().Before(deadline) {
		return
	}
	a.forwardingPolicy = &forwardingPolicySnapshot{
		server: a.remote.BaseURL(), user: a.currentUser.ID, token: a.currentSession.AccessToken,
		expires: deadline, networks: cloneForwardingNetworks(networks),
	}
}

func (a *Agent) forwardingNetworksLocked() (map[string]controlclient.Network, error) {
	if !time.Now().Before(a.forwardingPolicyDeadlineLocked(time.Now().Add(forwardingPolicyTTL))) {
		a.invalidateForwardingRoutesLocked()
		a.forwardingPolicy = nil
		return nil, errors.New("forwarding authorization expired or unavailable")
	}
	policy := a.forwardingPolicy
	if policy != nil && a.currentUser != nil && a.currentSession != nil &&
		policy.server == a.remote.BaseURL() && policy.user == a.currentUser.ID && policy.token == a.currentSession.AccessToken &&
		time.Now().Before(a.forwardingPolicyDeadlineLocked(policy.expires)) {
		return policy.networks, nil
	}
	a.invalidateForwardingRoutesLocked()
	a.forwardingPolicy = nil
	_, err := a.listNetworksByIDLocked()
	if err != nil {
		return nil, err
	}
	if a.forwardingPolicy == nil {
		return nil, errors.New("forwarding policy lease expired during refresh")
	}
	return a.forwardingPolicy.networks, nil
}
