package httpapi_test

import (
	"Ole/internal/app"
	"Ole/internal/domain"
	"Ole/internal/httpapi"
	"Ole/internal/store/memory"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuditFeedEnforcesVisibilityAndRedactsInvites(t *testing.T) {
	users := memory.NewUserRepo()
	networks := memory.NewNetworkRepo()
	audit := memory.NewAuditRepo()
	invites := memory.NewInviteRepo()
	auth := domain.NewAuthService(users, nil, memory.NewSessionRepo(), "test-secret", "ole-test")
	service := domain.NewNetworkService(networks, invites, audit)
	owner, err := auth.Register("audit-owner@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	network, err := service.CreateNetwork(owner.ID, "private", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatal(err)
	}
	ownerSession, err := auth.Login(owner.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	router := httpapi.NewRouter(&app.App{AuthService: auth, NetworkService: service, AuditRepo: audit})
	const secret = "inv-legacy-secret"
	for _, event := range []*domain.AuditEvent{
		{ID: "legacy-invite", ActorUserID: owner.ID, NetworkID: network.ID, Type: "network.invite_generated", Details: secret, CreatedAtUnix: 100},
		{ID: "owner-personal", ActorUserID: owner.ID, Type: "device.enrolled", Details: "owner device", CreatedAtUnix: 101},
	} {
		if err := audit.Append(event); err != nil {
			t.Fatal(err)
		}
	}
	read := func(token, path string) ([]domain.AuditEvent, int, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", path, response.Code, response.Body.String())
		}
		var body struct {
			Data []struct{ ID, Details string }
			Meta struct{ Total, Count int }
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Meta.Count != len(body.Data) || (body.Meta.Total == 0 && len(body.Data) != 0) {
			t.Fatalf("inconsistent or leaking pagination metadata: %s", response.Body.String())
		}
		events := make([]domain.AuditEvent, len(body.Data))
		for i, event := range body.Data {
			events[i] = domain.AuditEvent{ID: event.ID, Details: event.Details}
		}
		return events, body.Meta.Total, response.Body.String()
	}
	for i, role := range []domain.NetworkRole{domain.NetworkRoleOwner, domain.NetworkRoleAdmin, domain.NetworkRoleModerator, domain.NetworkRoleFileAdmin, domain.NetworkRoleMember, domain.NetworkRoleReadOnly, "OUTSIDER"} {
		t.Run(string(role), func(t *testing.T) {
			user, err := auth.Register(fmt.Sprintf("audit-reader-%d@example.com", i), "secret")
			if err != nil {
				t.Fatal(err)
			}
			token := ownerSession.AccessToken
			reader := owner.ID
			if role != domain.NetworkRoleOwner {
				reader = user.ID
				if role != "OUTSIDER" {
					if err := service.AddMember(owner.ID, network.ID, user.ID); err != nil {
						t.Fatal(err)
					}
					if err := service.ChangeMemberRole(owner.ID, network.ID, user.ID, role); err != nil {
						t.Fatal(err)
					}
				}
				session, err := auth.Login(user.Email, "secret", domain.SessionMetadata{})
				if err != nil {
					t.Fatal(err)
				}
				token = session.AccessToken
			}
			// Even an event authored by the reader is not a bypass for network permissions.
			if err := audit.Append(&domain.AuditEvent{ID: "reader-network-" + reader.String(), ActorUserID: reader, NetworkID: network.ID, Type: "peer.heartbeat", Details: "network-only", CreatedAtUnix: 102}); err != nil {
				t.Fatal(err)
			}
			allowed := role == domain.NetworkRoleOwner || role == domain.NetworkRoleAdmin || role == domain.NetworkRoleModerator
			_, total, raw := read(token, "/api/v1/audit-events?type=network.invite_generated&limit=1&offset=0")
			want := 0
			if allowed {
				want = 1
			}
			if total != want {
				t.Errorf("visible invite total=%d, want=%d", total, want)
			}
			if strings.Contains(raw, secret) {
				t.Error("legacy invite code leaked")
			}
			_, ownNetworkTotal, _ := read(token, "/api/v1/audit-events?type=peer.heartbeat&actorUserId="+reader.String())
			if !allowed && ownNetworkTotal != 0 {
				t.Error("actor identity bypassed network audit permission")
			}
			_, personalTotal, _ := read(token, "/api/v1/audit-events?actorUserId="+owner.ID.String()+"&type=device.enrolled")
			if reader != owner.ID && personalTotal != 0 {
				t.Error("another user's personal audit leaked")
			}
			_, searchTotal, _ := read(token, "/api/v1/audit-events?q="+url.QueryEscape(secret))
			if searchTotal != 0 {
				t.Error("secret remained searchable after redaction")
			}
			if allowed {
				_, scopedTotal, scopedRaw := read(token, "/api/v1/networks/"+network.ID.String()+"/audit-events?type=network.invite_generated")
				if scopedTotal != 1 || strings.Contains(scopedRaw, secret) {
					t.Error("network endpoint leaked or lost legacy invite event")
				}
				_, scopedSearchTotal, _ := read(token, "/api/v1/networks/"+network.ID.String()+"/audit-events?q="+url.QueryEscape(secret))
				if scopedSearchTotal != 0 {
					t.Error("network endpoint exposed secret through search")
				}
			}
		})
	}
	t.Log("role_cases=7 allowed_network_audit=3 denied_network_audit=4 exposed_invite_codes=0")
	foreignOwner, err := auth.Register("foreign-owner@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	foreignNetwork, err := service.CreateNetwork(foreignOwner.ID, "other private network", domain.NetworkAccessInviteOnly)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.Append(&domain.AuditEvent{ID: "foreign-network-event", ActorUserID: foreignOwner.ID, NetworkID: foreignNetwork.ID, Type: "private.marker", Details: "foreign network data"}); err != nil {
		t.Fatal(err)
	}
	_, foreignTotal, _ := read(ownerSession.AccessToken, "/api/v1/audit-events?type=private.marker")
	if foreignTotal != 0 {
		t.Error("owning a network exposed another network's audit")
	}
	// A role change must take effect on the next read, even for the event's author.
	reader, err := auth.Register("demoted-reader@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.AddMember(owner.ID, network.ID, reader.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.ChangeMemberRole(owner.ID, network.ID, reader.ID, domain.NetworkRoleModerator); err != nil {
		t.Fatal(err)
	}
	session, err := auth.Login(reader.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	_, beforeDemotion, _ := read(session.AccessToken, "/api/v1/audit-events?type=network.invite_generated")
	if beforeDemotion != 1 {
		t.Fatal("moderator cannot read network audit")
	}
	if err := service.ChangeMemberRole(owner.ID, network.ID, reader.ID, domain.NetworkRoleReadOnly); err != nil {
		t.Fatal(err)
	}
	_, afterDemotion, _ := read(session.AccessToken, "/api/v1/audit-events?type=network.invite_generated")
	if afterDemotion != 0 {
		t.Fatal("revoked moderation permission still exposed audit")
	}
	// Authorization must precede the storage limit, not just HTTP pagination.
	for i := range 1001 {
		if err := audit.Append(&domain.AuditEvent{ID: fmt.Sprintf("foreign-%d", i), ActorUserID: domain.UserID{Value: "outsider"}, Type: "device.enrolled", Details: "foreign"}); err != nil {
			t.Fatal(err)
		}
	}
	_, total, _ := read(ownerSession.AccessToken, "/api/v1/audit-events?type=device.enrolled")
	if total != 1 {
		t.Errorf("foreign events displaced own event before limit: total=%d", total)
	}
	invite, err := service.GenerateInvite(owner.ID, network.ID, 3600, 1, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	events, err := audit.ListByNetworkID(network.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Type == "network.invite_generated" && event.Details == invite.Code {
			t.Error("new invite code persisted in audit")
		}
	}
	if _, err := service.JoinByInvite(domain.UserID{Value: "legitimate-recipient"}, invite.Code, time.Now().Unix()); err != nil {
		t.Fatalf("new invitation stopped working: %v", err)
	}
}
