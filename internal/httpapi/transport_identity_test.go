package httpapi_test

import (
	"Ole/internal/app"
	"Ole/internal/domain"
	"Ole/internal/httpapi"
	"Ole/internal/store/memory"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

type identityLookupFailure struct{ domain.UserRepo }

func (r identityLookupFailure) FindByID(domain.UserID) (*domain.User, error) {
	return nil, errors.New("private-dsn-marker")
}

func TestTransportIdentityRouteUsesCurrentNetworkDevicePolicy(t *testing.T) {
	users, devices, networks, peers, pools := memory.NewUserRepo(), memory.NewDeviceRepo(), memory.NewNetworkRepo(), memory.NewPeerRepo(), memory.NewVirtualIPPoolRepo()
	auth := domain.NewAuthService(users, nil, memory.NewSessionRepo(), "test-secret", "ole-test")
	owner, err := auth.Register("identity-owner@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	member, err := auth.Register("identity-member@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	ownerSession, err := auth.Login(owner.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	memberSession, err := auth.Login(member.Email, "secret", domain.SessionMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	network := domain.NewNetwork(domain.NetworkID{Value: "identity-net"}, owner.ID, "identity", domain.NetworkAccessInviteOnly, false)
	if err := network.AddMember(member.ID); err != nil {
		t.Fatal(err)
	}
	if err := networks.Save(network); err != nil {
		t.Fatal(err)
	}
	makeDevice := func(id string, user domain.UserID) *domain.Device {
		seed := sha256.Sum256([]byte(id))
		key := ed25519.NewKeyFromSeed(seed[:])
		d := domain.NewDevice(domain.DeviceID{Value: id}, user, id, base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), time.Now().Unix())
		if err := devices.Save(d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	leftDevice, rightDevice := makeDevice("left-device", owner.ID), makeDevice("right-device", member.ID)
	directory := domain.NewPeerDirectory(peers, networks, pools, devices, nil, users)
	left, err := directory.RegisterPeer(owner.ID, leftDevice.ID, network.ID, "127.0.0.1:20001", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	right, err := directory.RegisterPeer(member.ID, rightDevice.ID, network.ID, "127.0.0.1:20002", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	router := httpapi.NewRouter(&app.App{AuthService: auth, PeerDirectory: directory})
	path := "/api/v1/peers/" + left.ID.String() + "/transport-identities"
	get := func(token string) *domain.TransportIdentitySnapshot {
		t.Helper()
		r := performAuthenticatedJSON(t, router, http.MethodGet, path, token, nil)
		if r.Code != http.StatusOK {
			t.Fatalf("identity route: %d %s", r.Code, r.Body.String())
		}
		if r.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("key snapshot may be cached")
		}
		var response struct {
			Data domain.TransportIdentitySnapshot `json:"data"`
		}
		if err := json.Unmarshal(r.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return &response.Data
	}
	snapshot := get(ownerSession.AccessToken)
	if snapshot.Local.PublicKey != leftDevice.PublicKey || len(snapshot.Peers) != 1 || snapshot.Peers[0].PeerID != right.ID.String() || snapshot.Peers[0].PublicKey != rightDevice.PublicKey {
		t.Fatal("snapshot did not use registered device keys")
	}
	if ttl := snapshot.ExpiresAtUnix - time.Now().Unix(); ttl < 28 || ttl > 30 {
		t.Fatal("unbounded identity lifetime")
	}
	if r := performAuthenticatedJSON(t, router, http.MethodGet, path, memberSession.AccessToken, nil); r.Code != http.StatusUnauthorized {
		t.Fatal("another member fetched an owned peer's credentials")
	}
	if r := performJSON(t, router, http.MethodGet, path, nil); r.Code != http.StatusUnauthorized {
		t.Fatal("anonymous identity fetch accepted")
	}
	for _, tc := range []struct {
		name    string
		change  func()
		restore func()
	}{
		{"banned remote", func() { member.Status = domain.UserStatusBanned; users.Save(member) }, func() { member.Status = domain.UserStatusActive; users.Save(member) }},
		{"revoked remote", func() { rightDevice.Status = domain.DeviceStatusRevoked; devices.Save(rightDevice) }, func() { rightDevice.Status = domain.DeviceStatusActive; devices.Save(rightDevice) }},
		{"offline remote", func() { right.Status = domain.PeerStatusOffline; peers.Save(right) }, func() { right.Status = domain.PeerStatusOnline; peers.Save(right) }},
		{"read only remote", func() {
			network.ChangeMemberRole(owner.ID, member.ID, domain.NetworkRoleReadOnly)
			networks.Save(network)
		}, func() {
			network.ChangeMemberRole(owner.ID, member.ID, domain.NetworkRoleMember)
			networks.Save(network)
		}},
		{"unapproved remote", func() { network.DeviceApprovalRequired = true; networks.Save(network) }, func() { network.DeviceApprovalRequired = false; networks.Save(network) }},
		{"malformed remote key", func() { rightDevice.PublicKey = "bad-key"; devices.Save(rightDevice) }, func() {
			seed := sha256.Sum256([]byte("right-device"))
			rightDevice.PublicKey = base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey))
			devices.Save(rightDevice)
		}},
		{"wrong device owner", func() { rightDevice.UserID = owner.ID; devices.Save(rightDevice) }, func() { rightDevice.UserID = member.ID; devices.Save(rightDevice) }},
		{"foreign peer network", func() { right.NetworkID = domain.NetworkID{Value: "foreign"}; peers.Save(right) }, func() { right.NetworkID = network.ID; peers.Save(right) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.change()
			defer tc.restore()
			if len(get(ownerSession.AccessToken).Peers) != 0 {
				t.Fatal("ineligible remote identity was trusted")
			}
		})
	}
	leftDevice.Status = domain.DeviceStatusRevoked
	if err := devices.Save(leftDevice); err != nil {
		t.Fatal(err)
	}
	if r := performAuthenticatedJSON(t, router, http.MethodGet, path, ownerSession.AccessToken, nil); r.Code == http.StatusOK {
		t.Fatal("revoked local device fetched credentials")
	}
	failedDirectory := domain.NewPeerDirectory(peers, networks, pools, devices, nil, identityLookupFailure{users})
	failedRouter := httpapi.NewRouter(&app.App{AuthService: auth, PeerDirectory: failedDirectory})
	r := performAuthenticatedJSON(t, failedRouter, http.MethodGet, path, ownerSession.AccessToken, nil)
	if r.Code != http.StatusInternalServerError || strings.Contains(r.Body.String(), "private-dsn-marker") {
		t.Fatal("storage failure did not produce a safe server error")
	}
}
