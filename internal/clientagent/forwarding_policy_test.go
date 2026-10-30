package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/transportauth"
	"Ole/internal/virtualadapter"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestForwardingPolicyLeaseScopeAndExpiry(t *testing.T) {
	for _, scenario := range []string{"deadline", "session-expired", "session-revoked", "server", "user", "token", "credentials-expired", "logout"} {
		t.Run(scenario, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
			}))
			defer server.Close()
			a := &Agent{remote: controlclient.New(server.URL), currentUser: &controlclient.User{ID: "user"}, currentSession: &controlclient.Session{AccessToken: "token", ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}}
			a.publishForwardingPolicyLocked(map[string]controlclient.Network{"network": {ID: "network"}}, time.Now())
			switch scenario {
			case "deadline":
				a.forwardingPolicy.expires = time.Now().Add(-time.Second)
			case "session-expired":
				a.currentSession.ExpiresAtUnix = time.Now().Add(-time.Second).Unix()
			case "session-revoked":
				a.currentSession.RevokedAtUnix = time.Now().Unix()
			case "server":
				a.remote.SetBaseURL(server.URL + "/other")
			case "user":
				a.currentUser.ID = "other"
			case "token":
				a.currentSession.AccessToken = "other"
			case "credentials-expired":
				a.transportCredentials = map[string]cachedTransportCredentials{"peer": {credentials: &transportauth.Credentials{ExpiresAt: time.Now().Add(-time.Second)}}}
			case "logout":
				a.clearInMemorySessionLocked()
			}
			if networks, err := a.forwardingNetworksLocked(); err == nil || networks != nil || a.forwardingPolicy != nil {
				t.Fatal("stale forwarding authorization survived", err)
			}
			wantRequests := int32(1)
			if scenario == "session-expired" || scenario == "session-revoked" || scenario == "credentials-expired" || scenario == "logout" {
				wantRequests = 0
			}
			if requests.Load() != wantRequests {
				t.Fatalf("requests=%d, want %d", requests.Load(), wantRequests)
			}
		})
	}
}

func TestForwardingPolicyCopiesAndBoundsDeadline(t *testing.T) {
	a := &Agent{remote: controlclient.New("http://127.0.0.1"), currentUser: &controlclient.User{ID: "user"}, currentSession: &controlclient.Session{AccessToken: "token", ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}}
	networks := map[string]controlclient.Network{"network": {ID: "network", Members: []string{"user"}, ApprovedDeviceIDs: []string{"device"}, MemberRoles: map[string]string{"user": "OWNER"}}}
	started := time.Now()
	a.publishForwardingPolicyLocked(networks, started)
	if a.forwardingPolicy == nil || !a.forwardingPolicy.expires.Equal(started.Add(forwardingPolicyTTL)) {
		t.Fatal("policy TTL is not measured from request start")
	}
	networks["network"].Members[0] = "other"
	networks["network"].ApprovedDeviceIDs[0] = "other"
	networks["network"].MemberRoles["user"] = "MEMBER"
	delete(networks, "network")
	copy := a.forwardingPolicy.networks["network"]
	if copy.Members[0] != "user" || copy.ApprovedDeviceIDs[0] != "device" || copy.MemberRoles["user"] != "OWNER" {
		t.Fatal("snapshot shares mutable policy data")
	}
	a.publishForwardingPolicyLocked(networks, started.Add(-2*forwardingPolicyTTL))
	if a.forwardingPolicy != nil {
		t.Fatal("slow response extended the lease")
	}
	a.currentSession.ExpiresAtUnix = time.Now().Add(3 * time.Second).Unix()
	a.publishForwardingPolicyLocked(networks, time.Now())
	if a.forwardingPolicy == nil || !a.forwardingPolicy.expires.Equal(time.Unix(a.currentSession.ExpiresAtUnix, 0)) {
		t.Fatal("policy outlives the access session")
	}
	credentialDeadline := time.Now().Add(time.Second)
	a.transportCredentials = map[string]cachedTransportCredentials{"peer": {credentials: &transportauth.Credentials{ExpiresAt: credentialDeadline}}}
	a.publishForwardingPolicyLocked(networks, time.Now())
	if a.forwardingPolicy == nil || !a.forwardingPolicy.expires.Equal(credentialDeadline) {
		t.Fatal("policy outlives identity credentials")
	}
}

func TestForwardingPolicyFailureInvalidatesLease(t *testing.T) {
	for _, status := range []int{401, 403, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "failure", status) }))
			defer server.Close()
			a := &Agent{remote: controlclient.New(server.URL), currentUser: &controlclient.User{ID: "user"}, currentSession: &controlclient.Session{AccessToken: "token", ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}}
			a.publishForwardingPolicyLocked(map[string]controlclient.Network{}, time.Now())
			if _, err := a.listNetworksByIDLocked(); err == nil || a.forwardingPolicy != nil {
				t.Fatal("failed refresh retained old lease")
			}
		})
	}
}

func TestForwardingUsesLeaseDuringAPIOutage(t *testing.T) {
	for _, mode := range []string{"DIRECT", "RELAY"} {
		t.Run(mode, func(t *testing.T) {
			var unavailable atomic.Bool
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if unavailable.Load() {
					http.Error(w, "offline", http.StatusServiceUnavailable)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": []controlclient.Network{{ID: "network", RoutingPolicy: "SPLIT"}}})
			}))
			defer server.Close()
			a, adapter, transport := newForwardingAgent(t, mode, server.URL)
			for batch := range 2 {
				if err := a.forwardTransportPacketsLocked(time.Now()); err != nil {
					t.Fatal(err)
				}
				unavailable.Store(true)
				deadline, received := time.Now().Add(time.Second), 0
				for received < 32 && time.Now().Before(deadline) {
					received += len(transport.DrainInbound("remote", 256))
					time.Sleep(time.Millisecond)
				}
				if received != 32 {
					t.Fatalf("batch %d: delivered %d/32", batch, received)
				}
			}
			if requests.Load() != 1 {
				t.Fatalf("two batches required %d HTTP requests, want 1", requests.Load())
			}
			adapter.outbound = []virtualadapter.Packet{{Data: forwardingIPv4Packet("10.0.0.2", "10.0.0.3", 64)}}
			a.forwardingPolicy.expires = time.Now().Add(-time.Second)
			if err := a.forwardTransportPacketsLocked(time.Now()); err == nil {
				t.Fatal("outage bypassed lease expiry")
			}
			if reads, pending := adapter.pending(); reads != 2 || pending != 1 {
				t.Fatal("expired policy consumed queued packet")
			}
		})
	}
}

func TestForwardingDoesNotRouteRemovedNetwork(t *testing.T) {
	for _, mode := range []string{"DIRECT", "RELAY"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"data":[]}`)) }))
			defer server.Close()
			a, adapter, transport := newForwardingAgent(t, mode, server.URL)
			if err := a.forwardTransportPacketsLocked(time.Now()); err != nil {
				t.Fatal(err)
			}
			if reads, pending := adapter.pending(); reads != 0 || pending != 64 {
				t.Fatal("removed network consumed adapter packets")
			}
			if received := transport.DrainInbound("remote", 256); len(received) != 0 {
				t.Fatal("removed network kept forwarding")
			}
		})
	}
}
