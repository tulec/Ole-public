package clientagent_test

import (
	"Ole/internal/clientagent"
	"Ole/internal/controlclient"
	"Ole/internal/directprobe"
	"Ole/internal/overlaydns"
	"Ole/internal/relaytransport"
	"Ole/internal/stun"
	"Ole/internal/tracectx"
	"Ole/internal/virtualadapter"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAgentIPCUpdateCheckAndDownload(t *testing.T) {
	installerBody := []byte("ole-setup")
	installerHash := sha256.Sum256(installerBody)
	updateMux := http.NewServeMux()
	updateMux.HandleFunc("/ole-update.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":         "0.2.0",
			"publishedAtUnix": int64(1_710_000_000),
			"installerUrl":    "/Ole-Setup-0.2.0.exe",
			"sha256":          hex.EncodeToString(installerHash[:]),
			"releaseNotesUrl": "/release-notes",
		})
	})
	updateMux.HandleFunc("/Ole-Setup-0.2.0.exe", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(installerBody)
	})
	updateServer := httptest.NewServer(updateMux)
	defer updateServer.Close()

	runtime := clientagent.DefaultRuntimeConfig()
	runtime.UpdateManifestURL = updateServer.URL + "/ole-update.json"
	runtime.UpdateDownloadDir = t.TempDir()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStoreAndRuntime(nil, "127.0.0.1:0", stateStore, runtime)
	defer agent.Close()

	ipcServer := httptest.NewServer(agent.Handler())
	defer ipcServer.Close()

	client := clientagent.NewIPCClient(ipcServer.URL)
	status, err := client.CheckForUpdates()
	if err != nil {
		t.Fatalf("check for updates: %v", err)
	}
	if !status.Update.Available {
		t.Fatalf("expected update to be available, got %#v", status.Update)
	}
	if status.Update.LatestVersion != "0.2.0" {
		t.Fatalf("expected latest version 0.2.0, got %#v", status.Update)
	}

	status, err = client.DownloadUpdate()
	if err != nil {
		t.Fatalf("download update: %v", err)
	}
	if !status.Update.Downloaded {
		t.Fatalf("expected downloaded update, got %#v", status.Update)
	}
	data, err := os.ReadFile(status.Update.DownloadedPath)
	if err != nil {
		t.Fatalf("read downloaded update: %v", err)
	}
	if string(data) != string(installerBody) {
		t.Fatalf("unexpected downloaded contents: %q", string(data))
	}
}

func TestAgentIPCUpdateChannelPersistsAcrossRestart(t *testing.T) {
	stableBody := []byte("stable-installer")
	stableHash := sha256.Sum256(stableBody)
	betaBody := []byte("beta-installer")
	betaHash := sha256.Sum256(betaBody)
	updateMux := http.NewServeMux()
	updateMux.HandleFunc("/stable.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":      "0.2.0",
			"installerUrl": "/Ole-Setup-stable.exe",
			"sha256":       hex.EncodeToString(stableHash[:]),
		})
	})
	updateMux.HandleFunc("/beta.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":      "0.3.0-beta.1",
			"installerUrl": "/Ole-Setup-beta.exe",
			"sha256":       hex.EncodeToString(betaHash[:]),
		})
	})
	updateMux.HandleFunc("/Ole-Setup-stable.exe", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(stableBody)
	})
	updateMux.HandleFunc("/Ole-Setup-beta.exe", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(betaBody)
	})
	updateServer := httptest.NewServer(updateMux)
	defer updateServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.DefaultRuntimeConfig()
	runtime.UpdateStableManifestURL = updateServer.URL + "/stable.json"
	runtime.UpdateBetaManifestURL = updateServer.URL + "/beta.json"
	runtime.UpdateDownloadDir = t.TempDir()

	agent := clientagent.NewWithClientAndStoreAndRuntime(nil, "127.0.0.1:0", stateStore, runtime)
	ipcServer := httptest.NewServer(agent.Handler())
	client := clientagent.NewIPCClient(ipcServer.URL)

	status, err := client.SetUpdateChannel("beta")
	if err != nil {
		t.Fatalf("set update channel: %v", err)
	}
	if status.Update.Channel != "beta" {
		t.Fatalf("expected beta channel, got %#v", status.Update)
	}
	status, err = client.CheckForUpdates()
	if err != nil {
		t.Fatalf("check beta updates: %v", err)
	}
	if status.Update.LatestVersion != "0.3.0-beta.1" {
		t.Fatalf("expected beta manifest, got %#v", status.Update)
	}
	status, err = client.DownloadUpdate()
	if err != nil {
		t.Fatalf("download beta update: %v", err)
	}
	data, err := os.ReadFile(status.Update.DownloadedPath)
	if err != nil {
		t.Fatalf("read beta installer: %v", err)
	}
	if string(data) != string(betaBody) {
		t.Fatalf("expected beta installer, got %q", string(data))
	}

	ipcServer.Close()
	_ = agent.Close()

	restarted := clientagent.NewWithClientAndStoreAndRuntime(nil, "127.0.0.1:0", stateStore, runtime)
	defer restarted.Close()
	restartedIPC := httptest.NewServer(restarted.Handler())
	defer restartedIPC.Close()

	status, err = clientagent.NewIPCClient(restartedIPC.URL).GetStatus()
	if err != nil {
		t.Fatalf("status after restart: %v", err)
	}
	if status.Update.Channel != "beta" {
		t.Fatalf("expected beta channel to persist, got %#v", status.Update)
	}
}

func TestAgentUpdatePolicyBlocksDownloadAndAllowsRollback(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	updateBody := []byte("blocked-update")
	updateHash := sha256.Sum256(updateBody)
	rollbackBody := []byte("rollback-installer")
	rollbackHash := sha256.Sum256(rollbackBody)
	updateMux := http.NewServeMux()
	updateMux.HandleFunc("/stable.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":      "0.2.0",
			"installerUrl": "/Ole-Setup-0.2.0.exe",
			"sha256":       hex.EncodeToString(updateHash[:]),
			"compatibility": map[string]any{
				"minimumServerVersion": "0.2.0",
			},
			"rollback": map[string]any{
				"version":      "0.1.0",
				"installerUrl": "/Ole-Setup-0.1.0.exe",
				"sha256":       hex.EncodeToString(rollbackHash[:]),
				"reason":       "Use this rollback if the server is still on 0.1.x",
			},
		})
	})
	updateMux.HandleFunc("/Ole-Setup-0.2.0.exe", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(updateBody)
	})
	updateMux.HandleFunc("/Ole-Setup-0.1.0.exe", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(rollbackBody)
	})
	updateServer := httptest.NewServer(updateMux)
	defer updateServer.Close()

	runtime := clientagent.DefaultRuntimeConfig()
	runtime.UpdateStableManifestURL = updateServer.URL + "/stable.json"
	runtime.UpdateDownloadDir = t.TempDir()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStoreAndRuntime(nil, "127.0.0.1:0", stateStore, runtime)
	defer agent.Close()
	agent.SetServerBaseURL(upstreamServer.URL)

	ipcServer := httptest.NewServer(agent.Handler())
	defer ipcServer.Close()
	client := clientagent.NewIPCClient(ipcServer.URL)

	status, err := client.CheckForUpdates()
	if err != nil {
		t.Fatalf("check for updates: %v", err)
	}
	if status.Update.PolicyStatus != "BLOCKED_SERVER_TOO_OLD" {
		t.Fatalf("expected blocked policy status, got %#v", status.Update)
	}
	if !status.Update.RollbackAvailable {
		t.Fatalf("expected rollback to be available, got %#v", status.Update)
	}

	if _, err := client.DownloadUpdate(); err == nil {
		t.Fatalf("expected update download to be blocked by policy")
	}

	status, err = client.DownloadRollback()
	if err != nil {
		t.Fatalf("download rollback: %v", err)
	}
	if !status.Update.RollbackDownloaded {
		t.Fatalf("expected rollback download to succeed, got %#v", status.Update)
	}
	data, err := os.ReadFile(status.Update.RollbackDownloadedPath)
	if err != nil {
		t.Fatalf("read rollback installer: %v", err)
	}
	if string(data) != string(rollbackBody) {
		t.Fatalf("expected rollback body, got %q", string(data))
	}
}

func TestAgentIPCLoginAndPeerRegistration(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer agent.Close()
	agent.SetServerBaseURL(upstreamServer.URL)
	ipcServer := httptest.NewServer(agent.Handler())
	defer ipcServer.Close()

	client := clientagent.NewIPCClient(ipcServer.URL)

	status, err := client.SetServerBaseURL(upstreamServer.URL)
	if err != nil {
		t.Fatalf("set server base url: %v", err)
	}
	if status.ServerBaseURL != upstreamServer.URL {
		t.Fatalf("expected server base url %q, got %q", upstreamServer.URL, status.ServerBaseURL)
	}
	if status.StatePath == "" {
		t.Fatalf("expected status to report state path")
	}
	status, err = client.SetAdapterMTU(1360)
	if err != nil {
		t.Fatalf("set adapter mtu: %v", err)
	}
	if status.Adapter.DesiredMTU != 1360 {
		t.Fatalf("expected desired MTU to be reported, got %#v", status.Adapter)
	}

	if _, err := client.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}

	status, err = client.Login("owner@example.com", "secret")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !status.Connected || status.CurrentUser == nil || status.CurrentDevice == nil {
		t.Fatalf("expected connected status with current user and device, got %#v", status)
	}

	network, err := client.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}

	peer, err := client.RegisterPeer(network.ID, reserveUDPBindEndpoint(t))
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}
	if peer.DeviceID == "" {
		t.Fatalf("expected service to supply device id, got %#v", peer)
	}
	if peer.OverlayCIDR == "" {
		t.Fatalf("expected service to supply overlay cidr, got %#v", peer)
	}

	peers, err := client.ListPeers(network.ID)
	if err != nil {
		t.Fatalf("list peers: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected one peer, got %d", len(peers))
	}

	sessions, err := client.ListSessions()
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected one session, got %d", len(sessions))
	}

	if _, err := client.RevokeSession(sessions[0].ID); err != nil {
		t.Fatalf("revoke session: %v", err)
	}

	status, err = client.GetStatus()
	if err != nil {
		t.Fatalf("get status after revoke: %v", err)
	}
	if status.Connected {
		t.Fatalf("expected service to disconnect after revoking current session")
	}
}

func TestAgentIPCMessageAndFileTransferWorkflow(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer agent.Close()
	agent.SetServerBaseURL(upstreamServer.URL)
	ipcServer := httptest.NewServer(agent.Handler())
	defer ipcServer.Close()

	client := clientagent.NewIPCClient(ipcServer.URL)
	if _, err := client.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := client.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := client.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	peerA, err := client.RegisterPeer(network.ID, reserveUDPBindEndpoint(t))
	if err != nil {
		t.Fatalf("register local peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:4010", []string{"127.0.0.1:4010"})

	message, err := client.SendMessage(network.ID, peerA.ID, "hello overlay")
	if err != nil {
		t.Fatalf("send message: %v", err)
	}
	if message.FromPeerID != peerA.ID || message.Text != "hello overlay" {
		t.Fatalf("unexpected message response: %#v", message)
	}
	messages, err := client.ListMessages(network.ID)
	if err != nil {
		t.Fatalf("list messages: %v", err)
	}
	if len(messages) != 1 || messages[0].ID != message.ID {
		t.Fatalf("expected one listed message, got %#v", messages)
	}

	transfer, err := client.CreateFileTransfer(network.ID, peerA.ID, "peer-remote", "notes.txt", 128)
	if err != nil {
		t.Fatalf("create file transfer: %v", err)
	}
	if transfer.Status != "INIT" {
		t.Fatalf("expected init transfer state, got %#v", transfer)
	}
	transfers, err := client.ListFileTransfers(network.ID)
	if err != nil {
		t.Fatalf("list file transfers: %v", err)
	}
	if len(transfers) != 1 || transfers[0].ID != transfer.ID {
		t.Fatalf("expected one listed transfer, got %#v", transfers)
	}

	accepted, err := client.AcceptFileTransfer(transfer.ID)
	if err != nil {
		t.Fatalf("accept file transfer: %v", err)
	}
	if accepted.Status != "IN_PROGRESS" {
		t.Fatalf("expected in-progress transfer after accept, got %#v", accepted)
	}
	progressed, err := client.UpdateFileTransferProgress(transfer.ID, 100)
	if err != nil {
		t.Fatalf("update file transfer progress: %v", err)
	}
	if progressed.Status != "DONE" || progressed.ProgressPercent != 100 {
		t.Fatalf("expected done transfer after progress update, got %#v", progressed)
	}

	secondTransfer, err := client.CreateFileTransfer(network.ID, peerA.ID, "peer-remote", "cancel-me.bin", 64)
	if err != nil {
		t.Fatalf("create second file transfer: %v", err)
	}
	canceled, err := client.CancelFileTransfer(secondTransfer.ID, "receiver busy")
	if err != nil {
		t.Fatalf("cancel file transfer: %v", err)
	}
	if canceled.Status != "CANCELED" || canceled.CancelReason != "receiver busy" {
		t.Fatalf("expected canceled transfer with reason, got %#v", canceled)
	}
}

func TestAgentIPCCreateNetworkWithPolicies(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer agent.Close()
	agent.SetServerBaseURL(upstreamServer.URL)
	ipcServer := httptest.NewServer(agent.Handler())
	defer ipcServer.Close()

	client := clientagent.NewIPCClient(ipcServer.URL)

	if _, err := client.Register("policy-owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := client.Login("policy-owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}

	network, err := client.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy:           "FULL",
		GroupTrafficPolicy:      "FLOOD",
		NameResolutionMode:      "NETWORK_ONLY",
		DNSLabel:                "friends-lan",
		FileTransfersEnabledSet: true,
		FileTransfersEnabled:    false,
		FileTransferMaxBytes:    2048,
	})
	if err != nil {
		t.Fatalf("create network with policies: %v", err)
	}
	if network.RoutingPolicy != "FULL" || network.GroupTrafficPolicy != "FLOOD" || network.NameResolutionMode != "NETWORK_ONLY" || network.DNSLabel != "friends-lan" || network.FileTransfersEnabled || network.FileTransferMaxBytes != 2048 {
		t.Fatalf("expected policy-rich network response, got %#v", network)
	}
}

func TestAgentUpdatesNetworkFileTransferPolicy(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer agent.Close()
	agent.SetServerBaseURL(upstreamServer.URL)
	ipcServer := httptest.NewServer(agent.Handler())
	defer ipcServer.Close()

	client := clientagent.NewIPCClient(ipcServer.URL)
	if _, err := client.Register("file-policy@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := client.Login("file-policy@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := client.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}

	updated, err := client.UpdateNetworkFileTransferPolicy(network.ID, false, 4096)
	if err != nil {
		t.Fatalf("update network file transfer policy: %v", err)
	}
	if updated.FileTransfersEnabled || updated.FileTransferMaxBytes != 4096 {
		t.Fatalf("expected updated file transfer policy, got %#v", updated)
	}
}

func TestAgentMetricsExposeRuntimeState(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer agent.Close()
	agent.SetServerBaseURL(upstreamServer.URL)

	if _, err := agent.Register("metrics@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("metrics@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}

	ipcServer := httptest.NewServer(agent.Handler())
	defer ipcServer.Close()

	healthResp, err := http.Get(ipcServer.URL + "/health")
	if err != nil {
		t.Fatalf("get health: %v", err)
	}
	_ = healthResp.Body.Close()

	resp, err := http.Get(ipcServer.URL + "/metrics")
	if err != nil {
		t.Fatalf("get metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from metrics, got %d", resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read metrics body: %v", err)
	}
	body := string(bodyBytes)
	if !strings.Contains(body, "ole_agent_connected 1") {
		t.Fatalf("expected connected gauge in metrics output, got %q", body)
	}
	if !strings.Contains(body, "ole_agent_direct_attempts_total") {
		t.Fatalf("expected direct metrics in metrics output, got %q", body)
	}
	if !strings.Contains(body, "ole_agent_stun_configured 0") || !strings.Contains(body, "ole_agent_relay_pool_size 0") {
		t.Fatalf("expected NAT/relay configuration gauges in metrics output, got %q", body)
	}
	if !strings.Contains(body, "ole_agent_public_endpoint_known 0") {
		t.Fatalf("expected public-endpoint availability gauge in metrics output, got %q", body)
	}
	if !strings.Contains(body, `ole_agent_http_requests_total{method="GET",path="/health",status="200"} 1`) {
		t.Fatalf("expected agent HTTP request metric in output, got %q", body)
	}
}

func TestAgentProbeEndpointsExposeLivenessAndReadiness(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer agent.Close()
	agent.SetServerBaseURL(upstreamServer.URL)

	ipcServer := httptest.NewServer(agent.Handler())
	defer ipcServer.Close()

	liveResp, err := http.Get(ipcServer.URL + "/livez")
	if err != nil {
		t.Fatalf("get livez: %v", err)
	}
	defer liveResp.Body.Close()
	if liveResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from livez, got %d", liveResp.StatusCode)
	}
	var liveBody struct {
		Data clientagent.ProbeResponse `json:"data"`
	}
	if err := json.NewDecoder(liveResp.Body).Decode(&liveBody); err != nil {
		t.Fatalf("decode livez body: %v", err)
	}
	if liveBody.Data.Status != "alive" || liveBody.Data.Checks["process"].Status != "ok" {
		t.Fatalf("unexpected livez payload: %#v", liveBody.Data)
	}

	readyResp, err := http.Get(ipcServer.URL + "/readyz")
	if err != nil {
		t.Fatalf("get readyz: %v", err)
	}
	defer readyResp.Body.Close()
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from readyz, got %d", readyResp.StatusCode)
	}
	var readyBody struct {
		Data clientagent.ProbeResponse `json:"data"`
	}
	if err := json.NewDecoder(readyResp.Body).Decode(&readyBody); err != nil {
		t.Fatalf("decode readyz body: %v", err)
	}
	if readyBody.Data.Status != "ready" || readyBody.Data.Checks["stateStore"].Status != "ok" {
		t.Fatalf("unexpected readyz payload: %#v", readyBody.Data)
	}
}

func TestAgentReadinessEndpointReturnsServiceUnavailableWhenStateStoreFails(t *testing.T) {
	brokenStateStore := clientagent.NewStateStore(t.TempDir())
	agent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", brokenStateStore)
	defer agent.Close()

	ipcServer := httptest.NewServer(agent.Handler())
	defer ipcServer.Close()

	resp, err := http.Get(ipcServer.URL + "/readyz")
	if err != nil {
		t.Fatalf("get readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 from readyz, got %d", resp.StatusCode)
	}
	var body struct {
		Data clientagent.ProbeResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode readyz body: %v", err)
	}
	if body.Data.Status != "not_ready" || body.Data.Checks["stateStore"].Status != "error" || body.Data.Checks["stateStore"].Detail == "" {
		t.Fatalf("unexpected failing readyz payload: %#v", body.Data)
	}
}

func TestAgentDiagnosticsBundleRedactsTokensAndIncludesRecentLogs(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer agent.Close()
	agent.SetServerBaseURL(upstreamServer.URL)
	ipcServer := httptest.NewServer(agent.Handler())
	defer ipcServer.Close()

	client := clientagent.NewIPCClient(ipcServer.URL)

	if _, err := client.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	status, err := client.Login("owner@example.com", "secret")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := client.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	peerA, err := client.RegisterPeer(network.ID, reserveUDPBindEndpoint(t))
	if err != nil {
		t.Fatalf("register peer a: %v", err)
	}
	peerB, err := client.RegisterPeer(network.ID, reserveUDPBindEndpoint(t))
	if err != nil {
		t.Fatalf("register peer b: %v", err)
	}
	if _, err := client.CreateTunnel(network.ID, peerA.ID, peerB.ID); err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	bundle, err := client.GetDiagnosticsBundle()
	if err != nil {
		t.Fatalf("get diagnostics bundle: %v", err)
	}
	if bundle.GeneratedAtUnix == 0 {
		t.Fatalf("expected generated timestamp in bundle")
	}
	if bundle.Status.CurrentSession == nil {
		t.Fatalf("expected current session in diagnostics status")
	}
	if bundle.Status.CurrentSession.AccessToken != "" || bundle.Status.CurrentSession.RefreshToken != "" {
		t.Fatalf("expected diagnostics status session to be redacted, got %#v", bundle.Status.CurrentSession)
	}
	if len(bundle.Sessions) != 1 {
		t.Fatalf("expected one sanitized session, got %d", len(bundle.Sessions))
	}
	if bundle.Sessions[0].AccessToken != "" || bundle.Sessions[0].RefreshToken != "" {
		t.Fatalf("expected listed sessions to be redacted, got %#v", bundle.Sessions[0])
	}
	if len(bundle.Networks) != 1 {
		t.Fatalf("expected one network in diagnostics bundle, got %d", len(bundle.Networks))
	}
	if bundle.UsageSummary.NetworkCount != 1 || bundle.UsageSummary.PeerCount != 1 || bundle.UsageSummary.TunnelCount != 1 {
		t.Fatalf("expected aggregate diagnostics usage summary counts, got %#v", bundle.UsageSummary)
	}
	if bundle.Networks[0].UsageSummary.NetworkCount != 1 || bundle.Networks[0].UsageSummary.PeerCount != 1 || bundle.Networks[0].UsageSummary.TunnelCount != 1 {
		t.Fatalf("expected per-network diagnostics usage summary counts, got %#v", bundle.Networks[0].UsageSummary)
	}
	if bundle.UsageSummary.Transport != nil || bundle.Networks[0].UsageSummary.Transport != nil {
		t.Fatalf("expected transport rollup to stay empty when no managed connections exist, got %#v / %#v", bundle.UsageSummary.Transport, bundle.Networks[0].UsageSummary.Transport)
	}
	if bundle.UsageSummary.CrossNetwork != nil {
		t.Fatalf("expected cross-network rollup to stay empty for single-network bundle, got %#v", bundle.UsageSummary.CrossNetwork)
	}
	if bundle.UsageSummary.ConnectionState != nil || bundle.Networks[0].UsageSummary.ConnectionState != nil {
		t.Fatalf("expected connection-state rollup to stay empty when no managed connections exist, got %#v / %#v", bundle.UsageSummary.ConnectionState, bundle.Networks[0].UsageSummary.ConnectionState)
	}
	if bundle.UsageSummary.RecentErrors != nil || bundle.Networks[0].UsageSummary.RecentErrors != nil {
		t.Fatalf("expected recent-error rollup to stay empty when no managed connections exist, got %#v / %#v", bundle.UsageSummary.RecentErrors, bundle.Networks[0].UsageSummary.RecentErrors)
	}
	if bundle.UsageSummary.Neighbors != nil || bundle.Networks[0].UsageSummary.Neighbors != nil || len(bundle.Networks[0].Neighbors) != 0 {
		t.Fatalf("expected neighbor diagnostics to stay empty when no discovered neighbors exist, got %#v / %#v / %#v", bundle.UsageSummary.Neighbors, bundle.Networks[0].UsageSummary.Neighbors, bundle.Networks[0].Neighbors)
	}
	if bundle.UsageSummary.AdapterNeighbor != nil || bundle.Networks[0].UsageSummary.AdapterNeighbor != nil {
		t.Fatalf("expected adapter-neighbor correlation to stay empty when no adapter or neighbor convergence exists, got %#v / %#v", bundle.UsageSummary.AdapterNeighbor, bundle.Networks[0].UsageSummary.AdapterNeighbor)
	}
	for _, adapter := range []*clientagent.DiagnosticsAdapterRollup{bundle.UsageSummary.Adapter, bundle.Networks[0].UsageSummary.Adapter} {
		if adapter == nil || adapter.DesiredMTU != 1280 || adapter.CurrentMTU != 0 || adapter.Enabled || adapter.SessionActive || adapter.BindingCount != 0 {
			t.Fatalf("expected safe default MTU without an active adapter, got %#v", adapter)
		}
	}
	if len(bundle.GatewayHistory) != 0 || len(bundle.Networks[0].GatewayHistory) != 0 || bundle.UsageSummary.Gateway != nil || bundle.Networks[0].UsageSummary.Gateway != nil {
		t.Fatalf("expected gateway diagnostics to stay empty when no gateway history exists, got %#v / %#v / %#v / %#v", bundle.GatewayHistory, bundle.Networks[0].GatewayHistory, bundle.UsageSummary.Gateway, bundle.Networks[0].UsageSummary.Gateway)
	}
	if bundle.UsageSummary.GatewayCurrent != nil || bundle.Networks[0].UsageSummary.GatewayCurrent != nil {
		t.Fatalf("expected current gateway rollup to stay empty when no FULL gateway binding exists, got %#v / %#v", bundle.UsageSummary.GatewayCurrent, bundle.Networks[0].UsageSummary.GatewayCurrent)
	}
	if bundle.UsageSummary.GroupTraffic != nil || bundle.Networks[0].UsageSummary.GroupTraffic != nil {
		t.Fatalf("expected group-traffic rollup to stay empty when no group-traffic diagnostics exist, got %#v / %#v", bundle.UsageSummary.GroupTraffic, bundle.Networks[0].UsageSummary.GroupTraffic)
	}
	if len(bundle.Networks[0].Peers) != 1 {
		t.Fatalf("expected one peer in diagnostics bundle, got %d", len(bundle.Networks[0].Peers))
	}
	if len(bundle.Networks[0].Tunnels) != 1 {
		t.Fatalf("expected one tunnel in diagnostics bundle, got %d", len(bundle.Networks[0].Tunnels))
	}
	if len(bundle.RecentLogs) == 0 {
		t.Fatalf("expected recent logs in diagnostics bundle")
	}
	foundLogin := false
	foundTunnel := false
	foundStructuredLogin := false
	foundControlPlaneTrace := false
	for _, entry := range bundle.RecentLogs {
		if strings.Contains(entry.Message, "login succeeded") {
			foundLogin = true
			if entry.Component == "clientagent" && entry.Event == "session.login.succeeded" && entry.Fields["email"] == "owner@example.com" {
				foundStructuredLogin = true
			}
		}
		if strings.Contains(entry.Message, "tunnel created") {
			foundTunnel = true
		}
		if entry.Component == "controlclient" && entry.Event == "controlplane.request.completed" && entry.Fields["traceId"] != "" && entry.Fields["serverSpanId"] == "srvfake01" {
			foundControlPlaneTrace = true
		}
	}
	if !foundLogin || !foundTunnel {
		t.Fatalf("expected diagnostics logs to include login and tunnel creation, got %#v", bundle.RecentLogs)
	}
	if !foundStructuredLogin {
		t.Fatalf("expected diagnostics logs to include structured login event, got %#v", bundle.RecentLogs)
	}
	if !foundControlPlaneTrace {
		t.Fatalf("expected diagnostics logs to include control-plane trace correlation, got %#v", bundle.RecentLogs)
	}
	if !status.Connected {
		t.Fatalf("expected connected status after login")
	}
}

func TestAgentSurfacesSessionReuseAndRevokedDeviceDiagnostics(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:         10 * time.Millisecond,
		SessionRefreshSkew:        10 * time.Millisecond,
		SecurityDiagnosticsPeriod: 10 * time.Millisecond,
		HeartbeatInterval:         time.Hour,
		PeerDiscoveryPeriod:       time.Hour,
		STUNProbePeriod:           time.Hour,
		RelayFailbackPeriod:       time.Hour,
		TransportKeepalive:        time.Hour,
		DirectProbeTimeout:        10 * time.Millisecond,
		DirectRetryBase:           time.Second,
		DirectRetryMax:            time.Second,
		DirectMaxAttempts:         1,
		TransportSessionTTL:       time.Hour,
		TransportRekeyAfter:       1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntime(nil, "127.0.0.1:0", stateStore, runtime)
	defer agent.Close()
	agent.SetServerBaseURL(upstreamServer.URL)

	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	status, err := agent.Login("owner@example.com", "secret")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if status.CurrentSession == nil || status.CurrentDevice == nil {
		t.Fatalf("expected current session and device after login, got %#v", status)
	}

	detectedAt := time.Now().Unix()
	upstream.MarkSessionReuseDetected(status.CurrentSession.ID, detectedAt)
	upstream.RevokeDevice(status.CurrentDevice.ID, detectedAt)

	waitForCondition(t, time.Second, func() bool {
		current := agent.Status()
		return current.Security.ReuseDetectedCount == 1 &&
			current.Security.CurrentSessionReuseDetected &&
			current.Security.CurrentDeviceStatus == "REVOKED" &&
			current.Security.EnrollmentStatus == "REVOKED" &&
			len(current.Security.Alerts) >= 2
	})

	current := agent.Status()
	if current.Security.RevokedDeviceCount != 1 {
		t.Fatalf("expected one revoked device in security diagnostics, got %#v", current.Security)
	}

	bundle := agent.DiagnosticsBundle()
	if bundle.Security.ReuseDetectedCount != 1 || !bundle.Security.CurrentSessionReuseDetected {
		t.Fatalf("expected diagnostics bundle to include session reuse alert, got %#v", bundle.Security)
	}
	if bundle.Security.CurrentDeviceStatus != "REVOKED" || bundle.Security.EnrollmentStatus != "REVOKED" {
		t.Fatalf("expected diagnostics bundle to include revoked current device status, got %#v", bundle.Security)
	}
	if len(bundle.Devices) != 1 || bundle.Devices[0].Status != "REVOKED" {
		t.Fatalf("expected diagnostics bundle to include revoked device snapshot, got %#v", bundle.Devices)
	}
}

func TestAgentStatusIncludesIncidentSummary(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.incidentReports = []map[string]any{
		{
			"id":                "session-token-reuse",
			"category":          "TOKEN_REUSE",
			"severity":          "elevated",
			"status":            "ACTIVE",
			"source":            "account.session_tokens",
			"summary":           "One or more session families were revoked after suspicious refresh-token reuse.",
			"detail":            "1 affected session family",
			"recommendedAction": "Use `Revoke All Sessions`, sign in again, and review the trusted-device list if you do not recognize the affected device.",
			"eventCount":        1,
			"detectedAtUnix":    1710000000,
			"updatedAtUnix":     1710000000,
		},
	}
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer agent.Close()
	agent.SetServerBaseURL(upstreamServer.URL)

	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}

	status := agent.Status()
	if status.Incidents.ActiveCount != 1 || status.Incidents.TokenReuseCount != 1 {
		t.Fatalf("expected incident summary to include one active token-reuse incident, got %#v", status.Incidents)
	}
	if status.Incidents.MostSevere != "elevated" {
		t.Fatalf("expected incident severity to be elevated, got %#v", status.Incidents)
	}
	if status.Incidents.LastCheckedUnix == 0 || strings.TrimSpace(status.Incidents.RecommendedAction) == "" {
		t.Fatalf("expected incident summary timestamps and guidance, got %#v", status.Incidents)
	}
}

func TestAgentIPCListsFilteredAuditEvents(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.AddAuditEvent("aud-1", "usr-1", "device.revoked", "dev-1", 100)
	upstream.AddAuditEvent("aud-2", "usr-2", "network.created", "net-1", 200)
	upstream.AddAuditEvent("aud-3", "usr-1", "device.revoked", "dev-2", 300)
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer agent.Close()
	agent.SetServerBaseURL(upstreamServer.URL)
	ipcServer := httptest.NewServer(agent.Handler())
	defer ipcServer.Close()

	client := clientagent.NewIPCClient(ipcServer.URL)
	if _, err := client.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := client.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}

	events, err := client.ListAuditEvents(controlclient.AuditEventFilter{
		ActorUserID: "usr-1",
		Type:        "device.revoked",
		FromUnix:    150,
		ToUnix:      400,
	})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one filtered audit event, got %#v", events)
	}
	if events[0].ID != "aud-3" {
		t.Fatalf("expected latest matching audit event, got %#v", events[0])
	}
}

func TestAgentIPCAuditPresetsPersistAcrossRestart(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	firstAgent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	firstAgent.SetServerBaseURL(upstreamServer.URL)
	ipcServer := httptest.NewServer(firstAgent.Handler())

	client := clientagent.NewIPCClient(ipcServer.URL)
	if _, err := client.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := client.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}

	presets, err := client.SaveAuditPreset("Device Revokes", controlclient.AuditEventFilter{
		ActorUserID: "usr-1",
		Type:        "device.revoked",
		Query:       "desktop",
		FromUnix:    100,
		ToUnix:      200,
	})
	if err != nil {
		t.Fatalf("save audit preset: %v", err)
	}
	if len(presets) != 1 {
		t.Fatalf("expected one saved audit preset, got %#v", presets)
	}
	if presets[0].Name != "Device Revokes" || presets[0].Type != "device.revoked" || presets[0].FromUnix != 100 || presets[0].ToUnix != 200 {
		t.Fatalf("expected saved preset fields to round-trip, got %#v", presets[0])
	}

	listed, err := client.ListAuditPresets()
	if err != nil {
		t.Fatalf("list audit presets: %v", err)
	}
	if len(listed) != 1 || listed[0].Query != "desktop" {
		t.Fatalf("expected saved audit preset to be listed, got %#v", listed)
	}

	ipcServer.Close()
	firstAgent.Close()

	secondAgent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer secondAgent.Close()
	secondAgent.SetServerBaseURL(upstreamServer.URL)
	secondIPCServer := httptest.NewServer(secondAgent.Handler())
	defer secondIPCServer.Close()

	secondClient := clientagent.NewIPCClient(secondIPCServer.URL)
	if _, err := secondClient.Reconnect(); err != nil {
		t.Fatalf("reconnect: %v", err)
	}

	persisted, err := secondClient.ListAuditPresets()
	if err != nil {
		t.Fatalf("list audit presets after restart: %v", err)
	}
	if len(persisted) != 1 || persisted[0].Name != "Device Revokes" {
		t.Fatalf("expected preset to persist across restart, got %#v", persisted)
	}

	persisted, err = secondClient.DeleteAuditPreset("Device Revokes")
	if err != nil {
		t.Fatalf("delete audit preset: %v", err)
	}
	if len(persisted) != 0 {
		t.Fatalf("expected preset list to be empty after delete, got %#v", persisted)
	}
}

func TestAgentIPCListsDevices(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer agent.Close()
	agent.SetServerBaseURL(upstreamServer.URL)
	ipcServer := httptest.NewServer(agent.Handler())
	defer ipcServer.Close()

	client := clientagent.NewIPCClient(ipcServer.URL)
	if _, err := client.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := client.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}

	devices, err := client.ListDevices()
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected one device via IPC, got %#v", devices)
	}
	if devices[0].Status != "ACTIVE" || devices[0].Fingerprint == "" {
		t.Fatalf("expected active device with fingerprint via IPC, got %#v", devices[0])
	}
}

func TestAgentIPCListsIncidentReports(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.incidentReports = []map[string]any{
		{
			"id":                "auth-abuse",
			"category":          "AUTH_ABUSE",
			"severity":          "warning",
			"status":            "ACTIVE",
			"source":            "server.auth_abuse",
			"summary":           "Authentication abuse alerts are active.",
			"detail":            "1 login alert, 1 blocked key",
			"recommendedAction": "Review blocked login sources.",
			"eventCount":        1,
			"detectedAtUnix":    int64(1710000000),
			"updatedAtUnix":     int64(1710000000),
		},
	}
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer agent.Close()
	agent.SetServerBaseURL(upstreamServer.URL)
	ipcServer := httptest.NewServer(agent.Handler())
	defer ipcServer.Close()

	client := clientagent.NewIPCClient(ipcServer.URL)
	if _, err := client.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := client.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}

	incidents, err := client.ListIncidentReports()
	if err != nil {
		t.Fatalf("list incident reports: %v", err)
	}
	if len(incidents) != 1 || incidents[0].Category != "AUTH_ABUSE" {
		t.Fatalf("expected one auth-abuse incident, got %#v", incidents)
	}
}

func TestAgentIPCManagesSensitiveNetworkDeviceApprovals(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer agent.Close()
	agent.SetServerBaseURL(upstreamServer.URL)
	ipcServer := httptest.NewServer(agent.Handler())
	defer ipcServer.Close()

	client := clientagent.NewIPCClient(ipcServer.URL)
	if _, err := client.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := client.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}

	devices, err := client.ListDevices()
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected one device, got %#v", devices)
	}

	network, err := client.CreateNetworkWithPolicy("sensitive", "INVITE_ONLY", true)
	if err != nil {
		t.Fatalf("create sensitive network: %v", err)
	}
	if !network.DeviceApprovalRequired {
		t.Fatalf("expected sensitive network policy, got %#v", network)
	}

	network, err = client.ApproveNetworkDevice(network.ID, devices[0].ID)
	if err != nil {
		t.Fatalf("approve network device: %v", err)
	}
	if !containsString(network.ApprovedDeviceIDs, devices[0].ID) {
		t.Fatalf("expected approved device in network payload, got %#v", network)
	}

	network, err = client.RevokeNetworkDeviceApproval(network.ID, devices[0].ID)
	if err != nil {
		t.Fatalf("revoke network device approval: %v", err)
	}
	if containsString(network.ApprovedDeviceIDs, devices[0].ID) {
		t.Fatalf("expected device approval to be removed, got %#v", network)
	}
}

func TestAgentIPCReconnectRestoresPersistedSession(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	firstAgent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	firstAgent.SetServerBaseURL(upstreamServer.URL)
	if _, err := firstAgent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := firstAgent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	firstAgent.Close()

	secondAgent := clientagent.NewWithClientAndStore(controlclient.New(upstreamServer.URL), "127.0.0.1:0", stateStore)
	defer secondAgent.Close()
	ipcServer := httptest.NewServer(secondAgent.Handler())
	defer ipcServer.Close()

	client := clientagent.NewIPCClient(ipcServer.URL)
	status, err := client.Reconnect()
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	if !status.Connected || status.CurrentUser == nil || status.CurrentSession == nil {
		t.Fatalf("expected reconnect to restore persisted session, got %#v", status)
	}
}

func TestAgentIPCRevokeAllSessionsClearsCurrentSession(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer agent.Close()
	agent.SetServerBaseURL(upstreamServer.URL)
	ipcServer := httptest.NewServer(agent.Handler())
	defer ipcServer.Close()

	client := clientagent.NewIPCClient(ipcServer.URL)
	if _, err := client.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := client.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}

	status, err := client.RevokeAllSessions()
	if err != nil {
		t.Fatalf("revoke all sessions: %v", err)
	}
	if status.Connected || status.CurrentSession != nil {
		t.Fatalf("expected current session to be cleared after revoke-all, got %#v", status)
	}
}

func TestAgentAutoReconnectUsesExponentialBackoffAfterTransientRestoreFailure(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	firstAgent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	firstAgent.SetServerBaseURL(upstreamServer.URL)
	if _, err := firstAgent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := firstAgent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	firstAgent.Close()

	upstream.SetHealthFailures(2)
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   5 * time.Millisecond,
		ReconnectRetryBase:  20 * time.Millisecond,
		ReconnectRetryMax:   40 * time.Millisecond,
		HeartbeatInterval:   time.Hour,
		PeerDiscoveryPeriod: time.Hour,
		STUNProbePeriod:     time.Hour,
		TransportKeepalive:  time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	secondAgent := clientagent.NewWithClientAndStoreAndRuntime(controlclient.New(upstreamServer.URL), "127.0.0.1:0", stateStore, runtime)
	defer secondAgent.Close()

	waitForCondition(t, 50*time.Millisecond, func() bool {
		return secondAgent.Status().ReconnectAttemptCount == 1
	})
	firstFailure := secondAgent.Status()
	if firstFailure.Connected {
		t.Fatalf("expected reconnect to still be pending after first transient failure, got %#v", firstFailure)
	}
	if !firstFailure.PersistedSession || firstFailure.ReconnectAttemptCount != 1 {
		t.Fatalf("expected one pending reconnect attempt with persisted session, got %#v", firstFailure)
	}
	if firstFailure.ReconnectState != "BACKOFF" || !firstFailure.ReconnectBackoffActive || firstFailure.ReconnectRemainingMs <= 0 {
		t.Fatalf("expected reconnect diagnostics to expose active backoff, got %#v", firstFailure)
	}
	if wait := time.Until(time.UnixMilli(firstFailure.NextReconnectAttemptMs).Add(-3 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
		if current := secondAgent.Status(); current.ReconnectAttemptCount != 1 {
			t.Fatalf("expected reconnect backoff to suppress an immediate retry, got %#v", current)
		}
	}

	waitForCondition(t, 80*time.Millisecond, func() bool {
		return secondAgent.Status().ReconnectAttemptCount >= 2
	})
	secondFailure := secondAgent.Status()
	if secondFailure.NextReconnectAttemptMs <= secondFailure.LastReconnectAttemptMs {
		t.Fatalf("expected reconnect status to expose a future retry, got %#v", secondFailure)
	}
	if wait := time.Until(time.UnixMilli(secondFailure.NextReconnectAttemptMs).Add(-3 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
		if current := secondAgent.Status(); current.ReconnectAttemptCount != 2 {
			t.Fatalf("expected second reconnect backoff window to hold before max delay, got %#v", current)
		}
	}

	waitForCondition(t, 150*time.Millisecond, func() bool {
		status := secondAgent.Status()
		return status.Connected && status.CurrentUser != nil && status.ReconnectAttemptCount == 0
	})

	status := secondAgent.Status()
	if !status.Connected || status.CurrentSession == nil {
		t.Fatalf("expected auto reconnect to succeed after transient failures, got %#v", status)
	}
	if status.LastReconnectError != "" || status.NextReconnectAttemptMs != 0 {
		t.Fatalf("expected reconnect backoff state to clear after success, got %#v", status)
	}
	if status.ReconnectState != "CONNECTED" || status.ReconnectBackoffActive || status.ReconnectRemainingMs != 0 {
		t.Fatalf("expected reconnect diagnostics to report connected state after success, got %#v", status)
	}
}

func TestAgentManualReconnectOverridesScheduledBackoff(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	firstAgent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	firstAgent.SetServerBaseURL(upstreamServer.URL)
	if _, err := firstAgent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := firstAgent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	firstAgent.Close()

	upstream.SetHealthFailures(1)
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   5 * time.Millisecond,
		ReconnectRetryBase:  150 * time.Millisecond,
		ReconnectRetryMax:   300 * time.Millisecond,
		HeartbeatInterval:   time.Hour,
		PeerDiscoveryPeriod: time.Hour,
		STUNProbePeriod:     time.Hour,
		TransportKeepalive:  time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	secondAgent := clientagent.NewWithClientAndStoreAndRuntime(controlclient.New(upstreamServer.URL), "127.0.0.1:0", stateStore, runtime)
	defer secondAgent.Close()

	waitForCondition(t, 50*time.Millisecond, func() bool {
		return secondAgent.Status().ReconnectAttemptCount == 1
	})
	pending := secondAgent.Status()
	if pending.NextReconnectAttemptMs <= pending.LastReconnectAttemptMs {
		t.Fatalf("expected a delayed reconnect attempt to be scheduled, got %#v", pending)
	}
	if pending.ReconnectState != "BACKOFF" || !pending.ReconnectBackoffActive {
		t.Fatalf("expected pending reconnect to expose backoff diagnostics, got %#v", pending)
	}

	status, err := secondAgent.Reconnect()
	if err != nil {
		t.Fatalf("manual reconnect: %v", err)
	}
	if !status.Connected || status.ReconnectAttemptCount != 0 {
		t.Fatalf("expected manual reconnect to restore session immediately, got %#v", status)
	}
	if status.NextReconnectAttemptMs != 0 || status.LastReconnectError != "" {
		t.Fatalf("expected manual reconnect to clear pending backoff state, got %#v", status)
	}
	if status.ReconnectState != "CONNECTED" || status.ReconnectBackoffActive {
		t.Fatalf("expected manual reconnect to clear reconnect diagnostics, got %#v", status)
	}
}

func TestAgentGracefulCloseClearsLifecycleDirtyMarker(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := agent.Close(); err != nil {
		t.Fatalf("close agent: %v", err)
	}

	state, err := stateStore.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if state.Lifecycle.Dirty {
		t.Fatalf("expected graceful close to clear dirty lifecycle marker, got %#v", state.Lifecycle)
	}
	if state.Lifecycle.LastStartUnix == 0 || state.Lifecycle.LastCleanShutdownUnix == 0 {
		t.Fatalf("expected lifecycle timestamps to be persisted on graceful close, got %#v", state.Lifecycle)
	}
}

func TestAgentCrashRecoveryRestoresReconnectStateAfterUncleanShutdown(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	firstAgent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	firstAgent.SetServerBaseURL(upstreamServer.URL)
	if _, err := firstAgent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := firstAgent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := firstAgent.Close(); err != nil {
		t.Fatalf("close first agent: %v", err)
	}

	upstream.SetHealthFailures(1)
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   5 * time.Millisecond,
		ReconnectRetryBase:  150 * time.Millisecond,
		ReconnectRetryMax:   300 * time.Millisecond,
		HeartbeatInterval:   time.Hour,
		PeerDiscoveryPeriod: time.Hour,
		STUNProbePeriod:     time.Hour,
		TransportKeepalive:  time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	secondAgent := clientagent.NewWithClientAndStoreAndRuntime(controlclient.New(upstreamServer.URL), "127.0.0.1:0", stateStore, runtime)
	waitForCondition(t, 50*time.Millisecond, func() bool {
		return secondAgent.Status().ReconnectAttemptCount == 1
	})
	pending := secondAgent.Status()
	if pending.ReconnectState != "BACKOFF" || pending.NextReconnectAttemptMs == 0 {
		t.Fatalf("expected reconnect backoff before crash simulation, got %#v", pending)
	}
	if err := secondAgent.Close(); err != nil {
		t.Fatalf("close second agent: %v", err)
	}

	crashedState, err := stateStore.Load()
	if err != nil {
		t.Fatalf("load crash state: %v", err)
	}
	if crashedState.Lifecycle.ReconnectAttemptCount != 1 || crashedState.Lifecycle.NextReconnectAttemptUnix == 0 {
		t.Fatalf("expected reconnect lifecycle metadata to persist before crash recovery, got %#v", crashedState.Lifecycle)
	}
	crashedState.Lifecycle.Dirty = true
	if err := stateStore.Save(crashedState); err != nil {
		t.Fatalf("save simulated crash state: %v", err)
	}

	thirdAgent := clientagent.NewWithClientAndStoreAndRuntime(controlclient.New(upstreamServer.URL), "127.0.0.1:0", stateStore, runtime)
	defer thirdAgent.Close()

	waitForCondition(t, 50*time.Millisecond, func() bool {
		status := thirdAgent.Status()
		return status.UncleanShutdownDetected && status.CrashRecoveryCount >= 1
	})
	initial := thirdAgent.Status()
	if !initial.UncleanShutdownDetected || initial.CrashRecoveryCount < 1 {
		t.Fatalf("expected crash recovery marker in status, got %#v", initial)
	}

	time.Sleep(25 * time.Millisecond)
	duringRecovery := thirdAgent.Status()
	if !duringRecovery.Connected && duringRecovery.ReconnectBackoffActive {
		t.Fatalf("expected crash recovery to bypass persisted stale backoff window, got %#v", duringRecovery)
	}

	waitForCondition(t, 150*time.Millisecond, func() bool {
		status := thirdAgent.Status()
		return status.Connected && status.ReconnectAttemptCount == 0
	})
	recovered := thirdAgent.Status()
	if !recovered.Connected || recovered.CurrentSession == nil {
		t.Fatalf("expected crash-recovered agent to restore session, got %#v", recovered)
	}
	if recovered.LastCrashRecoveryUnix == 0 || recovered.LastStartUnix == 0 {
		t.Fatalf("expected crash recovery timestamps in status, got %#v", recovered)
	}
	if recovered.ReconnectState != "CONNECTED" || recovered.LastReconnectError != "" {
		t.Fatalf("expected reconnect journal to clear after crash recovery succeeds, got %#v", recovered)
	}
}

func TestAgentIPCRejoinNetworkReusesStoredEndpoint(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer agent.Close()
	agent.SetServerBaseURL(upstreamServer.URL)
	ipcServer := httptest.NewServer(agent.Handler())
	defer ipcServer.Close()

	client := clientagent.NewIPCClient(ipcServer.URL)
	if _, err := client.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := client.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := client.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := client.RegisterPeer(network.ID, "127.0.0.1:4010"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.RemovePeer("peer-1")
	if upstream.PeerCountForNetwork(network.ID) != 0 {
		t.Fatalf("expected upstream peer to be removed before rejoin")
	}

	status, err := client.RejoinNetwork(network.ID, "")
	if err != nil {
		t.Fatalf("rejoin network: %v", err)
	}
	if !status.Connected || status.ManagedPeerCount != 1 {
		t.Fatalf("expected rejoin to keep agent connected with one managed peer, got %#v", status)
	}
	if upstream.PeerCountForNetwork(network.ID) != 1 {
		t.Fatalf("expected peer to be re-created on upstream after rejoin")
	}
}

func TestAgentBlocksLoginAgainstIncompatibleServerVersion(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.minClientVersion = "9.0.0"
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	agent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer agent.Close()

	status := agent.SetServerBaseURL(upstreamServer.URL)
	if status.CompatibilityStatus != "UPGRADE_REQUIRED" {
		t.Fatalf("expected upgrade required compatibility status, got %#v", status)
	}

	if _, err := agent.Login("owner@example.com", "secret"); err == nil {
		t.Fatalf("expected login to fail against incompatible server")
	}
}

func TestAgentPersistsDeviceIdentityAcrossRestarts(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))

	firstAgent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer firstAgent.Close()
	firstAgent.SetServerBaseURL(upstreamServer.URL)
	if _, err := firstAgent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := firstAgent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("first login: %v", err)
	}
	if upstream.DeviceCreateCalls() != 1 {
		t.Fatalf("expected first login to create one device, got %d", upstream.DeviceCreateCalls())
	}
	firstStatus := firstAgent.Status()
	if firstStatus.CurrentDevice == nil {
		t.Fatalf("expected current device after first login")
	}
	if strings.TrimSpace(firstStatus.CurrentDevice.PublicKey) == "" {
		t.Fatalf("expected persistent device public key to be enrolled")
	}

	secondAgent := clientagent.NewWithClientAndStore(nil, "127.0.0.1:0", stateStore)
	defer secondAgent.Close()
	secondAgent.SetServerBaseURL(upstreamServer.URL)
	if _, err := secondAgent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("second login: %v", err)
	}
	if upstream.DeviceCreateCalls() != 1 {
		t.Fatalf("expected second login to reuse enrolled device, got create calls=%d", upstream.DeviceCreateCalls())
	}
	secondStatus := secondAgent.Status()
	if secondStatus.CurrentDevice == nil {
		t.Fatalf("expected current device after second login")
	}
	if secondStatus.CurrentDevice.ID != firstStatus.CurrentDevice.ID {
		t.Fatalf("expected same device id across agent restarts, got %s then %s", firstStatus.CurrentDevice.ID, secondStatus.CurrentDevice.ID)
	}
}

func TestAgentRestoresSessionAndRunsLifecycleLoops(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		SessionRefreshSkew:  time.Hour,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
	}
	adapterManager := &fakeAdapterManager{}

	firstAgent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, runtime, adapterManager)
	firstAgent.SetServerBaseURL(upstreamServer.URL)
	if _, err := firstAgent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := firstAgent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := firstAgent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := firstAgent.RegisterPeer(network.ID, reserveUDPBindEndpoint(t)); err != nil {
		t.Fatalf("register peer: %v", err)
	}

	waitForCondition(t, time.Second, func() bool {
		return upstream.RefreshCalls() >= 1 && upstream.HeartbeatCalls() >= 1 && upstream.ListPeerCalls() >= 1
	})
	waitForCondition(t, time.Second, func() bool {
		return len(adapterManager.LastDesired()) == 1
	})
	firstAgent.Close()

	secondAdapterManager := &fakeAdapterManager{}
	secondAgent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, runtime, secondAdapterManager)
	defer secondAgent.Close()
	status := secondAgent.SetServerBaseURL(upstreamServer.URL)
	if !status.Connected {
		t.Fatalf("expected persisted session to restore on agent restart, got %#v", status)
	}
	if status.ManagedPeerCount != 1 {
		t.Fatalf("expected restored managed peer count to be 1, got %d", status.ManagedPeerCount)
	}

	initialHeartbeatCalls := upstream.HeartbeatCalls()
	initialDiscoveryCalls := upstream.ListPeerCalls()
	waitForCondition(t, time.Second, func() bool {
		return upstream.HeartbeatCalls() > initialHeartbeatCalls && upstream.ListPeerCalls() > initialDiscoveryCalls
	})
	waitForCondition(t, time.Second, func() bool {
		desired := secondAdapterManager.LastDesired()
		return len(desired) == 1 && desired[0].VirtualIP == "10.0.0.2" && desired[0].RoutePrefix == "10.0.0.0/24"
	})
}

func TestAgentClearsVirtualAdapterStateOnLogout(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, clientagent.DefaultRuntimeConfig(), adapterManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, reserveUDPBindEndpoint(t)); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	if err := agent.Logout(); err != nil {
		t.Fatalf("logout: %v", err)
	}
	desired := adapterManager.LastDesired()
	if len(desired) != 0 {
		t.Fatalf("expected adapter reconcile to clear desired state on logout, got %#v", desired)
	}
}

func TestAgentPersistsAdapterMTUAcrossRestartAndReconcile(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	firstAdapterManager := &fakeAdapterManager{}
	firstAgent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, clientagent.DefaultRuntimeConfig(), firstAdapterManager)
	defer firstAgent.Close()

	firstAgent.SetServerBaseURL(upstreamServer.URL)
	if _, err := firstAgent.SetAdapterMTU(1380); err != nil {
		t.Fatalf("set adapter mtu: %v", err)
	}
	if _, err := firstAgent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := firstAgent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := firstAgent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := firstAgent.RegisterPeer(network.ID, reserveUDPBindEndpoint(t)); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	waitForCondition(t, time.Second, func() bool {
		desired := firstAdapterManager.LastDesired()
		return len(desired) == 1 && desired[0].MTU == 1380
	})
	firstAgent.Close()

	secondAdapterManager := &fakeAdapterManager{}
	secondAgent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, clientagent.DefaultRuntimeConfig(), secondAdapterManager)
	defer secondAgent.Close()

	status := secondAgent.SetServerBaseURL(upstreamServer.URL)
	if status.Adapter.DesiredMTU != 1380 {
		t.Fatalf("expected desired MTU after restart, got %#v", status.Adapter)
	}
	waitForCondition(t, time.Second, func() bool {
		desired := secondAdapterManager.LastDesired()
		return len(desired) == 1 && desired[0].MTU == 1380
	})
}

func TestAgentConfiguresOverlayDNSAndResolvesPeerNames(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:       10 * time.Millisecond,
		HeartbeatInterval:       10 * time.Millisecond,
		PeerDiscoveryPeriod:     10 * time.Millisecond,
		OverlayDNSListenAddress: "127.0.0.1:0",
		OverlayDNSDomain:        "ole",
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, runtime, adapterManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, reserveUDPBindEndpoint(t)); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42020", []string{"127.0.0.1:42020"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		desired := adapterManager.LastDesired()
		return status.OverlayDNSListenAddress != "" && status.OverlayDNSRecordCount >= 2 && len(desired) == 1 && desired[0].DNSServer == "127.0.0.1" && desired[0].DNSSuffix == "ole"
	})

	status := agent.Status()
	var hosts []string
	waitForCondition(t, time.Second, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		resolved, err := overlaydns.LookupHost(ctx, status.OverlayDNSListenAddress, "peer-remote.ole")
		if err != nil {
			return false
		}
		hosts = resolved
		return len(resolved) == 1 && resolved[0] == "10.0.0.3"
	})
	if len(hosts) != 1 || hosts[0] != "10.0.0.3" {
		t.Fatalf("expected overlay dns to resolve remote peer virtual IP, got %#v", hosts)
	}
}

func TestAgentOverlayDNSDeduplicatesSameUserReplacementPeers(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:       10 * time.Millisecond,
		HeartbeatInterval:       10 * time.Millisecond,
		PeerDiscoveryPeriod:     10 * time.Millisecond,
		OverlayDNSListenAddress: "127.0.0.1:0",
		OverlayDNSDomain:        "ole",
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, runtime, adapterManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, reserveUDPBindEndpoint(t)); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeerForUser(network.ID, "peer-remote-old", "usr-remote", "dev-remote", "10.0.0.3", "127.0.0.1:42020", []string{"127.0.0.1:42020"})
	time.Sleep(10 * time.Millisecond)
	upstream.AddRemotePeerForUser(network.ID, "peer-remote-new", "usr-remote", "dev-remote", "10.0.0.3", "127.0.0.1:42021", []string{"127.0.0.1:42021"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		desired := adapterManager.LastDesired()
		return status.OverlayDNSListenAddress != "" && status.OverlayDNSRecordCount >= 2 && len(desired) == 1 && desired[0].DNSServer == "127.0.0.1" && desired[0].DNSSuffix == "ole"
	})

	status := agent.Status()
	var hosts []string
	waitForCondition(t, time.Second, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		resolved, err := overlaydns.LookupHost(ctx, status.OverlayDNSListenAddress, "peer-remote-new.ole")
		if err != nil {
			return false
		}
		hosts = resolved
		return len(resolved) == 1 && resolved[0] == "10.0.0.3"
	})
	if len(hosts) != 1 || hosts[0] != "10.0.0.3" {
		t.Fatalf("expected overlay dns to resolve replacement peer virtual IP, got %#v", hosts)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := overlaydns.LookupHost(ctx, status.OverlayDNSListenAddress, "peer-remote-old.ole"); err == nil {
		t.Fatalf("expected overlay dns to drop stale peer name after replacement")
	}
}

func TestAgentOverlayDNSDeduplicatesReplacementPeersWithoutUserMetadata(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:       10 * time.Millisecond,
		HeartbeatInterval:       10 * time.Millisecond,
		PeerDiscoveryPeriod:     10 * time.Millisecond,
		OverlayDNSListenAddress: "127.0.0.1:0",
		OverlayDNSDomain:        "ole",
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, runtime, adapterManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, reserveUDPBindEndpoint(t)); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeerForUser(network.ID, "peer-remote-old", "", "dev-remote", "10.0.0.3", "127.0.0.1:42022", []string{"127.0.0.1:42022"})
	time.Sleep(10 * time.Millisecond)
	upstream.AddRemotePeerForUser(network.ID, "peer-remote-new", "", "dev-remote", "10.0.0.3", "127.0.0.1:42023", []string{"127.0.0.1:42023"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		desired := adapterManager.LastDesired()
		return status.OverlayDNSListenAddress != "" && status.OverlayDNSRecordCount >= 2 && len(desired) == 1 && desired[0].DNSServer == "127.0.0.1" && desired[0].DNSSuffix == "ole"
	})

	status := agent.Status()
	var hosts []string
	waitForCondition(t, time.Second, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		resolved, err := overlaydns.LookupHost(ctx, status.OverlayDNSListenAddress, "peer-remote-new.ole")
		if err != nil {
			return false
		}
		hosts = resolved
		return len(resolved) == 1 && resolved[0] == "10.0.0.3"
	})
	if len(hosts) != 1 || hosts[0] != "10.0.0.3" {
		t.Fatalf("expected overlay dns to resolve replacement peer virtual IP even without user metadata, got %#v", hosts)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := overlaydns.LookupHost(ctx, status.OverlayDNSListenAddress, "peer-remote-old.ole"); err == nil {
		t.Fatalf("expected overlay dns to drop stale peer name after replacement even without user metadata")
	}
}

func TestAgentDedupesManagedPeersForRuntimeBindings(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: time.Hour,
		STUNProbePeriod:     time.Hour,
	}
	adapterManager := &fakeAdapterManager{}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, runtime, adapterManager)

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	peer, err := agent.RegisterPeer(network.ID, reserveUDPBindEndpoint(t))
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}
	agent.Close()

	state, err := stateStore.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(state.ManagedPeers) == 0 {
		t.Fatalf("expected managed peers to persist")
	}
	existing := state.ManagedPeers[0]
	replacement := clientagent.ManagedPeerState{
		ServerBaseURL: upstreamServer.URL,
		UserID:        existing.UserID,
		NetworkID:     network.ID,
		PeerID:        "peer-local-replacement",
		Endpoint:      "127.0.0.1:4001",
		OverlayCIDR:   overlayCIDRForTestIP(peer.VirtualIP),
		VirtualIP:     peer.VirtualIP,
	}
	state.ManagedPeers = []clientagent.ManagedPeerState{replacement, existing}
	if err := stateStore.Save(state); err != nil {
		t.Fatalf("save state: %v", err)
	}

	directManager := &fakeDirectManager{}
	adapterManager = &fakeAdapterManager{}
	agent = clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := agent.SetAdapterMTU(1380); err != nil {
		t.Fatalf("set adapter mtu: %v", err)
	}

	waitForCondition(t, 2*time.Second, func() bool {
		directManager.mu.Lock()
		defer directManager.mu.Unlock()
		return len(directManager.bindings) > 0
	})
	directManager.mu.Lock()
	defer directManager.mu.Unlock()
	if len(directManager.bindings) != 1 ||
		directManager.bindings[0].ListenAddress != replacement.Endpoint ||
		directManager.bindings[0].PeerID == existing.PeerID {
		t.Fatalf("expected deduped direct binding for replacement peer, got %#v", directManager.bindings)
	}
}

func TestAgentDedupesRelayBindingsForReplacementPeers(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: time.Hour,
		STUNProbePeriod:     time.Hour,
		RelayServerAddress:  "",
	}
	adapterManager := &fakeAdapterManager{}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, runtime, adapterManager)

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	peer, err := agent.RegisterPeer(network.ID, reserveUDPBindEndpoint(t))
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}
	agent.Close()

	state, err := stateStore.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(state.ManagedPeers) == 0 {
		t.Fatalf("expected managed peers to persist")
	}
	existing := state.ManagedPeers[0]
	replacement := clientagent.ManagedPeerState{
		ServerBaseURL: upstreamServer.URL,
		UserID:        existing.UserID,
		NetworkID:     network.ID,
		PeerID:        "peer-local-replacement",
		Endpoint:      "127.0.0.1:4001",
		OverlayCIDR:   overlayCIDRForTestIP(peer.VirtualIP),
		VirtualIP:     peer.VirtualIP,
	}
	state.ManagedPeers = []clientagent.ManagedPeerState{replacement, existing}
	if err := stateStore.Save(state); err != nil {
		t.Fatalf("save state: %v", err)
	}

	directManager := &fakeDirectManager{}
	relayManager := &fakeRelayManager{}
	adapterManager = &fakeAdapterManager{}
	runtimeWithRelay := runtime
	runtimeWithRelay.RelayServerAddress = "127.0.0.1:47000"
	agent = clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(nil, "127.0.0.1:0", stateStore, runtimeWithRelay, adapterManager, directManager, relayManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}

	waitForCondition(t, time.Second, func() bool {
		relayManager.mu.Lock()
		defer relayManager.mu.Unlock()
		return len(relayManager.bindings) == 1 && relayManager.bindings[0].PeerID == "peer-local-replacement"
	})
	relayManager.mu.Lock()
	defer relayManager.mu.Unlock()
	if len(relayManager.bindings) != 1 || relayManager.bindings[0].PeerID != "peer-local-replacement" {
		t.Fatalf("expected deduped relay binding for replacement peer, got %#v", relayManager.bindings)
	}
}

func TestAgentManagedPeerCountDedupesReplacementPeers(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: time.Hour,
		STUNProbePeriod:     time.Hour,
	}
	adapterManager := &fakeAdapterManager{}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, runtime, adapterManager)

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	peer, err := agent.RegisterPeer(network.ID, reserveUDPBindEndpoint(t))
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}
	agent.Close()

	state, err := stateStore.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(state.ManagedPeers) == 0 {
		t.Fatalf("expected managed peers to persist")
	}
	existing := state.ManagedPeers[0]
	replacement := clientagent.ManagedPeerState{
		ServerBaseURL: upstreamServer.URL,
		UserID:        existing.UserID,
		NetworkID:     network.ID,
		PeerID:        "peer-local-replacement",
		Endpoint:      "127.0.0.1:4001",
		OverlayCIDR:   overlayCIDRForTestIP(peer.VirtualIP),
		VirtualIP:     peer.VirtualIP,
	}
	state.ManagedPeers = []clientagent.ManagedPeerState{replacement, existing}
	if err := stateStore.Save(state); err != nil {
		t.Fatalf("save state: %v", err)
	}

	agent = clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, runtime, adapterManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}

	waitForCondition(t, time.Second, func() bool {
		return agent.Status().ManagedPeerCount == 1
	})
	if agent.Status().ManagedPeerCount != 1 {
		t.Fatalf("expected managed peer count to dedupe replacements, got %d", agent.Status().ManagedPeerCount)
	}
}

func TestAgentHonorsPerNetworkNameResolutionPolicy(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:       10 * time.Millisecond,
		HeartbeatInterval:       10 * time.Millisecond,
		PeerDiscoveryPeriod:     10 * time.Millisecond,
		OverlayDNSListenAddress: "127.0.0.1:0",
		OverlayDNSDomain:        "ole",
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, runtime, adapterManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		NameResolutionMode: "NETWORK_ONLY",
		DNSLabel:           "friends-lan",
	})
	if err != nil {
		t.Fatalf("create network with name-resolution policy: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, reserveUDPBindEndpoint(t)); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42020", []string{"127.0.0.1:42020"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return status.OverlayDNSListenAddress != "" && status.OverlayDNSRecordCount >= 2
	})

	status := agent.Status()
	var hosts []string
	waitForCondition(t, time.Second, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		resolved, err := overlaydns.LookupHost(ctx, status.OverlayDNSListenAddress, "peer-remote.friends-lan.ole")
		if err != nil {
			return false
		}
		hosts = resolved
		return len(resolved) == 1 && resolved[0] == "10.0.0.3"
	})
	if len(hosts) != 1 || hosts[0] != "10.0.0.3" {
		t.Fatalf("expected network-scoped overlay dns to resolve remote peer virtual IP, got %#v", hosts)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := overlaydns.LookupHost(ctx, status.OverlayDNSListenAddress, "peer-remote.ole"); err == nil {
		t.Fatalf("expected global overlay hostname to stay unresolved in NETWORK_ONLY mode")
	}

	updated, err := agent.UpdateNetworkNameResolution(network.ID, "DISABLED", "")
	if err != nil {
		t.Fatalf("disable name resolution: %v", err)
	}
	if updated.NameResolutionMode != "DISABLED" {
		t.Fatalf("expected disabled name resolution mode, got %#v", updated)
	}

	waitForCondition(t, time.Second, func() bool {
		return agent.Status().OverlayDNSRecordCount == 0
	})
}

func TestAgentReconcilesAdapterWithNetworkRoutingPolicy(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: time.Hour,
		STUNProbePeriod:     time.Hour,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, runtime, adapterManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create network with routing policy: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, reserveUDPBindEndpoint(t)); err != nil {
		t.Fatalf("register peer: %v", err)
	}

	waitForCondition(t, time.Second, func() bool {
		desired := adapterManager.LastDesired()
		return len(desired) == 1 && desired[0].RoutingPolicy == "FULL"
	})

	updated, err := agent.UpdateNetworkRoutingPolicy(network.ID, "SPLIT")
	if err != nil {
		t.Fatalf("update routing policy: %v", err)
	}
	if updated.RoutingPolicy != "SPLIT" {
		t.Fatalf("expected split routing policy after update, got %#v", updated)
	}
	waitForCondition(t, time.Second, func() bool {
		desired := adapterManager.LastDesired()
		return len(desired) == 1 && desired[0].RoutingPolicy == "SPLIT"
	})
}

func TestAgentMarksOwnerFullNetworkAsGatewayRole(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: time.Hour,
		STUNProbePeriod:     time.Hour,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, runtime, adapterManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create network with routing policy: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, reserveUDPBindEndpoint(t)); err != nil {
		t.Fatalf("register peer: %v", err)
	}

	waitForCondition(t, time.Second, func() bool {
		desired := adapterManager.LastDesired()
		return len(desired) == 1 && desired[0].RoutingPolicy == "FULL" && desired[0].GatewayRole == "GATEWAY"
	})

	desired := adapterManager.LastDesired()
	if desired[0].RoutePrefix == "0.0.0.0/0" {
		t.Fatalf("expected owner full-tunnel network to stay on overlay route, got %#v", desired[0])
	}
}

func TestAgentMarksAdminFullNetworkAsGatewayRole(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: time.Hour,
		STUNProbePeriod:     time.Hour,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, runtime, adapterManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("admin@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("admin@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create full network: %v", err)
	}
	upstream.OverrideNetworkOwner(network.ID, "usr-upstream-owner")
	upstream.AddNetworkMember(network.ID, "usr-1", "ADMIN")
	if _, err := agent.RegisterPeer(network.ID, reserveUDPBindEndpoint(t)); err != nil {
		t.Fatalf("register peer: %v", err)
	}

	waitForCondition(t, time.Second, func() bool {
		desired := adapterManager.LastDesired()
		return len(desired) == 1 && desired[0].RoutingPolicy == "FULL" && desired[0].GatewayRole == "GATEWAY"
	})

	desired := adapterManager.LastDesired()
	if desired[0].GatewayRole != "GATEWAY" || desired[0].RoutePrefix == "0.0.0.0/0" {
		t.Fatalf("expected admin full network to activate local gateway role without default route, got %#v", desired[0])
	}
}

func TestAgentRoutesFullTunnelGatewayReturnTrafficBackToRemoteOverlayPeer(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "gateway-return-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1, stunMappedAddress: "203.0.113.10:54000"}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   time.Hour,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("gateway-owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("gateway-owner@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create full network: %v", err)
	}
	upstream.AddNetworkMember(network.ID, "usr-member", "MEMBER")
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41044"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeerForUser(network.ID, "peer-member", "usr-member", "dev-member", "10.0.0.3", "127.0.0.1:42044", []string{"127.0.0.1:42044"})

	waitForCondition(t, 2*time.Second, func() bool {
		desired := adapterManager.LastDesired()
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			len(desired) == 1 &&
			desired[0].RoutingPolicy == "FULL" &&
			desired[0].GatewayRole == "GATEWAY"
	})

	packet := buildIPv4Packet(t, "8.8.8.8", "10.0.0.3", []byte{1, 2, 3, 4})
	before := directManager.SentPacketCount()
	adapterManager.EnqueueOutbound(packet)

	waitForCondition(t, time.Second, func() bool {
		return directManager.SentPacketCount() == before+1
	})

	sent := directManager.SentPacketDetails()
	if len(sent) == 0 {
		t.Fatalf("expected gateway return packet to be forwarded, got none")
	}
	last := sent[len(sent)-1]
	if last.RemotePeerID != "peer-member" || string(last.Payload) != string(packet) {
		t.Fatalf("expected gateway return packet to route back to remote overlay peer, got %#v", last)
	}
}

func TestAgentDoesNotBridgeOtherManagedOverlayTrafficThroughFullTunnelGatewayReturnPath(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "gateway-cross-overlay-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("gateway-owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("gateway-owner@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}

	gatewayNetwork, err := agent.CreateNetworkWithOptions("gateway-full", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create gateway full network: %v", err)
	}
	upstream.AddNetworkMember(gatewayNetwork.ID, "usr-member-a", "MEMBER")
	upstream.localPeerCIDR = "10.10.0.0/24"
	if _, err := agent.RegisterPeer(gatewayNetwork.ID, "127.0.0.1:41045"); err != nil {
		t.Fatalf("register gateway peer: %v", err)
	}
	upstream.AddRemotePeerForUser(gatewayNetwork.ID, "peer-member-a", "usr-member-a", "dev-member-a", "10.10.0.3", "127.0.0.1:42045", []string{"127.0.0.1:42045"})

	overlayNetwork, err := agent.CreateNetworkWithOptions("overlay-split", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "SPLIT",
	})
	if err != nil {
		t.Fatalf("create overlay split network: %v", err)
	}
	upstream.OverrideNetworkOwner(overlayNetwork.ID, "usr-owner-b")
	upstream.AddNetworkMember(overlayNetwork.ID, "usr-1", "MEMBER")
	upstream.localPeerCIDR = "10.20.0.0/24"
	if _, err := agent.RegisterPeer(overlayNetwork.ID, "127.0.0.1:41046"); err != nil {
		t.Fatalf("register overlay peer: %v", err)
	}
	upstream.AddRemotePeerForUser(overlayNetwork.ID, "peer-member-b", "usr-owner-b", "dev-member-b", "10.20.0.3", "127.0.0.1:42046", []string{"127.0.0.1:42046"})

	deadline := time.Now().Add(2 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		desired := adapterManager.LastDesired()
		status := agent.Status()
		if len(desired) == 2 {
			foundGateway := false
			foundOverlay := false
			foundGatewayConnection := false
			for _, network := range desired {
				if network.NetworkID == gatewayNetwork.ID && network.GatewayRole == "GATEWAY" && network.RoutingPolicy == "FULL" {
					foundGateway = true
				}
				if network.NetworkID == overlayNetwork.ID && network.RoutingPolicy == "SPLIT" {
					foundOverlay = true
				}
			}
			for _, connection := range status.Connections {
				if connection.NetworkID == gatewayNetwork.ID && connection.RemotePeerID == "peer-member-a" && connection.State == "CONNECTED" {
					foundGatewayConnection = true
					break
				}
			}
			if foundGateway && foundOverlay && foundGatewayConnection {
				ready = true
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("expected gateway plus overlay topology to reconcile, got status=%#v desired=%#v", agent.Status(), adapterManager.LastDesired())
	}

	before := directManager.SentPacketCount()
	crossOverlayPacket := buildIPv4Packet(t, "10.20.0.3", "10.10.0.3", []byte{1, 2, 3, 4})
	adapterManager.EnqueueOutbound(crossOverlayPacket)
	time.Sleep(120 * time.Millisecond)
	if directManager.SentPacketCount() != before {
		t.Fatalf("expected cross-overlay packet to stay off FULL gateway return path, got %#v", directManager.SentPacketDetails())
	}

	internetReturnPacket := buildIPv4Packet(t, "8.8.8.8", "10.10.0.3", []byte{5, 6, 7, 8})
	adapterManager.EnqueueOutbound(internetReturnPacket)
	waitForCondition(t, time.Second, func() bool {
		return directManager.SentPacketCount() == before+1
	})
	sent := directManager.SentPacketDetails()
	if len(sent) == 0 {
		t.Fatalf("expected internet return packet to still route through FULL gateway")
	}
	last := sent[len(sent)-1]
	if last.RemotePeerID != "peer-member-a" || string(last.Payload) != string(internetReturnPacket) {
		t.Fatalf("expected only true internet return traffic to route through FULL gateway, got %#v", last)
	}
}

func TestAgentKeepsGatewayHostLocalSourceTrafficOffFullTunnelReturnPath(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "gateway-local-source-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("gateway-owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("gateway-owner@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create full network: %v", err)
	}
	upstream.AddNetworkMember(network.ID, "usr-member", "MEMBER")
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41054"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeerForUser(network.ID, "peer-member", "usr-member", "dev-member", "10.0.0.3", "127.0.0.1:42054", []string{"127.0.0.1:42054"})

	waitForCondition(t, 2*time.Second, func() bool {
		desired := adapterManager.LastDesired()
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			len(desired) == 1 &&
			desired[0].RoutingPolicy == "FULL" &&
			desired[0].GatewayRole == "GATEWAY"
	})

	before := directManager.SentPacketCount()
	adapterManager.EnqueueOutbound(buildIPv4Packet(t, "127.0.0.1", "10.0.0.3", []byte{1, 2, 3, 4}))
	adapterManager.EnqueueOutbound(buildIPv4Packet(t, "169.254.10.20", "10.0.0.3", []byte{5, 6, 7, 8}))
	time.Sleep(120 * time.Millisecond)
	if directManager.SentPacketCount() != before {
		t.Fatalf("expected gateway-host local-source traffic to stay off FULL return path, got %#v", directManager.SentPacketDetails())
	}

	internetReturnPacket := buildIPv4Packet(t, "8.8.8.8", "10.0.0.3", []byte{9, 8, 7, 6})
	adapterManager.EnqueueOutbound(internetReturnPacket)
	waitForCondition(t, time.Second, func() bool {
		return directManager.SentPacketCount() == before+1
	})
	sent := directManager.SentPacketDetails()
	if len(sent) == 0 {
		t.Fatalf("expected true internet return traffic to keep routing through FULL gateway")
	}
	last := sent[len(sent)-1]
	if last.RemotePeerID != "peer-member" || string(last.Payload) != string(internetReturnPacket) {
		t.Fatalf("expected only true internet return traffic to route through FULL gateway, got %#v", last)
	}
}

func TestAgentDropsAmbiguousFullTunnelGatewayReturnTrafficAcrossOverlappingNetworks(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "gateway-overlap-ambiguity-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("gateway-owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("gateway-owner@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}

	networkA, err := agent.CreateNetworkWithOptions("gateway-a", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create first full gateway network: %v", err)
	}
	upstream.AddNetworkMember(networkA.ID, "usr-member-a1", "MEMBER")
	upstream.AddNetworkMember(networkA.ID, "usr-member-a2", "MEMBER")
	upstream.localPeerCIDR = "10.10.0.0/24"
	if _, err := agent.RegisterPeer(networkA.ID, "127.0.0.1:41047"); err != nil {
		t.Fatalf("register first gateway peer: %v", err)
	}
	upstream.AddRemotePeerForUser(networkA.ID, "peer-member-a1", "usr-member-a1", "dev-member-a1", "10.10.0.3", "127.0.0.1:42047", []string{"127.0.0.1:42047"})
	upstream.AddRemotePeerForUser(networkA.ID, "peer-member-a2", "usr-member-a2", "dev-member-a2", "10.10.0.4", "127.0.0.1:42048", []string{"127.0.0.1:42048"})

	networkB, err := agent.CreateNetworkWithOptions("gateway-b", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create second full gateway network: %v", err)
	}
	upstream.AddNetworkMember(networkB.ID, "usr-member-b1", "MEMBER")
	upstream.localPeerCIDR = "10.10.0.0/24"
	if _, err := agent.RegisterPeer(networkB.ID, "127.0.0.1:41049"); err != nil {
		t.Fatalf("register second gateway peer: %v", err)
	}
	upstream.AddRemotePeerForUser(networkB.ID, "peer-member-b1", "usr-member-b1", "dev-member-b1", "10.10.0.3", "127.0.0.1:42049", []string{"127.0.0.1:42049"})

	waitForCondition(t, 2*time.Second, func() bool {
		status := agent.Status()
		connected := map[string]bool{}
		ambiguousMatches := 0
		seenNetworks := map[string]bool{}
		for _, connection := range status.Connections {
			if connection.State == "CONNECTED" {
				connected[connection.RemotePeerID] = true
				if connection.RemoteVirtualIP == "10.10.0.3" && !seenNetworks[connection.NetworkID] {
					ambiguousMatches++
					seenNetworks[connection.NetworkID] = true
				}
			}
		}
		return connected["peer-member-a1"] && connected["peer-member-a2"] && connected["peer-member-b1"] && ambiguousMatches >= 2
	})

	before := directManager.SentPacketCount()
	ambiguousPacket := buildIPv4Packet(t, "8.8.8.8", "10.10.0.3", []byte{1, 2, 3, 4})
	adapterManager.EnqueueOutbound(ambiguousPacket)
	time.Sleep(120 * time.Millisecond)
	if directManager.SentPacketCount() != before {
		t.Fatalf("expected overlapping FULL gateway return traffic to be dropped when destination is ambiguous, got %#v", directManager.SentPacketDetails())
	}
}

func TestAgentUsesOwnerGatewayForFullTunnelDefaultRouteAndInternetPackets(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "joiner-agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create full network: %v", err)
	}
	upstream.OverrideNetworkOwner(network.ID, "usr-owner")
	upstream.AddNetworkMember(network.ID, "usr-1", "MEMBER")
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41040"); err != nil {
		t.Fatalf("register peer: %v", err)
	}

	upstream.AddRemotePeerForUser(network.ID, "peer-owner", "usr-owner", "dev-owner", "10.0.0.3", "127.0.0.1:42040", []string{"127.0.0.1:42040"})

	deadline := time.Now().Add(2 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		status := agent.Status()
		desired := adapterManager.LastDesired()
		ready = len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			len(desired) == 1 &&
			desired[0].RoutingPolicy == "FULL" &&
			desired[0].RoutePrefix == "0.0.0.0/0" &&
			desired[0].GatewayRole == "CLIENT" &&
			desired[0].GatewayPeerID == "peer-owner"
		if ready {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatalf(
			"expected full-tunnel guest route to switch onto owner gateway, got status=%#v desired=%#v attempts=%d establish=%d",
			agent.Status(),
			adapterManager.LastDesired(),
			directManager.AttemptCalls(),
			directManager.EstablishCalls(),
		)
	}

	outbound := buildIPv4Packet(t, "10.0.0.2", "8.8.8.8", []byte{1, 2, 3, 4})
	adapterManager.EnqueueOutbound(outbound)

	waitForCondition(t, time.Second, func() bool {
		return directManager.SentPacketCount() >= 1
	})

	sent := directManager.SentPackets()
	if len(sent) == 0 || string(sent[0]) != string(outbound) {
		t.Fatalf("expected internet-bound packet to be forwarded through owner gateway connection, got %#v", sent)
	}
}

func TestAgentAcceptsInboundInternetReturnPacketFromSelectedFullTunnelGateway(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "full-inbound-gateway-return-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("full-inbound-owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("full-inbound-owner@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create full network: %v", err)
	}
	upstream.OverrideNetworkOwner(network.ID, "usr-owner")
	upstream.AddNetworkMember(network.ID, "usr-1", "MEMBER")
	localPeer, err := agent.RegisterPeer(network.ID, "127.0.0.1:41041")
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}

	upstream.AddRemotePeerForUser(network.ID, "peer-owner", "usr-owner", "dev-owner", "10.0.0.3", "127.0.0.1:42041", []string{"127.0.0.1:42041"})

	waitForCondition(t, 2*time.Second, func() bool {
		desired := adapterManager.LastDesired()
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			len(desired) == 1 &&
			desired[0].RoutingPolicy == "FULL" &&
			desired[0].GatewayPeerID == "peer-owner"
	})

	packet := buildIPv4Packet(t, "8.8.8.8", localPeer.VirtualIP, []byte{5, 6, 7, 8})
	directManager.InjectInbound(localPeer.ID, directprobe.Packet{
		RemotePeerID:   "peer-owner",
		Payload:        packet,
		ReceivedAtUnix: time.Now().Unix(),
	})

	waitForCondition(t, time.Second, func() bool {
		return len(adapterManager.WrittenPackets()) == 1
	})

	written := adapterManager.WrittenPackets()
	if len(written) != 1 || string(written[0]) != string(packet) {
		t.Fatalf("expected inbound internet-return packet from selected full-tunnel gateway to reach adapter, got %#v", written)
	}
}

func TestAgentDropsInboundInternetReturnPacketFromStandbyFullTunnelGateway(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "full-inbound-standby-gateway-return-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("full-inbound-standby-owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("full-inbound-standby-owner@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}

	ownerPreferred, err := agent.CreateNetworkWithOptions("owner-full", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create owner-full network: %v", err)
	}
	upstream.OverrideNetworkOwner(ownerPreferred.ID, "usr-owner-a")
	upstream.AddNetworkMember(ownerPreferred.ID, "usr-1", "MEMBER")
	upstream.localPeerCIDR = "10.10.0.0/24"
	ownerPeer, err := agent.RegisterPeer(ownerPreferred.ID, "127.0.0.1:41042")
	if err != nil {
		t.Fatalf("register owner-full peer: %v", err)
	}
	upstream.AddRemotePeerForUser(ownerPreferred.ID, "peer-owner-a", "usr-owner-a", "dev-owner-a", "10.10.0.3", "127.0.0.1:42042", []string{"127.0.0.1:42042"})

	adminStandby, err := agent.CreateNetworkWithOptions("admin-full", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create admin-full network: %v", err)
	}
	upstream.OverrideNetworkOwner(adminStandby.ID, "usr-owner-b")
	upstream.AddNetworkMember(adminStandby.ID, "usr-admin-b", "ADMIN")
	upstream.AddNetworkMember(adminStandby.ID, "usr-1", "MEMBER")
	upstream.localPeerCIDR = "10.20.0.0/24"
	standbyPeer, err := agent.RegisterPeer(adminStandby.ID, "127.0.0.1:41043")
	if err != nil {
		t.Fatalf("register admin-full peer: %v", err)
	}
	upstream.AddRemotePeerForUser(adminStandby.ID, "peer-admin-b", "usr-admin-b", "dev-admin-b", "10.20.0.3", "127.0.0.1:42043", []string{"127.0.0.1:42043"})

	waitForCondition(t, 2*time.Second, func() bool {
		desired := adapterManager.LastDesired()
		status := agent.Status()
		if len(status.Connections) < 2 || len(desired) != 2 {
			return false
		}
		var active, standby *virtualadapter.NetworkConfig
		for idx := range desired {
			switch desired[idx].NetworkID {
			case ownerPreferred.ID:
				active = &desired[idx]
			case adminStandby.ID:
				standby = &desired[idx]
			}
		}
		return active != nil &&
			standby != nil &&
			active.RoutePrefix == "0.0.0.0/0" &&
			active.GatewayPeerID == "peer-owner-a" &&
			strings.TrimSpace(active.PolicyStatusHint) == "" &&
			standby.RoutePrefix == "10.20.0.0/24" &&
			standby.GatewayPeerID == "peer-admin-b" &&
			standby.PolicyStatusHint == "STANDBY_GATEWAY"
	})

	standbyPacket := buildIPv4Packet(t, "8.8.8.8", standbyPeer.VirtualIP, []byte{1, 2, 3, 4})
	directManager.InjectInbound(standbyPeer.ID, directprobe.Packet{
		RemotePeerID:   "peer-admin-b",
		Payload:        standbyPacket,
		ReceivedAtUnix: time.Now().Unix(),
	})

	time.Sleep(120 * time.Millisecond)

	if written := adapterManager.WrittenPackets(); len(written) != 0 {
		t.Fatalf("expected standby full-tunnel gateway return packet to be dropped, got %#v", written)
	}

	activePacket := buildIPv4Packet(t, "1.1.1.1", ownerPeer.VirtualIP, []byte{5, 6, 7, 8})
	directManager.InjectInbound(ownerPeer.ID, directprobe.Packet{
		RemotePeerID:   "peer-owner-a",
		Payload:        activePacket,
		ReceivedAtUnix: time.Now().Unix(),
	})

	waitForCondition(t, time.Second, func() bool {
		return len(adapterManager.WrittenPackets()) == 1
	})

	written := adapterManager.WrittenPackets()
	if len(written) != 1 || string(written[0]) != string(activePacket) {
		t.Fatalf("expected only active full-tunnel gateway return packet to reach adapter, got %#v", written)
	}
}

func TestAgentKeepsLoopbackAndLinkLocalTrafficOffFullTunnelGateway(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "full-local-special-use-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("local-special-use@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("local-special-use@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create full network: %v", err)
	}
	upstream.OverrideNetworkOwner(network.ID, "usr-owner")
	upstream.AddNetworkMember(network.ID, "usr-1", "MEMBER")
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41041"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeerForUser(network.ID, "peer-owner", "usr-owner", "dev-owner", "10.0.0.3", "127.0.0.1:42041", []string{"127.0.0.1:42041"})

	waitForCondition(t, 2*time.Second, func() bool {
		desired := adapterManager.LastDesired()
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			len(desired) == 1 &&
			desired[0].RoutingPolicy == "FULL" &&
			desired[0].RoutePrefix == "0.0.0.0/0" &&
			desired[0].GatewayPeerID == "peer-owner"
	})

	beforeBlocked := directManager.SentPacketCount()
	adapterManager.EnqueueOutbound(buildIPv4Packet(t, "10.0.0.2", "127.0.0.1", []byte{1, 2, 3, 4}))
	adapterManager.EnqueueOutbound(buildIPv4Packet(t, "10.0.0.2", "169.254.10.20", []byte{5, 6, 7, 8}))
	time.Sleep(100 * time.Millisecond)
	if directManager.SentPacketCount() != beforeBlocked {
		t.Fatalf("expected loopback and link-local traffic to stay off the full-tunnel gateway, got %#v", directManager.SentPacketDetails())
	}

	adapterManager.EnqueueOutbound(buildIPv4Packet(t, "10.0.0.2", "8.8.8.8", []byte{9, 8, 7, 6}))
	waitForCondition(t, time.Second, func() bool {
		return directManager.SentPacketCount() == beforeBlocked+1
	})
	sent := directManager.SentPacketDetails()
	if len(sent) == 0 || sent[len(sent)-1].RemotePeerID != "peer-owner" {
		t.Fatalf("expected ordinary internet traffic to keep using the owner gateway, got %#v", sent)
	}
}

func TestAgentKeepsFullTunnelPendingWithoutEligibleGatewayPeer(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "full-pending-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("member@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("member@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}

	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create full network: %v", err)
	}
	upstream.OverrideNetworkOwner(network.ID, "usr-owner")
	upstream.AddNetworkMember(network.ID, "usr-1", "MEMBER")
	upstream.AddNetworkMember(network.ID, "usr-member", "MEMBER")
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41055"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeerForUser(network.ID, "peer-member", "usr-member", "dev-member", "10.0.0.3", "127.0.0.1:42055", []string{"127.0.0.1:42055"})

	waitForCondition(t, 2*time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED"
	})
	waitForCondition(t, time.Second, func() bool {
		desired := adapterManager.LastDesired()
		return len(desired) == 1 && desired[0].RoutingPolicy == "FULL"
	})

	desired := adapterManager.LastDesired()
	if len(desired) != 1 {
		t.Fatalf("expected one managed full network, got %#v", desired)
	}
	if desired[0].RoutePrefix != "10.0.0.0/24" || desired[0].GatewayRole != "" || desired[0].GatewayPeerID != "" {
		t.Fatalf("expected full network to stay on overlay route without eligible gateway peer, got %#v", desired[0])
	}

	status := agent.Status()
	if len(status.Adapter.Networks) != 1 || status.Adapter.Networks[0].PolicyStatus != "PENDING_GATEWAY" {
		t.Fatalf("expected adapter status to stay pending gateway, got %#v", status.Adapter.Networks)
	}

	internetPacket := buildIPv4Packet(t, "10.0.0.2", "8.8.8.8", []byte{1, 2, 3, 4})
	beforeInternet := directManager.SentPacketCount()
	adapterManager.EnqueueOutbound(internetPacket)
	time.Sleep(100 * time.Millisecond)
	if directManager.SentPacketCount() != beforeInternet {
		t.Fatalf("expected internet-bound packet to stay blocked without eligible gateway peer, got %#v", directManager.SentPackets())
	}

	overlayPacket := buildIPv4Packet(t, "10.0.0.2", "10.0.0.3", []byte{9, 8, 7, 6})
	beforeOverlay := directManager.SentPacketCount()
	adapterManager.EnqueueOutbound(overlayPacket)
	waitForCondition(t, time.Second, func() bool {
		return directManager.SentPacketCount() == beforeOverlay+1
	})
	sent := directManager.SentPackets()
	if len(sent) == 0 || string(sent[len(sent)-1]) != string(overlayPacket) {
		t.Fatalf("expected overlay packet to keep flowing to connected member peer, got %#v", sent)
	}

	bundle := agent.DiagnosticsBundle()
	if bundle.UsageSummary.GatewayCurrent == nil || bundle.UsageSummary.GatewayCurrent.CurrentPolicyStatus != "PENDING_GATEWAY" {
		t.Fatalf("expected diagnostics bundle to keep full network pending until eligible gateway appears, got %#v", bundle.UsageSummary.GatewayCurrent)
	}
}

func TestAgentFailsOverFullTunnelGatewayFromOwnerToAdmin(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "joiner-agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("member@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("member@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create full network: %v", err)
	}
	upstream.OverrideNetworkOwner(network.ID, "usr-owner")
	upstream.AddNetworkMember(network.ID, "usr-owner", "OWNER")
	upstream.AddNetworkMember(network.ID, "usr-admin", "ADMIN")
	upstream.AddNetworkMember(network.ID, "usr-1", "MEMBER")
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41060"); err != nil {
		t.Fatalf("register peer: %v", err)
	}

	upstream.AddRemotePeerForUser(network.ID, "peer-owner", "usr-owner", "dev-owner", "10.0.0.3", "127.0.0.1:42060", []string{"127.0.0.1:42060"})
	upstream.AddRemotePeerForUser(network.ID, "peer-admin", "usr-admin", "dev-admin", "10.0.0.4", "127.0.0.1:42061", []string{"127.0.0.1:42061"})

	waitForCondition(t, 2*time.Second, func() bool {
		desired := adapterManager.LastDesired()
		return len(desired) == 1 &&
			desired[0].RoutingPolicy == "FULL" &&
			desired[0].GatewayRole == "CLIENT" &&
			desired[0].GatewayPeerID == "peer-owner" &&
			desired[0].RoutePrefix == "0.0.0.0/0"
	})

	upstream.SetRemotePeerStatus("peer-owner", "OFFLINE")

	waitForCondition(t, 2*time.Second, func() bool {
		status := agent.Status()
		desired := adapterManager.LastDesired()
		if len(status.Connections) < 2 || len(desired) != 1 {
			return false
		}
		return desired[0].GatewayPeerID == "peer-admin" &&
			desired[0].GatewayRole == "CLIENT" &&
			desired[0].RoutePrefix == "0.0.0.0/0"
	})

	outbound := buildIPv4Packet(t, "10.0.0.2", "1.1.1.1", []byte{4, 5, 6, 7})
	before := directManager.SentPacketCount()
	adapterManager.EnqueueOutbound(outbound)

	waitForCondition(t, time.Second, func() bool {
		return directManager.SentPacketCount() > before
	})

	sent := directManager.SentPackets()
	if len(sent) == 0 || string(sent[len(sent)-1]) != string(outbound) {
		t.Fatalf("expected internet-bound packet to be forwarded through failover gateway connection, got %#v", sent)
	}
	desired := adapterManager.LastDesired()
	if desired[0].GatewayPeerID != "peer-admin" {
		t.Fatalf("expected admin gateway after owner failover, got %#v", desired[0])
	}
	status := agent.Status()
	if len(status.GatewayHistory) == 0 {
		t.Fatalf("expected gateway history after failover")
	}
	foundFailover := false
	for _, event := range status.GatewayHistory {
		if event.NetworkID == network.ID &&
			event.Event == "FAILOVER" &&
			event.PreviousGatewayPeerID == "peer-owner" &&
			event.CurrentGatewayPeerID == "peer-admin" {
			foundFailover = true
			break
		}
	}
	if !foundFailover {
		t.Fatalf("expected failover event in gateway history, got %#v", status.GatewayHistory)
	}
	bundle := agent.DiagnosticsBundle()
	if len(bundle.GatewayHistory) == 0 || bundle.UsageSummary.Gateway == nil {
		t.Fatalf("expected diagnostics bundle to include gateway history, got %#v / %#v", bundle.GatewayHistory, bundle.UsageSummary.Gateway)
	}
	if bundle.UsageSummary.CrossNetwork != nil {
		t.Fatalf("expected cross-network rollup to stay empty for single-network failover bundle, got %#v", bundle.UsageSummary.CrossNetwork)
	}
	if bundle.UsageSummary.Gateway.FailoverCount < 1 {
		t.Fatalf("expected diagnostics bundle to include gateway failover count, got %#v", bundle.UsageSummary.Gateway)
	}
	if len(bundle.Networks) != 1 || len(bundle.Networks[0].GatewayHistory) == 0 || bundle.Networks[0].UsageSummary.Gateway == nil {
		t.Fatalf("expected per-network gateway diagnostics in bundle, got %#v", bundle.Networks)
	}
	if bundle.UsageSummary.GatewayCurrent == nil || bundle.Networks[0].UsageSummary.GatewayCurrent == nil {
		t.Fatalf("expected current gateway rollups in bundle, got %#v / %#v", bundle.UsageSummary.GatewayCurrent, bundle.Networks[0].UsageSummary.GatewayCurrent)
	}
	if bundle.Networks[0].UsageSummary.GatewayCurrent.CurrentGatewayPeerID != "peer-admin" || bundle.Networks[0].UsageSummary.GatewayCurrent.CurrentGatewayRole != "CLIENT" {
		t.Fatalf("expected per-network current gateway to point at admin after failover, got %#v", bundle.Networks[0].UsageSummary.GatewayCurrent)
	}
	if bundle.UsageSummary.Adapter == nil || bundle.Networks[0].UsageSummary.Adapter == nil {
		t.Fatalf("expected adapter rollups in bundle, got %#v / %#v", bundle.UsageSummary.Adapter, bundle.Networks[0].UsageSummary.Adapter)
	}
	if bundle.UsageSummary.Neighbors == nil || bundle.Networks[0].UsageSummary.Neighbors == nil || len(bundle.Networks[0].Neighbors) == 0 {
		t.Fatalf("expected neighbor rollups and raw neighbor snapshots in bundle, got %#v / %#v / %#v", bundle.UsageSummary.Neighbors, bundle.Networks[0].UsageSummary.Neighbors, bundle.Networks[0].Neighbors)
	}
	if bundle.UsageSummary.ConnectionState == nil || bundle.Networks[0].UsageSummary.ConnectionState == nil {
		t.Fatalf("expected connection-state rollups in bundle, got %#v / %#v", bundle.UsageSummary.ConnectionState, bundle.Networks[0].UsageSummary.ConnectionState)
	}
	if bundle.UsageSummary.TransportSessions == nil || bundle.Networks[0].UsageSummary.TransportSessions == nil {
		t.Fatalf("expected transport-session rollups in bundle, got %#v / %#v", bundle.UsageSummary.TransportSessions, bundle.Networks[0].UsageSummary.TransportSessions)
	}
	if bundle.UsageSummary.AdapterNeighbor == nil || bundle.Networks[0].UsageSummary.AdapterNeighbor == nil {
		t.Fatalf("expected adapter-neighbor correlation in bundle, got %#v / %#v", bundle.UsageSummary.AdapterNeighbor, bundle.Networks[0].UsageSummary.AdapterNeighbor)
	}
	if bundle.UsageSummary.Adapter.BindingCount != 1 ||
		bundle.UsageSummary.Adapter.FullBindingCount != 1 ||
		bundle.UsageSummary.Adapter.VisibleIPCount != 1 ||
		bundle.UsageSummary.Adapter.VisibleRouteCount != 1 ||
		bundle.UsageSummary.Adapter.HealthyBindingCount != 1 {
		t.Fatalf("expected aggregate adapter rollup counts in bundle, got %#v", bundle.UsageSummary.Adapter)
	}
	if bundle.Networks[0].UsageSummary.Adapter.BindingCount != 1 ||
		bundle.Networks[0].UsageSummary.Adapter.ActivePolicyCount != 1 ||
		bundle.Networks[0].UsageSummary.Adapter.FullBindingCount != 1 {
		t.Fatalf("expected per-network adapter rollup counts in bundle, got %#v", bundle.Networks[0].UsageSummary.Adapter)
	}
	if bundle.UsageSummary.Neighbors.NeighborCount < 2 ||
		bundle.UsageSummary.Neighbors.OfflineCount < 1 ||
		bundle.UsageSummary.Neighbors.MaxCandidateCount < 1 {
		t.Fatalf("expected aggregate neighbor rollup counts in bundle, got %#v", bundle.UsageSummary.Neighbors)
	}
	if bundle.Networks[0].UsageSummary.Neighbors.NeighborCount < 2 ||
		bundle.Networks[0].UsageSummary.Neighbors.DirectReachabilityCount < 1 ||
		bundle.Networks[0].UsageSummary.Neighbors.PendingCount < 1 {
		t.Fatalf("expected per-network neighbor rollup counts in bundle, got %#v", bundle.Networks[0].UsageSummary.Neighbors)
	}
	if bundle.UsageSummary.AdapterNeighbor.NetworkCount != 1 ||
		bundle.UsageSummary.AdapterNeighbor.HealthyBindingCount != 1 ||
		bundle.UsageSummary.AdapterNeighbor.MostSevereState == "" ||
		bundle.UsageSummary.AdapterNeighbor.AffectedNetworkID != "net-1" {
		t.Fatalf("expected aggregate adapter-neighbor correlation details in bundle, got %#v", bundle.UsageSummary.AdapterNeighbor)
	}
	if bundle.UsageSummary.ConnectionState.ConnectionCount < 2 ||
		bundle.UsageSummary.ConnectionState.DirectPathCount < 1 ||
		bundle.UsageSummary.ConnectionState.MostSevereState == "" ||
		bundle.UsageSummary.ConnectionState.Hint == "" {
		t.Fatalf("expected aggregate connection-state rollup details in bundle, got %#v", bundle.UsageSummary.ConnectionState)
	}
	if bundle.UsageSummary.TransportSessions.SessionCount < 1 ||
		bundle.UsageSummary.TransportSessions.RekeyScheduledCount < 1 ||
		bundle.UsageSummary.TransportSessions.MostSevereState == "" ||
		bundle.UsageSummary.TransportSessions.Hint == "" {
		t.Fatalf("expected aggregate transport-session rollup details in bundle, got %#v", bundle.UsageSummary.TransportSessions)
	}
	if bundle.Networks[0].UsageSummary.AdapterNeighbor.NetworkCount != 1 ||
		bundle.Networks[0].UsageSummary.AdapterNeighbor.HealthyBindingCount != 1 ||
		bundle.Networks[0].UsageSummary.AdapterNeighbor.MostSevereState == "" ||
		bundle.Networks[0].UsageSummary.AdapterNeighbor.Hint == "" {
		t.Fatalf("expected per-network adapter-neighbor correlation details in bundle, got %#v", bundle.Networks[0].UsageSummary.AdapterNeighbor)
	}
	if bundle.Networks[0].UsageSummary.ConnectionState.ConnectionCount < 2 ||
		bundle.Networks[0].UsageSummary.ConnectionState.TunnelOpenCount < 1 ||
		bundle.Networks[0].UsageSummary.ConnectionState.MostSevereState == "" ||
		bundle.Networks[0].UsageSummary.ConnectionState.Hint == "" {
		t.Fatalf("expected per-network connection-state rollup details in bundle, got %#v", bundle.Networks[0].UsageSummary.ConnectionState)
	}
	if bundle.Networks[0].UsageSummary.TransportSessions.SessionCount < 1 ||
		bundle.Networks[0].UsageSummary.TransportSessions.RekeyScheduledCount < 1 ||
		bundle.Networks[0].UsageSummary.TransportSessions.OldestSessionUnix == 0 ||
		bundle.Networks[0].UsageSummary.TransportSessions.NextRekeyUnix == 0 {
		t.Fatalf("expected per-network transport-session rollup details in bundle, got %#v", bundle.Networks[0].UsageSummary.TransportSessions)
	}
}

func TestAgentRecordsFailoverBetweenDistinctGatewayDevicesOfSameAdminUser(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "same-admin-gateway-failover-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("member-same-admin-full@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("member-same-admin-full@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("same-admin-full", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create full network: %v", err)
	}
	upstream.OverrideNetworkOwner(network.ID, "usr-owner")
	upstream.AddNetworkMember(network.ID, "usr-admin", "ADMIN")
	upstream.AddNetworkMember(network.ID, "usr-1", "MEMBER")
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41310"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeerForUser(network.ID, "peer-admin-a", "usr-admin", "dev-admin-a", "10.30.0.3", "127.0.0.1:42310", []string{"127.0.0.1:42310"})

	waitForCondition(t, 2*time.Second, func() bool {
		desired := adapterManager.LastDesired()
		return len(desired) == 1 &&
			desired[0].RoutingPolicy == "FULL" &&
			desired[0].GatewayRole == "CLIENT" &&
			desired[0].GatewayPeerID == "peer-admin-a" &&
			desired[0].RoutePrefix == "0.0.0.0/0"
	})

	upstream.AddRemotePeerForUser(network.ID, "peer-admin-b", "usr-admin", "dev-admin-b", "10.30.0.4", "127.0.0.1:42311", []string{"127.0.0.1:42311"})

	waitForCondition(t, 2*time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) >= 2
	})

	upstream.SetRemotePeerStatus("peer-admin-a", "OFFLINE")

	waitForCondition(t, 2*time.Second, func() bool {
		desired := adapterManager.LastDesired()
		return len(desired) == 1 &&
			desired[0].GatewayPeerID == "peer-admin-b" &&
			desired[0].RoutePrefix == "0.0.0.0/0"
	})

	status := agent.Status()
	foundFailover := false
	for _, event := range status.GatewayHistory {
		if event.NetworkID == network.ID &&
			event.Event == "FAILOVER" &&
			event.PreviousGatewayPeerID == "peer-admin-a" &&
			event.CurrentGatewayPeerID == "peer-admin-b" {
			foundFailover = true
			break
		}
	}
	if !foundFailover {
		t.Fatalf("expected gateway history to record failover between distinct admin devices of the same user, got %#v", status.GatewayHistory)
	}

	bundle := agent.DiagnosticsBundle()
	if bundle.UsageSummary.Gateway == nil || bundle.UsageSummary.Gateway.FailoverCount < 1 {
		t.Fatalf("expected aggregate diagnostics bundle to count same-user device failover, got %#v", bundle.UsageSummary.Gateway)
	}
	if len(bundle.Networks) != 1 || bundle.Networks[0].UsageSummary.Gateway == nil || bundle.Networks[0].UsageSummary.Gateway.FailoverCount < 1 {
		t.Fatalf("expected per-network diagnostics bundle to count same-user device failover, got %#v", bundle.Networks)
	}
	if bundle.Networks[0].UsageSummary.GatewayCurrent == nil || bundle.Networks[0].UsageSummary.GatewayCurrent.CurrentGatewayPeerID != "peer-admin-b" {
		t.Fatalf("expected current gateway diagnostics to point at replacement admin device, got %#v", bundle.Networks[0].UsageSummary.GatewayCurrent)
	}
}

func TestAgentFailsBackFullTunnelGatewayFromAdminToOwnerWhenOwnerRecovers(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "joiner-agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("member@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("member@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create full network: %v", err)
	}
	upstream.OverrideNetworkOwner(network.ID, "usr-owner")
	upstream.AddNetworkMember(network.ID, "usr-owner", "OWNER")
	upstream.AddNetworkMember(network.ID, "usr-admin", "ADMIN")
	upstream.AddNetworkMember(network.ID, "usr-1", "MEMBER")
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41060"); err != nil {
		t.Fatalf("register peer: %v", err)
	}

	upstream.AddRemotePeerForUser(network.ID, "peer-owner", "usr-owner", "dev-owner", "10.0.0.3", "127.0.0.1:42060", []string{"127.0.0.1:42060"})
	upstream.AddRemotePeerForUser(network.ID, "peer-admin", "usr-admin", "dev-admin", "10.0.0.4", "127.0.0.1:42061", []string{"127.0.0.1:42061"})

	waitForCondition(t, 2*time.Second, func() bool {
		desired := adapterManager.LastDesired()
		return len(desired) == 1 &&
			desired[0].RoutingPolicy == "FULL" &&
			desired[0].GatewayRole == "CLIENT" &&
			desired[0].GatewayPeerID == "peer-owner" &&
			desired[0].RoutePrefix == "0.0.0.0/0"
	})

	upstream.SetRemotePeerStatus("peer-owner", "OFFLINE")

	waitForCondition(t, 2*time.Second, func() bool {
		desired := adapterManager.LastDesired()
		return len(desired) == 1 &&
			desired[0].GatewayPeerID == "peer-admin" &&
			desired[0].GatewayRole == "CLIENT" &&
			desired[0].RoutePrefix == "0.0.0.0/0"
	})

	upstream.SetRemotePeerStatus("peer-owner", "ONLINE")

	waitForCondition(t, 2*time.Second, func() bool {
		desired := adapterManager.LastDesired()
		return len(desired) == 1 &&
			desired[0].GatewayPeerID == "peer-owner" &&
			desired[0].GatewayRole == "CLIENT" &&
			desired[0].RoutePrefix == "0.0.0.0/0"
	})

	outbound := buildIPv4Packet(t, "10.0.0.2", "1.1.1.1", []byte{8, 7, 6, 5})
	before := directManager.SentPacketCount()
	adapterManager.EnqueueOutbound(outbound)

	waitForCondition(t, time.Second, func() bool {
		return directManager.SentPacketCount() > before
	})

	sent := directManager.SentPacketDetails()
	if len(sent) == 0 {
		t.Fatalf("expected internet-bound packet to be forwarded through recovered owner gateway")
	}
	lastSent := sent[len(sent)-1]
	if lastSent.RemotePeerID != "peer-owner" || string(lastSent.Payload) != string(outbound) {
		t.Fatalf("expected internet-bound packet to route through recovered owner gateway, got %#v", lastSent)
	}

	status := agent.Status()
	foundFailover := false
	foundFailback := false
	for _, event := range status.GatewayHistory {
		if event.NetworkID != network.ID {
			continue
		}
		if event.Event == "FAILOVER" && event.PreviousGatewayPeerID == "peer-owner" && event.CurrentGatewayPeerID == "peer-admin" {
			foundFailover = true
		}
		if event.Event == "FAILBACK" && event.PreviousGatewayPeerID == "peer-admin" && event.CurrentGatewayPeerID == "peer-owner" {
			foundFailback = true
		}
	}
	if !foundFailover || !foundFailback {
		t.Fatalf("expected gateway history to record owner failover and failback, got %#v", status.GatewayHistory)
	}

	bundle := agent.DiagnosticsBundle()
	if bundle.UsageSummary.Gateway == nil || bundle.UsageSummary.Gateway.FailoverCount < 1 || bundle.UsageSummary.Gateway.FailbackCount < 1 {
		t.Fatalf("expected diagnostics bundle to include owner failover and failback counts, got %#v", bundle.UsageSummary.Gateway)
	}
	if bundle.UsageSummary.GatewayCurrent == nil || bundle.UsageSummary.GatewayCurrent.CurrentGatewayPeerID != "peer-owner" {
		t.Fatalf("expected diagnostics current gateway to return to owner after recovery, got %#v", bundle.UsageSummary.GatewayCurrent)
	}
}

func TestAgentKeepsOnlyPreferredFullTunnelClientNetworkOnDefaultRoute(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "multi-full-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("member-multi-full@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("member-multi-full@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}

	ownerPreferred, err := agent.CreateNetworkWithOptions("owner-full", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create owner-full network: %v", err)
	}
	upstream.OverrideNetworkOwner(ownerPreferred.ID, "usr-owner-a")
	upstream.AddNetworkMember(ownerPreferred.ID, "usr-1", "MEMBER")
	upstream.localPeerCIDR = "10.10.0.0/24"
	if _, err := agent.RegisterPeer(ownerPreferred.ID, "127.0.0.1:41110"); err != nil {
		t.Fatalf("register owner-full peer: %v", err)
	}
	upstream.AddRemotePeerForUser(ownerPreferred.ID, "peer-owner-a", "usr-owner-a", "dev-owner-a", "10.10.0.3", "127.0.0.1:42110", []string{"127.0.0.1:42110"})

	adminStandby, err := agent.CreateNetworkWithOptions("admin-full", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create admin-full network: %v", err)
	}
	upstream.OverrideNetworkOwner(adminStandby.ID, "usr-owner-b")
	upstream.AddNetworkMember(adminStandby.ID, "usr-admin-b", "ADMIN")
	upstream.AddNetworkMember(adminStandby.ID, "usr-1", "MEMBER")
	upstream.localPeerCIDR = "10.20.0.0/24"
	if _, err := agent.RegisterPeer(adminStandby.ID, "127.0.0.1:41120"); err != nil {
		t.Fatalf("register admin-full peer: %v", err)
	}
	upstream.AddRemotePeerForUser(adminStandby.ID, "peer-admin-b", "usr-admin-b", "dev-admin-b", "10.20.0.3", "127.0.0.1:42120", []string{"127.0.0.1:42120"})

	deadline := time.Now().Add(2 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		status := agent.Status()
		desired := adapterManager.LastDesired()
		if len(status.Connections) >= 2 && len(desired) == 2 {
			var active, standby *virtualadapter.NetworkConfig
			for idx := range desired {
				switch desired[idx].NetworkID {
				case ownerPreferred.ID:
					active = &desired[idx]
				case adminStandby.ID:
					standby = &desired[idx]
				}
			}
			ready = active != nil &&
				standby != nil &&
				active.RoutePrefix == "0.0.0.0/0" &&
				active.GatewayRole == "CLIENT" &&
				active.GatewayPeerID == "peer-owner-a" &&
				strings.TrimSpace(active.PolicyStatusHint) == "" &&
				standby.RoutePrefix == "10.20.0.0/24" &&
				standby.GatewayRole == "CLIENT" &&
				standby.GatewayPeerID == "peer-admin-b" &&
				standby.PolicyStatusHint == "STANDBY_GATEWAY"
			if ready {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("expected one active and one standby full-tunnel network, got status=%#v desired=%#v", agent.Status(), adapterManager.LastDesired())
	}

	status := agent.Status()
	if len(status.Adapter.Networks) != 2 {
		t.Fatalf("expected both full networks in adapter status, got %#v", status.Adapter.Networks)
	}
	var activeBinding, standbyBinding *virtualadapter.NetworkBinding
	for idx := range status.Adapter.Networks {
		switch status.Adapter.Networks[idx].NetworkID {
		case ownerPreferred.ID:
			activeBinding = &status.Adapter.Networks[idx]
		case adminStandby.ID:
			standbyBinding = &status.Adapter.Networks[idx]
		}
	}
	if activeBinding == nil || activeBinding.PolicyStatus != "ACTIVE" || activeBinding.RoutePrefix != "0.0.0.0/0" {
		t.Fatalf("expected owner-backed full network to own default route, got %#v", activeBinding)
	}
	if standbyBinding == nil || standbyBinding.PolicyStatus != "STANDBY_GATEWAY" || standbyBinding.RoutePrefix != "10.20.0.0/24" {
		t.Fatalf("expected admin-backed full network to stay on standby, got %#v", standbyBinding)
	}

	bundle := agent.DiagnosticsBundle()
	if bundle.UsageSummary.GatewayCurrent == nil {
		t.Fatalf("expected gateway-current rollup for multi-full diagnostics bundle")
	}
	if bundle.UsageSummary.GatewayCurrent.CurrentNetworkID != ownerPreferred.ID || bundle.UsageSummary.GatewayCurrent.CurrentPolicyStatus != "ACTIVE" {
		t.Fatalf("expected diagnostics to prefer active full network, got %#v", bundle.UsageSummary.GatewayCurrent)
	}
	if len(bundle.Networks) != 2 {
		t.Fatalf("expected per-network diagnostics for both full networks, got %#v", bundle.Networks)
	}
	foundStandby := false
	for _, network := range bundle.Networks {
		if network.Network.ID == adminStandby.ID &&
			network.UsageSummary.GatewayCurrent != nil &&
			network.UsageSummary.GatewayCurrent.CurrentPolicyStatus == "STANDBY_GATEWAY" {
			foundStandby = true
			break
		}
	}
	if !foundStandby {
		t.Fatalf("expected per-network diagnostics to surface standby full network, got %#v", bundle.Networks)
	}

	beforeActiveInternet := directManager.SentPacketCount()
	adapterManager.EnqueueOutbound(buildIPv4Packet(t, "10.0.0.2", "8.8.8.8", []byte{5, 6, 7, 8}))
	deadline = time.Now().Add(2 * time.Second)
	activeRouted := false
	for time.Now().Before(deadline) {
		if directManager.SentPacketCount() == beforeActiveInternet+1 {
			activeRouted = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !activeRouted {
		t.Fatalf("expected active FULL network to route internet packet, got sent=%#v status=%#v desired=%#v", directManager.SentPacketDetails(), agent.Status(), adapterManager.LastDesired())
	}
	activeSent := directManager.SentPacketDetails()
	if len(activeSent) == 0 || activeSent[len(activeSent)-1].RemotePeerID != "peer-owner-a" {
		t.Fatalf("expected active FULL network to route internet packet through owner-backed gateway, got %#v", activeSent)
	}

	beforeStandbyOverlay := directManager.SentPacketCount()
	adapterManager.EnqueueOutbound(buildIPv4Packet(t, "10.0.0.2", "10.20.0.3", []byte{9, 8, 7, 6}))
	deadline = time.Now().Add(2 * time.Second)
	standbyOverlayRouted := false
	for time.Now().Before(deadline) {
		if directManager.SentPacketCount() == beforeStandbyOverlay+1 {
			standbyOverlayRouted = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !standbyOverlayRouted {
		t.Fatalf("expected standby FULL network to keep routing overlay packets, got sent=%#v status=%#v desired=%#v", directManager.SentPacketDetails(), agent.Status(), adapterManager.LastDesired())
	}
	standbySent := directManager.SentPacketDetails()
	if len(standbySent) == 0 || standbySent[len(standbySent)-1].RemotePeerID != "peer-admin-b" {
		t.Fatalf("expected standby FULL network to keep routing overlay packets to its own peer, got %#v", standbySent)
	}
}

func TestAgentRecordsFullTunnelStandbyPromotionAndDemotionAcrossNetworks(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "multi-full-promotion-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("member-multi-full-history@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("member-multi-full-history@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}

	ownerPreferred, err := agent.CreateNetworkWithOptions("owner-full-history", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create owner-full network: %v", err)
	}
	upstream.OverrideNetworkOwner(ownerPreferred.ID, "usr-owner-a")
	upstream.AddNetworkMember(ownerPreferred.ID, "usr-1", "MEMBER")
	upstream.localPeerCIDR = "10.10.0.0/24"
	if _, err := agent.RegisterPeer(ownerPreferred.ID, "127.0.0.1:41210"); err != nil {
		t.Fatalf("register owner-full peer: %v", err)
	}
	upstream.AddRemotePeerForUser(ownerPreferred.ID, "peer-owner-a", "usr-owner-a", "dev-owner-a", "10.10.0.3", "127.0.0.1:42210", []string{"127.0.0.1:42210"})

	adminStandby, err := agent.CreateNetworkWithOptions("admin-full-history", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy: "FULL",
	})
	if err != nil {
		t.Fatalf("create admin-full network: %v", err)
	}
	upstream.OverrideNetworkOwner(adminStandby.ID, "usr-owner-b")
	upstream.AddNetworkMember(adminStandby.ID, "usr-admin-b", "ADMIN")
	upstream.AddNetworkMember(adminStandby.ID, "usr-1", "MEMBER")
	upstream.localPeerCIDR = "10.20.0.0/24"
	if _, err := agent.RegisterPeer(adminStandby.ID, "127.0.0.1:41220"); err != nil {
		t.Fatalf("register admin-full peer: %v", err)
	}
	upstream.AddRemotePeerForUser(adminStandby.ID, "peer-admin-b", "usr-admin-b", "dev-admin-b", "10.20.0.3", "127.0.0.1:42220", []string{"127.0.0.1:42220"})

	waitForCondition(t, 2*time.Second, func() bool {
		status := agent.Status()
		if len(status.Adapter.Networks) != 2 {
			return false
		}
		var ownerBinding, adminBinding *virtualadapter.NetworkBinding
		for idx := range status.Adapter.Networks {
			switch status.Adapter.Networks[idx].NetworkID {
			case ownerPreferred.ID:
				ownerBinding = &status.Adapter.Networks[idx]
			case adminStandby.ID:
				adminBinding = &status.Adapter.Networks[idx]
			}
		}
		return ownerBinding != nil &&
			adminBinding != nil &&
			ownerBinding.PolicyStatus == "ACTIVE" &&
			ownerBinding.RoutePrefix == "0.0.0.0/0" &&
			adminBinding.PolicyStatus == "STANDBY_GATEWAY" &&
			adminBinding.RoutePrefix == "10.20.0.0/24"
	})

	upstream.SetRemotePeerStatus("peer-owner-a", "OFFLINE")

	waitForCondition(t, 2*time.Second, func() bool {
		status := agent.Status()
		if len(status.Adapter.Networks) != 2 {
			return false
		}
		var ownerBinding, adminBinding *virtualadapter.NetworkBinding
		for idx := range status.Adapter.Networks {
			switch status.Adapter.Networks[idx].NetworkID {
			case ownerPreferred.ID:
				ownerBinding = &status.Adapter.Networks[idx]
			case adminStandby.ID:
				adminBinding = &status.Adapter.Networks[idx]
			}
		}
		return ownerBinding != nil &&
			adminBinding != nil &&
			ownerBinding.PolicyStatus == "PENDING_GATEWAY" &&
			ownerBinding.RoutePrefix == "10.10.0.0/24" &&
			adminBinding.PolicyStatus == "ACTIVE" &&
			adminBinding.RoutePrefix == "0.0.0.0/0"
	})

	upstream.SetRemotePeerStatus("peer-owner-a", "ONLINE")

	waitForCondition(t, 2*time.Second, func() bool {
		status := agent.Status()
		if len(status.Adapter.Networks) != 2 {
			return false
		}
		var ownerBinding, adminBinding *virtualadapter.NetworkBinding
		for idx := range status.Adapter.Networks {
			switch status.Adapter.Networks[idx].NetworkID {
			case ownerPreferred.ID:
				ownerBinding = &status.Adapter.Networks[idx]
			case adminStandby.ID:
				adminBinding = &status.Adapter.Networks[idx]
			}
		}
		return ownerBinding != nil &&
			adminBinding != nil &&
			ownerBinding.PolicyStatus == "ACTIVE" &&
			ownerBinding.RoutePrefix == "0.0.0.0/0" &&
			adminBinding.PolicyStatus == "STANDBY_GATEWAY" &&
			adminBinding.RoutePrefix == "10.20.0.0/24"
	})

	status := agent.Status()
	foundPromoted := false
	foundDemoted := false
	for _, event := range status.GatewayHistory {
		if event.NetworkID != adminStandby.ID {
			continue
		}
		if event.Event == "PROMOTED" &&
			event.PreviousGatewayPeerID == "peer-admin-b" &&
			event.CurrentGatewayPeerID == "peer-admin-b" &&
			event.PreviousPolicyStatus == "STANDBY_GATEWAY" &&
			event.CurrentPolicyStatus == "ACTIVE" {
			foundPromoted = true
		}
		if event.Event == "DEMOTED" &&
			event.PreviousGatewayPeerID == "peer-admin-b" &&
			event.CurrentGatewayPeerID == "peer-admin-b" &&
			event.PreviousPolicyStatus == "ACTIVE" &&
			event.CurrentPolicyStatus == "STANDBY_GATEWAY" {
			foundDemoted = true
		}
	}
	if !foundPromoted || !foundDemoted {
		t.Fatalf("expected standby network history to record promotion and demotion, got %#v", status.GatewayHistory)
	}

	bundle := agent.DiagnosticsBundle()
	if bundle.UsageSummary.Gateway == nil || bundle.UsageSummary.Gateway.PromotedCount < 1 || bundle.UsageSummary.Gateway.DemotedCount < 1 {
		t.Fatalf("expected aggregate diagnostics bundle to count promotion and demotion, got %#v", bundle.UsageSummary.Gateway)
	}
	for _, network := range bundle.Networks {
		if network.Network.ID != adminStandby.ID {
			continue
		}
		if network.UsageSummary.Gateway == nil || network.UsageSummary.Gateway.PromotedCount < 1 || network.UsageSummary.Gateway.DemotedCount < 1 {
			t.Fatalf("expected standby network diagnostics to count promotion and demotion, got %#v", network.UsageSummary.Gateway)
		}
		if network.UsageSummary.GatewayCurrent == nil || network.UsageSummary.GatewayCurrent.CurrentPolicyStatus != "STANDBY_GATEWAY" {
			t.Fatalf("expected standby network diagnostics to end back on standby, got %#v", network.UsageSummary.GatewayCurrent)
		}
		return
	}
	t.Fatalf("expected diagnostics bundle to include standby network details, got %#v", bundle.Networks)
}

func TestAgentBlocksBroadcastAndMulticastWhenGroupTrafficPolicyIsBlocked(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "group-blocked-agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("blocked-owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("blocked-owner@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		GroupTrafficPolicy: "BLOCKED",
	})
	if err != nil {
		t.Fatalf("create blocked group-traffic network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41050"); err != nil {
		t.Fatalf("register peer: %v", err)
	}

	upstream.AddRemotePeer(network.ID, "peer-remote-a", "10.0.0.3", "127.0.0.1:42050", []string{"127.0.0.1:42050"})
	upstream.AddRemotePeer(network.ID, "peer-remote-b", "10.0.0.4", "127.0.0.1:42051", []string{"127.0.0.1:42051"})

	waitForCondition(t, 2*time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 2 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[1].State == "CONNECTED"
	})

	adapterManager.EnqueueOutbound(buildIPv4Packet(t, "10.0.0.2", "224.0.0.251", []byte{1, 2, 3, 4}))
	time.Sleep(100 * time.Millisecond)

	if sent := directManager.SentPackets(); len(sent) != 0 {
		t.Fatalf("expected multicast packet to be blocked when group traffic policy is blocked, got %#v", sent)
	}
	status := agent.Status()
	if len(status.GroupTraffic) != 1 || status.GroupTraffic[0].BlockedPacketCount != 1 || status.GroupTraffic[0].MulticastPacketCount != 1 || status.GroupTraffic[0].LastAction != "BLOCKED" {
		t.Fatalf("expected blocked group traffic diagnostics, got %#v", status.GroupTraffic)
	}
}

func TestAgentFloodsBroadcastPacketsToConnectedPeersWhenGroupTrafficPolicyIsFlood(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "group-flood-agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("flood-owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("flood-owner@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		GroupTrafficPolicy: "FLOOD",
	})
	if err != nil {
		t.Fatalf("create flood group-traffic network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41052"); err != nil {
		t.Fatalf("register peer: %v", err)
	}

	upstream.AddRemotePeer(network.ID, "peer-remote-a", "10.0.0.3", "127.0.0.1:42052", []string{"127.0.0.1:42052"})
	upstream.AddRemotePeer(network.ID, "peer-remote-b", "10.0.0.4", "127.0.0.1:42053", []string{"127.0.0.1:42053"})

	waitForCondition(t, 2*time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 2 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[1].State == "CONNECTED"
	})

	packet := buildIPv4Packet(t, "10.0.0.2", "10.0.0.255", []byte{9, 8, 7, 6})
	adapterManager.EnqueueOutbound(packet)

	waitForCondition(t, time.Second, func() bool {
		return directManager.SentPacketCount() >= 2
	})

	sent := directManager.SentPackets()
	if len(sent) != 2 {
		t.Fatalf("expected broadcast packet to be fanned out to both connected peers, got %#v", sent)
	}
	for idx, candidate := range sent {
		if string(candidate) != string(packet) {
			t.Fatalf("expected flooded packet copy %d to match original payload", idx)
		}
	}
	status := agent.Status()
	if len(status.GroupTraffic) != 1 || status.GroupTraffic[0].FloodPacketCount != 1 || status.GroupTraffic[0].FanoutCopyCount != 2 || status.GroupTraffic[0].BroadcastPacketCount != 1 || status.GroupTraffic[0].LastAction != "FLOOD" {
		t.Fatalf("expected flood group traffic diagnostics, got %#v", status.GroupTraffic)
	}
	if len(status.Connections) != 2 {
		t.Fatalf("expected two connections for flood diagnostics, got %#v", status.Connections)
	}
	for _, connection := range status.Connections {
		if connection.GroupTrafficPacketCopies != 1 || connection.GroupBroadcastCopies != 1 || connection.LastGroupTrafficUnix == 0 {
			t.Fatalf("expected per-connection group traffic counters after flood, got %#v", connection)
		}
	}
}

func TestAgentDropsInboundMulticastWhenGroupTrafficPolicyIsBlocked(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "group-inbound-blocked-agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("blocked-inbound-owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("blocked-inbound-owner@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		GroupTrafficPolicy: "BLOCKED",
	})
	if err != nil {
		t.Fatalf("create blocked inbound group-traffic network: %v", err)
	}
	localPeer, err := agent.RegisterPeer(network.ID, "127.0.0.1:41054")
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}

	upstream.AddRemotePeer(network.ID, "peer-remote-a", "10.0.0.3", "127.0.0.1:42054", []string{"127.0.0.1:42054"})

	waitForCondition(t, 2*time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED"
	})

	packet := buildIPv4Packet(t, "10.0.0.3", "224.0.0.251", []byte{1, 2, 3, 4})
	directManager.InjectInbound(localPeer.ID, directprobe.Packet{
		RemotePeerID:   "peer-remote-a",
		Payload:        packet,
		ReceivedAtUnix: time.Now().Unix(),
	})

	time.Sleep(120 * time.Millisecond)

	if written := adapterManager.WrittenPackets(); len(written) != 0 {
		t.Fatalf("expected inbound multicast packet to be dropped when group traffic policy is blocked, got %#v", written)
	}
	status := agent.Status()
	if len(status.GroupTraffic) != 1 || status.GroupTraffic[0].Policy != "BLOCKED" || status.GroupTraffic[0].BlockedPacketCount != 1 || status.GroupTraffic[0].MulticastPacketCount != 1 || status.GroupTraffic[0].LastAction != "BLOCKED" {
		t.Fatalf("expected blocked inbound group traffic diagnostics, got %#v", status.GroupTraffic)
	}
}

func TestAgentAcceptsInboundBroadcastWhenGroupTrafficPolicyIsFlood(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "group-inbound-flood-agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("flood-inbound-owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("flood-inbound-owner@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		GroupTrafficPolicy: "FLOOD",
	})
	if err != nil {
		t.Fatalf("create flood inbound group-traffic network: %v", err)
	}
	localPeer, err := agent.RegisterPeer(network.ID, "127.0.0.1:41055")
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}

	upstream.AddRemotePeer(network.ID, "peer-remote-a", "10.0.0.3", "127.0.0.1:42055", []string{"127.0.0.1:42055"})

	waitForCondition(t, 2*time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED"
	})

	packet := buildIPv4Packet(t, "10.0.0.3", "10.0.0.255", []byte{9, 8, 7, 6})
	directManager.InjectInbound(localPeer.ID, directprobe.Packet{
		RemotePeerID:   "peer-remote-a",
		Payload:        packet,
		ReceivedAtUnix: time.Now().Unix(),
	})

	waitForCondition(t, time.Second, func() bool {
		return len(adapterManager.WrittenPackets()) == 1
	})

	written := adapterManager.WrittenPackets()
	if len(written) != 1 || string(written[0]) != string(packet) {
		t.Fatalf("expected inbound broadcast packet to reach adapter when group traffic policy is flood, got %#v", written)
	}
	status := agent.Status()
	if len(status.GroupTraffic) != 0 {
		t.Fatalf("expected inbound flood packet not to be classified as blocked traffic, got %#v", status.GroupTraffic)
	}
}

func TestAgentDropsInboundPacketWithSpoofedOverlaySourceIP(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "spoofed-inbound-source-agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("spoofed-inbound-owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("spoofed-inbound-owner@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	localPeer, err := agent.RegisterPeer(network.ID, "127.0.0.1:41056")
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}

	upstream.AddRemotePeer(network.ID, "peer-remote-a", "10.0.0.3", "127.0.0.1:42056", []string{"127.0.0.1:42056"})

	waitForCondition(t, 2*time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED"
	})

	packet := buildIPv4Packet(t, "10.0.0.4", localPeer.VirtualIP, []byte{4, 3, 2, 1})
	directManager.InjectInbound(localPeer.ID, directprobe.Packet{
		RemotePeerID:   "peer-remote-a",
		Payload:        packet,
		ReceivedAtUnix: time.Now().Unix(),
	})

	time.Sleep(120 * time.Millisecond)

	if written := adapterManager.WrittenPackets(); len(written) != 0 {
		t.Fatalf("expected inbound packet with spoofed overlay source IP to be dropped, got %#v", written)
	}
}

func TestAgentBlocksFullTunnelGatewayFromCarryingBlockedGroupTraffic(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "full-group-blocked-agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("full-blocked-member@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("full-blocked-member@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy:      "FULL",
		GroupTrafficPolicy: "BLOCKED",
	})
	if err != nil {
		t.Fatalf("create full blocked network: %v", err)
	}
	upstream.OverrideNetworkOwner(network.ID, "usr-owner")
	upstream.AddNetworkMember(network.ID, "usr-1", "MEMBER")
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41070"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeerForUser(network.ID, "peer-owner", "usr-owner", "dev-owner", "10.0.0.3", "127.0.0.1:42070", []string{"127.0.0.1:42070"})

	waitForCondition(t, 2*time.Second, func() bool {
		desired := adapterManager.LastDesired()
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			len(desired) == 1 &&
			desired[0].RoutingPolicy == "FULL" &&
			desired[0].RoutePrefix == "0.0.0.0/0" &&
			desired[0].GatewayPeerID == "peer-owner"
	})

	packet := buildIPv4Packet(t, "10.0.0.2", "224.0.0.251", []byte{1, 2, 3, 4})
	adapterManager.EnqueueOutbound(packet)
	time.Sleep(100 * time.Millisecond)

	if sent := directManager.SentPacketDetails(); len(sent) != 0 {
		t.Fatalf("expected blocked multicast to stay off the full-tunnel gateway path, got %#v", sent)
	}
	status := agent.Status()
	if len(status.GroupTraffic) != 1 || status.GroupTraffic[0].Policy != "BLOCKED" || status.GroupTraffic[0].BlockedPacketCount != 1 || status.GroupTraffic[0].MulticastPacketCount != 1 || status.GroupTraffic[0].LastAction != "BLOCKED" {
		t.Fatalf("expected blocked group traffic diagnostics for full-tunnel network, got %#v", status.GroupTraffic)
	}
}

func TestAgentFloodsFullTunnelBroadcastAcrossPeersInsteadOfSingleGatewayPath(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "full-group-flood-agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     time.Hour,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     time.Second,
		DirectRetryMax:      time.Second,
		DirectMaxAttempts:   1,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("full-flood-member@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("full-flood-member@example.com", "secret"); err != nil {
		t.Fatalf("login user: %v", err)
	}
	network, err := agent.CreateNetworkWithOptions("friends", "INVITE_ONLY", controlclient.NetworkCreateOptions{
		RoutingPolicy:      "FULL",
		GroupTrafficPolicy: "FLOOD",
	})
	if err != nil {
		t.Fatalf("create full flood network: %v", err)
	}
	upstream.OverrideNetworkOwner(network.ID, "usr-owner")
	upstream.AddNetworkMember(network.ID, "usr-owner", "OWNER")
	upstream.AddNetworkMember(network.ID, "usr-member", "MEMBER")
	upstream.AddNetworkMember(network.ID, "usr-1", "MEMBER")
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41071"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeerForUser(network.ID, "peer-owner", "usr-owner", "dev-owner", "10.0.0.3", "127.0.0.1:42071", []string{"127.0.0.1:42071"})
	upstream.AddRemotePeerForUser(network.ID, "peer-member", "usr-member", "dev-member", "10.0.0.4", "127.0.0.1:42072", []string{"127.0.0.1:42072"})

	waitForCondition(t, 2*time.Second, func() bool {
		desired := adapterManager.LastDesired()
		status := agent.Status()
		return len(status.Connections) == 2 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[1].State == "CONNECTED" &&
			len(desired) == 1 &&
			desired[0].RoutingPolicy == "FULL" &&
			desired[0].RoutePrefix == "0.0.0.0/0" &&
			desired[0].GatewayPeerID == "peer-owner"
	})

	packet := buildIPv4Packet(t, "10.0.0.2", "10.0.0.255", []byte{9, 8, 7, 6})
	adapterManager.EnqueueOutbound(packet)

	waitForCondition(t, time.Second, func() bool {
		return directManager.SentPacketCount() >= 2
	})

	sent := directManager.SentPacketDetails()
	if len(sent) != 2 {
		t.Fatalf("expected flooded full-tunnel broadcast to fan out to both peers, got %#v", sent)
	}
	seen := map[string]bool{}
	for _, candidate := range sent {
		if string(candidate.Payload) != string(packet) {
			t.Fatalf("expected flooded full-tunnel payload to stay unchanged, got %#v", sent)
		}
		seen[candidate.RemotePeerID] = true
	}
	if !seen["peer-owner"] || !seen["peer-member"] {
		t.Fatalf("expected flooded full-tunnel broadcast to reach both owner and member peers, got %#v", sent)
	}
	status := agent.Status()
	if len(status.GroupTraffic) != 1 || status.GroupTraffic[0].Policy != "FLOOD" || status.GroupTraffic[0].FloodPacketCount != 1 || status.GroupTraffic[0].FanoutCopyCount != 2 || status.GroupTraffic[0].BroadcastPacketCount != 1 || status.GroupTraffic[0].LastAction != "FLOOD" {
		t.Fatalf("expected flood group traffic diagnostics for full-tunnel network, got %#v", status.GroupTraffic)
	}
}

func TestAgentUsesManagedPeerOverlayCIDRForAdapterRoutes(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.localPeerCIDR = "10.42.7.0/28"
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	adapterManager := &fakeAdapterManager{}
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: time.Hour,
		STUNProbePeriod:     time.Hour,
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, runtime, adapterManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, reserveUDPBindEndpoint(t)); err != nil {
		t.Fatalf("register peer: %v", err)
	}

	waitForCondition(t, time.Second, func() bool {
		desired := adapterManager.LastDesired()
		return len(desired) == 1 && desired[0].RoutePrefix == "10.42.7.0/28" && desired[0].PrefixLength == 28
	})
}

func TestAgentPublishesServerReflexiveCandidateFromSTUN(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stunServer, err := newScriptedSTUNServer("127.0.0.1:0", "203.0.113.10:54000")
	if err != nil {
		t.Fatalf("listen stun server: %v", err)
	}
	defer stunServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     10 * time.Millisecond,
		STUNServerAddress:   stunServer.LocalAddr().String(),
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapter(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{})
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}

	endpoint := reserveUDPBindEndpoint(t)
	if _, err := agent.RegisterPeer(network.ID, endpoint); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	registerStatus := agent.Status()
	if registerStatus.NATType != stun.NATTypeNAT {
		t.Fatalf("expected NAT type %q right after STUN-backed peer registration, got %#v", stun.NATTypeNAT, registerStatus)
	}
	if registerStatus.PublicEndpoint != "203.0.113.10:54000" {
		t.Fatalf("expected public endpoint %q right after STUN-backed peer registration, got %#v", "203.0.113.10:54000", registerStatus)
	}

	deadline := time.Now().Add(3 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		types := upstream.CandidateTypes("peer-1")
		addresses := strings.Join(upstream.CandidateAddresses("peer-1", "SRFLX"), ",")
		if len(types) >= 2 &&
			strings.Contains(strings.Join(types, ","), "SRFLX") &&
			strings.Contains(addresses, "203.0.113.10:54000") {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("expected SRFLX candidate publication after STUN-backed peer registration, got status=%#v types=%#v addresses=%#v", agent.Status(), upstream.CandidateTypes("peer-1"), upstream.CandidateAddresses("peer-1", "SRFLX"))
	}

	status := agent.Status()
	if status.STUNServerAddress != stunServer.LocalAddr().String() {
		t.Fatalf("expected STUN server address %q, got %q", stunServer.LocalAddr().String(), status.STUNServerAddress)
	}
}

func TestAgentRefreshesServerReflexiveCandidateAndReestablishesDirectTransportAfterPublicEndpointChange(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stunServer, err := newScriptedSTUNServer("127.0.0.1:0", "203.0.113.10:54000")
	if err != nil {
		t.Fatalf("listen scripted stun server: %v", err)
	}
	defer stunServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     10 * time.Millisecond,
		STUNServerAddress:   stunServer.LocalAddr().String(),
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      20 * time.Millisecond,
		DirectMaxAttempts:   2,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Hour,
		TransportRekeyAfter: 1 << 20,
	}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	endpoint := reserveUDPBindEndpoint(t)
	if _, err := agent.RegisterPeer(network.ID, endpoint); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42020", []string{"127.0.0.1:42020"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		addresses := strings.Join(upstream.CandidateAddresses("peer-1", "SRFLX"), ",")
		return status.PublicEndpoint == "203.0.113.10:54000" &&
			len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			strings.Contains(addresses, "203.0.113.10:54000")
	})
	firstSessionID := agent.Status().Connections[0].TransportSessionID

	stunServer.SetMappedAddress("203.0.113.11:54001")
	directManager.stunMappedAddress = "203.0.113.11:54001"

	deadline := time.Now().Add(2 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		status := agent.Status()
		addresses := strings.Join(upstream.CandidateAddresses("peer-1", "SRFLX"), ",")
		if status.PublicEndpoint == "203.0.113.11:54001" &&
			len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].TransportSessionID != "" &&
			status.Connections[0].TransportSessionID != firstSessionID &&
			strings.Contains(addresses, "203.0.113.11:54001") {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("expected direct recovery after public endpoint change, got status=%#v srflx=%#v dropCalls=%d establishCalls=%d", agent.Status(), upstream.CandidateAddresses("peer-1", "SRFLX"), directManager.DropSessionCalls(), directManager.EstablishCalls())
	}

	status := agent.Status()
	if directManager.DropSessionCalls() < 1 {
		t.Fatalf("expected direct session to be dropped after public endpoint change")
	}
	if len(status.Connections) != 1 || status.Connections[0].LastError != "" {
		t.Fatalf("expected direct connection to recover cleanly after public endpoint change, got %#v", status.Connections)
	}
}

func TestAgentRefreshesSTUNThroughBoundDirectListenerAfterPeerRegistration(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stunServer, err := newScriptedSTUNServer("127.0.0.1:0", "203.0.113.10:54000")
	if err != nil {
		t.Fatalf("listen scripted stun server: %v", err)
	}
	defer stunServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: time.Hour,
		STUNProbePeriod:     10 * time.Millisecond,
		STUNServerAddress:   stunServer.LocalAddr().String(),
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directprobe.New())
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	endpoint := reserveUDPBindEndpoint(t)
	if _, err := agent.RegisterPeer(network.ID, endpoint); err != nil {
		t.Fatalf("register peer: %v", err)
	}

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return status.NATType == stun.NATTypeNAT && status.PublicEndpoint == "203.0.113.10:54000"
	})

	stunServer.SetMappedAddress("203.0.113.11:54001")

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return status.NATType == stun.NATTypeNAT && status.PublicEndpoint == "203.0.113.11:54001"
	})
}

func TestAgentRebindsDirectListenerDuringPeriodicSTUNRefreshAfterIdleListenerLoss(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   time.Hour,
		PeerDiscoveryPeriod: time.Hour,
		STUNProbePeriod:     10 * time.Millisecond,
		STUNServerAddress:   "127.0.0.1:3478",
	}
	directManager := &fakeDirectManager{stunMappedAddress: "203.0.113.10:54000"}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	endpoint := reserveUDPBindEndpoint(t)
	if _, err := agent.RegisterPeer(network.ID, endpoint); err != nil {
		t.Fatalf("register peer: %v", err)
	}

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return status.NATType == stun.NATTypeNAT && status.PublicEndpoint == "203.0.113.10:54000"
	})

	directManager.DropBinding("peer-1")
	directManager.stunMappedAddress = "203.0.113.11:54001"

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		bindings := directManager.LastBindings()
		return status.NATType == stun.NATTypeNAT &&
			status.PublicEndpoint == "203.0.113.11:54001" &&
			len(bindings) == 1 &&
			bindings[0].PeerID == "peer-1" &&
			bindings[0].ListenAddress == endpoint
	})

	status := agent.Status()
	if status.LastLifecycleError != "" {
		t.Fatalf("expected idle STUN listener-loss recovery to clear lifecycle errors, got %#v", status)
	}
	if directManager.STUNProbeCalls() < 2 {
		t.Fatalf("expected repeated STUN probes around listener recovery, got %d", directManager.STUNProbeCalls())
	}
}

func TestAgentTriggersImmediateDirectFailbackAfterIdleSTUNListenerRecovery(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   time.Hour,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		STUNProbePeriod:     10 * time.Millisecond,
		STUNServerAddress:   "127.0.0.1:3478",
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      10 * time.Millisecond,
		DirectMaxAttempts:   1,
		RelayServerAddress:  "127.0.0.1:3479",
		RelayFailbackPeriod: time.Hour,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Minute,
		TransportRekeyAfter: 100,
	}
	directManager := &fakeDirectManager{alwaysFail: true, stunMappedAddress: "203.0.113.10:54000"}
	relayManager := &fakeRelayManager{}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager, relayManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	endpoint := reserveUDPBindEndpoint(t)
	if _, err := agent.RegisterPeer(network.ID, endpoint); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42026", []string{"127.0.0.1:42026"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "RELAY"
	})

	relaySessionID := agent.Status().Connections[0].TransportSessionID
	directManager.DropBinding("peer-1")
	directManager.stunMappedAddress = "203.0.113.11:54001"
	directManager.AllowNextAttemptToSucceed()

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		bindings := directManager.LastBindings()
		return status.PublicEndpoint == "203.0.113.11:54001" &&
			len(bindings) == 1 &&
			bindings[0].PeerID == "peer-1" &&
			len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].Reachability == "DIRECT" &&
			status.Connections[0].TransportSessionID != "" &&
			status.Connections[0].TransportSessionID != relaySessionID
	})

	status := agent.Status()
	if relayManager.DropSessionCalls() < 1 {
		t.Fatalf("expected relay session to be dropped after immediate direct failback, got %#v", status)
	}
	if directManager.EstablishCalls() < 1 {
		t.Fatalf("expected direct transport to be re-established immediately after listener recovery, got %#v", status)
	}
	if status.DirectMetrics.FailbackSuccessCount < 1 {
		t.Fatalf("expected failback metrics to record immediate direct recovery, got %#v", status.DirectMetrics)
	}
}

func TestAgentNegotiatesDirectConnectionWithBoundedRetries(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      20 * time.Millisecond,
		DirectMaxAttempts:   2,
	}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41010"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42020", []string{"127.0.0.1:42020"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED"
	})

	status := agent.Status()
	if status.LastDirectProbeUnix == 0 {
		t.Fatalf("expected direct probe timestamp in status")
	}
	if directManager.AttemptCalls() < 1 {
		t.Fatalf("expected at least one direct probe attempt")
	}
	connection := status.Connections[0]
	if connection.AttemptCount != 1 {
		t.Fatalf("expected one attempt, got %#v", connection)
	}
	if connection.SelectedCandidate != "127.0.0.1:42020" {
		t.Fatalf("expected selected candidate to be stored, got %#v", connection)
	}
	if !connection.TransportReady || connection.TransportSessionID == "" || connection.LastTransportUnix == 0 {
		t.Fatalf("expected encrypted transport metadata on connection, got %#v", connection)
	}
	if connection.TunnelMode != "P2P" || connection.TunnelState != "OPEN" || connection.TunnelID == "" {
		t.Fatalf("expected open tunnel metadata on connection, got %#v", connection)
	}
	if status.DirectMetrics.AttemptCount < 1 || status.DirectMetrics.SuccessCount != 1 || status.DirectMetrics.FailureCount != 0 {
		t.Fatalf("expected direct metrics to record one successful direct attempt, got %#v", status.DirectMetrics)
	}
	if status.DirectMetrics.SuccessRatePct != 100 || status.DirectMetrics.LastSuccessCandidate != "127.0.0.1:42020" {
		t.Fatalf("expected direct success rate and candidate in metrics, got %#v", status.DirectMetrics)
	}
}

func TestAgentRebindsManagedPeerWhenHeartbeatReturnsRoamedEndpoint(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: time.Hour,
	}
	directManager := &fakeDirectManager{}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	firstEndpoint := reserveUDPBindEndpoint(t)
	if _, err := agent.RegisterPeer(network.ID, firstEndpoint); err != nil {
		t.Fatalf("register peer: %v", err)
	}

	waitForCondition(t, time.Second, func() bool {
		bindings := directManager.LastBindings()
		return len(bindings) == 1 && bindings[0].ListenAddress == firstEndpoint
	})

	secondEndpoint := reserveUDPBindEndpoint(t)
	upstream.SetHeartbeatEndpointOverride("peer-1", secondEndpoint)

	waitForCondition(t, time.Second, func() bool {
		bindings := directManager.LastBindings()
		return len(bindings) == 1 && bindings[0].ListenAddress == secondEndpoint
	})
}

func TestAgentFailsBackToDirectImmediatelyAfterHeartbeatReportsRoamedEndpointWhileOnRelay(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      10 * time.Millisecond,
		DirectMaxAttempts:   1,
		RelayServerAddress:  "127.0.0.1:3479",
		RelayFailbackPeriod: time.Hour,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Minute,
		TransportRekeyAfter: 100,
	}
	directManager := &fakeDirectManager{alwaysFail: true}
	relayManager := &fakeRelayManager{}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager, relayManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	firstEndpoint := reserveUDPBindEndpoint(t)
	if _, err := agent.RegisterPeer(network.ID, firstEndpoint); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42026", []string{"127.0.0.1:42026"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		bindings := directManager.LastBindings()
		return len(bindings) == 1 &&
			bindings[0].ListenAddress == firstEndpoint &&
			len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "RELAY"
	})

	relaySessionID := agent.Status().Connections[0].TransportSessionID
	secondEndpoint := reserveUDPBindEndpoint(t)
	upstream.SetHeartbeatEndpointOverride("peer-1", secondEndpoint)
	directManager.AllowNextAttemptToSucceed()

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		bindings := directManager.LastBindings()
		return len(bindings) == 1 &&
			bindings[0].ListenAddress == secondEndpoint &&
			len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].Reachability == "DIRECT" &&
			status.Connections[0].TransportSessionID != "" &&
			status.Connections[0].TransportSessionID != relaySessionID
	})

	status := agent.Status()
	if relayManager.DropSessionCalls() < 1 {
		t.Fatalf("expected relay session to be dropped after immediate direct failback on local roam, got %#v", status)
	}
	if directManager.EstablishCalls() < 1 {
		t.Fatalf("expected direct transport to be re-established after local roam, got %#v", status)
	}
	if status.DirectMetrics.FailbackSuccessCount < 1 {
		t.Fatalf("expected failback metrics to record direct recovery after local roam, got %#v", status.DirectMetrics)
	}
}

func TestAgentFailsBackToDirectImmediatelyAfterRemoteEndpointChangeWhileOnRelay(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   time.Hour,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      10 * time.Millisecond,
		DirectMaxAttempts:   1,
		RelayServerAddress:  "127.0.0.1:3479",
		RelayFailbackPeriod: time.Hour,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Minute,
		TransportRekeyAfter: 100,
	}
	directManager := &fakeDirectManager{alwaysFail: true}
	relayManager := &fakeRelayManager{}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager, relayManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41018"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42028", []string{"127.0.0.1:42028"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "RELAY"
	})

	relaySessionID := agent.Status().Connections[0].TransportSessionID
	upstream.UpdateRemotePeerEndpoint("peer-remote", "127.0.0.1:43028", []string{"127.0.0.1:43028"})
	directManager.AllowNextAttemptToSucceed()

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].Reachability == "DIRECT" &&
			status.Connections[0].SelectedCandidate == "127.0.0.1:43028" &&
			status.Connections[0].TransportSessionID != "" &&
			status.Connections[0].TransportSessionID != relaySessionID
	})

	status := agent.Status()
	if relayManager.DropSessionCalls() < 1 {
		t.Fatalf("expected relay session to be dropped after immediate direct failback on remote endpoint change, got %#v", status)
	}
	if directManager.EstablishCalls() < 1 {
		t.Fatalf("expected direct transport to be re-established after remote endpoint change, got %#v", status)
	}
	if status.DirectMetrics.FailbackSuccessCount < 1 {
		t.Fatalf("expected failback metrics to record direct recovery after remote endpoint change, got %#v", status.DirectMetrics)
	}
}

func TestAgentFailsBackToDirectImmediatelyAfterLocalAndRemoteEndpointChangeWhileOnRelay(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      10 * time.Millisecond,
		DirectMaxAttempts:   1,
		RelayServerAddress:  "127.0.0.1:3479",
		RelayFailbackPeriod: time.Hour,
		TransportKeepalive:  time.Hour,
		TransportSessionTTL: time.Minute,
		TransportRekeyAfter: 100,
	}
	directManager := &fakeDirectManager{alwaysFail: true}
	relayManager := &fakeRelayManager{}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager, relayManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	firstEndpoint := reserveUDPBindEndpoint(t)
	if _, err := agent.RegisterPeer(network.ID, firstEndpoint); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42030", []string{"127.0.0.1:42030"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		bindings := directManager.LastBindings()
		return len(bindings) == 1 &&
			bindings[0].ListenAddress == firstEndpoint &&
			len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "RELAY"
	})

	relaySessionID := agent.Status().Connections[0].TransportSessionID
	secondEndpoint := reserveUDPBindEndpoint(t)
	upstream.SetHeartbeatEndpointOverride("peer-1", secondEndpoint)
	upstream.UpdateRemotePeerEndpoint("peer-remote", "127.0.0.1:43030", []string{"127.0.0.1:43030"})
	directManager.AllowNextAttemptToSucceed()

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		bindings := directManager.LastBindings()
		return len(bindings) == 1 &&
			bindings[0].ListenAddress == secondEndpoint &&
			len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].Reachability == "DIRECT" &&
			status.Connections[0].SelectedCandidate == "127.0.0.1:43030" &&
			status.Connections[0].TransportSessionID != "" &&
			status.Connections[0].TransportSessionID != relaySessionID
	})

	status := agent.Status()
	if relayManager.DropSessionCalls() < 1 {
		t.Fatalf("expected relay session to be dropped after immediate direct failback on combined local and remote endpoint churn, got %#v", status)
	}
	if directManager.EstablishCalls() < 1 {
		t.Fatalf("expected direct transport to be re-established after combined local and remote endpoint churn, got %#v", status)
	}
	if status.DirectMetrics.FailbackSuccessCount < 1 {
		t.Fatalf("expected failback metrics to record direct recovery after combined local and remote endpoint churn, got %#v", status.DirectMetrics)
	}
}

func TestAgentReestablishesDirectTransportAfterLocalAndRemoteEndpointChange(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      20 * time.Millisecond,
		DirectMaxAttempts:   2,
	}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	firstEndpoint := reserveUDPBindEndpoint(t)
	if _, err := agent.RegisterPeer(network.ID, firstEndpoint); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42032", []string{"127.0.0.1:42032"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		bindings := directManager.LastBindings()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].TransportSessionID != "" &&
			len(bindings) == 1 &&
			bindings[0].ListenAddress == firstEndpoint
	})

	initialSessionID := agent.Status().Connections[0].TransportSessionID
	secondEndpoint := reserveUDPBindEndpoint(t)
	upstream.SetHeartbeatEndpointOverride("peer-1", secondEndpoint)
	upstream.UpdateRemotePeerEndpoint("peer-remote", "127.0.0.1:43032", []string{"127.0.0.1:43032"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		bindings := directManager.LastBindings()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].SelectedCandidate == "127.0.0.1:43032" &&
			status.Connections[0].TransportSessionID != "" &&
			status.Connections[0].TransportSessionID != initialSessionID &&
			len(status.Connections[0].RemoteCandidates) == 1 &&
			status.Connections[0].RemoteCandidates[0] == "127.0.0.1:43032" &&
			len(bindings) == 1 &&
			bindings[0].ListenAddress == secondEndpoint
	})

	status := agent.Status()
	if directManager.DropSessionCalls() < 1 || directManager.EstablishCalls() < 2 {
		t.Fatalf("expected direct session to be dropped and re-established after combined local and remote endpoint change, got drop=%d establish=%d status=%#v", directManager.DropSessionCalls(), directManager.EstablishCalls(), status)
	}
	if len(status.Connections) != 1 || status.Connections[0].LastError != "" {
		t.Fatalf("expected direct connection to recover cleanly after combined local and remote endpoint change, got %#v", status.Connections)
	}
}

func TestAgentReestablishesDirectAndRetriesPacketAfterCombinedLocalAndRemoteEndpointChange(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      20 * time.Millisecond,
		DirectMaxAttempts:   2,
		TransportKeepalive:  time.Hour,
		TransportLossLimit:  3,
		TransportSessionTTL: time.Minute,
		TransportRekeyAfter: 100,
	}
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	firstEndpoint := reserveUDPBindEndpoint(t)
	if _, err := agent.RegisterPeer(network.ID, firstEndpoint); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42034", []string{"127.0.0.1:42034"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].TransportSessionID != ""
	})

	initialSessionID := agent.Status().Connections[0].TransportSessionID
	secondEndpoint := reserveUDPBindEndpoint(t)
	upstream.SetHeartbeatEndpointOverride("peer-1", secondEndpoint)
	upstream.UpdateRemotePeerEndpoint("peer-remote", "127.0.0.1:43034", []string{"127.0.0.1:43034"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		bindings := directManager.LastBindings()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].SelectedCandidate == "127.0.0.1:43034" &&
			status.Connections[0].TransportSessionID != "" &&
			status.Connections[0].TransportSessionID != initialSessionID &&
			len(status.Connections[0].RemoteCandidates) == 1 &&
			status.Connections[0].RemoteCandidates[0] == "127.0.0.1:43034" &&
			len(bindings) == 1 &&
			bindings[0].ListenAddress == secondEndpoint
	})

	status := agent.Status()
	connection := status.Connections[0]
	recoveredSessionID := connection.TransportSessionID
	baselineEstablishes := directManager.EstablishCalls()
	outbound := buildIPv4Packet(t, "10.0.0.2", "10.0.0.3", []byte{9, 4, 9, 4})
	directManager.DropSession(connection.LocalPeerID, connection.RemotePeerID)
	adapterManager.EnqueueOutbound(outbound)

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		bindings := directManager.LastBindings()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].SelectedCandidate == "127.0.0.1:43034" &&
			status.Connections[0].TransportSessionID != "" &&
			status.Connections[0].TransportSessionID != recoveredSessionID &&
			directManager.EstablishCalls() >= baselineEstablishes+1 &&
			directManager.SentPacketCount() >= 1 &&
			len(bindings) == 1 &&
			bindings[0].ListenAddress == secondEndpoint
	})

	sent := directManager.SentPackets()
	if len(sent) == 0 || string(sent[len(sent)-1]) != string(outbound) {
		t.Fatalf("expected outbound packet to be retried over re-established direct transport after combined endpoint churn, got %#v", sent)
	}
	status = agent.Status()
	if len(status.Connections) != 1 || status.Connections[0].LastError != "" {
		t.Fatalf("expected direct connection to stay clean after packet retry across combined endpoint churn, got %#v", status.Connections)
	}
	if directManager.EstablishCalls() < baselineEstablishes+1 {
		t.Fatalf("expected another direct establish after send-path session loss on combined endpoint churn, got %d (baseline %d)", directManager.EstablishCalls(), baselineEstablishes)
	}
}

func TestAgentReestablishesDirectAfterKeepaliveSessionLossOnCombinedLocalAndRemoteEndpointChange(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      10 * time.Millisecond,
		DirectMaxAttempts:   2,
		TransportKeepalive:  20 * time.Millisecond,
		TransportLossLimit:  3,
		TransportSessionTTL: time.Minute,
		TransportRekeyAfter: 100,
	}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	firstEndpoint := reserveUDPBindEndpoint(t)
	if _, err := agent.RegisterPeer(network.ID, firstEndpoint); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42035", []string{"127.0.0.1:42035"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].TransportSessionID != ""
	})

	initialSessionID := agent.Status().Connections[0].TransportSessionID
	secondEndpoint := reserveUDPBindEndpoint(t)
	upstream.SetHeartbeatEndpointOverride("peer-1", secondEndpoint)
	upstream.UpdateRemotePeerEndpoint("peer-remote", "127.0.0.1:43035", []string{"127.0.0.1:43035"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		bindings := directManager.LastBindings()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].SelectedCandidate == "127.0.0.1:43035" &&
			status.Connections[0].TransportSessionID != "" &&
			status.Connections[0].TransportSessionID != initialSessionID &&
			len(bindings) == 1 &&
			bindings[0].ListenAddress == secondEndpoint
	})

	status := agent.Status()
	connection := status.Connections[0]
	recoveredSessionID := connection.TransportSessionID
	baselineExchanges := directManager.ExchangeCalls()
	directManager.DropSession(connection.LocalPeerID, connection.RemotePeerID)

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		bindings := directManager.LastBindings()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].Reachability == "DIRECT" &&
			status.Connections[0].SelectedCandidate == "127.0.0.1:43035" &&
			status.Connections[0].TransportSessionID != "" &&
			status.Connections[0].TransportSessionID != recoveredSessionID &&
			len(bindings) == 1 &&
			bindings[0].ListenAddress == secondEndpoint
	})

	directExchangeDelta := directManager.ExchangeCalls() - baselineExchanges
	if directExchangeDelta >= runtime.TransportLossLimit {
		t.Fatalf("expected immediate direct re-establish on updated addresses before exhausting %d keepalive losses, got %d direct exchanges after combined-endpoint churn session drop", runtime.TransportLossLimit, directExchangeDelta)
	}
	if directManager.EstablishCalls() < 3 {
		t.Fatalf("expected direct transport to be re-established again after keepalive-detected session loss on combined endpoint churn, got %d establishes", directManager.EstablishCalls())
	}
}

func TestAgentRebindsDirectListenerAndRetriesPacketAfterSendPathListenerLoss(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      20 * time.Millisecond,
		DirectMaxAttempts:   2,
		TransportKeepalive:  time.Hour,
		TransportLossLimit:  3,
		TransportSessionTTL: time.Minute,
		TransportRekeyAfter: 100,
	}
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	endpoint := reserveUDPBindEndpoint(t)
	if _, err := agent.RegisterPeer(network.ID, endpoint); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42026", []string{"127.0.0.1:42026"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		bindings := directManager.LastBindings()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			len(bindings) == 1 &&
			bindings[0].PeerID == "peer-1" &&
			bindings[0].ListenAddress == endpoint
	})

	status := agent.Status()
	baselineAttempts := directManager.AttemptCalls()
	directManager.DropBinding(status.Connections[0].LocalPeerID)
	outbound := buildIPv4Packet(t, "10.0.0.2", "10.0.0.3", []byte{2, 4, 6, 8})
	adapterManager.EnqueueOutbound(outbound)

	deadline := time.Now().Add(time.Second)
	recovered := false
	for time.Now().Before(deadline) {
		status := agent.Status()
		bindings := directManager.LastBindings()
		if len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].TransportSessionID != "" &&
			len(bindings) == 1 &&
			bindings[0].PeerID == "peer-1" &&
			directManager.SentPacketCount() >= 1 {
			recovered = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !recovered {
		t.Fatalf("expected direct listener rebinding recovery, got status=%#v bindings=%#v attempts=%d establishes=%d sent=%#v", agent.Status(), directManager.LastBindings(), directManager.AttemptCalls(), directManager.EstablishCalls(), directManager.SentPackets())
	}

	directAttemptDelta := directManager.AttemptCalls() - baselineAttempts
	if directAttemptDelta >= runtime.TransportLossLimit {
		t.Fatalf("expected listener rebinding to recover direct transport before exhausting %d losses, got %d direct attempts", runtime.TransportLossLimit, directAttemptDelta)
	}
	sent := directManager.SentPackets()
	if len(sent) == 0 || string(sent[len(sent)-1]) != string(outbound) {
		t.Fatalf("expected outbound packet to be retried over rebound direct listener, got %#v", sent)
	}
	if directManager.EstablishCalls() < 1 {
		t.Fatalf("expected direct transport to remain usable after local listener loss, got %d establishes", directManager.EstablishCalls())
	}
}

func TestAgentReRegistersManagedPeerAfterHeartbeatNotFound(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      20 * time.Millisecond,
		DirectMaxAttempts:   2,
	}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	endpoint := reserveUDPBindEndpoint(t)
	if _, err := agent.RegisterPeer(network.ID, endpoint); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42020", []string{"127.0.0.1:42020"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		bindings := directManager.LastBindings()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].LocalPeerID == "peer-1" &&
			upstream.TunnelStateForPair("peer-1", "peer-remote") == "OPEN" &&
			len(bindings) == 1 &&
			bindings[0].PeerID == "peer-1"
	})
	firstSessionID := agent.Status().Connections[0].TransportSessionID

	upstream.RemovePeer("peer-1")

	waitForCondition(t, 2*time.Second, func() bool {
		status := agent.Status()
		bindings := directManager.LastBindings()
		return upstream.PeerCountForNetwork(network.ID) == 2 &&
			status.ManagedPeerCount == 1 &&
			len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].LocalPeerID == "peer-2" &&
			status.Connections[0].TransportSessionID != "" &&
			status.Connections[0].TransportSessionID != firstSessionID &&
			upstream.TunnelStateForPair("peer-1", "peer-remote") == "CLOSED" &&
			upstream.TunnelStateForPair("peer-2", "peer-remote") == "OPEN" &&
			len(bindings) == 1 &&
			bindings[0].PeerID == "peer-2" &&
			bindings[0].ListenAddress == endpoint
	})

	status := agent.Status()
	if directManager.DropSessionCalls() < 1 {
		t.Fatalf("expected old direct session to be dropped after managed peer re-registration")
	}
	if len(status.Connections) != 1 || status.Connections[0].LocalPeerID != "peer-2" {
		t.Fatalf("expected connection to use replacement local peer registration, got %#v", status.Connections)
	}
	if upstream.TunnelStateForPair("peer-1", "peer-remote") != "CLOSED" || upstream.TunnelStateForPair("peer-2", "peer-remote") != "OPEN" {
		t.Fatalf("expected stale tunnel to close and replacement tunnel to open after peer re-registration")
	}
}

func TestAgentReestablishesDirectTransportWhenRemoteEndpointChanges(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      20 * time.Millisecond,
		DirectMaxAttempts:   2,
	}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41010"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42020", []string{"127.0.0.1:42020"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED" && status.Connections[0].TransportSessionID != ""
	})
	firstSessionID := agent.Status().Connections[0].TransportSessionID

	upstream.UpdateRemotePeerEndpoint("peer-remote", "127.0.0.1:43020", []string{"127.0.0.1:43020"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].SelectedCandidate == "127.0.0.1:43020" &&
			status.Connections[0].TransportSessionID != "" &&
			status.Connections[0].TransportSessionID != firstSessionID
	})

	status := agent.Status()
	if directManager.DropSessionCalls() < 1 || directManager.EstablishCalls() < 2 {
		t.Fatalf("expected direct session to be dropped and re-established after remote endpoint change, got drop=%d establish=%d status=%#v", directManager.DropSessionCalls(), directManager.EstablishCalls(), status)
	}
}

func TestAgentDropsDirectTransportWhenRemotePeerDisappears(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      20 * time.Millisecond,
		DirectMaxAttempts:   2,
	}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41030"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42030", []string{"127.0.0.1:42030"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT"
	})

	upstream.RemovePeer("peer-remote")

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 0 && len(status.Neighbors) == 0
	})

	if directManager.DropSessionCalls() < 1 {
		t.Fatalf("expected direct session to be dropped after remote peer disappeared, got drop=%d", directManager.DropSessionCalls())
	}
}

func TestAgentPreservesDirectCandidatesAcrossSameTargetRemotePeerReplacement(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      20 * time.Millisecond,
		DirectMaxAttempts:   2,
	}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41031"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeerForUser(network.ID, "peer-remote-old", "usr-remote", "dev-remote", "10.0.0.3", "127.0.0.1:42031", []string{"127.0.0.1:42031"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].RemotePeerID == "peer-remote-old" &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT"
	})

	upstream.RemovePeer("peer-remote-old")
	upstream.AddRemotePeerForUser(network.ID, "peer-remote-new", "usr-remote", "dev-remote", "10.0.0.3", "127.0.0.1:42032", nil)

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].RemotePeerID == "peer-remote-new" &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			len(status.Connections[0].RemoteCandidates) == 1 &&
			status.Connections[0].RemoteCandidates[0] == "127.0.0.1:42031"
	})

	status := agent.Status()
	if len(status.Connections) != 1 || status.Connections[0].RemotePeerID != "peer-remote-new" {
		t.Fatalf("expected replacement remote peer to take over connection state, got %#v", status.Connections)
	}
	if status.Connections[0].TransportMode != "DIRECT" || status.Connections[0].State != "CONNECTED" {
		t.Fatalf("expected direct transport to survive same-target remote peer replacement while candidates lag, got %#v", status.Connections[0])
	}
	if len(status.Connections[0].RemoteCandidates) != 1 || status.Connections[0].RemoteCandidates[0] != "127.0.0.1:42031" {
		t.Fatalf("expected replacement peer to preserve prior direct candidates until fresh ones arrive, got %#v", status.Connections[0].RemoteCandidates)
	}
}

func TestAgentPreservesDirectCandidatesAcrossSameTargetRemotePeerReplacementWithoutUserMetadata(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      20 * time.Millisecond,
		DirectMaxAttempts:   2,
	}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41033"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeerForUser(network.ID, "peer-remote-old", "usr-remote", "dev-remote", "10.0.0.3", "127.0.0.1:42033", []string{"127.0.0.1:42033"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].RemotePeerID == "peer-remote-old" &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT"
	})

	upstream.RemovePeer("peer-remote-old")
	upstream.AddRemotePeerForUser(network.ID, "peer-remote-new", "", "dev-remote", "10.0.0.3", "127.0.0.1:42034", nil)

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].RemotePeerID == "peer-remote-new" &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			len(status.Connections[0].RemoteCandidates) == 1 &&
			status.Connections[0].RemoteCandidates[0] == "127.0.0.1:42033"
	})

	status := agent.Status()
	if len(status.Connections) != 1 || status.Connections[0].RemotePeerID != "peer-remote-new" {
		t.Fatalf("expected replacement remote peer without user metadata to take over connection state, got %#v", status.Connections)
	}
	if status.Connections[0].TransportMode != "DIRECT" || status.Connections[0].State != "CONNECTED" {
		t.Fatalf("expected direct transport to survive same-target remote peer replacement without user metadata while candidates lag, got %#v", status.Connections[0])
	}
	if len(status.Connections[0].RemoteCandidates) != 1 || status.Connections[0].RemoteCandidates[0] != "127.0.0.1:42033" {
		t.Fatalf("expected replacement peer without user metadata to preserve prior direct candidates until fresh ones arrive, got %#v", status.Connections[0].RemoteCandidates)
	}
}

func TestAgentPreservesDirectCandidatesAcrossLocalPeerReregistrationWhileRemoteCandidatesLag(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      20 * time.Millisecond,
		DirectMaxAttempts:   2,
	}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	endpoint := reserveUDPBindEndpoint(t)
	if _, err := agent.RegisterPeer(network.ID, endpoint); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeerForUser(network.ID, "peer-remote", "usr-remote", "dev-remote", "10.0.0.3", "127.0.0.1:42036", []string{"127.0.0.1:42036"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].LocalPeerID == "peer-1" &&
			status.Connections[0].RemotePeerID == "peer-remote" &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT"
	})

	upstream.RemovePeer("peer-1")
	upstream.RemovePeer("peer-remote")
	upstream.AddRemotePeerForUser(network.ID, "peer-remote", "usr-remote", "dev-remote", "10.0.0.3", "127.0.0.1:42037", nil)

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].LocalPeerID == "peer-2" &&
			status.Connections[0].RemotePeerID == "peer-remote" &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			len(status.Connections[0].RemoteCandidates) == 1 &&
			status.Connections[0].RemoteCandidates[0] == "127.0.0.1:42036"
	})

	status := agent.Status()
	if len(status.Connections) != 1 || status.Connections[0].LocalPeerID != "peer-2" || status.Connections[0].RemotePeerID != "peer-remote" {
		t.Fatalf("expected replacement local peer registration to keep the remote target connection, got %#v", status.Connections)
	}
	if status.Connections[0].TransportMode != "DIRECT" || status.Connections[0].State != "CONNECTED" {
		t.Fatalf("expected direct transport to survive local peer re-registration while remote candidates lag, got %#v", status.Connections[0])
	}
	if len(status.Connections[0].RemoteCandidates) != 1 || status.Connections[0].RemoteCandidates[0] != "127.0.0.1:42036" {
		t.Fatalf("expected replacement local peer registration to preserve prior direct candidates until fresh ones arrive, got %#v", status.Connections[0].RemoteCandidates)
	}
}

func TestAgentDropsStaleDirectTransportWhenRemotePeerGoesOffline(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      20 * time.Millisecond,
		DirectMaxAttempts:   2,
	}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41031"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42031", []string{"127.0.0.1:42031"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT"
	})

	upstream.SetRemotePeerStatus("peer-remote", "OFFLINE")

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "IDLE" &&
			!status.Connections[0].TransportReady &&
			status.Connections[0].TransportMode == "" &&
			len(status.Neighbors) == 1 &&
			status.Neighbors[0].Presence == "offline"
	})

	status := agent.Status()
	if directManager.DropSessionCalls() < 1 {
		t.Fatalf("expected direct session to be dropped after remote peer went offline, got drop=%d status=%#v", directManager.DropSessionCalls(), status)
	}
	if status.Connections[0].LastError == "" {
		t.Fatalf("expected offline transition to surface a reason on the connection, got %#v", status.Connections[0])
	}
}

func TestAgentFallsBackToRelayAfterBoundedDirectProbeRetries(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      10 * time.Millisecond,
		DirectMaxAttempts:   2,
	}
	directManager := &fakeDirectManager{alwaysFail: true}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41011"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42021", []string{"127.0.0.1:42021"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "RELAY_READY"
	})

	status := agent.Status()
	connection := status.Connections[0]
	if connection.AttemptCount != 2 {
		t.Fatalf("expected two bounded attempts before relay fallback, got %#v", connection)
	}
	if connection.LastError == "" {
		t.Fatalf("expected last error to be surfaced after bounded retries, got %#v", connection)
	}
	if connection.TransportReady || connection.TransportSessionID != "" {
		t.Fatalf("expected relay fallback to leave encrypted transport unavailable, got %#v", connection)
	}
	if connection.TunnelMode != "RELAY" || connection.TunnelState != "NEGOTIATING" || connection.TunnelID == "" {
		t.Fatalf("expected relay negotiation tunnel metadata after bounded retries, got %#v", connection)
	}
	if status.DirectMetrics.AttemptCount != 2 || status.DirectMetrics.FailureCount != 2 || status.DirectMetrics.SuccessCount != 0 {
		t.Fatalf("expected failed direct attempt metrics after bounded retries, got %#v", status.DirectMetrics)
	}
	if status.DirectMetrics.SuccessRatePct != 0 {
		t.Fatalf("expected zero direct success rate after failed retries, got %#v", status.DirectMetrics)
	}

	bundle := agent.DiagnosticsBundle()
	if bundle.UsageSummary.RecentErrors == nil || bundle.Networks[0].UsageSummary.RecentErrors == nil {
		t.Fatalf("expected diagnostics bundle to include recent-error rollups after bounded retry failure, got %#v / %#v", bundle.UsageSummary.RecentErrors, bundle.Networks[0].UsageSummary.RecentErrors)
	}
	if bundle.UsageSummary.RecentErrors.ErrorCount != 1 ||
		bundle.UsageSummary.RecentErrors.PersistentFailureCount != 1 ||
		bundle.UsageSummary.RecentErrors.TransientRetryCount != 0 ||
		bundle.UsageSummary.RecentErrors.LastErrorPeerID != "peer-remote" ||
		bundle.UsageSummary.RecentErrors.MostSevereState != "PERSISTENT_FAILURE" {
		t.Fatalf("expected aggregate recent-error rollup after bounded retry failure, got %#v", bundle.UsageSummary.RecentErrors)
	}
	if bundle.Networks[0].UsageSummary.RecentErrors.ErrorCount != 1 ||
		bundle.Networks[0].UsageSummary.RecentErrors.LastErrorState != "RELAY_READY" ||
		bundle.Networks[0].UsageSummary.RecentErrors.MostRecentError == "" ||
		bundle.Networks[0].UsageSummary.RecentErrors.Hint == "" {
		t.Fatalf("expected per-network recent-error rollup after bounded retry failure, got %#v", bundle.Networks[0].UsageSummary.RecentErrors)
	}
}

func TestAgentEstablishesRelayTransportAfterDirectFallback(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      10 * time.Millisecond,
		DirectMaxAttempts:   2,
		RelayServerAddress:  "127.0.0.1:3479",
	}
	directManager := &fakeDirectManager{alwaysFail: true}
	relayManager := &fakeRelayManager{}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager, relayManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41014"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42024", []string{"127.0.0.1:42024"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED" && status.Connections[0].Reachability == "RELAY"
	})

	status := agent.Status()
	connection := status.Connections[0]
	if connection.TransportMode != "RELAY" || !connection.TransportReady || connection.TransportSessionID == "" {
		t.Fatalf("expected relay transport metadata on connection, got %#v", connection)
	}
	if connection.TunnelMode != "RELAY" || connection.TunnelState != "OPEN" || connection.TunnelID == "" {
		t.Fatalf("expected open relay tunnel metadata, got %#v", connection)
	}
	if relayManager.EstablishCalls() < 1 || relayManager.ExchangeCalls() < 1 {
		t.Fatalf("expected relay manager to establish and exchange, got establish=%d exchange=%d", relayManager.EstablishCalls(), relayManager.ExchangeCalls())
	}
	if status.DirectMetrics.RelayFallbackCount < 1 || status.DirectMetrics.FailureCount < 1 {
		t.Fatalf("expected direct metrics to record relay fallback after direct failure, got %#v", status.DirectMetrics)
	}
}

func TestAgentPublishesAllRelayPoolCandidates(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		RelayServerAddress:  "127.0.0.1:3479, 127.0.0.1:3480",
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, &fakeDirectManager{}, &fakeRelayManager{})
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41014"); err != nil {
		t.Fatalf("register peer: %v", err)
	}

	waitForCondition(t, time.Second, func() bool {
		addresses := strings.Join(upstream.CandidateAddresses("peer-1", "RELAY"), ",")
		return strings.Contains(addresses, "127.0.0.1:3479") && strings.Contains(addresses, "127.0.0.1:3480")
	})

	status := agent.Status()
	if len(status.RelayServerAddresses) != 2 {
		t.Fatalf("expected two relay servers in status, got %#v", status.RelayServerAddresses)
	}
	if status.ActiveRelayServer != "127.0.0.1:3479" {
		t.Fatalf("expected first relay to be active before failover, got %#v", status)
	}
}

func TestAgentFailsOverAcrossRelayPoolWhenPrimaryRelayFails(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      10 * time.Millisecond,
		DirectMaxAttempts:   1,
		RelayServerAddress:  "127.0.0.1:3479,127.0.0.1:3480",
	}
	directManager := &fakeDirectManager{alwaysFail: true}
	relayManager := &fakeRelayManager{
		establishErrors: map[string]error{
			"127.0.0.1:3479": strconv.ErrSyntax,
		},
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager, relayManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41015"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42025", []string{"127.0.0.1:42025"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].Reachability == "RELAY" &&
			status.Connections[0].SelectedCandidate == "127.0.0.1:3480"
	})

	status := agent.Status()
	connection := status.Connections[0]
	if status.ActiveRelayServer != "127.0.0.1:3480" {
		t.Fatalf("expected failover to second relay, got %#v", status)
	}
	if status.RelayFailoverCount < 1 {
		t.Fatalf("expected relay failover count to increase, got %#v", status)
	}
	if connection.TransportMode != "RELAY" || connection.SelectedCandidate != "127.0.0.1:3480" {
		t.Fatalf("expected relay connection to use second relay, got %#v", connection)
	}
	establishAddresses := strings.Join(relayManager.EstablishRelayAddresses(), ",")
	if !strings.Contains(establishAddresses, "127.0.0.1:3479") || !strings.Contains(establishAddresses, "127.0.0.1:3480") {
		t.Fatalf("expected relay establish attempts across both relays, got %q", establishAddresses)
	}
}

func TestAgentForwardsPacketsAcrossRelayTransport(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      10 * time.Millisecond,
		DirectMaxAttempts:   1,
		RelayServerAddress:  "127.0.0.1:3479",
	}
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{alwaysFail: true}
	relayManager := &fakeRelayManager{}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager, relayManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41015"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42025", []string{"127.0.0.1:42025"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED" && status.Connections[0].Reachability == "RELAY"
	})

	outbound := buildIPv4Packet(t, "10.0.0.2", "10.0.0.3", []byte{5, 4, 3, 2})
	inbound := buildIPv4Packet(t, "10.0.0.3", "10.0.0.2", []byte{6, 7, 8, 9})
	adapterManager.EnqueueOutbound(outbound)
	relayManager.InjectInbound("peer-1", relaytransport.Packet{
		RemotePeerID:   "peer-remote",
		Payload:        inbound,
		ReceivedAtUnix: time.Now().Unix(),
	})

	waitForCondition(t, time.Second, func() bool {
		return relayManager.SentPacketCount() >= 1 && len(adapterManager.WrittenPackets()) >= 1
	})

	sent := relayManager.SentPackets()
	if len(sent) == 0 || string(sent[0]) != string(outbound) {
		t.Fatalf("expected outbound adapter packet to be forwarded into relay transport, got %#v", sent)
	}
	written := adapterManager.WrittenPackets()
	if len(written) == 0 || string(written[0]) != string(inbound) {
		t.Fatalf("expected inbound relay packet to be written back to adapter, got %#v", written)
	}
}

func TestAgentFailsOverRelayPoolAndRetriesCurrentPacketAfterRelaySendFailure(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      10 * time.Millisecond,
		DirectMaxAttempts:   1,
		RelayServerAddress:  "127.0.0.1:3479,127.0.0.1:3480",
	}
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{alwaysFail: true}
	relayManager := &fakeRelayManager{
		sendErrors: map[string]error{
			"127.0.0.1:3479": strconv.ErrSyntax,
		},
	}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager, relayManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41022"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42032", []string{"127.0.0.1:42032"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].Reachability == "RELAY" &&
			status.ActiveRelayServer == "127.0.0.1:3479"
	})

	outbound := buildIPv4Packet(t, "10.0.0.2", "10.0.0.3", []byte{4, 2, 4, 2})
	adapterManager.EnqueueOutbound(outbound)

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "RELAY" &&
			status.Connections[0].SelectedCandidate == "127.0.0.1:3480" &&
			status.ActiveRelayServer == "127.0.0.1:3480" &&
			relayManager.SentPacketCount() >= 1
	})

	sent := relayManager.SentPackets()
	if len(sent) == 0 || string(sent[len(sent)-1]) != string(outbound) {
		t.Fatalf("expected current outbound packet to be retried across relay failover, got %#v", sent)
	}
	status := agent.Status()
	if status.RelayFailoverCount < 1 {
		t.Fatalf("expected relay failover count to increase after send failure, got %#v", status)
	}
	establishAddresses := strings.Join(relayManager.EstablishRelayAddresses(), ",")
	if !strings.Contains(establishAddresses, "127.0.0.1:3479") || !strings.Contains(establishAddresses, "127.0.0.1:3480") {
		t.Fatalf("expected relay establish attempts on both pool members, got %q", establishAddresses)
	}
}

func TestAgentFailsOverRelayPoolImmediatelyAfterRelayKeepaliveSessionLoss(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      10 * time.Millisecond,
		DirectMaxAttempts:   1,
		RelayServerAddress:  "127.0.0.1:3479,127.0.0.1:3480",
		TransportKeepalive:  20 * time.Millisecond,
		TransportLossLimit:  3,
		TransportSessionTTL: time.Minute,
		TransportRekeyAfter: 100,
	}
	directManager := &fakeDirectManager{alwaysFail: true}
	relayManager := &fakeRelayManager{}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager, relayManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41024"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42034", []string{"127.0.0.1:42034"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].Reachability == "RELAY" &&
			status.ActiveRelayServer == "127.0.0.1:3479"
	})

	status := agent.Status()
	connection := status.Connections[0]
	baselineExchanges := relayManager.ExchangeCalls()
	relayManager.DropSession(connection.LocalPeerID, connection.RemotePeerID)

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "RELAY" &&
			status.Connections[0].SelectedCandidate == "127.0.0.1:3480" &&
			status.ActiveRelayServer == "127.0.0.1:3480"
	})

	relayExchangeDelta := relayManager.ExchangeCalls() - baselineExchanges
	if relayExchangeDelta >= runtime.TransportLossLimit+1 {
		t.Fatalf("expected immediate relay keepalive failover before exhausting %d losses, got %d relay exchanges after session drop", runtime.TransportLossLimit, relayExchangeDelta)
	}
	if relayManager.EstablishCalls() < 2 {
		t.Fatalf("expected relay transport to be established again after keepalive-detected relay session loss, got %d establishes", relayManager.EstablishCalls())
	}
}

func TestAgentFailsBackFromRelayToDirectWhenDirectLaterBecomesAvailable(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      10 * time.Millisecond,
		DirectMaxAttempts:   1,
		RelayServerAddress:  "127.0.0.1:3479",
		RelayFailbackPeriod: 20 * time.Millisecond,
		TransportSessionTTL: time.Minute,
		TransportRekeyAfter: 100,
	}
	directManager := &fakeDirectManager{alwaysFail: true}
	relayManager := &fakeRelayManager{}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager, relayManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41016"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42026", []string{"127.0.0.1:42026"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED" && status.Connections[0].Reachability == "RELAY"
	})
	relaySessionID := agent.Status().Connections[0].TransportSessionID
	directManager.AllowNextAttemptToSucceed()

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].Reachability == "DIRECT" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].TransportSessionID != "" &&
			status.Connections[0].TransportSessionID != relaySessionID
	})

	status := agent.Status()
	connection := status.Connections[0]
	if connection.TunnelMode != "P2P" || connection.TunnelState != "OPEN" {
		t.Fatalf("expected tunnel to fail back to open P2P mode, got %#v", connection)
	}
	if relayManager.DropSessionCalls() < 1 {
		t.Fatalf("expected relay session to be dropped after successful direct failback")
	}
	if directManager.EstablishCalls() < 1 {
		t.Fatalf("expected direct transport to be re-established during failback")
	}
	if status.DirectMetrics.FailbackSuccessCount < 1 || status.DirectMetrics.SuccessCount < 1 {
		t.Fatalf("expected direct metrics to record successful direct failback, got %#v", status.DirectMetrics)
	}
}

func TestAgentTracksKeepaliveAndRTTMetricsOnDirectTransport(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      20 * time.Millisecond,
		DirectMaxAttempts:   2,
		TransportKeepalive:  20 * time.Millisecond,
		TransportLossLimit:  2,
		TransportSessionTTL: time.Minute,
		TransportRekeyAfter: 100,
	}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41017"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42027", []string{"127.0.0.1:42027"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED" && status.Connections[0].TransportMode == "DIRECT"
	})
	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].LastKeepaliveUnix > 0 &&
			status.Connections[0].LastRTTMillis > 0 &&
			status.Connections[0].AverageRTTMillis > 0 &&
			status.Connections[0].ConsecutiveLosses == 0
	})

	status := agent.Status()
	connection := status.Connections[0]
	if directManager.ExchangeCalls() < 2 {
		t.Fatalf("expected transport exchange count to include keepalive traffic, got %d", directManager.ExchangeCalls())
	}
	if connection.LastKeepaliveUnix == 0 || connection.LastRTTMillis == 0 || connection.AverageRTTMillis == 0 {
		t.Fatalf("expected keepalive RTT metrics on connection, got %#v", connection)
	}
}

func TestAgentFallsBackToRelayAfterDirectKeepaliveLosses(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      10 * time.Millisecond,
		DirectMaxAttempts:   2,
		RelayServerAddress:  "127.0.0.1:3479",
		TransportKeepalive:  20 * time.Millisecond,
		TransportLossLimit:  1,
		TransportSessionTTL: time.Minute,
		TransportRekeyAfter: 100,
	}
	directManager := &fakeDirectManager{successAfter: 1}
	relayManager := &fakeRelayManager{}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager, relayManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41018"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42028", []string{"127.0.0.1:42028"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED" && status.Connections[0].TransportMode == "DIRECT"
	})

	directManager.EnableExchangeFailures()

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "RELAY" &&
			status.Connections[0].Reachability == "RELAY"
	})

	status := agent.Status()
	connection := status.Connections[0]
	if connection.TunnelMode != "RELAY" || connection.TunnelState != "OPEN" {
		t.Fatalf("expected tunnel to degrade to open RELAY mode after direct keepalive loss, got %#v", connection)
	}
	if relayManager.EstablishCalls() < 1 {
		t.Fatalf("expected relay manager to re-establish transport after direct keepalive loss")
	}
}

func TestAgentFallsBackToRelayImmediatelyAfterDirectSessionDisappears(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      10 * time.Millisecond,
		DirectMaxAttempts:   2,
		RelayServerAddress:  "127.0.0.1:3479",
		RelayFailbackPeriod: time.Hour,
		TransportKeepalive:  20 * time.Millisecond,
		TransportLossLimit:  3,
		TransportSessionTTL: time.Minute,
		TransportRekeyAfter: 100,
	}
	directManager := &fakeDirectManager{successAfter: 1}
	relayManager := &fakeRelayManager{}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager, relayManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41019"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42029", []string{"127.0.0.1:42029"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED" && status.Connections[0].TransportMode == "DIRECT"
	})

	status := agent.Status()
	connection := status.Connections[0]
	baselineAttempts := directManager.AttemptCalls()
	directManager.DropSession(connection.LocalPeerID, connection.RemotePeerID)
	directManager.alwaysFail = true

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "RELAY" &&
			status.Connections[0].Reachability == "RELAY"
	})

	directAttemptDelta := directManager.AttemptCalls() - baselineAttempts
	if directAttemptDelta >= runtime.TransportLossLimit {
		t.Fatalf("expected immediate relay fallback before exhausting %d keepalive losses, got %d direct recovery attempts after session drop", runtime.TransportLossLimit, directAttemptDelta)
	}
	if relayManager.EstablishCalls() < 1 {
		t.Fatalf("expected relay transport to establish after direct session vanished")
	}
}

func TestAgentReestablishesDirectImmediatelyAfterKeepaliveSessionLossWithoutRelay(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      10 * time.Millisecond,
		DirectMaxAttempts:   2,
		TransportKeepalive:  20 * time.Millisecond,
		TransportLossLimit:  3,
		TransportSessionTTL: time.Minute,
		TransportRekeyAfter: 100,
	}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41023"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42033", []string{"127.0.0.1:42033"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED" && status.Connections[0].TransportMode == "DIRECT"
	})

	status := agent.Status()
	connection := status.Connections[0]
	initialSessionID := connection.TransportSessionID
	baselineExchanges := directManager.ExchangeCalls()
	directManager.DropSession(connection.LocalPeerID, connection.RemotePeerID)

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].Reachability == "DIRECT" &&
			status.Connections[0].TransportSessionID != "" &&
			status.Connections[0].TransportSessionID != initialSessionID
	})

	directExchangeDelta := directManager.ExchangeCalls() - baselineExchanges
	if directExchangeDelta >= runtime.TransportLossLimit {
		t.Fatalf("expected immediate direct re-establish before exhausting %d keepalive losses, got %d direct exchanges after session drop", runtime.TransportLossLimit, directExchangeDelta)
	}
	if directManager.EstablishCalls() < 2 {
		t.Fatalf("expected direct transport to be re-established after keepalive-detected session loss, got %d establishes", directManager.EstablishCalls())
	}
}

func TestAgentFallsBackToRelayAndRetriesPacketAfterDirectSendSessionLoss(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      10 * time.Millisecond,
		DirectMaxAttempts:   2,
		RelayServerAddress:  "127.0.0.1:3479",
		RelayFailbackPeriod: time.Hour,
		TransportKeepalive:  time.Hour,
		TransportLossLimit:  3,
		TransportSessionTTL: time.Minute,
		TransportRekeyAfter: 100,
	}
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	relayManager := &fakeRelayManager{}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirectAndRelay(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager, relayManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41020"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42030", []string{"127.0.0.1:42030"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED" && status.Connections[0].TransportMode == "DIRECT"
	})

	status := agent.Status()
	connection := status.Connections[0]
	outbound := buildIPv4Packet(t, "10.0.0.2", "10.0.0.3", []byte{7, 7, 7, 7})
	directManager.DropSession(connection.LocalPeerID, connection.RemotePeerID)
	directManager.alwaysFail = true
	adapterManager.EnqueueOutbound(outbound)

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "RELAY" &&
			status.Connections[0].Reachability == "RELAY" &&
			relayManager.SentPacketCount() >= 1
	})

	if directManager.SentPacketCount() != 0 {
		t.Fatalf("expected dead direct session not to carry outbound payload, got %#v", directManager.SentPackets())
	}
	sent := relayManager.SentPackets()
	if len(sent) == 0 || string(sent[len(sent)-1]) != string(outbound) {
		t.Fatalf("expected outbound packet to be retried over relay after direct send-path loss, got %#v", sent)
	}
	if relayManager.EstablishCalls() < 1 {
		t.Fatalf("expected relay transport to establish after direct send-path session loss")
	}
}

func TestAgentReestablishesDirectAndRetriesPacketAfterDirectSendSessionLossWithoutRelay(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      10 * time.Millisecond,
		DirectMaxAttempts:   2,
		TransportKeepalive:  time.Hour,
		TransportLossLimit:  3,
		TransportSessionTTL: time.Minute,
		TransportRekeyAfter: 100,
	}
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41021"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42031", []string{"127.0.0.1:42031"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED" && status.Connections[0].TransportMode == "DIRECT"
	})

	status := agent.Status()
	connection := status.Connections[0]
	initialSessionID := connection.TransportSessionID
	outbound := buildIPv4Packet(t, "10.0.0.2", "10.0.0.3", []byte{3, 1, 3, 1})
	directManager.DropSession(connection.LocalPeerID, connection.RemotePeerID)
	adapterManager.EnqueueOutbound(outbound)

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 &&
			status.Connections[0].State == "CONNECTED" &&
			status.Connections[0].TransportMode == "DIRECT" &&
			status.Connections[0].TransportSessionID != "" &&
			status.Connections[0].TransportSessionID != initialSessionID &&
			directManager.SentPacketCount() >= 1
	})

	sent := directManager.SentPackets()
	if len(sent) == 0 || string(sent[len(sent)-1]) != string(outbound) {
		t.Fatalf("expected outbound packet to be retried over re-established direct transport, got %#v", sent)
	}
	if directManager.EstablishCalls() < 2 {
		t.Fatalf("expected direct transport to be established again after send-path session loss, got %d establishes", directManager.EstablishCalls())
	}
}

func TestAgentForwardsAdapterPacketsAcrossEncryptedTransport(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      20 * time.Millisecond,
		DirectMaxAttempts:   2,
	}
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41012"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42022", []string{"127.0.0.1:42022"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED"
	})

	outbound := buildIPv4Packet(t, "10.0.0.2", "10.0.0.3", []byte{1, 2, 3, 4})
	inbound := buildIPv4Packet(t, "10.0.0.3", "10.0.0.2", []byte{9, 8, 7, 6})
	adapterManager.EnqueueOutbound(outbound)
	directManager.InjectInbound("peer-1", directprobe.Packet{
		RemotePeerID:   "peer-remote",
		Payload:        inbound,
		ReceivedAtUnix: time.Now().Unix(),
	})

	waitForCondition(t, time.Second, func() bool {
		return directManager.SentPacketCount() >= 1 && len(adapterManager.WrittenPackets()) >= 1
	})

	sent := directManager.SentPackets()
	if len(sent) == 0 || string(sent[0]) != string(outbound) {
		t.Fatalf("expected outbound adapter packet to be forwarded into encrypted transport, got %#v", sent)
	}
	written := adapterManager.WrittenPackets()
	if len(written) == 0 || string(written[0]) != string(inbound) {
		t.Fatalf("expected inbound encrypted packet to be written back to adapter, got %#v", written)
	}
}

func TestAgentRekeysTransportSessionAfterTTL(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      20 * time.Millisecond,
		DirectMaxAttempts:   2,
		TransportSessionTTL: 30 * time.Millisecond,
		TransportRekeyAfter: 100,
	}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, &fakeAdapterManager{}, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41013"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42023", []string{"127.0.0.1:42023"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED" && status.Connections[0].TransportSessionID != ""
	})
	firstSessionID := agent.Status().Connections[0].TransportSessionID

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED" && status.Connections[0].TransportSessionID != "" && status.Connections[0].TransportSessionID != firstSessionID
	})

	status := agent.Status()
	connection := status.Connections[0]
	if connection.TransportEstablishedUnix == 0 || connection.TransportRekeyDueUnix == 0 {
		t.Fatalf("expected transport timing metadata after rekey, got %#v", connection)
	}
	if directManager.EstablishCalls() < 2 || directManager.DropSessionCalls() < 1 {
		t.Fatalf("expected at least one rekey cycle, got establish=%d drop=%d", directManager.EstablishCalls(), directManager.DropSessionCalls())
	}
}

func TestAgentRekeysTransportSessionAfterPacketThreshold(t *testing.T) {
	upstream := newFakeUpstream()
	upstreamServer := httptest.NewServer(upstream.Handler())
	defer upstreamServer.Close()

	stateStore := clientagent.NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	runtime := clientagent.RuntimeConfig{
		LifecycleInterval:   10 * time.Millisecond,
		HeartbeatInterval:   10 * time.Millisecond,
		PeerDiscoveryPeriod: 10 * time.Millisecond,
		DirectProbeTimeout:  10 * time.Millisecond,
		DirectRetryBase:     10 * time.Millisecond,
		DirectRetryMax:      20 * time.Millisecond,
		DirectMaxAttempts:   2,
		TransportSessionTTL: time.Minute,
		TransportRekeyAfter: 1,
	}
	adapterManager := &fakeAdapterManager{}
	directManager := &fakeDirectManager{successAfter: 1}
	agent := clientagent.NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(nil, "127.0.0.1:0", stateStore, runtime, adapterManager, directManager)
	defer agent.Close()

	agent.SetServerBaseURL(upstreamServer.URL)
	if _, err := agent.Register("owner@example.com", "secret"); err != nil {
		t.Fatalf("register user: %v", err)
	}
	if _, err := agent.Login("owner@example.com", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	network, err := agent.CreateNetwork("friends", "INVITE_ONLY")
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	if _, err := agent.RegisterPeer(network.ID, "127.0.0.1:41014"); err != nil {
		t.Fatalf("register peer: %v", err)
	}
	upstream.AddRemotePeer(network.ID, "peer-remote", "10.0.0.3", "127.0.0.1:42024", []string{"127.0.0.1:42024"})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED" && status.Connections[0].TransportSessionID != ""
	})
	firstSessionID := agent.Status().Connections[0].TransportSessionID

	adapterManager.EnqueueOutbound(buildIPv4Packet(t, "10.0.0.2", "10.0.0.3", []byte{5, 6, 7, 8}))

	waitForCondition(t, time.Second, func() bool {
		return directManager.SentPacketCount() >= 1
	})

	waitForCondition(t, time.Second, func() bool {
		status := agent.Status()
		return len(status.Connections) == 1 && status.Connections[0].State == "CONNECTED" && status.Connections[0].TransportSessionID != "" && status.Connections[0].TransportSessionID != firstSessionID
	})

	status := agent.Status()
	if status.Connections[0].TransportPacketCount != 0 {
		t.Fatalf("expected packet-count rekey to reset session counters, got %#v", status.Connections[0])
	}
	if directManager.DropSessionCalls() < 1 {
		t.Fatalf("expected packet-threshold rekey to drop old session")
	}
}

type fakeUpstream struct {
	mu                         sync.Mutex
	users                      map[string]fakeUser
	devices                    []map[string]any
	sessions                   []map[string]any
	auditEvents                []map[string]any
	incidentReports            []map[string]any
	networks                   []map[string]any
	peers                      []map[string]any
	messages                   []map[string]any
	fileTransfers              []map[string]any
	fileTransferPayloads       map[string][]byte
	candidates                 map[string][]map[string]any
	tunnels                    []map[string]any
	deviceCreateCalls          int
	refreshCalls               int
	heartbeatCalls             int
	listPeerCalls              int
	disconnectCalls            int
	healthCalls                int
	healthFailures             int
	fileTransferChunkDownloads int
	heartbeatOverride          map[string]string
	serverVersion              string
	minClientVersion           string
	localPeerCIDR              string
}

type fakeUser struct {
	ID       string
	Email    string
	Password string
}

func newFakeUpstream() *fakeUpstream {
	return &fakeUpstream{
		users:                map[string]fakeUser{},
		fileTransferPayloads: map[string][]byte{},
		candidates:           map[string][]map[string]any{},
		heartbeatOverride:    map[string]string{},
		serverVersion:        "0.1.0",
		minClientVersion:     "0.1.0",
	}
}

func (s *fakeUpstream) DeviceCreateCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deviceCreateCalls
}

func (s *fakeUpstream) MarkSessionReuseDetected(sessionID string, detectedAtUnix int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for idx := range s.sessions {
		if asString(s.sessions[idx]["id"]) == sessionID {
			s.sessions[idx]["reuseDetectedAtUnix"] = detectedAtUnix
		}
	}
}

func (s *fakeUpstream) RefreshCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshCalls
}

func (s *fakeUpstream) HeartbeatCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.heartbeatCalls
}

func (s *fakeUpstream) ListPeerCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listPeerCalls
}

func (s *fakeUpstream) HealthCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.healthCalls
}

func (s *fakeUpstream) FileTransferChunkDownloads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fileTransferChunkDownloads
}

func (s *fakeUpstream) SetHealthFailures(count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthFailures = count
}

func (s *fakeUpstream) SetHeartbeatEndpointOverride(peerID, endpoint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(endpoint) == "" {
		delete(s.heartbeatOverride, peerID)
		return
	}
	s.heartbeatOverride[peerID] = endpoint
}

func (s *fakeUpstream) CandidateTypes(peerID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidates := s.candidates[peerID]
	types := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidateType, _ := candidate["type"].(string)
		types = append(types, candidateType)
	}
	return types
}

func (s *fakeUpstream) CandidateAddresses(peerID, candidateType string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidates := s.candidates[peerID]
	addresses := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		itemType, _ := candidate["type"].(string)
		if candidateType != "" && !strings.EqualFold(itemType, candidateType) {
			continue
		}
		address, _ := candidate["address"].(string)
		if strings.TrimSpace(address) != "" {
			addresses = append(addresses, address)
		}
	}
	return addresses
}

func (s *fakeUpstream) RemovePeer(peerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	filtered := s.peers[:0]
	for _, peer := range s.peers {
		if asString(peer["id"]) != peerID {
			filtered = append(filtered, peer)
		}
	}
	s.peers = filtered
	delete(s.candidates, peerID)
}

func (s *fakeUpstream) RevokeDevice(deviceID string, revokedAtUnix int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for idx := range s.devices {
		if asString(s.devices[idx]["id"]) == deviceID {
			s.devices[idx]["status"] = "REVOKED"
			s.devices[idx]["revokedAtUnix"] = revokedAtUnix
		}
	}
}

func (s *fakeUpstream) AddAuditEvent(id, actorUserID, eventType, details string, createdAtUnix int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditEvents = append(s.auditEvents, map[string]any{
		"id":            id,
		"actorUserId":   actorUserID,
		"type":          eventType,
		"details":       details,
		"createdAtUnix": createdAtUnix,
	})
}

func (s *fakeUpstream) findNetworkLocked(networkID string) (int, map[string]any) {
	for idx, network := range s.networks {
		if asString(network["id"]) == networkID {
			return idx, network
		}
	}
	return -1, nil
}

func (s *fakeUpstream) findDeviceLocked(deviceID string) map[string]any {
	for _, device := range s.devices {
		if asString(device["id"]) == deviceID {
			return device
		}
	}
	return nil
}

func (s *fakeUpstream) AddNetworkMember(networkID, userID, role string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, network := s.findNetworkLocked(networkID)
	if network == nil {
		return
	}
	members := append([]string(nil), asStrings(network["members"])...)
	if !containsString(members, userID) {
		members = append(members, userID)
	}
	memberRoles := map[string]any{}
	if existing, ok := network["memberRoles"].(map[string]any); ok {
		for key, value := range existing {
			memberRoles[key] = value
		}
	}
	memberRoles[userID] = firstNonEmpty(role, "MEMBER")
	network["members"] = members
	network["memberRoles"] = memberRoles
	s.networks[idx] = network
}

func (s *fakeUpstream) OverrideNetworkOwner(networkID, ownerUserID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, network := s.findNetworkLocked(networkID)
	if network == nil {
		return
	}
	network["ownerId"] = ownerUserID
	members := append([]string(nil), asStrings(network["members"])...)
	if !containsString(members, ownerUserID) {
		members = append(members, ownerUserID)
	}
	memberRoles := map[string]any{}
	if existing, ok := network["memberRoles"].(map[string]any); ok {
		for key, value := range existing {
			memberRoles[key] = value
		}
	}
	memberRoles[ownerUserID] = "OWNER"
	network["members"] = members
	network["memberRoles"] = memberRoles
	s.networks[idx] = network
}

func (s *fakeUpstream) PeerCountForNetwork(networkID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, peer := range s.peers {
		if asString(peer["networkId"]) == networkID {
			count++
		}
	}
	return count
}

func (s *fakeUpstream) TunnelStateForPair(peerAID, peerBID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tunnel := range s.tunnels {
		if samePair(asString(tunnel["peerAId"]), asString(tunnel["peerBId"]), peerAID, peerBID) {
			return asString(tunnel["state"])
		}
	}
	return ""
}

func (s *fakeUpstream) AddRemotePeer(networkID, peerID, virtualIP, endpoint string, candidateAddresses []string) {
	s.AddRemotePeerForUser(networkID, peerID, "usr-remote", "dev-remote", virtualIP, endpoint, candidateAddresses)
}

func (s *fakeUpstream) AddRemotePeerForUser(networkID, peerID, userID, deviceID, virtualIP, endpoint string, candidateAddresses []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer := map[string]any{
		"id":                 peerID,
		"userId":             userID,
		"deviceId":           deviceID,
		"networkId":          networkID,
		"overlayCidr":        overlayCIDRForTestIP(virtualIP),
		"virtualIp":          virtualIP,
		"endpoint":           endpoint,
		"status":             "ONLINE",
		"reachability":       "DIRECT",
		"connectionState":    "DIRECT_CANDIDATE",
		"lastSeenUnix":       time.Now().Unix(),
		"lastSignaledAtUnix": time.Now().Unix(),
	}
	s.peers = append(s.peers, peer)
	candidates := make([]map[string]any, 0, len(candidateAddresses))
	for idx, address := range candidateAddresses {
		candidates = append(candidates, map[string]any{
			"id":            "cand-remote-" + strconv.Itoa(idx+1),
			"peerId":        peerID,
			"networkId":     networkID,
			"type":          "HOST",
			"protocol":      "UDP",
			"address":       address,
			"preference":    100 - idx,
			"reachable":     true,
			"createdAtUnix": time.Now().Unix(),
			"expiresAtUnix": time.Now().Add(2 * time.Minute).Unix(),
		})
	}
	s.candidates[peerID] = candidates
}

func (s *fakeUpstream) UpdateRemotePeerEndpoint(peerID, endpoint string, candidateAddresses []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	networkID := ""
	for idx := range s.peers {
		if asString(s.peers[idx]["id"]) != peerID {
			continue
		}
		networkID = asString(s.peers[idx]["networkId"])
		s.peers[idx]["endpoint"] = endpoint
		s.peers[idx]["lastSeenUnix"] = time.Now().Unix()
		break
	}
	candidates := make([]map[string]any, 0, len(candidateAddresses))
	for idx, address := range candidateAddresses {
		candidates = append(candidates, map[string]any{
			"id":            "cand-remote-update-" + strconv.Itoa(idx+1),
			"peerId":        peerID,
			"networkId":     networkID,
			"type":          "HOST",
			"protocol":      "UDP",
			"address":       address,
			"preference":    100 - idx,
			"reachable":     true,
			"createdAtUnix": time.Now().Unix(),
			"expiresAtUnix": time.Now().Add(2 * time.Minute).Unix(),
		})
	}
	s.candidates[peerID] = candidates
}

func (s *fakeUpstream) SetRemotePeerStatus(peerID, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for idx := range s.peers {
		if asString(s.peers[idx]["id"]) != peerID {
			continue
		}
		s.peers[idx]["status"] = strings.ToUpper(strings.TrimSpace(status))
		s.peers[idx]["lastSeenUnix"] = time.Now().Unix()
		return
	}
}

func (s *fakeUpstream) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/v1/users", s.handleUsers)
	mux.HandleFunc("/api/v1/users/", s.handleUserByID)
	mux.HandleFunc("/api/v1/sessions", s.handleSessions)
	mux.HandleFunc("/api/v1/sessions/", s.handleSessionsRefresh)
	mux.HandleFunc("/api/v1/devices", s.handleDevices)
	mux.HandleFunc("/api/v1/audit-events", s.handleAuditEvents)
	mux.HandleFunc("/api/v1/incidents", s.handleIncidentReports)
	mux.HandleFunc("/api/v1/networks", s.handleNetworks)
	mux.HandleFunc("/api/v1/networks/", s.handleNetworkChildren)
	mux.HandleFunc("/api/v1/file-transfers/", s.handleFileTransferByID)
	mux.HandleFunc("/api/v1/peers/", s.handlePeerByID)
	mux.HandleFunc("/api/v1/tunnels/", s.handleTunnelByID)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceID := strings.TrimSpace(r.Header.Get(tracectx.HeaderTraceID))
		if traceID != "" {
			w.Header().Set(tracectx.HeaderTraceID, traceID)
		}
		parentSpanID := strings.TrimSpace(r.Header.Get(tracectx.HeaderParentSpanID))
		if parentSpanID != "" {
			w.Header().Set(tracectx.HeaderParentSpanID, parentSpanID)
		}
		w.Header().Set(tracectx.HeaderSpanID, "srvfake01")
		mux.ServeHTTP(w, r)
	})
}

func (s *fakeUpstream) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.healthCalls++
	if s.healthFailures > 0 {
		s.healthFailures--
		s.mu.Unlock()
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "temporary unavailable"})
		return
	}
	serverVersion := s.serverVersion
	minClientVersion := s.minClientVersion
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().Unix(),
		"version": map[string]any{
			"apiVersion":       "v1",
			"serverVersion":    serverVersion,
			"minClientVersion": minClientVersion,
		},
	})
}

func (s *fakeUpstream) handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	id := "usr-1"
	s.mu.Lock()
	s.users[id] = fakeUser{ID: id, Email: req.Email, Password: req.Password}
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{
		"data": map[string]any{
			"id":     id,
			"email":  req.Email,
			"status": "ACTIVE",
		},
	})
}

func (s *fakeUpstream) handleUserByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	s.mu.Lock()
	user, ok := s.users[id]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"id":     user.ID,
			"email":  user.Email,
			"status": "ACTIVE",
		},
	})
}

func (s *fakeUpstream) handleSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		user := s.users["usr-1"]
		s.mu.Unlock()
		if req.Email != user.Email || req.Password != user.Password {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
			return
		}
		session := s.newSession("1", time.Now().Add(time.Second).Unix())
		s.mu.Lock()
		s.sessions = []map[string]any{session}
		s.mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{"data": session})
	case http.MethodGet:
		if !s.authorize(w, r) {
			return
		}
		s.mu.Lock()
		sessions := append([]map[string]any(nil), s.sessions...)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"data": sessions})
	case http.MethodDelete:
		if !s.authorize(w, r) {
			return
		}
		s.mu.Lock()
		s.sessions = nil
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *fakeUpstream) handleSessionsRefresh(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/sessions/refresh" {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !s.authorize(w, r) {
			return
		}
		s.mu.Lock()
		s.sessions = nil
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RefreshToken string `json:"refreshToken"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) == 0 || s.sessions[0]["refreshToken"] != req.RefreshToken {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	s.refreshCalls++
	session := s.newSession(strconv.Itoa(s.refreshCalls+1), time.Now().Add(time.Hour).Unix())
	s.sessions = []map[string]any{session}
	writeJSON(w, http.StatusOK, map[string]any{"data": session})
}

func (s *fakeUpstream) handleDevices(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		devices := append([]map[string]any(nil), s.devices...)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"data": devices})
	case http.MethodPost:
		var req struct {
			Name      string `json:"name"`
			PublicKey string `json:"publicKey"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		s.deviceCreateCalls++
		deviceID := "dev-" + strconv.Itoa(s.deviceCreateCalls)
		device := map[string]any{
			"id":            deviceID,
			"userId":        "usr-1",
			"name":          req.Name,
			"publicKey":     req.PublicKey,
			"fingerprint":   "fp-" + deviceID,
			"status":        "ACTIVE",
			"createdAtUnix": 10,
			"revokedAtUnix": 0,
		}
		s.devices = append([]map[string]any{device}, s.devices...)
		s.mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{"data": device})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *fakeUpstream) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	actorUserID := strings.TrimSpace(r.URL.Query().Get("actorUserId"))
	eventType := strings.TrimSpace(r.URL.Query().Get("type"))
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	fromUnix, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("fromUnix")), 10, 64)
	toUnix, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("toUnix")), 10, 64)

	s.mu.Lock()
	source := append([]map[string]any(nil), s.auditEvents...)
	s.mu.Unlock()

	filtered := make([]map[string]any, 0, len(source))
	for _, event := range source {
		createdAtUnix, _ := event["createdAtUnix"].(int64)
		if actorUserID != "" && asString(event["actorUserId"]) != actorUserID {
			continue
		}
		if eventType != "" && asString(event["type"]) != eventType {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(asString(event["type"])), query) && !strings.Contains(strings.ToLower(asString(event["details"])), query) {
			continue
		}
		if fromUnix > 0 && createdAtUnix < fromUnix {
			continue
		}
		if toUnix > 0 && createdAtUnix > toUnix {
			continue
		}
		filtered = append(filtered, event)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": filtered})
}

func (s *fakeUpstream) handleIncidentReports(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"data": append([]map[string]any(nil), s.incidentReports...)})
}

func (s *fakeUpstream) handleNetworks(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		networks := append([]map[string]any(nil), s.networks...)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"data": networks})
	case http.MethodPost:
		var req struct {
			Name                   string `json:"name"`
			Access                 string `json:"access"`
			DeviceApprovalRequired bool   `json:"deviceApprovalRequired"`
			RoutingPolicy          string `json:"routingPolicy"`
			GroupTrafficPolicy     string `json:"groupTrafficPolicy"`
			NameResolutionMode     string `json:"nameResolutionMode"`
			DNSLabel               string `json:"dnsLabel"`
			FileTransfersEnabled   bool   `json:"fileTransfersEnabled"`
			FileTransferMaxBytes   int64  `json:"fileTransferMaxBytes"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		networkID := "net-" + strconv.Itoa(len(s.networks)+1)
		s.mu.Unlock()
		network := map[string]any{
			"id":                     networkID,
			"name":                   req.Name,
			"ownerId":                "usr-1",
			"access":                 firstNonEmpty(strings.ToUpper(strings.TrimSpace(req.Access)), "INVITE_ONLY"),
			"deviceApprovalRequired": req.DeviceApprovalRequired,
			"routingPolicy":          firstNonEmpty(strings.ToUpper(strings.TrimSpace(req.RoutingPolicy)), "SPLIT"),
			"groupTrafficPolicy":     firstNonEmpty(strings.ToUpper(strings.TrimSpace(req.GroupTrafficPolicy)), "BLOCKED"),
			"nameResolutionMode":     firstNonEmpty(strings.ToUpper(strings.TrimSpace(req.NameResolutionMode)), "DEFAULT"),
			"dnsLabel":               strings.ToLower(strings.TrimSpace(req.DNSLabel)),
			"fileTransfersEnabled":   req.FileTransfersEnabled,
			"fileTransferMaxBytes":   firstPositive(req.FileTransferMaxBytes, 8<<20),
			"approvedDeviceIds":      []string{},
			"members":                []string{"usr-1"},
			"memberRoles": map[string]any{
				"usr-1": "OWNER",
			},
		}
		s.mu.Lock()
		s.networks = append(s.networks, network)
		s.mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{"data": network})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *fakeUpstream) handleNetworkChildren(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/networks/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || len(parts) > 3 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch parts[1] {
	case "routing-policy":
		if len(parts) != 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPatch {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Policy string `json:"policy"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		defer s.mu.Unlock()
		idx, network := s.findNetworkLocked(parts[0])
		if network == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		network["routingPolicy"] = firstNonEmpty(strings.ToUpper(strings.TrimSpace(req.Policy)), "SPLIT")
		s.networks[idx] = network
		writeJSON(w, http.StatusOK, map[string]any{"data": network})
	case "group-traffic":
		if len(parts) != 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPatch {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Policy string `json:"policy"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		defer s.mu.Unlock()
		idx, network := s.findNetworkLocked(parts[0])
		if network == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		network["groupTrafficPolicy"] = firstNonEmpty(strings.ToUpper(strings.TrimSpace(req.Policy)), "BLOCKED")
		s.networks[idx] = network
		writeJSON(w, http.StatusOK, map[string]any{"data": network})
	case "name-resolution":
		if len(parts) != 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPatch {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Mode     string `json:"mode"`
			DNSLabel string `json:"dnsLabel"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		defer s.mu.Unlock()
		idx, network := s.findNetworkLocked(parts[0])
		if network == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		network["nameResolutionMode"] = firstNonEmpty(strings.ToUpper(strings.TrimSpace(req.Mode)), "DEFAULT")
		network["dnsLabel"] = strings.ToLower(strings.TrimSpace(req.DNSLabel))
		s.networks[idx] = network
		writeJSON(w, http.StatusOK, map[string]any{"data": network})
	case "file-transfer-policy":
		if len(parts) != 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPatch {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Enabled  bool  `json:"enabled"`
			MaxBytes int64 `json:"maxBytes"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		defer s.mu.Unlock()
		idx, network := s.findNetworkLocked(parts[0])
		if network == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		network["fileTransfersEnabled"] = req.Enabled
		network["fileTransferMaxBytes"] = firstPositive(req.MaxBytes, 8<<20)
		s.networks[idx] = network
		writeJSON(w, http.StatusOK, map[string]any{"data": network})
	case "device-approvals":
		if len(parts) != 3 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		deviceID := parts[2]
		s.mu.Lock()
		defer s.mu.Unlock()
		idx, network := s.findNetworkLocked(parts[0])
		if network == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		approvedDeviceIDs, _ := network["approvedDeviceIds"].([]string)
		switch r.Method {
		case http.MethodPost:
			if !containsString(approvedDeviceIDs, deviceID) {
				approvedDeviceIDs = append(approvedDeviceIDs, deviceID)
			}
			network["approvedDeviceIds"] = approvedDeviceIDs
			s.networks[idx] = network
			writeJSON(w, http.StatusOK, map[string]any{"data": network})
		case http.MethodDelete:
			filtered := approvedDeviceIDs[:0]
			for _, approvedDeviceID := range approvedDeviceIDs {
				if approvedDeviceID != deviceID {
					filtered = append(filtered, approvedDeviceID)
				}
			}
			network["approvedDeviceIds"] = filtered
			s.networks[idx] = network
			writeJSON(w, http.StatusOK, map[string]any{"data": network})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "messages":
		if len(parts) != 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.mu.Lock()
			messages := make([]map[string]any, 0, len(s.messages))
			for _, message := range s.messages {
				if asString(message["networkId"]) == parts[0] {
					messages = append(messages, message)
				}
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"data": messages})
		case http.MethodPost:
			var req struct {
				FromPeerID string `json:"fromPeerId"`
				Text       string `json:"text"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			message := map[string]any{
				"id":         "msg-" + strconv.Itoa(len(s.messages)+1),
				"networkId":  parts[0],
				"fromPeerId": req.FromPeerID,
				"text":       req.Text,
				"preview":    req.Text,
				"sentAtUnix": time.Now().Unix(),
			}
			s.mu.Lock()
			s.messages = append(s.messages, message)
			s.mu.Unlock()
			writeJSON(w, http.StatusCreated, map[string]any{"data": message})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "file-transfers":
		if len(parts) != 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.mu.Lock()
			transfers := make([]map[string]any, 0, len(s.fileTransfers))
			for _, transfer := range s.fileTransfers {
				if asString(transfer["networkId"]) == parts[0] {
					transfers = append(transfers, transfer)
				}
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"data": transfers})
		case http.MethodPost:
			var req struct {
				FromPeerID string `json:"fromPeerId"`
				ToPeerID   string `json:"toPeerId"`
				FileName   string `json:"fileName"`
				SizeBytes  int64  `json:"sizeBytes"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			transfer := map[string]any{
				"id":                   "xfer-" + strconv.Itoa(len(s.fileTransfers)+1),
				"networkId":            parts[0],
				"fromPeerId":           req.FromPeerID,
				"toPeerId":             req.ToPeerID,
				"fileName":             req.FileName,
				"sizeBytes":            req.SizeBytes,
				"status":               "INIT",
				"progressPercent":      0,
				"cancelReason":         "",
				"contentType":          "",
				"payloadSha256":        "",
				"payloadReady":         false,
				"payloadUploadedBytes": int64(0),
				"uploadedAtUnix":       int64(0),
				"downloadedAtUnix":     int64(0),
			}
			s.mu.Lock()
			s.fileTransfers = append(s.fileTransfers, transfer)
			s.mu.Unlock()
			writeJSON(w, http.StatusCreated, map[string]any{"data": transfer})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "peers":
		if len(parts) != 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.mu.Lock()
			s.listPeerCalls++
			peers := append([]map[string]any(nil), s.peers...)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"data": peers})
		case http.MethodPost:
			var req struct {
				DeviceID string `json:"deviceId"`
				Endpoint string `json:"endpoint"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			s.mu.Lock()
			_, network := s.findNetworkLocked(parts[0])
			if network == nil {
				s.mu.Unlock()
				writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
				return
			}
			if enabled, _ := network["deviceApprovalRequired"].(bool); enabled && !containsString(asStrings(network["approvedDeviceIds"]), req.DeviceID) {
				s.mu.Unlock()
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "device approval required"})
				return
			}
			peerID := "peer-" + strconv.Itoa(len(s.peers)+1)
			peer := map[string]any{
				"id":                 peerID,
				"userId":             "usr-1",
				"deviceId":           req.DeviceID,
				"networkId":          parts[0],
				"overlayCidr":        firstNonEmpty(strings.TrimSpace(s.localPeerCIDR), "10.0.0.0/24"),
				"virtualIp":          "10.0.0.2",
				"endpoint":           req.Endpoint,
				"status":             "ONLINE",
				"reachability":       "UNKNOWN",
				"connectionState":    "IDLE",
				"lastSeenUnix":       time.Now().Unix(),
				"lastSignaledAtUnix": int64(0),
			}
			s.peers = append(s.peers, peer)
			s.mu.Unlock()
			writeJSON(w, http.StatusCreated, map[string]any{"data": peer})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "tunnels":
		if len(parts) != 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.mu.Lock()
			tunnels := make([]map[string]any, 0, len(s.tunnels))
			for _, tunnel := range s.tunnels {
				if asString(tunnel["networkId"]) == parts[0] {
					tunnels = append(tunnels, tunnel)
				}
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"data": tunnels})
		case http.MethodPost:
			var req struct {
				PeerAID string `json:"peerAId"`
				PeerBID string `json:"peerBId"`
				Mode    string `json:"mode"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			s.mu.Lock()
			defer s.mu.Unlock()
			for idx := range s.tunnels {
				if asString(s.tunnels[idx]["networkId"]) != parts[0] {
					continue
				}
				if samePair(asString(s.tunnels[idx]["peerAId"]), asString(s.tunnels[idx]["peerBId"]), req.PeerAID, req.PeerBID) {
					if strings.TrimSpace(req.Mode) != "" {
						s.tunnels[idx]["mode"] = strings.ToUpper(strings.TrimSpace(req.Mode))
					}
					s.tunnels[idx]["state"] = "NEGOTIATING"
					writeJSON(w, http.StatusCreated, map[string]any{"data": s.tunnels[idx]})
					return
				}
			}
			tunnel := map[string]any{
				"id":            "tun-" + strconv.Itoa(len(s.tunnels)+1),
				"networkId":     parts[0],
				"peerAId":       req.PeerAID,
				"peerBId":       req.PeerBID,
				"mode":          firstNonEmpty(strings.ToUpper(strings.TrimSpace(req.Mode)), "P2P"),
				"state":         "NEGOTIATING",
				"createdAtUnix": time.Now().Unix(),
			}
			s.tunnels = append(s.tunnels, tunnel)
			writeJSON(w, http.StatusCreated, map[string]any{"data": tunnel})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "invites":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"data": map[string]any{
				"code":          "inv-1",
				"networkId":     parts[0],
				"expiresAtUnix": 1000,
				"maxUses":       1,
				"uses":          0,
			},
		})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *fakeUpstream) handleFileTransferByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/file-transfers/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	transferID := strings.TrimSpace(parts[0])
	if len(parts) == 2 && parts[1] == "content-chunks" {
		switch r.Method {
		case http.MethodGet:
			offsetBytes, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("offsetBytes")), 10, 64)
			limitBytes, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("limitBytes")), 10, 64)
			if limitBytes <= 0 {
				limitBytes = 1 << 20
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			for idx := range s.fileTransfers {
				if asString(s.fileTransfers[idx]["id"]) != transferID {
					continue
				}
				payload := append([]byte(nil), s.fileTransferPayloads[transferID]...)
				if offsetBytes < 0 || offsetBytes > int64(len(payload)) {
					writeJSON(w, http.StatusBadRequest, map[string]any{"error": "offset out of range"})
					return
				}
				end := offsetBytes + limitBytes
				if end > int64(len(payload)) {
					end = int64(len(payload))
				}
				s.fileTransferChunkDownloads++
				writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
					"transfer":         s.fileTransfers[idx],
					"contentType":      asString(s.fileTransfers[idx]["contentType"]),
					"sha256":           asString(s.fileTransfers[idx]["payloadSha256"]),
					"payloadBase64":    base64.StdEncoding.EncodeToString(payload[offsetBytes:end]),
					"offsetBytes":      offsetBytes,
					"nextOffsetBytes":  end,
					"totalSizeBytes":   int64(len(payload)),
					"uploadedAtUnix":   s.fileTransfers[idx]["uploadedAtUnix"],
					"downloadedAtUnix": s.fileTransfers[idx]["downloadedAtUnix"],
					"complete":         end >= int64(len(payload)),
				}})
				return
			}
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		case http.MethodPut:
			var req struct {
				ContentType   string `json:"contentType"`
				PayloadBase64 string `json:"payloadBase64"`
				OffsetBytes   int64  `json:"offsetBytes"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PayloadBase64))
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid payload"})
				return
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			for idx := range s.fileTransfers {
				if asString(s.fileTransfers[idx]["id"]) != transferID {
					continue
				}
				current := append([]byte(nil), s.fileTransferPayloads[transferID]...)
				if req.OffsetBytes != int64(len(current)) {
					writeJSON(w, http.StatusConflict, map[string]any{"error": "offset mismatch"})
					return
				}
				current = append(current, payload...)
				s.fileTransferPayloads[transferID] = current
				s.fileTransfers[idx]["contentType"] = strings.TrimSpace(req.ContentType)
				s.fileTransfers[idx]["payloadUploadedBytes"] = int64(len(current))
				s.fileTransfers[idx]["payloadReady"] = int64(len(current)) >= asInt64(s.fileTransfers[idx]["sizeBytes"])
				s.fileTransfers[idx]["uploadedAtUnix"] = time.Now().Unix()
				if ready, _ := s.fileTransfers[idx]["payloadReady"].(bool); ready {
					s.fileTransfers[idx]["payloadSha256"] = "sha-" + transferID
				}
				writeJSON(w, http.StatusOK, map[string]any{"data": s.fileTransfers[idx]})
				return
			}
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	}
	if len(parts) != 1 {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		defer s.mu.Unlock()
		for idx := range s.fileTransfers {
			if asString(s.fileTransfers[idx]["id"]) != transferID {
				continue
			}
			writeJSON(w, http.StatusOK, map[string]any{"data": s.fileTransfers[idx]})
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
	case http.MethodPatch:
		var req struct {
			Action          string `json:"action"`
			Reason          string `json:"reason"`
			ProgressPercent int    `json:"progressPercent"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		s.mu.Lock()
		defer s.mu.Unlock()
		for idx := range s.fileTransfers {
			if asString(s.fileTransfers[idx]["id"]) != transferID {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(req.Action)) {
			case "accept":
				s.fileTransfers[idx]["status"] = "IN_PROGRESS"
				s.fileTransfers[idx]["cancelReason"] = ""
			case "cancel":
				s.fileTransfers[idx]["status"] = "CANCELED"
				s.fileTransfers[idx]["cancelReason"] = strings.TrimSpace(req.Reason)
			case "progress":
				s.fileTransfers[idx]["progressPercent"] = req.ProgressPercent
				if req.ProgressPercent >= 100 {
					s.fileTransfers[idx]["status"] = "DONE"
					s.fileTransfers[idx]["cancelReason"] = ""
				} else if req.ProgressPercent > 0 {
					s.fileTransfers[idx]["status"] = "IN_PROGRESS"
				}
			default:
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported file transfer action"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"data": s.fileTransfers[idx]})
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *fakeUpstream) handlePeerByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/peers/")
	parts := strings.Split(path, "/")
	peerID := parts[0]
	if len(parts) == 2 && parts[1] == "candidates" {
		s.handlePeerCandidates(w, r, peerID)
		return
	}
	if r.Method != http.MethodPatch {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Endpoint        *string `json:"endpoint"`
		Status          *string `json:"status"`
		Reachability    *string `json:"reachability"`
		ConnectionState *string `json:"connectionState"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	defer s.mu.Unlock()
	for idx := range s.peers {
		if s.peers[idx]["id"] != peerID {
			continue
		}
		if req.Endpoint != nil {
			s.heartbeatCalls++
			endpoint := *req.Endpoint
			if override := strings.TrimSpace(s.heartbeatOverride[peerID]); override != "" {
				endpoint = override
			}
			s.peers[idx]["endpoint"] = endpoint
			s.peers[idx]["status"] = "ONLINE"
			s.peers[idx]["lastSeenUnix"] = time.Now().Unix()
		}
		if req.Status != nil && strings.EqualFold(*req.Status, "OFFLINE") {
			s.disconnectCalls++
			s.peers[idx]["status"] = "OFFLINE"
			s.peers[idx]["lastSeenUnix"] = time.Now().Unix()
		}
		if req.Reachability != nil {
			s.peers[idx]["reachability"] = *req.Reachability
			s.peers[idx]["lastSignaledAtUnix"] = time.Now().Unix()
		}
		if req.ConnectionState != nil {
			s.peers[idx]["connectionState"] = *req.ConnectionState
			s.peers[idx]["lastSignaledAtUnix"] = time.Now().Unix()
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": s.peers[idx]})
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
}

func (s *fakeUpstream) handlePeerCandidates(w http.ResponseWriter, r *http.Request, peerID string) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		candidates := append([]map[string]any(nil), s.candidates[peerID]...)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"data": candidates})
	case http.MethodPost:
		var req struct {
			Type       string `json:"type"`
			Protocol   string `json:"protocol"`
			Address    string `json:"address"`
			Preference int    `json:"preference"`
			Reachable  bool   `json:"reachable"`
			TTLSec     int64  `json:"ttlSec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		nextID := len(s.candidates[peerID]) + 1
		s.mu.Unlock()
		candidate := map[string]any{
			"id":            "cand-" + strconv.Itoa(nextID),
			"peerId":        peerID,
			"networkId":     "net-1",
			"type":          req.Type,
			"protocol":      req.Protocol,
			"address":       req.Address,
			"preference":    req.Preference,
			"reachable":     req.Reachable,
			"createdAtUnix": time.Now().Unix(),
			"expiresAtUnix": time.Now().Add(120 * time.Second).Unix(),
		}
		s.mu.Lock()
		s.candidates[peerID] = append(s.candidates[peerID], candidate)
		s.mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{"data": candidate})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *fakeUpstream) handleTunnelByID(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	if r.Method != http.MethodPatch {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tunnelID := strings.TrimPrefix(r.URL.Path, "/api/v1/tunnels/")
	var req struct {
		State string `json:"state"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	defer s.mu.Unlock()
	for idx := range s.tunnels {
		if asString(s.tunnels[idx]["id"]) != tunnelID {
			continue
		}
		s.tunnels[idx]["state"] = strings.ToUpper(strings.TrimSpace(req.State))
		writeJSON(w, http.StatusOK, map[string]any{"data": s.tunnels[idx]})
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
}

func (s *fakeUpstream) authorize(w http.ResponseWriter, r *http.Request) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) == 0 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return false
	}
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" || token != s.sessions[0]["accessToken"] {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return false
	}
	return true
}

func (s *fakeUpstream) newSession(suffix string, expiresAtUnix int64) map[string]any {
	return map[string]any{
		"id":             "ses-" + suffix,
		"userId":         "usr-1",
		"familyId":       "fam-1",
		"accessToken":    "acc-" + suffix,
		"refreshToken":   "ref-" + suffix,
		"deviceName":     "Ole Desktop",
		"ip":             "127.0.0.1",
		"userAgent":      "test",
		"lastUsedAtUnix": time.Now().Unix(),
		"expiresAtUnix":  expiresAtUnix,
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not satisfied within %s", timeout)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func reserveUDPBindEndpoint(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	if err := conn.Close(); err != nil {
		t.Fatalf("close reserved udp port: %v", err)
	}
	return "127.0.0.1:" + strconv.Itoa(port)
}

func samePair(a1, b1, a2, b2 string) bool {
	return (a1 == a2 && b1 == b2) || (a1 == b2 && b1 == a2)
}

func asString(value any) string {
	text, _ := value.(string)
	return text
}

func asInt64(value any) int64 {
	switch typed := value.(type) {
	case int64:
		return typed
	case int:
		return int64(typed)
	case float64:
		return int64(typed)
	default:
		return 0
	}
}

func asStrings(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text := asString(item); strings.TrimSpace(text) != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

func overlayCIDRForTestIP(virtualIP string) string {
	ip := net.ParseIP(strings.TrimSpace(virtualIP)).To4()
	if ip == nil {
		return ""
	}
	return strconv.Itoa(int(ip[0])) + "." + strconv.Itoa(int(ip[1])) + "." + strconv.Itoa(int(ip[2])) + ".0/24"
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstPositive(values ...int64) int64 {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func firstBindingAddress(bindings []directprobe.Binding, peerID string) string {
	peerID = strings.TrimSpace(peerID)
	for _, binding := range bindings {
		if strings.EqualFold(strings.TrimSpace(binding.PeerID), peerID) {
			return strings.TrimSpace(binding.ListenAddress)
		}
	}
	return ""
}

type fakeAdapterManager struct {
	mu       sync.Mutex
	status   virtualadapter.Status
	desired  []virtualadapter.NetworkConfig
	outbound []virtualadapter.Packet
	written  []virtualadapter.Packet
}

type fakeDirectManager struct {
	mu                 sync.Mutex
	bindings           []directprobe.Binding
	attempts           int
	establishes        int
	exchanges          int
	drops              int
	stunProbes         int
	successAfter       int
	alwaysFail         bool
	failEstablish      bool
	failExchange       bool
	forceExchangeError bool
	stunMappedAddress  string
	sessions           map[string]directprobe.Session
	sentPackets        [][]byte
	sentPacketDetails  []fakeDirectPacket
	inbound            map[string][]directprobe.Packet
	missingListeners   map[string]bool
	exchangeHandlers   map[string]directprobe.ExchangeHandler
}

type fakeDirectPacket struct {
	LocalPeerID  string
	RemotePeerID string
	Payload      []byte
}

type fakeRelayManager struct {
	mu               sync.Mutex
	bindings         []relaytransport.Binding
	establish        int
	exchange         int
	drops            int
	sessions         map[string]relaytransport.Session
	sentPackets      [][]byte
	inbound          map[string][]relaytransport.Packet
	establishErrors  map[string]error
	exchangeErrors   map[string]error
	sendErrors       map[string]error
	establishRelays  []string
	reconciledRelays []string
	exchangeHandlers map[string]relaytransport.ExchangeHandler
}

func (m *fakeDirectManager) Reconcile(bindings []directprobe.Binding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bindings = append([]directprobe.Binding(nil), bindings...)
	if len(bindings) == 0 {
		m.missingListeners = nil
		return nil
	}
	if m.missingListeners == nil {
		return nil
	}
	active := map[string]struct{}{}
	for _, binding := range bindings {
		active[binding.PeerID] = struct{}{}
		delete(m.missingListeners, binding.PeerID)
	}
	for peerID := range m.missingListeners {
		if _, ok := active[peerID]; !ok {
			delete(m.missingListeners, peerID)
		}
	}
	return nil
}

func (m *fakeDirectManager) Attempt(localPeerID, remotePeerID string, remoteCandidates []string, _ time.Duration) (directprobe.Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempts++
	if m.missingListeners[localPeerID] {
		return directprobe.Result{}, fmt.Errorf("no direct-probe listener for peer %s", localPeerID)
	}
	if m.alwaysFail || m.attempts < m.successAfter {
		return directprobe.Result{}, strconv.ErrSyntax
	}
	if len(remoteCandidates) == 0 {
		return directprobe.Result{}, strconv.ErrSyntax
	}
	return directprobe.Result{RemoteAddress: remoteCandidates[0]}, nil
}

func (m *fakeDirectManager) Establish(localPeerID, remotePeerID string, remoteCandidates []string, _ time.Duration) (directprobe.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.establishes++
	if m.missingListeners[localPeerID] {
		return directprobe.Session{}, fmt.Errorf("no direct-probe listener for peer %s", localPeerID)
	}
	if m.failEstablish || m.alwaysFail {
		return directprobe.Session{}, strconv.ErrSyntax
	}
	address := ""
	if len(remoteCandidates) > 0 {
		address = remoteCandidates[0]
	}
	session := directprobe.Session{
		SessionID:         "sess-" + strconv.Itoa(m.establishes),
		RemoteAddress:     address,
		EstablishedAtUnix: time.Now().Unix(),
	}
	if m.sessions == nil {
		m.sessions = map[string]directprobe.Session{}
	}
	m.sessions[localPeerID+"|"+remotePeerID] = session
	return session, nil
}

func (m *fakeDirectManager) Exchange(localPeerID, remotePeerID string, payload []byte, _ time.Duration) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.exchanges++
	if m.failExchange || m.alwaysFail || m.forceExchangeError {
		return nil, strconv.ErrSyntax
	}
	if m.missingListeners[localPeerID] {
		return nil, fmt.Errorf("no direct-probe listener for peer %s", localPeerID)
	}
	if m.sessions == nil || m.sessions[localPeerID+"|"+remotePeerID].SessionID == "" {
		return nil, fmt.Errorf("no encrypted session for peer %s", remotePeerID)
	}
	if handler := m.exchangeHandlers[remotePeerID]; handler != nil {
		if response := handler(localPeerID, append([]byte(nil), payload...)); response != nil {
			return response, nil
		}
	}
	return []byte("ack:" + string(payload)), nil
}

func (m *fakeDirectManager) SetExchangeHandler(localPeerID string, handler directprobe.ExchangeHandler) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.exchangeHandlers == nil {
		m.exchangeHandlers = map[string]directprobe.ExchangeHandler{}
	}
	if handler == nil {
		delete(m.exchangeHandlers, localPeerID)
		return nil
	}
	m.exchangeHandlers[localPeerID] = handler
	return nil
}

func (m *fakeDirectManager) SendPacket(localPeerID, remotePeerID string, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.missingListeners[localPeerID] {
		return fmt.Errorf("no direct-probe listener for peer %s", localPeerID)
	}
	if m.sessions == nil || m.sessions[localPeerID+"|"+remotePeerID].SessionID == "" {
		return fmt.Errorf("no encrypted session for peer %s", remotePeerID)
	}
	m.sentPackets = append(m.sentPackets, append([]byte(nil), payload...))
	m.sentPacketDetails = append(m.sentPacketDetails, fakeDirectPacket{
		LocalPeerID:  localPeerID,
		RemotePeerID: remotePeerID,
		Payload:      append([]byte(nil), payload...),
	})
	return nil
}

func (m *fakeDirectManager) ProbeSTUN(localPeerID, serverAddress string, _ time.Duration) (stun.ProbeResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stunProbes++
	if m.missingListeners[localPeerID] {
		return stun.ProbeResult{ServerAddress: strings.TrimSpace(serverAddress), NATType: stun.NATTypeUnknown}, fmt.Errorf("no direct-probe listener for peer %s", localPeerID)
	}
	mappedAddress := strings.TrimSpace(m.stunMappedAddress)
	if mappedAddress == "" {
		mappedAddress = "203.0.113.10:54000"
	}
	return stun.ProbeResult{
		ServerAddress: strings.TrimSpace(serverAddress),
		LocalAddress:  firstBindingAddress(m.bindings, localPeerID),
		MappedAddress: mappedAddress,
		NATType:       stun.NATTypeNAT,
	}, nil
}

func (m *fakeDirectManager) DrainInbound(localPeerID string, limit int) []directprobe.Packet {
	m.mu.Lock()
	defer m.mu.Unlock()
	packets := m.inbound[localPeerID]
	if limit <= 0 || limit > len(packets) {
		limit = len(packets)
	}
	if limit == 0 {
		return nil
	}
	out := append([]directprobe.Packet(nil), packets[:limit]...)
	m.inbound[localPeerID] = append([]directprobe.Packet(nil), packets[limit:]...)
	return out
}

func (m *fakeDirectManager) Close() error {
	return nil
}

func (m *fakeDirectManager) DropSession(localPeerID, remotePeerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drops++
	if m.sessions != nil {
		delete(m.sessions, localPeerID+"|"+remotePeerID)
	}
}

func (m *fakeDirectManager) AttemptCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.attempts
}

func (m *fakeDirectManager) AllowNextAttemptToSucceed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alwaysFail = false
	m.successAfter = m.attempts + 1
}

func (m *fakeDirectManager) EnableExchangeFailures() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forceExchangeError = true
}

func (m *fakeDirectManager) EstablishCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.establishes
}

func (m *fakeDirectManager) ExchangeCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.exchanges
}

func (m *fakeDirectManager) DropSessionCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.drops
}

func (m *fakeDirectManager) InjectInbound(localPeerID string, packet directprobe.Packet) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inbound == nil {
		m.inbound = map[string][]directprobe.Packet{}
	}
	m.inbound[localPeerID] = append(m.inbound[localPeerID], packet)
}

func (m *fakeDirectManager) SentPackets() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]byte, 0, len(m.sentPackets))
	for _, packet := range m.sentPackets {
		out = append(out, append([]byte(nil), packet...))
	}
	return out
}

func (m *fakeDirectManager) SentPacketCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sentPackets)
}

func (m *fakeDirectManager) SentPacketDetails() []fakeDirectPacket {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]fakeDirectPacket, 0, len(m.sentPacketDetails))
	for _, packet := range m.sentPacketDetails {
		out = append(out, fakeDirectPacket{
			LocalPeerID:  packet.LocalPeerID,
			RemotePeerID: packet.RemotePeerID,
			Payload:      append([]byte(nil), packet.Payload...),
		})
	}
	return out
}

func (m *fakeDirectManager) LastBindings() []directprobe.Binding {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]directprobe.Binding(nil), m.bindings...)
}

func (m *fakeDirectManager) STUNProbeCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stunProbes
}

func (m *fakeDirectManager) DropBinding(localPeerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.missingListeners == nil {
		m.missingListeners = map[string]bool{}
	}
	m.missingListeners[localPeerID] = true
	filtered := make([]directprobe.Binding, 0, len(m.bindings))
	for _, binding := range m.bindings {
		if binding.PeerID == localPeerID {
			continue
		}
		filtered = append(filtered, binding)
	}
	m.bindings = filtered
}

func (m *fakeRelayManager) Reconcile(bindings []relaytransport.Binding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bindings = append([]relaytransport.Binding(nil), bindings...)
	m.reconciledRelays = m.reconciledRelays[:0]
	for _, binding := range bindings {
		m.reconciledRelays = append(m.reconciledRelays, binding.RelayAddress)
	}
	return nil
}

func (m *fakeRelayManager) Establish(localPeerID, remotePeerID string, _ time.Duration) (relaytransport.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.establish++
	relayAddress := m.currentRelayAddressLocked(localPeerID)
	m.establishRelays = append(m.establishRelays, relayAddress)
	if err := m.establishErrors[relayAddress]; err != nil {
		return relaytransport.Session{}, err
	}
	session := relaytransport.Session{
		SessionID:         "relay-sess-" + strconv.Itoa(m.establish),
		RemoteAddress:     relayAddress,
		EstablishedAtUnix: time.Now().Unix(),
	}
	if m.sessions == nil {
		m.sessions = map[string]relaytransport.Session{}
	}
	m.sessions[localPeerID+"|"+remotePeerID] = session
	return session, nil
}

func (m *fakeRelayManager) Exchange(localPeerID, remotePeerID string, payload []byte, _ time.Duration) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.exchange++
	if err := m.exchangeErrors[m.currentRelayAddressLocked(localPeerID)]; err != nil {
		return nil, err
	}
	if m.sessions == nil || m.sessions[localPeerID+"|"+remotePeerID].SessionID == "" {
		return nil, fmt.Errorf("no relay session for peer %s", remotePeerID)
	}
	if handler := m.exchangeHandlers[remotePeerID]; handler != nil {
		if response := handler(localPeerID, append([]byte(nil), payload...)); response != nil {
			return response, nil
		}
	}
	return []byte("ack:" + string(payload)), nil
}

func (m *fakeRelayManager) SetExchangeHandler(localPeerID string, handler relaytransport.ExchangeHandler) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.exchangeHandlers == nil {
		m.exchangeHandlers = map[string]relaytransport.ExchangeHandler{}
	}
	if handler == nil {
		delete(m.exchangeHandlers, localPeerID)
		return nil
	}
	m.exchangeHandlers[localPeerID] = handler
	return nil
}

func (m *fakeRelayManager) SendPacket(localPeerID, remotePeerID string, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.sendErrors[m.currentRelayAddressLocked(localPeerID)]; err != nil {
		return err
	}
	if m.sessions == nil || m.sessions[localPeerID+"|"+remotePeerID].SessionID == "" {
		return fmt.Errorf("no relay session for peer %s", remotePeerID)
	}
	m.sentPackets = append(m.sentPackets, append([]byte(nil), payload...))
	return nil
}

func (m *fakeRelayManager) DrainInbound(localPeerID string, limit int) []relaytransport.Packet {
	m.mu.Lock()
	defer m.mu.Unlock()
	packets := m.inbound[localPeerID]
	if limit <= 0 || limit > len(packets) {
		limit = len(packets)
	}
	if limit == 0 {
		return nil
	}
	out := append([]relaytransport.Packet(nil), packets[:limit]...)
	m.inbound[localPeerID] = append([]relaytransport.Packet(nil), packets[limit:]...)
	return out
}

func (m *fakeRelayManager) DropSession(localPeerID, remotePeerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drops++
	if m.sessions != nil {
		delete(m.sessions, localPeerID+"|"+remotePeerID)
	}
}

func (m *fakeRelayManager) Close() error {
	return nil
}

func (m *fakeRelayManager) InjectInbound(localPeerID string, packet relaytransport.Packet) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inbound == nil {
		m.inbound = map[string][]relaytransport.Packet{}
	}
	m.inbound[localPeerID] = append(m.inbound[localPeerID], packet)
}

func (m *fakeRelayManager) EstablishCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.establish
}

func (m *fakeRelayManager) ExchangeCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.exchange
}

func (m *fakeRelayManager) SentPackets() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]byte, 0, len(m.sentPackets))
	for _, packet := range m.sentPackets {
		out = append(out, append([]byte(nil), packet...))
	}
	return out
}

func (m *fakeRelayManager) SentPacketCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sentPackets)
}

func (m *fakeRelayManager) DropSessionCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.drops
}

func (m *fakeRelayManager) EstablishRelayAddresses() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.establishRelays...)
}

func (m *fakeRelayManager) currentRelayAddressLocked(localPeerID string) string {
	for _, binding := range m.bindings {
		if binding.PeerID == localPeerID {
			return binding.RelayAddress
		}
	}
	if len(m.bindings) > 0 {
		return m.bindings[0].RelayAddress
	}
	return ""
}

func (m *fakeAdapterManager) Reconcile(desired []virtualadapter.NetworkConfig) (virtualadapter.Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.desired = append([]virtualadapter.NetworkConfig(nil), desired...)
	m.status = virtualadapter.Status{
		Enabled:     true,
		Available:   true,
		AdapterName: "Ole",
	}
	if len(desired) > 0 {
		m.status.DesiredMTU = desired[0].MTU
		m.status.MTU = desired[0].MTU
		m.status.DesiredDNSServer = desired[0].DNSServer
		m.status.SessionActive = true
		if desired[0].DNSServer != "" {
			m.status.DNSServers = []string{desired[0].DNSServer}
		} else {
			m.status.DNSServers = nil
		}
		m.status.DNSSuffix = desired[0].DNSSuffix
	}
	m.status.Networks = make([]virtualadapter.NetworkBinding, 0, len(desired))
	for _, network := range desired {
		policyStatus := strings.ToUpper(strings.TrimSpace(network.PolicyStatusHint))
		if policyStatus == "" {
			switch {
			case !strings.EqualFold(network.RoutingPolicy, "FULL"):
				policyStatus = "ACTIVE"
			case strings.EqualFold(network.GatewayRole, "GATEWAY"):
				policyStatus = "ACTIVE"
			case strings.EqualFold(network.GatewayRole, "CLIENT") && strings.TrimSpace(network.GatewayPeerID) != "" && strings.EqualFold(network.RoutePrefix, "0.0.0.0/0"):
				policyStatus = "ACTIVE"
			default:
				policyStatus = "PENDING_GATEWAY"
			}
		}
		m.status.Networks = append(m.status.Networks, virtualadapter.NetworkBinding{
			NetworkID:        network.NetworkID,
			VirtualIP:        network.VirtualIP,
			PrefixLength:     network.PrefixLength,
			OverlayCIDR:      network.OverlayCIDR,
			RoutePrefix:      network.RoutePrefix,
			RoutingPolicy:    network.RoutingPolicy,
			PolicyStatus:     policyStatus,
			GatewayRole:      network.GatewayRole,
			GatewayPeerID:    network.GatewayPeerID,
			IPAddressVisible: true,
			RouteVisible:     true,
		})
	}
	return m.status, nil
}

func (m *fakeAdapterManager) Snapshot() virtualadapter.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *fakeAdapterManager) Close() error {
	return nil
}

func (m *fakeAdapterManager) LastDesired() []virtualadapter.NetworkConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]virtualadapter.NetworkConfig(nil), m.desired...)
}

func (m *fakeAdapterManager) ReadPackets(limit int) ([]virtualadapter.Packet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > len(m.outbound) {
		limit = len(m.outbound)
	}
	if limit == 0 {
		return nil, nil
	}
	out := append([]virtualadapter.Packet(nil), m.outbound[:limit]...)
	m.outbound = append([]virtualadapter.Packet(nil), m.outbound[limit:]...)
	return out, nil
}

func (m *fakeAdapterManager) WritePackets(packets []virtualadapter.Packet) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, packet := range packets {
		m.written = append(m.written, virtualadapter.Packet{Data: append([]byte(nil), packet.Data...)})
	}
	return nil
}

func (m *fakeAdapterManager) EnqueueOutbound(packet []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outbound = append(m.outbound, virtualadapter.Packet{Data: append([]byte(nil), packet...)})
}

func (m *fakeAdapterManager) WrittenPackets() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]byte, 0, len(m.written))
	for _, packet := range m.written {
		out = append(out, append([]byte(nil), packet.Data...))
	}
	return out
}

type scriptedSTUNServer struct {
	mu            sync.Mutex
	conn          *net.UDPConn
	mappedAddress string
}

func newScriptedSTUNServer(listenAddress, mappedAddress string) (*scriptedSTUNServer, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", strings.TrimSpace(listenAddress))
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	server := &scriptedSTUNServer{
		conn:          conn,
		mappedAddress: strings.TrimSpace(mappedAddress),
	}
	go server.serve()
	return server, nil
}

func (s *scriptedSTUNServer) LocalAddr() net.Addr {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

func (s *scriptedSTUNServer) SetMappedAddress(mappedAddress string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mappedAddress = strings.TrimSpace(mappedAddress)
}

func (s *scriptedSTUNServer) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

func (s *scriptedSTUNServer) serve() {
	buffer := make([]byte, 512)
	for {
		n, remoteAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		transactionID, ok := decodeSTUNBindingTransactionID(buffer[:n])
		if !ok {
			continue
		}
		s.mu.Lock()
		mappedAddress := s.mappedAddress
		s.mu.Unlock()
		mappedAddr, err := net.ResolveUDPAddr("udp", mappedAddress)
		if err != nil {
			continue
		}
		response, err := stun.EncodeBindingSuccessResponse(transactionID, mappedAddr)
		if err != nil {
			continue
		}
		_, _ = s.conn.WriteToUDP(response, remoteAddr)
	}
}

func decodeSTUNBindingTransactionID(message []byte) ([12]byte, bool) {
	var transactionID [12]byte
	if len(message) < 20 {
		return transactionID, false
	}
	if message[0] != 0x00 || message[1] != 0x01 {
		return transactionID, false
	}
	if message[4] != 0x21 || message[5] != 0x12 || message[6] != 0xA4 || message[7] != 0x42 {
		return transactionID, false
	}
	copy(transactionID[:], message[8:20])
	return transactionID, true
}

func buildIPv4Packet(t *testing.T, sourceIP, destinationIP string, payload []byte) []byte {
	t.Helper()
	source := net.ParseIP(sourceIP).To4()
	destination := net.ParseIP(destinationIP).To4()
	if source == nil || destination == nil {
		t.Fatalf("invalid ipv4 endpoints: %s -> %s", sourceIP, destinationIP)
	}
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	packet[2] = byte(len(packet) >> 8)
	packet[3] = byte(len(packet))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], source)
	copy(packet[16:20], destination)
	copy(packet[20:], payload)
	return packet
}
