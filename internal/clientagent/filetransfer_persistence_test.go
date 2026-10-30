package clientagent

import (
	"Ole/internal/controlclient"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestStateStoreRoundTripsFileTransferSources(t *testing.T) {
	store := NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	state := defaultPersistentState()
	state.SetFileTransferSource(FileTransferSourceState{
		ServerBaseURL:  "http://example.invalid",
		UserID:         "user-1",
		TransferID:     "xfer-1",
		NetworkID:      "net-1",
		LocalPeerID:    "peer-local",
		RemotePeerID:   "peer-remote",
		SourcePath:     `C:\payload.bin`,
		FileName:       "payload.bin",
		ContentType:    "application/octet-stream",
		PayloadSHA256:  "sha-1",
		SizeBytes:      42,
		UploadedAtUnix: 123,
	})
	if err := store.Save(state); err != nil {
		t.Fatalf("save state: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(loaded.FileTransferSources) != 1 {
		t.Fatalf("expected 1 file transfer source, got %d", len(loaded.FileTransferSources))
	}
	got := loaded.FileTransferSources[0]
	if got.TransferID != "xfer-1" || got.NetworkID != "net-1" || got.LocalPeerID != "peer-local" || got.RemotePeerID != "peer-remote" {
		t.Fatalf("unexpected persisted peer mapping: %#v", got)
	}
	if got.SourcePath != `C:\payload.bin` || got.ContentType != "application/octet-stream" || got.PayloadSHA256 != "sha-1" {
		t.Fatalf("unexpected persisted file transfer source payload: %#v", got)
	}
	if got.SizeBytes != 42 || got.UploadedAtUnix != 123 {
		t.Fatalf("unexpected persisted file transfer source size metadata: %#v", got)
	}
}

func TestStateStoreRoundTripsFileTransferCaches(t *testing.T) {
	store := NewStateStore(filepath.Join(t.TempDir(), "agent-state.json"))
	state := defaultPersistentState()
	state.SetFileTransferCache(FileTransferCacheState{
		ServerBaseURL:  "http://example.invalid",
		UserID:         "user-1",
		TransferID:     "xfer-cache-1",
		NetworkID:      "net-1",
		LocalPeerID:    "peer-local",
		RemotePeerID:   "peer-remote",
		CachePath:      `C:\cache\xfer-cache-1.part`,
		FileName:       "payload.bin",
		ContentType:    "application/octet-stream",
		PayloadSHA256:  "sha-cache-1",
		SizeBytes:      128,
		CachedBytes:    64,
		UploadedAtUnix: 456,
	})
	if err := store.Save(state); err != nil {
		t.Fatalf("save state: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(loaded.FileTransferCaches) != 1 {
		t.Fatalf("expected 1 file transfer cache, got %d", len(loaded.FileTransferCaches))
	}
	got := loaded.FileTransferCaches[0]
	if got.TransferID != "xfer-cache-1" || got.NetworkID != "net-1" || got.LocalPeerID != "peer-local" || got.RemotePeerID != "peer-remote" {
		t.Fatalf("unexpected persisted peer mapping: %#v", got)
	}
	if got.CachePath != `C:\cache\xfer-cache-1.part` || got.ContentType != "application/octet-stream" || got.PayloadSHA256 != "sha-cache-1" {
		t.Fatalf("unexpected persisted file transfer cache payload: %#v", got)
	}
	if got.SizeBytes != 128 || got.CachedBytes != 64 || got.UploadedAtUnix != 456 {
		t.Fatalf("unexpected persisted file transfer cache size metadata: %#v", got)
	}
}

func TestAgentRestoresPersistedFileTransferSourcesAndPrunesInvalidOnes(t *testing.T) {
	tempDir := t.TempDir()
	store := NewStateStore(filepath.Join(tempDir, "agent-state.json"))
	payloadPath := filepath.Join(tempDir, "payload.bin")
	if err := os.WriteFile(payloadPath, []byte("ole-payload"), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	state := defaultPersistentState()
	state.SetManagedPeer("http://example.invalid", "user-1", "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	state.SetFileTransferSource(FileTransferSourceState{
		ServerBaseURL:  "http://example.invalid",
		UserID:         "user-1",
		TransferID:     "xfer-valid",
		NetworkID:      "net-1",
		LocalPeerID:    "peer-local",
		RemotePeerID:   "peer-remote",
		SourcePath:     payloadPath,
		FileName:       "payload.bin",
		ContentType:    "application/octet-stream",
		PayloadSHA256:  "sha-valid",
		SizeBytes:      int64(len("ole-payload")),
		UploadedAtUnix: 456,
	})
	state.SetFileTransferSource(FileTransferSourceState{
		ServerBaseURL:  "http://example.invalid",
		UserID:         "user-1",
		TransferID:     "xfer-missing",
		NetworkID:      "net-1",
		LocalPeerID:    "peer-local",
		RemotePeerID:   "peer-remote",
		SourcePath:     filepath.Join(tempDir, "missing.bin"),
		FileName:       "missing.bin",
		ContentType:    "application/octet-stream",
		PayloadSHA256:  "sha-missing",
		SizeBytes:      11,
		UploadedAtUnix: 789,
	})
	if err := store.Save(state); err != nil {
		t.Fatalf("save state: %v", err)
	}

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", store, RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()
	agent.currentUser = &controlclient.User{ID: "user-1", Email: "owner@example.com"}

	if err := agent.restorePersistedFileTransferSourcesLocked(); err != nil {
		t.Fatalf("restore persisted file transfer sources: %v", err)
	}

	if len(agent.fileTransferSources) != 1 {
		t.Fatalf("expected 1 restored in-memory source, got %d", len(agent.fileTransferSources))
	}
	source, ok := agent.fileTransferSources["xfer-valid"]
	if !ok {
		t.Fatalf("expected valid transfer source to restore, got %#v", agent.fileTransferSources)
	}
	if source.SourcePath != payloadPath || source.LocalPeerID != "peer-local" || source.RemotePeerID != "peer-remote" {
		t.Fatalf("unexpected restored source mapping: %#v", source)
	}
	if source.SizeBytes != int64(len("ole-payload")) || source.UploadedAtUnix != 456 || source.PayloadSHA256 != "sha-valid" {
		t.Fatalf("unexpected restored source metadata: %#v", source)
	}

	persisted, err := store.Load()
	if err != nil {
		t.Fatalf("reload pruned state: %v", err)
	}
	sources := persisted.FileTransferSourcesFor("http://example.invalid", "user-1")
	if len(sources) != 1 {
		t.Fatalf("expected 1 persisted source after prune, got %d", len(sources))
	}
	if sources[0].TransferID != "xfer-valid" {
		t.Fatalf("expected valid source to remain persisted, got %#v", sources[0])
	}
}

func TestAgentRestoresPersistedFileTransferCachesAndPrunesInvalidOnes(t *testing.T) {
	tempDir := t.TempDir()
	store := NewStateStore(filepath.Join(tempDir, "agent-state.json"))
	cachePath := filepath.Join(tempDir, "xfer-cache.part")
	if err := os.WriteFile(cachePath, []byte("ole-cache"), 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	state := defaultPersistentState()
	state.SetManagedPeer("http://example.invalid", "user-1", "net-1", "peer-local", "127.0.0.1:4000", "10.10.0.0/24", "10.10.0.2")
	state.SetFileTransferCache(FileTransferCacheState{
		ServerBaseURL:  "http://example.invalid",
		UserID:         "user-1",
		TransferID:     "xfer-cache-valid",
		NetworkID:      "net-1",
		LocalPeerID:    "peer-local",
		RemotePeerID:   "peer-remote",
		CachePath:      cachePath,
		FileName:       "payload.bin",
		ContentType:    "application/octet-stream",
		PayloadSHA256:  "sha-cache-valid",
		SizeBytes:      64,
		CachedBytes:    int64(len("ole-cache")),
		UploadedAtUnix: 654,
	})
	state.SetFileTransferCache(FileTransferCacheState{
		ServerBaseURL:  "http://example.invalid",
		UserID:         "user-1",
		TransferID:     "xfer-cache-missing",
		NetworkID:      "net-1",
		LocalPeerID:    "peer-local",
		RemotePeerID:   "peer-remote",
		CachePath:      filepath.Join(tempDir, "missing.part"),
		FileName:       "missing.bin",
		ContentType:    "application/octet-stream",
		PayloadSHA256:  "sha-cache-missing",
		SizeBytes:      64,
		CachedBytes:    11,
		UploadedAtUnix: 987,
	})
	if err := store.Save(state); err != nil {
		t.Fatalf("save state: %v", err)
	}

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", store, RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()
	agent.currentUser = &controlclient.User{ID: "user-1", Email: "owner@example.com"}

	if err := agent.restorePersistedFileTransferCachesLocked(); err != nil {
		t.Fatalf("restore persisted file transfer caches: %v", err)
	}

	if len(agent.fileTransferCaches) != 1 {
		t.Fatalf("expected 1 restored in-memory cache, got %d", len(agent.fileTransferCaches))
	}
	cache, ok := agent.fileTransferCaches["xfer-cache-valid"]
	if !ok {
		t.Fatalf("expected valid file transfer cache to restore, got %#v", agent.fileTransferCaches)
	}
	if cache.CachePath != cachePath || cache.LocalPeerID != "peer-local" || cache.RemotePeerID != "peer-remote" {
		t.Fatalf("unexpected restored cache mapping: %#v", cache)
	}
	if cache.SizeBytes != 64 || cache.CachedBytes != int64(len("ole-cache")) || cache.UploadedAtUnix != 654 || cache.PayloadSHA256 != "sha-cache-valid" {
		t.Fatalf("unexpected restored cache metadata: %#v", cache)
	}

	persisted, err := store.Load()
	if err != nil {
		t.Fatalf("reload pruned state: %v", err)
	}
	caches := persisted.FileTransferCachesFor("http://example.invalid", "user-1")
	if len(caches) != 1 {
		t.Fatalf("expected 1 persisted cache after prune, got %d", len(caches))
	}
	if caches[0].TransferID != "xfer-cache-valid" {
		t.Fatalf("expected valid cache to remain persisted, got %#v", caches[0])
	}
}

func TestAgentRestoresPersistedFileTransferSourcesAcrossManagedPeerReRegistration(t *testing.T) {
	tempDir := t.TempDir()
	store := NewStateStore(filepath.Join(tempDir, "agent-state.json"))
	payloadPath := filepath.Join(tempDir, "payload.bin")
	if err := os.WriteFile(payloadPath, []byte("ole-payload"), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	state := defaultPersistentState()
	state.SetManagedPeer("http://example.invalid", "user-1", "net-1", "peer-replacement", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.9")
	state.SetFileTransferSource(FileTransferSourceState{
		ServerBaseURL:  "http://example.invalid",
		UserID:         "user-1",
		TransferID:     "xfer-rebind-source",
		NetworkID:      "net-1",
		LocalPeerID:    "peer-old",
		RemotePeerID:   "peer-remote",
		SourcePath:     payloadPath,
		FileName:       "payload.bin",
		ContentType:    "application/octet-stream",
		PayloadSHA256:  "sha-rebind-source",
		SizeBytes:      int64(len("ole-payload")),
		UploadedAtUnix: 456,
	})
	if err := store.Save(state); err != nil {
		t.Fatalf("save state: %v", err)
	}

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", store, RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()
	agent.currentUser = &controlclient.User{ID: "user-1", Email: "owner@example.com"}

	if err := agent.restorePersistedFileTransferSourcesLocked(); err != nil {
		t.Fatalf("restore persisted file transfer sources across peer re-registration: %v", err)
	}

	source, ok := agent.fileTransferSources["xfer-rebind-source"]
	if !ok {
		t.Fatalf("expected transfer source to survive peer re-registration, got %#v", agent.fileTransferSources)
	}
	if source.LocalPeerID != "peer-replacement" {
		t.Fatalf("expected restored source to rebind onto replacement peer, got %#v", source)
	}

	persisted, err := store.Load()
	if err != nil {
		t.Fatalf("reload rebound state: %v", err)
	}
	sources := persisted.FileTransferSourcesFor("http://example.invalid", "user-1")
	if len(sources) != 1 || sources[0].LocalPeerID != "peer-replacement" {
		t.Fatalf("expected persisted source to rebind onto replacement peer, got %#v", sources)
	}
}

func TestAgentRestoresPersistedFileTransferCachesAcrossManagedPeerReRegistration(t *testing.T) {
	tempDir := t.TempDir()
	store := NewStateStore(filepath.Join(tempDir, "agent-state.json"))
	cachePath := filepath.Join(tempDir, "xfer-cache.part")
	if err := os.WriteFile(cachePath, []byte("ole-cache"), 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	state := defaultPersistentState()
	state.SetManagedPeer("http://example.invalid", "user-1", "net-1", "peer-replacement", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.9")
	state.SetFileTransferCache(FileTransferCacheState{
		ServerBaseURL:  "http://example.invalid",
		UserID:         "user-1",
		TransferID:     "xfer-rebind-cache",
		NetworkID:      "net-1",
		LocalPeerID:    "peer-old",
		RemotePeerID:   "peer-remote",
		CachePath:      cachePath,
		FileName:       "payload.bin",
		ContentType:    "application/octet-stream",
		PayloadSHA256:  "sha-rebind-cache",
		SizeBytes:      64,
		CachedBytes:    int64(len("ole-cache")),
		UploadedAtUnix: 654,
	})
	if err := store.Save(state); err != nil {
		t.Fatalf("save state: %v", err)
	}

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", store, RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()
	agent.currentUser = &controlclient.User{ID: "user-1", Email: "owner@example.com"}

	if err := agent.restorePersistedFileTransferCachesLocked(); err != nil {
		t.Fatalf("restore persisted file transfer caches across peer re-registration: %v", err)
	}

	cache, ok := agent.fileTransferCaches["xfer-rebind-cache"]
	if !ok {
		t.Fatalf("expected file transfer cache to survive peer re-registration, got %#v", agent.fileTransferCaches)
	}
	if cache.LocalPeerID != "peer-replacement" {
		t.Fatalf("expected restored cache to rebind onto replacement peer, got %#v", cache)
	}

	persisted, err := store.Load()
	if err != nil {
		t.Fatalf("reload rebound cache state: %v", err)
	}
	caches := persisted.FileTransferCachesFor("http://example.invalid", "user-1")
	if len(caches) != 1 || caches[0].LocalPeerID != "peer-replacement" {
		t.Fatalf("expected persisted cache to rebind onto replacement peer, got %#v", caches)
	}
}

func TestAgentPrunesFileTransferSourcesByRebindingToReplacementManagedPeer(t *testing.T) {
	tempDir := t.TempDir()
	store := NewStateStore(filepath.Join(tempDir, "agent-state.json"))
	payloadPath := filepath.Join(tempDir, "payload.bin")
	if err := os.WriteFile(payloadPath, []byte("ole-payload"), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", store, RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()
	agent.currentUser = &controlclient.User{ID: "user-1", Email: "owner@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer("http://example.invalid", "user-1", "net-1", "peer-replacement", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.9")
	agent.fileTransferSources["xfer-rebind-source"] = localFileTransferSource{
		TransferID:     "xfer-rebind-source",
		NetworkID:      "net-1",
		LocalPeerID:    "peer-old",
		RemotePeerID:   "peer-remote",
		SourcePath:     payloadPath,
		FileName:       "payload.bin",
		ContentType:    "application/octet-stream",
		PayloadSHA256:  "sha-rebind-source",
		SizeBytes:      int64(len("ole-payload")),
		UploadedAtUnix: 456,
	}
	agent.deviceState.SetFileTransferSource(FileTransferSourceState{
		ServerBaseURL:  "http://example.invalid",
		UserID:         "user-1",
		TransferID:     "xfer-rebind-source",
		NetworkID:      "net-1",
		LocalPeerID:    "peer-old",
		RemotePeerID:   "peer-remote",
		SourcePath:     payloadPath,
		FileName:       "payload.bin",
		ContentType:    "application/octet-stream",
		PayloadSHA256:  "sha-rebind-source",
		SizeBytes:      int64(len("ole-payload")),
		UploadedAtUnix: 456,
	})
	if err := agent.savePersistentStateLocked(); err != nil {
		t.Fatalf("save source state: %v", err)
	}

	managedPeers := agent.deviceState.ManagedPeersFor("http://example.invalid", "user-1")
	if err := agent.pruneFileTransferSourcesLocked(managedPeers); err != nil {
		t.Fatalf("prune sources with replacement peer: %v", err)
	}

	source := agent.fileTransferSources["xfer-rebind-source"]
	if source.LocalPeerID != "peer-replacement" {
		t.Fatalf("expected in-memory source to rebind onto replacement peer, got %#v", source)
	}
	persisted, err := store.Load()
	if err != nil {
		t.Fatalf("reload rebound source state: %v", err)
	}
	sources := persisted.FileTransferSourcesFor("http://example.invalid", "user-1")
	if len(sources) != 1 || sources[0].LocalPeerID != "peer-replacement" {
		t.Fatalf("expected persisted source to rebind during prune, got %#v", sources)
	}
}

func TestAgentPrunesFileTransferCachesByRebindingToReplacementManagedPeer(t *testing.T) {
	tempDir := t.TempDir()
	store := NewStateStore(filepath.Join(tempDir, "agent-state.json"))
	cachePath := filepath.Join(tempDir, "xfer-cache.part")
	if err := os.WriteFile(cachePath, []byte("ole-cache"), 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", store, RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()
	agent.currentUser = &controlclient.User{ID: "user-1", Email: "owner@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer("http://example.invalid", "user-1", "net-1", "peer-replacement", "127.0.0.1:4001", "10.10.0.0/24", "10.10.0.9")
	agent.fileTransferCaches["xfer-rebind-cache"] = localFileTransferCache{
		TransferID:     "xfer-rebind-cache",
		NetworkID:      "net-1",
		LocalPeerID:    "peer-old",
		RemotePeerID:   "peer-remote",
		CachePath:      cachePath,
		FileName:       "payload.bin",
		ContentType:    "application/octet-stream",
		PayloadSHA256:  "sha-rebind-cache",
		SizeBytes:      64,
		CachedBytes:    int64(len("ole-cache")),
		UploadedAtUnix: 654,
	}
	agent.deviceState.SetFileTransferCache(FileTransferCacheState{
		ServerBaseURL:  "http://example.invalid",
		UserID:         "user-1",
		TransferID:     "xfer-rebind-cache",
		NetworkID:      "net-1",
		LocalPeerID:    "peer-old",
		RemotePeerID:   "peer-remote",
		CachePath:      cachePath,
		FileName:       "payload.bin",
		ContentType:    "application/octet-stream",
		PayloadSHA256:  "sha-rebind-cache",
		SizeBytes:      64,
		CachedBytes:    int64(len("ole-cache")),
		UploadedAtUnix: 654,
	})
	if err := agent.savePersistentStateLocked(); err != nil {
		t.Fatalf("save cache state: %v", err)
	}

	managedPeers := agent.deviceState.ManagedPeersFor("http://example.invalid", "user-1")
	if err := agent.pruneFileTransferCachesLocked(managedPeers); err != nil {
		t.Fatalf("prune caches with replacement peer: %v", err)
	}

	cache := agent.fileTransferCaches["xfer-rebind-cache"]
	if cache.LocalPeerID != "peer-replacement" {
		t.Fatalf("expected in-memory cache to rebind onto replacement peer, got %#v", cache)
	}
	persisted, err := store.Load()
	if err != nil {
		t.Fatalf("reload rebound cache state: %v", err)
	}
	caches := persisted.FileTransferCachesFor("http://example.invalid", "user-1")
	if len(caches) != 1 || caches[0].LocalPeerID != "peer-replacement" {
		t.Fatalf("expected persisted cache to rebind during prune, got %#v", caches)
	}
}

func TestIPCGetFileTransferLocalStateExposesSenderSourceAndReceiverCache(t *testing.T) {
	tempDir := t.TempDir()
	sourcePath := filepath.Join(tempDir, "payload.bin")
	if err := os.WriteFile(sourcePath, []byte("ole-source"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	cachePath := filepath.Join(tempDir, "xfer-cache.part")
	if err := os.WriteFile(cachePath, []byte("ole-cache"), 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(tempDir, "agent-state.json")), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()
	agent.currentUser = &controlclient.User{ID: "user-1", Email: "owner@example.com"}
	agent.fileTransferSources["xfer-1"] = localFileTransferSource{
		TransferID:     "xfer-1",
		NetworkID:      "net-1",
		LocalPeerID:    "peer-local",
		RemotePeerID:   "peer-remote",
		SourcePath:     sourcePath,
		FileName:       "payload.bin",
		ContentType:    "application/octet-stream",
		SizeBytes:      int64(len("ole-source")),
		UploadedAtUnix: 111,
	}
	agent.fileTransferCaches["xfer-1"] = localFileTransferCache{
		TransferID:     "xfer-1",
		NetworkID:      "net-1",
		LocalPeerID:    "peer-local",
		RemotePeerID:   "peer-remote",
		CachePath:      cachePath,
		FileName:       "payload.bin",
		ContentType:    "application/octet-stream",
		SizeBytes:      64,
		CachedBytes:    int64(len("ole-cache")),
		UploadedAtUnix: 222,
	}

	server := httptest.NewServer(agent.Handler())
	defer server.Close()
	client := NewIPCClient(server.URL)

	localState, err := client.GetFileTransferLocalState("xfer-1")
	if err != nil {
		t.Fatalf("get local file transfer state: %v", err)
	}
	if !localState.SenderSourceRegistered || !localState.SenderSourceAvailable || localState.SenderSourcePath != sourcePath {
		t.Fatalf("expected sender source details, got %#v", localState)
	}
	if !localState.ReceiverCacheAvailable || localState.ReceiverCachePath != cachePath || localState.ReceiverCachedBytes != int64(len("ole-cache")) {
		t.Fatalf("expected receiver cache details, got %#v", localState)
	}
	if localState.ReceiverCacheComplete {
		t.Fatalf("expected partial receiver cache, got %#v", localState)
	}
}
