package clientagent

import (
	"Ole/internal/controlclient"
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDownloadFileTransferContentChunkViaDataplaneSurvivesPeerReRegistration(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	sender := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sender-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer sender.Close()
	receiver := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "receiver-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiver.Close()

	payload := bytes.Repeat([]byte("ole-rebind"), (fileTransferDataplaneChunkBytes/10)+8)
	sourcePath := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write sender payload: %v", err)
	}

	sender.discoveredPeers["net-1"] = []controlclient.Peer{{
		ID:        "peer-receiver-new",
		UserID:    "user-receiver",
		NetworkID: "net-1",
	}}
	sender.fileTransferSources = map[string]localFileTransferSource{
		"xfer-rebind": {
			TransferID:     "xfer-rebind",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender-new",
			RemotePeerID:   "peer-receiver-old",
			RemoteUserID:   "user-receiver",
			SourcePath:     sourcePath,
			FileName:       "payload.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-rebind",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 123,
		},
	}
	if err := manager.SetExchangeHandler("peer-sender-new", sender.transportExchangeHandler("peer-sender-new")); err != nil {
		t.Fatalf("set sender exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-new", "peer-sender-new", []string{"127.0.0.1:43160"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish dataplane session: %v", err)
	}

	receiver.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	receiver.deviceState = defaultPersistentState()
	receiver.deviceState.SetManagedPeer(receiver.remote.BaseURL(), receiver.currentUser.ID, "net-1", "peer-receiver-new", "127.0.0.1:43160", "10.0.0.0/24", "10.0.0.9")
	receiver.discoveredPeers["net-1"] = []controlclient.Peer{{
		ID:        "peer-sender-new",
		UserID:    "user-sender",
		NetworkID: "net-1",
	}}
	receiver.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-receiver-new",
		RemotePeerID:   "peer-sender-new",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}

	chunk, err := receiver.downloadFileTransferContentChunkViaDataplaneLocked(controlclient.FileTransfer{
		ID:         "xfer-rebind",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-receiver-old",
		ToUserID:   "user-receiver",
		FileName:   "payload.bin",
		SizeBytes:  int64(len(payload)),
	}, 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download dataplane chunk after peer re-registration: %v", err)
	}
	if chunk == nil || !bytes.Equal(chunk.Payload, payload) {
		t.Fatalf("expected replacement peer path to preserve dataplane payload, got %#v", chunk)
	}
	if chunk.LocalPeerID != "peer-receiver-new" || chunk.RemotePeerID != "peer-sender-new" {
		t.Fatalf("expected dataplane transfer to use replacement peer pair, got %#v", chunk)
	}
}

func TestDownloadFileTransferContentChunkViaReceiverPeerCacheSurvivesMissingDiscoveryPeerRecord(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	cacheHolder := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "cache-holder-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer cacheHolder.Close()
	requester := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "requester-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer requester.Close()

	payload := bytes.Repeat([]byte("ole-peer-cache"), 4096)
	cachePath := filepath.Join(t.TempDir(), "peer-cache.bin")
	if err := os.WriteFile(cachePath, payload, 0o600); err != nil {
		t.Fatalf("write peer cache payload: %v", err)
	}

	cacheHolder.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	cacheHolder.fileTransferCaches = map[string]localFileTransferCache{
		"xfer-peer-cache-rebind": {
			TransferID:     "xfer-peer-cache-rebind",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-receiver-a-new",
			RemotePeerID:   "peer-receiver-b-old",
			CachePath:      cachePath,
			FileName:       "peer-cache.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-peer-cache-rebind",
			SizeBytes:      int64(len(payload)),
			CachedBytes:    int64(len(payload)),
			UploadedAtUnix: 456,
		},
	}
	cacheHolder.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-receiver-a-new",
		RemotePeerID:   "peer-receiver-b-new",
		RemoteUserID:   "user-receiver",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}
	if err := manager.SetExchangeHandler("peer-receiver-a-new", cacheHolder.transportExchangeHandler("peer-receiver-a-new")); err != nil {
		t.Fatalf("set cache-holder exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-b-new", "peer-receiver-a-new", []string{"127.0.0.1:43170"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish requester -> cache-holder session: %v", err)
	}

	requester.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	requester.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-receiver-b-new",
		RemotePeerID:   "peer-receiver-a-new",
		RemoteUserID:   "user-receiver",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}

	chunk, err := requester.downloadFileTransferContentChunkViaReceiverCacheLocked(controlclient.FileTransfer{
		ID:         "xfer-peer-cache-rebind",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-receiver-a-old",
		ToUserID:   "user-receiver",
		FileName:   "peer-cache.bin",
		SizeBytes:  int64(len(payload)),
	}, 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download peer-cache chunk after discovery peer loss: %v", err)
	}
	if chunk == nil || !bytes.Equal(chunk.Payload, payload) {
		t.Fatalf("expected live same-user peer cache to survive missing discovery peer record, got %#v", chunk)
	}
	if chunk.LocalPeerID != "peer-receiver-b-new" || chunk.RemotePeerID != "peer-receiver-a-new" {
		t.Fatalf("expected peer-cache download to use replacement peer pair, got %#v", chunk)
	}
}

func TestDownloadFileTransferContentChunkViaReceiverPeerCacheSurvivesMetadataGapOnBothPeers(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	cacheHolder := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "cache-holder-metadata-gap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer cacheHolder.Close()
	requester := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "requester-metadata-gap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer requester.Close()

	payload := bytes.Repeat([]byte("ole-peer-cache-metadata-gap"), 2048)
	cachePath := filepath.Join(t.TempDir(), "peer-cache-metadata-gap.bin")
	if err := os.WriteFile(cachePath, payload, 0o600); err != nil {
		t.Fatalf("write peer cache payload: %v", err)
	}

	cacheHolder.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	cacheHolder.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-requester-old", UserID: "user-receiver", NetworkID: "net-1", VirtualIP: "10.0.0.9"},
	}
	cacheHolder.fileTransferCaches = map[string]localFileTransferCache{
		"xfer-peer-cache-metadata-gap": {
			TransferID:     "xfer-peer-cache-metadata-gap",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-cache-holder-new",
			RemotePeerID:   "peer-requester-old",
			CachePath:      cachePath,
			FileName:       "peer-cache-metadata-gap.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-peer-cache-metadata-gap",
			SizeBytes:      int64(len(payload)),
			CachedBytes:    int64(len(payload)),
			UploadedAtUnix: 654,
		},
	}
	cacheHolder.connections = []ConnectionStatus{{
		NetworkID:        "net-1",
		LocalPeerID:      "peer-cache-holder-new",
		RemotePeerID:     "peer-requester-new",
		RemoteVirtualIP:  "10.0.0.9",
		TransportReady:   true,
		TransportMode:    "DIRECT",
		State:            "CONNECTED",
		Reachability:     "DIRECT",
		AverageRTTMillis: 12,
		LastRTTMillis:    10,
	}}
	if err := manager.SetExchangeHandler("peer-cache-holder-new", cacheHolder.transportExchangeHandler("peer-cache-holder-new")); err != nil {
		t.Fatalf("set cache-holder exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-requester-new", "peer-cache-holder-new", []string{"127.0.0.1:43172"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish requester -> cache-holder session: %v", err)
	}

	requester.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	requester.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-cache-holder-old", UserID: "user-receiver", NetworkID: "net-1", VirtualIP: "10.0.0.4"},
	}
	requester.connections = []ConnectionStatus{{
		NetworkID:        "net-1",
		LocalPeerID:      "peer-requester-new",
		RemotePeerID:     "peer-cache-holder-new",
		RemoteVirtualIP:  "10.0.0.4",
		TransportReady:   true,
		TransportMode:    "DIRECT",
		State:            "CONNECTED",
		Reachability:     "DIRECT",
		AverageRTTMillis: 12,
		LastRTTMillis:    10,
	}}

	chunk, err := requester.downloadFileTransferContentChunkViaReceiverCacheLocked(controlclient.FileTransfer{
		ID:         "xfer-peer-cache-metadata-gap",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-cache-holder-old",
		FileName:   "peer-cache-metadata-gap.bin",
		SizeBytes:  int64(len(payload)),
	}, 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download peer-cache chunk during same-user metadata gap: %v", err)
	}
	if chunk == nil || !bytes.Equal(chunk.Payload, payload) {
		t.Fatalf("expected same-user peer cache to survive metadata-gap replacement handoff, got %#v", chunk)
	}
	if chunk.LocalPeerID != "peer-requester-new" || chunk.RemotePeerID != "peer-cache-holder-new" {
		t.Fatalf("expected peer-cache metadata-gap handoff to use live replacement peer pair, got %#v", chunk)
	}
}

func TestDownloadFileTransferContentChunkViaDataplaneSurvivesMetadataGapOnBothPeers(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	sender := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sender-metadata-gap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer sender.Close()
	receiver := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "receiver-metadata-gap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiver.Close()

	payload := bytes.Repeat([]byte("ole-dataplane-metadata-gap"), (fileTransferDataplaneChunkBytes/14)+7)
	sourcePath := filepath.Join(t.TempDir(), "dataplane-metadata-gap.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write sender payload: %v", err)
	}

	sender.currentUser = &controlclient.User{ID: "user-sender", Email: "sender@example.com"}
	sender.deviceState = defaultPersistentState()
	sender.deviceState.SetManagedPeer(sender.remote.BaseURL(), sender.currentUser.ID, "net-1", "peer-sender-new", "127.0.0.1:43171", "10.0.0.0/24", "10.0.0.3")
	sender.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-receiver-old", UserID: "user-receiver", NetworkID: "net-1", VirtualIP: "10.0.0.9"},
	}
	sender.fileTransferSources = map[string]localFileTransferSource{
		"xfer-dataplane-metadata-gap": {
			TransferID:     "xfer-dataplane-metadata-gap",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender-new",
			RemotePeerID:   "peer-receiver-old",
			RemoteUserID:   "user-receiver",
			SourcePath:     sourcePath,
			FileName:       "dataplane-metadata-gap.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-dataplane-metadata-gap",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 987,
		},
	}
	sender.connections = []ConnectionStatus{{
		NetworkID:        "net-1",
		LocalPeerID:      "peer-sender-new",
		RemotePeerID:     "peer-receiver-new",
		RemoteVirtualIP:  "10.0.0.9",
		TransportReady:   true,
		TransportMode:    "DIRECT",
		State:            "CONNECTED",
		Reachability:     "DIRECT",
		AverageRTTMillis: 14,
		LastRTTMillis:    11,
	}}
	sender.deviceState.SetFileTransferSource(sender.fileTransferSourceStateLocked(sender.fileTransferSources["xfer-dataplane-metadata-gap"]))
	if err := sender.savePersistentStateLocked(); err != nil {
		t.Fatalf("persist sender metadata-gap source state: %v", err)
	}
	if err := manager.SetExchangeHandler("peer-sender-new", sender.transportExchangeHandler("peer-sender-new")); err != nil {
		t.Fatalf("set sender exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-new", "peer-sender-new", []string{"127.0.0.1:43171"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish dataplane session: %v", err)
	}

	receiver.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	receiver.deviceState = defaultPersistentState()
	receiver.deviceState.SetManagedPeer(receiver.remote.BaseURL(), receiver.currentUser.ID, "net-1", "peer-receiver-new", "127.0.0.1:43171", "10.0.0.0/24", "10.0.0.9")
	receiver.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-sender-old", UserID: "user-sender", NetworkID: "net-1", VirtualIP: "10.0.0.3"},
	}
	receiver.connections = []ConnectionStatus{{
		NetworkID:        "net-1",
		LocalPeerID:      "peer-receiver-new",
		RemotePeerID:     "peer-sender-new",
		RemoteVirtualIP:  "10.0.0.3",
		TransportReady:   true,
		TransportMode:    "DIRECT",
		State:            "CONNECTED",
		Reachability:     "DIRECT",
		AverageRTTMillis: 14,
		LastRTTMillis:    11,
	}}

	chunk, err := receiver.downloadFileTransferContentChunkViaDataplaneLocked(controlclient.FileTransfer{
		ID:         "xfer-dataplane-metadata-gap",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-receiver-old",
		ToUserID:   "user-receiver",
		FileName:   "dataplane-metadata-gap.bin",
		SizeBytes:  int64(len(payload)),
	}, 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download dataplane chunk during metadata gap: %v", err)
	}
	if chunk == nil || !bytes.Equal(chunk.Payload, payload) {
		t.Fatalf("expected sender-online dataplane to survive metadata-gap replacement handoff, got %#v", chunk)
	}
	if chunk.LocalPeerID != "peer-receiver-new" || chunk.RemotePeerID != "peer-sender-new" {
		t.Fatalf("expected dataplane metadata-gap handoff to use live replacement peer pair, got %#v", chunk)
	}
	if sender.fileTransferSources["xfer-dataplane-metadata-gap"].RemotePeerID != "peer-receiver-new" {
		t.Fatalf("expected sender source metadata to rebind onto replacement receiver peer, got %#v", sender.fileTransferSources["xfer-dataplane-metadata-gap"])
	}
	persistedSender, err := sender.stateStore.Load()
	if err != nil {
		t.Fatalf("reload sender metadata-gap source state: %v", err)
	}
	sources := persistedSender.FileTransferSourcesFor(sender.remote.BaseURL(), sender.currentUser.ID)
	if len(sources) != 1 || sources[0].RemotePeerID != "peer-receiver-new" {
		t.Fatalf("expected persisted sender source metadata to keep replacement receiver peer, got %#v", sources)
	}
}

func TestDownloadFileTransferContentChunkViaDataplanePrefersFresherReplacementReceiverPeerDuringOverlap(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	sender := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sender-overlap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer sender.Close()
	receiver := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "receiver-overlap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiver.Close()

	payload := bytes.Repeat([]byte("ole-overlap"), (fileTransferDataplaneChunkBytes/12)+17)
	sourcePath := filepath.Join(t.TempDir(), "overlap-payload.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write sender payload: %v", err)
	}

	sender.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-receiver-old", UserID: "user-receiver", NetworkID: "net-1"},
		{ID: "peer-receiver-new", UserID: "user-receiver", NetworkID: "net-1"},
	}
	sender.fileTransferSources = map[string]localFileTransferSource{
		"xfer-overlap-download": {
			TransferID:     "xfer-overlap-download",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender-old",
			RemotePeerID:   "peer-receiver-old",
			RemoteUserID:   "user-receiver",
			SourcePath:     sourcePath,
			FileName:       "overlap-payload.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-overlap-download",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 123,
		},
	}
	if err := manager.SetExchangeHandler("peer-sender-old", sender.transportExchangeHandler("peer-sender-old")); err != nil {
		t.Fatalf("set sender exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-old", "peer-sender-old", []string{"127.0.0.1:43180"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish old receiver dataplane session: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-new", "peer-sender-old", []string{"127.0.0.1:43181"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish replacement receiver dataplane session: %v", err)
	}

	receiver.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	receiver.deviceState = defaultPersistentState()
	receiver.deviceState.SetManagedPeer(receiver.remote.BaseURL(), receiver.currentUser.ID, "net-1", "peer-receiver-old", "127.0.0.1:43180", "10.0.0.0/24", "10.0.0.9")
	receiver.deviceState.SetManagedPeer(receiver.remote.BaseURL(), receiver.currentUser.ID, "net-1", "peer-receiver-new", "127.0.0.1:43181", "10.0.0.0/24", "10.0.0.9")
	receiver.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-receiver-old",
			RemotePeerID:             "peer-sender-old",
			RemoteUserID:             "user-sender",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			TransportEstablishedUnix: 100,
			LastTransportUnix:        150,
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-receiver-new",
			RemotePeerID:             "peer-sender-old",
			RemoteUserID:             "user-sender",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
	}

	chunk, err := receiver.downloadFileTransferContentChunkViaDataplaneLocked(controlclient.FileTransfer{
		ID:         "xfer-overlap-download",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-receiver-old",
		ToUserID:   "user-receiver",
		FileName:   "overlap-payload.bin",
		SizeBytes:  int64(len(payload)),
	}, 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download dataplane chunk during overlapping receiver peer replacement: %v", err)
	}
	if chunk == nil || !bytes.Equal(chunk.Payload, payload) {
		t.Fatalf("expected overlapping receiver replacement path to preserve dataplane payload, got %#v", chunk)
	}
	if chunk.LocalPeerID != "peer-receiver-new" || chunk.RemotePeerID != "peer-sender-old" {
		t.Fatalf("expected dataplane transfer to prefer fresher replacement receiver peer, got %#v", chunk)
	}
}

func TestDownloadFileTransferContentChunkViaReceiverPeerCachePrefersFresherReplacementRequesterPeerDuringOverlap(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	cacheHolder := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "cache-holder-overlap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer cacheHolder.Close()
	requester := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "requester-overlap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer requester.Close()

	payload := bytes.Repeat([]byte("ole-overlap-cache"), 4096)
	cachePath := filepath.Join(t.TempDir(), "overlap-peer-cache.bin")
	if err := os.WriteFile(cachePath, payload, 0o600); err != nil {
		t.Fatalf("write peer cache payload: %v", err)
	}

	cacheHolder.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	cacheHolder.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-requester-old", UserID: "user-receiver", NetworkID: "net-1"},
		{ID: "peer-requester-new", UserID: "user-receiver", NetworkID: "net-1"},
	}
	cacheHolder.fileTransferCaches = map[string]localFileTransferCache{
		"xfer-overlap-peer-cache": {
			TransferID:     "xfer-overlap-peer-cache",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-cache-holder-old",
			RemotePeerID:   "peer-requester-old",
			CachePath:      cachePath,
			FileName:       "overlap-peer-cache.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-overlap-peer-cache",
			SizeBytes:      int64(len(payload)),
			CachedBytes:    int64(len(payload)),
			UploadedAtUnix: 456,
		},
	}
	if err := manager.SetExchangeHandler("peer-cache-holder-old", cacheHolder.transportExchangeHandler("peer-cache-holder-old")); err != nil {
		t.Fatalf("set cache-holder exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-requester-old", "peer-cache-holder-old", []string{"127.0.0.1:43182"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish old requester peer-cache session: %v", err)
	}
	if _, err := manager.Establish("peer-requester-new", "peer-cache-holder-old", []string{"127.0.0.1:43183"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish replacement requester peer-cache session: %v", err)
	}

	requester.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	requester.deviceState = defaultPersistentState()
	requester.deviceState.SetManagedPeer(requester.remote.BaseURL(), requester.currentUser.ID, "net-1", "peer-requester-old", "127.0.0.1:43182", "10.0.0.0/24", "10.0.0.10")
	requester.deviceState.SetManagedPeer(requester.remote.BaseURL(), requester.currentUser.ID, "net-1", "peer-requester-new", "127.0.0.1:43183", "10.0.0.0/24", "10.0.0.10")
	requester.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-requester-old",
			RemotePeerID:             "peer-cache-holder-old",
			RemoteUserID:             "user-receiver",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			TransportEstablishedUnix: 100,
			LastTransportUnix:        150,
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-requester-new",
			RemotePeerID:             "peer-cache-holder-old",
			RemoteUserID:             "user-receiver",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
	}

	chunk, err := requester.downloadFileTransferContentChunkViaReceiverCacheLocked(controlclient.FileTransfer{
		ID:         "xfer-overlap-peer-cache",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-cache-holder-old",
		ToUserID:   "user-receiver",
		FileName:   "overlap-peer-cache.bin",
		SizeBytes:  int64(len(payload)),
	}, 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download peer-cache chunk during overlapping requester peer replacement: %v", err)
	}
	if chunk == nil || !bytes.Equal(chunk.Payload, payload) {
		t.Fatalf("expected overlapping requester replacement path to preserve peer-cache payload, got %#v", chunk)
	}
	if chunk.LocalPeerID != "peer-requester-new" || chunk.RemotePeerID != "peer-cache-holder-old" {
		t.Fatalf("expected peer-cache transfer to prefer fresher replacement requester peer, got %#v", chunk)
	}
}

func TestDownloadFileTransferContentChunkViaDataplanePrefersActiveReplacementReceiverPeerOnEqualQualityOverlap(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	sender := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sender-equal-overlap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer sender.Close()
	receiver := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "receiver-equal-overlap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiver.Close()

	payload := bytes.Repeat([]byte("ole-equal-overlap"), (fileTransferDataplaneChunkBytes/12)+9)
	sourcePath := filepath.Join(t.TempDir(), "equal-overlap-payload.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write sender payload: %v", err)
	}

	sender.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-receiver-old", UserID: "user-receiver", NetworkID: "net-1"},
		{ID: "peer-receiver-new", UserID: "user-receiver", NetworkID: "net-1"},
	}
	sender.fileTransferSources = map[string]localFileTransferSource{
		"xfer-equal-overlap-download": {
			TransferID:     "xfer-equal-overlap-download",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender-old",
			RemotePeerID:   "peer-receiver-old",
			RemoteUserID:   "user-receiver",
			SourcePath:     sourcePath,
			FileName:       "equal-overlap-payload.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-equal-overlap-download",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 321,
		},
	}
	if err := manager.SetExchangeHandler("peer-sender-old", sender.transportExchangeHandler("peer-sender-old")); err != nil {
		t.Fatalf("set sender exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-old", "peer-sender-old", []string{"127.0.0.1:43184"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish old receiver dataplane session: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-new", "peer-sender-old", []string{"127.0.0.1:43185"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish replacement receiver dataplane session: %v", err)
	}

	receiver.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	receiver.deviceState = defaultPersistentState()
	receiver.deviceState.SetManagedPeer(receiver.remote.BaseURL(), receiver.currentUser.ID, "net-1", "peer-receiver-old", "", "10.0.0.0/24", "10.0.0.9")
	receiver.deviceState.SetManagedPeer(receiver.remote.BaseURL(), receiver.currentUser.ID, "net-1", "peer-receiver-new", "127.0.0.1:43185", "10.0.0.0/24", "10.0.0.9")
	receiver.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-receiver-old",
			RemotePeerID:             "peer-sender-old",
			RemoteUserID:             "user-sender",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			TransportEstablishedUnix: 100,
			LastTransportUnix:        150,
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-receiver-new",
			RemotePeerID:             "peer-sender-old",
			RemoteUserID:             "user-sender",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			TransportEstablishedUnix: 100,
			LastTransportUnix:        150,
		},
	}

	chunk, err := receiver.downloadFileTransferContentChunkViaDataplaneLocked(controlclient.FileTransfer{
		ID:         "xfer-equal-overlap-download",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-receiver-old",
		ToUserID:   "user-receiver",
		FileName:   "equal-overlap-payload.bin",
		SizeBytes:  int64(len(payload)),
	}, 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download dataplane chunk on equal-quality receiver overlap: %v", err)
	}
	if chunk == nil || !bytes.Equal(chunk.Payload, payload) {
		t.Fatalf("expected equal-quality receiver overlap to preserve dataplane payload, got %#v", chunk)
	}
	if chunk.LocalPeerID != "peer-receiver-new" || chunk.RemotePeerID != "peer-sender-old" {
		t.Fatalf("expected dataplane transfer to prefer active replacement receiver peer over stale exact match, got %#v", chunk)
	}
}

func TestDownloadFileTransferContentChunkViaReceiverPeerCachePrefersActiveReplacementRequesterPeerOnEqualQualityOverlap(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	cacheHolder := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "cache-holder-equal-overlap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer cacheHolder.Close()
	requester := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "requester-equal-overlap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer requester.Close()

	payload := bytes.Repeat([]byte("ole-equal-cache-overlap"), 4096)
	cachePath := filepath.Join(t.TempDir(), "equal-overlap-peer-cache.bin")
	if err := os.WriteFile(cachePath, payload, 0o600); err != nil {
		t.Fatalf("write peer cache payload: %v", err)
	}

	cacheHolder.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	cacheHolder.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-requester-old", UserID: "user-receiver", NetworkID: "net-1"},
		{ID: "peer-requester-new", UserID: "user-receiver", NetworkID: "net-1"},
	}
	cacheHolder.fileTransferCaches = map[string]localFileTransferCache{
		"xfer-equal-overlap-peer-cache": {
			TransferID:     "xfer-equal-overlap-peer-cache",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-cache-holder-old",
			RemotePeerID:   "peer-requester-old",
			CachePath:      cachePath,
			FileName:       "equal-overlap-peer-cache.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-equal-overlap-peer-cache",
			SizeBytes:      int64(len(payload)),
			CachedBytes:    int64(len(payload)),
			UploadedAtUnix: 654,
		},
	}
	if err := manager.SetExchangeHandler("peer-cache-holder-old", cacheHolder.transportExchangeHandler("peer-cache-holder-old")); err != nil {
		t.Fatalf("set cache-holder exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-requester-old", "peer-cache-holder-old", []string{"127.0.0.1:43186"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish old requester peer-cache session: %v", err)
	}
	if _, err := manager.Establish("peer-requester-new", "peer-cache-holder-old", []string{"127.0.0.1:43187"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish replacement requester peer-cache session: %v", err)
	}

	requester.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	requester.deviceState = defaultPersistentState()
	requester.deviceState.SetManagedPeer(requester.remote.BaseURL(), requester.currentUser.ID, "net-1", "peer-requester-old", "", "10.0.0.0/24", "10.0.0.10")
	requester.deviceState.SetManagedPeer(requester.remote.BaseURL(), requester.currentUser.ID, "net-1", "peer-requester-new", "127.0.0.1:43187", "10.0.0.0/24", "10.0.0.10")
	requester.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-requester-old",
			RemotePeerID:             "peer-cache-holder-old",
			RemoteUserID:             "user-receiver",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			TransportEstablishedUnix: 100,
			LastTransportUnix:        150,
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-requester-new",
			RemotePeerID:             "peer-cache-holder-old",
			RemoteUserID:             "user-receiver",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			TransportEstablishedUnix: 100,
			LastTransportUnix:        150,
		},
	}

	chunk, err := requester.downloadFileTransferContentChunkViaReceiverCacheLocked(controlclient.FileTransfer{
		ID:         "xfer-equal-overlap-peer-cache",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-cache-holder-old",
		ToUserID:   "user-receiver",
		FileName:   "equal-overlap-peer-cache.bin",
		SizeBytes:  int64(len(payload)),
	}, 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download peer-cache chunk on equal-quality requester overlap: %v", err)
	}
	if chunk == nil || !bytes.Equal(chunk.Payload, payload) {
		t.Fatalf("expected equal-quality requester overlap to preserve peer-cache payload, got %#v", chunk)
	}
	if chunk.LocalPeerID != "peer-requester-new" || chunk.RemotePeerID != "peer-cache-holder-old" {
		t.Fatalf("expected peer-cache transfer to prefer active replacement requester peer over stale exact match, got %#v", chunk)
	}
}

func TestDownloadFileTransferContentChunkViaDataplanePrefersActiveReplacementReceiverPeerDespiteStaleBetterPath(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	sender := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sender-better-stale-overlap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer sender.Close()
	receiver := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "receiver-better-stale-overlap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiver.Close()

	payload := bytes.Repeat([]byte("ole-better-stale-overlap"), (fileTransferDataplaneChunkBytes/12)+7)
	sourcePath := filepath.Join(t.TempDir(), "better-stale-overlap-payload.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write sender payload: %v", err)
	}

	sender.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-receiver-old", UserID: "user-receiver", NetworkID: "net-1"},
		{ID: "peer-receiver-new", UserID: "user-receiver", NetworkID: "net-1"},
	}
	sender.fileTransferSources = map[string]localFileTransferSource{
		"xfer-better-stale-overlap-download": {
			TransferID:     "xfer-better-stale-overlap-download",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender-old",
			RemotePeerID:   "peer-receiver-old",
			RemoteUserID:   "user-receiver",
			SourcePath:     sourcePath,
			FileName:       "better-stale-overlap-payload.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-better-stale-overlap-download",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 331,
		},
	}
	if err := manager.SetExchangeHandler("peer-sender-old", sender.transportExchangeHandler("peer-sender-old")); err != nil {
		t.Fatalf("set sender exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-old", "peer-sender-old", []string{"127.0.0.1:43190"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish stale receiver dataplane session: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-new", "peer-sender-old", []string{"127.0.0.1:43191"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish active receiver dataplane session: %v", err)
	}

	receiver.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	receiver.deviceState = defaultPersistentState()
	receiver.deviceState.SetManagedPeer(receiver.remote.BaseURL(), receiver.currentUser.ID, "net-1", "peer-receiver-old", "", "10.0.0.0/24", "10.0.0.9")
	receiver.deviceState.SetManagedPeer(receiver.remote.BaseURL(), receiver.currentUser.ID, "net-1", "peer-receiver-new", "127.0.0.1:43191", "10.0.0.0/24", "10.0.0.9")
	receiver.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-receiver-old",
			RemotePeerID:             "peer-sender-old",
			RemoteUserID:             "user-sender",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 100,
			LastTransportUnix:        150,
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-receiver-new",
			RemotePeerID:             "peer-sender-old",
			RemoteUserID:             "user-sender",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         90,
			LastRTTMillis:            95,
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
	}

	chunk, err := receiver.downloadFileTransferContentChunkViaDataplaneLocked(controlclient.FileTransfer{
		ID:         "xfer-better-stale-overlap-download",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-receiver-old",
		ToUserID:   "user-receiver",
		FileName:   "better-stale-overlap-payload.bin",
		SizeBytes:  int64(len(payload)),
	}, 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download dataplane chunk on stale-better receiver overlap: %v", err)
	}
	if chunk == nil || !bytes.Equal(chunk.Payload, payload) {
		t.Fatalf("expected stale-better receiver overlap to preserve dataplane payload, got %#v", chunk)
	}
	if chunk.LocalPeerID != "peer-receiver-new" || chunk.RemotePeerID != "peer-sender-old" {
		t.Fatalf("expected dataplane transfer to keep the active replacement receiver peer even when stale exact path has better RTT, got %#v", chunk)
	}
}

func TestDownloadFileTransferContentChunkViaReceiverPeerCachePrefersActiveReplacementRequesterPeerDespiteStaleBetterPath(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	cacheHolder := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "cache-holder-better-stale-overlap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer cacheHolder.Close()
	requester := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "requester-better-stale-overlap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer requester.Close()

	payload := bytes.Repeat([]byte("ole-better-stale-cache-overlap"), 4096)
	cachePath := filepath.Join(t.TempDir(), "better-stale-overlap-peer-cache.bin")
	if err := os.WriteFile(cachePath, payload, 0o600); err != nil {
		t.Fatalf("write peer cache payload: %v", err)
	}

	cacheHolder.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	cacheHolder.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-requester-old", UserID: "user-receiver", NetworkID: "net-1"},
		{ID: "peer-requester-new", UserID: "user-receiver", NetworkID: "net-1"},
	}
	cacheHolder.fileTransferCaches = map[string]localFileTransferCache{
		"xfer-better-stale-overlap-peer-cache": {
			TransferID:     "xfer-better-stale-overlap-peer-cache",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-cache-holder-old",
			RemotePeerID:   "peer-requester-old",
			CachePath:      cachePath,
			FileName:       "better-stale-overlap-peer-cache.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-better-stale-overlap-peer-cache",
			SizeBytes:      int64(len(payload)),
			CachedBytes:    int64(len(payload)),
			UploadedAtUnix: 664,
		},
	}
	if err := manager.SetExchangeHandler("peer-cache-holder-old", cacheHolder.transportExchangeHandler("peer-cache-holder-old")); err != nil {
		t.Fatalf("set cache-holder exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-requester-old", "peer-cache-holder-old", []string{"127.0.0.1:43192"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish stale requester peer-cache session: %v", err)
	}
	if _, err := manager.Establish("peer-requester-new", "peer-cache-holder-old", []string{"127.0.0.1:43193"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish active requester peer-cache session: %v", err)
	}

	requester.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	requester.deviceState = defaultPersistentState()
	requester.deviceState.SetManagedPeer(requester.remote.BaseURL(), requester.currentUser.ID, "net-1", "peer-requester-old", "", "10.0.0.0/24", "10.0.0.10")
	requester.deviceState.SetManagedPeer(requester.remote.BaseURL(), requester.currentUser.ID, "net-1", "peer-requester-new", "127.0.0.1:43193", "10.0.0.0/24", "10.0.0.10")
	requester.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-requester-old",
			RemotePeerID:             "peer-cache-holder-old",
			RemoteUserID:             "user-receiver",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         10,
			LastRTTMillis:            10,
			TransportEstablishedUnix: 100,
			LastTransportUnix:        150,
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-requester-new",
			RemotePeerID:             "peer-cache-holder-old",
			RemoteUserID:             "user-receiver",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			AverageRTTMillis:         90,
			LastRTTMillis:            95,
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
	}

	chunk, err := requester.downloadFileTransferContentChunkViaReceiverCacheLocked(controlclient.FileTransfer{
		ID:         "xfer-better-stale-overlap-peer-cache",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-cache-holder-old",
		ToUserID:   "user-receiver",
		FileName:   "better-stale-overlap-peer-cache.bin",
		SizeBytes:  int64(len(payload)),
	}, 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download peer-cache chunk on stale-better requester overlap: %v", err)
	}
	if chunk == nil || !bytes.Equal(chunk.Payload, payload) {
		t.Fatalf("expected stale-better requester overlap to preserve peer-cache payload, got %#v", chunk)
	}
	if chunk.LocalPeerID != "peer-requester-new" || chunk.RemotePeerID != "peer-cache-holder-old" {
		t.Fatalf("expected peer-cache transfer to keep the active replacement requester peer even when stale exact path has better RTT, got %#v", chunk)
	}
}

func TestDownloadFileTransferContentChunkViaDataplaneSurvivesSenderLocalPeerOverlapBeforeSourceRebind(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	sender := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sender-local-overlap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer sender.Close()
	receiver := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "receiver-local-overlap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiver.Close()

	payload := bytes.Repeat([]byte("ole-sender-local-overlap"), (fileTransferDataplaneChunkBytes/12)+11)
	sourcePath := filepath.Join(t.TempDir(), "sender-local-overlap.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write sender payload: %v", err)
	}

	sender.currentUser = &controlclient.User{ID: "user-sender", Email: "sender@example.com"}
	sender.deviceState = defaultPersistentState()
	sender.deviceState.SetManagedPeer(sender.remote.BaseURL(), sender.currentUser.ID, "net-1", "peer-sender-old", "", "10.0.0.0/24", "10.0.0.2")
	sender.deviceState.SetManagedPeer(sender.remote.BaseURL(), sender.currentUser.ID, "net-1", "peer-sender-new", "127.0.0.1:43188", "10.0.0.0/24", "10.0.0.2")
	sender.discoveredPeers["net-1"] = []controlclient.Peer{{ID: "peer-receiver-new", UserID: "user-receiver", NetworkID: "net-1"}}
	sender.fileTransferSources = map[string]localFileTransferSource{
		"xfer-sender-local-overlap": {
			TransferID:     "xfer-sender-local-overlap",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender-old",
			RemotePeerID:   "peer-receiver-old",
			RemoteUserID:   "user-receiver",
			SourcePath:     sourcePath,
			FileName:       "sender-local-overlap.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-sender-local-overlap",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 777,
		},
	}
	sender.deviceState.SetFileTransferSource(sender.fileTransferSourceStateLocked(sender.fileTransferSources["xfer-sender-local-overlap"]))
	if err := sender.savePersistentStateLocked(); err != nil {
		t.Fatalf("persist sender overlap source state: %v", err)
	}
	if err := manager.SetExchangeHandler("peer-sender-new", sender.transportExchangeHandler("peer-sender-new")); err != nil {
		t.Fatalf("set sender exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-new", "peer-sender-new", []string{"127.0.0.1:43188"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish dataplane session: %v", err)
	}

	receiver.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	receiver.deviceState = defaultPersistentState()
	receiver.deviceState.SetManagedPeer(receiver.remote.BaseURL(), receiver.currentUser.ID, "net-1", "peer-receiver-new", "127.0.0.1:43188", "10.0.0.0/24", "10.0.0.9")
	receiver.discoveredPeers["net-1"] = []controlclient.Peer{{ID: "peer-sender-new", UserID: "user-sender", NetworkID: "net-1"}}
	receiver.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-receiver-new",
		RemotePeerID:   "peer-sender-new",
		RemoteUserID:   "user-sender",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}

	chunk, err := receiver.downloadFileTransferContentChunkViaDataplaneLocked(controlclient.FileTransfer{
		ID:         "xfer-sender-local-overlap",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-receiver-old",
		ToUserID:   "user-receiver",
		FileName:   "sender-local-overlap.bin",
		SizeBytes:  int64(len(payload)),
	}, 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download dataplane chunk during sender local-peer overlap: %v", err)
	}
	if chunk == nil || !bytes.Equal(chunk.Payload, payload) {
		t.Fatalf("expected sender local-peer overlap to preserve dataplane payload, got %#v", chunk)
	}
	if chunk.LocalPeerID != "peer-receiver-new" || chunk.RemotePeerID != "peer-sender-new" {
		t.Fatalf("expected dataplane transfer to use replacement sender local peer, got %#v", chunk)
	}
	if sender.fileTransferSources["xfer-sender-local-overlap"].LocalPeerID != "peer-sender-new" {
		t.Fatalf("expected sender source metadata to rebind onto replacement local peer, got %#v", sender.fileTransferSources["xfer-sender-local-overlap"])
	}
	if sender.fileTransferSources["xfer-sender-local-overlap"].RemotePeerID != "peer-receiver-new" {
		t.Fatalf("expected sender source metadata to rebind onto replacement remote peer, got %#v", sender.fileTransferSources["xfer-sender-local-overlap"])
	}
	persistedSender, err := sender.stateStore.Load()
	if err != nil {
		t.Fatalf("reload sender overlap source state: %v", err)
	}
	sources := persistedSender.FileTransferSourcesFor(sender.remote.BaseURL(), sender.currentUser.ID)
	if len(sources) != 1 || sources[0].LocalPeerID != "peer-sender-new" || sources[0].RemotePeerID != "peer-receiver-new" {
		t.Fatalf("expected persisted sender source metadata to rebind onto replacement local peer, got %#v", sources)
	}
}

func TestTransferDownloadPrefersActiveLocalPeerAcrossEndpointMetadataGap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "transfer-download-local-peer-endpoint-gap-state.json")), RuntimeConfig{}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	agent.mu.Lock()
	defer agent.mu.Unlock()

	agent.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-receiver-new", "127.0.0.1:43001", "10.0.0.0/24", "10.0.0.9")
	agent.connections = []ConnectionStatus{
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-receiver-old",
			RemotePeerID:     "peer-sender-old",
			RemoteUserID:     "user-sender",
			RemoteVirtualIP:  "10.0.0.2",
			RemoteEndpoint:   "198.51.100.20:5000",
			RemoteCandidates: []string{"198.51.100.20:5000", "203.0.113.20:6000"},
			TransportReady:   true,
			TransportMode:    "DIRECT",
			Reachability:     "DIRECT",
			State:            "CONNECTED",
			AverageRTTMillis: 8,
			LastRTTMillis:    7,
		},
		{
			NetworkID:        "net-1",
			LocalPeerID:      "peer-receiver-new",
			RemotePeerID:     "peer-sender-new",
			RemoteEndpoint:   "198.51.100.20:5000",
			RemoteCandidates: []string{"198.51.100.20:5000"},
			TransportReady:   true,
			TransportMode:    "RELAY",
			Reachability:     "RELAY",
			State:            "CONNECTED",
			AverageRTTMillis: 80,
			LastRTTMillis:    78,
		},
	}

	selected := agent.transportReadyConnectionForTransferDownloadLocked(controlclient.FileTransfer{
		ID:         "xfer-download-endpoint-gap",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-receiver-old",
		ToUserID:   "user-receiver",
		FileName:   "transfer-download-endpoint-gap.bin",
		SizeBytes:  128,
	})
	if selected == nil || selected.LocalPeerID != "peer-receiver-new" || selected.RemotePeerID != "peer-sender-new" {
		t.Fatalf("expected transfer download to prefer active endpoint-continuity replacement, got %#v", selected)
	}
}

func TestDownloadFileTransferContentChunkViaReceiverPeerCacheSurvivesCacheHolderLocalPeerOverlapBeforeCacheRebind(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	cacheHolder := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "cache-holder-local-overlap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer cacheHolder.Close()
	requester := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "requester-local-overlap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer requester.Close()

	payload := bytes.Repeat([]byte("ole-cache-holder-local-overlap"), 4096)
	cachePath := filepath.Join(t.TempDir(), "cache-holder-local-overlap.bin")
	if err := os.WriteFile(cachePath, payload, 0o600); err != nil {
		t.Fatalf("write peer cache payload: %v", err)
	}

	cacheHolder.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	cacheHolder.deviceState = defaultPersistentState()
	cacheHolder.deviceState.SetManagedPeer(cacheHolder.remote.BaseURL(), cacheHolder.currentUser.ID, "net-1", "peer-cache-holder-old", "", "10.0.0.0/24", "10.0.0.4")
	cacheHolder.deviceState.SetManagedPeer(cacheHolder.remote.BaseURL(), cacheHolder.currentUser.ID, "net-1", "peer-cache-holder-new", "127.0.0.1:43189", "10.0.0.0/24", "10.0.0.4")
	cacheHolder.discoveredPeers["net-1"] = []controlclient.Peer{{ID: "peer-requester-new", UserID: "user-receiver", NetworkID: "net-1"}}
	cacheHolder.fileTransferCaches = map[string]localFileTransferCache{
		"xfer-cache-holder-local-overlap": {
			TransferID:     "xfer-cache-holder-local-overlap",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-cache-holder-old",
			RemotePeerID:   "peer-requester-old",
			CachePath:      cachePath,
			FileName:       "cache-holder-local-overlap.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-cache-holder-local-overlap",
			SizeBytes:      int64(len(payload)),
			CachedBytes:    int64(len(payload)),
			UploadedAtUnix: 888,
		},
	}
	cacheHolder.deviceState.SetFileTransferCache(cacheHolder.fileTransferCacheStateLocked(cacheHolder.fileTransferCaches["xfer-cache-holder-local-overlap"]))
	if err := cacheHolder.savePersistentStateLocked(); err != nil {
		t.Fatalf("persist cache-holder overlap cache state: %v", err)
	}
	if err := manager.SetExchangeHandler("peer-cache-holder-new", cacheHolder.transportExchangeHandler("peer-cache-holder-new")); err != nil {
		t.Fatalf("set cache-holder exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-requester-new", "peer-cache-holder-new", []string{"127.0.0.1:43189"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish peer-cache session: %v", err)
	}

	requester.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	requester.deviceState = defaultPersistentState()
	requester.deviceState.SetManagedPeer(requester.remote.BaseURL(), requester.currentUser.ID, "net-1", "peer-requester-new", "127.0.0.1:43189", "10.0.0.0/24", "10.0.0.10")
	requester.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-requester-new",
		RemotePeerID:   "peer-cache-holder-new",
		RemoteUserID:   "user-receiver",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}

	chunk, err := requester.downloadFileTransferContentChunkViaReceiverCacheLocked(controlclient.FileTransfer{
		ID:         "xfer-cache-holder-local-overlap",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-cache-holder-old",
		ToUserID:   "user-receiver",
		FileName:   "cache-holder-local-overlap.bin",
		SizeBytes:  int64(len(payload)),
	}, 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download peer-cache chunk during cache-holder local-peer overlap: %v", err)
	}
	if chunk == nil || !bytes.Equal(chunk.Payload, payload) {
		t.Fatalf("expected cache-holder local-peer overlap to preserve peer-cache payload, got %#v", chunk)
	}
	if chunk.LocalPeerID != "peer-requester-new" || chunk.RemotePeerID != "peer-cache-holder-new" {
		t.Fatalf("expected peer-cache transfer to use replacement cache-holder local peer, got %#v", chunk)
	}
	if cacheHolder.fileTransferCaches["xfer-cache-holder-local-overlap"].LocalPeerID != "peer-cache-holder-new" {
		t.Fatalf("expected cache-holder metadata to rebind onto replacement local peer, got %#v", cacheHolder.fileTransferCaches["xfer-cache-holder-local-overlap"])
	}
	if cacheHolder.fileTransferCaches["xfer-cache-holder-local-overlap"].RemotePeerID != "peer-requester-new" {
		t.Fatalf("expected cache-holder metadata to rebind onto replacement remote peer, got %#v", cacheHolder.fileTransferCaches["xfer-cache-holder-local-overlap"])
	}
	persistedCacheHolder, err := cacheHolder.stateStore.Load()
	if err != nil {
		t.Fatalf("reload cache-holder overlap cache state: %v", err)
	}
	caches := persistedCacheHolder.FileTransferCachesFor(cacheHolder.remote.BaseURL(), cacheHolder.currentUser.ID)
	if len(caches) != 1 || caches[0].LocalPeerID != "peer-cache-holder-new" || caches[0].RemotePeerID != "peer-requester-new" {
		t.Fatalf("expected persisted cache-holder metadata to rebind onto replacement local peer, got %#v", caches)
	}
}

func TestDownloadFileTransferContentChunkViaDataplaneKeepsPreferredReplacementRemotePeerOnStaleOverlapRequest(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	sender := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sender-stale-overlap-request-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer sender.Close()
	receiver := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "receiver-stale-overlap-request-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiver.Close()

	payload := bytes.Repeat([]byte("ole-stale-overlap-request"), (fileTransferDataplaneChunkBytes/12)+19)
	sourcePath := filepath.Join(t.TempDir(), "stale-overlap-request.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write sender payload: %v", err)
	}

	sender.currentUser = &controlclient.User{ID: "user-sender", Email: "sender@example.com"}
	sender.deviceState = defaultPersistentState()
	sender.deviceState.SetManagedPeer(sender.remote.BaseURL(), sender.currentUser.ID, "net-1", "peer-sender-new", "127.0.0.1:43190", "10.0.0.0/24", "10.0.0.2")
	sender.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-receiver-old", UserID: "user-receiver", NetworkID: "net-1", VirtualIP: "10.0.0.9"},
		{ID: "peer-receiver-new", UserID: "user-receiver", NetworkID: "net-1", VirtualIP: "10.0.0.9"},
	}
	sender.fileTransferSources = map[string]localFileTransferSource{
		"xfer-stale-overlap-request": {
			TransferID:     "xfer-stale-overlap-request",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender-new",
			RemotePeerID:   "peer-receiver-new",
			RemoteUserID:   "user-receiver",
			SourcePath:     sourcePath,
			FileName:       "stale-overlap-request.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-stale-overlap-request",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 889,
		},
	}
	sender.deviceState.SetFileTransferSource(sender.fileTransferSourceStateLocked(sender.fileTransferSources["xfer-stale-overlap-request"]))
	if err := sender.savePersistentStateLocked(); err != nil {
		t.Fatalf("persist sender stale overlap source state: %v", err)
	}
	sender.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-sender-new",
			RemotePeerID:             "peer-receiver-old",
			RemoteUserID:             "user-receiver",
			RemoteVirtualIP:          "10.0.0.9",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			TransportEstablishedUnix: 100,
			LastTransportUnix:        150,
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-sender-new",
			RemotePeerID:             "peer-receiver-new",
			RemoteUserID:             "user-receiver",
			RemoteVirtualIP:          "10.0.0.9",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
	}
	if err := manager.SetExchangeHandler("peer-sender-new", sender.transportExchangeHandler("peer-sender-new")); err != nil {
		t.Fatalf("set sender exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-old", "peer-sender-new", []string{"127.0.0.1:43190"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish stale receiver dataplane session: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-new", "peer-sender-new", []string{"127.0.0.1:43191"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish preferred replacement receiver dataplane session: %v", err)
	}

	receiver.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	receiver.deviceState = defaultPersistentState()
	receiver.deviceState.SetManagedPeer(receiver.remote.BaseURL(), receiver.currentUser.ID, "net-1", "peer-receiver-old", "127.0.0.1:43190", "10.0.0.0/24", "10.0.0.9")
	receiver.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-receiver-old",
		RemotePeerID:   "peer-sender-new",
		RemoteUserID:   "user-sender",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}

	chunk, err := receiver.downloadFileTransferContentChunkViaDataplaneLocked(controlclient.FileTransfer{
		ID:         "xfer-stale-overlap-request",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-new",
		FromUserID: "user-sender",
		ToPeerID:   "peer-receiver-old",
		ToUserID:   "user-receiver",
		FileName:   "stale-overlap-request.bin",
		SizeBytes:  int64(len(payload)),
	}, 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download dataplane chunk during stale overlap request: %v", err)
	}
	if chunk == nil || !bytes.Equal(chunk.Payload, payload) {
		t.Fatalf("expected stale overlap request to preserve dataplane payload, got %#v", chunk)
	}
	if chunk.LocalPeerID != "peer-receiver-old" || chunk.RemotePeerID != "peer-sender-new" {
		t.Fatalf("expected stale overlap request to keep serving over the stale requester path, got %#v", chunk)
	}
	if sender.fileTransferSources["xfer-stale-overlap-request"].RemotePeerID != "peer-receiver-new" {
		t.Fatalf("expected sender source metadata to keep preferred replacement remote peer during stale overlap request, got %#v", sender.fileTransferSources["xfer-stale-overlap-request"])
	}
	persistedSender, err := sender.stateStore.Load()
	if err != nil {
		t.Fatalf("reload sender stale overlap source state: %v", err)
	}
	sources := persistedSender.FileTransferSourcesFor(sender.remote.BaseURL(), sender.currentUser.ID)
	if len(sources) != 1 || sources[0].RemotePeerID != "peer-receiver-new" {
		t.Fatalf("expected persisted sender source metadata to keep preferred replacement remote peer during stale overlap request, got %#v", sources)
	}
}

func TestDownloadFileTransferContentChunkViaReceiverPeerCacheKeepsPreferredReplacementRequesterPeerOnStaleOverlapRequest(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	cacheHolder := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "cache-holder-stale-overlap-request-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer cacheHolder.Close()
	requester := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "requester-stale-overlap-request-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer requester.Close()

	payload := bytes.Repeat([]byte("ole-cache-stale-overlap-request"), 4096)
	cachePath := filepath.Join(t.TempDir(), "cache-stale-overlap-request.bin")
	if err := os.WriteFile(cachePath, payload, 0o600); err != nil {
		t.Fatalf("write peer cache payload: %v", err)
	}

	cacheHolder.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	cacheHolder.deviceState = defaultPersistentState()
	cacheHolder.deviceState.SetManagedPeer(cacheHolder.remote.BaseURL(), cacheHolder.currentUser.ID, "net-1", "peer-cache-holder-new", "127.0.0.1:43192", "10.0.0.0/24", "10.0.0.4")
	cacheHolder.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-requester-old", UserID: "user-receiver", NetworkID: "net-1", VirtualIP: "10.0.0.10"},
		{ID: "peer-requester-new", UserID: "user-receiver", NetworkID: "net-1", VirtualIP: "10.0.0.10"},
	}
	cacheHolder.fileTransferCaches = map[string]localFileTransferCache{
		"xfer-cache-stale-overlap-request": {
			TransferID:     "xfer-cache-stale-overlap-request",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-cache-holder-new",
			RemotePeerID:   "peer-requester-new",
			CachePath:      cachePath,
			FileName:       "cache-stale-overlap-request.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-cache-stale-overlap-request",
			SizeBytes:      int64(len(payload)),
			CachedBytes:    int64(len(payload)),
			UploadedAtUnix: 890,
		},
	}
	cacheHolder.deviceState.SetFileTransferCache(cacheHolder.fileTransferCacheStateLocked(cacheHolder.fileTransferCaches["xfer-cache-stale-overlap-request"]))
	if err := cacheHolder.savePersistentStateLocked(); err != nil {
		t.Fatalf("persist cache-holder stale overlap cache state: %v", err)
	}
	cacheHolder.connections = []ConnectionStatus{
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-cache-holder-new",
			RemotePeerID:             "peer-requester-old",
			RemoteUserID:             "user-receiver",
			RemoteVirtualIP:          "10.0.0.10",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			TransportEstablishedUnix: 100,
			LastTransportUnix:        150,
		},
		{
			NetworkID:                "net-1",
			LocalPeerID:              "peer-cache-holder-new",
			RemotePeerID:             "peer-requester-new",
			RemoteUserID:             "user-receiver",
			RemoteVirtualIP:          "10.0.0.10",
			TransportReady:           true,
			TransportMode:            "DIRECT",
			State:                    "CONNECTED",
			Reachability:             "DIRECT",
			TransportEstablishedUnix: 200,
			LastTransportUnix:        250,
		},
	}
	if err := manager.SetExchangeHandler("peer-cache-holder-new", cacheHolder.transportExchangeHandler("peer-cache-holder-new")); err != nil {
		t.Fatalf("set cache-holder exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-requester-old", "peer-cache-holder-new", []string{"127.0.0.1:43192"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish stale requester peer-cache session: %v", err)
	}
	if _, err := manager.Establish("peer-requester-new", "peer-cache-holder-new", []string{"127.0.0.1:43193"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish preferred replacement requester peer-cache session: %v", err)
	}

	requester.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	requester.deviceState = defaultPersistentState()
	requester.deviceState.SetManagedPeer(requester.remote.BaseURL(), requester.currentUser.ID, "net-1", "peer-requester-old", "127.0.0.1:43192", "10.0.0.0/24", "10.0.0.10")
	requester.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-requester-old",
		RemotePeerID:   "peer-cache-holder-new",
		RemoteUserID:   "user-receiver",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}

	chunk, err := requester.downloadFileTransferContentChunkViaReceiverCacheLocked(controlclient.FileTransfer{
		ID:         "xfer-cache-stale-overlap-request",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-new",
		FromUserID: "user-sender",
		ToPeerID:   "peer-cache-holder-new",
		ToUserID:   "user-receiver",
		FileName:   "cache-stale-overlap-request.bin",
		SizeBytes:  int64(len(payload)),
	}, 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download peer-cache chunk during stale overlap request: %v", err)
	}
	if chunk == nil || !bytes.Equal(chunk.Payload, payload) {
		t.Fatalf("expected stale overlap request to preserve peer-cache payload, got %#v", chunk)
	}
	if chunk.LocalPeerID != "peer-requester-old" || chunk.RemotePeerID != "peer-cache-holder-new" {
		t.Fatalf("expected stale overlap request to keep serving over the stale requester path, got %#v", chunk)
	}
	if cacheHolder.fileTransferCaches["xfer-cache-stale-overlap-request"].RemotePeerID != "peer-requester-new" {
		t.Fatalf("expected cache-holder metadata to keep preferred replacement requester peer during stale overlap request, got %#v", cacheHolder.fileTransferCaches["xfer-cache-stale-overlap-request"])
	}
	persistedCacheHolder, err := cacheHolder.stateStore.Load()
	if err != nil {
		t.Fatalf("reload cache-holder stale overlap cache state: %v", err)
	}
	caches := persistedCacheHolder.FileTransferCachesFor(cacheHolder.remote.BaseURL(), cacheHolder.currentUser.ID)
	if len(caches) != 1 || caches[0].RemotePeerID != "peer-requester-new" {
		t.Fatalf("expected persisted cache-holder metadata to keep preferred replacement requester peer during stale overlap request, got %#v", caches)
	}
}

func TestDownloadFileTransferContentChunkViaDataplaneKeepsActiveReplacementLocalPeerOnStaleLocalOverlapRequest(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	sender := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sender-stale-local-overlap-request-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer sender.Close()
	receiver := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "receiver-stale-local-overlap-request-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiver.Close()

	payload := bytes.Repeat([]byte("ole-stale-local-overlap-request"), (fileTransferDataplaneChunkBytes/12)+13)
	sourcePath := filepath.Join(t.TempDir(), "stale-local-overlap-request.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write sender payload: %v", err)
	}

	sender.currentUser = &controlclient.User{ID: "user-sender", Email: "sender@example.com"}
	sender.deviceState = defaultPersistentState()
	sender.deviceState.SetManagedPeer(sender.remote.BaseURL(), sender.currentUser.ID, "net-1", "peer-sender-old", "", "10.0.0.0/24", "10.0.0.2")
	sender.deviceState.SetManagedPeer(sender.remote.BaseURL(), sender.currentUser.ID, "net-1", "peer-sender-new", "127.0.0.1:43194", "10.0.0.0/24", "10.0.0.2")
	sender.discoveredPeers["net-1"] = []controlclient.Peer{{ID: "peer-receiver-new", UserID: "user-receiver", NetworkID: "net-1"}}
	sender.fileTransferSources = map[string]localFileTransferSource{
		"xfer-stale-local-overlap-request": {
			TransferID:     "xfer-stale-local-overlap-request",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender-new",
			RemotePeerID:   "peer-receiver-new",
			RemoteUserID:   "user-receiver",
			SourcePath:     sourcePath,
			FileName:       "stale-local-overlap-request.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-stale-local-overlap-request",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 901,
		},
	}
	sender.deviceState.SetFileTransferSource(sender.fileTransferSourceStateLocked(sender.fileTransferSources["xfer-stale-local-overlap-request"]))
	if err := sender.savePersistentStateLocked(); err != nil {
		t.Fatalf("persist sender stale local-overlap source state: %v", err)
	}
	sender.connections = []ConnectionStatus{
		{
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender-old",
			RemotePeerID:   "peer-receiver-new",
			RemoteUserID:   "user-receiver",
			TransportReady: true,
			TransportMode:  "DIRECT",
			State:          "CONNECTED",
			Reachability:   "DIRECT",
		},
		{
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender-new",
			RemotePeerID:   "peer-receiver-new",
			RemoteUserID:   "user-receiver",
			TransportReady: true,
			TransportMode:  "DIRECT",
			State:          "CONNECTED",
			Reachability:   "DIRECT",
		},
	}
	if err := manager.SetExchangeHandler("peer-sender-old", sender.transportExchangeHandler("peer-sender-old")); err != nil {
		t.Fatalf("set sender exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-new", "peer-sender-old", []string{"127.0.0.1:43194"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish stale sender-local dataplane session: %v", err)
	}
	source := sender.fileTransferSources["xfer-stale-local-overlap-request"]
	if !sender.rebindFileTransferSourceToActiveManagedPeerLocked("xfer-stale-local-overlap-request", &source, "peer-sender-old", "peer-receiver-new") {
		t.Fatalf("expected sender local-peer rebind gate to allow stale local-overlap request")
	}
	response := sender.buildFileTransferDataplaneResponse("peer-sender-old", "peer-receiver-new", fileTransferDataplaneRequest{
		Type:        "file-transfer-chunk-request",
		TransferID:  "xfer-stale-local-overlap-request",
		OffsetBytes: 0,
		LimitBytes:  int64(len(payload)),
	})
	if response.Error != "" || len(response.Payload) == 0 {
		t.Fatalf("expected sender to keep serving stale local-overlap request via old local peer while preserving active metadata, got %#v", response)
	}

	receiver.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	receiver.deviceState = defaultPersistentState()
	receiver.deviceState.SetManagedPeer(receiver.remote.BaseURL(), receiver.currentUser.ID, "net-1", "peer-receiver-new", "127.0.0.1:43194", "10.0.0.0/24", "10.0.0.9")
	receiver.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-receiver-new",
		RemotePeerID:   "peer-sender-old",
		RemoteUserID:   "user-sender",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}

	chunk, err := receiver.downloadFileTransferContentChunkViaDataplaneLocked(controlclient.FileTransfer{
		ID:         "xfer-stale-local-overlap-request",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-receiver-old",
		ToUserID:   "user-receiver",
		FileName:   "stale-local-overlap-request.bin",
		SizeBytes:  int64(len(payload)),
	}, 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download dataplane chunk during stale local-overlap request: %v", err)
	}
	if chunk == nil || !bytes.Equal(chunk.Payload, payload) {
		t.Fatalf("expected stale local-overlap request to preserve dataplane payload, got %#v", chunk)
	}
	if chunk.LocalPeerID != "peer-receiver-new" || chunk.RemotePeerID != "peer-sender-old" {
		t.Fatalf("expected stale local-overlap request to keep serving over the requester path that still hits the old sender local peer, got %#v", chunk)
	}
	if sender.fileTransferSources["xfer-stale-local-overlap-request"].LocalPeerID != "peer-sender-new" {
		t.Fatalf("expected sender source metadata to keep active replacement local peer during stale local-overlap request, got %#v", sender.fileTransferSources["xfer-stale-local-overlap-request"])
	}
	persistedSender, err := sender.stateStore.Load()
	if err != nil {
		t.Fatalf("reload sender stale local-overlap source state: %v", err)
	}
	sources := persistedSender.FileTransferSourcesFor(sender.remote.BaseURL(), sender.currentUser.ID)
	if len(sources) != 1 || sources[0].LocalPeerID != "peer-sender-new" {
		t.Fatalf("expected persisted sender source metadata to keep active replacement local peer during stale local-overlap request, got %#v", sources)
	}
}

func TestDownloadFileTransferContentChunkViaReceiverPeerCacheKeepsActiveCacheHolderLocalPeerOnStaleLocalOverlapRequest(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	cacheHolder := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "cache-holder-stale-local-overlap-request-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer cacheHolder.Close()
	requester := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "requester-stale-local-overlap-request-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer requester.Close()

	payload := bytes.Repeat([]byte("ole-cache-stale-local-overlap-request"), 4096)
	cachePath := filepath.Join(t.TempDir(), "cache-stale-local-overlap-request.bin")
	if err := os.WriteFile(cachePath, payload, 0o600); err != nil {
		t.Fatalf("write peer cache payload: %v", err)
	}

	cacheHolder.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	cacheHolder.deviceState = defaultPersistentState()
	cacheHolder.deviceState.SetManagedPeer(cacheHolder.remote.BaseURL(), cacheHolder.currentUser.ID, "net-1", "peer-cache-holder-old", "", "10.0.0.0/24", "10.0.0.4")
	cacheHolder.deviceState.SetManagedPeer(cacheHolder.remote.BaseURL(), cacheHolder.currentUser.ID, "net-1", "peer-cache-holder-new", "127.0.0.1:43195", "10.0.0.0/24", "10.0.0.4")
	cacheHolder.discoveredPeers["net-1"] = []controlclient.Peer{{ID: "peer-requester-new", UserID: "user-receiver", NetworkID: "net-1"}}
	cacheHolder.fileTransferCaches = map[string]localFileTransferCache{
		"xfer-cache-stale-local-overlap-request": {
			TransferID:     "xfer-cache-stale-local-overlap-request",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-cache-holder-new",
			RemotePeerID:   "peer-requester-new",
			CachePath:      cachePath,
			FileName:       "cache-stale-local-overlap-request.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-cache-stale-local-overlap-request",
			SizeBytes:      int64(len(payload)),
			CachedBytes:    int64(len(payload)),
			UploadedAtUnix: 902,
		},
	}
	cacheHolder.deviceState.SetFileTransferCache(cacheHolder.fileTransferCacheStateLocked(cacheHolder.fileTransferCaches["xfer-cache-stale-local-overlap-request"]))
	if err := cacheHolder.savePersistentStateLocked(); err != nil {
		t.Fatalf("persist cache-holder stale local-overlap cache state: %v", err)
	}
	cacheHolder.connections = []ConnectionStatus{
		{
			NetworkID:      "net-1",
			LocalPeerID:    "peer-cache-holder-old",
			RemotePeerID:   "peer-requester-new",
			RemoteUserID:   "user-receiver",
			TransportReady: true,
			TransportMode:  "DIRECT",
			State:          "CONNECTED",
			Reachability:   "DIRECT",
		},
		{
			NetworkID:      "net-1",
			LocalPeerID:    "peer-cache-holder-new",
			RemotePeerID:   "peer-requester-new",
			RemoteUserID:   "user-receiver",
			TransportReady: true,
			TransportMode:  "DIRECT",
			State:          "CONNECTED",
			Reachability:   "DIRECT",
		},
	}
	if err := manager.SetExchangeHandler("peer-cache-holder-old", cacheHolder.transportExchangeHandler("peer-cache-holder-old")); err != nil {
		t.Fatalf("set cache-holder exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-requester-new", "peer-cache-holder-old", []string{"127.0.0.1:43195"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish stale cache-holder-local peer-cache session: %v", err)
	}
	cache := cacheHolder.fileTransferCaches["xfer-cache-stale-local-overlap-request"]
	if !cacheHolder.rebindFileTransferCacheToActiveManagedPeerLocked("xfer-cache-stale-local-overlap-request", &cache, "peer-cache-holder-old", "peer-requester-new") {
		t.Fatalf("expected cache-holder local-peer rebind gate to allow stale local-overlap request")
	}
	response := cacheHolder.buildFileTransferDataplaneResponse("peer-cache-holder-old", "peer-requester-new", fileTransferDataplaneRequest{
		Type:        "file-transfer-chunk-request",
		TransferID:  "xfer-cache-stale-local-overlap-request",
		OffsetBytes: 0,
		LimitBytes:  int64(len(payload)),
	})
	if response.Error != "" || len(response.Payload) == 0 {
		t.Fatalf("expected cache-holder to keep serving stale local-overlap request via old local peer while preserving active metadata, got %#v", response)
	}

	requester.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	requester.deviceState = defaultPersistentState()
	requester.deviceState.SetManagedPeer(requester.remote.BaseURL(), requester.currentUser.ID, "net-1", "peer-requester-new", "127.0.0.1:43195", "10.0.0.0/24", "10.0.0.10")
	requester.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-requester-new",
		RemotePeerID:   "peer-cache-holder-old",
		RemoteUserID:   "user-receiver",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}

	chunk, err := requester.downloadFileTransferContentChunkViaReceiverCacheLocked(controlclient.FileTransfer{
		ID:         "xfer-cache-stale-local-overlap-request",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-new",
		FromUserID: "user-sender",
		ToPeerID:   "peer-cache-holder-old",
		ToUserID:   "user-receiver",
		FileName:   "cache-stale-local-overlap-request.bin",
		SizeBytes:  int64(len(payload)),
	}, 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download peer-cache chunk during stale local-overlap request: %v", err)
	}
	if chunk == nil || !bytes.Equal(chunk.Payload, payload) {
		t.Fatalf("expected stale local-overlap request to preserve peer-cache payload, got %#v", chunk)
	}
	if chunk.LocalPeerID != "peer-requester-new" || chunk.RemotePeerID != "peer-cache-holder-old" {
		t.Fatalf("expected stale local-overlap request to keep serving over the requester path that still hits the old cache-holder local peer, got %#v", chunk)
	}
	if cacheHolder.fileTransferCaches["xfer-cache-stale-local-overlap-request"].LocalPeerID != "peer-cache-holder-new" {
		t.Fatalf("expected cache-holder metadata to keep active replacement local peer during stale local-overlap request, got %#v", cacheHolder.fileTransferCaches["xfer-cache-stale-local-overlap-request"])
	}
	persistedCacheHolder, err := cacheHolder.stateStore.Load()
	if err != nil {
		t.Fatalf("reload cache-holder stale local-overlap cache state: %v", err)
	}
	caches := persistedCacheHolder.FileTransferCachesFor(cacheHolder.remote.BaseURL(), cacheHolder.currentUser.ID)
	if len(caches) != 1 || caches[0].LocalPeerID != "peer-cache-holder-new" {
		t.Fatalf("expected persisted cache-holder metadata to keep active replacement local peer during stale local-overlap request, got %#v", caches)
	}
}

func TestSyncRegisteredFileTransferSourceKeepsReboundRemotePeerDuringStaleControlPlaneOverlap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sync-rebound-source-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	payload := bytes.Repeat([]byte("ole-sync-rebound"), 1024)
	sourcePath := filepath.Join(t.TempDir(), "sync-rebound-source.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write source payload: %v", err)
	}

	agent.currentUser = &controlclient.User{ID: "user-sender", Email: "sender@example.com"}
	agent.fileTransferSources = map[string]localFileTransferSource{
		"xfer-sync-rebound-source": {
			TransferID:     "xfer-sync-rebound-source",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender-new",
			RemotePeerID:   "peer-receiver-new",
			RemoteUserID:   "user-receiver",
			SourcePath:     sourcePath,
			FileName:       "sync-rebound-source.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-sync-rebound-source",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 999,
		},
	}
	if err := agent.persistFileTransferSourceLocked(agent.fileTransferSources["xfer-sync-rebound-source"]); err != nil {
		t.Fatalf("persist rebound source state: %v", err)
	}

	if err := agent.syncRegisteredFileTransferSourceLocked(&controlclient.FileTransfer{
		ID:         "xfer-sync-rebound-source",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-receiver-old",
		ToUserID:   "user-receiver",
		FileName:   "sync-rebound-source.bin",
		SizeBytes:  int64(len(payload)),
	}); err != nil {
		t.Fatalf("sync registered file transfer source during stale control-plane overlap: %v", err)
	}

	source := agent.fileTransferSources["xfer-sync-rebound-source"]
	if source.RemotePeerID != "peer-receiver-new" {
		t.Fatalf("expected sync to keep rebound remote peer instead of stale control-plane peer, got %#v", source)
	}
	persisted, err := agent.stateStore.Load()
	if err != nil {
		t.Fatalf("reload rebound source state: %v", err)
	}
	sources := persisted.FileTransferSourcesFor(agent.remote.BaseURL(), agent.currentUser.ID)
	if len(sources) != 1 || sources[0].RemotePeerID != "peer-receiver-new" {
		t.Fatalf("expected persisted source metadata to keep rebound remote peer, got %#v", sources)
	}
}

func TestSyncRegisteredFileTransferSourcePromotesActiveReplacementRemotePeerDuringOverlap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sync-active-source-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	payload := bytes.Repeat([]byte("ole-sync-active"), 1024)
	sourcePath := filepath.Join(t.TempDir(), "sync-active-source.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write source payload: %v", err)
	}

	agent.currentUser = &controlclient.User{ID: "user-sender", Email: "sender@example.com"}
	agent.fileTransferSources = map[string]localFileTransferSource{
		"xfer-sync-active-source": {
			TransferID:     "xfer-sync-active-source",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender-new",
			RemotePeerID:   "peer-receiver-old",
			RemoteUserID:   "user-receiver",
			SourcePath:     sourcePath,
			FileName:       "sync-active-source.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-sync-active-source",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 1001,
		},
	}
	if err := agent.persistFileTransferSourceLocked(agent.fileTransferSources["xfer-sync-active-source"]); err != nil {
		t.Fatalf("persist active source state: %v", err)
	}
	agent.connections = []ConnectionStatus{{
		NetworkID:                "net-1",
		LocalPeerID:              "peer-sender-new",
		RemotePeerID:             "peer-receiver-new",
		RemoteUserID:             "user-receiver",
		TransportReady:           true,
		TransportMode:            "DIRECT",
		State:                    "CONNECTED",
		Reachability:             "DIRECT",
		LastTransportUnix:        200,
		TransportEstablishedUnix: 100,
	}}

	if err := agent.syncRegisteredFileTransferSourceLocked(&controlclient.FileTransfer{
		ID:         "xfer-sync-active-source",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-receiver-old",
		ToUserID:   "user-receiver",
		FileName:   "sync-active-source.bin",
		SizeBytes:  int64(len(payload)),
	}); err != nil {
		t.Fatalf("sync registered file transfer source during active overlap: %v", err)
	}

	source := agent.fileTransferSources["xfer-sync-active-source"]
	if source.RemotePeerID != "peer-receiver-new" {
		t.Fatalf("expected sync to promote active replacement remote peer, got %#v", source)
	}
	persisted, err := agent.stateStore.Load()
	if err != nil {
		t.Fatalf("reload active source state: %v", err)
	}
	sources := persisted.FileTransferSourcesFor(agent.remote.BaseURL(), agent.currentUser.ID)
	if len(sources) != 1 || sources[0].RemotePeerID != "peer-receiver-new" {
		t.Fatalf("expected persisted source metadata to promote active replacement remote peer, got %#v", sources)
	}
}

func TestSyncRegisteredFileTransferSourcePromotesActiveReplacementRemotePeerWithoutExplicitRemoteUserID(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sync-inferred-user-source-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	payload := bytes.Repeat([]byte("ole-sync-inferred-user"), 1024)
	sourcePath := filepath.Join(t.TempDir(), "sync-inferred-user-source.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write source payload: %v", err)
	}

	agent.currentUser = &controlclient.User{ID: "user-sender", Email: "sender@example.com"}
	agent.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-receiver-old", UserID: "user-receiver", NetworkID: "net-1"},
		{ID: "peer-receiver-new", UserID: "user-receiver", NetworkID: "net-1"},
	}
	agent.fileTransferSources = map[string]localFileTransferSource{
		"xfer-sync-inferred-user": {
			TransferID:     "xfer-sync-inferred-user",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender-new",
			RemotePeerID:   "peer-receiver-old",
			SourcePath:     sourcePath,
			FileName:       "sync-inferred-user-source.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-sync-inferred-user",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 1002,
		},
	}
	if err := agent.persistFileTransferSourceLocked(agent.fileTransferSources["xfer-sync-inferred-user"]); err != nil {
		t.Fatalf("persist inferred-user source state: %v", err)
	}
	agent.connections = []ConnectionStatus{{
		NetworkID:                "net-1",
		LocalPeerID:              "peer-sender-new",
		RemotePeerID:             "peer-receiver-new",
		TransportReady:           true,
		TransportMode:            "DIRECT",
		State:                    "CONNECTED",
		Reachability:             "DIRECT",
		LastTransportUnix:        210,
		TransportEstablishedUnix: 110,
	}}

	if err := agent.syncRegisteredFileTransferSourceLocked(&controlclient.FileTransfer{
		ID:         "xfer-sync-inferred-user",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-receiver-old",
		FileName:   "sync-inferred-user-source.bin",
		SizeBytes:  int64(len(payload)),
	}); err != nil {
		t.Fatalf("sync registered file transfer source during inferred-user overlap: %v", err)
	}

	source := agent.fileTransferSources["xfer-sync-inferred-user"]
	if source.RemoteUserID != "user-receiver" {
		t.Fatalf("expected sync to infer remote user ID from peer metadata, got %#v", source)
	}
	if source.RemotePeerID != "peer-receiver-new" {
		t.Fatalf("expected sync to promote active replacement remote peer without explicit remote user ID, got %#v", source)
	}
	persisted, err := agent.stateStore.Load()
	if err != nil {
		t.Fatalf("reload inferred-user source state: %v", err)
	}
	sources := persisted.FileTransferSourcesFor(agent.remote.BaseURL(), agent.currentUser.ID)
	if len(sources) != 1 || sources[0].RemoteUserID != "user-receiver" || sources[0].RemotePeerID != "peer-receiver-new" {
		t.Fatalf("expected persisted source metadata to infer remote user ID and promote active replacement remote peer, got %#v", sources)
	}
}

func TestSyncRegisteredFileTransferSourcePromotesActiveReplacementRemotePeerAcrossMetadataGap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sync-metadata-gap-source-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	payload := bytes.Repeat([]byte("ole-sync-metadata-gap"), 1024)
	sourcePath := filepath.Join(t.TempDir(), "sync-metadata-gap-source.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write source payload: %v", err)
	}

	agent.currentUser = &controlclient.User{ID: "user-sender", Email: "sender@example.com"}
	agent.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-receiver-old", UserID: "user-receiver", NetworkID: "net-1", VirtualIP: "10.0.0.9"},
	}
	agent.fileTransferSources = map[string]localFileTransferSource{
		"xfer-sync-metadata-gap-source": {
			TransferID:     "xfer-sync-metadata-gap-source",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender-new",
			RemotePeerID:   "peer-receiver-old",
			RemoteUserID:   "user-receiver",
			SourcePath:     sourcePath,
			FileName:       "sync-metadata-gap-source.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-sync-metadata-gap-source",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 1003,
		},
	}
	if err := agent.persistFileTransferSourceLocked(agent.fileTransferSources["xfer-sync-metadata-gap-source"]); err != nil {
		t.Fatalf("persist metadata-gap source state: %v", err)
	}
	agent.connections = []ConnectionStatus{{
		NetworkID:                "net-1",
		LocalPeerID:              "peer-sender-new",
		RemotePeerID:             "peer-receiver-new",
		RemoteVirtualIP:          "10.0.0.9",
		TransportReady:           true,
		TransportMode:            "DIRECT",
		State:                    "CONNECTED",
		Reachability:             "DIRECT",
		LastTransportUnix:        220,
		TransportEstablishedUnix: 120,
	}}

	if err := agent.syncRegisteredFileTransferSourceLocked(&controlclient.FileTransfer{
		ID:         "xfer-sync-metadata-gap-source",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-receiver-old",
		FileName:   "sync-metadata-gap-source.bin",
		SizeBytes:  int64(len(payload)),
	}); err != nil {
		t.Fatalf("sync registered file transfer source during metadata-gap overlap: %v", err)
	}

	source := agent.fileTransferSources["xfer-sync-metadata-gap-source"]
	if source.RemotePeerID != "peer-receiver-new" {
		t.Fatalf("expected sync to promote active replacement remote peer across metadata gap, got %#v", source)
	}
	if source.RemoteUserID != "user-receiver" {
		t.Fatalf("expected sync to preserve remote user identity across metadata gap, got %#v", source)
	}
	persisted, err := agent.stateStore.Load()
	if err != nil {
		t.Fatalf("reload metadata-gap source state: %v", err)
	}
	sources := persisted.FileTransferSourcesFor(agent.remote.BaseURL(), agent.currentUser.ID)
	if len(sources) != 1 || sources[0].RemotePeerID != "peer-receiver-new" || sources[0].RemoteUserID != "user-receiver" {
		t.Fatalf("expected persisted source metadata to promote active replacement remote peer across metadata gap, got %#v", sources)
	}
}

func TestSyncRegisteredFileTransferSourceKeepsReboundRemotePeerAcrossStaleMetadataGapWithoutLiveConnection(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sync-stale-metadata-gap-source-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	payload := bytes.Repeat([]byte("ole-sync-stale-metadata-gap"), 1024)
	sourcePath := filepath.Join(t.TempDir(), "sync-stale-metadata-gap-source.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write source payload: %v", err)
	}

	agent.currentUser = &controlclient.User{ID: "user-sender", Email: "sender@example.com"}
	agent.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-receiver-old", NetworkID: "net-1", VirtualIP: "10.0.0.9"},
	}
	agent.fileTransferSources = map[string]localFileTransferSource{
		"xfer-sync-stale-metadata-gap-source": {
			TransferID:     "xfer-sync-stale-metadata-gap-source",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender-new",
			RemotePeerID:   "peer-receiver-new",
			RemoteUserID:   "user-receiver",
			SourcePath:     sourcePath,
			FileName:       "sync-stale-metadata-gap-source.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-sync-stale-metadata-gap-source",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 1004,
		},
	}
	if err := agent.persistFileTransferSourceLocked(agent.fileTransferSources["xfer-sync-stale-metadata-gap-source"]); err != nil {
		t.Fatalf("persist stale metadata-gap source state: %v", err)
	}

	if err := agent.syncRegisteredFileTransferSourceLocked(&controlclient.FileTransfer{
		ID:         "xfer-sync-stale-metadata-gap-source",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-receiver-old",
		FileName:   "sync-stale-metadata-gap-source.bin",
		SizeBytes:  int64(len(payload)),
	}); err != nil {
		t.Fatalf("sync registered file transfer source during stale metadata gap without live connection: %v", err)
	}

	source := agent.fileTransferSources["xfer-sync-stale-metadata-gap-source"]
	if source.RemotePeerID != "peer-receiver-new" {
		t.Fatalf("expected sync to keep rebound remote peer across stale metadata gap without live connection, got %#v", source)
	}
	if source.RemoteUserID != "user-receiver" {
		t.Fatalf("expected sync to preserve remote user identity across stale metadata gap without live connection, got %#v", source)
	}
	persisted, err := agent.stateStore.Load()
	if err != nil {
		t.Fatalf("reload stale metadata-gap source state: %v", err)
	}
	sources := persisted.FileTransferSourcesFor(agent.remote.BaseURL(), agent.currentUser.ID)
	if len(sources) != 1 || sources[0].RemotePeerID != "peer-receiver-new" || sources[0].RemoteUserID != "user-receiver" {
		t.Fatalf("expected persisted source metadata to keep rebound remote peer across stale metadata gap without live connection, got %#v", sources)
	}
}

func TestSyncRegisteredFileTransferSourceKeepsReboundRemotePeerAcrossOverlayContinuityMetadataGapWithoutLiveConnection(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sync-stale-overlay-gap-source-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	payload := bytes.Repeat([]byte("ole-sync-stale-overlay-gap"), 1024)
	sourcePath := filepath.Join(t.TempDir(), "sync-stale-overlay-gap-source.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write source payload: %v", err)
	}

	agent.currentUser = &controlclient.User{ID: "user-sender", Email: "sender@example.com"}
	agent.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-receiver-old", NetworkID: "net-1", VirtualIP: "10.0.0.9"},
		{ID: "peer-receiver-new", NetworkID: "net-1", VirtualIP: "10.0.0.9"},
	}
	agent.fileTransferSources = map[string]localFileTransferSource{
		"xfer-sync-stale-overlay-gap-source": {
			TransferID:     "xfer-sync-stale-overlay-gap-source",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender-new",
			RemotePeerID:   "peer-receiver-new",
			SourcePath:     sourcePath,
			FileName:       "sync-stale-overlay-gap-source.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-sync-stale-overlay-gap-source",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 1005,
		},
	}
	if err := agent.persistFileTransferSourceLocked(agent.fileTransferSources["xfer-sync-stale-overlay-gap-source"]); err != nil {
		t.Fatalf("persist stale overlay-gap source state: %v", err)
	}

	if err := agent.syncRegisteredFileTransferSourceLocked(&controlclient.FileTransfer{
		ID:         "xfer-sync-stale-overlay-gap-source",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		FromUserID: "user-sender",
		ToPeerID:   "peer-receiver-old",
		FileName:   "sync-stale-overlay-gap-source.bin",
		SizeBytes:  int64(len(payload)),
	}); err != nil {
		t.Fatalf("sync registered file transfer source during stale overlay continuity metadata gap without live connection: %v", err)
	}

	source := agent.fileTransferSources["xfer-sync-stale-overlay-gap-source"]
	if source.RemotePeerID != "peer-receiver-new" {
		t.Fatalf("expected sync to keep rebound remote peer across overlay continuity metadata gap without live connection, got %#v", source)
	}
	if source.RemoteUserID != "" {
		t.Fatalf("expected sync to leave remote user identity blank across overlay continuity metadata gap without live connection, got %#v", source)
	}
	persisted, err := agent.stateStore.Load()
	if err != nil {
		t.Fatalf("reload stale overlay-gap source state: %v", err)
	}
	sources := persisted.FileTransferSourcesFor(agent.remote.BaseURL(), agent.currentUser.ID)
	if len(sources) != 1 || sources[0].RemotePeerID != "peer-receiver-new" || sources[0].RemoteUserID != "" {
		t.Fatalf("expected persisted source metadata to keep rebound remote peer across overlay continuity metadata gap without live connection, got %#v", sources)
	}
}

func TestSyncRegisteredFileTransferSourcePromotesActiveReplacementLocalPeerAcrossSenderMetadataGap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sync-local-peer-metadata-gap-source-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	payload := bytes.Repeat([]byte("ole-sync-local-peer-metadata-gap"), 1024)
	sourcePath := filepath.Join(t.TempDir(), "sync-local-peer-metadata-gap-source.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write source payload: %v", err)
	}

	agent.currentUser = &controlclient.User{ID: "user-sender", Email: "sender@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-sender-new", "127.0.0.1:0", "10.0.0.0/24", "10.0.0.2")
	agent.fileTransferSources = map[string]localFileTransferSource{
		"xfer-sync-local-peer-metadata-gap-source": {
			TransferID:     "xfer-sync-local-peer-metadata-gap-source",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender-old",
			RemotePeerID:   "peer-receiver-old",
			RemoteUserID:   "user-receiver",
			SourcePath:     sourcePath,
			FileName:       "sync-local-peer-metadata-gap-source.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-sync-local-peer-metadata-gap-source",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 1006,
		},
	}
	if err := agent.persistFileTransferSourceLocked(agent.fileTransferSources["xfer-sync-local-peer-metadata-gap-source"]); err != nil {
		t.Fatalf("persist local-peer metadata-gap source state: %v", err)
	}

	if err := agent.syncRegisteredFileTransferSourceLocked(&controlclient.FileTransfer{
		ID:         "xfer-sync-local-peer-metadata-gap-source",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender-old",
		ToPeerID:   "peer-receiver-old",
		ToUserID:   "user-receiver",
		FileName:   "sync-local-peer-metadata-gap-source.bin",
		SizeBytes:  int64(len(payload)),
	}); err != nil {
		t.Fatalf("sync registered file transfer source during sender metadata-gap local-peer overlap: %v", err)
	}

	source := agent.fileTransferSources["xfer-sync-local-peer-metadata-gap-source"]
	if source.LocalPeerID != "peer-sender-new" {
		t.Fatalf("expected sync to promote active replacement local peer across sender metadata gap, got %#v", source)
	}
	persisted, err := agent.stateStore.Load()
	if err != nil {
		t.Fatalf("reload local-peer metadata-gap source state: %v", err)
	}
	sources := persisted.FileTransferSourcesFor(agent.remote.BaseURL(), agent.currentUser.ID)
	if len(sources) != 1 || sources[0].LocalPeerID != "peer-sender-new" {
		t.Fatalf("expected persisted source metadata to promote active replacement local peer across sender metadata gap, got %#v", sources)
	}
}

func TestRestorePersistedFileTransferSourcePromotesReplacementRemotePeerAcrossMetadataGap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "restore-source-metadata-gap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	payload := bytes.Repeat([]byte("ole-restore-source-metadata-gap"), 1024)
	sourcePath := filepath.Join(t.TempDir(), "restore-source-metadata-gap.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write source payload: %v", err)
	}

	agent.currentUser = &controlclient.User{ID: "user-sender", Email: "sender@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-sender-new", "127.0.0.1:0", "10.0.0.0/24", "10.0.0.2")
	agent.deviceState.SetFileTransferSource(FileTransferSourceState{
		ServerBaseURL:  agent.remote.BaseURL(),
		UserID:         agent.currentUser.ID,
		TransferID:     "xfer-restore-source-metadata-gap",
		NetworkID:      "net-1",
		LocalPeerID:    "peer-sender-new",
		RemotePeerID:   "peer-receiver-old",
		SourcePath:     sourcePath,
		FileName:       "restore-source-metadata-gap.bin",
		ContentType:    "application/octet-stream",
		PayloadSHA256:  "sha-xfer-restore-source-metadata-gap",
		SizeBytes:      int64(len(payload)),
		UploadedAtUnix: 1006,
	})
	if err := agent.savePersistentStateLocked(); err != nil {
		t.Fatalf("persist source restore state: %v", err)
	}

	agent.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-receiver-old", NetworkID: "net-1", VirtualIP: "10.0.0.9"},
	}
	agent.connections = []ConnectionStatus{{
		NetworkID:                "net-1",
		LocalPeerID:              "peer-sender-new",
		RemotePeerID:             "peer-receiver-new",
		RemoteVirtualIP:          "10.0.0.9",
		TransportReady:           true,
		TransportMode:            "DIRECT",
		State:                    "CONNECTED",
		Reachability:             "DIRECT",
		TransportEstablishedUnix: 200,
		LastTransportUnix:        250,
	}}

	if err := agent.restorePersistedFileTransferSourcesLocked(); err != nil {
		t.Fatalf("restore persisted source metadata across metadata gap: %v", err)
	}

	source := agent.fileTransferSources["xfer-restore-source-metadata-gap"]
	if source.RemotePeerID != "peer-receiver-new" {
		t.Fatalf("expected restore to promote source remote peer onto live replacement across metadata gap, got %#v", source)
	}
	if source.RemoteUserID != "" {
		t.Fatalf("expected restore to leave source remote user blank across metadata gap, got %#v", source)
	}
	persisted, err := agent.stateStore.Load()
	if err != nil {
		t.Fatalf("reload restored source state: %v", err)
	}
	sources := persisted.FileTransferSourcesFor(agent.remote.BaseURL(), agent.currentUser.ID)
	if len(sources) != 1 || sources[0].RemotePeerID != "peer-receiver-new" || sources[0].RemoteUserID != "" {
		t.Fatalf("expected persisted source restore state to promote replacement remote peer across metadata gap, got %#v", sources)
	}
}

func TestRestorePersistedFileTransferCachePromotesReplacementRequesterPeerAcrossMetadataGap(t *testing.T) {
	agent := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "restore-cache-metadata-gap-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, &dataplaneExchangeManager{})
	defer agent.Close()

	payload := bytes.Repeat([]byte("ole-restore-cache-metadata-gap"), 2048)
	cachePath := filepath.Join(t.TempDir(), "restore-cache-metadata-gap.bin")
	if err := os.WriteFile(cachePath, payload, 0o600); err != nil {
		t.Fatalf("write cache payload: %v", err)
	}

	agent.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	agent.deviceState = defaultPersistentState()
	agent.deviceState.SetManagedPeer(agent.remote.BaseURL(), agent.currentUser.ID, "net-1", "peer-cache-holder-new", "127.0.0.1:0", "10.0.0.0/24", "10.0.0.4")
	agent.deviceState.SetFileTransferCache(FileTransferCacheState{
		ServerBaseURL:  agent.remote.BaseURL(),
		UserID:         agent.currentUser.ID,
		TransferID:     "xfer-restore-cache-metadata-gap",
		NetworkID:      "net-1",
		LocalPeerID:    "peer-cache-holder-new",
		RemotePeerID:   "peer-requester-old",
		CachePath:      cachePath,
		FileName:       "restore-cache-metadata-gap.bin",
		ContentType:    "application/octet-stream",
		PayloadSHA256:  "sha-xfer-restore-cache-metadata-gap",
		SizeBytes:      int64(len(payload)),
		CachedBytes:    int64(len(payload)),
		UploadedAtUnix: 1007,
	})
	if err := agent.savePersistentStateLocked(); err != nil {
		t.Fatalf("persist cache restore state: %v", err)
	}

	agent.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-requester-old", NetworkID: "net-1", VirtualIP: "10.0.0.10"},
	}
	agent.connections = []ConnectionStatus{{
		NetworkID:                "net-1",
		LocalPeerID:              "peer-cache-holder-new",
		RemotePeerID:             "peer-requester-new",
		RemoteVirtualIP:          "10.0.0.10",
		TransportReady:           true,
		TransportMode:            "DIRECT",
		State:                    "CONNECTED",
		Reachability:             "DIRECT",
		TransportEstablishedUnix: 210,
		LastTransportUnix:        260,
	}}

	if err := agent.restorePersistedFileTransferCachesLocked(); err != nil {
		t.Fatalf("restore persisted cache metadata across metadata gap: %v", err)
	}

	cache := agent.fileTransferCaches["xfer-restore-cache-metadata-gap"]
	if cache.RemotePeerID != "peer-requester-new" {
		t.Fatalf("expected restore to promote cache requester remote peer onto live replacement across metadata gap, got %#v", cache)
	}
	persisted, err := agent.stateStore.Load()
	if err != nil {
		t.Fatalf("reload restored cache state: %v", err)
	}
	caches := persisted.FileTransferCachesFor(agent.remote.BaseURL(), agent.currentUser.ID)
	if len(caches) != 1 || caches[0].RemotePeerID != "peer-requester-new" {
		t.Fatalf("expected persisted cache restore state to promote replacement requester remote peer across metadata gap, got %#v", caches)
	}
}
