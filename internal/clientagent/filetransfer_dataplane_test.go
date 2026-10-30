package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/directprobe"
	"Ole/internal/domain"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

type dataplaneExchangeManager struct {
	mu       sync.Mutex
	handlers map[string]directprobe.ExchangeHandler
	sessions map[string]directprobe.Session
}

func (m *dataplaneExchangeManager) Reconcile(_ []directprobe.Binding) error {
	return nil
}

func (m *dataplaneExchangeManager) Attempt(_, _ string, remoteCandidates []string, _ time.Duration) (directprobe.Result, error) {
	if len(remoteCandidates) == 0 {
		return directprobe.Result{}, errors.New("missing candidate")
	}
	return directprobe.Result{RemoteAddress: remoteCandidates[0]}, nil
}

func (m *dataplaneExchangeManager) Establish(localPeerID, remotePeerID string, remoteCandidates []string, _ time.Duration) (directprobe.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions == nil {
		m.sessions = map[string]directprobe.Session{}
	}
	session := directprobe.Session{
		SessionID:         localPeerID + "|" + remotePeerID,
		EstablishedAtUnix: time.Now().Unix(),
	}
	if len(remoteCandidates) > 0 {
		session.RemoteAddress = remoteCandidates[0]
	}
	m.sessions[localPeerID+"|"+remotePeerID] = session
	return session, nil
}

func (m *dataplaneExchangeManager) Exchange(localPeerID, remotePeerID string, payload []byte, _ time.Duration) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions == nil || m.sessions[localPeerID+"|"+remotePeerID].SessionID == "" {
		return nil, errors.New("missing session")
	}
	if handler := m.handlers[remotePeerID]; handler != nil {
		if response := handler(localPeerID, append([]byte(nil), payload...)); response != nil {
			return response, nil
		}
	}
	return []byte("ack:" + string(payload)), nil
}

func (m *dataplaneExchangeManager) SetExchangeHandler(localPeerID string, handler directprobe.ExchangeHandler) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.handlers == nil {
		m.handlers = map[string]directprobe.ExchangeHandler{}
	}
	if handler == nil {
		delete(m.handlers, localPeerID)
		return nil
	}
	m.handlers[localPeerID] = handler
	return nil
}

func (m *dataplaneExchangeManager) SendPacket(_, _ string, _ []byte) error {
	return nil
}

func (m *dataplaneExchangeManager) DrainInbound(_ string, _ int) []directprobe.Packet {
	return nil
}

func (m *dataplaneExchangeManager) DropSession(localPeerID, remotePeerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions != nil {
		delete(m.sessions, localPeerID+"|"+remotePeerID)
	}
}

func (m *dataplaneExchangeManager) Close() error {
	return nil
}

func TestDownloadFileTransferContentChunkViaDataplaneUsesRegisteredSenderSource(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	sender := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sender-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer sender.Close()
	receiver := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New("http://example.invalid"), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "receiver-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiver.Close()

	payload := bytes.Repeat([]byte("ole-dataplane"), (fileTransferDataplaneChunkBytes/12)+200)
	sourcePath := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write sender payload: %v", err)
	}

	sender.fileTransferSources = map[string]localFileTransferSource{
		"xfer-1": {
			TransferID:     "xfer-1",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender",
			RemotePeerID:   "peer-receiver",
			SourcePath:     sourcePath,
			FileName:       "payload.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-1",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 123,
		},
	}
	if err := manager.SetExchangeHandler("peer-sender", sender.transportExchangeHandler("peer-sender")); err != nil {
		t.Fatalf("set sender exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-receiver", "peer-sender", []string{"127.0.0.1:43100"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish dataplane session: %v", err)
	}

	receiver.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-receiver",
		RemotePeerID:   "peer-sender",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}

	requestLimit := int64(fileTransferDataplaneChunkBytes + 1024)
	chunk, err := receiver.downloadFileTransferContentChunkViaDataplaneLocked(controlclient.FileTransfer{
		ID:         "xfer-1",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender",
		ToPeerID:   "peer-receiver",
		FileName:   "payload.bin",
		SizeBytes:  int64(len(payload)),
	}, 0, requestLimit)
	if err != nil {
		t.Fatalf("download dataplane chunk: %v", err)
	}
	if len(chunk.Payload) != int(requestLimit) {
		t.Fatalf("expected %d dataplane bytes, got %d", requestLimit, len(chunk.Payload))
	}
	if !bytes.Equal(chunk.Payload, payload[:requestLimit]) {
		t.Fatalf("unexpected dataplane chunk payload")
	}
	if chunk.NextOffsetBytes != requestLimit || chunk.Complete {
		t.Fatalf("expected partial dataplane chunk, got %#v", chunk)
	}
	if chunk.ContentType != "application/octet-stream" || chunk.SHA256 != "sha-xfer-1" || chunk.UploadedAtUnix != 123 {
		t.Fatalf("expected dataplane metadata to round-trip, got %#v", chunk)
	}
}

func TestDownloadFileTransferContentChunkMirrorsDataplanePayloadToControlPlaneForOfflineFallback(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	payload := bytes.Repeat([]byte("ole-mirror"), 128)
	sourcePath := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write sender payload: %v", err)
	}

	upstream := newMirroringTransferServer(controlclient.Network{
		ID:                   "net-1",
		Name:                 "friends",
		FileTransfersEnabled: true,
		FileTransferMaxBytes: domain.DefaultControlPlaneFileTransferPayloadMaxBytes,
	}, controlclient.FileTransfer{
		ID:         "xfer-mirror",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender",
		ToPeerID:   "peer-receiver",
		FileName:   "payload.bin",
		SizeBytes:  int64(len(payload)),
		Status:     "IN_PROGRESS",
	})
	upstreamServer := httptest.NewServer(upstream.handler())
	defer upstreamServer.Close()

	sender := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sender-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer sender.Close()
	receiver := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "receiver-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiver.Close()
	receiver.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}

	sender.fileTransferSources = map[string]localFileTransferSource{
		"xfer-mirror": {
			TransferID:     "xfer-mirror",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender",
			RemotePeerID:   "peer-receiver",
			SourcePath:     sourcePath,
			FileName:       "payload.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-mirror",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 111,
		},
	}
	if err := manager.SetExchangeHandler("peer-sender", sender.transportExchangeHandler("peer-sender")); err != nil {
		t.Fatalf("set sender exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-receiver", "peer-sender", []string{"127.0.0.1:43110"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish dataplane session: %v", err)
	}
	receiver.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-receiver",
		RemotePeerID:   "peer-sender",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}

	first, err := receiver.DownloadFileTransferContentChunk("xfer-mirror", 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download mirrored dataplane chunk: %v", err)
	}
	if !bytes.Equal(first.Payload, payload) || !first.Transfer.PayloadReady {
		t.Fatalf("expected dataplane chunk to mirror into control plane, got %#v", first)
	}
	if upstream.uploadCalls() == 0 {
		t.Fatalf("expected mirrored control-plane upload call")
	}

	receiver.connections = nil
	manager.DropSession("peer-receiver", "peer-sender")
	if err := manager.SetExchangeHandler("peer-sender", nil); err != nil {
		t.Fatalf("clear sender exchange handler: %v", err)
	}

	second, err := receiver.DownloadFileTransferContentChunk("xfer-mirror", 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download mirrored control-plane chunk after sender offline: %v", err)
	}
	if !bytes.Equal(second.Payload, payload) || !second.Complete {
		t.Fatalf("expected offline fallback chunk to come from mirrored control-plane payload, got %#v", second)
	}
	if upstream.downloadCalls() == 0 {
		t.Fatalf("expected control-plane chunk download after sender went offline")
	}
}

func TestAutoMirrorAcceptedFileTransfersMirrorsInboxTransferWithoutManualDownload(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	payload := bytes.Repeat([]byte("ole-auto-mirror"), 1024)
	sourcePath := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write sender payload: %v", err)
	}

	upstream := newMirroringTransferServer(controlclient.Network{
		ID:                   "net-1",
		Name:                 "friends",
		FileTransfersEnabled: true,
		FileTransferMaxBytes: domain.DefaultControlPlaneFileTransferPayloadMaxBytes,
	}, controlclient.FileTransfer{
		ID:         "xfer-auto-mirror",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender",
		ToPeerID:   "peer-receiver",
		FileName:   "payload.bin",
		SizeBytes:  int64(len(payload)),
		Status:     "IN_PROGRESS",
	})
	upstreamServer := httptest.NewServer(upstream.handler())
	defer upstreamServer.Close()

	sender := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sender-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer sender.Close()
	receiver := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "receiver-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiver.Close()

	sender.fileTransferSources = map[string]localFileTransferSource{
		"xfer-auto-mirror": {
			TransferID:     "xfer-auto-mirror",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender",
			RemotePeerID:   "peer-receiver",
			SourcePath:     sourcePath,
			FileName:       "payload.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-auto-mirror",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 222,
		},
	}
	if err := manager.SetExchangeHandler("peer-sender", sender.transportExchangeHandler("peer-sender")); err != nil {
		t.Fatalf("set sender exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-receiver", "peer-sender", []string{"127.0.0.1:43120"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish dataplane session: %v", err)
	}

	receiver.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	receiver.currentSession = &controlclient.Session{AccessToken: "token", RefreshToken: "refresh", ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}
	receiver.deviceState = &PersistentState{}
	receiver.deviceState.SetManagedPeer(receiver.remote.BaseURL(), receiver.currentUser.ID, "net-1", "peer-receiver", "127.0.0.1:43120", "10.0.0.0/24", "10.0.0.2")
	receiver.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-receiver",
		RemotePeerID:   "peer-sender",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}

	receiver.mu.Lock()
	err := receiver.autoMirrorAcceptedFileTransfersLocked()
	receiver.mu.Unlock()
	if err != nil {
		t.Fatalf("auto mirror accepted file transfer: %v", err)
	}
	if upstream.uploadCalls() == 0 {
		t.Fatalf("expected background auto-mirror to upload control-plane chunk")
	}

	receiver.connections = nil
	manager.DropSession("peer-receiver", "peer-sender")
	if err := manager.SetExchangeHandler("peer-sender", nil); err != nil {
		t.Fatalf("clear sender exchange handler: %v", err)
	}

	content, err := receiver.DownloadFileTransferContentChunk("xfer-auto-mirror", 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download auto-mirrored control-plane chunk after sender offline: %v", err)
	}
	if !bytes.Equal(content.Payload, payload) || !content.Transfer.PayloadReady {
		t.Fatalf("expected auto-mirrored payload to survive sender going offline, got %#v", content)
	}
	if upstream.downloadCalls() == 0 {
		t.Fatalf("expected offline fallback download to use mirrored control-plane payload")
	}
}

func TestAutoMirrorAcceptedFileTransfersKeepsMirroringDoneTransferUntilPayloadReady(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	payload := bytes.Repeat([]byte("ole-auto-mirror-done"), 1024)
	sourcePath := filepath.Join(t.TempDir(), "payload-done.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatalf("write sender payload: %v", err)
	}

	upstream := newMirroringTransferServer(controlclient.Network{
		ID:                   "net-1",
		Name:                 "friends",
		FileTransfersEnabled: true,
		FileTransferMaxBytes: domain.DefaultControlPlaneFileTransferPayloadMaxBytes,
	}, controlclient.FileTransfer{
		ID:         "xfer-auto-mirror-done",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender",
		ToPeerID:   "peer-receiver",
		FileName:   "payload-done.bin",
		SizeBytes:  int64(len(payload)),
		Status:     "IN_PROGRESS",
	})
	upstreamServer := httptest.NewServer(upstream.handler())
	defer upstreamServer.Close()

	sender := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sender-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer sender.Close()
	receiver := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "receiver-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiver.Close()

	sender.fileTransferSources = map[string]localFileTransferSource{
		"xfer-auto-mirror-done": {
			TransferID:     "xfer-auto-mirror-done",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender",
			RemotePeerID:   "peer-receiver",
			SourcePath:     sourcePath,
			FileName:       "payload-done.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-auto-mirror-done",
			SizeBytes:      int64(len(payload)),
			UploadedAtUnix: 223,
		},
	}
	if err := manager.SetExchangeHandler("peer-sender", sender.transportExchangeHandler("peer-sender")); err != nil {
		t.Fatalf("set sender exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-receiver", "peer-sender", []string{"127.0.0.1:43121"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish dataplane session: %v", err)
	}

	receiver.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	receiver.currentSession = &controlclient.Session{AccessToken: "token", RefreshToken: "refresh", ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}
	receiver.deviceState = &PersistentState{}
	receiver.deviceState.SetManagedPeer(receiver.remote.BaseURL(), receiver.currentUser.ID, "net-1", "peer-receiver", "127.0.0.1:43121", "10.0.0.0/24", "10.0.0.2")
	receiver.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-receiver",
		RemotePeerID:   "peer-sender",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}

	completed, err := receiver.UpdateFileTransferProgress("xfer-auto-mirror-done", 100)
	if err != nil {
		t.Fatalf("mark auto-mirror transfer done before background mirror: %v", err)
	}
	if completed.Status != "DONE" || completed.ProgressPercent != 100 || completed.PayloadReady {
		t.Fatalf("expected completed transfer without mirrored payload yet, got %#v", completed)
	}

	receiver.mu.Lock()
	err = receiver.autoMirrorAcceptedFileTransfersLocked()
	receiver.mu.Unlock()
	if err != nil {
		t.Fatalf("auto mirror completed transfer: %v", err)
	}
	if upstream.uploadCalls() == 0 {
		t.Fatalf("expected background auto-mirror to keep mirroring completed transfer")
	}

	receiver.connections = nil
	manager.DropSession("peer-receiver", "peer-sender")
	if err := manager.SetExchangeHandler("peer-sender", nil); err != nil {
		t.Fatalf("clear sender exchange handler: %v", err)
	}

	content, err := receiver.DownloadFileTransferContentChunk("xfer-auto-mirror-done", 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("download mirrored completed transfer after sender offline: %v", err)
	}
	if !bytes.Equal(content.Payload, payload) || !content.Transfer.PayloadReady || content.Transfer.Status != "DONE" {
		t.Fatalf("expected completed transfer to keep mirrored offline fallback, got %#v", content)
	}
	if upstream.downloadCalls() == 0 {
		t.Fatalf("expected completed transfer offline fallback to use mirrored control-plane payload")
	}
}

func TestAutoMirrorAcceptedFileTransfersMirrorsLargeTransferAboveSenderControlPlaneCeiling(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	sizeBytes := domain.DefaultControlPlaneFileTransferPayloadMaxBytes + 1
	sourcePath := filepath.Join(t.TempDir(), "large-mirror.bin")
	file, err := os.Create(sourcePath)
	if err != nil {
		t.Fatalf("create large payload: %v", err)
	}
	prefix := bytes.Repeat([]byte("ole-large-mirror"), 8192)
	if _, err := file.Write(prefix); err != nil {
		_ = file.Close()
		t.Fatalf("seed large payload: %v", err)
	}
	if err := file.Truncate(sizeBytes); err != nil {
		_ = file.Close()
		t.Fatalf("truncate large payload: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close large payload: %v", err)
	}

	upstream := newMirroringTransferServer(controlclient.Network{
		ID:                   "net-1",
		Name:                 "friends",
		FileTransfersEnabled: true,
		FileTransferMaxBytes: sizeBytes,
	}, controlclient.FileTransfer{
		ID:         "xfer-large-mirror",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender",
		ToPeerID:   "peer-receiver-a",
		FileName:   "large-mirror.bin",
		SizeBytes:  sizeBytes,
		Status:     "IN_PROGRESS",
	})
	upstreamServer := httptest.NewServer(upstream.handler())
	defer upstreamServer.Close()

	sender := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sender-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer sender.Close()
	receiverA := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "receiver-a-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiverA.Close()
	receiverBStatePath := filepath.Join(t.TempDir(), "receiver-b-state.json")
	receiverB := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", NewStateStore(receiverBStatePath), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiverB.Close()

	sender.fileTransferSources = map[string]localFileTransferSource{
		"xfer-large-mirror": {
			TransferID:     "xfer-large-mirror",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender",
			RemotePeerID:   "peer-receiver-a",
			SourcePath:     sourcePath,
			FileName:       "large-mirror.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-large-mirror",
			SizeBytes:      sizeBytes,
			UploadedAtUnix: 333,
		},
	}
	if err := manager.SetExchangeHandler("peer-sender", sender.transportExchangeHandler("peer-sender")); err != nil {
		t.Fatalf("set sender exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-a", "peer-sender", []string{"127.0.0.1:43125"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish receiver A -> sender session: %v", err)
	}

	receiverA.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	receiverA.currentSession = &controlclient.Session{AccessToken: "token-a", RefreshToken: "refresh-a", ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}
	receiverA.deviceState = defaultPersistentState()
	receiverA.deviceState.SetManagedPeer(receiverA.remote.BaseURL(), receiverA.currentUser.ID, "net-1", "peer-receiver-a", "127.0.0.1:43125", "10.0.0.0/24", "10.0.0.2")
	receiverA.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-receiver-a",
		RemotePeerID:   "peer-sender",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}
	receiverB.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	receiverB.currentSession = &controlclient.Session{AccessToken: "token-b", RefreshToken: "refresh-b", ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}

	maxPasses := int((sizeBytes+fileTransferAgentChunkBytes-1)/fileTransferAgentChunkBytes) + 2
	for attempt := 0; attempt < maxPasses; attempt++ {
		receiverA.mu.Lock()
		err = receiverA.autoMirrorAcceptedFileTransfersLocked()
		receiverA.mu.Unlock()
		if err != nil {
			t.Fatalf("auto mirror large transfer on attempt %d: %v", attempt, err)
		}
		transfer, err := receiverA.remote.GetFileTransfer("xfer-large-mirror")
		if err != nil {
			t.Fatalf("get mirrored transfer state: %v", err)
		}
		if transfer.PayloadReady {
			break
		}
		if attempt == maxPasses-1 {
			t.Fatalf("expected large transfer to finish mirrored control-plane upload within %d passes", maxPasses)
		}
	}
	if upstream.uploadCalls() == 0 {
		t.Fatalf("expected large transfer auto-mirror to upload control-plane chunks")
	}
	if receiverA.cachedFileTransferBytesLocked("xfer-large-mirror") != 0 {
		t.Fatalf("expected large mirrored transfer to avoid receiver-local cache staging")
	}

	manager.DropSession("peer-receiver-a", "peer-sender")
	receiverA.connections = nil
	if err := manager.SetExchangeHandler("peer-sender", nil); err != nil {
		t.Fatalf("clear sender exchange handler: %v", err)
	}

	requestLimit := int64(64 << 10)
	expected := make([]byte, requestLimit)
	fh, err := os.Open(sourcePath)
	if err != nil {
		t.Fatalf("open source file for expected bytes: %v", err)
	}
	defer fh.Close()
	n, err := io.ReadFull(fh, expected)
	if err != nil {
		t.Fatalf("read expected bytes: %v", err)
	}
	expected = expected[:n]

	content, err := receiverB.DownloadFileTransferContentChunk("xfer-large-mirror", 0, requestLimit)
	if err != nil {
		t.Fatalf("download mirrored large chunk on fresh device after sender offline: %v", err)
	}
	if !bytes.Equal(content.Payload, expected) {
		t.Fatalf("expected fresh device to read mirrored large-transfer bytes from control plane")
	}
	if !content.Transfer.PayloadReady {
		t.Fatalf("expected large transfer payload to stay mirrored and ready for offline fallback")
	}
	if upstream.downloadCalls() == 0 {
		t.Fatalf("expected fresh device offline fallback to use mirrored control-plane payload")
	}
}

func TestDownloadFileTransferContentChunkStagesOversizedDataplanePayloadToLocalCacheAcrossRestart(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	sizeBytes := domain.DefaultMirroredFileTransferPayloadMaxBytes + 1
	sourcePath := filepath.Join(t.TempDir(), "oversized.bin")
	file, err := os.Create(sourcePath)
	if err != nil {
		t.Fatalf("create oversized payload: %v", err)
	}
	prefix := bytes.Repeat([]byte("ole-cache"), 8192)
	if _, err := file.Write(prefix); err != nil {
		_ = file.Close()
		t.Fatalf("seed oversized payload: %v", err)
	}
	if err := file.Truncate(sizeBytes); err != nil {
		_ = file.Close()
		t.Fatalf("truncate oversized payload: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close oversized payload: %v", err)
	}

	upstream := newMirroringTransferServer(controlclient.Network{
		ID:                   "net-1",
		Name:                 "friends",
		FileTransfersEnabled: true,
		FileTransferMaxBytes: sizeBytes,
	}, controlclient.FileTransfer{
		ID:         "xfer-cache",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender",
		ToPeerID:   "peer-receiver",
		FileName:   "oversized.bin",
		SizeBytes:  sizeBytes,
		Status:     "IN_PROGRESS",
	})
	upstreamServer := httptest.NewServer(upstream.handler())
	defer upstreamServer.Close()

	receiverStore := NewStateStore(filepath.Join(t.TempDir(), "receiver-state.json"))
	sender := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sender-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer sender.Close()
	receiver := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", receiverStore, RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)

	sender.fileTransferSources = map[string]localFileTransferSource{
		"xfer-cache": {
			TransferID:     "xfer-cache",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender",
			RemotePeerID:   "peer-receiver",
			SourcePath:     sourcePath,
			FileName:       "oversized.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-cache",
			SizeBytes:      sizeBytes,
			UploadedAtUnix: 333,
		},
	}
	if err := manager.SetExchangeHandler("peer-sender", sender.transportExchangeHandler("peer-sender")); err != nil {
		t.Fatalf("set sender exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-receiver", "peer-sender", []string{"127.0.0.1:43130"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish dataplane session: %v", err)
	}

	receiver.mu.Lock()
	receiver.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	receiver.currentSession = &controlclient.Session{AccessToken: "token", RefreshToken: "refresh", ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}
	receiver.deviceState = defaultPersistentState()
	receiver.deviceState.SetManagedPeer(receiver.remote.BaseURL(), receiver.currentUser.ID, "net-1", "peer-receiver", "127.0.0.1:43130", "10.0.0.0/24", "10.0.0.2")
	if err := receiver.savePersistentStateLocked(); err != nil {
		receiver.mu.Unlock()
		t.Fatalf("persist receiver state: %v", err)
	}
	receiver.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-receiver",
		RemotePeerID:   "peer-sender",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}
	receiver.mu.Unlock()

	requestLimit := int64(64 << 10)
	first, err := receiver.DownloadFileTransferContentChunk("xfer-cache", 0, requestLimit)
	if err != nil {
		t.Fatalf("download oversized dataplane chunk: %v", err)
	}
	if len(first.Payload) != int(requestLimit) {
		t.Fatalf("expected %d cached bytes, got %d", requestLimit, len(first.Payload))
	}
	if first.Transfer.PayloadReady {
		t.Fatalf("expected oversized transfer to stay off control-plane mirror path")
	}

	receiver.Close()

	restored := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", receiverStore, RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer restored.Close()
	restored.mu.Lock()
	restored.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	restored.currentSession = &controlclient.Session{AccessToken: "token", RefreshToken: "refresh", ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}
	if err := restored.restorePersistedFileTransferCachesLocked(); err != nil {
		restored.mu.Unlock()
		t.Fatalf("restore persisted oversized cache: %v", err)
	}
	restored.mu.Unlock()

	manager.DropSession("peer-receiver", "peer-sender")
	if err := manager.SetExchangeHandler("peer-sender", nil); err != nil {
		t.Fatalf("clear sender exchange handler: %v", err)
	}

	second, err := restored.DownloadFileTransferContentChunk("xfer-cache", 0, requestLimit)
	if err != nil {
		t.Fatalf("download oversized cached chunk after restart and sender offline: %v", err)
	}
	if !bytes.Equal(second.Payload, first.Payload) {
		t.Fatalf("expected oversized transfer to read from restored local cache")
	}
	if second.Transfer.PayloadReady {
		t.Fatalf("expected oversized local-cache fallback without mirrored control-plane payload")
	}
}

func TestDownloadFileTransferContentChunkUsesSameUserPeerCacheWhenSenderOffline(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	sizeBytes := domain.DefaultMirroredFileTransferPayloadMaxBytes + 1
	sourcePath := filepath.Join(t.TempDir(), "shared-oversized.bin")
	file, err := os.Create(sourcePath)
	if err != nil {
		t.Fatalf("create oversized payload: %v", err)
	}
	prefix := bytes.Repeat([]byte("ole-share"), 8192)
	if _, err := file.Write(prefix); err != nil {
		_ = file.Close()
		t.Fatalf("seed oversized payload: %v", err)
	}
	if err := file.Truncate(sizeBytes); err != nil {
		_ = file.Close()
		t.Fatalf("truncate oversized payload: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close oversized payload: %v", err)
	}

	upstream := newMirroringTransferServer(controlclient.Network{
		ID:                   "net-1",
		Name:                 "friends",
		FileTransfersEnabled: true,
		FileTransferMaxBytes: sizeBytes,
	}, controlclient.FileTransfer{
		ID:         "xfer-share",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender",
		ToPeerID:   "peer-receiver-a",
		FileName:   "shared-oversized.bin",
		SizeBytes:  sizeBytes,
		Status:     "IN_PROGRESS",
	})
	upstreamServer := httptest.NewServer(upstream.handler())
	defer upstreamServer.Close()

	sender := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sender-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer sender.Close()
	receiverA := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "receiver-a-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiverA.Close()
	receiverBStatePath := filepath.Join(t.TempDir(), "receiver-b-state.json")
	receiverB := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", NewStateStore(receiverBStatePath), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiverB.Close()

	sender.fileTransferSources = map[string]localFileTransferSource{
		"xfer-share": {
			TransferID:     "xfer-share",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender",
			RemotePeerID:   "peer-receiver-a",
			SourcePath:     sourcePath,
			FileName:       "shared-oversized.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-share",
			SizeBytes:      sizeBytes,
			UploadedAtUnix: 444,
		},
	}
	if err := manager.SetExchangeHandler("peer-sender", sender.transportExchangeHandler("peer-sender")); err != nil {
		t.Fatalf("set sender exchange handler: %v", err)
	}
	if err := manager.SetExchangeHandler("peer-receiver-a", receiverA.transportExchangeHandler("peer-receiver-a")); err != nil {
		t.Fatalf("set receiver A exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-a", "peer-sender", []string{"127.0.0.1:43140"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish receiver A -> sender session: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-b", "peer-receiver-a", []string{"127.0.0.1:43141"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish receiver B -> receiver A session: %v", err)
	}

	receiverA.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	receiverA.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-receiver-b", UserID: "user-receiver", NetworkID: "net-1"},
		{ID: "peer-sender", UserID: "user-sender", NetworkID: "net-1"},
	}
	receiverA.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-receiver-a",
		RemotePeerID:   "peer-sender",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}
	receiverB.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	receiverB.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-receiver-a", UserID: "user-receiver", NetworkID: "net-1"},
	}
	receiverB.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-receiver-b",
		RemotePeerID:   "peer-receiver-a",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}

	requestLimit := int64(64 << 10)
	staged, err := receiverA.DownloadFileTransferContentChunk("xfer-share", 0, requestLimit)
	if err != nil {
		t.Fatalf("stage oversized chunk on receiver A: %v", err)
	}
	if len(staged.Payload) != int(requestLimit) {
		t.Fatalf("expected receiver A to stage %d bytes, got %d", requestLimit, len(staged.Payload))
	}
	if receiverA.cachedFileTransferBytesLocked("xfer-share") == 0 {
		t.Fatalf("expected receiver A to keep staged cache bytes")
	}

	manager.DropSession("peer-receiver-a", "peer-sender")
	if err := manager.SetExchangeHandler("peer-sender", nil); err != nil {
		t.Fatalf("clear sender exchange handler: %v", err)
	}

	shared, err := receiverB.DownloadFileTransferContentChunk("xfer-share", 0, requestLimit)
	if err != nil {
		t.Fatalf("download chunk from same-user peer cache: %v", err)
	}
	if !bytes.Equal(shared.Payload, staged.Payload) {
		t.Fatalf("expected receiver B to read staged bytes from receiver A cache")
	}
	if receiverB.cachedFileTransferBytesLocked("xfer-share") == 0 {
		t.Fatalf("expected receiver B to stage the shared cache bytes locally as well")
	}
	if shared.Transfer.PayloadReady {
		t.Fatalf("expected oversized same-user peer-cache path without control-plane payload mirror")
	}
}

func TestAutoMirrorAcceptedFileTransfersStagesOversizedChunkFromSameUserPeerCache(t *testing.T) {
	manager := &dataplaneExchangeManager{}
	sizeBytes := domain.DefaultMirroredFileTransferPayloadMaxBytes + 1
	sourcePath := filepath.Join(t.TempDir(), "shared-auto-stage.bin")
	file, err := os.Create(sourcePath)
	if err != nil {
		t.Fatalf("create oversized payload: %v", err)
	}
	prefix := bytes.Repeat([]byte("ole-auto-stage"), 8192)
	if _, err := file.Write(prefix); err != nil {
		_ = file.Close()
		t.Fatalf("seed oversized payload: %v", err)
	}
	if err := file.Truncate(sizeBytes); err != nil {
		_ = file.Close()
		t.Fatalf("truncate oversized payload: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close oversized payload: %v", err)
	}

	upstream := newMirroringTransferServer(controlclient.Network{
		ID:                   "net-1",
		Name:                 "friends",
		FileTransfersEnabled: true,
		FileTransferMaxBytes: sizeBytes,
	}, controlclient.FileTransfer{
		ID:         "xfer-auto-stage-share",
		NetworkID:  "net-1",
		FromPeerID: "peer-sender",
		ToPeerID:   "peer-receiver-a",
		FileName:   "shared-auto-stage.bin",
		SizeBytes:  sizeBytes,
		Status:     "IN_PROGRESS",
	})
	upstreamServer := httptest.NewServer(upstream.handler())
	defer upstreamServer.Close()

	sender := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "sender-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer sender.Close()
	receiverA := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "receiver-a-state.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiverA.Close()
	receiverBStatePath := filepath.Join(t.TempDir(), "receiver-b-state.json")
	receiverB := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", NewStateStore(receiverBStatePath), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer receiverB.Close()

	sender.fileTransferSources = map[string]localFileTransferSource{
		"xfer-auto-stage-share": {
			TransferID:     "xfer-auto-stage-share",
			NetworkID:      "net-1",
			LocalPeerID:    "peer-sender",
			RemotePeerID:   "peer-receiver-a",
			SourcePath:     sourcePath,
			FileName:       "shared-auto-stage.bin",
			ContentType:    "application/octet-stream",
			PayloadSHA256:  "sha-xfer-auto-stage-share",
			SizeBytes:      sizeBytes,
			UploadedAtUnix: 555,
		},
	}
	if err := manager.SetExchangeHandler("peer-sender", sender.transportExchangeHandler("peer-sender")); err != nil {
		t.Fatalf("set sender exchange handler: %v", err)
	}
	if err := manager.SetExchangeHandler("peer-receiver-a", receiverA.transportExchangeHandler("peer-receiver-a")); err != nil {
		t.Fatalf("set receiver A exchange handler: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-a", "peer-sender", []string{"127.0.0.1:43150"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish receiver A -> sender session: %v", err)
	}
	if _, err := manager.Establish("peer-receiver-b", "peer-receiver-a", []string{"127.0.0.1:43151"}, 10*time.Millisecond); err != nil {
		t.Fatalf("establish receiver B -> receiver A session: %v", err)
	}

	receiverA.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	receiverA.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-receiver-b", UserID: "user-receiver", NetworkID: "net-1"},
		{ID: "peer-sender", UserID: "user-sender", NetworkID: "net-1"},
	}
	receiverA.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-receiver-a",
		RemotePeerID:   "peer-sender",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}
	receiverB.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	receiverB.currentSession = &controlclient.Session{AccessToken: "token", RefreshToken: "refresh", ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}
	receiverB.deviceState = defaultPersistentState()
	receiverB.deviceState.SetManagedPeer(receiverB.remote.BaseURL(), receiverB.currentUser.ID, "net-1", "peer-receiver-b", "127.0.0.1:43151", "10.0.0.0/24", "10.0.0.4")
	receiverB.mu.Lock()
	err = receiverB.savePersistentStateLocked()
	receiverB.mu.Unlock()
	if err != nil {
		t.Fatalf("persist receiver B managed peer state: %v", err)
	}
	receiverB.discoveredPeers["net-1"] = []controlclient.Peer{
		{ID: "peer-receiver-a", UserID: "user-receiver", NetworkID: "net-1"},
		{ID: "peer-sender", UserID: "user-sender", NetworkID: "net-1"},
	}
	receiverB.connections = []ConnectionStatus{{
		NetworkID:      "net-1",
		LocalPeerID:    "peer-receiver-b",
		RemotePeerID:   "peer-receiver-a",
		TransportReady: true,
		TransportMode:  "DIRECT",
		State:          "CONNECTED",
		Reachability:   "DIRECT",
	}}

	requestLimit := int64(64 << 10)
	stagedOnA, err := receiverA.DownloadFileTransferContentChunk("xfer-auto-stage-share", 0, requestLimit)
	if err != nil {
		t.Fatalf("stage oversized chunk on receiver A: %v", err)
	}
	if len(stagedOnA.Payload) != int(requestLimit) {
		t.Fatalf("expected receiver A to stage %d bytes, got %d", requestLimit, len(stagedOnA.Payload))
	}
	if receiverA.cachedFileTransferBytesLocked("xfer-auto-stage-share") == 0 {
		t.Fatalf("expected receiver A to keep staged cache bytes")
	}
	completed, err := receiverA.UpdateFileTransferProgress("xfer-auto-stage-share", 100)
	if err != nil {
		t.Fatalf("mark oversized transfer done on receiver A: %v", err)
	}
	if completed.Status != "DONE" || completed.ProgressPercent != 100 {
		t.Fatalf("expected receiver A to complete transfer before same-user auto-stage, got %#v", completed)
	}

	manager.DropSession("peer-receiver-a", "peer-sender")
	receiverA.connections = nil
	if err := manager.SetExchangeHandler("peer-sender", nil); err != nil {
		t.Fatalf("clear sender exchange handler: %v", err)
	}

	receiverB.mu.Lock()
	err = receiverB.autoMirrorAcceptedFileTransfersLocked()
	receiverB.mu.Unlock()
	if err != nil {
		t.Fatalf("auto-stage oversized chunk from same-user peer cache: %v", err)
	}
	if receiverB.cachedFileTransferBytesLocked("xfer-auto-stage-share") == 0 {
		t.Fatalf("expected receiver B to auto-stage bytes from receiver A cache")
	}
	cache, ok := receiverB.fileTransferCaches["xfer-auto-stage-share"]
	if !ok {
		t.Fatalf("expected receiver B to persist peer-cache staging metadata")
	}
	if cache.LocalPeerID != "peer-receiver-b" || cache.RemotePeerID != "peer-receiver-a" {
		t.Fatalf("expected receiver B cache metadata to track actual peer-cache path, got %#v", cache)
	}
	if upstream.uploadCalls() != 0 || upstream.downloadCalls() != 0 {
		t.Fatalf("expected oversized same-user auto-stage to avoid control-plane payload copy, got uploads=%d downloads=%d", upstream.uploadCalls(), upstream.downloadCalls())
	}

	manager.DropSession("peer-receiver-b", "peer-receiver-a")
	receiverB.connections = nil
	if err := manager.SetExchangeHandler("peer-receiver-a", nil); err != nil {
		t.Fatalf("clear receiver A exchange handler: %v", err)
	}

	offline, err := receiverB.DownloadFileTransferContentChunk("xfer-auto-stage-share", 0, requestLimit)
	if err != nil {
		t.Fatalf("download auto-staged chunk from local cache after peer cache holder offline: %v", err)
	}
	if !bytes.Equal(offline.Payload, stagedOnA.Payload) {
		t.Fatalf("expected receiver B offline fallback to use its newly auto-staged local cache")
	}
	if offline.Transfer.PayloadReady {
		t.Fatalf("expected oversized same-user auto-stage path without control-plane payload mirror")
	}

	restoredReceiverB := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(upstreamServer.URL), "127.0.0.1:0", NewStateStore(receiverBStatePath), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	defer restoredReceiverB.Close()
	restoredReceiverB.currentUser = &controlclient.User{ID: "user-receiver", Email: "receiver@example.com"}
	restoredReceiverB.currentSession = &controlclient.Session{AccessToken: "token", RefreshToken: "refresh", ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}
	restoredReceiverB.mu.Lock()
	err = restoredReceiverB.restorePersistedFileTransferCachesLocked()
	restoredReceiverB.mu.Unlock()
	if err != nil {
		t.Fatalf("restore receiver B staged peer-cache bytes: %v", err)
	}
	restoredCache, ok := restoredReceiverB.fileTransferCaches["xfer-auto-stage-share"]
	if !ok {
		t.Fatalf("expected receiver B staged peer-cache bytes to survive restart")
	}
	if restoredCache.LocalPeerID != "peer-receiver-b" || restoredCache.RemotePeerID != "peer-receiver-a" {
		t.Fatalf("expected restored peer-cache metadata to keep actual peer pair, got %#v", restoredCache)
	}

	restoredOffline, err := restoredReceiverB.DownloadFileTransferContentChunk("xfer-auto-stage-share", 0, requestLimit)
	if err != nil {
		t.Fatalf("download restored peer-cache chunk after restart: %v", err)
	}
	if !bytes.Equal(restoredOffline.Payload, stagedOnA.Payload) {
		t.Fatalf("expected restored receiver B cache to keep staged oversized bytes after restart")
	}
	if restoredOffline.Transfer.PayloadReady {
		t.Fatalf("expected restored oversized peer-cache path without control-plane payload mirror")
	}
}

type mirroringTransferServer struct {
	mu            sync.Mutex
	network       controlclient.Network
	transfer      controlclient.FileTransfer
	payload       []byte
	uploadCount   int
	downloadCount int
}

func newMirroringTransferServer(network controlclient.Network, transfer controlclient.FileTransfer) *mirroringTransferServer {
	network.ID = strings.TrimSpace(network.ID)
	if network.ID == "" {
		network.ID = transfer.NetworkID
	}
	if network.Name == "" {
		network.Name = "friends"
	}
	if network.FileTransferMaxBytes <= 0 {
		network.FileTransferMaxBytes = domain.DefaultControlPlaneFileTransferPayloadMaxBytes
	}
	return &mirroringTransferServer{network: network, transfer: transfer}
}

func (s *mirroringTransferServer) uploadCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uploadCount
}

func (s *mirroringTransferServer) downloadCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.downloadCount
}

func (s *mirroringTransferServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/networks" && r.Method == http.MethodGet {
			s.listNetworks(w)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/networks/") {
			path := strings.TrimPrefix(r.URL.Path, "/api/v1/networks/")
			parts := strings.Split(strings.Trim(path, "/"), "/")
			if len(parts) == 2 && parts[1] == "file-transfers" && r.Method == http.MethodGet {
				s.listTransfers(w, parts[0])
				return
			}
			http.NotFound(w, r)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/v1/file-transfers/") {
			http.NotFound(w, r)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/file-transfers/")
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			http.NotFound(w, r)
			return
		}
		transferID := parts[0]
		switch {
		case len(parts) == 1 && r.Method == http.MethodGet:
			s.writeTransfer(w, transferID)
		case len(parts) == 1 && r.Method == http.MethodPatch:
			s.patchTransfer(w, r, transferID)
		case len(parts) == 2 && parts[1] == "content-chunks" && r.Method == http.MethodPut:
			s.uploadChunk(w, r, transferID)
		case len(parts) == 2 && parts[1] == "content-chunks" && r.Method == http.MethodGet:
			s.downloadChunk(w, r, transferID)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

func (s *mirroringTransferServer) listNetworks(w http.ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeMirroringJSON(w, http.StatusOK, map[string]any{"data": []controlclient.Network{s.network}})
}

func (s *mirroringTransferServer) listTransfers(w http.ResponseWriter, networkID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.network.ID != networkID {
		writeMirroringJSON(w, http.StatusNotFound, map[string]any{"error": "network not found"})
		return
	}
	writeMirroringJSON(w, http.StatusOK, map[string]any{"data": []controlclient.FileTransfer{s.transfer}})
}

func (s *mirroringTransferServer) writeTransfer(w http.ResponseWriter, transferID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.transfer.ID != transferID {
		writeMirroringJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	writeMirroringJSON(w, http.StatusOK, map[string]any{"data": s.transfer})
}

func (s *mirroringTransferServer) patchTransfer(w http.ResponseWriter, r *http.Request, transferID string) {
	var req struct {
		ProgressPercent int `json:"progressPercent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeMirroringJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.transfer.ID != transferID {
		writeMirroringJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	s.transfer.ProgressPercent = req.ProgressPercent
	if req.ProgressPercent >= 100 {
		s.transfer.Status = "DONE"
	}
	writeMirroringJSON(w, http.StatusOK, map[string]any{"data": s.transfer})
}

func (s *mirroringTransferServer) uploadChunk(w http.ResponseWriter, r *http.Request, transferID string) {
	var req struct {
		ContentType   string `json:"contentType"`
		PayloadBase64 string `json:"payloadBase64"`
		OffsetBytes   int64  `json:"offsetBytes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeMirroringJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PayloadBase64))
	if err != nil {
		writeMirroringJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.transfer.ID != transferID {
		writeMirroringJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	if req.OffsetBytes != int64(len(s.payload)) {
		writeMirroringJSON(w, http.StatusConflict, map[string]any{"error": "offset mismatch"})
		return
	}
	s.payload = append(s.payload, payload...)
	s.uploadCount++
	s.transfer.ContentType = strings.TrimSpace(req.ContentType)
	s.transfer.PayloadUploadedBytes = int64(len(s.payload))
	s.transfer.PayloadReady = int64(len(s.payload)) == s.transfer.SizeBytes
	if s.transfer.PayloadReady {
		sum := sha256.Sum256(s.payload)
		s.transfer.PayloadSHA256 = hex.EncodeToString(sum[:])
		s.transfer.UploadedAtUnix = time.Now().Unix()
	}
	writeMirroringJSON(w, http.StatusOK, map[string]any{"data": s.transfer})
}

func (s *mirroringTransferServer) downloadChunk(w http.ResponseWriter, r *http.Request, transferID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.transfer.ID != transferID {
		writeMirroringJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	if !s.transfer.PayloadReady {
		writeMirroringJSON(w, http.StatusNotFound, map[string]any{"error": "payload missing"})
		return
	}
	offsetBytes, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("offsetBytes")), 10, 64)
	limitBytes, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("limitBytes")), 10, 64)
	if limitBytes <= 0 {
		limitBytes = int64(len(s.payload))
	}
	if offsetBytes < 0 || offsetBytes > int64(len(s.payload)) {
		writeMirroringJSON(w, http.StatusConflict, map[string]any{"error": "offset mismatch"})
		return
	}
	end := offsetBytes + limitBytes
	if end > int64(len(s.payload)) {
		end = int64(len(s.payload))
	}
	s.downloadCount++
	writeMirroringJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"transfer":         s.transfer,
		"contentType":      s.transfer.ContentType,
		"sha256":           s.transfer.PayloadSHA256,
		"payloadBase64":    base64.StdEncoding.EncodeToString(s.payload[offsetBytes:end]),
		"offsetBytes":      offsetBytes,
		"nextOffsetBytes":  end,
		"totalSizeBytes":   s.transfer.SizeBytes,
		"uploadedAtUnix":   s.transfer.UploadedAtUnix,
		"downloadedAtUnix": s.transfer.DownloadedAtUnix,
		"complete":         end >= int64(len(s.payload)),
	}})
}

func writeMirroringJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		panic(fmt.Sprintf("encode mirroring payload: %v", err))
	}
}
