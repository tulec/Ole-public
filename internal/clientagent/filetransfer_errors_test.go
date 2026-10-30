package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/domain"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDownloadFileTransferContentChunkPreservesSourceErrorWhenFallbackFails(t *testing.T) {
	transfer := controlclient.FileTransfer{
		ID: "xfer-source-error", NetworkID: "net-1",
		FromPeerID: "peer-sender", ToPeerID: "peer-receiver",
		FromUserID: "user-sender", ToUserID: "user-receiver",
		FileName: "missing.bin", SizeBytes: 1024, Status: "IN_PROGRESS",
	}
	upstream := newMirroringTransferServer(controlclient.Network{ID: transfer.NetworkID}, transfer)
	upstreamHandler := upstream.handler()
	var fallbackCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/file-transfers/"+transfer.ID+"/content-chunks" {
			fallbackCalls.Add(1)
		}
		upstreamHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)

	manager := &dataplaneExchangeManager{}
	const sourceError = "registered source file is missing"
	sourceCalls := 0
	if err := manager.SetExchangeHandler(transfer.FromPeerID, func(_ string, _ []byte) []byte {
		sourceCalls++
		return encodeFileTransferDataplaneResponse(fileTransferDataplaneResponse{
			Type: "file-transfer-chunk-response", Error: sourceError,
		})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Establish(transfer.ToPeerID, transfer.FromPeerID, nil, time.Second); err != nil {
		t.Fatal(err)
	}
	receiver := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(server.URL), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "receiver.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	t.Cleanup(func() { _ = receiver.Close() })
	receiver.currentUser = &controlclient.User{ID: transfer.ToUserID}
	receiver.connections = []ConnectionStatus{{
		NetworkID: transfer.NetworkID, LocalPeerID: transfer.ToPeerID, RemotePeerID: transfer.FromPeerID,
		RemoteUserID: transfer.FromUserID, TransportReady: true, TransportMode: "DIRECT", State: "CONNECTED",
	}}

	chunk, err := receiver.DownloadFileTransferContentChunk(transfer.ID, 0, 512)
	if chunk != nil || err == nil {
		t.Fatalf("expected source and fallback failures, got chunk=%#v err=%v", chunk, err)
	}
	if !strings.Contains(err.Error(), sourceError) || !strings.Contains(err.Error(), "payload missing") {
		t.Fatalf("source or control-plane failure was lost: %v", err)
	}
	if sourceCalls != 1 {
		t.Fatalf("terminal source error was retried or skipped: calls=%d", sourceCalls)
	}
	if got := fallbackCalls.Load(); got != 1 {
		t.Fatalf("control-plane fallback was not attempted once: calls=%d", got)
	}
}

func TestAutoStageFileTransferFallsBackToPeerCacheAfterSourceError(t *testing.T) {
	transfer := controlclient.FileTransfer{
		ID: "xfer-cache-after-source-error", NetworkID: "net-1",
		FromPeerID: "peer-sender", ToPeerID: "peer-receiver",
		FromUserID: "user-sender", ToUserID: "user-receiver",
		FileName: "large.bin", SizeBytes: domain.DefaultMirroredFileTransferPayloadMaxBytes + 1,
		ContentType: "application/octet-stream", PayloadSHA256: "cache-checksum", UploadedAtUnix: 123,
	}
	// Only a small prefix is cached; the advertised file size selects local
	// staging without creating a large file or fetching control-plane content.
	prefix := bytes.Repeat([]byte{73}, 2*fileTransferDataplaneChunkBytes+17)
	var upstreamCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		http.Error(w, "unexpected control-plane request", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	manager := &dataplaneExchangeManager{}
	sourceCalls, cacheCalls := 0, 0
	if err := manager.SetExchangeHandler(transfer.FromPeerID, func(_ string, _ []byte) []byte {
		sourceCalls++
		return encodeFileTransferDataplaneResponse(fileTransferDataplaneResponse{
			Type: "file-transfer-chunk-response", Error: "source file unavailable",
		})
	}); err != nil {
		t.Fatal(err)
	}
	const cachePeerID = "peer-receiver-cache"
	if err := manager.SetExchangeHandler(cachePeerID, func(_ string, payload []byte) []byte {
		cacheCalls++
		var request fileTransferDataplaneRequest
		if err := json.Unmarshal(payload, &request); err != nil {
			t.Fatalf("decode cache request: %v", err)
		}
		if sourceCalls != 1 || request.TransferID != transfer.ID || request.OffsetBytes < 0 || request.OffsetBytes > int64(len(prefix)) {
			t.Fatalf("unexpected peer-cache fallback request: sourceCalls=%d request=%#v", sourceCalls, request)
		}
		end := minInt64(request.OffsetBytes+request.LimitBytes, int64(len(prefix)))
		return encodeFileTransferDataplaneResponse(fileTransferDataplaneResponse{
			Type: "file-transfer-chunk-response", ContentType: transfer.ContentType,
			SHA256: transfer.PayloadSHA256, Payload: prefix[request.OffsetBytes:end],
			OffsetBytes: request.OffsetBytes, NextOffsetBytes: end, TotalSizeBytes: transfer.SizeBytes,
			UploadedAtUnix: transfer.UploadedAtUnix, Complete: false,
		})
	}); err != nil {
		t.Fatal(err)
	}
	for _, remotePeerID := range []string{transfer.FromPeerID, cachePeerID} {
		if _, err := manager.Establish(transfer.ToPeerID, remotePeerID, nil, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	receiver := NewWithClientAndStoreAndRuntimeAndAdapterAndDirect(controlclient.New(server.URL), "127.0.0.1:0", NewStateStore(filepath.Join(t.TempDir(), "receiver.json")), RuntimeConfig{DirectProbeTimeout: 10 * time.Millisecond}, nil, manager)
	t.Cleanup(func() { _ = receiver.Close() })
	receiver.currentUser = &controlclient.User{ID: transfer.ToUserID}
	receiver.connections = []ConnectionStatus{
		{NetworkID: transfer.NetworkID, LocalPeerID: transfer.ToPeerID, RemotePeerID: transfer.FromPeerID, RemoteUserID: transfer.FromUserID, TransportReady: true, TransportMode: "DIRECT", State: "CONNECTED"},
		{NetworkID: transfer.NetworkID, LocalPeerID: transfer.ToPeerID, RemotePeerID: cachePeerID, RemoteUserID: transfer.ToUserID, TransportReady: true, TransportMode: "DIRECT", State: "CONNECTED"},
	}

	receiver.mu.Lock()
	staged, err := receiver.autoStageFileTransferChunkLocked(transfer)
	receiver.mu.Unlock()
	if err != nil || !staged {
		t.Fatalf("peer cache did not recover source error: staged=%v err=%v", staged, err)
	}
	cache := receiver.fileTransferCaches[transfer.ID]
	if sourceCalls != 1 || cacheCalls < 2 || cache.CachedBytes != int64(len(prefix)) {
		t.Fatalf("unexpected fallback progress: sourceCalls=%d cacheCalls=%d cache=%#v", sourceCalls, cacheCalls, cache)
	}
	if cache.LocalPeerID != transfer.ToPeerID || cache.RemotePeerID != cachePeerID {
		t.Fatalf("staged cache lost the peer-cache route: %#v", cache)
	}
	got, err := os.ReadFile(cache.CachePath)
	if err != nil || !bytes.Equal(got, prefix) {
		t.Fatalf("staged peer-cache bytes differ: len=%d err=%v", len(got), err)
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("partial peer-cache staging unexpectedly used control plane: calls=%d", got)
	}
}
