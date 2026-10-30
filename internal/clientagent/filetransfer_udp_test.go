package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/directprobe"
	"Ole/internal/relay"
	"Ole/internal/relaytransport"
	"Ole/internal/transportauth"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every exchange reaches the real authenticated UDP manager before this wrapper
// optionally discards its response. A retry must issue a new transport request;
// replaying the previous encrypted record would never invoke the sender again.
type fileTransferUDPExchangeFaults struct {
	mu        sync.Mutex
	dropAt    int64
	dropsLeft int
	calls     []fileTransferDataplaneRequest
}

func (f *fileTransferUDPExchangeFaults) exchange(real func(string, string, []byte, time.Duration) ([]byte, error), local, remote string, payload []byte, timeout time.Duration) ([]byte, error) {
	var request fileTransferDataplaneRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.calls = append(f.calls, request)
	f.mu.Unlock()
	response, err := real(local, remote, payload, timeout)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	drop := request.OffsetBytes == f.dropAt && f.dropsLeft > 0
	if drop {
		f.dropsLeft--
	}
	f.mu.Unlock()
	if drop {
		return nil, errors.New("test discarded a real UDP exchange response")
	}
	return response, nil
}

func (f *fileTransferUDPExchangeFaults) discard(offset int64, count int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dropAt, f.dropsLeft = offset, count
}

type fileTransferUDPDirect struct {
	directprobe.Manager
	faults *fileTransferUDPExchangeFaults
}

func (m fileTransferUDPDirect) Exchange(local, remote string, payload []byte, timeout time.Duration) ([]byte, error) {
	return m.faults.exchange(m.Manager.Exchange, local, remote, payload, timeout)
}

type fileTransferUDPRelay struct {
	relaytransport.Manager
	faults *fileTransferUDPExchangeFaults
}

func (m fileTransferUDPRelay) Exchange(local, remote string, payload []byte, timeout time.Duration) ([]byte, error) {
	return m.faults.exchange(m.Manager.Exchange, local, remote, payload, timeout)
}

type fileTransferUDPObservation struct {
	request   fileTransferDataplaneRequest
	response  fileTransferDataplaneResponse
	requestN  int
	responseN int
}

type fileTransferUDPFixture struct {
	sender, receiver *Agent
	transfer         controlclient.FileTransfer
	sourcePath       string
	payload          []byte
	faults           *fileTransferUDPExchangeFaults
	mu               sync.Mutex
	observations     []fileTransferUDPObservation
}

func fileTransferUDPAddress(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	address := conn.LocalAddr().String()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func newFileTransferUDPFixture(t *testing.T, mode string, size int) *fileTransferUDPFixture {
	t.Helper()
	f := &fileTransferUDPFixture{faults: &fileTransferUDPExchangeFaults{}, payload: make([]byte, size)}
	for i := range f.payload {
		f.payload[i] = byte((i*29 + i/251) % 256)
	}
	digest := sha256.Sum256(f.payload)
	f.sourcePath = filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(f.sourcePath, f.payload, 0o600); err != nil {
		t.Fatal(err)
	}
	f.transfer = controlclient.FileTransfer{ID: "udp-file", NetworkID: "udp-net", FromPeerID: "sender", ToPeerID: "receiver", FileName: "source.bin", SizeBytes: int64(size), ContentType: "application/octet-stream", PayloadSHA256: hex.EncodeToString(digest[:]), UploadedAtUnix: 123}
	// The only HTTP operation is the completion progress update. File contents
	// and every block response must pass through the authenticated UDP session.
	metadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v1/file-transfers/"+f.transfer.ID {
			t.Errorf("unexpected control-plane request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "metadata only", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": f.transfer})
	}))
	t.Cleanup(metadata.Close)
	f.sender = &Agent{fileTransferSources: map[string]localFileTransferSource{f.transfer.ID: {
		TransferID: f.transfer.ID, NetworkID: f.transfer.NetworkID, LocalPeerID: "sender", RemotePeerID: "receiver", SourcePath: f.sourcePath, FileName: f.transfer.FileName, ContentType: f.transfer.ContentType, PayloadSHA256: f.transfer.PayloadSHA256, SizeBytes: int64(size), UploadedAtUnix: 123,
	}}}
	f.receiver = &Agent{remote: controlclient.New(metadata.URL), runtime: RuntimeConfig{DirectProbeTimeout: time.Second}, connections: []ConnectionStatus{{NetworkID: f.transfer.NetworkID, LocalPeerID: "receiver", RemotePeerID: "sender", TransportReady: true, TransportMode: mode, State: "CONNECTED"}}}
	keys := map[string]ed25519.PrivateKey{}
	identities := map[string]transportauth.Identity{}
	for _, peer := range []string{"sender", "receiver"} {
		seed := sha256.Sum256([]byte("file-transfer-UDP-" + peer))
		keys[peer] = ed25519.NewKeyFromSeed(seed[:])
		identities[peer] = transportauth.Identity{DeviceID: "device-" + peer, PublicKey: keys[peer].Public().(ed25519.PublicKey)}
	}
	credentials := func(peer string) *transportauth.Credentials {
		return &transportauth.Credentials{NetworkID: f.transfer.NetworkID, PeerID: peer, DeviceID: identities[peer].DeviceID, PrivateKey: keys[peer], Peers: identities, ExpiresAt: time.Now().Add(transportauth.SnapshotTTL)}
	}
	realHandler := f.sender.transportExchangeHandler("sender")
	handler := func(remote string, payload []byte) []byte {
		response := realHandler(remote, payload)
		observation := fileTransferUDPObservation{requestN: len(payload), responseN: len(response)}
		_ = json.Unmarshal(payload, &observation.request)
		_ = json.Unmarshal(response, &observation.response)
		f.mu.Lock()
		f.observations = append(f.observations, observation)
		f.mu.Unlock()
		return response
	}
	switch mode {
	case "DIRECT":
		manager := directprobe.New()
		t.Cleanup(func() { _ = manager.Close() })
		senderAddress, receiverAddress := fileTransferUDPAddress(t), fileTransferUDPAddress(t)
		if err := manager.Reconcile([]directprobe.Binding{{PeerID: "sender", ListenAddress: senderAddress, Credentials: credentials("sender")}, {PeerID: "receiver", ListenAddress: receiverAddress, Credentials: credentials("receiver")}}); err != nil {
			t.Fatal(err)
		}
		if err := manager.SetExchangeHandler("sender", handler); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Establish("receiver", "sender", []string{senderAddress}, time.Second); err != nil {
			t.Fatal(err)
		}
		f.receiver.directManager = fileTransferUDPDirect{Manager: manager, faults: f.faults}
	case "RELAY":
		server, err := relay.Listen("127.0.0.1:0", relay.StaticAuthorizer{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = server.Close() })
		manager := relaytransport.New()
		t.Cleanup(func() { _ = manager.Close() })
		if err := manager.Reconcile([]relaytransport.Binding{{PeerID: "sender", RelayAddress: server.LocalAddr().String(), AccessToken: "sender", Credentials: credentials("sender")}, {PeerID: "receiver", RelayAddress: server.LocalAddr().String(), AccessToken: "receiver", Credentials: credentials("receiver")}}); err != nil {
			t.Fatal(err)
		}
		if err := manager.SetExchangeHandler("sender", handler); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Establish("receiver", "sender", time.Second); err != nil {
			t.Fatal(err)
		}
		f.receiver.relayManager = fileTransferUDPRelay{Manager: manager, faults: f.faults}
	default:
		t.Fatalf("unknown transport mode %q", mode)
	}
	return f
}

func (f *fileTransferUDPFixture) download(t *testing.T, offset, limit int64) *dataplaneFileTransferChunk {
	t.Helper()
	return f.downloadVia(t, offset, limit, false)
}

func (f *fileTransferUDPFixture) downloadCache(t *testing.T, offset, limit int64) *dataplaneFileTransferChunk {
	t.Helper()
	return f.downloadVia(t, offset, limit, true)
}

func (f *fileTransferUDPFixture) downloadVia(t *testing.T, offset, limit int64, cache bool) *dataplaneFileTransferChunk {
	t.Helper()
	f.receiver.mu.Lock()
	var chunk *dataplaneFileTransferChunk
	var err error
	if cache {
		chunk, err = f.receiver.downloadFileTransferContentChunkViaPeerCacheConnectionLocked(f.transfer, &f.receiver.connections[0], offset, limit)
	} else {
		chunk, err = f.receiver.downloadFileTransferContentChunkViaDataplaneLocked(f.transfer, offset, limit)
	}
	f.receiver.mu.Unlock()
	if err != nil || chunk == nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		maxResponse := 0
		for _, o := range f.observations {
			if o.responseN > maxResponse {
				maxResponse = o.responseN
			}
		}
		t.Fatalf("UDP download offset=%d limit=%d: chunk=%v, err=%v (sender responses=%d, largest=%d bytes)", offset, limit, chunk, err, len(f.observations), maxResponse)
	}
	if chunk.OffsetBytes != offset || chunk.NextOffsetBytes != offset+int64(len(chunk.Payload)) || !bytes.Equal(chunk.Payload, f.payload[offset:chunk.NextOffsetBytes]) {
		t.Fatal("UDP chunk has incorrect offsets or contents")
	}
	return chunk
}

func (f *fileTransferUDPFixture) useCache(t *testing.T, cachedBytes int) {
	t.Helper()
	if err := os.WriteFile(f.sourcePath, f.payload[:cachedBytes], 0o600); err != nil {
		t.Fatal(err)
	}
	f.sender.mu.Lock()
	defer f.sender.mu.Unlock()
	delete(f.sender.fileTransferSources, f.transfer.ID)
	f.sender.fileTransferCaches = map[string]localFileTransferCache{f.transfer.ID: {
		TransferID: f.transfer.ID, NetworkID: f.transfer.NetworkID, LocalPeerID: "sender", RemotePeerID: "receiver", CachePath: f.sourcePath, FileName: f.transfer.FileName, ContentType: f.transfer.ContentType, PayloadSHA256: f.transfer.PayloadSHA256, SizeBytes: f.transfer.SizeBytes, CachedBytes: int64(cachedBytes), UploadedAtUnix: 123,
	}}
	// Cache sharing requires an authenticated same-user peer in addition to the
	// trusted transport identity; the sender-source route has different rules.
	f.sender.currentUser = &controlclient.User{ID: "cache-owner"}
	f.sender.discoveredPeers = map[string][]controlclient.Peer{f.transfer.NetworkID: {{ID: "receiver", NetworkID: f.transfer.NetworkID, UserID: "cache-owner"}}}
}

func (f *fileTransferUDPFixture) assertBudgets(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.observations) == 0 {
		t.Fatal("no real UDP requests reached the sender")
	}
	for _, o := range f.observations {
		if o.requestN > transportauth.MaxMessageBytes || o.responseN > transportauth.MaxResponseBytes {
			t.Errorf("JSON plaintext exceeds authenticated record budget: request=%d, response=%d", o.requestN, o.responseN)
		}
	}
}

func TestFileTransferUDP64KiBIntegrityRetryAndResume(t *testing.T) {
	for _, mode := range []string{"DIRECT", "RELAY"} {
		t.Run(mode, func(t *testing.T) {
			f := newFileTransferUDPFixture(t, mode, 64*1024+137)
			first := f.download(t, 0, 4096)
			if first.Complete || len(first.Payload) != 4096 {
				t.Fatal("first download did not stop at the requested resume offset")
			}
			f.faults.discard(first.NextOffsetBytes, 1)
			resumed := f.download(t, first.NextOffsetBytes, int64(len(f.payload))-first.NextOffsetBytes)
			if !resumed.Complete || resumed.SHA256 != f.transfer.PayloadSHA256 {
				t.Fatal("resumed UDP download lost completion or hash metadata")
			}
			outputPath := filepath.Join(t.TempDir(), "received.bin")
			if err := os.WriteFile(outputPath, append(append([]byte(nil), first.Payload...), resumed.Payload...), 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(output)
			if !bytes.Equal(output, f.payload) || hex.EncodeToString(digest[:]) != f.transfer.PayloadSHA256 {
				t.Fatal("assembled file differs from the sender's bytes/SHA256")
			}
			f.mu.Lock()
			retried := 0
			for _, o := range f.observations {
				if o.request.OffsetBytes == first.NextOffsetBytes {
					retried++
				}
			}
			f.mu.Unlock()
			if retried != 2 {
				t.Fatalf("lost response caused %d fresh authenticated requests, want 2", retried)
			}
			for repeat := 0; repeat < 2; repeat++ {
				complete := f.download(t, int64(len(f.payload)), 4096)
				if !complete.Complete || len(complete.Payload) != 0 || complete.SHA256 != f.transfer.PayloadSHA256 {
					t.Fatal("repeated source request at file size did not remain complete")
				}
			}
			f.assertBudgets(t)
		})
	}
}

func TestFileTransferUDPBoundedRetryThenRecovery(t *testing.T) {
	for _, mode := range []string{"DIRECT", "RELAY"} {
		t.Run(mode, func(t *testing.T) {
			f := newFileTransferUDPFixture(t, mode, 8192)
			first := f.download(t, 0, 2048)
			f.faults.discard(first.NextOffsetBytes, 10)
			f.receiver.mu.Lock()
			failed, err := f.receiver.downloadFileTransferContentChunkViaDataplaneLocked(f.transfer, first.NextOffsetBytes, 4096)
			f.receiver.mu.Unlock()
			if failed != nil || err == nil {
				t.Fatalf("download did not report bounded failure: chunk=%v error=%v", failed, err)
			}
			f.mu.Lock()
			attempts := 0
			for _, o := range f.observations {
				if o.request.OffsetBytes == first.NextOffsetBytes {
					attempts++
				}
			}
			f.mu.Unlock()
			if attempts != 3 {
				t.Fatalf("failed block attempted %d authenticated requests, want bounded 3", attempts)
			}
			f.faults.discard(0, 0)
			recovered := f.download(t, first.NextOffsetBytes, int64(len(f.payload))-first.NextOffsetBytes)
			if !recovered.Complete {
				t.Fatal("download could not resume after bounded failure")
			}
			f.assertBudgets(t)
		})
	}
}

func TestFileTransferUDPSourceMissingThenRecovery(t *testing.T) {
	for _, mode := range []string{"DIRECT", "RELAY"} {
		t.Run(mode, func(t *testing.T) {
			f := newFileTransferUDPFixture(t, mode, 4096)
			if err := os.Remove(f.sourcePath); err != nil {
				t.Fatal(err)
			}
			f.receiver.mu.Lock()
			missing, err := f.receiver.downloadFileTransferContentChunkViaDataplaneLocked(f.transfer, 0, 4096)
			f.receiver.mu.Unlock()
			if missing != nil || err == nil {
				t.Fatalf("missing source did not report an error: chunk=%v error=%v", missing, err)
			}
			f.mu.Lock()
			count, sourceError := len(f.observations), ""
			if count > 0 {
				sourceError = f.observations[count-1].response.Error
			}
			f.mu.Unlock()
			if count != 1 || sourceError == "" {
				t.Fatalf("missing source did not produce one terminal authenticated error: attempts=%d error=%q", count, sourceError)
			}
			if err := os.WriteFile(f.sourcePath, f.payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if recovered := f.download(t, 0, 4096); !recovered.Complete {
				t.Fatalf("restored source incomplete at %d", recovered.NextOffsetBytes)
			}
			f.assertBudgets(t)
		})
	}
}

func TestFileTransferUDPResponseFitsEscapedMetadata(t *testing.T) {
	for _, mode := range []string{"DIRECT", "RELAY"} {
		t.Run(mode, func(t *testing.T) {
			f := newFileTransferUDPFixture(t, mode, 4096)
			// JSON escaping makes this envelope larger than the ordinary 768-byte
			// block can accommodate. The sender must reduce the block and keep the
			// next offset precise, so the receiver can finish without skipping data.
			contentType := strings.Repeat(`<"&`, 24)
			source := f.sender.fileTransferSources[f.transfer.ID]
			source.ContentType = contentType
			f.sender.fileTransferSources[f.transfer.ID] = source
			chunk := f.download(t, 0, int64(len(f.payload)))
			if !chunk.Complete || chunk.ContentType != contentType {
				t.Fatal("adaptive block sizing changed metadata or completion")
			}
			f.mu.Lock()
			shrunk := false
			for _, o := range f.observations {
				if o.request.LimitBytes == fileTransferDataplaneChunkBytes && len(o.response.Payload) < fileTransferDataplaneChunkBytes && !o.response.Complete {
					shrunk = true
				}
			}
			f.mu.Unlock()
			if !shrunk {
				t.Fatal("escaped metadata never exercised adaptive block sizing")
			}
			f.assertBudgets(t)
		})
	}
}

func TestFileTransferUDPPartialCacheEOFThenAppendAndResume(t *testing.T) {
	for _, mode := range []string{"DIRECT", "RELAY"} {
		t.Run(mode, func(t *testing.T) {
			f := newFileTransferUDPFixture(t, mode, 64*1024+137)
			f.useCache(t, 4096)
			partial := f.downloadCache(t, 0, int64(len(f.payload)))
			if partial.Complete || len(partial.Payload) != 4096 || partial.NextOffsetBytes != 4096 {
				t.Fatalf("partial cache incorrectly reported completion: bytes=%d next=%d complete=%v", len(partial.Payload), partial.NextOffsetBytes, partial.Complete)
			}
			f.receiver.mu.Lock()
			empty, err := f.receiver.downloadFileTransferContentChunkViaPeerCacheConnectionLocked(f.transfer, &f.receiver.connections[0], partial.NextOffsetBytes, 4096)
			f.receiver.mu.Unlock()
			if err != nil || empty != nil {
				t.Fatalf("partial cache EOF must remain incomplete without an error: chunk=%v error=%v", empty, err)
			}
			f.mu.Lock()
			eof := f.observations[len(f.observations)-1].response
			f.mu.Unlock()
			if eof.Complete || len(eof.Payload) != 0 || eof.OffsetBytes != 4096 || eof.NextOffsetBytes != 4096 {
				t.Fatal("cached EOF was confused with a complete file")
			}
			file, err := os.OpenFile(f.sourcePath, os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write(f.payload[4096:]); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			f.sender.mu.Lock()
			cache := f.sender.fileTransferCaches[f.transfer.ID]
			cache.CachedBytes = int64(len(f.payload))
			f.sender.fileTransferCaches[f.transfer.ID] = cache
			f.sender.mu.Unlock()
			resumed := f.downloadCache(t, partial.NextOffsetBytes, int64(len(f.payload))-partial.NextOffsetBytes)
			assembled := append(append([]byte(nil), partial.Payload...), resumed.Payload...)
			digest := sha256.Sum256(assembled)
			if !resumed.Complete || !bytes.Equal(assembled, f.payload) || resumed.SHA256 != f.transfer.PayloadSHA256 || hex.EncodeToString(digest[:]) != f.transfer.PayloadSHA256 {
				t.Fatal("appended cache did not resume to the complete original bytes/SHA256")
			}
			for repeat := 0; repeat < 2; repeat++ {
				complete := f.downloadCache(t, int64(len(f.payload)), 4096)
				if !complete.Complete || len(complete.Payload) != 0 {
					t.Fatal("repeated cache request at file size did not remain complete")
				}
			}
			f.assertBudgets(t)
		})
	}
}

func TestFileTransferUDPZeroByteSourceAndCacheRemainComplete(t *testing.T) {
	for _, mode := range []string{"DIRECT", "RELAY"} {
		t.Run(mode, func(t *testing.T) {
			f := newFileTransferUDPFixture(t, mode, 0)
			for _, cache := range []bool{false, true} {
				if cache {
					f.useCache(t, 0)
				}
				for repeat := 0; repeat < 2; repeat++ {
					chunk := f.downloadVia(t, 0, 4096, cache)
					if !chunk.Complete || len(chunk.Payload) != 0 || chunk.NextOffsetBytes != 0 || chunk.TotalSizeBytes != 0 || chunk.SHA256 != f.transfer.PayloadSHA256 {
						t.Fatalf("empty file lost verified completion (cache=%v, repeat=%d)", cache, repeat)
					}
				}
			}
			f.assertBudgets(t)
		})
	}
}
