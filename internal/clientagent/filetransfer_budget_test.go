package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/directprobe"
	"Ole/internal/transportauth"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

func TestFileTransferBudgetEncodeEscapedMetadataTrimsPayload(t *testing.T) {
	payload := bytes.Repeat([]byte{0, 1, 0xff}, fileTransferDataplaneChunkBytes/3)
	response := fileTransferDataplaneResponse{
		Type:            "file-transfer-chunk-response",
		ContentType:     strings.Repeat("\x00<&\"\\\n", 25),
		SHA256:          strings.Repeat("a", 64),
		Payload:         payload,
		OffsetBytes:     17,
		NextOffsetBytes: 17 + int64(len(payload)),
		TotalSizeBytes:  17 + int64(len(payload)),
		UploadedAtUnix:  123,
		Complete:        true,
	}
	oversized, err := json.Marshal(response)
	if err != nil || len(oversized) <= transportauth.MaxResponseBytes {
		t.Fatalf("fixture must exceed response budget: bytes=%d err=%v", len(oversized), err)
	}
	encoded := encodeFileTransferDataplaneResponse(response)
	if len(encoded) > transportauth.MaxResponseBytes {
		t.Fatalf("response exceeds transport budget: %d", len(encoded))
	}
	var decoded fileTransferDataplaneResponse
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Error != "" || len(decoded.Payload) == 0 || len(decoded.Payload) >= len(payload) {
		t.Fatalf("expected a nonempty partial block, got bytes=%d error=%q", len(decoded.Payload), decoded.Error)
	}
	if !bytes.Equal(decoded.Payload, payload[:len(decoded.Payload)]) {
		t.Fatal("trimmed block changed payload bytes")
	}
	if decoded.NextOffsetBytes != response.OffsetBytes+int64(len(decoded.Payload)) || decoded.Complete {
		t.Fatalf("partial block retained stale EOF/next offset: %+v", decoded)
	}
	if decoded.OffsetBytes != response.OffsetBytes || decoded.TotalSizeBytes != response.TotalSizeBytes ||
		decoded.ContentType != response.ContentType || decoded.SHA256 != response.SHA256 || decoded.UploadedAtUnix != response.UploadedAtUnix {
		t.Fatal("partial block changed source metadata")
	}
	request := fileTransferDataplaneRequest{OffsetBytes: response.OffsetBytes, LimitBytes: int64(len(payload))}
	if err := validateFileTransferBlock(decoded, request, response.TotalSizeBytes, false); err != nil {
		t.Fatalf("trimmed response is not a valid resumable source block: %v", err)
	}
}

func TestFileTransferBudgetEncodeUnshrinkableResponses(t *testing.T) {
	for _, test := range []struct {
		name     string
		response fileTransferDataplaneResponse
	}{
		{"escaped content type", fileTransferDataplaneResponse{ContentType: strings.Repeat("<", transportauth.MaxResponseBytes), Payload: []byte("payload")}},
		{"checksum metadata", fileTransferDataplaneResponse{SHA256: strings.Repeat("a", transportauth.MaxResponseBytes), Payload: []byte("payload")}},
		{"escaped source error", fileTransferDataplaneResponse{Error: strings.Repeat("\x00", transportauth.MaxResponseBytes)}},
		{"plain content type over field cap", fileTransferDataplaneResponse{ContentType: strings.Repeat("a", transportauth.MaxResponseBytes+1)}},
		{"plain checksum over field cap", fileTransferDataplaneResponse{SHA256: strings.Repeat("a", transportauth.MaxResponseBytes+1)}},
		{"plain error over field cap", fileTransferDataplaneResponse{Error: strings.Repeat("a", transportauth.MaxResponseBytes+1)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded := encodeFileTransferDataplaneResponse(test.response)
			if len(encoded) > transportauth.MaxResponseBytes {
				t.Fatalf("fallback exceeds transport budget: %d", len(encoded))
			}
			var response fileTransferDataplaneResponse
			if err := json.Unmarshal(encoded, &response); err != nil {
				t.Fatal(err)
			}
			if response.Type != "file-transfer-chunk-response" || response.Error == "" || len(response.Payload) != 0 || response.Complete {
				t.Fatalf("oversized metadata did not become a bounded error: %+v", response)
			}
		})
	}
}

func TestFileTransferBudgetEncodeCapsSourceBlockBeforeJSON(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), fileTransferDataplaneChunkBytes+1)
	response := fileTransferDataplaneResponse{
		Type: "file-transfer-chunk-response", Payload: payload,
		OffsetBytes: 10, NextOffsetBytes: 10 + int64(len(payload)), TotalSizeBytes: 10 + int64(len(payload)), Complete: true,
	}
	encoded := encodeFileTransferDataplaneResponse(response)
	var decoded fileTransferDataplaneResponse
	if len(encoded) > transportauth.MaxResponseBytes || json.Unmarshal(encoded, &decoded) != nil {
		t.Fatal("source block is not a bounded response")
	}
	if !bytes.Equal(decoded.Payload, payload[:fileTransferDataplaneChunkBytes]) || decoded.NextOffsetBytes != 10+fileTransferDataplaneChunkBytes || decoded.Complete || decoded.Error != "" {
		t.Fatalf("oversized source block retained stale payload/EOF/next offset: %+v", decoded)
	}
}

func TestFileTransferBudgetEncodeFittingFinalBlock(t *testing.T) {
	want := fileTransferDataplaneResponse{
		Type: "file-transfer-chunk-response", ContentType: "application/octet-stream",
		Payload: []byte("final"), OffsetBytes: 10, NextOffsetBytes: 15, TotalSizeBytes: 15, Complete: true,
	}
	encoded := encodeFileTransferDataplaneResponse(want)
	var got fileTransferDataplaneResponse
	if len(encoded) > transportauth.MaxResponseBytes || json.Unmarshal(encoded, &got) != nil {
		t.Fatal("final block is not a bounded response")
	}
	if !bytes.Equal(got.Payload, want.Payload) || got.NextOffsetBytes != want.NextOffsetBytes || !got.Complete || got.Error != "" {
		t.Fatalf("a fitting final block was shortened or lost EOF: %+v", got)
	}
}

func TestFileTransferBudgetValidateRejectsCorruptBlocks(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fileTransferDataplaneRequest, *fileTransferDataplaneResponse, *int64)
	}{
		{"negative request offset", func(q *fileTransferDataplaneRequest, _ *fileTransferDataplaneResponse, _ *int64) { q.OffsetBytes = -1 }},
		{"offset beyond total", func(q *fileTransferDataplaneRequest, _ *fileTransferDataplaneResponse, _ *int64) { q.OffsetBytes = 21 }},
		{"changed total", func(_ *fileTransferDataplaneRequest, r *fileTransferDataplaneResponse, _ *int64) { r.TotalSizeBytes++ }},
		{"changed offset", func(_ *fileTransferDataplaneRequest, r *fileTransferDataplaneResponse, _ *int64) { r.OffsetBytes++ }},
		{"payload exceeds requested limit", func(q *fileTransferDataplaneRequest, _ *fileTransferDataplaneResponse, _ *int64) { q.LimitBytes = 3 }},
		{"negative requested limit", func(q *fileTransferDataplaneRequest, _ *fileTransferDataplaneResponse, _ *int64) { q.LimitBytes = -1 }},
		{"payload exceeds total", func(_ *fileTransferDataplaneRequest, r *fileTransferDataplaneResponse, total *int64) {
			*total = 13
			r.TotalSizeBytes = 13
		}},
		{"next offset skips bytes", func(_ *fileTransferDataplaneRequest, r *fileTransferDataplaneResponse, _ *int64) { r.NextOffsetBytes++ }},
		{"next offset regresses", func(_ *fileTransferDataplaneRequest, r *fileTransferDataplaneResponse, _ *int64) {
			r.NextOffsetBytes = 9
		}},
		{"false early EOF", func(_ *fileTransferDataplaneRequest, r *fileTransferDataplaneResponse, _ *int64) { r.Complete = true }},
		{"missing EOF on final payload", func(_ *fileTransferDataplaneRequest, r *fileTransferDataplaneResponse, total *int64) {
			*total = 14
			r.TotalSizeBytes = 14
		}},
		{"negative total", func(_ *fileTransferDataplaneRequest, r *fileTransferDataplaneResponse, total *int64) {
			*total = -1
			r.TotalSizeBytes = -1
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := fileTransferDataplaneRequest{OffsetBytes: 10, LimitBytes: 4}
			response := fileTransferDataplaneResponse{Payload: []byte("data"), OffsetBytes: 10, NextOffsetBytes: 14, TotalSizeBytes: 20}
			total := int64(20)
			test.mutate(&request, &response, &total)
			for _, cache := range []bool{false, true} {
				if err := validateFileTransferBlock(response, request, total, cache); err == nil {
					t.Fatalf("corrupt block accepted with cache=%v", cache)
				}
			}
		})
	}
}

func TestFileTransferBudgetValidateProgressAndPartialCaches(t *testing.T) {
	for _, test := range []struct {
		name     string
		offset   int64
		total    int64
		payload  []byte
		complete bool
		cache    bool
		valid    bool
	}{
		{"source short block", 10, 100, []byte("xy"), false, false, true},
		{"cache short block", 10, 100, []byte("xy"), false, true, true},
		{"empty partial cache", 0, 100, nil, false, true, true},
		{"cache caught up", 10, 100, nil, false, true, true},
		{"empty zero-size cache missing EOF", 0, 0, nil, false, true, false},
		{"empty zero-size cache complete", 0, 0, nil, true, true, true},
		{"cache at end without completion", 100, 100, nil, false, true, false},
		{"cache at end complete", 100, 100, nil, true, true, true},
		{"source made no progress", 10, 100, nil, false, false, false},
		{"source end without EOF", 100, 100, nil, false, false, false},
		{"source explicit EOF", 100, 100, nil, true, false, true},
		{"empty source explicit EOF", 0, 0, nil, true, false, true},
		{"cache false EOF", 10, 100, nil, true, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := fileTransferDataplaneRequest{OffsetBytes: test.offset, LimitBytes: fileTransferDataplaneChunkBytes}
			response := fileTransferDataplaneResponse{Payload: test.payload, OffsetBytes: test.offset, NextOffsetBytes: test.offset + int64(len(test.payload)), TotalSizeBytes: test.total, Complete: test.complete}
			if err := validateFileTransferBlock(response, request, test.total, test.cache); (err == nil) != test.valid {
				t.Fatalf("valid=%v: %v", test.valid, err)
			}
		})
	}
}

func TestFileTransferBudgetValidateInt64Boundaries(t *testing.T) {
	for _, test := range []struct {
		name     string
		offset   int64
		next     int64
		total    int64
		payload  []byte
		complete bool
		valid    bool
	}{
		{"last bytes", math.MaxInt64 - 3, math.MaxInt64, math.MaxInt64, []byte("end"), true, true},
		{"EOF at maximum", math.MaxInt64, math.MaxInt64, math.MaxInt64, nil, true, true},
		{"wrapped next offset", math.MaxInt64 - 1, math.MinInt64, math.MaxInt64, []byte("xx"), true, false},
		{"negative offset at minimum", math.MinInt64, math.MinInt64 + 1, math.MaxInt64, []byte("x"), false, false},
		{"negative total at minimum", 0, 0, math.MinInt64, nil, true, false},
		{"forged minimum next offset", 1, math.MinInt64, math.MaxInt64, []byte("x"), false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := fileTransferDataplaneRequest{OffsetBytes: test.offset, LimitBytes: math.MaxInt64}
			response := fileTransferDataplaneResponse{Payload: test.payload, OffsetBytes: test.offset, NextOffsetBytes: test.next, TotalSizeBytes: test.total, Complete: test.complete}
			if err := validateFileTransferBlock(response, request, test.total, false); (err == nil) != test.valid {
				t.Fatalf("valid=%v: %v", test.valid, err)
			}
		})
	}
}

func TestFileTransferBudgetDownloadPartialCacheProgress(t *testing.T) {
	for _, test := range []struct {
		name      string
		available []byte
		total     int64
		wantNil   bool
		wantCalls int
	}{
		{"empty partial cache", nil, 10, true, 1},
		{"short blocks followed by cache end", []byte("cache"), 10, false, 4},
		{"complete zero-size cache", nil, 0, false, 1},
		{"complete cache in short blocks", []byte("cache"), 5, false, 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			manager := &dataplaneExchangeManager{
				sessions: map[string]directprobe.Session{"receiver|sender": {SessionID: "session"}},
				handlers: map[string]directprobe.ExchangeHandler{"sender": func(_ string, encoded []byte) []byte {
					calls++
					var request fileTransferDataplaneRequest
					if err := json.Unmarshal(encoded, &request); err != nil {
						t.Fatal(err)
					}
					if request.OffsetBytes < 0 || request.OffsetBytes > int64(len(test.available)) {
						t.Fatalf("download skipped the available prefix: %+v", request)
					}
					end := request.OffsetBytes + 2
					if end > int64(len(test.available)) {
						end = int64(len(test.available))
					}
					response := fileTransferDataplaneResponse{
						Type: "file-transfer-chunk-response", ContentType: "application/octet-stream", SHA256: "sha", UploadedAtUnix: 123,
						Payload: test.available[request.OffsetBytes:end], OffsetBytes: request.OffsetBytes, NextOffsetBytes: end,
						TotalSizeBytes: test.total, Complete: end == test.total,
					}
					return encodeFileTransferDataplaneResponse(response)
				}},
			}
			agent := &Agent{directManager: manager, runtime: RuntimeConfig{DirectProbeTimeout: time.Millisecond}}
			transfer := controlclient.FileTransfer{ID: "transfer", SizeBytes: test.total, ContentType: "application/octet-stream", PayloadSHA256: "sha", UploadedAtUnix: 123}
			connection := &ConnectionStatus{LocalPeerID: "receiver", RemotePeerID: "sender", TransportMode: "DIRECT"}
			chunk, err := agent.downloadFileTransferFromConnectionLocked(transfer, connection, 0, 10, time.Now().Add(time.Second), true)
			if err != nil || (chunk == nil) != test.wantNil || calls != test.wantCalls {
				t.Fatalf("nil=%v calls=%d want=%d error=%v", chunk == nil, calls, test.wantCalls, err)
			}
			if chunk != nil && (!bytes.Equal(chunk.Payload, test.available) || chunk.NextOffsetBytes != int64(len(test.available)) || chunk.Complete != (int64(len(test.available)) == test.total)) {
				t.Fatalf("cache download lost verified progress or claimed false EOF: %+v", chunk)
			}
		})
	}
}

type fileTransferBudgetManager struct {
	exchange func(local, remote string, payload []byte, timeout time.Duration) ([]byte, error)
}

func (m *fileTransferBudgetManager) Exchange(local, remote string, payload []byte, timeout time.Duration) ([]byte, error) {
	return m.exchange(local, remote, payload, timeout)
}
func (*fileTransferBudgetManager) SendPacket(string, string, []byte) error           { return nil }
func (*fileTransferBudgetManager) DrainInbound(string, int) []transportInboundPacket { return nil }

func TestFileTransferBudgetExchangeRetriesAndStops(t *testing.T) {
	transient := errors.New("packet lost")
	validResponse, err := json.Marshal(fileTransferDataplaneResponse{Type: "file-transfer-chunk-response", Payload: []byte("ok")})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		failures    int
		reply       []byte
		failure     error
		wantCalls   int
		wantError   bool
		interrupted bool
	}{
		{name: "two lost exchanges then success", failures: 2, reply: validResponse, failure: transient, wantCalls: 3},
		{name: "three lost exchanges stop", failures: 10, failure: transient, wantCalls: 3, wantError: true, interrupted: true},
		{name: "oversized request record is terminal", failures: 10, failure: transportauth.ErrMessageTooLarge, wantCalls: 1, wantError: true},
		{name: "exhausted counter is terminal", failures: 10, failure: transportauth.ErrCounterExhausted, wantCalls: 1, wantError: true},
		{name: "invalid session is terminal", failures: 10, failure: transportauth.ErrInvalidRecord, wantCalls: 1, wantError: true},
		{name: "malformed JSON is terminal", reply: []byte("{"), wantCalls: 1, wantError: true},
		{name: "wrong response kind is terminal", reply: []byte(`{"type":"unrelated"}`), wantCalls: 1, wantError: true},
		{name: "source error is terminal", reply: []byte(`{"type":"file-transfer-chunk-response","error":"source unavailable"}`), wantCalls: 1, wantError: true},
		{name: "oversized response is terminal", reply: bytes.Repeat([]byte(" "), transportauth.MaxResponseBytes+1), wantCalls: 1, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := fileTransferDataplaneRequest{Type: "file-transfer-chunk-request", TransferID: "transfer", OffsetBytes: 100, LimitBytes: 32}
			wantRequest, _ := json.Marshal(request)
			calls := 0
			manager := &fileTransferBudgetManager{exchange: func(local, remote string, payload []byte, timeout time.Duration) ([]byte, error) {
				calls++
				if local != "receiver" || remote != "sender" || !bytes.Equal(payload, wantRequest) {
					t.Fatal("retry changed the requested transfer range or peers")
				}
				if timeout <= 0 || timeout > time.Second {
					t.Fatalf("exchange timeout is not bounded: %v", timeout)
				}
				if calls <= test.failures {
					return nil, fmt.Errorf("transport failed: %w", test.failure)
				}
				return test.reply, nil
			}}
			agent := &Agent{runtime: RuntimeConfig{DirectProbeTimeout: 2 * time.Second}}
			response, err := agent.exchangeFileTransferBlock(manager, &ConnectionStatus{LocalPeerID: "receiver", RemotePeerID: "sender"}, request, time.Now().Add(5*time.Second))
			if calls != test.wantCalls || (err != nil) != test.wantError {
				t.Fatalf("calls=%d want=%d error=%v", calls, test.wantCalls, err)
			}
			if errors.Is(err, errFileTransferInterrupted) != test.interrupted {
				t.Fatalf("unexpected interruption classification: %v", err)
			}
			if test.failure != nil && test.wantError && !errors.Is(err, test.failure) {
				t.Fatalf("underlying transport failure was lost: %v", err)
			}
			if !test.wantError && !bytes.Equal(response.Payload, []byte("ok")) {
				t.Fatalf("successful retry lost the response: %+v", response)
			}
		})
	}
}

func TestFileTransferBudgetExchangeRejectsBeforeSending(t *testing.T) {
	for _, test := range []struct {
		name        string
		transferID  string
		deadline    time.Time
		interrupted bool
	}{
		{"oversized request metadata", strings.Repeat("<", transportauth.MaxMessageBytes), time.Now().Add(time.Second), false},
		{"expired deadline", "transfer", time.Now().Add(-time.Second), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := &fileTransferBudgetManager{exchange: func(string, string, []byte, time.Duration) ([]byte, error) {
				t.Fatal("invalid request or expired deadline reached the transport")
				return nil, nil
			}}
			agent := &Agent{}
			request := fileTransferDataplaneRequest{Type: "file-transfer-chunk-request", TransferID: test.transferID, LimitBytes: 1}
			_, err := agent.exchangeFileTransferBlock(manager, &ConnectionStatus{}, request, test.deadline)
			if err == nil || errors.Is(err, errFileTransferInterrupted) != test.interrupted {
				t.Fatalf("unexpected rejection: %v", err)
			}
		})
	}
}

func TestFileTransferBudgetRelayTimeoutCoversBindAndReply(t *testing.T) {
	for _, window := range []time.Duration{2 * time.Second, 200 * time.Millisecond} {
		t.Run(window.String(), func(t *testing.T) {
			maxStage := min(window/2, time.Second/2)
			manager := &fileTransferBudgetManager{exchange: func(_, _ string, _ []byte, timeout time.Duration) ([]byte, error) {
				if timeout <= 0 || timeout > maxStage {
					t.Fatalf("relay bind and reply can exceed the attempt/phase budget: stage=%s max=%s", timeout, maxStage)
				}
				return []byte(`{"type":"file-transfer-chunk-response"}`), nil
			}}
			agent := &Agent{runtime: RuntimeConfig{DirectProbeTimeout: 3 * time.Second}}
			_, err := agent.exchangeFileTransferBlock(manager, &ConnectionStatus{TransportMode: "RELAY"}, fileTransferDataplaneRequest{Type: "file-transfer-chunk-request", TransferID: "file"}, time.Now().Add(window))
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
