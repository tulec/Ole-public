package controlclient_test

import (
	"Ole/internal/controlclient"
	"Ole/internal/tracectx"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientPropagatesTraceHeadersAndObserver(t *testing.T) {
	var seenRequestTraceID string
	var seenRequestParentSpanID string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenRequestTraceID = r.Header.Get(tracectx.HeaderTraceID)
		seenRequestParentSpanID = r.Header.Get(tracectx.HeaderParentSpanID)
		w.Header().Set(tracectx.HeaderTraceID, seenRequestTraceID)
		w.Header().Set(tracectx.HeaderSpanID, "abcdabcdabcdabcd")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"time":   int64(1),
			"version": map[string]any{
				"apiVersion":       "v1",
				"serverVersion":    "0.1.0",
				"minClientVersion": "0.1.0",
			},
		})
	}))
	defer server.Close()

	client := controlclient.New(server.URL)
	var observed controlclient.RequestTrace
	client.SetRequestObserver(func(trace controlclient.RequestTrace) {
		observed = trace
	})

	info, err := client.GetServerInfo()
	if err != nil {
		t.Fatalf("get server info: %v", err)
	}
	if info == nil || info.Status != "ok" {
		t.Fatalf("expected server info response, got %#v", info)
	}
	if seenRequestTraceID == "" {
		t.Fatalf("expected client to send trace id header")
	}
	if len(seenRequestParentSpanID) != 16 {
		t.Fatalf("expected client to send parent span id header, got %q", seenRequestParentSpanID)
	}
	if observed.TraceID != seenRequestTraceID {
		t.Fatalf("expected observer trace id %q, got %q", seenRequestTraceID, observed.TraceID)
	}
	if observed.SpanID != seenRequestParentSpanID {
		t.Fatalf("expected observer span id %q, got %q", seenRequestParentSpanID, observed.SpanID)
	}
	if observed.ServerSpanID != "abcdabcdabcdabcd" {
		t.Fatalf("expected observer server span id, got %q", observed.ServerSpanID)
	}
	if observed.ResponseTrace != seenRequestTraceID {
		t.Fatalf("expected response trace id %q, got %q", seenRequestTraceID, observed.ResponseTrace)
	}
	if observed.Path != "/health" || observed.Method != http.MethodGet {
		t.Fatalf("unexpected observer request info: %#v", observed)
	}
	if observed.StatusCode != http.StatusOK {
		t.Fatalf("expected successful observer status, got %#v", observed)
	}
}

func TestClientMessageAndFileTransferEndpoints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/networks/net-1/messages":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":         "msg-1",
					"networkId":  "net-1",
					"fromPeerId": "peer-1",
					"text":       "hello",
					"preview":    "hello",
					"sentAtUnix": int64(10),
				}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/networks/net-1/messages":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			if strings.TrimSpace(req["fromPeerId"].(string)) != "peer-1" {
				t.Fatalf("unexpected message payload: %#v", req)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id":         "msg-2",
					"networkId":  "net-1",
					"fromPeerId": req["fromPeerId"],
					"text":       req["text"],
					"preview":    req["text"],
					"sentAtUnix": int64(20),
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/networks/net-1/file-transfers":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":              "xfer-1",
					"networkId":       "net-1",
					"fromPeerId":      "peer-1",
					"toPeerId":        "peer-2",
					"fileName":        "notes.txt",
					"sizeBytes":       int64(64),
					"status":          "INIT",
					"progressPercent": 0,
				}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/networks/net-1/file-transfers":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id":              "xfer-2",
					"networkId":       "net-1",
					"fromPeerId":      req["fromPeerId"],
					"toPeerId":        req["toPeerId"],
					"fileName":        req["fileName"],
					"sizeBytes":       req["sizeBytes"],
					"status":          "INIT",
					"progressPercent": 0,
				},
			})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/file-transfers/xfer-2":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id":              "xfer-2",
					"networkId":       "net-1",
					"fromPeerId":      "peer-1",
					"toPeerId":        "peer-2",
					"fileName":        "notes.txt",
					"sizeBytes":       int64(64),
					"status":          map[string]string{"accept": "IN_PROGRESS", "cancel": "CANCELED", "progress": "DONE"}[req["action"].(string)],
					"progressPercent": 100,
					"cancelReason":    req["reason"],
				},
			})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client := controlclient.New(server.URL)
	messages, err := client.ListMessages("net-1")
	if err != nil {
		t.Fatalf("list messages: %v", err)
	}
	if len(messages) != 1 || messages[0].ID != "msg-1" {
		t.Fatalf("unexpected listed messages: %#v", messages)
	}
	message, err := client.SendMessage("net-1", "peer-1", "hello")
	if err != nil {
		t.Fatalf("send message: %v", err)
	}
	if message.ID != "msg-2" || message.FromPeerID != "peer-1" {
		t.Fatalf("unexpected sent message: %#v", message)
	}

	transfers, err := client.ListFileTransfers("net-1")
	if err != nil {
		t.Fatalf("list file transfers: %v", err)
	}
	if len(transfers) != 1 || transfers[0].ID != "xfer-1" {
		t.Fatalf("unexpected listed transfers: %#v", transfers)
	}
	transfer, err := client.CreateFileTransfer("net-1", "peer-1", "peer-2", "notes.txt", 64)
	if err != nil {
		t.Fatalf("create file transfer: %v", err)
	}
	if transfer.ID != "xfer-2" {
		t.Fatalf("unexpected created transfer: %#v", transfer)
	}
	if _, err := client.AcceptFileTransfer("xfer-2"); err != nil {
		t.Fatalf("accept file transfer: %v", err)
	}
	if _, err := client.UpdateFileTransferProgress("xfer-2", 100); err != nil {
		t.Fatalf("progress file transfer: %v", err)
	}
	if _, err := client.CancelFileTransfer("xfer-2", "done"); err != nil {
		t.Fatalf("cancel file transfer: %v", err)
	}
}

func TestClientNetworkFileTransferPolicyEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/networks/net-1/file-transfer-policy":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["enabled"] != false || int64(req["maxBytes"].(float64)) != 4096 {
				t.Fatalf("unexpected file transfer policy payload: %#v", req)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id":                   "net-1",
					"name":                 "friends",
					"ownerId":              "usr-1",
					"access":               "INVITE_ONLY",
					"fileTransfersEnabled": false,
					"fileTransferMaxBytes": int64(4096),
				},
			})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client := controlclient.New(server.URL)
	network, err := client.UpdateNetworkFileTransferPolicy("net-1", false, 4096)
	if err != nil {
		t.Fatalf("update network file transfer policy: %v", err)
	}
	if network.FileTransfersEnabled || network.FileTransferMaxBytes != 4096 {
		t.Fatalf("unexpected network file transfer policy response: %#v", network)
	}
}

func TestClientFileTransferChunkEndpoints(t *testing.T) {
	uploadedPayload := []byte("abcdefgh")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/file-transfers/xfer-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id":                   "xfer-1",
					"networkId":            "net-1",
					"fromPeerId":           "peer-1",
					"toPeerId":             "peer-2",
					"fileName":             "resume.bin",
					"sizeBytes":            int64(len(uploadedPayload)),
					"status":               "INIT",
					"payloadUploadedBytes": int64(4),
				},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/file-transfers/xfer-1/content-chunks":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			if int64(req["offsetBytes"].(float64)) != 4 {
				t.Fatalf("expected resumed upload offset 4, got %#v", req)
			}
			decoded, err := base64.StdEncoding.DecodeString(req["payloadBase64"].(string))
			if err != nil || !bytes.Equal(decoded, uploadedPayload[4:]) {
				t.Fatalf("unexpected uploaded chunk payload: %q err=%v", req["payloadBase64"], err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id":                   "xfer-1",
					"networkId":            "net-1",
					"fromPeerId":           "peer-1",
					"toPeerId":             "peer-2",
					"fileName":             "resume.bin",
					"sizeBytes":            int64(len(uploadedPayload)),
					"status":               "INIT",
					"payloadUploadedBytes": int64(len(uploadedPayload)),
					"payloadReady":         true,
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/file-transfers/xfer-1/content-chunks":
			offset := r.URL.Query().Get("offsetBytes")
			switch offset {
			case "":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{
						"transfer": map[string]any{
							"id":        "xfer-1",
							"networkId": "net-1",
						},
						"contentType":     "application/octet-stream",
						"payloadBase64":   base64.StdEncoding.EncodeToString(uploadedPayload[:4]),
						"offsetBytes":     int64(0),
						"nextOffsetBytes": int64(4),
						"totalSizeBytes":  int64(len(uploadedPayload)),
						"complete":        false,
					},
				})
			case "4":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{
						"transfer": map[string]any{
							"id":        "xfer-1",
							"networkId": "net-1",
						},
						"contentType":     "application/octet-stream",
						"payloadBase64":   base64.StdEncoding.EncodeToString(uploadedPayload[4:]),
						"offsetBytes":     int64(4),
						"nextOffsetBytes": int64(len(uploadedPayload)),
						"totalSizeBytes":  int64(len(uploadedPayload)),
						"complete":        true,
					},
				})
			default:
				t.Fatalf("unexpected chunk offset query: %q", offset)
			}
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client := controlclient.New(server.URL)
	transfer, err := client.UploadFileTransferContent("xfer-1", "application/octet-stream", uploadedPayload)
	if err != nil {
		t.Fatalf("upload chunked content: %v", err)
	}
	if !transfer.PayloadReady || transfer.PayloadUploadedBytes != int64(len(uploadedPayload)) {
		t.Fatalf("unexpected uploaded transfer metadata: %#v", transfer)
	}

	content, err := client.DownloadFileTransferContent("xfer-1")
	if err != nil {
		t.Fatalf("download chunked content: %v", err)
	}
	if !bytes.Equal(content.Payload, uploadedPayload) || content.SizeBytes != int64(len(uploadedPayload)) {
		t.Fatalf("unexpected downloaded chunked payload: %#v", content)
	}
}
