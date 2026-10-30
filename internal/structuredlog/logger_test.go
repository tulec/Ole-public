package structuredlog

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestLoggerWritesStructuredJSON(t *testing.T) {
	var buffer bytes.Buffer
	logger := NewWithWriter("server.httpapi", &buffer)
	logger.Info("request complete", "method", "GET", "status", 200, "durationMs", 12)

	var payload map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &payload); err != nil {
		t.Fatalf("decode log line: %v", err)
	}
	if payload["msg"] != "request complete" {
		t.Fatalf("expected message in payload, got %#v", payload)
	}
	if payload["service"] != "ole" || payload["component"] != "server.httpapi" {
		t.Fatalf("expected service and component fields, got %#v", payload)
	}
	if payload["method"] != "GET" {
		t.Fatalf("expected structured method field, got %#v", payload)
	}
}

func TestFieldsMapNormalizesOddAndErrorValues(t *testing.T) {
	fields := FieldsMap("reason", "temporary", "err", assertErr("boom"), "dangling")
	if fields["reason"] != "temporary" {
		t.Fatalf("expected reason field, got %#v", fields)
	}
	if fields["err"] != "boom" {
		t.Fatalf("expected error stringification, got %#v", fields)
	}
	if fields["dangling"] != "" {
		t.Fatalf("expected dangling field to normalize into empty value, got %#v", fields)
	}
}

type assertErr string

func (e assertErr) Error() string { return string(e) }
