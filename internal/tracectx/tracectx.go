package tracectx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

const (
	HeaderTraceID      = "X-Ole-Trace-Id"
	HeaderParentSpanID = "X-Ole-Parent-Span-Id"
	HeaderSpanID       = "X-Ole-Span-Id"
)

type contextKey string

const traceContextKey contextKey = "ole_trace_context"

type Context struct {
	TraceID      string
	ParentSpanID string
	SpanID       string
}

func StartServerTrace(headers http.Header) Context {
	traceID := normalizeID(headers.Get(HeaderTraceID), 16)
	if traceID == "" {
		traceID = NewTraceID()
	}
	return Context{
		TraceID:      traceID,
		ParentSpanID: normalizeID(headers.Get(HeaderParentSpanID), 8),
		SpanID:       NewSpanID(),
	}
}

func StartClientTrace() Context {
	traceID := NewTraceID()
	return Context{
		TraceID: traceID,
		SpanID:  NewSpanID(),
	}
}

func WithContext(ctx context.Context, trace Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, traceContextKey, trace)
}

func FromContext(ctx context.Context) Context {
	if ctx == nil {
		return Context{}
	}
	if trace, ok := ctx.Value(traceContextKey).(Context); ok {
		return trace
	}
	return Context{}
}

func TraceID(ctx context.Context) string {
	return FromContext(ctx).TraceID
}

func ParentSpanID(ctx context.Context) string {
	return FromContext(ctx).ParentSpanID
}

func SpanID(ctx context.Context) string {
	return FromContext(ctx).SpanID
}

func ApplyRequestHeaders(headers http.Header, trace Context) {
	if headers == nil {
		return
	}
	if traceID := normalizeID(trace.TraceID, 16); traceID != "" {
		headers.Set(HeaderTraceID, traceID)
	}
	if spanID := normalizeID(trace.SpanID, 8); spanID != "" {
		headers.Set(HeaderParentSpanID, spanID)
	}
}

func ApplyResponseHeaders(headers http.Header, trace Context) {
	if headers == nil {
		return
	}
	if traceID := normalizeID(trace.TraceID, 16); traceID != "" {
		headers.Set(HeaderTraceID, traceID)
	}
	if parentSpanID := normalizeID(trace.ParentSpanID, 8); parentSpanID != "" {
		headers.Set(HeaderParentSpanID, parentSpanID)
	}
	if spanID := normalizeID(trace.SpanID, 8); spanID != "" {
		headers.Set(HeaderSpanID, spanID)
	}
}

func NewTraceID() string {
	return randomHex(16)
}

func NewSpanID() string {
	return randomHex(8)
}

func randomHex(size int) string {
	if size <= 0 {
		return ""
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return hex.EncodeToString(buf)
}

func normalizeID(value string, expectedBytes int) string {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "" {
		return ""
	}
	if len(trimmed) != expectedBytes*2 {
		return ""
	}
	for _, ch := range trimmed {
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'f':
		default:
			return ""
		}
	}
	return trimmed
}
