package httpapi

import (
	"Ole/internal/domain"
	"Ole/internal/structuredlog"
	"Ole/internal/tracectx"
	"Ole/internal/versioninfo"
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type contextKey string

const userIDContextKey contextKey = "user_id"

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (api *API) withMiddleware(next http.Handler) http.Handler {
	return api.recoverMiddleware(api.traceMiddleware(api.loggingMiddleware(api.versionMiddleware(next))))
}

func (api *API) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "missing bearer token"})
			return
		}
		userID, err := api.app.AuthService.ValidateAccessToken(token)
		if err != nil {
			writeDomainError(w, err)
			return
		}
		ctx := context.WithValue(r.Context(), userIDContextKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (api *API) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(recorder, r)
		path := normalizeMetricsPath(r.URL.Path)
		if api != nil && api.metrics != nil {
			labels := map[string]string{
				"method": r.Method,
				"path":   path,
				"status": strconv.Itoa(recorder.statusCode),
			}
			api.metrics.IncCounter("ole_server_http_requests_total", "HTTP requests processed by the Ole server.", labels, 1)
			api.metrics.IncCounter("ole_server_http_request_duration_seconds_total", "Total HTTP request duration in seconds.", labels, time.Since(start).Seconds())
		}
		if api != nil && api.logger != nil {
			api.logger.Info(
				"http request completed",
				"method", r.Method,
				"path", path,
				"status", recorder.statusCode,
				"durationMs", time.Since(start).Milliseconds(),
				"remoteAddr", r.RemoteAddr,
				"traceId", tracectx.TraceID(r.Context()),
				"spanId", tracectx.SpanID(r.Context()),
				"parentSpanId", tracectx.ParentSpanID(r.Context()),
			)
		}
	})
}

func (api *API) traceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trace := tracectx.StartServerTrace(r.Header)
		tracectx.ApplyResponseHeaders(w.Header(), trace)
		next.ServeHTTP(w, r.WithContext(tracectx.WithContext(r.Context(), trace)))
	})
}

func (api *API) versionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(api.versionInfo.ServerVersion) != "" {
			w.Header().Set(versioninfo.HeaderServerVersion, api.versionInfo.ServerVersion)
		}
		if strings.TrimSpace(api.versionInfo.MinClientVersion) != "" {
			w.Header().Set(versioninfo.HeaderMinClientVersion, api.versionInfo.MinClientVersion)
		}
		if allowsVersionDiscovery(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		clientVersion := strings.TrimSpace(r.Header.Get(versioninfo.HeaderClientVersion))
		if clientVersion != "" {
			compatibility := versioninfo.Evaluate(clientVersion, api.versionInfo)
			if !compatibility.Compatible {
				writeJSON(w, http.StatusUpgradeRequired, errorResponse{Error: compatibility.Message})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func allowsVersionDiscovery(path string) bool {
	switch path {
	case "/health", "/livez", "/readyz", "/metrics", "/api/v1", "/openapi.yaml", "/swagger":
		return true
	default:
		return strings.HasPrefix(path, "/swagger/")
	}
}

func (api *API) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				logger := structuredlog.New("server.httpapi")
				if api != nil && api.logger != nil {
					logger = api.logger
				}
				if api != nil && api.metrics != nil {
					api.metrics.IncCounter("ole_server_http_panics_total", "Panics recovered while serving HTTP requests.", map[string]string{
						"method": r.Method,
						"path":   normalizeMetricsPath(r.URL.Path),
					}, 1)
				}
				logger.Error(
					"panic while handling request",
					"method", r.Method,
					"path", r.URL.Path,
					"panic", recovered,
					"traceId", tracectx.TraceID(r.Context()),
					"spanId", tracectx.SpanID(r.Context()),
					"parentSpanId", tracectx.ParentSpanID(r.Context()),
				)
				writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal server error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (api *API) traceInfo(r *http.Request, event, message string, keyvals ...any) {
	if api == nil || api.logger == nil {
		return
	}
	api.logger.Info(strings.TrimSpace(message), api.traceKeyvals(r, append([]any{"event", strings.TrimSpace(event)}, keyvals...)...)...)
}

func (api *API) traceError(r *http.Request, event, message string, keyvals ...any) {
	if api == nil || api.logger == nil {
		return
	}
	api.logger.Error(strings.TrimSpace(message), api.traceKeyvals(r, append([]any{"event", strings.TrimSpace(event)}, keyvals...)...)...)
}

func (api *API) traceKeyvals(r *http.Request, keyvals ...any) []any {
	trace := tracectx.FromContext(r.Context())
	return append(keyvals,
		"traceId", trace.TraceID,
		"spanId", trace.SpanID,
		"parentSpanId", trace.ParentSpanID,
	)
}

func currentUserID(r *http.Request) domain.UserID {
	if value, ok := r.Context().Value(userIDContextKey).(domain.UserID); ok {
		return value
	}
	return domain.UserID{}
}
