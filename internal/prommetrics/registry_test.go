package prommetrics

import (
	"strings"
	"testing"
)

func TestRegistryRendersPrometheusText(t *testing.T) {
	registry := NewRegistry()
	registry.IncCounter("ole_server_http_requests_total", "HTTP requests processed.", map[string]string{
		"method": "GET",
		"path":   "/health",
		"status": "200",
	}, 1)
	registry.SetGauge("ole_server_connected_peers", "Connected peers.", nil, 2)

	body := string(registry.Render())
	assertContains(t, body, "# HELP ole_server_connected_peers Connected peers.")
	assertContains(t, body, "# TYPE ole_server_http_requests_total counter")
	assertContains(t, body, `ole_server_http_requests_total{method="GET",path="/health",status="200"} 1`)
	assertContains(t, body, "ole_server_connected_peers 2")
}

func TestRegistryEscapesLabels(t *testing.T) {
	registry := NewRegistry()
	registry.SetGauge("ole_value", "help", map[string]string{"path": `/api/"test"`}, 1)
	body := string(registry.Render())
	assertContains(t, body, `path="/api/\"test\""`)
}

func assertContains(t *testing.T, value, fragment string) {
	t.Helper()
	if !strings.Contains(value, fragment) {
		t.Fatalf("expected %q to contain %q", value, fragment)
	}
}
