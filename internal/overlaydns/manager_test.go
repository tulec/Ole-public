package overlaydns_test

import (
	"Ole/internal/overlaydns"
	"context"
	"testing"
	"time"
)

func TestManagerResolvesOverlayARecords(t *testing.T) {
	manager := overlaydns.New("127.0.0.1:0", "ole")
	defer manager.Close()

	if err := manager.Reconcile(map[string]string{
		"peer-1.ole":       "10.55.1.2",
		"peer-2.net-1.ole": "10.55.1.3",
	}); err != nil {
		t.Fatalf("reconcile records: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	hosts, err := overlaydns.LookupHost(ctx, manager.Address(), "peer-1.ole")
	if err != nil {
		t.Fatalf("lookup host: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "10.55.1.2" {
		t.Fatalf("expected one overlay A record, got %#v", hosts)
	}

	status := manager.Snapshot()
	if status.RecordCount != 2 || status.Domain != "ole" || status.ListenAddress == "" {
		t.Fatalf("unexpected dns status: %#v", status)
	}
}

func TestLookupHostReturnsNotFoundForUnknownOverlayName(t *testing.T) {
	manager := overlaydns.New("127.0.0.1:0", "ole")
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if _, err := overlaydns.LookupHost(ctx, manager.Address(), "missing.ole"); err == nil {
		t.Fatalf("expected lookup for missing overlay host to fail")
	}
}
