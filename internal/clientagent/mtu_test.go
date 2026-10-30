package clientagent

import (
	"Ole/internal/transportauth"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultAndLegacyMTUFitTransport(t *testing.T) {
	if got := defaultPersistentState().AdapterMTU; got != transportauth.DefaultAdapterMTU {
		t.Fatal("new state does not select safe default MTU")
	}
	for _, tc := range []struct{ saved, want int }{{0, 1280}, {-1, 1280}, {575, 1280}, {576, 576}, {1280, 1280}, {1500, 1500}, {1501, 1500}, {65535, 1500}} {
		state := PersistentState{AdapterMTU: tc.saved}
		state.normalize()
		if state.AdapterMTU != tc.want {
			t.Fatalf("saved MTU%d became%d, want%d", tc.saved, state.AdapterMTU, tc.want)
		}
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"adapterMtu":65535}`), 0600); err != nil {
		t.Fatal(err)
	}
	state, err := NewStateStore(path).Load()
	if err != nil || state.AdapterMTU != 1500 {
		t.Fatal("legacy oversized MTU was not migrated", err)
	}
	a := &Agent{}
	if _, err := a.SetAdapterMTU(1501); err == nil {
		t.Fatal("settings accepted unsupported MTU")
	}
}
