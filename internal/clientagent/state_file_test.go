package clientagent

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestStateStoreConcurrentReadersSeeCompleteJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := NewStateStore(path)
	state := defaultPersistentState()
	state.DeviceName = strings.Repeat("complete-state-", 8192)
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	errors := make(chan error, 5)
	workers.Add(5)
	for range 4 {
		go func() {
			defer workers.Done()
			reader := NewStateStore(path)
			for range 120 {
				loaded, err := reader.Load()
				if err != nil {
					errors <- err
					return
				}
				if loaded.DeviceName != state.DeviceName {
					t.Error("reader saw incomplete state")
					return
				}
			}
		}()
	}
	go func() {
		defer workers.Done()
		for range 120 {
			if err := store.Save(state); err != nil {
				errors <- err
				return
			}
		}
	}()
	workers.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	entries, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".ole-state-*"))
	if err != nil || len(entries) != 0 {
		t.Fatal("temporary state files retained", entries, err)
	}
}

func TestStateReplacementFailurePreservesDestination(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "destination")
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(destination, "keep")
	if err := os.WriteFile(marker, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := replaceStateFile(destination, []byte("new")); err == nil {
		t.Fatal("replacement should fail")
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "original" {
		t.Fatal("previous destination damaged", err)
	}
	entries, err := filepath.Glob(filepath.Join(filepath.Dir(destination), ".ole-state-*"))
	if err != nil || len(entries) != 0 {
		t.Fatal("failed write retained temporary files", entries, err)
	}
}
