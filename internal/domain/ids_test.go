package domain

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const idTestBatchSize = 2500

// Separate processes model both restarts and independent server instances.
func TestIdentifiersSurviveProcessRestarts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := func() ([]string, error) {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestIdentifierProcessHelper$")
		cmd.Env = append(os.Environ(), "OLE_ID_PROCESS_HELPER=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("ID process: %w: %s", err, output)
		}
		var ids []string
		if err := json.Unmarshal(output, &ids); err != nil {
			return nil, fmt.Errorf("decode IDs: %w", err)
		}
		if len(ids) != idTestBatchSize {
			return nil, fmt.Errorf("got %d IDs, want %d", len(ids), idTestBatchSize)
		}
		return ids, nil
	}
	var batches [][]string
	for range 2 {
		ids, err := run()
		if err != nil {
			t.Fatal(err)
		}
		batches = append(batches, ids)
	}
	type result struct {
		ids []string
		err error
	}
	concurrent := make(chan result, 2)
	for range 2 {
		go func() {
			ids, err := run()
			concurrent <- result{ids, err}
		}()
	}
	for range 2 {
		item := <-concurrent
		if item.err != nil {
			t.Fatal(item.err)
		}
		batches = append(batches, item.ids)
	}
	seen := make(map[string]bool)
	duplicates := 0
	for _, ids := range batches {
		for _, id := range ids {
			if seen[id] {
				duplicates++
			}
			seen[id] = true
		}
	}
	t.Logf("processes=%d generated=%d unique=%d duplicates=%d", len(batches), len(batches)*idTestBatchSize, len(seen), duplicates)
	if duplicates != 0 {
		t.Fatalf("IDs collided across independent processes: %d duplicates", duplicates)
	}
}

func TestIdentifierProcessHelper(t *testing.T) {
	if os.Getenv("OLE_ID_PROCESS_HELPER") != "1" {
		return
	}
	ids := make([]string, idTestBatchSize)
	for i := range ids {
		ids[i] = nextID("usr")
	}
	if err := json.NewEncoder(os.Stdout).Encode(ids); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestIdentifierAndTokenNamespacesHaveRandomEntropy(t *testing.T) {
	for _, prefix := range []string{"usr", "ses", "fam", "aud", "dev", "net", "peer", "cand", "tun", "msg", "xfer", "ref", "inv", "acc"} {
		t.Run(prefix, func(t *testing.T) {
			value := nextID(prefix)
			if prefix == "ref" || prefix == "inv" || prefix == "acc" {
				value = secureToken(prefix)
			}
			if !strings.HasPrefix(value, prefix+"-") {
				t.Fatalf("namespace missing: %q", value)
			}
			randomBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimPrefix(value, prefix+"-"))
			if err != nil || len(randomBytes) < 16 {
				t.Fatalf("expected at least 128 random bits in base32 suffix, got %q", value)
			}
		})
	}
}
