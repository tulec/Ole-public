package autoupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckResolvesRelativeManifestURLs(t *testing.T) {
	installerBody := []byte("installer-binary")
	installerHash := sha256.Sum256(installerBody)
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest/download/ole-update.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Manifest{
			Version:         "0.2.0",
			PublishedAtUnix: 1_710_000_000,
			InstallerURL:    "Ole-Setup-0.2.0.exe",
			SHA256:          hex.EncodeToString(installerHash[:]),
			ReleaseNotesURL: "../notes/0.2.0",
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(server.URL + "/releases/latest/download/ole-update.json")
	result, err := client.Check(context.Background(), "0.1.0")
	if err != nil {
		t.Fatalf("check update: %v", err)
	}
	if !result.Available {
		t.Fatalf("expected update to be available")
	}
	if result.Manifest.InstallerURL != server.URL+"/releases/latest/download/Ole-Setup-0.2.0.exe" {
		t.Fatalf("unexpected installer url: %s", result.Manifest.InstallerURL)
	}
	if result.Manifest.ReleaseNotesURL != server.URL+"/releases/latest/notes/0.2.0" {
		t.Fatalf("unexpected notes url: %s", result.Manifest.ReleaseNotesURL)
	}
}

func TestDownloadInstallerVerifiesSHA256(t *testing.T) {
	installerBody := []byte("installer-binary")
	installerHash := sha256.Sum256(installerBody)
	mux := http.NewServeMux()
	mux.HandleFunc("/Ole-Setup-0.2.0.exe", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(installerBody)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(server.URL + "/ole-update.json")
	targetDir := t.TempDir()
	path, err := client.DownloadInstaller(context.Background(), Manifest{
		InstallerURL: server.URL + "/Ole-Setup-0.2.0.exe",
		SHA256:       hex.EncodeToString(installerHash[:]),
	}, targetDir)
	if err != nil {
		t.Fatalf("download installer: %v", err)
	}
	if filepath.Dir(path) != targetDir {
		t.Fatalf("expected download in %s, got %s", targetDir, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read installer: %v", err)
	}
	if string(data) != string(installerBody) {
		t.Fatalf("unexpected installer body: %q", string(data))
	}
}

func TestDownloadInstallerFailsOnChecksumMismatch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/Ole-Setup-0.2.0.exe", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("installer-binary"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(server.URL + "/ole-update.json")
	_, err := client.DownloadInstaller(context.Background(), Manifest{
		InstallerURL: server.URL + "/Ole-Setup-0.2.0.exe",
		SHA256:       "deadbeef",
	}, t.TempDir())
	if err == nil {
		t.Fatalf("expected checksum mismatch")
	}
}
