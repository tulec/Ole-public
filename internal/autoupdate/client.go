package autoupdate

import (
	"Ole/internal/versioninfo"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const defaultHTTPTimeout = 20 * time.Second

type Manifest struct {
	Version         string              `json:"version"`
	PublishedAtUnix int64               `json:"publishedAtUnix"`
	InstallerURL    string              `json:"installerUrl"`
	SHA256          string              `json:"sha256"`
	ReleaseNotesURL string              `json:"releaseNotesUrl,omitempty"`
	SignatureURL    string              `json:"signatureUrl,omitempty"`
	CertificateURL  string              `json:"certificateUrl,omitempty"`
	Compatibility   CompatibilityPolicy `json:"compatibility,omitempty"`
	Rollback        *Release            `json:"rollback,omitempty"`
}

type CompatibilityPolicy struct {
	MinimumServerVersion   string `json:"minimumServerVersion,omitempty"`
	MaximumServerVersion   string `json:"maximumServerVersion,omitempty"`
	MinimumRollbackVersion string `json:"minimumRollbackVersion,omitempty"`
}

type Release struct {
	Version         string `json:"version"`
	InstallerURL    string `json:"installerUrl"`
	SHA256          string `json:"sha256"`
	SignatureURL    string `json:"signatureUrl,omitempty"`
	CertificateURL  string `json:"certificateUrl,omitempty"`
	ReleaseNotesURL string `json:"releaseNotesUrl,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

type CheckResult struct {
	Manifest  Manifest
	Available bool
}

type Client struct {
	manifestURL string
	httpClient  *http.Client
}

func NewClient(manifestURL string) *Client {
	return NewClientWithHTTP(manifestURL, nil)
}

func NewClientWithHTTP(manifestURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	return &Client{
		manifestURL: strings.TrimSpace(manifestURL),
		httpClient:  httpClient,
	}
}

func DefaultDownloadDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil || strings.TrimSpace(cacheDir) == "" {
		return filepath.Join(".", "updates")
	}
	return filepath.Join(cacheDir, "Ole", "updates")
}

func (c *Client) ManifestURL() string {
	if c == nil {
		return ""
	}
	return c.manifestURL
}

func (c *Client) Check(ctx context.Context, currentVersion string) (CheckResult, error) {
	if c == nil || strings.TrimSpace(c.manifestURL) == "" {
		return CheckResult{}, errors.New("update manifest url is not configured")
	}
	manifest, err := c.fetchManifest(ctx)
	if err != nil {
		return CheckResult{}, err
	}
	cmp, err := versioninfo.Compare(strings.TrimSpace(currentVersion), manifest.Version)
	if err != nil {
		return CheckResult{}, err
	}
	return CheckResult{
		Manifest:  manifest,
		Available: cmp < 0,
	}, nil
}

func (c *Client) DownloadInstaller(ctx context.Context, manifest Manifest, targetDir string) (string, error) {
	return c.downloadRelease(ctx, Release{
		Version:         manifest.Version,
		InstallerURL:    manifest.InstallerURL,
		SHA256:          manifest.SHA256,
		SignatureURL:    manifest.SignatureURL,
		CertificateURL:  manifest.CertificateURL,
		ReleaseNotesURL: manifest.ReleaseNotesURL,
	}, targetDir)
}

func (c *Client) DownloadRollback(ctx context.Context, manifest Manifest, targetDir string) (string, error) {
	if manifest.Rollback == nil {
		return "", errors.New("no rollback release is available")
	}
	return c.downloadRelease(ctx, *manifest.Rollback, targetDir)
}

func (c *Client) downloadRelease(ctx context.Context, release Release, targetDir string) (string, error) {
	if c == nil {
		return "", errors.New("auto-update client is not configured")
	}
	installerURL := strings.TrimSpace(release.InstallerURL)
	if installerURL == "" {
		return "", errors.New("update installer url is missing")
	}
	if strings.TrimSpace(targetDir) == "" {
		targetDir = DefaultDownloadDir()
	}
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return "", err
	}
	targetName := installerFileName(installerURL)
	targetPath := filepath.Join(targetDir, targetName)
	if fileMatchesSHA256(targetPath, release.SHA256) {
		return targetPath, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, installerURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("update download failed with status %d", resp.StatusCode)
	}

	tempPath := targetPath + ".tmp"
	file, err := os.Create(tempPath)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	writer := io.MultiWriter(file, hasher)
	_, copyErr := io.Copy(writer, resp.Body)
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(tempPath)
		return "", copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tempPath)
		return "", closeErr
	}
	if expected := normalizeSHA256(release.SHA256); expected != "" {
		actual := strings.ToLower(hex.EncodeToString(hasher.Sum(nil)))
		if actual != expected {
			_ = os.Remove(tempPath)
			return "", fmt.Errorf("downloaded update checksum mismatch: expected %s, got %s", expected, actual)
		}
	}
	_ = os.Remove(targetPath)
	if err := os.Rename(tempPath, targetPath); err != nil {
		data, readErr := os.ReadFile(tempPath)
		if readErr != nil {
			_ = os.Remove(tempPath)
			return "", err
		}
		if writeErr := os.WriteFile(targetPath, data, 0o755); writeErr != nil {
			_ = os.Remove(tempPath)
			return "", err
		}
		_ = os.Remove(tempPath)
	}
	return targetPath, nil
}

func (c *Client) fetchManifest(ctx context.Context) (Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.manifestURL, nil)
	if err != nil {
		return Manifest{}, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Manifest{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Manifest{}, fmt.Errorf("update manifest request failed with status %d", resp.StatusCode)
	}
	var manifest Manifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode update manifest: %w", err)
	}
	manifest.Version = strings.TrimSpace(manifest.Version)
	if manifest.Version == "" {
		return Manifest{}, errors.New("update manifest version is missing")
	}
	var normalizeErr error
	if manifest.InstallerURL, normalizeErr = resolveURL(c.manifestURL, manifest.InstallerURL); normalizeErr != nil {
		return Manifest{}, normalizeErr
	}
	if manifest.ReleaseNotesURL, normalizeErr = resolveOptionalURL(c.manifestURL, manifest.ReleaseNotesURL); normalizeErr != nil {
		return Manifest{}, normalizeErr
	}
	if manifest.SignatureURL, normalizeErr = resolveOptionalURL(c.manifestURL, manifest.SignatureURL); normalizeErr != nil {
		return Manifest{}, normalizeErr
	}
	if manifest.CertificateURL, normalizeErr = resolveOptionalURL(c.manifestURL, manifest.CertificateURL); normalizeErr != nil {
		return Manifest{}, normalizeErr
	}
	manifest.SHA256 = normalizeSHA256(manifest.SHA256)
	manifest.Compatibility.MinimumServerVersion = strings.TrimSpace(manifest.Compatibility.MinimumServerVersion)
	manifest.Compatibility.MaximumServerVersion = strings.TrimSpace(manifest.Compatibility.MaximumServerVersion)
	manifest.Compatibility.MinimumRollbackVersion = strings.TrimSpace(manifest.Compatibility.MinimumRollbackVersion)
	if manifest.Rollback != nil {
		rollback := *manifest.Rollback
		rollback.Version = strings.TrimSpace(rollback.Version)
		if rollback.InstallerURL, normalizeErr = resolveURL(c.manifestURL, rollback.InstallerURL); normalizeErr != nil {
			return Manifest{}, normalizeErr
		}
		if rollback.ReleaseNotesURL, normalizeErr = resolveOptionalURL(c.manifestURL, rollback.ReleaseNotesURL); normalizeErr != nil {
			return Manifest{}, normalizeErr
		}
		if rollback.SignatureURL, normalizeErr = resolveOptionalURL(c.manifestURL, rollback.SignatureURL); normalizeErr != nil {
			return Manifest{}, normalizeErr
		}
		if rollback.CertificateURL, normalizeErr = resolveOptionalURL(c.manifestURL, rollback.CertificateURL); normalizeErr != nil {
			return Manifest{}, normalizeErr
		}
		rollback.SHA256 = normalizeSHA256(rollback.SHA256)
		rollback.Reason = strings.TrimSpace(rollback.Reason)
		manifest.Rollback = &rollback
	}
	return manifest, nil
}

func resolveOptionalURL(baseURL, value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", nil
	}
	return resolveURL(baseURL, value)
}

func resolveURL(baseURL, value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", errors.New("update manifest installer url is missing")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("parse update url: %w", err)
	}
	if parsed.IsAbs() {
		return parsed.String(), nil
	}
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", fmt.Errorf("parse update manifest base url: %w", err)
	}
	return base.ResolveReference(parsed).String(), nil
}

func installerFileName(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err == nil {
		name := path.Base(parsed.Path)
		if strings.TrimSpace(name) != "" && name != "." && name != "/" {
			return name
		}
	}
	return "Ole-Setup-latest.exe"
}

func normalizeSHA256(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return ""
	}
	if len(normalized) != 64 {
		return normalized
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return normalized
	}
	return normalized
}

func fileMatchesSHA256(path, expected string) bool {
	expected = normalizeSHA256(expected)
	if expected == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	actual := sha256.Sum256(data)
	return strings.EqualFold(hex.EncodeToString(actual[:]), expected)
}
