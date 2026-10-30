//go:build windows

package clientgui

import (
	"errors"
	"strings"
	"testing"
)

func TestFormatGUIErrorForLocaleLocalizesAgentUnreachableInRussian(t *testing.T) {
	message := formatGUIErrorForLocale(errors.New("Get \"http://127.0.0.1:5858/api/v1/status\": dial tcp 127.0.0.1:5858: connectex: No connection could be made because the target machine actively refused it."), "ru")
	if message.Title != "Ole Agent недоступен" {
		t.Fatalf("expected localized agent title, got %q", message.Title)
	}
	assertContains(t, message.Message, "Локальный Ole Agent не отвечает.")
	assertContains(t, message.Message, "Запустите `cmd/agent` или Windows service.")
}

func TestFormatGUIErrorForLocaleMapsInvalidCredentialsInEnglish(t *testing.T) {
	message := formatGUIErrorForLocale(errors.New("invalid credentials"), "en")
	if message.Title != "Sign-In Failed" {
		t.Fatalf("expected invalid-credentials title, got %q", message.Title)
	}
	assertContains(t, message.Message, "email or password did not match")
	assertContains(t, message.Message, "try `Reconnect`")
}

func TestFormatGUIErrorForLocaleMapsCompatibilityBlockInRussian(t *testing.T) {
	message := formatGUIErrorForLocale(errors.New("client is older than the minimum supported version"), "ru")
	if message.Title != "Нужна более новая версия клиента" {
		t.Fatalf("expected compatibility title, got %q", message.Title)
	}
	assertContains(t, message.Message, "требует более новую версию Ole Desktop")
	assertContains(t, message.Message, "Обновите клиент")
}

func TestFormatGUIErrorForLocaleFallsBackWithTechnicalDetail(t *testing.T) {
	message := formatGUIErrorForLocale(errors.New("something unexpected happened"), "en")
	if message.Title != "Ole Error" {
		t.Fatalf("expected generic title, got %q", message.Title)
	}
	assertContains(t, message.Message, "Ole could not complete this action.")
	assertContains(t, message.Message, "Technical detail:")
	assertContains(t, message.Message, "something unexpected happened")
}

func TestDetectGUILocalePrefersRussianEnvironment(t *testing.T) {
	t.Setenv("OLE_GUI_LOCALE", "")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "ru_RU.UTF-8")
	if locale := detectGUILocale(); locale != "ru" {
		t.Fatalf("expected ru locale, got %q", locale)
	}
}

func TestDetectGUILocaleDefaultsToEnglish(t *testing.T) {
	t.Setenv("OLE_GUI_LOCALE", "")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "")
	if locale := detectGUILocale(); locale != "en" {
		t.Fatalf("expected en locale, got %q", locale)
	}
}

func TestFormatGUIErrorForLocaleMapsSelectionGuidance(t *testing.T) {
	message := formatGUIErrorForLocale(errors.New("select a network first"), "ru")
	if !strings.Contains(message.Title, "сеть") && !strings.Contains(message.Title, "Сеть") {
		t.Fatalf("expected network-selection title, got %q", message.Title)
	}
	assertContains(t, message.Message, "выберите сеть")
	assertContains(t, message.Message, "Networks")
}

func TestFormatGUIErrorForLocaleMapsFingerprintUnavailable(t *testing.T) {
	message := formatGUIErrorForLocale(errors.New("device fingerprint is not available"), "en")
	if message.Title != "Fingerprint Unavailable" {
		t.Fatalf("expected fingerprint title, got %q", message.Title)
	}
	assertContains(t, message.Message, "does not currently have a fingerprint")
}

func TestFormatGUIErrorForLocaleMapsDeviceApprovalRequired(t *testing.T) {
	message := formatGUIErrorForLocale(errors.New("device approval required"), "en")
	if message.Title != "Device Approval Required" {
		t.Fatalf("expected device-approval title, got %q", message.Title)
	}
	assertContains(t, message.Message, "Approve For Network")
}

func TestFormatGUIErrorForLocaleMapsUnsupportedRoutingPolicy(t *testing.T) {
	message := formatGUIErrorForLocale(errors.New("unsupported routing policy \"sideways\""), "en")
	if message.Title != "Unsupported Routing Policy" {
		t.Fatalf("expected routing-policy title, got %q", message.Title)
	}
	assertContains(t, message.Message, "Use `SPLIT` or `FULL`.")
}

func TestFormatGUIErrorForLocaleMapsMissingUpdateManifest(t *testing.T) {
	message := formatGUIErrorForLocale(errors.New("update manifest url is not configured"), "en")
	if message.Title != "Auto-Update Not Configured" {
		t.Fatalf("expected update-manifest title, got %q", message.Title)
	}
	assertContains(t, message.Message, "OLE_UPDATE_MANIFEST_URL")
}

func TestFormatGUIErrorForLocaleMapsMissingDownloadedUpdate(t *testing.T) {
	message := formatGUIErrorForLocale(errors.New("no downloaded update is available to install"), "en")
	if message.Title != "Download The Update First" {
		t.Fatalf("expected download-first title, got %q", message.Title)
	}
	assertContains(t, message.Message, "Download Update")
}

func TestFormatGUIErrorForLocaleMapsUnavailableUpdateChannel(t *testing.T) {
	message := formatGUIErrorForLocale(errors.New("update channel beta is not configured"), "en")
	if message.Title != "Update Channel Unavailable" {
		t.Fatalf("expected update-channel title, got %q", message.Title)
	}
	assertContains(t, message.Message, "OLE_UPDATE_BETA_MANIFEST_URL")
}

func TestFormatGUIErrorForLocaleMapsRollbackUnavailable(t *testing.T) {
	message := formatGUIErrorForLocale(errors.New("no rollback release is available"), "en")
	if message.Title != "Rollback Unavailable" {
		t.Fatalf("expected rollback title, got %q", message.Title)
	}
	assertContains(t, message.Message, "switch to another update channel")
}

func TestFormatGUIErrorForLocaleMapsUpdateCompatibilityPolicy(t *testing.T) {
	message := formatGUIErrorForLocale(errors.New("server 1.3.0 is above the maximum supported version 1.2.0 for this update"), "en")
	if message.Title != "Update Blocked By Policy" {
		t.Fatalf("expected update-policy title, got %q", message.Title)
	}
	assertContains(t, message.Message, "current server version")
	assertContains(t, message.Message, "rollback build")
}
