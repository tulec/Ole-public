package versioninfo

import "testing"

func TestEvaluateRejectsTooOldClient(t *testing.T) {
	result := Evaluate("0.0.9", ServerMetadata{
		ServerVersion:    "0.1.0",
		MinClientVersion: "0.1.0",
	})
	if result.Compatible {
		t.Fatalf("expected incompatible result, got %#v", result)
	}
	if result.Status != StatusUpgradeRequired {
		t.Fatalf("expected upgrade required, got %q", result.Status)
	}
}

func TestEvaluateWarnsOnMinorMismatch(t *testing.T) {
	result := Evaluate("0.2.0", ServerMetadata{
		ServerVersion:    "0.1.0",
		MinClientVersion: "0.1.0",
	})
	if !result.Compatible {
		t.Fatalf("expected warning compatibility, got %#v", result)
	}
	if result.Status != StatusWarning {
		t.Fatalf("expected warning status, got %q", result.Status)
	}
}

func TestCompareSupportsShortVersions(t *testing.T) {
	cmp, err := Compare("1.2", "1.2.0")
	if err != nil {
		t.Fatalf("compare versions: %v", err)
	}
	if cmp != 0 {
		t.Fatalf("expected equal comparison, got %d", cmp)
	}
}
