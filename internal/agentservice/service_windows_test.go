//go:build windows

package agentservice

import (
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc/mgr"
)

func TestParseAction(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		isService bool
		want      Action
		wantErr   bool
	}{
		{name: "default console", args: nil, isService: false, want: ActionConsole},
		{name: "default service", args: nil, isService: true, want: ActionRun},
		{name: "install", args: []string{"install"}, want: ActionInstall},
		{name: "uninstall", args: []string{"uninstall"}, want: ActionUninstall},
		{name: "start", args: []string{"start"}, want: ActionStart},
		{name: "stop", args: []string{"stop"}, want: ActionStop},
		{name: "status", args: []string{"status"}, want: ActionStatus},
		{name: "service arg", args: []string{"service"}, want: ActionRun},
		{name: "unknown", args: []string{"wat"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAction(tt.args, tt.isService)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected action %v, got %v", tt.want, got)
			}
		})
	}
}

func TestBuildServiceConfig(t *testing.T) {
	settings := Settings{
		ServiceName: "OleAgent",
		DisplayName: "Ole Agent",
		Description: "Ole service",
		ListenAddr:  "127.0.0.1:5858",
	}
	cfg := buildServiceConfig(settings)
	if cfg.DisplayName != settings.DisplayName {
		t.Fatalf("expected display name %q, got %q", settings.DisplayName, cfg.DisplayName)
	}
	if cfg.Description != settings.Description {
		t.Fatalf("expected description %q, got %q", settings.Description, cfg.Description)
	}
	if cfg.StartType != mgr.StartAutomatic {
		t.Fatalf("expected automatic start, got %d", cfg.StartType)
	}
	if !cfg.DelayedAutoStart {
		t.Fatalf("expected delayed auto start to be enabled")
	}
}

func TestDefaultRecoveryActions(t *testing.T) {
	want := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
	got := defaultRecoveryActions()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected recovery actions: %#v", got)
	}
}

func TestServiceArguments(t *testing.T) {
	if got := serviceArguments(); !reflect.DeepEqual(got, []string{"service"}) {
		t.Fatalf("unexpected service arguments: %#v", got)
	}
}
