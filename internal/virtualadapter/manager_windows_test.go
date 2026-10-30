//go:build windows

package virtualadapter

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestManagerReconcileEnsuresAdapterIPAndRoute(t *testing.T) {
	runner := &fakeRunner{output: `{"mtu":1380,"interfaceMetric":25,"connectionState":"Connected","ipAddresses":[{"ipAddress":"10.55.1.2","prefixLength":24}],"routes":[{"destinationPrefix":"10.55.1.0/24","routeMetric":5}]}`}
	factory := &fakeFactory{}
	manager := &manager{
		status: Status{
			Enabled:     true,
			Available:   true,
			AdapterName: "Ole",
		},
		runner:      runner,
		factory:     factory,
		adapterName: "Ole",
		applied:     map[string]NetworkBinding{},
	}

	status, err := manager.Reconcile([]NetworkConfig{{
		NetworkID:    "net-1",
		VirtualIP:    "10.55.1.2",
		PrefixLength: 24,
		RoutePrefix:  "10.55.1.0/24",
	}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if factory.createCalls != 1 {
		t.Fatalf("expected create adapter to be called once, got %d", factory.createCalls)
	}
	if len(runner.scripts) != 6 {
		t.Fatalf("expected DNS, IP, route, forwarding, and diagnostics scripts, got %d", len(runner.scripts))
	}
	if !strings.Contains(runner.scripts[0], "Set-DnsClientServerAddress") || !strings.Contains(runner.scripts[1], "Set-DnsClient") {
		t.Fatalf("expected DNS reset scripts before IP/route reconcile, got %#v", runner.scripts)
	}
	if !strings.Contains(runner.scripts[2], "New-NetIPAddress") {
		t.Fatalf("expected IP address script, got %q", runner.scripts[2])
	}
	if !strings.Contains(runner.scripts[3], "New-NetRoute") {
		t.Fatalf("expected route script, got %q", runner.scripts[3])
	}
	if !strings.Contains(runner.scripts[4], "Forwarding Disabled") {
		t.Fatalf("expected forwarding-disable script when no full-tunnel gateway is active, got %q", runner.scripts[4])
	}
	if status.LUID == 0 {
		t.Fatalf("expected adapter LUID to be recorded")
	}
	if len(status.Networks) != 1 || status.Networks[0].VirtualIP != "10.55.1.2" {
		t.Fatalf("unexpected status networks: %#v", status.Networks)
	}
	if status.MTU != 1380 || status.InterfaceMetric != 25 || status.ConnectionState != "Connected" {
		t.Fatalf("unexpected adapter diagnostics: %+v", status)
	}
	if !status.Networks[0].IPAddressVisible || !status.Networks[0].RouteVisible || status.Networks[0].RouteMetric != 5 {
		t.Fatalf("expected enriched route visibility, got %#v", status.Networks[0])
	}
}

func TestManagerReconcileRemovesStaleRoutesAndIPs(t *testing.T) {
	runner := &fakeRunner{output: `{"mtu":1380,"interfaceMetric":25,"connectionState":"Connected","ipAddresses":[],"routes":[]}`}
	factory := &fakeFactory{openCallsAllowed: true}
	manager := &manager{
		status: Status{
			Enabled:     true,
			Available:   true,
			AdapterName: "Ole",
		},
		runner:      runner,
		factory:     factory,
		adapterName: "Ole",
		applied: map[string]NetworkBinding{
			"net-1": {NetworkID: "net-1", VirtualIP: "10.55.1.2", PrefixLength: 24, RoutePrefix: "10.55.1.0/24"},
		},
	}

	if _, err := manager.Reconcile(nil); err != nil {
		t.Fatalf("reconcile empty: %v", err)
	}
	if len(runner.scripts) != 6 {
		t.Fatalf("expected route, ip removal, dns clear, forwarding reset, and diagnostics scripts, got %d", len(runner.scripts))
	}
	if !strings.Contains(runner.scripts[0], "Remove-NetRoute") {
		t.Fatalf("expected route removal script, got %q", runner.scripts[0])
	}
	if !strings.Contains(runner.scripts[1], "Remove-NetIPAddress") {
		t.Fatalf("expected ip removal script, got %q", runner.scripts[1])
	}
	if !strings.Contains(runner.scripts[2], "Forwarding Disabled") {
		t.Fatalf("expected forwarding-disable script after clearing gateway state, got %#v", runner.scripts)
	}
	if !strings.Contains(runner.scripts[3], "Set-DnsClientServerAddress") || !strings.Contains(runner.scripts[4], "Set-DnsClient") {
		t.Fatalf("expected DNS clear scripts after removing routes and IPs, got %#v", runner.scripts)
	}
}

func TestManagerReconcileSurfacesCommandErrors(t *testing.T) {
	manager := &manager{
		status: Status{
			Enabled:     true,
			Available:   true,
			AdapterName: "Ole",
		},
		runner:      &fakeRunner{err: errors.New("boom")},
		factory:     &fakeFactory{openCallsAllowed: true},
		adapterName: "Ole",
		applied:     map[string]NetworkBinding{},
	}

	status, err := manager.Reconcile([]NetworkConfig{{
		NetworkID:    "net-1",
		VirtualIP:    "10.55.1.2",
		PrefixLength: 24,
		RoutePrefix:  "10.55.1.0/24",
	}})
	if err == nil {
		t.Fatalf("expected reconcile error")
	}
	if !strings.Contains(status.LastError, "boom") {
		t.Fatalf("expected last error to mention command failure, got %q", status.LastError)
	}
}

func TestManagerReconcileRefreshesAdapterDiagnostics(t *testing.T) {
	manager := &manager{
		status: Status{
			Enabled:     true,
			Available:   true,
			AdapterName: "Ole",
		},
		runner: &fakeRunner{
			output: `{"mtu":1420,"interfaceMetric":15,"connectionState":"Connected","ipAddresses":[{"ipAddress":"10.77.1.2","prefixLength":24}],"routes":[{"destinationPrefix":"10.77.1.0/24","routeMetric":7}]}`,
		},
		factory:     &fakeFactory{openCallsAllowed: true},
		adapterName: "Ole",
		applied:     map[string]NetworkBinding{},
	}

	status, err := manager.Reconcile([]NetworkConfig{{
		NetworkID:    "net-77",
		VirtualIP:    "10.77.1.2",
		PrefixLength: 24,
		RoutePrefix:  "10.77.1.0/24",
	}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if status.MTU != 1420 || status.InterfaceMetric != 15 || status.ConnectionState != "Connected" {
		t.Fatalf("unexpected adapter diagnostics: %+v", status)
	}
	if len(status.Networks) != 1 {
		t.Fatalf("expected one binding, got %#v", status.Networks)
	}
	if !status.Networks[0].IPAddressVisible || !status.Networks[0].RouteVisible || status.Networks[0].RouteMetric != 7 {
		t.Fatalf("expected route visibility in diagnostics, got %#v", status.Networks[0])
	}
}

func TestManagerReconcileAppliesConfiguredMTU(t *testing.T) {
	runner := &fakeRunner{output: `{"mtu":1360,"interfaceMetric":25,"connectionState":"Connected","ipAddresses":[{"ipAddress":"10.55.1.2","prefixLength":24}],"routes":[{"destinationPrefix":"10.55.1.0/24","routeMetric":5}]}`}
	manager := &manager{
		status: Status{
			Enabled:     true,
			Available:   true,
			AdapterName: "Ole",
		},
		runner:      runner,
		factory:     &fakeFactory{openCallsAllowed: true},
		adapterName: "Ole",
		applied:     map[string]NetworkBinding{},
	}

	status, err := manager.Reconcile([]NetworkConfig{{
		NetworkID:    "net-1",
		VirtualIP:    "10.55.1.2",
		PrefixLength: 24,
		RoutePrefix:  "10.55.1.0/24",
		MTU:          1360,
	}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if status.DesiredMTU != 1360 || status.MTU != 1360 {
		t.Fatalf("expected desired and observed MTU to be 1360, got %+v", status)
	}
	if len(runner.scripts) < 4 || !strings.Contains(runner.scripts[0], "Set-NetIPInterface") || !strings.Contains(runner.scripts[0], "1360") {
		t.Fatalf("expected MTU script before IP/route reconcile, got %#v", runner.scripts)
	}
}

func TestManagerReconcileRejectsConflictingMTUSettings(t *testing.T) {
	manager := &manager{
		status: Status{
			Enabled:     true,
			Available:   true,
			AdapterName: "Ole",
		},
		runner:      &fakeRunner{},
		factory:     &fakeFactory{openCallsAllowed: true},
		adapterName: "Ole",
		applied:     map[string]NetworkBinding{},
	}

	_, err := manager.Reconcile([]NetworkConfig{
		{NetworkID: "net-1", VirtualIP: "10.55.1.2", PrefixLength: 24, RoutePrefix: "10.55.1.0/24", MTU: 1360},
		{NetworkID: "net-2", VirtualIP: "10.66.1.2", PrefixLength: 24, RoutePrefix: "10.66.1.0/24", MTU: 1420},
	})
	if err == nil || !strings.Contains(err.Error(), "agree on adapter MTU") {
		t.Fatalf("expected conflicting MTU error, got %v", err)
	}
}

func TestManagerReconcileSuppressesOverlappingRoutes(t *testing.T) {
	runner := &fakeRunner{output: `{"mtu":1380,"interfaceMetric":25,"connectionState":"Connected","ipAddresses":[],"routes":[]}`}
	manager := &manager{
		status: Status{
			Enabled:     true,
			Available:   true,
			AdapterName: "Ole",
		},
		runner:      runner,
		factory:     &fakeFactory{openCallsAllowed: true},
		adapterName: "Ole",
		applied:     map[string]NetworkBinding{},
	}

	status, err := manager.Reconcile([]NetworkConfig{
		{NetworkID: "net-1", VirtualIP: "10.55.1.2", PrefixLength: 24, RoutePrefix: "10.55.1.0/24"},
		{NetworkID: "net-2", VirtualIP: "10.55.2.2", PrefixLength: 24, RoutePrefix: "10.55.0.0/16"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !strings.Contains(status.LastError, "overlapping overlay routes suppressed") {
		t.Fatalf("expected overlap warning in status, got %+v", status)
	}
	if len(status.Networks) != 1 || status.Networks[0].NetworkID != "net-1" {
		t.Fatalf("expected only the first non-conflicting network to remain applied, got %#v", status.Networks)
	}
	if len(runner.scripts) != 6 {
		t.Fatalf("expected scripts only for one applied network plus forwarding reset and diagnostics, got %d", len(runner.scripts))
	}
}

func TestManagerReconcileKeepsOverlayRoutesAlongsideFullTunnelSplitDefaults(t *testing.T) {
	runner := &fakeRunner{output: `{"mtu":1380,"interfaceMetric":25,"connectionState":"Connected","ipAddresses":[{"ipAddress":"10.55.1.2","prefixLength":24},{"ipAddress":"10.66.0.2","prefixLength":24}],"routes":[{"destinationPrefix":"0.0.0.0/1","routeMetric":5},{"destinationPrefix":"128.0.0.0/1","routeMetric":5},{"destinationPrefix":"10.66.0.0/24","routeMetric":5}]}`}
	manager := &manager{
		status: Status{
			Enabled:     true,
			Available:   true,
			AdapterName: "Ole",
		},
		runner:      runner,
		factory:     &fakeFactory{openCallsAllowed: true},
		adapterName: "Ole",
		applied:     map[string]NetworkBinding{},
	}

	status, err := manager.Reconcile([]NetworkConfig{
		{
			NetworkID:     "net-full",
			VirtualIP:     "10.55.1.2",
			PrefixLength:  24,
			RoutePrefix:   "0.0.0.0/0",
			RoutingPolicy: "FULL",
			GatewayRole:   "CLIENT",
			GatewayPeerID: "peer-owner",
		},
		{
			NetworkID:     "net-split",
			VirtualIP:     "10.66.0.2",
			PrefixLength:  24,
			RoutePrefix:   "10.66.0.0/24",
			RoutingPolicy: "SPLIT",
		},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if strings.Contains(status.LastError, "overlapping overlay routes suppressed") {
		t.Fatalf("expected full-tunnel split defaults to coexist with overlay routes, got %+v", status)
	}
	if len(status.Networks) != 2 {
		t.Fatalf("expected both full-tunnel and overlay networks to remain applied, got %#v", status.Networks)
	}
	if len(runner.scripts) < 9 {
		t.Fatalf("expected scripts for both networks plus split-default installation, got %#v", runner.scripts)
	}
	joined := strings.Join(runner.scripts, "\n")
	if !strings.Contains(joined, "DestinationPrefix '0.0.0.0/1'") || !strings.Contains(joined, "DestinationPrefix '128.0.0.0/1'") {
		t.Fatalf("expected split default routes for full-tunnel client, got %#v", runner.scripts)
	}
	if !strings.Contains(joined, "DestinationPrefix '10.66.0.0/24'") {
		t.Fatalf("expected overlay route to remain installed beside full-tunnel split defaults, got %#v", runner.scripts)
	}
}

func TestManagerReconcileSurfacesFullTunnelFoundationStatus(t *testing.T) {
	runner := &fakeRunner{output: `{"mtu":1380,"interfaceMetric":25,"connectionState":"Connected","ipAddresses":[{"ipAddress":"10.55.1.2","prefixLength":24}],"routes":[{"destinationPrefix":"10.55.1.0/24","routeMetric":5}]}`}
	manager := &manager{
		status: Status{
			Enabled:     true,
			Available:   true,
			AdapterName: "Ole",
		},
		runner:      runner,
		factory:     &fakeFactory{openCallsAllowed: true},
		adapterName: "Ole",
		applied:     map[string]NetworkBinding{},
	}

	status, err := manager.Reconcile([]NetworkConfig{{
		NetworkID:     "net-1",
		VirtualIP:     "10.55.1.2",
		PrefixLength:  24,
		RoutePrefix:   "10.55.1.0/24",
		RoutingPolicy: "FULL",
	}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(status.Networks) != 1 || status.Networks[0].RoutingPolicy != "FULL" || status.Networks[0].PolicyStatus != "PENDING_GATEWAY" {
		t.Fatalf("expected full-tunnel foundation policy status, got %#v", status.Networks)
	}
	if !strings.Contains(status.LastError, "gateway dataplane activation is still pending") {
		t.Fatalf("expected full-tunnel foundation warning, got %+v", status)
	}
}

func TestManagerReconcileActivatesFullTunnelClientDefaultRoute(t *testing.T) {
	runner := &fakeRunner{output: `{"mtu":1380,"interfaceMetric":25,"connectionState":"Connected","ipAddresses":[{"ipAddress":"10.55.1.2","prefixLength":24}],"routes":[{"destinationPrefix":"0.0.0.0/1","routeMetric":5},{"destinationPrefix":"128.0.0.0/1","routeMetric":5}]}`}
	manager := &manager{
		status: Status{
			Enabled:     true,
			Available:   true,
			AdapterName: "Ole",
		},
		runner:      runner,
		factory:     &fakeFactory{openCallsAllowed: true},
		adapterName: "Ole",
		applied:     map[string]NetworkBinding{},
	}

	status, err := manager.Reconcile([]NetworkConfig{{
		NetworkID:     "net-1",
		VirtualIP:     "10.55.1.2",
		PrefixLength:  24,
		OverlayCIDR:   "10.55.1.0/24",
		RoutePrefix:   "0.0.0.0/0",
		RoutingPolicy: "FULL",
		GatewayRole:   "CLIENT",
		GatewayPeerID: "peer-owner",
	}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(status.Networks) != 1 || status.Networks[0].PolicyStatus != "ACTIVE" || status.Networks[0].GatewayRole != "CLIENT" {
		t.Fatalf("expected active client full-tunnel policy status, got %#v", status.Networks)
	}
	if status.LastError != "" {
		t.Fatalf("expected no pending-gateway warning once client dataplane is active, got %+v", status)
	}
	if len(runner.scripts) < 6 {
		t.Fatalf("expected split default-route scripts for full-tunnel client, got %#v", runner.scripts)
	}
	if !strings.Contains(runner.scripts[3], "DestinationPrefix '0.0.0.0/1'") || !strings.Contains(runner.scripts[4], "DestinationPrefix '128.0.0.0/1'") {
		t.Fatalf("expected split default routes to be installed for full-tunnel client, got %#v", runner.scripts)
	}
}

func TestManagerReconcileKeepsSecondaryFullTunnelClientOnStandby(t *testing.T) {
	runner := &fakeRunner{output: `{"mtu":1380,"interfaceMetric":25,"connectionState":"Connected","ipAddresses":[{"ipAddress":"10.55.2.2","prefixLength":24}],"routes":[{"destinationPrefix":"10.55.2.0/24","routeMetric":5}]}`}
	manager := &manager{
		status: Status{
			Enabled:     true,
			Available:   true,
			AdapterName: "Ole",
		},
		runner:      runner,
		factory:     &fakeFactory{openCallsAllowed: true},
		adapterName: "Ole",
		applied:     map[string]NetworkBinding{},
	}

	status, err := manager.Reconcile([]NetworkConfig{{
		NetworkID:        "net-2",
		VirtualIP:        "10.55.2.2",
		PrefixLength:     24,
		OverlayCIDR:      "10.55.2.0/24",
		RoutePrefix:      "10.55.2.0/24",
		RoutingPolicy:    "FULL",
		PolicyStatusHint: "STANDBY_GATEWAY",
		GatewayRole:      "CLIENT",
		GatewayPeerID:    "peer-owner",
	}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(status.Networks) != 1 || status.Networks[0].PolicyStatus != "STANDBY_GATEWAY" || status.Networks[0].GatewayRole != "CLIENT" {
		t.Fatalf("expected standby full-tunnel client policy status, got %#v", status.Networks)
	}
	if status.LastError != "" {
		t.Fatalf("expected standby gateway state to avoid adapter warnings, got %+v", status)
	}
	if !strings.Contains(runner.scripts[3], "DestinationPrefix '10.55.2.0/24'") {
		t.Fatalf("expected standby full-tunnel client to keep overlay route instead of default route, got %#v", runner.scripts)
	}
}

func TestManagerReconcileRemovesSplitDefaultRoutesForFullTunnelClient(t *testing.T) {
	runner := &fakeRunner{output: `{"mtu":1380,"interfaceMetric":25,"connectionState":"Connected","ipAddresses":[],"routes":[]}`}
	manager := &manager{
		status: Status{
			Enabled:     true,
			Available:   true,
			AdapterName: "Ole",
		},
		runner:      runner,
		factory:     &fakeFactory{openCallsAllowed: true},
		adapterName: "Ole",
		applied: map[string]NetworkBinding{
			"net-1": {
				NetworkID:     "net-1",
				VirtualIP:     "10.55.1.2",
				PrefixLength:  24,
				OverlayCIDR:   "10.55.1.0/24",
				RoutePrefix:   "0.0.0.0/0",
				RoutingPolicy: "FULL",
				GatewayRole:   "CLIENT",
				GatewayPeerID: "peer-owner",
			},
		},
	}

	if _, err := manager.Reconcile(nil); err != nil {
		t.Fatalf("reconcile empty: %v", err)
	}
	if len(runner.scripts) < 7 {
		t.Fatalf("expected split default-route removals plus cleanup scripts, got %#v", runner.scripts)
	}
	if !strings.Contains(runner.scripts[0], "DestinationPrefix '0.0.0.0/1'") || !strings.Contains(runner.scripts[1], "DestinationPrefix '128.0.0.0/1'") {
		t.Fatalf("expected split default routes to be removed for stale full-tunnel client, got %#v", runner.scripts)
	}
}

func TestManagerReconcileDemotesFullTunnelClientToStandbyAndRemovesSplitDefaultRoutes(t *testing.T) {
	runner := &fakeRunner{output: `{"mtu":1380,"interfaceMetric":25,"connectionState":"Connected","ipAddresses":[{"ipAddress":"10.55.1.2","prefixLength":24}],"routes":[{"destinationPrefix":"10.55.1.0/24","routeMetric":5}]}`}
	manager := &manager{
		status: Status{
			Enabled:     true,
			Available:   true,
			AdapterName: "Ole",
		},
		runner:      runner,
		factory:     &fakeFactory{openCallsAllowed: true},
		adapterName: "Ole",
		applied: map[string]NetworkBinding{
			"net-1": {
				NetworkID:     "net-1",
				VirtualIP:     "10.55.1.2",
				PrefixLength:  24,
				OverlayCIDR:   "10.55.1.0/24",
				RoutePrefix:   "0.0.0.0/0",
				RoutingPolicy: "FULL",
				GatewayRole:   "CLIENT",
				GatewayPeerID: "peer-owner",
			},
		},
	}

	status, err := manager.Reconcile([]NetworkConfig{{
		NetworkID:        "net-1",
		VirtualIP:        "10.55.1.2",
		PrefixLength:     24,
		OverlayCIDR:      "10.55.1.0/24",
		RoutePrefix:      "10.55.1.0/24",
		RoutingPolicy:    "FULL",
		PolicyStatusHint: "STANDBY_GATEWAY",
		GatewayRole:      "CLIENT",
		GatewayPeerID:    "peer-owner",
	}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(status.Networks) != 1 || status.Networks[0].PolicyStatus != "STANDBY_GATEWAY" || status.Networks[0].RoutePrefix != "10.55.1.0/24" {
		t.Fatalf("expected standby full-tunnel client policy status after demotion, got %#v", status.Networks)
	}
	if len(runner.scripts) < 8 {
		t.Fatalf("expected split default-route removals plus overlay reconcile scripts, got %#v", runner.scripts)
	}
	if !strings.Contains(runner.scripts[2], "DestinationPrefix '0.0.0.0/1'") || !strings.Contains(runner.scripts[3], "DestinationPrefix '128.0.0.0/1'") {
		t.Fatalf("expected stale split default routes to be removed before standby reconcile, got %#v", runner.scripts)
	}
	if !strings.Contains(runner.scripts[5], "DestinationPrefix '10.55.1.0/24'") {
		t.Fatalf("expected standby overlay route to be installed after removing split defaults, got %#v", runner.scripts)
	}
}

func TestManagerReconcileActivatesFullTunnelGatewayDataplane(t *testing.T) {
	runner := &fakeRunner{output: `{"mtu":1380,"interfaceMetric":25,"connectionState":"Connected","ipAddresses":[{"ipAddress":"10.55.1.2","prefixLength":24}],"routes":[{"destinationPrefix":"10.55.1.0/24","routeMetric":5}]}`}
	manager := &manager{
		status: Status{
			Enabled:     true,
			Available:   true,
			AdapterName: "Ole",
		},
		runner:      runner,
		factory:     &fakeFactory{openCallsAllowed: true},
		adapterName: "Ole",
		applied:     map[string]NetworkBinding{},
	}

	status, err := manager.Reconcile([]NetworkConfig{{
		NetworkID:     "net-1",
		VirtualIP:     "10.55.1.2",
		PrefixLength:  24,
		OverlayCIDR:   "10.55.1.0/24",
		RoutePrefix:   "10.55.1.0/24",
		RoutingPolicy: "FULL",
		GatewayRole:   "GATEWAY",
	}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(status.Networks) != 1 || status.Networks[0].PolicyStatus != "ACTIVE" || status.Networks[0].GatewayRole != "GATEWAY" {
		t.Fatalf("expected active gateway full-tunnel policy status, got %#v", status.Networks)
	}
	if status.LastError != "" {
		t.Fatalf("expected no pending-gateway warning once gateway dataplane is active, got %+v", status)
	}
	if len(runner.scripts) < 7 {
		t.Fatalf("expected gateway forwarding and NAT scripts to run, got %#v", runner.scripts)
	}
	if !strings.Contains(runner.scripts[4], "Forwarding Enabled") {
		t.Fatalf("expected ipv4 forwarding enable script, got %#v", runner.scripts)
	}
	if !strings.Contains(runner.scripts[5], "New-NetNat") {
		t.Fatalf("expected gateway NAT script, got %#v", runner.scripts)
	}
}

func TestManagerReconcileAppliesDNSSettings(t *testing.T) {
	runner := &fakeRunner{output: `{"mtu":1360,"interfaceMetric":25,"connectionState":"Connected","dnsServers":["127.0.0.1"],"dnsSuffix":"ole","ipAddresses":[{"ipAddress":"10.55.1.2","prefixLength":24}],"routes":[{"destinationPrefix":"10.55.1.0/24","routeMetric":5}]}`}
	manager := &manager{
		status: Status{
			Enabled:     true,
			Available:   true,
			AdapterName: "Ole",
		},
		runner:      runner,
		factory:     &fakeFactory{openCallsAllowed: true},
		adapterName: "Ole",
		applied:     map[string]NetworkBinding{},
	}

	status, err := manager.Reconcile([]NetworkConfig{{
		NetworkID:    "net-1",
		VirtualIP:    "10.55.1.2",
		PrefixLength: 24,
		RoutePrefix:  "10.55.1.0/24",
		DNSServer:    "127.0.0.1",
		DNSSuffix:    "ole",
	}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if status.DesiredDNSServer != "127.0.0.1" || status.DNSSuffix != "ole" || len(status.DNSServers) != 1 || status.DNSServers[0] != "127.0.0.1" {
		t.Fatalf("unexpected dns diagnostics: %+v", status)
	}
	if len(runner.scripts) < 5 || !strings.Contains(runner.scripts[0], "Set-DnsClientServerAddress") || !strings.Contains(runner.scripts[1], "Set-DnsClient") {
		t.Fatalf("expected dns scripts ahead of IP/route reconcile, got %#v", runner.scripts)
	}
}

func TestManagerPacketIOReadsAndWritesWintunSessionPackets(t *testing.T) {
	session := &fakePacketSession{
		receiveQueue: [][]byte{{1, 2, 3, 4}},
	}
	manager := &manager{
		status: Status{
			Enabled:     true,
			Available:   true,
			AdapterName: "Ole",
		},
		runner:      &fakeRunner{},
		factory:     &fakeFactory{openCallsAllowed: true, session: session},
		adapterName: "Ole",
		applied:     map[string]NetworkBinding{},
	}

	packets, err := manager.ReadPackets(2)
	if err != nil {
		t.Fatalf("read packets: %v", err)
	}
	if len(packets) != 1 || len(packets[0].Data) != 4 {
		t.Fatalf("expected one packet from fake session, got %#v", packets)
	}

	if err := manager.WritePackets([]Packet{{Data: []byte{9, 8, 7}}}); err != nil {
		t.Fatalf("write packets: %v", err)
	}
	if len(session.sentPackets) != 1 || len(session.sentPackets[0]) != 3 {
		t.Fatalf("expected one sent packet to be captured, got %#v", session.sentPackets)
	}
}

type fakeRunner struct {
	scripts   []string
	err       error
	output    string
	outputErr error
}

func (r *fakeRunner) Run(script string) error {
	r.scripts = append(r.scripts, script)
	return r.err
}

func (r *fakeRunner) Output(script string) (string, error) {
	r.scripts = append(r.scripts, script)
	if r.outputErr != nil {
		return "", r.outputErr
	}
	return r.output, nil
}

type fakeFactory struct {
	createCalls      int
	openCallsAllowed bool
	session          *fakePacketSession
}

func (f *fakeFactory) Open(_ string) (wintunAdapter, error) {
	if f.openCallsAllowed {
		return fakeAdapter{session: f.session}, nil
	}
	return nil, errors.New("not found")
}

func (f *fakeFactory) Create(_ string) (wintunAdapter, error) {
	f.createCalls++
	return fakeAdapter{session: f.session}, nil
}

func (f *fakeFactory) DriverVersion() string {
	return "0.14"
}

type fakeAdapter struct {
	session *fakePacketSession
}

func (fakeAdapter) LUID() uint64 {
	return 42
}

func (a fakeAdapter) StartSession(_ uint32) (packetSession, error) {
	if a.session == nil {
		a.session = &fakePacketSession{}
	}
	return a.session, nil
}

func (fakeAdapter) Close() error {
	return nil
}

type fakePacketSession struct {
	receiveQueue [][]byte
	sentPackets  [][]byte
}

func (s *fakePacketSession) End() {}

func (s *fakePacketSession) ReceivePacket() ([]byte, error) {
	if len(s.receiveQueue) == 0 {
		return nil, windows.ERROR_NO_MORE_ITEMS
	}
	packet := append([]byte(nil), s.receiveQueue[0]...)
	s.receiveQueue = s.receiveQueue[1:]
	return packet, nil
}

func (s *fakePacketSession) ReleaseReceivePacket(_ []byte) {}

func (s *fakePacketSession) AllocateSendPacket(packetSize int) ([]byte, error) {
	return make([]byte, packetSize), nil
}

func (s *fakePacketSession) SendPacket(packet []byte) {
	s.sentPackets = append(s.sentPackets, append([]byte(nil), packet...))
}
