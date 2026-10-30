//go:build windows

package virtualadapter

import (
	"Ole/internal/transportauth"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const (
	defaultAdapterName = "Ole"
	defaultPrefixLen   = 24
	defaultRouteMetric = 5
	defaultIPv4Route   = "0.0.0.0/0"
	defaultRingSize    = wintun.RingCapacityMin
	minAdapterMTU      = 576
	maxAdapterMTU      = transportauth.MaxMessageBytes
)

type powerShellRunner interface {
	Run(script string) error
	Output(script string) (string, error)
}

type wintunAdapter interface {
	LUID() uint64
	StartSession(capacity uint32) (packetSession, error)
	Close() error
}

type packetSession interface {
	End()
	ReceivePacket() ([]byte, error)
	ReleaseReceivePacket(packet []byte)
	AllocateSendPacket(packetSize int) ([]byte, error)
	SendPacket(packet []byte)
}

type adapterFactory interface {
	Open(name string) (wintunAdapter, error)
	Create(name string) (wintunAdapter, error)
	DriverVersion() string
}

type manager struct {
	mu          sync.Mutex
	status      Status
	runner      powerShellRunner
	factory     adapterFactory
	required    bool
	adapterName string
	applied     map[string]NetworkBinding
	adapter     wintunAdapter
	session     packetSession
}

type adapterDiagnostics struct {
	MTU             int      `json:"mtu"`
	InterfaceMetric int      `json:"interfaceMetric"`
	ConnectionState string   `json:"connectionState"`
	DNSServers      []string `json:"dnsServers"`
	DNSSuffix       string   `json:"dnsSuffix"`
	IPAddresses     []struct {
		IPAddress    string `json:"ipAddress"`
		PrefixLength int    `json:"prefixLength"`
	} `json:"ipAddresses"`
	Routes []struct {
		DestinationPrefix string `json:"destinationPrefix"`
		RouteMetric       int    `json:"routeMetric"`
	} `json:"routes"`
}

type shellRunner struct{}

type realAdapter struct {
	inner *wintun.Adapter
}

type realSession struct {
	inner wintun.Session
}

type realFactory struct{}

func NewDefaultManager() Manager {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("OLE_WINTUN_ENABLED")))
	required := mode == "true"
	if mode == "false" {
		return &noopManager{
			status: Status{
				Enabled:     false,
				Available:   false,
				AdapterName: resolveAdapterName(),
				LastError:   "wintun disabled by OLE_WINTUN_ENABLED=false",
			},
		}
	}

	if !wintunDLLAvailable() {
		status := Status{
			Enabled:     required,
			Available:   false,
			AdapterName: resolveAdapterName(),
			LastError:   "wintun.dll not found in the application directory or System32",
		}
		if required {
			return &manager{
				status:      status,
				required:    true,
				adapterName: status.AdapterName,
				applied:     map[string]NetworkBinding{},
				runner:      shellRunner{},
				factory:     realFactory{},
			}
		}
		return &noopManager{status: status}
	}

	return &manager{
		status: Status{
			Enabled:     true,
			Available:   true,
			AdapterName: resolveAdapterName(),
		},
		runner:      shellRunner{},
		factory:     realFactory{},
		required:    required,
		adapterName: resolveAdapterName(),
		applied:     map[string]NetworkBinding{},
	}
}

func (m *manager) Reconcile(desired []NetworkConfig) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	desiredMTU, err := desiredMTUFromConfigs(desired)
	if err != nil {
		return m.failLocked(err)
	}
	desiredDNSServer, desiredDNSSuffix, err := desiredDNSSettingsFromConfigs(desired)
	if err != nil {
		return m.failLocked(err)
	}
	bindings := make(map[string]NetworkBinding, len(desired))
	for _, network := range desired {
		binding, err := normalizeNetwork(network)
		if err != nil {
			return m.failLocked(err)
		}
		bindings[binding.NetworkID] = binding
	}
	activeBindings, overlapWarning := suppressOverlappingBindings(bindings)

	if len(activeBindings) == 0 {
		for _, binding := range m.applied {
			if err := m.removeNetworkLocked(binding); err != nil {
				return m.failLocked(err)
			}
		}
		if err := m.reconcileGatewayDataplaneLocked(nil); err != nil {
			return m.failLocked(err)
		}
		m.applied = map[string]NetworkBinding{}
		m.status.Networks = nil
		m.status.DesiredMTU = desiredMTU
		m.status.DesiredDNSServer = ""
		m.status.DNSSuffix = ""
		m.status.DNSServers = nil
		if err := m.clearDNSLocked(); err != nil {
			return m.failLocked(err)
		}
		m.status.SessionActive = m.session != nil
		_ = m.refreshDiagnosticsLocked()
		m.status.LastError = combineWarnings(overlapWarning, fullTunnelPolicyWarning(activeBindings))
		return m.status, nil
	}

	adapter, created, err := m.ensureAdapterLocked()
	if err != nil {
		return m.failLocked(err)
	}
	if adapter != nil {
		m.status.Available = true
		m.status.Enabled = true
		m.status.LUID = adapter.LUID()
		m.status.DriverVersion = m.factory.DriverVersion()
		if created {
			m.status.LastError = ""
		}
	}
	m.status.DesiredMTU = desiredMTU
	m.status.DesiredDNSServer = desiredDNSServer
	if desiredMTU > 0 {
		if err := m.runner.Run(ensureMTUScript(m.adapterName, desiredMTU)); err != nil {
			return m.failLocked(fmt.Errorf("ensure adapter MTU: %w", err))
		}
	}
	if err := m.ensureDNSLocked(desiredDNSServer, desiredDNSSuffix); err != nil {
		return m.failLocked(err)
	}

	for networkID, oldBinding := range m.applied {
		if _, ok := activeBindings[networkID]; !ok {
			if err := m.removeNetworkLocked(oldBinding); err != nil {
				return m.failLocked(err)
			}
		}
	}
	for networkID, binding := range activeBindings {
		if oldBinding, ok := m.applied[networkID]; ok {
			if err := m.removeStaleNetworkStateLocked(oldBinding, binding); err != nil {
				return m.failLocked(err)
			}
		}
		if err := m.ensureNetworkLocked(binding); err != nil {
			return m.failLocked(err)
		}
	}
	if err := m.reconcileGatewayDataplaneLocked(activeBindings); err != nil {
		return m.failLocked(err)
	}

	m.applied = activeBindings
	m.status.Networks = bindingsSlice(activeBindings)
	m.status.SessionActive = m.session != nil
	_ = m.refreshDiagnosticsLocked()
	m.status.LastError = combineWarnings(overlapWarning, fullTunnelPolicyWarning(activeBindings))
	return m.status, nil
}

func (m *manager) Snapshot() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	snapshot := cloneStatus(m.status)
	snapshot.SessionActive = m.session != nil
	return snapshot
}

func (m *manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.session != nil {
		m.session.End()
		m.session = nil
	}
	if m.adapter != nil {
		err := m.adapter.Close()
		m.adapter = nil
		return err
	}
	return nil
}

func (m *manager) ReadPackets(limit int) ([]Packet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensurePacketSessionLocked(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 1
	}
	packets := make([]Packet, 0, limit)
	for len(packets) < limit {
		packet, err := m.session.ReceivePacket()
		if err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
				return packets, nil
			}
			return packets, err
		}
		cloned := append([]byte(nil), packet...)
		m.session.ReleaseReceivePacket(packet)
		packets = append(packets, Packet{Data: cloned})
	}
	return packets, nil
}

func (m *manager) WritePackets(packets []Packet) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(packets) == 0 {
		return nil
	}
	if err := m.ensurePacketSessionLocked(); err != nil {
		return err
	}
	for _, packet := range packets {
		if len(packet.Data) == 0 {
			continue
		}
		sendPacket, err := m.session.AllocateSendPacket(len(packet.Data))
		if err != nil {
			return err
		}
		copy(sendPacket, packet.Data)
		m.session.SendPacket(sendPacket)
	}
	return nil
}

func (shellRunner) Run(script string) error {
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := command.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(output))
		if trimmed != "" {
			return fmt.Errorf("%w: %s", err, trimmed)
		}
		return err
	}
	return nil
}

func (shellRunner) Output(script string) (string, error) {
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := command.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(output))
		if trimmed != "" {
			return "", fmt.Errorf("%w: %s", err, trimmed)
		}
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (a realAdapter) LUID() uint64 {
	return a.inner.LUID()
}

func (a realAdapter) StartSession(capacity uint32) (packetSession, error) {
	session, err := a.inner.StartSession(capacity)
	if err != nil {
		return nil, err
	}
	return realSession{inner: session}, nil
}

func (a realAdapter) Close() error {
	return a.inner.Close()
}

func (s realSession) End() {
	s.inner.End()
}

func (s realSession) ReceivePacket() ([]byte, error) {
	return s.inner.ReceivePacket()
}

func (s realSession) ReleaseReceivePacket(packet []byte) {
	s.inner.ReleaseReceivePacket(packet)
}

func (s realSession) AllocateSendPacket(packetSize int) ([]byte, error) {
	return s.inner.AllocateSendPacket(packetSize)
}

func (s realSession) SendPacket(packet []byte) {
	s.inner.SendPacket(packet)
}

func (realFactory) Open(name string) (wintunAdapter, error) {
	adapter, err := wintun.OpenAdapter(name)
	if err != nil {
		return nil, err
	}
	return realAdapter{inner: adapter}, nil
}

func (realFactory) Create(name string) (wintunAdapter, error) {
	adapter, err := wintun.CreateAdapter(name, "Wintun", nil)
	if err != nil {
		return nil, err
	}
	return realAdapter{inner: adapter}, nil
}

func (realFactory) DriverVersion() string {
	return wintun.Version()
}

func (m *manager) failLocked(err error) (Status, error) {
	m.status.LastError = err.Error()
	if !m.required {
		return m.status, err
	}
	return m.status, err
}

func (m *manager) ensureAdapterLocked() (wintunAdapter, bool, error) {
	if m.adapter != nil {
		return m.adapter, false, nil
	}
	adapter, err := m.factory.Open(m.adapterName)
	if err == nil {
		m.adapter = adapter
		return adapter, false, nil
	}
	adapter, createErr := m.factory.Create(m.adapterName)
	if createErr == nil {
		m.adapter = adapter
		return adapter, true, nil
	}
	return nil, false, fmt.Errorf("ensure Wintun adapter %q: open: %v; create: %w", m.adapterName, err, createErr)
}

func (m *manager) ensurePacketSessionLocked() error {
	if m.session != nil {
		return nil
	}
	adapter, _, err := m.ensureAdapterLocked()
	if err != nil {
		return err
	}
	session, err := adapter.StartSession(defaultRingSize)
	if err != nil {
		return err
	}
	m.session = session
	return nil
}

func (m *manager) ensureNetworkLocked(binding NetworkBinding) error {
	if err := m.runner.Run(ensureIPAddressScript(m.adapterName, binding.VirtualIP, binding.PrefixLength)); err != nil {
		return fmt.Errorf("ensure adapter IP for %s: %w", binding.NetworkID, err)
	}
	for _, prefix := range routePrefixesForBinding(binding) {
		if err := m.runner.Run(ensureRouteScript(m.adapterName, prefix)); err != nil {
			return fmt.Errorf("ensure adapter route for %s (%s): %w", binding.NetworkID, prefix, err)
		}
	}
	return nil
}

func (m *manager) removeNetworkLocked(binding NetworkBinding) error {
	for _, prefix := range routePrefixesForBinding(binding) {
		if err := m.runner.Run(removeRouteScript(m.adapterName, prefix)); err != nil {
			return fmt.Errorf("remove adapter route for %s (%s): %w", binding.NetworkID, prefix, err)
		}
	}
	if err := m.runner.Run(removeIPAddressScript(m.adapterName, binding.VirtualIP)); err != nil {
		return fmt.Errorf("remove adapter IP for %s: %w", binding.NetworkID, err)
	}
	return nil
}

func (m *manager) removeStaleNetworkStateLocked(previous, current NetworkBinding) error {
	for _, prefix := range staleRoutePrefixes(previous, current) {
		if err := m.runner.Run(removeRouteScript(m.adapterName, prefix)); err != nil {
			return fmt.Errorf("remove stale adapter route for %s (%s): %w", previous.NetworkID, prefix, err)
		}
	}
	if previous.VirtualIP != current.VirtualIP || previous.PrefixLength != current.PrefixLength {
		if err := m.runner.Run(removeIPAddressScript(m.adapterName, previous.VirtualIP)); err != nil {
			return fmt.Errorf("remove stale adapter IP for %s (%s): %w", previous.NetworkID, previous.VirtualIP, err)
		}
	}
	return nil
}

func (m *manager) reconcileGatewayDataplaneLocked(activeBindings map[string]NetworkBinding) error {
	if activeBindings == nil {
		activeBindings = map[string]NetworkBinding{}
	}
	desiredGatewayNetworks := map[string]NetworkBinding{}
	for networkID, binding := range activeBindings {
		if strings.EqualFold(binding.RoutingPolicy, "FULL") && strings.EqualFold(binding.GatewayRole, "GATEWAY") {
			desiredGatewayNetworks[networkID] = binding
		}
	}
	for networkID, binding := range m.applied {
		if !strings.EqualFold(binding.RoutingPolicy, "FULL") || !strings.EqualFold(binding.GatewayRole, "GATEWAY") {
			continue
		}
		if _, ok := desiredGatewayNetworks[networkID]; ok {
			continue
		}
		if err := m.runner.Run(removeGatewayNATScript(networkID)); err != nil {
			return fmt.Errorf("remove gateway NAT for %s: %w", binding.NetworkID, err)
		}
	}
	if len(desiredGatewayNetworks) == 0 {
		if err := m.runner.Run(disableIPv4ForwardingScript(m.adapterName)); err != nil {
			return fmt.Errorf("disable adapter IPv4 forwarding: %w", err)
		}
		return nil
	}
	if err := m.runner.Run(enableIPv4ForwardingScript(m.adapterName)); err != nil {
		return fmt.Errorf("enable adapter IPv4 forwarding: %w", err)
	}
	for _, binding := range desiredGatewayNetworks {
		if err := m.runner.Run(ensureGatewayNATScript(binding.NetworkID, binding.OverlayCIDR)); err != nil {
			return fmt.Errorf("ensure gateway NAT for %s: %w", binding.NetworkID, err)
		}
	}
	return nil
}

func (m *manager) ensureDNSLocked(server, suffix string) error {
	server = strings.TrimSpace(server)
	suffix = strings.Trim(strings.TrimSpace(suffix), ".")
	if server != "" {
		if err := m.runner.Run(ensureDNSServerScript(m.adapterName, server)); err != nil {
			return fmt.Errorf("ensure adapter DNS server: %w", err)
		}
	} else if err := m.runner.Run(clearDNSServerScript(m.adapterName)); err != nil {
		return fmt.Errorf("clear adapter DNS server: %w", err)
	}
	if suffix != "" {
		if err := m.runner.Run(ensureDNSSuffixScript(m.adapterName, suffix)); err != nil {
			return fmt.Errorf("ensure adapter DNS suffix: %w", err)
		}
	} else if err := m.runner.Run(clearDNSSuffixScript(m.adapterName)); err != nil {
		return fmt.Errorf("clear adapter DNS suffix: %w", err)
	}
	return nil
}

func (m *manager) clearDNSLocked() error {
	return m.ensureDNSLocked("", "")
}

func resolveAdapterName() string {
	if name := strings.TrimSpace(os.Getenv("OLE_ADAPTER_NAME")); name != "" {
		return name
	}
	return defaultAdapterName
}

func wintunDLLAvailable() bool {
	if dllPath := strings.TrimSpace(os.Getenv("OLE_WINTUN_DLL_PATH")); dllPath != "" {
		if _, err := os.Stat(dllPath); err == nil {
			return true
		}
	}
	if exePath, err := os.Executable(); err == nil {
		if _, err := os.Stat(filepath.Join(filepath.Dir(exePath), "wintun.dll")); err == nil {
			return true
		}
	}
	systemRoot := strings.TrimSpace(os.Getenv("SystemRoot"))
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	_, err := os.Stat(filepath.Join(systemRoot, "System32", "wintun.dll"))
	return err == nil
}

func normalizeNetwork(config NetworkConfig) (NetworkBinding, error) {
	networkID := strings.TrimSpace(config.NetworkID)
	if networkID == "" {
		return NetworkBinding{}, errors.New("network id is required")
	}
	virtualIP := strings.TrimSpace(config.VirtualIP)
	if virtualIP == "" {
		return NetworkBinding{}, fmt.Errorf("virtual IP is required for network %s", networkID)
	}
	parsedVirtualIP := net.ParseIP(virtualIP).To4()
	if parsedVirtualIP == nil {
		return NetworkBinding{}, fmt.Errorf("virtual IP must be IPv4 for network %s", networkID)
	}
	prefixLength := config.PrefixLength
	if prefixLength <= 0 {
		prefixLength = defaultPrefixLen
	}
	overlayCIDR := strings.TrimSpace(config.OverlayCIDR)
	if overlayCIDR == "" {
		overlayCIDR = strings.TrimSpace(config.RoutePrefix)
	}
	if overlayCIDR == "" {
		return NetworkBinding{}, fmt.Errorf("overlay CIDR is required for network %s", networkID)
	}
	_, overlayNet, err := net.ParseCIDR(overlayCIDR)
	if err != nil || overlayNet == nil || overlayNet.IP.To4() == nil {
		return NetworkBinding{}, fmt.Errorf("overlay CIDR must be a valid IPv4 CIDR for network %s", networkID)
	}
	routePrefix := strings.TrimSpace(config.RoutePrefix)
	if routePrefix == "" {
		return NetworkBinding{}, fmt.Errorf("route prefix is required for network %s", networkID)
	}
	_, routeNet, err := net.ParseCIDR(routePrefix)
	if err != nil || routeNet == nil {
		return NetworkBinding{}, fmt.Errorf("route prefix must be a valid IPv4 CIDR for network %s", networkID)
	}
	if routeNet.IP.To4() == nil {
		return NetworkBinding{}, fmt.Errorf("route prefix must be IPv4 for network %s", networkID)
	}
	gatewayRole := normalizeGatewayRole(config.GatewayRole)
	if !routeNet.Contains(parsedVirtualIP) && !(strings.EqualFold(config.RoutingPolicy, "FULL") && strings.EqualFold(gatewayRole, "CLIENT") && routeNet.String() == defaultIPv4Route) {
		return NetworkBinding{}, fmt.Errorf("virtual IP %s is outside route prefix %s for network %s", virtualIP, routeNet.String(), networkID)
	}
	routingPolicy, policyStatus, err := normalizeRoutingPolicy(config.RoutingPolicy, routeNet.String(), gatewayRole, strings.TrimSpace(config.GatewayPeerID), config.PolicyStatusHint)
	if err != nil {
		return NetworkBinding{}, fmt.Errorf("routing policy for network %s: %w", networkID, err)
	}
	return NetworkBinding{
		NetworkID:        networkID,
		VirtualIP:        virtualIP,
		PrefixLength:     prefixLength,
		OverlayCIDR:      overlayNet.String(),
		RoutePrefix:      routeNet.String(),
		RoutingPolicy:    routingPolicy,
		PolicyStatus:     policyStatus,
		GatewayRole:      gatewayRole,
		GatewayPeerID:    strings.TrimSpace(config.GatewayPeerID),
		GatewayUserID:    strings.TrimSpace(config.GatewayUserID),
		GatewayVirtualIP: strings.TrimSpace(config.GatewayVirtualIP),
	}, nil
}

func normalizeRoutingPolicy(policy, routePrefix, gatewayRole, gatewayPeerID, policyStatusHint string) (string, string, error) {
	normalized := strings.ToUpper(strings.TrimSpace(policy))
	if normalized == "" {
		normalized = "SPLIT"
	}
	hint := strings.ToUpper(strings.TrimSpace(policyStatusHint))
	switch normalized {
	case "SPLIT":
		return normalized, "ACTIVE", nil
	case "FULL":
		if hint == "STANDBY_GATEWAY" {
			if strings.EqualFold(gatewayRole, "CLIENT") && strings.TrimSpace(gatewayPeerID) != "" && !strings.EqualFold(strings.TrimSpace(routePrefix), defaultIPv4Route) {
				return normalized, "STANDBY_GATEWAY", nil
			}
			return "", "", fmt.Errorf("standby gateway status requires a client gateway peer on a non-default route")
		}
		if strings.EqualFold(gatewayRole, "CLIENT") && strings.TrimSpace(gatewayPeerID) != "" && strings.EqualFold(strings.TrimSpace(routePrefix), defaultIPv4Route) {
			return normalized, "ACTIVE", nil
		}
		if strings.EqualFold(gatewayRole, "GATEWAY") {
			return normalized, "ACTIVE", nil
		}
		return normalized, "PENDING_GATEWAY", nil
	default:
		return "", "", fmt.Errorf("unsupported routing policy %q", policy)
	}
}

func normalizeGatewayRole(role string) string {
	switch strings.ToUpper(strings.TrimSpace(role)) {
	case "CLIENT":
		return "CLIENT"
	case "GATEWAY":
		return "GATEWAY"
	default:
		return ""
	}
}

func suppressOverlappingBindings(bindings map[string]NetworkBinding) (map[string]NetworkBinding, string) {
	if len(bindings) == 0 {
		return map[string]NetworkBinding{}, ""
	}
	active := make(map[string]NetworkBinding, len(bindings))
	accepted := make([]string, 0, len(bindings))
	conflicts := make([]string, 0)
	keys := make([]string, 0, len(bindings))
	for networkID := range bindings {
		keys = append(keys, networkID)
	}
	sort.Strings(keys)
	for _, networkID := range keys {
		binding := bindings[networkID]
		conflictWith := ""
		for _, acceptedNetworkID := range accepted {
			if bindingsConflictForRouteSuppression(binding, active[acceptedNetworkID]) {
				conflictWith = acceptedNetworkID
				break
			}
		}
		if conflictWith != "" {
			conflicts = append(conflicts, fmt.Sprintf("%s overlaps %s", networkID, conflictWith))
			continue
		}
		active[networkID] = binding
		accepted = append(accepted, networkID)
	}
	if len(conflicts) == 0 {
		return active, ""
	}
	return active, "overlapping overlay routes suppressed: " + strings.Join(conflicts, "; ")
}

func bindingsConflictForRouteSuppression(left, right NetworkBinding) bool {
	leftUsesSplitDefault := bindingUsesSplitDefaultRoutes(left)
	rightUsesSplitDefault := bindingUsesSplitDefaultRoutes(right)
	switch {
	case leftUsesSplitDefault && rightUsesSplitDefault:
		return true
	case leftUsesSplitDefault || rightUsesSplitDefault:
		return false
	default:
		return routesOverlap(left.RoutePrefix, right.RoutePrefix)
	}
}

func bindingUsesSplitDefaultRoutes(binding NetworkBinding) bool {
	return strings.EqualFold(binding.RoutingPolicy, "FULL") &&
		strings.EqualFold(binding.GatewayRole, "CLIENT") &&
		strings.EqualFold(binding.RoutePrefix, defaultIPv4Route)
}

func routesOverlap(left, right string) bool {
	_, leftNet, err := net.ParseCIDR(strings.TrimSpace(left))
	if err != nil || leftNet == nil {
		return false
	}
	_, rightNet, err := net.ParseCIDR(strings.TrimSpace(right))
	if err != nil || rightNet == nil {
		return false
	}
	return leftNet.Contains(rightNet.IP) || rightNet.Contains(leftNet.IP)
}

func desiredMTUFromConfigs(configs []NetworkConfig) (int, error) {
	desiredMTU := 0
	for _, config := range configs {
		if config.MTU <= 0 {
			continue
		}
		if config.MTU < minAdapterMTU || config.MTU > maxAdapterMTU {
			return 0, fmt.Errorf("adapter MTU must be between %d and %d", minAdapterMTU, maxAdapterMTU)
		}
		if desiredMTU == 0 {
			desiredMTU = config.MTU
			continue
		}
		if desiredMTU != config.MTU {
			return 0, errors.New("all managed networks must agree on adapter MTU")
		}
	}
	return desiredMTU, nil
}

func desiredDNSSettingsFromConfigs(configs []NetworkConfig) (string, string, error) {
	desiredServer := ""
	desiredSuffix := ""
	for _, config := range configs {
		server := strings.TrimSpace(config.DNSServer)
		suffix := strings.Trim(strings.TrimSpace(config.DNSSuffix), ".")
		if server != "" {
			if net.ParseIP(server) == nil {
				return "", "", fmt.Errorf("adapter DNS server must be an IP address, got %q", server)
			}
			if desiredServer == "" {
				desiredServer = server
			} else if desiredServer != server {
				return "", "", errors.New("all managed networks must agree on adapter DNS server")
			}
		}
		if suffix != "" {
			if desiredSuffix == "" {
				desiredSuffix = suffix
			} else if !strings.EqualFold(desiredSuffix, suffix) {
				return "", "", errors.New("all managed networks must agree on adapter DNS suffix")
			}
		}
	}
	return desiredServer, desiredSuffix, nil
}

func bindingsSlice(bindings map[string]NetworkBinding) []NetworkBinding {
	out := make([]NetworkBinding, 0, len(bindings))
	keys := make([]string, 0, len(bindings))
	for networkID := range bindings {
		keys = append(keys, networkID)
	}
	sort.Strings(keys)
	for _, networkID := range keys {
		binding := bindings[networkID]
		out = append(out, binding)
	}
	return out
}

func fullTunnelPolicyWarning(bindings map[string]NetworkBinding) string {
	for _, binding := range bindings {
		if strings.EqualFold(binding.RoutingPolicy, "FULL") && strings.EqualFold(binding.PolicyStatus, "PENDING_GATEWAY") {
			return "full-tunnel policy is configured, but gateway dataplane activation is still pending"
		}
	}
	return ""
}

func combineWarnings(parts ...string) string {
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		filtered = append(filtered, part)
	}
	return strings.Join(filtered, "; ")
}

func cloneStatus(status Status) Status {
	copy := status
	if status.Networks != nil {
		copy.Networks = append([]NetworkBinding(nil), status.Networks...)
	}
	if status.DNSServers != nil {
		copy.DNSServers = append([]string(nil), status.DNSServers...)
	}
	return copy
}

func (m *manager) refreshDiagnosticsLocked() error {
	if m.runner == nil {
		return nil
	}
	output, err := m.runner.Output(adapterDiagnosticsScript(m.adapterName))
	if err != nil {
		return err
	}
	if strings.TrimSpace(output) == "" {
		return nil
	}
	var diagnostics adapterDiagnostics
	if err := json.Unmarshal([]byte(output), &diagnostics); err != nil {
		return err
	}
	m.status.MTU = diagnostics.MTU
	m.status.InterfaceMetric = diagnostics.InterfaceMetric
	m.status.ConnectionState = strings.TrimSpace(diagnostics.ConnectionState)
	m.status.DNSServers = append([]string(nil), diagnostics.DNSServers...)
	m.status.DNSSuffix = strings.Trim(strings.TrimSpace(diagnostics.DNSSuffix), ".")

	ipIndex := make(map[string]bool, len(diagnostics.IPAddresses))
	for _, item := range diagnostics.IPAddresses {
		key := strings.TrimSpace(item.IPAddress) + "/" + fmt.Sprintf("%d", item.PrefixLength)
		ipIndex[key] = true
	}
	routeIndex := make(map[string]int, len(diagnostics.Routes))
	for _, item := range diagnostics.Routes {
		routeIndex[strings.TrimSpace(item.DestinationPrefix)] = item.RouteMetric
	}

	for networkID, binding := range m.applied {
		enriched := binding
		enriched.IPAddressVisible = ipIndex[binding.VirtualIP+"/"+fmt.Sprintf("%d", binding.PrefixLength)]
		metric, routeVisible := routeVisibilityAndMetricForBinding(binding, routeIndex)
		enriched.RouteVisible = routeVisible
		enriched.RouteMetric = metric
		m.applied[networkID] = enriched
	}
	m.status.Networks = bindingsSlice(m.applied)
	return nil
}

func routePrefixesForBinding(binding NetworkBinding) []string {
	if bindingUsesSplitDefaultRoutes(binding) {
		return []string{"0.0.0.0/1", "128.0.0.0/1"}
	}
	return []string{binding.RoutePrefix}
}

func routeVisibilityAndMetricForBinding(binding NetworkBinding, routeIndex map[string]int) (int, bool) {
	prefixes := routePrefixesForBinding(binding)
	if len(prefixes) == 0 {
		return 0, false
	}
	metric := 0
	for idx, prefix := range prefixes {
		current, ok := routeIndex[strings.TrimSpace(prefix)]
		if !ok {
			return 0, false
		}
		if idx == 0 || current < metric {
			metric = current
		}
	}
	return metric, true
}

func staleRoutePrefixes(previous, current NetworkBinding) []string {
	currentSet := map[string]struct{}{}
	for _, prefix := range routePrefixesForBinding(current) {
		currentSet[strings.TrimSpace(prefix)] = struct{}{}
	}
	stale := make([]string, 0)
	for _, prefix := range routePrefixesForBinding(previous) {
		prefix = strings.TrimSpace(prefix)
		if _, ok := currentSet[prefix]; ok {
			continue
		}
		stale = append(stale, prefix)
	}
	return stale
}

func ensureIPAddressScript(adapterName, ip string, prefixLen int) string {
	return fmt.Sprintf(
		"$existing = Get-NetIPAddress -InterfaceAlias %s -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq %s -and $_.PrefixLength -eq %d }; if (-not $existing) { New-NetIPAddress -InterfaceAlias %s -IPAddress %s -PrefixLength %d -AddressFamily IPv4 -Type Unicast -PolicyStore ActiveStore | Out-Null }",
		psQuote(adapterName), psQuote(ip), prefixLen, psQuote(adapterName), psQuote(ip), prefixLen,
	)
}

func removeIPAddressScript(adapterName, ip string) string {
	return fmt.Sprintf(
		"Get-NetIPAddress -InterfaceAlias %s -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq %s } | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue",
		psQuote(adapterName), psQuote(ip),
	)
}

func ensureRouteScript(adapterName, prefix string) string {
	return fmt.Sprintf(
		"$existing = Get-NetRoute -InterfaceAlias %s -AddressFamily IPv4 -DestinationPrefix %s -ErrorAction SilentlyContinue; if (-not $existing) { New-NetRoute -InterfaceAlias %s -AddressFamily IPv4 -DestinationPrefix %s -NextHop '0.0.0.0' -RouteMetric %d -PolicyStore ActiveStore | Out-Null }",
		psQuote(adapterName), psQuote(prefix), psQuote(adapterName), psQuote(prefix), defaultRouteMetric,
	)
}

func ensureMTUScript(adapterName string, mtu int) string {
	return fmt.Sprintf(
		"$iface = Get-NetIPInterface -InterfaceAlias %s -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1; if ($iface -and [int]$iface.NlMtuBytes -ne %d) { Set-NetIPInterface -InterfaceAlias %s -AddressFamily IPv4 -NlMtuBytes %d -ErrorAction Stop | Out-Null }",
		psQuote(adapterName), mtu, psQuote(adapterName), mtu,
	)
}

func ensureDNSServerScript(adapterName, server string) string {
	return fmt.Sprintf(
		"$current = @(Get-DnsClientServerAddress -InterfaceAlias %s -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty ServerAddresses); if ((@($current) -join ',') -ne %s) { Set-DnsClientServerAddress -InterfaceAlias %s -ServerAddresses @(%s) -ErrorAction Stop | Out-Null }",
		psQuote(adapterName), psQuote(server), psQuote(adapterName), psQuote(server),
	)
}

func clearDNSServerScript(adapterName string) string {
	return fmt.Sprintf(
		"$current = @(Get-DnsClientServerAddress -InterfaceAlias %s -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty ServerAddresses); if (@($current).Count -gt 0) { Set-DnsClientServerAddress -InterfaceAlias %s -ResetServerAddresses -ErrorAction SilentlyContinue | Out-Null }",
		psQuote(adapterName), psQuote(adapterName),
	)
}

func ensureDNSSuffixScript(adapterName, suffix string) string {
	return fmt.Sprintf(
		"$client = Get-DnsClient -InterfaceAlias %s -ErrorAction SilentlyContinue | Select-Object -First 1; if ($client -and ('' + $client.ConnectionSpecificSuffix) -ne %s) { Set-DnsClient -InterfaceAlias %s -ConnectionSpecificSuffix %s -UseSuffixWhenRegistering $false -RegisterThisConnectionsAddress $false -ErrorAction Stop | Out-Null }",
		psQuote(adapterName), psQuote(suffix), psQuote(adapterName), psQuote(suffix),
	)
}

func clearDNSSuffixScript(adapterName string) string {
	return fmt.Sprintf(
		"$client = Get-DnsClient -InterfaceAlias %s -ErrorAction SilentlyContinue | Select-Object -First 1; if ($client -and -not [string]::IsNullOrWhiteSpace('' + $client.ConnectionSpecificSuffix)) { Set-DnsClient -InterfaceAlias %s -ConnectionSpecificSuffix '' -UseSuffixWhenRegistering $false -RegisterThisConnectionsAddress $false -ErrorAction SilentlyContinue | Out-Null }",
		psQuote(adapterName), psQuote(adapterName),
	)
}

func removeRouteScript(adapterName, prefix string) string {
	return fmt.Sprintf(
		"Get-NetRoute -InterfaceAlias %s -AddressFamily IPv4 -DestinationPrefix %s -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue",
		psQuote(adapterName), psQuote(prefix),
	)
}

func enableIPv4ForwardingScript(adapterName string) string {
	return fmt.Sprintf(
		"$iface = Get-NetIPInterface -InterfaceAlias %s -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1; if ($iface -and ('' + $iface.Forwarding) -ne 'Enabled') { Set-NetIPInterface -InterfaceAlias %s -AddressFamily IPv4 -Forwarding Enabled -ErrorAction Stop | Out-Null }",
		psQuote(adapterName), psQuote(adapterName),
	)
}

func disableIPv4ForwardingScript(adapterName string) string {
	return fmt.Sprintf(
		"$iface = Get-NetIPInterface -InterfaceAlias %s -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1; if ($iface -and ('' + $iface.Forwarding) -ne 'Disabled') { Set-NetIPInterface -InterfaceAlias %s -AddressFamily IPv4 -Forwarding Disabled -ErrorAction SilentlyContinue | Out-Null }",
		psQuote(adapterName), psQuote(adapterName),
	)
}

func ensureGatewayNATScript(networkID, overlayCIDR string) string {
	natName := gatewayNATName(networkID)
	return fmt.Sprintf(
		"$nat = Get-NetNat -Name %s -ErrorAction SilentlyContinue; if (-not $nat) { New-NetNat -Name %s -InternalIPInterfaceAddressPrefix %s -ErrorAction Stop | Out-Null } elseif ('' + $nat.InternalIPInterfaceAddressPrefix -ne %s) { Remove-NetNat -Name %s -Confirm:$false -ErrorAction SilentlyContinue | Out-Null; New-NetNat -Name %s -InternalIPInterfaceAddressPrefix %s -ErrorAction Stop | Out-Null }",
		psQuote(natName), psQuote(natName), psQuote(overlayCIDR), psQuote(overlayCIDR), psQuote(natName), psQuote(natName), psQuote(overlayCIDR),
	)
}

func removeGatewayNATScript(networkID string) string {
	return fmt.Sprintf(
		"Get-NetNat -Name %s -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false -ErrorAction SilentlyContinue",
		psQuote(gatewayNATName(networkID)),
	)
}

func gatewayNATName(networkID string) string {
	normalized := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-':
			return r
		default:
			return '-'
		}
	}, strings.TrimSpace(networkID))
	normalized = strings.Trim(normalized, "-")
	if normalized == "" {
		normalized = "network"
	}
	return "Ole-" + normalized
}

func adapterDiagnosticsScript(adapterName string) string {
	return fmt.Sprintf(
		"$iface = Get-NetIPInterface -InterfaceAlias %s -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1 InterfaceAlias, NlMtuBytes, InterfaceMetric, ConnectionState; "+
			"$ips = @(Get-NetIPAddress -InterfaceAlias %s -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object @{Name='ipAddress';Expression={$_.IPAddress}}, @{Name='prefixLength';Expression={$_.PrefixLength}}); "+
			"$routes = @(Get-NetRoute -InterfaceAlias %s -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object @{Name='destinationPrefix';Expression={$_.DestinationPrefix}}, @{Name='routeMetric';Expression={$_.RouteMetric}}); "+
			"$dnsServers = @(Get-DnsClientServerAddress -InterfaceAlias %s -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty ServerAddresses); "+
			"$dnsClient = Get-DnsClient -InterfaceAlias %s -ErrorAction SilentlyContinue | Select-Object -First 1 ConnectionSpecificSuffix; "+
			"@{ mtu = $(if ($iface) { [int]$iface.NlMtuBytes } else { 0 }); interfaceMetric = $(if ($iface) { [int]$iface.InterfaceMetric } else { 0 }); connectionState = $(if ($iface) { '' + $iface.ConnectionState } else { '' }); dnsServers = @($dnsServers); dnsSuffix = $(if ($dnsClient) { '' + $dnsClient.ConnectionSpecificSuffix } else { '' }); ipAddresses = $ips; routes = $routes } | ConvertTo-Json -Compress",
		psQuote(adapterName),
		psQuote(adapterName),
		psQuote(adapterName),
		psQuote(adapterName),
		psQuote(adapterName),
	)
}

func psQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

type noopManager struct {
	status Status
}

func (m *noopManager) Reconcile(_ []NetworkConfig) (Status, error) {
	return cloneStatus(m.status), nil
}

func (m *noopManager) Snapshot() Status {
	return cloneStatus(m.status)
}

func (m *noopManager) Close() error {
	return nil
}

func (m *noopManager) ReadPackets(_ int) ([]Packet, error) {
	return nil, nil
}

func (m *noopManager) WritePackets(_ []Packet) error {
	return nil
}
