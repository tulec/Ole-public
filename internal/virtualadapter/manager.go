package virtualadapter

type NetworkConfig struct {
	NetworkID         string
	VirtualIP         string
	PrefixLength      int
	OverlayCIDR       string
	RoutePrefix       string
	RoutingPolicy     string
	PolicyStatusHint  string
	GatewayRole       string
	GatewayPeerID     string
	GatewayUserID     string
	GatewayVirtualIP  string
	GatewayTargetRole string
	MTU               int
	DNSServer         string
	DNSSuffix         string
}

type NetworkBinding struct {
	NetworkID        string `json:"networkId"`
	VirtualIP        string `json:"virtualIp"`
	PrefixLength     int    `json:"prefixLength"`
	OverlayCIDR      string `json:"overlayCidr"`
	RoutePrefix      string `json:"routePrefix"`
	RoutingPolicy    string `json:"routingPolicy"`
	PolicyStatus     string `json:"policyStatus"`
	GatewayRole      string `json:"gatewayRole"`
	GatewayPeerID    string `json:"gatewayPeerId"`
	GatewayUserID    string `json:"gatewayUserId,omitempty"`
	GatewayVirtualIP string `json:"gatewayVirtualIp,omitempty"`
	IPAddressVisible bool   `json:"ipAddressVisible"`
	RouteVisible     bool   `json:"routeVisible"`
	RouteMetric      int    `json:"routeMetric"`
}

type Packet struct {
	Data []byte
}

type Status struct {
	Enabled          bool             `json:"enabled"`
	Available        bool             `json:"available"`
	AdapterName      string           `json:"adapterName"`
	DriverVersion    string           `json:"driverVersion"`
	LUID             uint64           `json:"luid"`
	DesiredMTU       int              `json:"desiredMtu"`
	MTU              int              `json:"mtu"`
	InterfaceMetric  int              `json:"interfaceMetric"`
	ConnectionState  string           `json:"connectionState"`
	SessionActive    bool             `json:"sessionActive"`
	DesiredDNSServer string           `json:"desiredDnsServer"`
	DNSServers       []string         `json:"dnsServers"`
	DNSSuffix        string           `json:"dnsSuffix"`
	LastError        string           `json:"lastError"`
	Networks         []NetworkBinding `json:"networks"`
}

type Manager interface {
	Reconcile(desired []NetworkConfig) (Status, error)
	Snapshot() Status
	Close() error
}

type PacketIO interface {
	ReadPackets(limit int) ([]Packet, error)
	WritePackets(packets []Packet) error
}
