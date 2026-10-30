//go:build !windows

package virtualadapter

type noopManager struct {
	status Status
}

func NewDefaultManager() Manager {
	return &noopManager{
		status: Status{
			Enabled:   false,
			Available: false,
			LastError: "virtual adapter management is only available on Windows",
		},
	}
}

func (m *noopManager) Reconcile(_ []NetworkConfig) (Status, error) {
	return m.status, nil
}

func (m *noopManager) Snapshot() Status {
	return m.status
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
