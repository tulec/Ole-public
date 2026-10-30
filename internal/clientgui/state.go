package clientgui

import "Ole/internal/clientagent"

type state struct {
	svc                *clientagent.IPCClient
	agentStatus        *clientagent.Status
	currentUser        *User
	currentSession     *Session
	sessions           []Session
	selectedSession    *Session
	currentDevice      *Device
	devices            []Device
	selectedDevice     *Device
	auditPresets       []AuditPreset
	selectedPreset     *AuditPreset
	networks           []Network
	selected           *Network
	peers              []Peer
	tunnels            []Tunnel
	messages           []Message
	fileTransfers      []FileTransfer
	selectedTransfer   *FileTransfer
	transferLocalState *clientagent.FileTransferLocalState
	auditEvents        []AuditEvent
	incidentReports    []IncidentReport
}
