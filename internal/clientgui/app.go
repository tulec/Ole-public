//go:build windows

package clientgui

import (
	"Ole/internal/clientagent"
	"Ole/internal/controlclient"
	"Ole/internal/domain"
	"Ole/internal/virtualadapter"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

type networkListModel struct {
	walk.ListModelBase
	items []string
}

func (m *networkListModel) ItemCount() int {
	return len(m.items)
}

func (m *networkListModel) Value(index int) any {
	return m.items[index]
}

type sessionListModel struct {
	walk.ListModelBase
	items []string
}

func (m *sessionListModel) ItemCount() int {
	return len(m.items)
}

func (m *sessionListModel) Value(index int) any {
	return m.items[index]
}

type deviceListModel struct {
	walk.ListModelBase
	items []string
}

func (m *deviceListModel) ItemCount() int {
	return len(m.items)
}

func (m *deviceListModel) Value(index int) any {
	return m.items[index]
}

type auditPresetListModel struct {
	walk.ListModelBase
	items []string
}

func (m *auditPresetListModel) ItemCount() int {
	return len(m.items)
}

func (m *auditPresetListModel) Value(index int) any {
	return m.items[index]
}

type fileTransferListModel struct {
	walk.ListModelBase
	items []string
}

func (m *fileTransferListModel) ItemCount() int {
	return len(m.items)
}

func (m *fileTransferListModel) Value(index int) any {
	return m.items[index]
}

type peerChoice struct {
	ID    string
	Label string
}

const fileTransferGUIChunkSizeBytes = 1 << 20

func Run() error {
	state := &state{svc: clientagent.NewIPCClient(clientagent.DefaultIPCBaseURL)}

	var mw *walk.MainWindow
	var statusBar *walk.Label
	var userLabel *walk.Label
	var quickStartView *walk.TextEdit
	var onboardingView *walk.TextEdit
	var serviceHealthView *walk.TextEdit
	var agentView *walk.TextEdit
	var connectionView *walk.TextEdit
	var auditView *walk.TextEdit
	var incidentView *walk.TextEdit
	var devicesView *walk.TextEdit
	var devicesBox *walk.ListBox
	var auditPresetsBox *walk.ListBox
	var sessionsBox *walk.ListBox
	var sessionDetailsView *walk.TextEdit
	var serverEdit *walk.LineEdit
	var mtuEdit *walk.LineEdit
	var updateChannelBox *walk.ComboBox
	var emailEdit *walk.LineEdit
	var passwordEdit *walk.LineEdit
	var networkNameEdit *walk.LineEdit
	var accessBox *walk.ComboBox
	var requireApprovalBox *walk.CheckBox
	var createRoutingPolicyBox *walk.ComboBox
	var createGroupTrafficBox *walk.ComboBox
	var createNameResolutionBox *walk.ComboBox
	var createDNSLabelEdit *walk.LineEdit
	var createFileTransfersBox *walk.ComboBox
	var createFileTransferMaxBytesEdit *walk.LineEdit
	var selectedRoutingPolicyBox *walk.ComboBox
	var selectedGroupTrafficBox *walk.ComboBox
	var selectedNameResolutionBox *walk.ComboBox
	var selectedDNSLabelEdit *walk.LineEdit
	var selectedFileTransfersBox *walk.ComboBox
	var selectedFileTransferMaxBytesEdit *walk.LineEdit
	var inviteCodeEdit *walk.LineEdit
	var endpointEdit *walk.LineEdit
	var inviteTTLEdit *walk.LineEdit
	var inviteUsesEdit *walk.LineEdit
	var peerAEdit *walk.LineEdit
	var peerBEdit *walk.LineEdit
	var auditActorEdit *walk.LineEdit
	var auditTypeEdit *walk.LineEdit
	var auditQueryEdit *walk.LineEdit
	var auditFromEdit *walk.LineEdit
	var auditToEdit *walk.LineEdit
	var auditPresetNameEdit *walk.LineEdit
	var peersView *walk.TextEdit
	var tunnelsView *walk.TextEdit
	var messagesView *walk.TextEdit
	var fileTransfersBox *walk.ListBox
	var fileTransferDetailsView *walk.TextEdit
	var networksBox *walk.ListBox
	var messageFromPeerBox *walk.ComboBox
	var messageFilterPeerBox *walk.ComboBox
	var messageFilterEdit *walk.LineEdit
	var messageTextEdit *walk.LineEdit
	var transferFromPeerBox *walk.ComboBox
	var transferToPeerBox *walk.ComboBox
	var transferMailboxBox *walk.ComboBox
	var transferFilterPeerBox *walk.ComboBox
	var transferStatusFilterBox *walk.ComboBox
	var transferFilterEdit *walk.LineEdit
	var transferSourcePathEdit *walk.LineEdit
	var transferFileNameEdit *walk.LineEdit
	var transferSizeEdit *walk.LineEdit
	var transferProgressEdit *walk.LineEdit
	var transferReasonEdit *walk.LineEdit

	networksModel := &networkListModel{}
	sessionsModel := &sessionListModel{}
	devicesModel := &deviceListModel{}
	auditPresetsModel := &auditPresetListModel{}
	fileTransfersModel := &fileTransferListModel{}
	var visibleFileTransfers []FileTransfer
	var messageSenderChoices []peerChoice
	var messageFilterChoices []peerChoice
	var transferSenderChoices []peerChoice
	var transferRecipientChoices []peerChoice
	var transferFilterChoices []peerChoice

	updateStatus := func(message string) {
		if statusBar != nil {
			statusBar.SetText(message)
		}
	}

	clearCollections := func() {
		state.sessions = nil
		state.selectedSession = nil
		state.devices = nil
		state.selectedDevice = nil
		state.auditPresets = nil
		state.selectedPreset = nil
		state.networks = nil
		state.selected = nil
		state.peers = nil
		state.tunnels = nil
		state.messages = nil
		state.fileTransfers = nil
		state.selectedTransfer = nil
		state.transferLocalState = nil
		state.auditEvents = nil
		state.incidentReports = nil
	}

	applyStatus := func(status *clientagent.Status) {
		state.agentStatus = status
		if status == nil {
			state.currentUser = nil
			state.currentSession = nil
			state.currentDevice = nil
			return
		}
		state.currentUser = status.CurrentUser
		state.currentSession = status.CurrentSession
		state.currentDevice = status.CurrentDevice
		if serverEdit != nil && strings.TrimSpace(status.ServerBaseURL) != "" {
			serverEdit.SetText(status.ServerBaseURL)
		}
		if mtuEdit != nil {
			switch {
			case status.Adapter.DesiredMTU > 0:
				mtuEdit.SetText(strconv.Itoa(status.Adapter.DesiredMTU))
			case status.Adapter.MTU > 0:
				mtuEdit.SetText(strconv.Itoa(status.Adapter.MTU))
			default:
				mtuEdit.SetText("")
			}
		}
		if updateChannelBox != nil {
			switch strings.ToLower(strings.TrimSpace(status.Update.Channel)) {
			case "beta":
				updateChannelBox.SetCurrentIndex(1)
			default:
				updateChannelBox.SetCurrentIndex(0)
			}
		}
	}

	updateDiagnostics := func() {
		if quickStartView != nil {
			quickStartView.SetText(formatQuickStartGuide(state.agentStatus, len(state.networks), state.selected, len(state.peers), len(state.tunnels)))
		}
		if onboardingView != nil {
			onboardingView.SetText(formatOnboardingGuide(state.agentStatus, len(state.networks), state.selected, len(state.peers), len(state.tunnels)))
		}
		if serviceHealthView != nil {
			serviceHealthView.SetText(formatServiceHealthStatus(state.agentStatus))
		}
		if agentView != nil {
			agentView.SetText(formatAgentStatus(state.agentStatus))
		}
		if connectionView != nil {
			connectionView.SetText(formatConnectionDiagnostics(state.agentStatus, state.selected))
		}
	}

	updateUserLabel := func() {
		if userLabel == nil {
			return
		}
		if state.currentUser == nil {
			userLabel.SetText("No active service session")
			return
		}
		deviceLabel := "no device"
		if state.currentDevice != nil {
			deviceLabel = state.currentDevice.Name
		}
		userLabel.SetText(fmt.Sprintf("%s (%s) | device: %s", state.currentUser.Email, state.currentUser.ID, deviceLabel))
	}

	updateSessionDetails := func() {
		if sessionDetailsView == nil {
			return
		}
		if state.selectedSession == nil {
			sessionDetailsView.SetText("Select a session to inspect or revoke it.")
			return
		}
		sessionDetailsView.SetText(formatSessionDetails(*state.selectedSession, state.currentSession))
	}

	updateSessionList := func() {
		items := make([]string, 0, len(state.sessions))
		currentIndex := -1
		for _, session := range state.sessions {
			items = append(items, formatSessionSummary(session, state.currentSession))
		}
		if state.selectedSession != nil {
			for idx := range state.sessions {
				if state.sessions[idx].ID == state.selectedSession.ID {
					currentIndex = idx
					break
				}
			}
		}
		sessionsModel.items = items
		sessionsModel.PublishItemsReset()
		if sessionsBox != nil {
			sessionsBox.SetCurrentIndex(currentIndex)
		}
		updateSessionDetails()
	}

	var updateDevicesView func()
	var updateDeviceList func()
	var updateAuditPresetsView func()

	refreshSessions := func() error {
		sessions, err := state.svc.ListSessions()
		if err != nil {
			return err
		}
		selectedID := ""
		if state.selectedSession != nil {
			selectedID = state.selectedSession.ID
		}
		state.sessions = sessions
		state.selectedSession = nil
		for idx := range state.sessions {
			if state.sessions[idx].ID == selectedID {
				state.selectedSession = &state.sessions[idx]
				break
			}
		}
		if state.selectedSession == nil && len(state.sessions) > 0 {
			state.selectedSession = &state.sessions[0]
		}
		updateSessionList()
		return nil
	}

	refreshDevices := func() error {
		if state.currentSession == nil {
			state.devices = nil
			state.selectedDevice = nil
			updateDeviceList()
			updateDevicesView()
			return nil
		}
		devices, err := state.svc.ListDevices()
		if err != nil {
			return err
		}
		selectedID := ""
		if state.selectedDevice != nil {
			selectedID = state.selectedDevice.ID
		}
		if selectedID == "" {
			selectedID = currentServiceDeviceID(state.agentStatus)
		}
		state.devices = devices
		state.selectedDevice = nil
		for idx := range state.devices {
			if state.devices[idx].ID == selectedID {
				state.selectedDevice = &state.devices[idx]
				break
			}
		}
		if state.selectedDevice == nil && len(state.devices) > 0 {
			state.selectedDevice = &state.devices[0]
		}
		updateDeviceList()
		updateDevicesView()
		return nil
	}

	updateAuditView := func() {
		if auditView == nil {
			return
		}
		auditView.SetText(formatAuditEvents(state.auditEvents))
	}

	updateIncidentView := func() {
		if incidentView == nil {
			return
		}
		incidentView.SetText(formatIncidentReports(state.incidentReports))
	}

	updateDeviceList = func() {
		items := make([]string, 0, len(state.devices))
		currentIndex := -1
		for idx, device := range state.devices {
			items = append(items, formatDeviceSummaryLine(device, state.agentStatus))
			if state.selectedDevice != nil && state.selectedDevice.ID == device.ID {
				currentIndex = idx
			}
		}
		devicesModel.items = items
		devicesModel.PublishItemsReset()
		if devicesBox != nil {
			devicesBox.SetCurrentIndex(currentIndex)
		}
	}

	updateDevicesView = func() {
		if devicesView == nil {
			return
		}
		devicesView.SetText(formatDeviceDetailsForNetwork(state.devices, state.selectedDevice, state.selected, state.agentStatus))
	}

	updateRoutingPolicyControls := func() {
		if selectedRoutingPolicyBox == nil {
			return
		}
		if state.selected == nil {
			selectedRoutingPolicyBox.SetCurrentIndex(0)
			return
		}
		switch networkRoutingPolicyOrDefault(*state.selected) {
		case "FULL":
			selectedRoutingPolicyBox.SetCurrentIndex(1)
		default:
			selectedRoutingPolicyBox.SetCurrentIndex(0)
		}
	}

	updateGroupTrafficControls := func() {
		if selectedGroupTrafficBox == nil {
			return
		}
		if state.selected == nil {
			selectedGroupTrafficBox.SetCurrentIndex(0)
			return
		}
		switch networkGroupTrafficPolicyOrDefault(*state.selected) {
		case "FLOOD":
			selectedGroupTrafficBox.SetCurrentIndex(1)
		default:
			selectedGroupTrafficBox.SetCurrentIndex(0)
		}
	}

	updateNameResolutionControls := func() {
		if selectedNameResolutionBox == nil || selectedDNSLabelEdit == nil {
			return
		}
		if state.selected == nil {
			selectedNameResolutionBox.SetCurrentIndex(0)
			selectedDNSLabelEdit.SetText("")
			return
		}
		mode := networkNameResolutionModeOrDefault(*state.selected)
		switch mode {
		case "NETWORK_ONLY":
			selectedNameResolutionBox.SetCurrentIndex(1)
		case "DISABLED":
			selectedNameResolutionBox.SetCurrentIndex(2)
		default:
			selectedNameResolutionBox.SetCurrentIndex(0)
		}
		selectedDNSLabelEdit.SetText(strings.TrimSpace(state.selected.DNSLabel))
	}

	updateFileTransferPolicyControls := func() {
		if selectedFileTransfersBox == nil || selectedFileTransferMaxBytesEdit == nil {
			return
		}
		if state.selected == nil {
			selectedFileTransfersBox.SetCurrentIndex(0)
			selectedFileTransferMaxBytesEdit.SetText(strconv.FormatInt(defaultNetworkFileTransferMaxBytes(), 10))
			return
		}
		if networkFileTransfersEnabledOrDefault(*state.selected) {
			selectedFileTransfersBox.SetCurrentIndex(0)
		} else {
			selectedFileTransfersBox.SetCurrentIndex(1)
		}
		selectedFileTransferMaxBytesEdit.SetText(strconv.FormatInt(networkFileTransferMaxBytesOrDefault(*state.selected), 10))
	}

	updateAuditPresetsView = func() {
		items := make([]string, 0, len(state.auditPresets))
		currentIndex := -1
		for idx, preset := range state.auditPresets {
			items = append(items, formatAuditPresetLabel(preset))
			if state.selectedPreset != nil && strings.EqualFold(state.selectedPreset.Name, preset.Name) {
				currentIndex = idx
			}
		}
		auditPresetsModel.items = items
		auditPresetsModel.PublishItemsReset()
		if auditPresetsBox != nil {
			auditPresetsBox.SetCurrentIndex(currentIndex)
		}
		if auditPresetNameEdit != nil && state.selectedPreset == nil && len(state.auditPresets) == 0 {
			auditPresetNameEdit.SetText("")
		}
	}

	readAuditFilter := func() (controlclient.AuditEventFilter, error) {
		filter := controlclient.AuditEventFilter{
			ActorUserID: strings.TrimSpace(auditActorEdit.Text()),
			Type:        strings.TrimSpace(auditTypeEdit.Text()),
			Query:       strings.TrimSpace(auditQueryEdit.Text()),
			Limit:       200,
		}
		if value := strings.TrimSpace(auditFromEdit.Text()); value != "" {
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return controlclient.AuditEventFilter{}, fmt.Errorf("audit from-unix must be a whole number")
			}
			filter.FromUnix = parsed
		}
		if value := strings.TrimSpace(auditToEdit.Text()); value != "" {
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return controlclient.AuditEventFilter{}, fmt.Errorf("audit to-unix must be a whole number")
			}
			filter.ToUnix = parsed
		}
		return filter, nil
	}

	writeAuditFilter := func(filter controlclient.AuditEventFilter) {
		if auditActorEdit != nil {
			auditActorEdit.SetText(strings.TrimSpace(filter.ActorUserID))
		}
		if auditTypeEdit != nil {
			auditTypeEdit.SetText(strings.TrimSpace(filter.Type))
		}
		if auditQueryEdit != nil {
			auditQueryEdit.SetText(strings.TrimSpace(filter.Query))
		}
		if auditFromEdit != nil {
			if filter.FromUnix > 0 {
				auditFromEdit.SetText(strconv.FormatInt(filter.FromUnix, 10))
			} else {
				auditFromEdit.SetText("")
			}
		}
		if auditToEdit != nil {
			if filter.ToUnix > 0 {
				auditToEdit.SetText(strconv.FormatInt(filter.ToUnix, 10))
			} else {
				auditToEdit.SetText("")
			}
		}
	}

	refreshAuditEvents := func() error {
		if state.currentSession == nil {
			state.auditEvents = nil
			updateAuditView()
			return nil
		}
		filter, err := readAuditFilter()
		if err != nil {
			return err
		}
		events, err := state.svc.ListAuditEvents(filter)
		if err != nil {
			return err
		}
		state.auditEvents = events
		updateAuditView()
		return nil
	}

	refreshAuditPresets := func() error {
		if state.currentSession == nil {
			state.auditPresets = nil
			state.selectedPreset = nil
			updateAuditPresetsView()
			return nil
		}
		presets, err := state.svc.ListAuditPresets()
		if err != nil {
			return err
		}
		selectedName := ""
		if state.selectedPreset != nil {
			selectedName = state.selectedPreset.Name
		}
		state.auditPresets = presets
		state.selectedPreset = nil
		for idx := range state.auditPresets {
			if selectedName != "" && strings.EqualFold(state.auditPresets[idx].Name, selectedName) {
				state.selectedPreset = &state.auditPresets[idx]
				break
			}
		}
		if state.selectedPreset == nil && len(state.auditPresets) > 0 {
			state.selectedPreset = &state.auditPresets[0]
		}
		updateAuditPresetsView()
		return nil
	}

	refreshIncidentReports := func() error {
		if state.currentSession == nil {
			state.incidentReports = nil
			updateIncidentView()
			return nil
		}
		incidents, err := state.svc.ListIncidentReports()
		if err != nil {
			return err
		}
		state.incidentReports = incidents
		updateIncidentView()
		return nil
	}

	updateNetworkList := func() {
		items := make([]string, 0, len(state.networks))
		for _, network := range state.networks {
			items = append(items, formatNetworkSummaryLine(network, state.agentStatus))
		}
		networksModel.items = items
		networksModel.PublishItemsReset()
	}

	updatePeerList := func() {
		var peerLines []string
		for _, peer := range dedupePeersForChoices(state.peers) {
			peerLines = append(peerLines, formatPeerLine(peer, state.agentStatus, state.selected))
		}
		if len(peerLines) == 0 {
			peerLines = []string{"No peers yet"}
		}
		peersView.SetText(strings.Join(peerLines, "\r\n"))
	}

	selectedPeerChoiceID := func(box *walk.ComboBox, choices []peerChoice) string {
		if box == nil {
			return ""
		}
		index := box.CurrentIndex()
		if index < 0 || index >= len(choices) {
			return ""
		}
		return strings.TrimSpace(choices[index].ID)
	}

	applyPeerChoices := func(box *walk.ComboBox, choices []peerChoice, preferredID string) {
		if box == nil {
			return
		}
		labels := make([]string, 0, len(choices))
		selectedIndex := 0
		for idx, choice := range choices {
			labels = append(labels, choice.Label)
			if preferredID != "" && strings.EqualFold(choice.ID, preferredID) {
				selectedIndex = idx
			}
		}
		if len(labels) == 0 {
			labels = []string{"-"}
			selectedIndex = -1
		}
		if err := box.SetModel(labels); err == nil {
			_ = box.SetCurrentIndex(selectedIndex)
		}
	}

	updateTransferRecipientChoices := func() {
		currentTransferRecipientID := selectedPeerChoiceID(transferToPeerBox, transferRecipientChoices)
		sourcePeerID := selectedPeerChoiceID(transferFromPeerBox, transferSenderChoices)
		transferRecipientChoices = buildRecipientPeerChoices(state.peers, sourcePeerID)
		applyPeerChoices(transferToPeerBox, transferRecipientChoices, currentTransferRecipientID)
	}

	updatePeerChoiceControls := func() {
		currentMessageSenderID := selectedPeerChoiceID(messageFromPeerBox, messageSenderChoices)
		currentMessageFilterID := selectedPeerChoiceID(messageFilterPeerBox, messageFilterChoices)
		currentTransferSenderID := selectedPeerChoiceID(transferFromPeerBox, transferSenderChoices)
		currentTransferFilterID := selectedPeerChoiceID(transferFilterPeerBox, transferFilterChoices)

		messageSenderChoices = buildOperatorPeerChoices(state.peers, state.agentStatus, true)
		if currentMessageSenderID == "" {
			currentMessageSenderID = preferredOperatorPeerID(state.peers, state.agentStatus)
		}
		applyPeerChoices(messageFromPeerBox, messageSenderChoices, currentMessageSenderID)

		messageFilterChoices = buildFilterPeerChoices(state.peers)
		applyPeerChoices(messageFilterPeerBox, messageFilterChoices, currentMessageFilterID)

		transferSenderChoices = buildOperatorPeerChoices(state.peers, state.agentStatus, true)
		if currentTransferSenderID == "" {
			currentTransferSenderID = preferredOperatorPeerID(state.peers, state.agentStatus)
		}
		applyPeerChoices(transferFromPeerBox, transferSenderChoices, currentTransferSenderID)
		updateTransferRecipientChoices()

		transferFilterChoices = buildFilterPeerChoices(state.peers)
		applyPeerChoices(transferFilterPeerBox, transferFilterChoices, currentTransferFilterID)
	}

	updateMessagesView := func() {
		if messagesView == nil {
			return
		}
		query := strings.TrimSpace(textOfLineEdit(messageFilterEdit))
		fromPeerID := selectedPeerChoiceID(messageFilterPeerBox, messageFilterChoices)
		filtered := filterMessages(state.messages, query, fromPeerID, state.peers)
		if len(filtered) == 0 && (query != "" || fromPeerID != "") {
			messagesView.SetText("No messages match the current filters.")
			return
		}
		messagesView.SetText(formatMessagesWithPeers(filtered, state.peers))
	}

	updateFileTransferList := func() {
		query := strings.TrimSpace(textOfLineEdit(transferFilterEdit))
		mailboxFilter := currentComboBoxText(transferMailboxBox)
		statusFilter := currentComboBoxText(transferStatusFilterBox)
		peerFilterID := selectedPeerChoiceID(transferFilterPeerBox, transferFilterChoices)
		visibleFileTransfers = filterFileTransfers(state.fileTransfers, query, mailboxFilter, statusFilter, peerFilterID, state.peers, state.agentStatus)
		items := make([]string, 0, len(visibleFileTransfers))
		currentIndex := -1
		selectedTransferID := ""
		if state.selectedTransfer != nil {
			selectedTransferID = state.selectedTransfer.ID
		}
		for idx, transfer := range visibleFileTransfers {
			items = append(items, formatFileTransferSummaryLineWithPeers(transfer, state.peers))
			if state.selectedTransfer != nil && state.selectedTransfer.ID == transfer.ID {
				currentIndex = idx
			}
		}
		if currentIndex < 0 {
			state.selectedTransfer = nil
			state.transferLocalState = nil
			if len(visibleFileTransfers) > 0 {
				for idx := range visibleFileTransfers {
					if visibleFileTransfers[idx].ID == selectedTransferID {
						state.selectedTransfer = &visibleFileTransfers[idx]
						currentIndex = idx
						break
					}
				}
			}
			if state.selectedTransfer == nil && len(visibleFileTransfers) > 0 {
				state.selectedTransfer = &visibleFileTransfers[0]
				currentIndex = 0
			}
		}
		fileTransfersModel.items = items
		fileTransfersModel.PublishItemsReset()
		if fileTransfersBox != nil {
			_ = fileTransfersBox.SetCurrentIndex(currentIndex)
		}
	}

	updateFileTransferDetails := func() {
		if fileTransferDetailsView == nil {
			return
		}
		if state.selectedTransfer == nil && len(visibleFileTransfers) == 0 && (strings.TrimSpace(textOfLineEdit(transferFilterEdit)) != "" || !strings.EqualFold(currentComboBoxText(transferMailboxBox), "All Transfers") || !strings.EqualFold(currentComboBoxText(transferStatusFilterBox), "All Statuses") || selectedPeerChoiceID(transferFilterPeerBox, transferFilterChoices) != "") {
			fileTransferDetailsView.SetText("No file transfers match the current filters.")
			return
		}
		localState := state.transferLocalState
		if state.selectedTransfer != nil {
			refreshed, err := state.svc.GetFileTransferLocalState(state.selectedTransfer.ID)
			if err == nil {
				localState = refreshed
				state.transferLocalState = refreshed
			}
		} else {
			state.transferLocalState = nil
			localState = nil
		}
		fileTransferDetailsView.SetText(formatFileTransferDetailsWithPeersAndLocalState(state.selectedTransfer, state.peers, localState))
		if transferProgressEdit != nil {
			if state.selectedTransfer != nil {
				transferProgressEdit.SetText(strconv.Itoa(state.selectedTransfer.ProgressPercent))
			} else {
				transferProgressEdit.SetText("0")
			}
		}
		if transferReasonEdit != nil {
			if state.selectedTransfer != nil {
				transferReasonEdit.SetText(strings.TrimSpace(state.selectedTransfer.CancelReason))
			} else {
				transferReasonEdit.SetText("")
			}
		}
	}

	updateDetails := func() {
		if state.selected == nil {
			state.peers = nil
			state.tunnels = nil
			state.messages = nil
			state.fileTransfers = nil
			state.selectedTransfer = nil
			state.transferLocalState = nil
			updateRoutingPolicyControls()
			updateGroupTrafficControls()
			updateNameResolutionControls()
			updateFileTransferPolicyControls()
			updatePeerChoiceControls()
			peersView.SetText("Select a network to view peers.")
			tunnelsView.SetText("Select a network to view tunnels.")
			if messagesView != nil {
				messagesView.SetText("Select a network to view messages.")
			}
			updateFileTransferList()
			updateFileTransferDetails()
			updateDevicesView()
			updateDiagnostics()
			return
		}

		peers, err := state.svc.ListPeers(state.selected.ID)
		if err != nil {
			showWinError(mw, err)
			return
		}
		tunnels, err := state.svc.ListTunnels(state.selected.ID)
		if err != nil {
			showWinError(mw, err)
			return
		}
		messages, err := state.svc.ListMessages(state.selected.ID)
		if err != nil {
			showWinError(mw, err)
			return
		}
		fileTransfers, err := state.svc.ListFileTransfers(state.selected.ID)
		if err != nil {
			showWinError(mw, err)
			return
		}

		state.peers = peers
		state.tunnels = tunnels
		state.messages = messages
		selectedTransferID := ""
		if state.selectedTransfer != nil {
			selectedTransferID = state.selectedTransfer.ID
		}
		state.fileTransfers = fileTransfers
		state.selectedTransfer = nil
		state.transferLocalState = nil
		for idx := range state.fileTransfers {
			if state.fileTransfers[idx].ID == selectedTransferID {
				state.selectedTransfer = &state.fileTransfers[idx]
				break
			}
		}
		if state.selectedTransfer == nil && len(state.fileTransfers) > 0 {
			state.selectedTransfer = &state.fileTransfers[0]
		}

		updatePeerChoiceControls()
		updatePeerList()
		updateMessagesView()
		updateFileTransferList()
		updateFileTransferDetails()
		updateDevicesView()

		var tunnelLines []string
		for _, tunnel := range tunnels {
			createdAt := time.Unix(tunnel.CreatedAtUnix, 0).Format(time.RFC3339)
			tunnelLines = append(tunnelLines, fmt.Sprintf(
				"%s | mode=%s | state=%s | %s -> %s | %s",
				tunnel.ID,
				firstNonEmpty(tunnel.Mode, "-"),
				firstNonEmpty(tunnel.State, "-"),
				tunnel.PeerAID,
				tunnel.PeerBID,
				createdAt,
			))
		}
		if len(tunnelLines) == 0 {
			tunnelLines = []string{"No tunnels yet"}
		}
		tunnelsView.SetText(strings.Join(tunnelLines, "\r\n"))
		updateDiagnostics()
		updateStatus("Loaded details for " + state.selected.Name)
	}

	refreshAgentStatus := func(showErrors bool) error {
		status, err := state.svc.GetStatus()
		if err != nil {
			if showErrors {
				showWinError(mw, err)
			}
			return err
		}
		applyStatus(status)
		updateUserLabel()
		updatePeerList()
		updateDiagnostics()
		return nil
	}

	refreshNetworks := func() {
		status, err := state.svc.SetServerBaseURL(serverEdit.Text())
		if err != nil {
			showWinError(mw, err)
			return
		}
		applyStatus(status)
		updateUserLabel()
		updateDiagnostics()
		networks, err := state.svc.ListNetworks()
		if err != nil {
			showWinError(mw, err)
			return
		}
		selectedID := ""
		if state.selected != nil {
			selectedID = state.selected.ID
		}
		state.networks = networks
		state.selected = nil
		for idx := range state.networks {
			if state.networks[idx].ID == selectedID {
				state.selected = &state.networks[idx]
				break
			}
		}
		if state.selected == nil && len(state.networks) > 0 {
			state.selected = &state.networks[0]
		}
		updateNetworkList()
		if networksBox != nil && state.selected != nil {
			for idx := range state.networks {
				if state.networks[idx].ID == state.selected.ID {
					networksBox.SetCurrentIndex(idx)
					break
				}
			}
		}
		updateRoutingPolicyControls()
		updateGroupTrafficControls()
		updateNameResolutionControls()
		updateFileTransferPolicyControls()
		updateDevicesView()
		updateDiagnostics()
		updateStatus(fmt.Sprintf("Loaded %d networks", len(networks)))
		updateDetails()
	}

	applyAdapterMTU := func() {
		raw := ""
		if mtuEdit != nil {
			raw = strings.TrimSpace(mtuEdit.Text())
		}
		mtu, err := strconv.Atoi(raw)
		if err != nil {
			showWinError(mw, fmt.Errorf("adapter MTU must be a whole number"))
			return
		}
		status, err := state.svc.SetAdapterMTU(mtu)
		if err != nil {
			showWinError(mw, err)
			return
		}
		applyStatus(status)
		updateDiagnostics()
		updateStatus(fmt.Sprintf("Applied adapter MTU %d", mtu))
	}

	login := func() {
		if _, err := state.svc.SetServerBaseURL(serverEdit.Text()); err != nil {
			showWinError(mw, err)
			return
		}
		status, err := state.svc.Login(strings.TrimSpace(emailEdit.Text()), passwordEdit.Text())
		if err != nil {
			showWinError(mw, err)
			return
		}
		applyStatus(status)
		if err := refreshSessions(); err != nil {
			showWinError(mw, err)
			return
		}
		if err := refreshDevices(); err != nil {
			showWinError(mw, err)
			return
		}
		if err := refreshAuditPresets(); err != nil {
			showWinError(mw, err)
			return
		}
		if err := refreshAuditEvents(); err != nil {
			showWinError(mw, err)
			return
		}
		if err := refreshIncidentReports(); err != nil {
			showWinError(mw, err)
			return
		}
		updateUserLabel()
		updateStatus("Signed in through Ole Agent")
		refreshNetworks()
	}

	reconnect := func() {
		status, err := state.svc.Reconnect()
		if err != nil {
			showWinError(mw, err)
			return
		}
		applyStatus(status)
		updateUserLabel()
		if err := refreshSessions(); err != nil {
			showWinError(mw, err)
			return
		}
		if err := refreshDevices(); err != nil {
			showWinError(mw, err)
			return
		}
		if err := refreshAuditPresets(); err != nil {
			showWinError(mw, err)
			return
		}
		if err := refreshAuditEvents(); err != nil {
			showWinError(mw, err)
			return
		}
		if err := refreshIncidentReports(); err != nil {
			showWinError(mw, err)
			return
		}
		refreshNetworks()
		updateStatus("Reconnected through Ole Agent")
	}

	checkForUpdates := func() {
		status, err := state.svc.CheckForUpdates()
		if err != nil {
			showWinError(mw, err)
			return
		}
		applyStatus(status)
		updateDiagnostics()
		if status.Update.Available {
			updateStatus("Update available: " + firstNonEmpty(status.Update.LatestVersion, "-"))
			return
		}
		updateStatus("Ole Desktop is up to date")
	}

	downloadUpdate := func() {
		status, err := state.svc.DownloadUpdate()
		if err != nil {
			showWinError(mw, err)
			return
		}
		applyStatus(status)
		updateDiagnostics()
		updateStatus("Update downloaded to " + firstNonEmpty(status.Update.DownloadedPath, "-"))
	}

	downloadRollback := func() {
		status, err := state.svc.DownloadRollback()
		if err != nil {
			showWinError(mw, err)
			return
		}
		applyStatus(status)
		updateDiagnostics()
		updateStatus("Rollback downloaded to " + firstNonEmpty(status.Update.RollbackDownloadedPath, "-"))
	}

	applyUpdateChannel := func() {
		status, err := state.svc.SetUpdateChannel(currentComboBoxText(updateChannelBox))
		if err != nil {
			showWinError(mw, err)
			return
		}
		applyStatus(status)
		updateDiagnostics()
		updateStatus("Update channel set to " + firstNonEmpty(status.Update.Channel, "-"))
	}

	installUpdate := func() {
		if state.agentStatus == nil || !state.agentStatus.Update.Downloaded || strings.TrimSpace(state.agentStatus.Update.DownloadedPath) == "" {
			showWinError(mw, fmt.Errorf("no downloaded update is available to install"))
			return
		}
		cmd := exec.Command(state.agentStatus.Update.DownloadedPath)
		if err := cmd.Start(); err != nil {
			showWinError(mw, err)
			return
		}
		updateStatus("Started installer: " + state.agentStatus.Update.DownloadedPath)
	}

	installRollback := func() {
		if state.agentStatus == nil || !state.agentStatus.Update.RollbackDownloaded || strings.TrimSpace(state.agentStatus.Update.RollbackDownloadedPath) == "" {
			showWinError(mw, fmt.Errorf("no rollback release is available"))
			return
		}
		cmd := exec.Command(state.agentStatus.Update.RollbackDownloadedPath)
		if err := cmd.Start(); err != nil {
			showWinError(mw, err)
			return
		}
		updateStatus("Started rollback installer: " + state.agentStatus.Update.RollbackDownloadedPath)
	}

	register := func() {
		if _, err := state.svc.SetServerBaseURL(serverEdit.Text()); err != nil {
			showWinError(mw, err)
			return
		}
		user, err := state.svc.Register(strings.TrimSpace(emailEdit.Text()), passwordEdit.Text())
		if err != nil {
			showWinError(mw, err)
			return
		}
		updateStatus("User registered: " + user.Email)
		walk.MsgBox(mw, "Ole", "Registration complete. You can now sign in.", walk.MsgBoxIconInformation)
	}

	logout := func() {
		if state.currentSession == nil {
			updateStatus("No active session")
			return
		}
		if err := state.svc.Logout(); err != nil {
			showWinError(mw, err)
			return
		}
		if err := refreshAgentStatus(false); err != nil {
			applyStatus(&clientagent.Status{ServerBaseURL: serverEdit.Text()})
		}
		clearCollections()
		updatePeerChoiceControls()
		updateUserLabel()
		updateSessionList()
		updateDeviceList()
		updateDevicesView()
		updateAuditPresetsView()
		updateAuditView()
		updateNetworkList()
		peersView.SetText("")
		tunnelsView.SetText("")
		updateMessagesView()
		updateFileTransferList()
		updateFileTransferDetails()
		updateDiagnostics()
		updateIncidentView()
		updateStatus("Disconnected from Ole Agent session")
	}

	revokeSelectedSession := func() {
		if state.selectedSession == nil {
			showWinError(mw, fmt.Errorf("select a session first"))
			return
		}
		status, err := state.svc.RevokeSession(state.selectedSession.ID)
		if err != nil {
			showWinError(mw, err)
			return
		}
		applyStatus(status)
		if state.currentSession == nil {
			clearCollections()
			updatePeerChoiceControls()
			updateUserLabel()
			updateSessionList()
			updateDeviceList()
			updateDevicesView()
			updateAuditPresetsView()
			updateAuditView()
			updateNetworkList()
			peersView.SetText("")
			tunnelsView.SetText("")
			updateMessagesView()
			updateFileTransferList()
			updateFileTransferDetails()
			updateDiagnostics()
			updateIncidentView()
			updateStatus("Current session revoked; agent disconnected")
			return
		}
		if err := refreshSessions(); err != nil {
			showWinError(mw, err)
			return
		}
		if err := refreshDevices(); err != nil {
			showWinError(mw, err)
			return
		}
		if err := refreshAuditPresets(); err != nil {
			showWinError(mw, err)
			return
		}
		if err := refreshAuditEvents(); err != nil {
			showWinError(mw, err)
			return
		}
		if err := refreshIncidentReports(); err != nil {
			showWinError(mw, err)
			return
		}
		updateStatus("Session revoked")
	}

	revokeAllSessions := func() {
		if state.currentSession == nil {
			showWinError(mw, fmt.Errorf("no active session is available"))
			return
		}
		status, err := state.svc.RevokeAllSessions()
		if err != nil {
			showWinError(mw, err)
			return
		}
		applyStatus(status)
		clearCollections()
		updatePeerChoiceControls()
		updateUserLabel()
		updateSessionList()
		updateDeviceList()
		updateDevicesView()
		updateAuditPresetsView()
		updateAuditView()
		updateNetworkList()
		peersView.SetText("")
		tunnelsView.SetText("")
		updateMessagesView()
		updateFileTransferList()
		updateFileTransferDetails()
		updateDiagnostics()
		updateIncidentView()
		updateStatus("All sessions revoked; sign in again to continue")
	}

	saveAuditPreset := func() {
		if state.currentSession == nil {
			showWinError(mw, fmt.Errorf("sign in first"))
			return
		}
		filter, err := readAuditFilter()
		if err != nil {
			showWinError(mw, err)
			return
		}
		name := strings.TrimSpace(auditPresetNameEdit.Text())
		if name == "" {
			showWinError(mw, fmt.Errorf("audit preset name is required"))
			return
		}
		presets, err := state.svc.SaveAuditPreset(name, filter)
		if err != nil {
			showWinError(mw, err)
			return
		}
		state.auditPresets = presets
		state.selectedPreset = nil
		for idx := range state.auditPresets {
			if strings.EqualFold(state.auditPresets[idx].Name, name) {
				state.selectedPreset = &state.auditPresets[idx]
				break
			}
		}
		updateAuditPresetsView()
		if auditPresetNameEdit != nil {
			auditPresetNameEdit.SetText(name)
		}
		updateStatus("Saved audit preset: " + name)
	}

	applySelectedAuditPreset := func() {
		if state.selectedPreset == nil {
			showWinError(mw, fmt.Errorf("select an audit preset first"))
			return
		}
		writeAuditFilter(state.selectedPreset.Filter())
		if err := refreshAuditEvents(); err != nil {
			showWinError(mw, err)
			return
		}
		updateStatus("Applied audit preset: " + state.selectedPreset.Name)
	}

	deleteSelectedAuditPreset := func() {
		if state.selectedPreset == nil {
			showWinError(mw, fmt.Errorf("select an audit preset first"))
			return
		}
		name := state.selectedPreset.Name
		presets, err := state.svc.DeleteAuditPreset(name)
		if err != nil {
			showWinError(mw, err)
			return
		}
		state.auditPresets = presets
		state.selectedPreset = nil
		if len(state.auditPresets) > 0 {
			state.selectedPreset = &state.auditPresets[0]
		}
		updateAuditPresetsView()
		if auditPresetNameEdit != nil {
			if state.selectedPreset != nil {
				auditPresetNameEdit.SetText(state.selectedPreset.Name)
			} else {
				auditPresetNameEdit.SetText("")
			}
		}
		updateStatus("Deleted audit preset: " + name)
	}

	copySelectedFingerprint := func() {
		if state.selectedDevice == nil {
			showWinError(mw, fmt.Errorf("select a device first"))
			return
		}
		fingerprint := strings.TrimSpace(state.selectedDevice.Fingerprint)
		if fingerprint == "" {
			showWinError(mw, fmt.Errorf("device fingerprint is not available"))
			return
		}
		if err := walk.Clipboard().SetText(fingerprint); err != nil {
			showWinError(mw, err)
			return
		}
		updateStatus("Copied device fingerprint for " + firstNonEmpty(state.selectedDevice.Name, state.selectedDevice.ID))
	}

	createNetwork := func() {
		if state.currentUser == nil {
			showWinError(mw, fmt.Errorf("sign in first"))
			return
		}
		fileTransferMaxBytes, err := parseFileTransferMaxBytes(textOfLineEdit(createFileTransferMaxBytesEdit))
		if err != nil {
			showWinError(mw, err)
			return
		}
		network, err := state.svc.CreateNetworkWithOptions(strings.TrimSpace(networkNameEdit.Text()), accessBox.Text(), controlclient.NetworkCreateOptions{
			DeviceApprovalRequired:  requireApprovalBox != nil && requireApprovalBox.Checked(),
			RoutingPolicy:           currentComboBoxText(createRoutingPolicyBox),
			GroupTrafficPolicy:      currentComboBoxText(createGroupTrafficBox),
			NameResolutionMode:      currentComboBoxText(createNameResolutionBox),
			DNSLabel:                strings.TrimSpace(textOfLineEdit(createDNSLabelEdit)),
			FileTransfersEnabledSet: true,
			FileTransfersEnabled:    currentComboBoxText(createFileTransfersBox) != "DISABLED",
			FileTransferMaxBytes:    fileTransferMaxBytes,
		})
		if err != nil {
			showWinError(mw, err)
			return
		}
		networkNameEdit.SetText("")
		if requireApprovalBox != nil {
			requireApprovalBox.SetChecked(false)
		}
		if createRoutingPolicyBox != nil {
			createRoutingPolicyBox.SetCurrentIndex(0)
		}
		if createGroupTrafficBox != nil {
			createGroupTrafficBox.SetCurrentIndex(0)
		}
		if createNameResolutionBox != nil {
			createNameResolutionBox.SetCurrentIndex(0)
		}
		if createDNSLabelEdit != nil {
			createDNSLabelEdit.SetText("")
		}
		if createFileTransfersBox != nil {
			createFileTransfersBox.SetCurrentIndex(0)
		}
		if createFileTransferMaxBytesEdit != nil {
			createFileTransferMaxBytesEdit.SetText(strconv.FormatInt(defaultNetworkFileTransferMaxBytes(), 10))
		}
		updateStatus("Created network: " + network.Name)
		refreshNetworks()
	}

	applySelectedNetworkRoutingPolicy := func() {
		if state.selected == nil {
			showWinError(mw, fmt.Errorf("select a network first"))
			return
		}
		network, err := state.svc.UpdateNetworkRoutingPolicy(state.selected.ID, currentComboBoxText(selectedRoutingPolicyBox))
		if err != nil {
			showWinError(mw, err)
			return
		}
		for idx := range state.networks {
			if state.networks[idx].ID == network.ID {
				state.networks[idx] = *network
				state.selected = &state.networks[idx]
				break
			}
		}
		updateNetworkList()
		updateRoutingPolicyControls()
		updateDevicesView()
		updateDiagnostics()
		updateStatus("Updated network routing policy: " + firstNonEmpty(state.selected.Name, state.selected.ID))
	}

	applySelectedNetworkGroupTrafficPolicy := func() {
		if state.selected == nil {
			showWinError(mw, fmt.Errorf("select a network first"))
			return
		}
		network, err := state.svc.UpdateNetworkGroupTrafficPolicy(state.selected.ID, currentComboBoxText(selectedGroupTrafficBox))
		if err != nil {
			showWinError(mw, err)
			return
		}
		for idx := range state.networks {
			if state.networks[idx].ID == network.ID {
				state.networks[idx] = *network
				state.selected = &state.networks[idx]
				break
			}
		}
		updateNetworkList()
		updateGroupTrafficControls()
		updateDevicesView()
		updateDiagnostics()
		updateStatus("Updated network group traffic policy: " + firstNonEmpty(state.selected.Name, state.selected.ID))
	}

	applySelectedNetworkNameResolution := func() {
		if state.selected == nil {
			showWinError(mw, fmt.Errorf("select a network first"))
			return
		}
		network, err := state.svc.UpdateNetworkNameResolution(state.selected.ID, currentComboBoxText(selectedNameResolutionBox), strings.TrimSpace(textOfLineEdit(selectedDNSLabelEdit)))
		if err != nil {
			showWinError(mw, err)
			return
		}
		for idx := range state.networks {
			if state.networks[idx].ID == network.ID {
				state.networks[idx] = *network
				state.selected = &state.networks[idx]
				break
			}
		}
		updateNetworkList()
		updateRoutingPolicyControls()
		updateGroupTrafficControls()
		updateNameResolutionControls()
		updateFileTransferPolicyControls()
		updateDevicesView()
		updateDiagnostics()
		updateStatus("Updated network DNS policy: " + firstNonEmpty(state.selected.Name, state.selected.ID))
	}

	applySelectedNetworkFileTransferPolicy := func() {
		if state.selected == nil {
			showWinError(mw, fmt.Errorf("select a network first"))
			return
		}
		maxBytes, err := parseFileTransferMaxBytes(textOfLineEdit(selectedFileTransferMaxBytesEdit))
		if err != nil {
			showWinError(mw, err)
			return
		}
		network, err := state.svc.UpdateNetworkFileTransferPolicy(state.selected.ID, currentComboBoxText(selectedFileTransfersBox) != "DISABLED", maxBytes)
		if err != nil {
			showWinError(mw, err)
			return
		}
		for idx := range state.networks {
			if state.networks[idx].ID == network.ID {
				state.networks[idx] = *network
				state.selected = &state.networks[idx]
				break
			}
		}
		updateNetworkList()
		updateRoutingPolicyControls()
		updateGroupTrafficControls()
		updateNameResolutionControls()
		updateFileTransferPolicyControls()
		updateDevicesView()
		updateDiagnostics()
		updateStatus("Updated network file transfer policy: " + firstNonEmpty(state.selected.Name, state.selected.ID))
	}

	approveSelectedDeviceForNetwork := func() {
		if state.selected == nil {
			showWinError(mw, fmt.Errorf("select a network first"))
			return
		}
		if state.selectedDevice == nil {
			showWinError(mw, fmt.Errorf("select a device first"))
			return
		}
		network, err := state.svc.ApproveNetworkDevice(state.selected.ID, state.selectedDevice.ID)
		if err != nil {
			showWinError(mw, err)
			return
		}
		for idx := range state.networks {
			if state.networks[idx].ID == network.ID {
				state.networks[idx] = *network
				state.selected = &state.networks[idx]
				break
			}
		}
		updateNetworkList()
		updateDevicesView()
		updateStatus("Approved device for network: " + firstNonEmpty(state.selectedDevice.Name, state.selectedDevice.ID))
	}

	revokeSelectedDeviceForNetwork := func() {
		if state.selected == nil {
			showWinError(mw, fmt.Errorf("select a network first"))
			return
		}
		if state.selectedDevice == nil {
			showWinError(mw, fmt.Errorf("select a device first"))
			return
		}
		network, err := state.svc.RevokeNetworkDeviceApproval(state.selected.ID, state.selectedDevice.ID)
		if err != nil {
			showWinError(mw, err)
			return
		}
		for idx := range state.networks {
			if state.networks[idx].ID == network.ID {
				state.networks[idx] = *network
				state.selected = &state.networks[idx]
				break
			}
		}
		updateNetworkList()
		updateDevicesView()
		updateStatus("Revoked device approval for network: " + firstNonEmpty(state.selectedDevice.Name, state.selectedDevice.ID))
	}

	joinByInvite := func() {
		if state.currentUser == nil {
			showWinError(mw, fmt.Errorf("sign in first"))
			return
		}
		network, err := state.svc.RedeemInvite(strings.TrimSpace(inviteCodeEdit.Text()))
		if err != nil {
			showWinError(mw, err)
			return
		}
		inviteCodeEdit.SetText("")
		updateStatus(formatJoinStatus(network, state.agentStatus))
		refreshNetworks()
	}

	createInvite := func() {
		if state.currentUser == nil || state.selected == nil {
			showWinError(mw, fmt.Errorf("select a network first"))
			return
		}
		ttl, err := strconv.Atoi(strings.TrimSpace(inviteTTLEdit.Text()))
		if err != nil {
			showWinError(mw, fmt.Errorf("ttl must be numeric"))
			return
		}
		maxUses, err := strconv.Atoi(strings.TrimSpace(inviteUsesEdit.Text()))
		if err != nil {
			showWinError(mw, fmt.Errorf("max uses must be numeric"))
			return
		}
		invite, err := state.svc.CreateInvite(state.selected.ID, ttl, maxUses)
		if err != nil {
			showWinError(mw, err)
			return
		}
		walk.MsgBox(mw, "Invite created", "Invite code: "+invite.Code, walk.MsgBoxIconInformation)
	}

	registerPeer := func() {
		if state.currentUser == nil || state.selected == nil {
			showWinError(mw, fmt.Errorf("select a network first"))
			return
		}
		if networkRequiresCurrentDeviceApproval(state.selected, state.agentStatus) {
			showWinError(mw, fmt.Errorf("device approval required"))
			return
		}
		peer, err := state.svc.RegisterPeer(state.selected.ID, strings.TrimSpace(endpointEdit.Text()))
		if err != nil {
			showWinError(mw, err)
			return
		}
		updateStatus("Registered peer: " + peer.ID)
		updateDetails()
	}

	rejoinSelectedNetwork := func() {
		if state.currentUser == nil || state.selected == nil {
			showWinError(mw, fmt.Errorf("select a network first"))
			return
		}
		if networkRequiresCurrentDeviceApproval(state.selected, state.agentStatus) {
			showWinError(mw, fmt.Errorf("device approval required"))
			return
		}
		status, err := state.svc.RejoinNetwork(state.selected.ID, strings.TrimSpace(endpointEdit.Text()))
		if err != nil {
			showWinError(mw, err)
			return
		}
		applyStatus(status)
		updateUserLabel()
		updateDiagnostics()
		updateStatus("Rejoined network: " + state.selected.Name)
		updateDetails()
	}

	createTunnel := func() {
		if state.selected == nil {
			showWinError(mw, fmt.Errorf("select a network first"))
			return
		}
		tunnel, err := state.svc.CreateTunnel(state.selected.ID, strings.TrimSpace(peerAEdit.Text()), strings.TrimSpace(peerBEdit.Text()))
		if err != nil {
			showWinError(mw, err)
			return
		}
		updateStatus("Created tunnel: " + tunnel.ID)
		updateDetails()
	}

	sendSelectedNetworkMessage := func() {
		if state.selected == nil {
			showWinError(mw, fmt.Errorf("select a network first"))
			return
		}
		fromPeerID := selectedPeerChoiceID(messageFromPeerBox, messageSenderChoices)
		if fromPeerID == "" {
			showWinError(mw, fmt.Errorf("select a local peer to send the message from"))
			return
		}
		message, err := state.svc.SendMessage(state.selected.ID, fromPeerID, strings.TrimSpace(textOfLineEdit(messageTextEdit)))
		if err != nil {
			showWinError(mw, err)
			return
		}
		if messageTextEdit != nil {
			messageTextEdit.SetText("")
		}
		updateStatus("Sent message: " + message.ID)
		updateDetails()
	}

	browseTransferSourceFile := func() {
		dialog := walk.FileDialog{
			Title:       "Select File To Send",
			Filter:      "All Files (*.*)|*.*",
			FilterIndex: 1,
		}
		accepted, err := dialog.ShowOpen(mw)
		if err != nil {
			showWinError(mw, err)
			return
		}
		if !accepted {
			updateStatus("File selection cancelled")
			return
		}
		sourcePath := strings.TrimSpace(dialog.FilePath)
		if sourcePath == "" {
			updateStatus("File selection cancelled")
			return
		}
		fileName, sizeBytes, err := readTransferSourceMetadata(sourcePath)
		if err != nil {
			showWinError(mw, err)
			return
		}
		if transferSourcePathEdit != nil {
			transferSourcePathEdit.SetText(sourcePath)
		}
		if transferFileNameEdit != nil {
			transferFileNameEdit.SetText(fileName)
		}
		if transferSizeEdit != nil {
			transferSizeEdit.SetText(strconv.FormatInt(sizeBytes, 10))
		}
		updateStatus("Selected file for transfer: " + fileName)
	}

	uploadTransferPayloadFromPath := func(transfer FileTransfer, sourcePath string) (*controlclient.FileTransfer, int64, error) {
		fileName, sizeBytes, err := readTransferSourceMetadata(sourcePath)
		if err != nil {
			return nil, 0, err
		}
		if err := validateTransferUploadSource(transfer, sizeBytes); err != nil {
			return nil, 0, err
		}
		file, err := os.Open(sourcePath)
		if err != nil {
			return nil, 0, err
		}
		defer file.Close()

		startOffset := transfer.PayloadUploadedBytes
		if startOffset > 0 {
			if _, err := file.Seek(startOffset, io.SeekStart); err != nil {
				return nil, 0, err
			}
		}

		contentType := inferFileTransferContentType(firstNonEmpty(strings.TrimSpace(transfer.FileName), fileName))
		current := transfer
		offset := startOffset
		buffer := make([]byte, fileTransferGUIChunkSizeBytes)
		for {
			n, readErr := file.Read(buffer)
			if n > 0 {
				uploaded, err := state.svc.UploadFileTransferContentChunk(current.ID, contentType, offset, buffer[:n])
				if err != nil {
					return nil, startOffset, err
				}
				current = *uploaded
				offset = current.PayloadUploadedBytes
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return nil, startOffset, readErr
			}
		}
		return &current, startOffset, nil
	}

	registerTransferSourceFromPath := func(transfer *controlclient.FileTransfer, sourcePath string) (*controlclient.FileTransfer, error) {
		if transfer == nil {
			return nil, fmt.Errorf("file transfer is required")
		}
		contentType := inferFileTransferContentType(firstNonEmpty(strings.TrimSpace(transfer.FileName), filepath.Base(sourcePath)))
		return state.svc.RegisterFileTransferSource(transfer.ID, sourcePath, contentType)
	}

	resumeSelectedFileTransferUpload := func() {
		if state.selectedTransfer == nil {
			showWinError(mw, fmt.Errorf("select a file transfer first"))
			return
		}
		sourcePath := strings.TrimSpace(textOfLineEdit(transferSourcePathEdit))
		if sourcePath == "" {
			showWinError(mw, fmt.Errorf("choose the original local file first"))
			return
		}
		transfer, err := registerTransferSourceFromPath(state.selectedTransfer, sourcePath)
		if err != nil {
			updateDetails()
			showWinError(mw, err)
			return
		}
		if transfer.SizeBytes > defaultControlPlaneFileTransferPayloadMaxBytes() {
			updateDetails()
			updateStatus(fmt.Sprintf("Registered sender-online dataplane source: %s (%d bytes)", transfer.ID, transfer.SizeBytes))
			return
		}
		transfer, startOffset, err := uploadTransferPayloadFromPath(*transfer, sourcePath)
		if err != nil {
			updateDetails()
			showWinError(mw, err)
			return
		}
		updateDetails()
		switch {
		case transfer.PayloadReady && startOffset > 0:
			updateStatus(fmt.Sprintf("Resumed file transfer upload: %s (%d/%d bytes)", transfer.ID, transfer.PayloadUploadedBytes, transfer.SizeBytes))
		case transfer.PayloadReady:
			updateStatus(fmt.Sprintf("Uploaded file transfer payload: %s (%d bytes)", transfer.ID, transfer.PayloadUploadedBytes))
		default:
			updateStatus(fmt.Sprintf("Uploaded file transfer chunk(s): %s (%d/%d bytes)", transfer.ID, transfer.PayloadUploadedBytes, transfer.SizeBytes))
		}
	}

	createSelectedNetworkFileTransfer := func() {
		if state.selected == nil {
			showWinError(mw, fmt.Errorf("select a network first"))
			return
		}
		fromPeerID := selectedPeerChoiceID(transferFromPeerBox, transferSenderChoices)
		if fromPeerID == "" {
			showWinError(mw, fmt.Errorf("select a local sender peer first"))
			return
		}
		toPeerID := selectedPeerChoiceID(transferToPeerBox, transferRecipientChoices)
		if toPeerID == "" {
			showWinError(mw, fmt.Errorf("select a recipient peer first"))
			return
		}
		sourcePath := strings.TrimSpace(textOfLineEdit(transferSourcePathEdit))
		if sourcePath == "" {
			showWinError(mw, fmt.Errorf("choose a local file to send first"))
			return
		}
		_, sizeBytes, err := readTransferSourceMetadata(sourcePath)
		if err != nil {
			showWinError(mw, err)
			return
		}
		fileName := strings.TrimSpace(textOfLineEdit(transferFileNameEdit))
		if fileName == "" {
			fileName = filepath.Base(sourcePath)
		}
		transfer, err := state.svc.CreateFileTransfer(
			state.selected.ID,
			fromPeerID,
			toPeerID,
			fileName,
			sizeBytes,
		)
		if err != nil {
			showWinError(mw, err)
			return
		}
		state.selectedTransfer = &FileTransfer{ID: transfer.ID}
		transfer, err = registerTransferSourceFromPath(transfer, sourcePath)
		if err != nil {
			updateDetails()
			showWinError(mw, err)
			return
		}
		if transfer.SizeBytes <= defaultControlPlaneFileTransferPayloadMaxBytes() {
			transfer, _, err = uploadTransferPayloadFromPath(*transfer, sourcePath)
			if err != nil {
				updateDetails()
				showWinError(mw, err)
				return
			}
		}
		if transferSourcePathEdit != nil {
			transferSourcePathEdit.SetText("")
		}
		if transferFileNameEdit != nil {
			transferFileNameEdit.SetText("")
		}
		if transferSizeEdit != nil {
			transferSizeEdit.SetText("0")
		}
		updateDetails()
		if transfer.SizeBytes > defaultControlPlaneFileTransferPayloadMaxBytes() {
			updateStatus("Created sender-online dataplane file transfer: " + transfer.ID)
		} else {
			updateStatus("Created file transfer with payload: " + transfer.ID)
		}
	}

	acceptSelectedFileTransfer := func() {
		if state.selectedTransfer == nil {
			showWinError(mw, fmt.Errorf("select a file transfer first"))
			return
		}
		transfer, err := state.svc.AcceptFileTransfer(state.selectedTransfer.ID)
		if err != nil {
			showWinError(mw, err)
			return
		}
		updateStatus("Accepted file transfer: " + transfer.ID)
		updateDetails()
	}

	cancelSelectedFileTransfer := func() {
		if state.selectedTransfer == nil {
			showWinError(mw, fmt.Errorf("select a file transfer first"))
			return
		}
		transfer, err := state.svc.CancelFileTransfer(state.selectedTransfer.ID, strings.TrimSpace(textOfLineEdit(transferReasonEdit)))
		if err != nil {
			showWinError(mw, err)
			return
		}
		updateStatus("Canceled file transfer: " + transfer.ID)
		updateDetails()
	}

	updateSelectedFileTransferProgress := func() {
		if state.selectedTransfer == nil {
			showWinError(mw, fmt.Errorf("select a file transfer first"))
			return
		}
		progressPercent, err := strconv.Atoi(strings.TrimSpace(textOfLineEdit(transferProgressEdit)))
		if err != nil {
			showWinError(mw, fmt.Errorf("progress percent must be a whole number"))
			return
		}
		transfer, err := state.svc.UpdateFileTransferProgress(state.selectedTransfer.ID, progressPercent)
		if err != nil {
			showWinError(mw, err)
			return
		}
		updateStatus(fmt.Sprintf("Updated file transfer progress: %s -> %d%%", transfer.ID, transfer.ProgressPercent))
		updateDetails()
	}

	downloadSelectedFileTransfer := func() {
		if state.selectedTransfer == nil {
			showWinError(mw, fmt.Errorf("select a file transfer first"))
			return
		}
		dialog := walk.FileDialog{
			Title:          "Save Transferred File",
			InitialDirPath: fileTransferDownloadDir(),
			FilePath:       defaultFileTransferDownloadPath(state.selectedTransfer.FileName),
			Filter:         "All Files (*.*)|*.*",
			FilterIndex:    1,
		}
		accepted, err := dialog.ShowSave(mw)
		if err != nil {
			showWinError(mw, err)
			return
		}
		if !accepted {
			updateStatus("File download cancelled")
			return
		}
		targetPath := strings.TrimSpace(dialog.FilePath)
		if targetPath == "" {
			updateStatus("File download cancelled")
			return
		}
		startOffset := int64(0)
		resumed := false
		if info, statErr := os.Stat(targetPath); statErr == nil {
			targetState, err := inspectTransferDownloadTarget(info.Size(), state.selectedTransfer.SizeBytes)
			if err != nil {
				showWinError(mw, err)
				return
			}
			switch targetState {
			case transferDownloadTargetPartial:
				if promptYesNo(mw, "Resume Download", fmt.Sprintf("A partial file already exists at %s (%d of %d bytes). Resume the download?", targetPath, info.Size(), state.selectedTransfer.SizeBytes)) {
					startOffset = info.Size()
					resumed = true
				}
			case transferDownloadTargetComplete:
				if !promptYesNo(mw, "Overwrite Download", fmt.Sprintf("A file already exists at %s with the expected %d bytes. Overwrite it?", targetPath, info.Size())) {
					updateStatus("File download cancelled")
					return
				}
			}
		} else if !os.IsNotExist(statErr) {
			showWinError(mw, statErr)
			return
		}

		file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			showWinError(mw, err)
			return
		}
		if resumed {
			if _, err := file.Seek(startOffset, io.SeekStart); err != nil {
				_ = file.Close()
				showWinError(mw, err)
				return
			}
		} else {
			if err := file.Truncate(0); err != nil {
				_ = file.Close()
				showWinError(mw, err)
				return
			}
			if _, err := file.Seek(0, io.SeekStart); err != nil {
				_ = file.Close()
				showWinError(mw, err)
				return
			}
		}

		offset := startOffset
		for {
			chunk, err := state.svc.DownloadFileTransferContentChunk(state.selectedTransfer.ID, offset, fileTransferGUIChunkSizeBytes)
			if err != nil {
				_ = file.Close()
				showWinError(mw, err)
				return
			}
			if chunk.OffsetBytes != offset {
				_ = file.Close()
				showWinError(mw, fmt.Errorf("file transfer download offset mismatch: expected %d bytes, got %d", offset, chunk.OffsetBytes))
				return
			}
			if len(chunk.Payload) == 0 && !chunk.Complete {
				_ = file.Close()
				showWinError(mw, fmt.Errorf("file transfer download returned an empty chunk before completion"))
				return
			}
			if len(chunk.Payload) > 0 {
				if _, err := file.Write(chunk.Payload); err != nil {
					_ = file.Close()
					showWinError(mw, err)
					return
				}
			}
			offset = chunk.NextOffsetBytes
			if chunk.Complete {
				if err := file.Sync(); err != nil {
					_ = file.Close()
					showWinError(mw, err)
					return
				}
				break
			}
		}
		if err := file.Close(); err != nil {
			showWinError(mw, err)
			return
		}
		updateDetails()
		if resumed {
			updateStatus("Resumed file download to " + targetPath)
			return
		}
		updateStatus("Saved transferred file to " + targetPath)
	}

	exportDiagnostics := func() {
		bundle, err := state.svc.GetDiagnosticsBundle()
		if err != nil {
			showWinError(mw, err)
			return
		}
		data, err := json.MarshalIndent(bundle, "", "  ")
		if err != nil {
			showWinError(mw, err)
			return
		}
		dialog := walk.FileDialog{
			Title:          "Export Ole Diagnostics Bundle",
			InitialDirPath: diagnosticsExportDir(),
			FilePath:       diagnosticsExportName(),
			Filter:         "JSON Files (*.json)|*.json|All Files (*.*)|*.*",
			FilterIndex:    1,
		}
		accepted, err := dialog.ShowSave(mw)
		if err != nil {
			showWinError(mw, err)
			return
		}
		if !accepted {
			updateStatus("Diagnostics export cancelled")
			return
		}
		targetPath := strings.TrimSpace(dialog.FilePath)
		if targetPath == "" {
			updateStatus("Diagnostics export cancelled")
			return
		}
		if !strings.HasSuffix(strings.ToLower(targetPath), ".json") {
			targetPath += ".json"
		}
		if err := os.WriteFile(targetPath, data, 0o644); err != nil {
			showWinError(mw, err)
			return
		}
		updateStatus("Diagnostics bundle exported to " + targetPath)
		walk.MsgBox(mw, "Diagnostics exported", targetPath, walk.MsgBoxIconInformation)
	}

	exportAuditEvents := func() {
		if err := refreshAuditEvents(); err != nil {
			showWinError(mw, err)
			return
		}
		data, err := json.MarshalIndent(state.auditEvents, "", "  ")
		if err != nil {
			showWinError(mw, err)
			return
		}
		dialog := walk.FileDialog{
			Title:          "Export Ole Audit Events",
			InitialDirPath: diagnosticsExportDir(),
			FilePath:       auditExportName(),
			Filter:         "JSON Files (*.json)|*.json|All Files (*.*)|*.*",
			FilterIndex:    1,
		}
		accepted, err := dialog.ShowSave(mw)
		if err != nil {
			showWinError(mw, err)
			return
		}
		if !accepted {
			updateStatus("Audit export cancelled")
			return
		}
		targetPath := strings.TrimSpace(dialog.FilePath)
		if targetPath == "" {
			updateStatus("Audit export cancelled")
			return
		}
		if !strings.HasSuffix(strings.ToLower(targetPath), ".json") {
			targetPath += ".json"
		}
		if err := os.WriteFile(targetPath, data, 0o644); err != nil {
			showWinError(mw, err)
			return
		}
		updateStatus("Audit events exported to " + targetPath)
		walk.MsgBox(mw, "Audit exported", targetPath, walk.MsgBoxIconInformation)
	}

	exportIncidentReports := func() {
		if err := refreshIncidentReports(); err != nil {
			showWinError(mw, err)
			return
		}
		data, err := json.MarshalIndent(state.incidentReports, "", "  ")
		if err != nil {
			showWinError(mw, err)
			return
		}
		dialog := walk.FileDialog{
			Title:          "Export Ole Incident Reports",
			InitialDirPath: diagnosticsExportDir(),
			FilePath:       incidentExportName(),
			Filter:         "JSON Files (*.json)|*.json|All Files (*.*)|*.*",
			FilterIndex:    1,
		}
		accepted, err := dialog.ShowSave(mw)
		if err != nil {
			showWinError(mw, err)
			return
		}
		if !accepted {
			updateStatus("Incident export cancelled")
			return
		}
		targetPath := strings.TrimSpace(dialog.FilePath)
		if targetPath == "" {
			updateStatus("Incident export cancelled")
			return
		}
		if !strings.HasSuffix(strings.ToLower(targetPath), ".json") {
			targetPath += ".json"
		}
		if err := os.WriteFile(targetPath, data, 0o644); err != nil {
			showWinError(mw, err)
			return
		}
		updateStatus("Incident reports exported to " + targetPath)
		walk.MsgBox(mw, "Incident reports exported", targetPath, walk.MsgBoxIconInformation)
	}

	if err := (MainWindow{
		AssignTo: &mw,
		Title:    "Ole Desktop",
		MinSize:  Size{Width: 1360, Height: 820},
		Layout:   VBox{MarginsZero: true},
		Children: []Widget{
			Composite{
				Layout: VBox{Margins: Margins{Left: 16, Top: 16, Right: 16, Bottom: 8}},
				Children: []Widget{
					Label{Text: "Ole Desktop"},
					Label{Text: "Create or join a private Ole network from this PC"},
				},
			},
			HSplitter{
				Children: []Widget{
					Composite{
						Layout: VBox{Margins: Margins{Left: 16, Top: 8, Right: 8, Bottom: 16}},
						Children: []Widget{
							GroupBox{
								Title:  "Quick Start",
								Layout: VBox{},
								Children: []Widget{
									TextEdit{AssignTo: &quickStartView, ReadOnly: true, VScroll: true},
								},
							},
							GroupBox{
								Title:  "Detailed Guide",
								Layout: VBox{},
								Children: []Widget{
									TextEdit{AssignTo: &onboardingView, ReadOnly: true, VScroll: true},
								},
							},
							GroupBox{
								Title:  "1. Sign In To Ole",
								Layout: Grid{Columns: 2},
								Children: []Widget{
									Label{Text: "Use `Create Account` only once. On every device after that, just sign in."},
									HSpacer{},
									Label{Text: "Server Base URL"},
									LineEdit{AssignTo: &serverEdit, Text: clientagent.DefaultServerBaseURL},
									Label{Text: "Adapter MTU"},
									LineEdit{AssignTo: &mtuEdit},
									Label{Text: "Update Channel"},
									ComboBox{AssignTo: &updateChannelBox, Model: []string{"stable", "beta"}, CurrentIndex: 0},
									Label{Text: "Email"},
									LineEdit{AssignTo: &emailEdit},
									Label{Text: "Password"},
									LineEdit{AssignTo: &passwordEdit, PasswordMode: true},
								},
							},
							Composite{
								Layout: HBox{},
								Children: []Widget{
									PushButton{Text: "Create Account", OnClicked: register},
									PushButton{Text: "Sign In", OnClicked: login},
									PushButton{Text: "Reconnect", OnClicked: reconnect},
									PushButton{Text: "Logout", OnClicked: logout},
									PushButton{Text: "Check Updates", OnClicked: checkForUpdates},
									PushButton{Text: "Apply Update Channel", OnClicked: applyUpdateChannel},
									PushButton{Text: "Download Update", OnClicked: downloadUpdate},
									PushButton{Text: "Install Update", OnClicked: installUpdate},
									PushButton{Text: "Download Rollback", OnClicked: downloadRollback},
									PushButton{Text: "Install Rollback", OnClicked: installRollback},
									PushButton{Text: "Export Diagnostics", OnClicked: exportDiagnostics},
									PushButton{Text: "Refresh Ole Agent", OnClicked: func() {
										if err := refreshAgentStatus(true); err != nil {
											updateStatus("Unable to refresh Ole Agent diagnostics")
											return
										}
										updateStatus("Ole Agent diagnostics refreshed")
									}},
									PushButton{Text: "Apply MTU", OnClicked: applyAdapterMTU},
									PushButton{Text: "Refresh Networks", OnClicked: refreshNetworks},
								},
							},
							GroupBox{
								Title:  "Sessions",
								Layout: VBox{},
								Children: []Widget{
									Label{AssignTo: &userLabel, Text: "No active service session"},
									Composite{
										Layout: HBox{},
										Children: []Widget{
											PushButton{Text: "Refresh Sessions", OnClicked: func() {
												if state.currentSession == nil {
													updateStatus("No active session")
													return
												}
												if err := refreshSessions(); err != nil {
													showWinError(mw, err)
													return
												}
												updateStatus(fmt.Sprintf("Loaded %d sessions", len(state.sessions)))
											}},
											PushButton{Text: "Revoke Selected", OnClicked: revokeSelectedSession},
											PushButton{Text: "Revoke All Sessions", OnClicked: revokeAllSessions},
										},
									},
									ListBox{
										AssignTo: &sessionsBox,
										Model:    sessionsModel,
										OnCurrentIndexChanged: func() {
											index := sessionsBox.CurrentIndex()
											if index < 0 || index >= len(state.sessions) {
												state.selectedSession = nil
												updateSessionDetails()
												return
											}
											state.selectedSession = &state.sessions[index]
											updateSessionDetails()
										},
									},
									TextEdit{AssignTo: &sessionDetailsView, ReadOnly: true, VScroll: true},
								},
							},
							GroupBox{
								Title:  "Trusted Devices",
								Layout: VBox{},
								Children: []Widget{
									Composite{
										Layout: HBox{},
										Children: []Widget{
											PushButton{Text: "Refresh Devices", OnClicked: func() {
												if err := refreshDevices(); err != nil {
													showWinError(mw, err)
													return
												}
												updateStatus(fmt.Sprintf("Loaded %d devices", len(state.devices)))
											}},
											PushButton{Text: "Copy Fingerprint", OnClicked: copySelectedFingerprint},
											PushButton{Text: "Approve For Network", OnClicked: approveSelectedDeviceForNetwork},
											PushButton{Text: "Revoke For Network", OnClicked: revokeSelectedDeviceForNetwork},
										},
									},
									ListBox{
										AssignTo: &devicesBox,
										Model:    devicesModel,
										OnCurrentIndexChanged: func() {
											index := devicesBox.CurrentIndex()
											if index < 0 || index >= len(state.devices) {
												state.selectedDevice = nil
												updateDevicesView()
												return
											}
											state.selectedDevice = &state.devices[index]
											updateDevicesView()
										},
									},
									TextEdit{AssignTo: &devicesView, ReadOnly: true, VScroll: true},
								},
							},
							GroupBox{
								Title:  "Audit Events",
								Layout: VBox{},
								Children: []Widget{
									Composite{
										Layout: Grid{Columns: 2},
										Children: []Widget{
											Label{Text: "Actor User ID"},
											LineEdit{AssignTo: &auditActorEdit},
											Label{Text: "Type"},
											LineEdit{AssignTo: &auditTypeEdit},
											Label{Text: "Query"},
											LineEdit{AssignTo: &auditQueryEdit},
											Label{Text: "From Unix"},
											LineEdit{AssignTo: &auditFromEdit},
											Label{Text: "To Unix"},
											LineEdit{AssignTo: &auditToEdit},
										},
									},
									Composite{
										Layout: Grid{Columns: 2},
										Children: []Widget{
											Label{Text: "Preset Name"},
											LineEdit{AssignTo: &auditPresetNameEdit},
										},
									},
									Composite{
										Layout: HBox{},
										Children: []Widget{
											PushButton{Text: "Save Filter", OnClicked: saveAuditPreset},
											PushButton{Text: "Apply Selected", OnClicked: applySelectedAuditPreset},
											PushButton{Text: "Delete Selected", OnClicked: deleteSelectedAuditPreset},
											PushButton{Text: "Refresh Audit", OnClicked: func() {
												if err := refreshAuditEvents(); err != nil {
													showWinError(mw, err)
													return
												}
												updateStatus(fmt.Sprintf("Loaded %d audit events", len(state.auditEvents)))
											}},
											PushButton{Text: "Export Audit", OnClicked: exportAuditEvents},
										},
									},
									ListBox{
										AssignTo: &auditPresetsBox,
										Model:    auditPresetsModel,
										OnCurrentIndexChanged: func() {
											index := auditPresetsBox.CurrentIndex()
											if index < 0 || index >= len(state.auditPresets) {
												state.selectedPreset = nil
												updateAuditPresetsView()
												return
											}
											state.selectedPreset = &state.auditPresets[index]
											if auditPresetNameEdit != nil {
												auditPresetNameEdit.SetText(state.selectedPreset.Name)
											}
										},
									},
									TextEdit{AssignTo: &auditView, ReadOnly: true, VScroll: true},
								},
							},
							GroupBox{
								Title:  "Incident Reports",
								Layout: VBox{},
								Children: []Widget{
									Composite{
										Layout: HBox{},
										Children: []Widget{
											PushButton{Text: "Refresh Incidents", OnClicked: func() {
												if err := refreshIncidentReports(); err != nil {
													showWinError(mw, err)
													return
												}
												updateStatus(fmt.Sprintf("Loaded %d incident reports", len(state.incidentReports)))
											}},
											PushButton{Text: "Export Incidents", OnClicked: exportIncidentReports},
										},
									},
									TextEdit{AssignTo: &incidentView, ReadOnly: true, VScroll: true},
								},
							},
							GroupBox{
								Title:  "2A. Create Your Network",
								Layout: Grid{Columns: 2},
								Children: []Widget{
									Label{Text: "Use this on the first PC. Safe defaults are already selected for a simple private network."},
									HSpacer{},
									Label{Text: "Name"},
									LineEdit{AssignTo: &networkNameEdit},
									Label{Text: "Access"},
									ComboBox{AssignTo: &accessBox, Model: []string{"PRIVATE", "INVITE_ONLY"}, CurrentIndex: 1},
									Label{Text: "Sensitive"},
									CheckBox{AssignTo: &requireApprovalBox, Text: "Require device approval"},
									Label{Text: "Routing"},
									ComboBox{AssignTo: &createRoutingPolicyBox, Model: []string{"SPLIT", "FULL"}, CurrentIndex: 0},
									Label{Text: "Group Traffic"},
									ComboBox{AssignTo: &createGroupTrafficBox, Model: []string{"BLOCKED", "FLOOD"}, CurrentIndex: 0},
									Label{Text: "DNS Mode"},
									ComboBox{AssignTo: &createNameResolutionBox, Model: []string{"DEFAULT", "NETWORK_ONLY", "DISABLED"}, CurrentIndex: 0},
									Label{Text: "DNS Label"},
									LineEdit{AssignTo: &createDNSLabelEdit},
									Label{Text: "File Transfers"},
									ComboBox{AssignTo: &createFileTransfersBox, Model: []string{"ENABLED", "DISABLED"}, CurrentIndex: 0},
									Label{Text: "Max Bytes"},
									LineEdit{AssignTo: &createFileTransferMaxBytesEdit, Text: strconv.FormatInt(defaultNetworkFileTransferMaxBytes(), 10)},
									HSpacer{},
									PushButton{Text: "Create Network", OnClicked: createNetwork},
								},
							},
							GroupBox{
								Title:  "2B. Join By Invite",
								Layout: Grid{Columns: 2},
								Children: []Widget{
									Label{Text: "Use this on the second PC or after someone sends you an invite code."},
									HSpacer{},
									Label{Text: "Invite code"},
									LineEdit{AssignTo: &inviteCodeEdit},
									HSpacer{},
									PushButton{Text: "Join By Invite", OnClicked: joinByInvite},
								},
							},
							GroupBox{
								Title:  "2C. Share Invite Code",
								Layout: Grid{Columns: 2},
								Children: []Widget{
									Label{Text: "Create a code to connect another PC or another person to the selected network."},
									HSpacer{},
									Label{Text: "TTL sec"},
									LineEdit{AssignTo: &inviteTTLEdit, Text: "3600"},
									Label{Text: "Max uses"},
									LineEdit{AssignTo: &inviteUsesEdit, Text: "5"},
									HSpacer{},
									PushButton{Text: "Create Invite", OnClicked: createInvite},
								},
							},
						},
					},
					Composite{
						Layout: VBox{Margins: Margins{Left: 8, Top: 8, Right: 16, Bottom: 16}},
						Children: []Widget{
							GroupBox{
								Title:  "Networks",
								Layout: VBox{},
								Children: []Widget{
									ListBox{
										AssignTo: &networksBox,
										Model:    networksModel,
										OnCurrentIndexChanged: func() {
											index := networksBox.CurrentIndex()
											if index < 0 || index >= len(state.networks) {
												return
											}
											state.selected = &state.networks[index]
											updateRoutingPolicyControls()
											updateGroupTrafficControls()
											updateNameResolutionControls()
											updateFileTransferPolicyControls()
											updateDetails()
										},
									},
								},
							},
							GroupBox{
								Title:  "Routing Policy",
								Layout: Grid{Columns: 2},
								Children: []Widget{
									Label{Text: "Policy"},
									ComboBox{AssignTo: &selectedRoutingPolicyBox, Model: []string{"SPLIT", "FULL"}, CurrentIndex: 0},
									Label{Text: "Note"},
									Label{Text: "SPLIT keeps internet traffic local. FULL routes non-overlay IPv4 through an OWNER or ADMIN gateway when one is ready; otherwise the adapter stays pending gateway."},
									HSpacer{},
									PushButton{Text: "Apply Routing Policy", OnClicked: applySelectedNetworkRoutingPolicy},
								},
							},
							GroupBox{
								Title:  "Group Traffic",
								Layout: Grid{Columns: 2},
								Children: []Widget{
									Label{Text: "Policy"},
									ComboBox{AssignTo: &selectedGroupTrafficBox, Model: []string{"BLOCKED", "FLOOD"}, CurrentIndex: 0},
									Label{Text: "Note"},
									Label{Text: "FLOOD forwards IPv4 broadcast and multicast packets to connected peers on the selected network."},
									HSpacer{},
									PushButton{Text: "Apply Group Traffic Policy", OnClicked: applySelectedNetworkGroupTrafficPolicy},
								},
							},
							GroupBox{
								Title:  "Name Resolution",
								Layout: Grid{Columns: 2},
								Children: []Widget{
									Label{Text: "Mode"},
									ComboBox{AssignTo: &selectedNameResolutionBox, Model: []string{"DEFAULT", "NETWORK_ONLY", "DISABLED"}, CurrentIndex: 0},
									Label{Text: "DNS Label"},
									LineEdit{AssignTo: &selectedDNSLabelEdit},
									HSpacer{},
									PushButton{Text: "Apply DNS Policy", OnClicked: applySelectedNetworkNameResolution},
								},
							},
							GroupBox{
								Title:  "File Transfers",
								Layout: Grid{Columns: 2},
								Children: []Widget{
									Label{Text: "Policy"},
									ComboBox{AssignTo: &selectedFileTransfersBox, Model: []string{"ENABLED", "DISABLED"}, CurrentIndex: 0},
									Label{Text: "Max Bytes"},
									LineEdit{AssignTo: &selectedFileTransferMaxBytesEdit, Text: strconv.FormatInt(defaultNetworkFileTransferMaxBytes(), 10)},
									Label{Text: "Note"},
									Label{Text: "The current control-plane payload path streams 1 MiB JSON/base64 chunks and is capped at 67108864 bytes (64 MiB) per transfer; larger transfers can ride the sender-online dataplane path instead."},
									HSpacer{},
									PushButton{Text: "Apply File Transfer Policy", OnClicked: applySelectedNetworkFileTransferPolicy},
								},
							},
							GroupBox{
								Title:  "3. Connect This PC",
								Layout: Grid{Columns: 2},
								Children: []Widget{
									Label{Text: "After you create or join a network, connect this PC to it here."},
									HSpacer{},
									Label{Text: "Endpoint"},
									LineEdit{AssignTo: &endpointEdit, Text: "127.0.0.1:4000"},
									PushButton{Text: "Connect This PC", OnClicked: registerPeer},
									PushButton{Text: "Reconnect This PC", OnClicked: rejoinSelectedNetwork},
								},
							},
							GroupBox{
								Title:  "Tunnel Creation",
								Layout: Grid{Columns: 2},
								Children: []Widget{
									Label{Text: "Peer A"},
									LineEdit{AssignTo: &peerAEdit},
									Label{Text: "Peer B"},
									LineEdit{AssignTo: &peerBEdit},
									HSpacer{},
									PushButton{Text: "Create Tunnel", OnClicked: createTunnel},
								},
							},
							GroupBox{
								Title:  "Messages",
								Layout: VBox{},
								Children: []Widget{
									Composite{
										Layout: Grid{Columns: 2},
										Children: []Widget{
											Label{Text: "From Peer"},
											ComboBox{AssignTo: &messageFromPeerBox, Editable: false},
											Label{Text: "Text"},
											LineEdit{AssignTo: &messageTextEdit},
										},
									},
									Composite{
										Layout: Grid{Columns: 2},
										Children: []Widget{
											Label{Text: "Filter Peer"},
											ComboBox{AssignTo: &messageFilterPeerBox, Editable: false, Model: []string{"All Peers"}, OnCurrentIndexChanged: updateMessagesView},
											Label{Text: "Filter Text"},
											LineEdit{AssignTo: &messageFilterEdit, OnTextChanged: updateMessagesView},
										},
									},
									Composite{
										Layout: HBox{},
										Children: []Widget{
											PushButton{Text: "Refresh Messages", OnClicked: updateDetails},
											PushButton{Text: "Send Message", OnClicked: sendSelectedNetworkMessage},
										},
									},
									TextEdit{AssignTo: &messagesView, ReadOnly: true, VScroll: true},
								},
							},
							GroupBox{
								Title:  "File Transfers",
								Layout: VBox{},
								Children: []Widget{
									Composite{
										Layout: Grid{Columns: 2},
										Children: []Widget{
											Label{Text: "From Peer"},
											ComboBox{AssignTo: &transferFromPeerBox, Editable: false, OnCurrentIndexChanged: updateTransferRecipientChoices},
											Label{Text: "To Peer"},
											ComboBox{AssignTo: &transferToPeerBox, Editable: false},
											Label{Text: "Source Path"},
											LineEdit{AssignTo: &transferSourcePathEdit},
											Label{Text: "File Name"},
											LineEdit{AssignTo: &transferFileNameEdit},
											Label{Text: "Size Bytes"},
											LineEdit{AssignTo: &transferSizeEdit, Text: "0"},
											Label{Text: "Progress %"},
											LineEdit{AssignTo: &transferProgressEdit, Text: "0"},
											Label{Text: "Cancel Reason"},
											LineEdit{AssignTo: &transferReasonEdit},
										},
									},
									Composite{
										Layout: Grid{Columns: 2},
										Children: []Widget{
											Label{Text: "Mailbox"},
											ComboBox{AssignTo: &transferMailboxBox, Editable: false, Model: []string{"All Transfers", "Inbox", "Sent"}, CurrentIndex: 0, OnCurrentIndexChanged: func() {
												updateFileTransferList()
												updateFileTransferDetails()
											}},
											Label{Text: "Filter Peer"},
											ComboBox{AssignTo: &transferFilterPeerBox, Editable: false, Model: []string{"All Peers"}, OnCurrentIndexChanged: func() {
												updateFileTransferList()
												updateFileTransferDetails()
											}},
											Label{Text: "Status"},
											ComboBox{AssignTo: &transferStatusFilterBox, Editable: false, Model: []string{"All Statuses", "PENDING", "IN_PROGRESS", "DONE", "CANCELED"}, CurrentIndex: 0, OnCurrentIndexChanged: func() {
												updateFileTransferList()
												updateFileTransferDetails()
											}},
											Label{Text: "Filter Text"},
											LineEdit{AssignTo: &transferFilterEdit, OnTextChanged: func() {
												updateFileTransferList()
												updateFileTransferDetails()
											}},
										},
									},
									Composite{
										Layout: HBox{},
										Children: []Widget{
											PushButton{Text: "Refresh Transfers", OnClicked: updateDetails},
											PushButton{Text: "Browse File", OnClicked: browseTransferSourceFile},
											PushButton{Text: "Create Transfer", OnClicked: createSelectedNetworkFileTransfer},
											PushButton{Text: "Resume Upload", OnClicked: resumeSelectedFileTransferUpload},
											PushButton{Text: "Download Selected", OnClicked: downloadSelectedFileTransfer},
											PushButton{Text: "Accept Selected", OnClicked: acceptSelectedFileTransfer},
											PushButton{Text: "Cancel Selected", OnClicked: cancelSelectedFileTransfer},
											PushButton{Text: "Apply Progress", OnClicked: updateSelectedFileTransferProgress},
										},
									},
									HSplitter{
										Children: []Widget{
											ListBox{
												AssignTo: &fileTransfersBox,
												Model:    fileTransfersModel,
												OnCurrentIndexChanged: func() {
													index := fileTransfersBox.CurrentIndex()
													if index < 0 || index >= len(visibleFileTransfers) {
														state.selectedTransfer = nil
														state.transferLocalState = nil
														updateFileTransferDetails()
														return
													}
													state.selectedTransfer = &visibleFileTransfers[index]
													state.transferLocalState = nil
													updateFileTransferDetails()
												},
											},
											TextEdit{AssignTo: &fileTransferDetailsView, ReadOnly: true, VScroll: true},
										},
									},
								},
							},
							HSplitter{
								Children: []Widget{
									GroupBox{
										Title:  "Peers",
										Layout: VBox{},
										Children: []Widget{
											TextEdit{AssignTo: &peersView, ReadOnly: true, VScroll: true},
										},
									},
									GroupBox{
										Title:  "Tunnels",
										Layout: VBox{},
										Children: []Widget{
											TextEdit{AssignTo: &tunnelsView, ReadOnly: true, VScroll: true},
										},
									},
								},
							},
							HSplitter{
								Children: []Widget{
									GroupBox{
										Title:  "Service Health",
										Layout: VBox{},
										Children: []Widget{
											TextEdit{AssignTo: &serviceHealthView, ReadOnly: true, VScroll: true},
										},
									},
									GroupBox{
										Title:  "Agent Diagnostics",
										Layout: VBox{},
										Children: []Widget{
											TextEdit{AssignTo: &agentView, ReadOnly: true, VScroll: true},
										},
									},
									GroupBox{
										Title:  "Connection Diagnostics",
										Layout: VBox{},
										Children: []Widget{
											TextEdit{AssignTo: &connectionView, ReadOnly: true, VScroll: true},
										},
									},
								},
							},
						},
					},
				},
			},
			Composite{
				Layout: HBox{Margins: Margins{Left: 16, Top: 8, Right: 16, Bottom: 12}},
				Children: []Widget{
					Label{AssignTo: &statusBar, Text: "Disconnected"},
				},
			},
		},
	}.Create()); err != nil {
		return err
	}

	if err := refreshAgentStatus(false); err != nil {
		updateStatus("Ole Agent is not reachable. Start cmd/agent or the Windows service, then press Refresh Ole Agent.")
	}
	updateUserLabel()
	updateSessionDetails()
	updateDeviceList()
	updateDevicesView()
	updateAuditPresetsView()
	updateAuditView()
	updateIncidentView()
	updateDiagnostics()
	peersView.SetText("Select a network to view peers.")
	tunnelsView.SetText("Select a network to view tunnels.")
	if messagesView != nil {
		messagesView.SetText("Select a network to view messages.")
	}
	updatePeerChoiceControls()
	updateFileTransferList()
	updateFileTransferDetails()
	if state.currentSession != nil {
		if err := refreshSessions(); err != nil {
			showWinError(mw, err)
		}
		if err := refreshDevices(); err != nil {
			showWinError(mw, err)
		}
		if err := refreshAuditPresets(); err != nil {
			showWinError(mw, err)
		}
		if err := refreshAuditEvents(); err != nil {
			showWinError(mw, err)
		}
		if err := refreshIncidentReports(); err != nil {
			showWinError(mw, err)
		}
		refreshNetworks()
	}

	autoRefreshStop := make(chan struct{})
	mw.Disposing().Attach(func() {
		close(autoRefreshStop)
	})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				status, err := state.svc.GetStatus()
				if err != nil || mw == nil || mw.IsDisposed() {
					continue
				}
				mw.Synchronize(func() {
					applyStatus(status)
					updateUserLabel()
					updatePeerList()
					if state.currentSession != nil {
						if devices, listErr := state.svc.ListDevices(); listErr == nil {
							selectedID := ""
							if state.selectedDevice != nil {
								selectedID = state.selectedDevice.ID
							}
							if selectedID == "" {
								selectedID = currentServiceDeviceID(state.agentStatus)
							}
							state.devices = devices
							state.selectedDevice = nil
							for idx := range state.devices {
								if selectedID != "" && state.devices[idx].ID == selectedID {
									state.selectedDevice = &state.devices[idx]
									break
								}
							}
							if state.selectedDevice == nil && len(state.devices) > 0 {
								state.selectedDevice = &state.devices[0]
							}
						}
						if presets, listErr := state.svc.ListAuditPresets(); listErr == nil {
							selectedName := ""
							if state.selectedPreset != nil {
								selectedName = state.selectedPreset.Name
							}
							state.auditPresets = presets
							state.selectedPreset = nil
							for idx := range state.auditPresets {
								if selectedName != "" && strings.EqualFold(state.auditPresets[idx].Name, selectedName) {
									state.selectedPreset = &state.auditPresets[idx]
									break
								}
							}
							if state.selectedPreset == nil && len(state.auditPresets) > 0 {
								state.selectedPreset = &state.auditPresets[0]
							}
						}
					} else {
						state.devices = nil
						state.selectedDevice = nil
						state.auditPresets = nil
						state.selectedPreset = nil
					}
					updateDeviceList()
					updateDevicesView()
					updateAuditPresetsView()
					updateDiagnostics()
				})
			case <-autoRefreshStop:
				return
			}
		}
	}()

	mw.Run()
	return nil
}

func formatSessionSummary(session Session, currentSession *Session) string {
	label := session.DeviceName
	if strings.TrimSpace(label) == "" {
		label = "Unnamed session"
	}
	if currentSession != nil && session.FamilyID == currentSession.FamilyID {
		label += " | current"
	}
	if session.ReuseDetectedAtUnix > 0 {
		label += " | reuse detected"
	}
	return fmt.Sprintf("%s | last used %s", label, formatUnix(session.LastUsedAtUnix))
}

func formatSessionDetails(session Session, currentSession *Session) string {
	lines := []string{
		"ID: " + session.ID,
		"Family: " + session.FamilyID,
		"Device: " + firstNonEmpty(session.DeviceName, "-"),
		"IP: " + firstNonEmpty(session.IP, "-"),
		"User-Agent: " + firstNonEmpty(session.UserAgent, "-"),
		"Last Used: " + formatUnix(session.LastUsedAtUnix),
		"Expires: " + formatUnix(session.ExpiresAtUnix),
		"Revoked: " + formatUnix(session.RevokedAtUnix),
		"Reuse Detected: " + formatUnix(session.ReuseDetectedAtUnix),
	}
	if currentSession != nil && session.FamilyID == currentSession.FamilyID {
		lines = append(lines, "Current: yes")
	}
	if session.ReuseDetectedAtUnix > 0 {
		lines = append(lines, "Security Alert: token reuse detected for this session family")
		lines = append(lines, "Recommended Action: Use `Revoke All Sessions` and sign in again.")
	}
	return strings.Join(lines, "\r\n")
}

func formatUnix(value int64) string {
	if value <= 0 {
		return "-"
	}
	return time.Unix(value, 0).Format(time.RFC3339)
}

func formatUnixMillis(value int64) string {
	if value <= 0 {
		return "-"
	}
	return time.UnixMilli(value).Format(time.RFC3339)
}

func formatOnboardingGuide(status *clientagent.Status, networkCount int, selected *Network, peerCount, tunnelCount int) string {
	lines := []string{}

	switch {
	case status == nil:
		lines = append(lines,
			"Current Step: bring the local Ole Agent online.",
			"",
			"[next] Start `cmd/agent` or the Windows service.",
			"[next] Press `Refresh Ole Agent` after it starts listening on localhost.",
			"[next] Confirm the `Server Base URL` before registering or signing in.",
			"[next] Use `Create Account` for a new account or `Sign In` for an existing one.",
			"",
			"Recovery:",
			"If the agent stays unreachable, make sure the service is running and the GUI can reach `127.0.0.1:5858`.",
		)
	case strings.EqualFold(status.CompatibilityStatus, "UPGRADE_REQUIRED"):
		lines = append(lines,
			"Current Step: fix client/server compatibility before signing in.",
			"",
			"[done] The local Ole Agent is reachable.",
			"[next] Use `Check Updates` and `Download Update` if the local agent has an update manifest, or upgrade Ole Desktop manually.",
			"[next] Press `Refresh Ole Agent` after upgrading.",
			"",
			"Recovery:",
			"Server version: "+firstNonEmpty(status.ServerVersion, "-")+". Minimum client: "+firstNonEmpty(status.MinClientVersion, "-")+".",
		)
	case status.Security.CurrentSessionReuseDetected || status.Security.ReuseDetectedCount > 0 || status.Incidents.TokenReuseCount > 0:
		lines = append(lines,
			"Current Step: secure the account before continuing network setup.",
			"",
			"[done] The local Ole Agent is reachable and the current session is known.",
			"[next] Open the `Sessions` pane and press `Revoke All Sessions`.",
			"[next] Sign in again so the local service gets a fresh trusted session.",
			"[next] Review `Service Health` and `Agent Diagnostics` for the reuse alert details.",
			"",
			"Recovery:",
			"Token reuse was detected for the current account, so session recovery should come before network changes.",
		)
	case status.PersistedSession && status.ReconnectBackoffActive:
		lines = append(lines,
			"Current Step: wait for the local agent to retry the persisted session restore.",
			"",
			"[done] The local Ole Agent is reachable and already holds a persisted session.",
			"[next] Wait for the scheduled auto-reconnect window to expire.",
			"[next] Use `Reconnect` to bypass the backoff window and retry immediately.",
			"[next] Open `Service Health` to review the last reconnect error and next retry time.",
			"",
			"Recovery:",
			"Next reconnect: "+formatReconnectNextRetry(status, time.Now())+".",
		)
	case !status.Connected:
		lines = append(lines,
			"Current Step: create or restore a service session.",
			"",
			"[done] The local Ole Agent is reachable.",
			"[next] Use `Create Account` if this is your first time on this server.",
			"[next] Use `Sign In` to start a new session.",
			"[next] Use `Reconnect` if the agent already has a persisted session.",
			"",
			"Recovery:",
			"If login fails, recheck the `Server Base URL`, then open `Service Health` for compatibility and lifecycle hints.",
		)
	case networkCount == 0:
		lines = append(lines,
			"Current Step: create or join your first network.",
			"",
			"[done] Agent and service session are ready.",
			"[next] Use `Create Network` to start a private overlay.",
			"[next] Or use `Join By Invite` if another peer already created the network.",
			"[next] Press `Refresh Networks` if another device created the network recently.",
			"",
			"Recovery:",
			"`INVITE_ONLY` is a safe default for first testing with friends or your second device.",
		)
	case selected == nil:
		lines = append(lines,
			"Current Step: choose a network to continue setup.",
			"",
			"[done] A service session and at least one network already exist.",
			"[next] Select a network from the `Networks` list.",
			"[next] Then register the local peer endpoint for that network.",
			"",
			"Recovery:",
			"If the list is empty or stale, press `Refresh Networks`.",
		)
	case networkRequiresCurrentDeviceApproval(selected, status):
		lines = append(lines,
			"Current Step: approve the current device for the selected sensitive network.",
			"",
			"[done] Network selected: "+firstNonEmpty(selected.Name, selected.ID)+".",
			"[next] Open `Trusted Devices` and keep the current service device selected.",
			"[next] Press `Approve For Network` for the selected network.",
			"[next] Then retry `Connect This PC` or `Reconnect This PC`.",
			"",
			"Recovery:",
			"Sensitive networks do not allow peer registration until the current device is approved.",
		)
	case peerCount == 0:
		lines = append(lines,
			"Current Step: register this device as a peer on the selected network.",
			"",
			"[done] Network selected: "+firstNonEmpty(selected.Name, selected.ID)+".",
			"[next] Fill in the `Endpoint` field for this device.",
			"[next] Press `Connect This PC` to publish the local peer.",
			"[next] Use `Reconnect This PC` if the peer existed before and needs to be recreated.",
			"",
			"Recovery:",
			"Use a reachable UDP endpoint when testing across machines; `127.0.0.1` only works for same-host experiments.",
		)
	case tunnelCount == 0:
		lines = append(lines,
			"Current Step: establish peer-to-peer intent for the selected network.",
			"",
			"[done] The local peer is registered on "+firstNonEmpty(selected.Name, selected.ID)+".",
			"[next] Wait until another peer appears in the `Peers` pane.",
			"[next] Enter `Peer A` and `Peer B`, then press `Create Tunnel`.",
			"",
			"Recovery:",
			"If peers disappear after a restart, try `Reconnect This PC` and then refresh the network details.",
		)
	case hasConnectedPath(status, selected):
		lines = append(lines,
			"Current Step: Ole is ready for traffic on the selected network.",
			"",
			"[done] Agent, session, network, peer, and tunnel are all in place.",
			"[done] At least one managed connection is already connected.",
			"[next] Watch `Connection Diagnostics` for direct versus relay path changes.",
			"[next] Use `Export Diagnostics` if you need to share a support snapshot.",
		)
	default:
		lines = append(lines,
			"Current Step: wait for transport to finish negotiating.",
			"",
			"[done] Agent, session, network, peer, and tunnel setup are in place.",
			"[next] Watch `Connection Diagnostics` for `DIRECT_CANDIDATE`, `NEGOTIATING`, or `CONNECTED` state changes.",
			"[next] If transport stalls, try `Reconnect` or `Reconnect This PC`.",
			"",
			"Recovery:",
			"Use `Service Health` and `Agent Diagnostics` if the path keeps falling back or stays pending.",
		)
	}

	return strings.Join(lines, "\r\n")
}

func formatQuickStartGuide(status *clientagent.Status, networkCount int, selected *Network, peerCount, tunnelCount int) string {
	switch {
	case status == nil:
		return strings.Join([]string{
			"1. Start the Ole Agent service.",
			"2. Press `Refresh Ole Agent`.",
			"3. Enter the server URL, then use `Create Account` or `Sign In`.",
		}, "\r\n")
	case !status.Connected:
		return strings.Join([]string{
			"1. Check the server URL.",
			"2. Use `Create Account` if this is your first time.",
			"3. Use `Sign In` to open your Ole session on this PC.",
		}, "\r\n")
	case networkCount == 0:
		return strings.Join([]string{
			"Next: create or join a network.",
			"If this is the first PC, use `2A. Create Your Network`.",
			"If someone already invited you, paste the code into `2B. Join By Invite`.",
		}, "\r\n")
	case selected == nil:
		return strings.Join([]string{
			"Next: pick a network from the `Networks` list.",
			"Then go to `3. Connect This PC` to attach this device to that network.",
		}, "\r\n")
	case networkRequiresCurrentDeviceApproval(selected, status):
		return strings.Join([]string{
			"Next: approve this device for the selected network.",
			"Open `Trusted Devices`, select this device, then press `Approve For Network`.",
			"After that, come back and use `Connect This PC`.",
		}, "\r\n")
	case peerCount == 0:
		return strings.Join([]string{
			"Next: connect this PC to the selected network.",
			"Leave `127.0.0.1:4000` for same-PC experiments, or enter a reachable UDP address for another machine.",
			"Then press `Connect This PC`.",
		}, "\r\n")
	case tunnelCount == 0:
		return strings.Join([]string{
			"Next: wait for another peer to appear, then create a tunnel between the peers.",
			"If the peer used to exist on this PC, try `Reconnect This PC` first.",
		}, "\r\n")
	case hasConnectedPath(status, selected):
		return strings.Join([]string{
			"Connected: this PC is ready to use the selected Ole network.",
			"You can now exchange traffic, messages, and files on this network.",
		}, "\r\n")
	default:
		return strings.Join([]string{
			"Setup is almost done.",
			"Wait for transport negotiation to finish, or try `Reconnect` / `Reconnect This PC` if it stalls.",
		}, "\r\n")
	}
}

func formatServiceHealthStatus(status *clientagent.Status) string {
	return formatServiceHealthStatusAt(status, time.Now())
}

func formatServiceHealthStatusAt(status *clientagent.Status, now time.Time) string {
	if status == nil {
		return strings.Join([]string{
			"Overall: offline",
			"Local Agent: unreachable",
			"Server Reachability: unknown",
			"Version Pairing: unknown",
			"Next Action: Start `cmd/agent` or the Windows service, then press `Refresh Ole Agent`.",
		}, "\r\n")
	}

	overall := "healthy"
	nextAction := "No action needed."
	switch {
	case strings.EqualFold(status.CompatibilityStatus, "UPGRADE_REQUIRED"):
		overall = "blocked"
		nextAction = "Upgrade Ole Desktop to at least the minimum supported client version before signing in again."
	case status.Incidents.TokenReuseCount > 0:
		overall = "security-alert"
		nextAction = firstNonEmpty(status.Incidents.RecommendedAction, "Use `Revoke All Sessions` and sign in again because suspicious token reuse was reported for this account.")
	case status.Security.CurrentSessionReuseDetected || status.Security.ReuseDetectedCount > 0:
		overall = "security-alert"
		nextAction = "Use `Revoke All Sessions` and sign in again because token reuse was detected for this account."
	case updatePolicyBlocked(status.Update.PolicyStatus) && status.Update.RollbackAvailable:
		overall = "rollback-recommended"
		nextAction = "This update channel is not compatible with the current server. Use `Download Rollback` if you need to revert to the recommended rollback build."
	case updatePolicyBlocked(status.Update.PolicyStatus):
		overall = "blocked"
		nextAction = "This update channel is blocked by the current server compatibility policy."
	case status.Update.Downloaded:
		overall = "ready-to-upgrade"
		nextAction = "Run `Install Update` to launch the downloaded Ole Desktop installer."
	case status.Update.Available:
		overall = "upgrade-available"
		nextAction = "Use `Download Update` to fetch the newer Ole Desktop installer."
	case status.ReconnectBackoffActive:
		overall = "recovering"
		nextAction = "Wait for the scheduled auto-reconnect retry or press `Reconnect` to retry immediately."
	case strings.TrimSpace(status.LastLifecycleError) != "":
		overall = "degraded"
		nextAction = "Review the lifecycle error and try `Reconnect` after the server or network issue is fixed."
	case !status.Connected:
		overall = "idle"
		nextAction = "Sign in or use `Reconnect` to restore the persisted service session."
	case strings.EqualFold(status.CompatibilityStatus, "WARNING"):
		overall = "warning"
		nextAction = "Plan a client upgrade soon so this desktop stays within the supported compatibility window."
	}

	sessionState := "none"
	if status.CurrentSession != nil {
		sessionState = "active"
	}
	deviceState := firstNonEmpty(status.Security.EnrollmentStatus, status.Security.CurrentDeviceStatus, "-")
	if strings.EqualFold(deviceState, "ACTIVE") {
		deviceState = "active"
	}

	lines := []string{
		"Overall: " + overall,
		"Local Agent: reachable",
		"Service: " + firstNonEmpty(status.ServiceName, "-"),
		"Listen: " + firstNonEmpty(status.ListenAddress, "-"),
		"Service Uptime: " + formatSinceUnixAt(status.StartedAtUnix, now),
		"Server Reachability: " + connectedLabel(status.Connected),
		"Server Base URL: " + firstNonEmpty(status.ServerBaseURL, "-"),
		"Session State: " + sessionState,
		"Persisted Session: " + yesNo(status.PersistedSession),
		"Current User: " + formatUserSummary(status.CurrentUser),
		"Current Device: " + formatDeviceSummary(status.CurrentDevice),
		"Device Enrollment: " + firstNonEmpty(deviceState, "-"),
		"Version Pairing: " + firstNonEmpty(status.CompatibilityStatus, "-"),
		"Client Version: " + firstNonEmpty(status.ClientVersion, "-"),
		"Server Version: " + firstNonEmpty(status.ServerVersion, "-"),
		"Minimum Client: " + firstNonEmpty(status.MinClientVersion, "-"),
		"Compatibility Message: " + firstNonEmpty(status.CompatibilityMessage, "-"),
		"Last Session Refresh: " + formatTimestampAndAge(status.LastSessionRefreshUnix, now),
		"Last Heartbeat: " + formatTimestampAndAge(status.LastHeartbeatUnix, now),
		"Last Peer Discovery: " + formatTimestampAndAge(status.LastPeerDiscoveryUnix, now),
		"Last STUN Probe: " + formatTimestampAndAge(status.LastSTUNProbeUnix, now),
		"Last Direct Probe: " + formatTimestampAndAge(status.LastDirectProbeUnix, now),
		"Reconnect State: " + formatReconnectStateLabel(status),
		"Reconnect Attempts: " + strconv.Itoa(status.ReconnectAttemptCount),
		"Last Reconnect Attempt: " + formatTimestampAndAgeMillis(status.LastReconnectAttemptMs, now),
		"Next Reconnect Retry: " + formatReconnectNextRetry(status, now),
		"Direct Success Rate: " + formatPercent(status.DirectMetrics.SuccessRatePct),
		"Relay Fallbacks: " + strconv.Itoa(status.DirectMetrics.RelayFallbackCount),
		"Security Alerts: " + strconv.Itoa(len(status.Security.Alerts)),
		"Active Incidents: " + strconv.Itoa(status.Incidents.ActiveCount),
		"Token Reuse Incidents: " + strconv.Itoa(status.Incidents.TokenReuseCount),
		"Incident Severity: " + firstNonEmpty(status.Incidents.MostSevere, "-"),
		"Last Incident Refresh: " + formatTimestampAndAge(status.Incidents.LastCheckedUnix, now),
		"Managed Peers: " + strconv.Itoa(status.ManagedPeerCount),
		"Discovered Peers: " + strconv.Itoa(status.DiscoveredPeerCount),
		"Update Channel: " + firstNonEmpty(status.Update.Channel, formatUpdateChannel(status)),
		"Available Update Channels: " + joinOrDash(status.Update.AvailableChannels),
		"Update State: " + formatUpdateState(status),
		"Update Policy: " + firstNonEmpty(status.Update.PolicyStatus, "-"),
		"Latest Client Version: " + firstNonEmpty(status.Update.LatestVersion, "-"),
		"Last Update Check: " + formatTimestampAndAge(status.Update.LastCheckedUnix, now),
		"Downloaded Update: " + yesNo(status.Update.Downloaded),
		"Rollback Available: " + yesNo(status.Update.RollbackAvailable),
		"Rollback Downloaded: " + yesNo(status.Update.RollbackDownloaded),
	}
	if strings.TrimSpace(status.Update.DownloadedPath) != "" {
		lines = append(lines, "Downloaded Installer: "+status.Update.DownloadedPath)
	}
	if strings.TrimSpace(status.Update.ReleaseNotesURL) != "" {
		lines = append(lines, "Release Notes: "+status.Update.ReleaseNotesURL)
	}
	if strings.TrimSpace(status.Update.PolicyMessage) != "" {
		lines = append(lines, "Update Policy Message: "+status.Update.PolicyMessage)
	}
	if strings.TrimSpace(status.Update.RollbackDownloadedPath) != "" {
		lines = append(lines, "Rollback Installer: "+status.Update.RollbackDownloadedPath)
	}
	if strings.TrimSpace(status.Update.LastError) != "" {
		lines = append(lines, "Update Error: "+status.Update.LastError)
	}
	if strings.TrimSpace(status.LastReconnectError) != "" {
		lines = append(lines, "Reconnect Error: "+status.LastReconnectError)
	}
	if strings.TrimSpace(status.LastLifecycleError) != "" {
		lines = append(lines, "Last Lifecycle Error: "+status.LastLifecycleError)
	}
	if strings.TrimSpace(status.Incidents.LastRefreshError) != "" {
		lines = append(lines, "Incident Refresh Error: "+status.Incidents.LastRefreshError)
	}
	lines = append(lines, "Next Action: "+nextAction)
	return strings.Join(lines, "\r\n")
}

func formatAgentStatus(status *clientagent.Status) string {
	if status == nil {
		return "Ole Agent diagnostics are not available yet."
	}

	lines := []string{
		"Service: " + firstNonEmpty(status.ServiceName, "-"),
		"Listen: " + firstNonEmpty(status.ListenAddress, "-"),
		"Server: " + firstNonEmpty(status.ServerBaseURL, "-"),
		"Client Version: " + firstNonEmpty(status.ClientVersion, "-"),
		"Server Version: " + firstNonEmpty(status.ServerVersion, "-"),
		"Min Client Version: " + firstNonEmpty(status.MinClientVersion, "-"),
		"Compatibility: " + firstNonEmpty(status.CompatibilityStatus, "-"),
		"Compatibility Message: " + firstNonEmpty(status.CompatibilityMessage, "-"),
		"State Path: " + firstNonEmpty(status.StatePath, "-"),
		"Connected: " + yesNo(status.Connected),
		"Started: " + formatUnix(status.StartedAtUnix),
		"Managed Peers: " + strconv.Itoa(status.ManagedPeerCount),
		"Discovered Peers: " + strconv.Itoa(status.DiscoveredPeerCount),
		"Current User: " + formatUserSummary(status.CurrentUser),
		"Current Device: " + formatDeviceSummary(status.CurrentDevice),
		"Current Device Status: " + firstNonEmpty(status.Security.CurrentDeviceStatus, "-"),
		"Enrollment Status: " + firstNonEmpty(status.Security.EnrollmentStatus, "-"),
		"Reconnect State: " + formatReconnectStateLabel(status),
		"Reconnect Attempts: " + strconv.Itoa(status.ReconnectAttemptCount),
		"Last Reconnect Attempt: " + formatUnixMillis(status.LastReconnectAttemptMs),
		"Next Reconnect Retry: " + formatReconnectNextRetry(status, time.Now()),
		"Last Session Refresh: " + formatUnix(status.LastSessionRefreshUnix),
		"Security Checked: " + formatUnix(status.Security.LastCheckedUnix),
		"Incident Refresh: " + formatUnix(status.Incidents.LastCheckedUnix),
		"Active Incidents: " + strconv.Itoa(status.Incidents.ActiveCount),
		"Token Reuse Incidents: " + strconv.Itoa(status.Incidents.TokenReuseCount),
		"Incident Severity: " + firstNonEmpty(status.Incidents.MostSevere, "-"),
		"Security Reuse Alerts: " + strconv.Itoa(status.Security.ReuseDetectedCount),
		"Security Revoked Devices: " + strconv.Itoa(status.Security.RevokedDeviceCount),
		"Last Heartbeat: " + formatUnix(status.LastHeartbeatUnix),
		"Last Peer Discovery: " + formatUnix(status.LastPeerDiscoveryUnix),
		"Last STUN Probe: " + formatUnix(status.LastSTUNProbeUnix),
		"Last Direct Probe: " + formatUnix(status.LastDirectProbeUnix),
		"",
		"Direct Connect Metrics",
		"Attempts: " + strconv.Itoa(status.DirectMetrics.AttemptCount),
		"Successes: " + strconv.Itoa(status.DirectMetrics.SuccessCount),
		"Failures: " + strconv.Itoa(status.DirectMetrics.FailureCount),
		"Success Rate: " + formatPercent(status.DirectMetrics.SuccessRatePct),
		"Relay Fallbacks: " + strconv.Itoa(status.DirectMetrics.RelayFallbackCount),
		"Direct Failbacks: " + strconv.Itoa(status.DirectMetrics.FailbackSuccessCount),
		"Last Direct Attempt: " + formatUnix(status.DirectMetrics.LastAttemptUnix),
		"Last Direct Success: " + formatUnix(status.DirectMetrics.LastSuccessUnix),
		"Last Direct Failure: " + formatUnix(status.DirectMetrics.LastFailureUnix),
		"Last Relay Fallback: " + formatUnix(status.DirectMetrics.LastFallbackUnix),
		"Last Direct Failback: " + formatUnix(status.DirectMetrics.LastFailbackUnix),
		"Last Success Candidate: " + firstNonEmpty(status.DirectMetrics.LastSuccessCandidate, "-"),
		"NAT Type: " + firstNonEmpty(status.NATType, "-"),
		"Public Endpoint: " + firstNonEmpty(status.PublicEndpoint, "-"),
		"STUN Server: " + firstNonEmpty(status.STUNServerAddress, "-"),
		"Relay Server: " + firstNonEmpty(status.RelayServerAddress, "-"),
		"Relay Pool: " + joinOrDash(status.RelayServerAddresses),
		"Active Relay: " + firstNonEmpty(status.ActiveRelayServer, "-"),
		"Relay Failovers: " + strconv.Itoa(status.RelayFailoverCount),
		"",
		"Updater",
		"Channel: " + firstNonEmpty(status.Update.Channel, "-"),
		"Available Channels: " + joinOrDash(status.Update.AvailableChannels),
		"Manifest URL: " + firstNonEmpty(status.Update.ManifestURL, "-"),
		"Check Period: " + formatUpdateCheckPeriod(status.Update.CheckPeriodSec),
		"State: " + formatUpdateState(status),
		"Policy: " + firstNonEmpty(status.Update.PolicyStatus, "-"),
		"Policy Message: " + firstNonEmpty(status.Update.PolicyMessage, "-"),
		"Minimum Server Version: " + firstNonEmpty(status.Update.MinimumServerVersion, "-"),
		"Maximum Server Version: " + firstNonEmpty(status.Update.MaximumServerVersion, "-"),
		"Minimum Rollback Base: " + firstNonEmpty(status.Update.MinimumRollbackVersion, "-"),
		"Current Version: " + firstNonEmpty(status.Update.CurrentVersion, "-"),
		"Latest Version: " + firstNonEmpty(status.Update.LatestVersion, "-"),
		"Published: " + formatUnix(status.Update.PublishedAtUnix),
		"Last Checked: " + formatUnix(status.Update.LastCheckedUnix),
		"Installer URL: " + firstNonEmpty(status.Update.InstallerURL, "-"),
		"Downloaded: " + yesNo(status.Update.Downloaded),
		"Downloaded Path: " + firstNonEmpty(status.Update.DownloadedPath, "-"),
		"Last Downloaded: " + formatUnix(status.Update.LastDownloadedUnix),
		"Rollback Available: " + yesNo(status.Update.RollbackAvailable),
		"Rollback Version: " + firstNonEmpty(status.Update.RollbackVersion, "-"),
		"Rollback Reason: " + firstNonEmpty(status.Update.RollbackReason, "-"),
		"Rollback Installer URL: " + firstNonEmpty(status.Update.RollbackInstallerURL, "-"),
		"Rollback Downloaded: " + yesNo(status.Update.RollbackDownloaded),
		"Rollback Downloaded Path: " + firstNonEmpty(status.Update.RollbackDownloadedPath, "-"),
		"Rollback Last Downloaded: " + formatUnix(status.Update.RollbackLastDownloadedUnix),
		"",
		"Adapter",
		"Enabled: " + yesNo(status.Adapter.Enabled),
		"Available: " + yesNo(status.Adapter.Available),
		"Name: " + firstNonEmpty(status.Adapter.AdapterName, "-"),
		"Driver Version: " + firstNonEmpty(status.Adapter.DriverVersion, "-"),
		"LUID: " + fmt.Sprintf("%d", status.Adapter.LUID),
		"Desired MTU: " + formatInt(status.Adapter.DesiredMTU),
		"MTU: " + formatInt(status.Adapter.MTU),
		"Interface Metric: " + formatInt(status.Adapter.InterfaceMetric),
		"Connection State: " + firstNonEmpty(status.Adapter.ConnectionState, "-"),
		"Packet Session Active: " + yesNo(status.Adapter.SessionActive),
		"Last Error: " + firstNonEmpty(status.Adapter.LastError, "-"),
	}
	if len(status.Adapter.Networks) == 0 {
		lines = append(lines, "Networks: none")
	} else {
		lines = append(lines, "Networks:")
		for _, binding := range status.Adapter.Networks {
			lines = append(lines, fmt.Sprintf(
				"- %s | %s/%d | routing=%s | policy=%s | ip visible=%s | route %s | route visible=%s | metric=%s",
				binding.NetworkID,
				binding.VirtualIP,
				binding.PrefixLength,
				firstNonEmpty(strings.ToLower(strings.TrimSpace(binding.RoutingPolicy)), "-"),
				firstNonEmpty(strings.ToLower(strings.TrimSpace(binding.PolicyStatus)), "-"),
				yesNo(binding.IPAddressVisible),
				firstNonEmpty(binding.RoutePrefix, "-"),
				yesNo(binding.RouteVisible),
				formatInt(binding.RouteMetric),
			))
			lines = append(lines, fmt.Sprintf(
				"  overlay %s -> %s/%d",
				binding.NetworkID,
				binding.VirtualIP,
				binding.PrefixLength,
			))
		}
	}
	if len(status.GroupTraffic) > 0 {
		lines = append(lines, "", "Group Traffic:")
		for _, item := range status.GroupTraffic {
			lines = append(lines, fmt.Sprintf(
				"- %s | policy=%s | blocked=%d | flooded=%d | copies=%d | broadcast=%d | multicast=%d | last action=%s | last packet=%s",
				firstNonEmpty(item.NetworkID, "-"),
				firstNonEmpty(strings.ToLower(strings.TrimSpace(item.Policy)), "-"),
				item.BlockedPacketCount,
				item.FloodPacketCount,
				item.FanoutCopyCount,
				item.BroadcastPacketCount,
				item.MulticastPacketCount,
				firstNonEmpty(strings.ToLower(strings.TrimSpace(item.LastAction)), "-"),
				formatUnix(item.LastPacketUnix),
			))
		}
	}
	if len(status.Security.Alerts) > 0 {
		lines = append(lines, "", "Security Alerts:")
		for _, alert := range status.Security.Alerts {
			lines = append(lines, fmt.Sprintf(
				"- %s | %s | %s | %s | detected %s",
				firstNonEmpty(alert.Severity, "-"),
				firstNonEmpty(alert.Code, "-"),
				firstNonEmpty(alert.Summary, "-"),
				firstNonEmpty(alert.Detail, "-"),
				formatUnix(alert.DetectedAtUnix),
			))
		}
	}
	if status.Security.CurrentSessionReuseDetected || status.Security.ReuseDetectedCount > 0 || status.Incidents.TokenReuseCount > 0 {
		lines = append(lines, "", "Suggested Recovery: Use `Revoke All Sessions` and sign in again.")
	}
	if len(status.Neighbors) > 0 {
		lines = append(lines, "", "Neighbors:")
		for _, neighbor := range status.Neighbors {
			lines = append(lines, formatNeighborSummaryLine(neighbor))
		}
	}
	if strings.TrimSpace(status.LastReconnectError) != "" {
		lines = append(lines, "", "Last Reconnect Error: "+status.LastReconnectError)
	}
	if strings.TrimSpace(status.Update.ReleaseNotesURL) != "" {
		lines = append(lines, "", "Update Release Notes: "+status.Update.ReleaseNotesURL)
	}
	if strings.TrimSpace(status.Update.LastError) != "" {
		lines = append(lines, "", "Update Error: "+status.Update.LastError)
	}
	if strings.TrimSpace(status.LastLifecycleError) != "" {
		lines = append(lines, "", "Last Lifecycle Error: "+status.LastLifecycleError)
	}
	if strings.TrimSpace(status.Incidents.LastRefreshError) != "" {
		lines = append(lines, "", "Incident Refresh Error: "+status.Incidents.LastRefreshError)
	}
	return strings.Join(lines, "\r\n")
}

func formatConnectionDiagnostics(status *clientagent.Status, selected *Network) string {
	if status == nil {
		return "Connection diagnostics are not available yet."
	}

	lines := []string{}
	if transportSummaryLines := formatNetworkTransportSummaryLines(status, selected); len(transportSummaryLines) > 0 {
		lines = append(lines, "Network Transport Summary")
		lines = append(lines, transportSummaryLines...)
	}
	if gatewayLines := formatGatewayDiagnosticsLines(status, selected); len(gatewayLines) > 0 {
		lines = append(lines, "Gateway Path")
		lines = append(lines, gatewayLines...)
	}
	if gatewayHistoryLines := formatGatewayHistoryLines(status, selected); len(gatewayHistoryLines) > 0 {
		lines = append(lines, "Gateway History")
		lines = append(lines, gatewayHistoryLines...)
	}
	neighborLines := []string{}
	for _, neighbor := range status.Neighbors {
		if selected != nil && neighbor.NetworkID != selected.ID {
			continue
		}
		neighborLines = append(neighborLines,
			fmt.Sprintf("[neighbor %s] %s -> %s", neighbor.NetworkID, neighbor.LocalPeerID, neighbor.RemotePeerID),
			"Presence: "+firstNonEmpty(neighbor.Presence, "-"),
			"Neighbor State: "+firstNonEmpty(neighbor.NeighborState, "-"),
			"Remote Virtual IP: "+firstNonEmpty(neighbor.RemoteVirtualIP, "-"),
			"Remote Endpoint: "+firstNonEmpty(neighbor.RemoteEndpoint, "-"),
			"Overlay CIDR: "+firstNonEmpty(neighbor.OverlayCIDR, "-"),
			"Reachability: "+firstNonEmpty(neighbor.Reachability, "-"),
			"Candidates: "+strconv.Itoa(neighbor.CandidateCount),
			"Transport Ready: "+yesNo(neighbor.TransportReady),
			"Transport Mode: "+firstNonEmpty(neighbor.TransportMode, "-"),
			"Last Seen: "+formatUnix(neighbor.LastSeenUnix),
			"Last Signaled: "+formatUnix(neighbor.LastSignaledAtUnix),
			"",
		)
	}
	if len(neighborLines) > 0 {
		lines = append(lines, "Overlay Neighbors")
		lines = append(lines, neighborLines...)
	}
	groupLines := []string{}
	for _, item := range status.GroupTraffic {
		if selected != nil && item.NetworkID != selected.ID {
			continue
		}
		groupLines = append(groupLines,
			fmt.Sprintf("[group %s]", item.NetworkID),
			"Policy: "+firstNonEmpty(strings.ToLower(strings.TrimSpace(item.Policy)), "-"),
			"Blocked Packets: "+strconv.Itoa(item.BlockedPacketCount),
			"Flood Events: "+strconv.Itoa(item.FloodPacketCount),
			"Fanout Copies: "+strconv.Itoa(item.FanoutCopyCount),
			"Broadcast Packets: "+strconv.Itoa(item.BroadcastPacketCount),
			"Multicast Packets: "+strconv.Itoa(item.MulticastPacketCount),
			"Last Action: "+firstNonEmpty(strings.ToLower(strings.TrimSpace(item.LastAction)), "-"),
			"Last Packet: "+formatUnix(item.LastPacketUnix),
			"",
		)
	}
	if len(groupLines) > 0 {
		lines = append(lines, "Group Traffic")
		lines = append(lines, groupLines...)
	}
	for _, connection := range status.Connections {
		if selected != nil && connection.NetworkID != selected.ID {
			continue
		}
		lines = append(lines,
			fmt.Sprintf("[%s] %s -> %s", connection.NetworkID, connection.LocalPeerID, connection.RemotePeerID),
			"Remote Virtual IP: "+firstNonEmpty(connection.RemoteVirtualIP, "-"),
			"Remote Endpoint: "+firstNonEmpty(connection.RemoteEndpoint, "-"),
			"Candidates: "+strconv.Itoa(connection.RemoteCandidateCount),
			"Candidate List: "+joinOrDash(connection.RemoteCandidates),
			"Reachability: "+firstNonEmpty(connection.Reachability, "-"),
			"State: "+firstNonEmpty(connection.State, "-"),
			"Selected Candidate: "+firstNonEmpty(connection.SelectedCandidate, "-"),
			"Attempts: "+strconv.Itoa(connection.AttemptCount),
			"Last Attempt: "+formatUnix(connection.LastAttemptUnix),
			"Next Retry: "+formatUnix(connection.NextRetryUnix),
			"Tunnel: "+firstNonEmpty(connection.TunnelID, "-"),
			"Tunnel Mode: "+firstNonEmpty(connection.TunnelMode, "-"),
			"Tunnel State: "+firstNonEmpty(connection.TunnelState, "-"),
			"Transport Ready: "+yesNo(connection.TransportReady),
			"Transport Mode: "+firstNonEmpty(connection.TransportMode, "-"),
			"Transport Session: "+firstNonEmpty(connection.TransportSessionID, "-"),
			"Transport Established: "+formatUnix(connection.TransportEstablishedUnix),
			"Transport Packets: "+strconv.Itoa(connection.TransportPacketCount),
			"Last Transport Packet: "+formatUnix(connection.LastTransportUnix),
			"Rekey Due: "+formatUnix(connection.TransportRekeyDueUnix),
			"Last Keepalive: "+formatUnix(connection.LastKeepaliveUnix),
			"RTT: "+formatMillis(connection.LastRTTMillis),
			"Average RTT: "+formatMillis(connection.AverageRTTMillis),
			"Consecutive Losses: "+strconv.Itoa(connection.ConsecutiveLosses),
			"Group Traffic Copies: "+strconv.Itoa(connection.GroupTrafficPacketCopies),
			"Group Broadcast Copies: "+strconv.Itoa(connection.GroupBroadcastCopies),
			"Group Multicast Copies: "+strconv.Itoa(connection.GroupMulticastCopies),
			"Last Group Traffic: "+formatUnix(connection.LastGroupTrafficUnix),
			"Last Error: "+firstNonEmpty(connection.LastError, "-"),
			"",
		)
	}
	if len(lines) == 0 {
		if selected != nil {
			return "No managed connections for the selected network yet."
		}
		return "No managed connections yet."
	}
	return strings.Join(lines, "\r\n")
}

func formatNeighborSummaryLine(neighbor clientagent.NeighborStatus) string {
	return fmt.Sprintf(
		"- %s | net=%s | %s | %s | candidates=%d | path=%s | last seen=%s",
		firstNonEmpty(neighbor.RemotePeerID, "-"),
		firstNonEmpty(neighbor.NetworkID, "-"),
		firstNonEmpty(neighbor.Presence, "-"),
		firstNonEmpty(neighbor.NeighborState, "-"),
		neighbor.CandidateCount,
		firstNonEmpty(neighbor.TransportMode, firstNonEmpty(neighbor.Reachability, "-")),
		formatUnix(neighbor.LastSeenUnix),
	)
}

func formatDevices(devices []Device, status *clientagent.Status) string {
	return formatDeviceDetails(devices, firstDeviceOrNil(devices), status)
}

func formatDeviceSummaryLine(device Device, status *clientagent.Status) string {
	parts := []string{
		firstNonEmpty(device.Name, "Unnamed device"),
		"trust=" + deviceTrustLabel(device, status),
		"server=" + firstNonEmpty(device.Status, "-"),
	}
	if fingerprint := shortFingerprint(device.Fingerprint); fingerprint != "-" {
		parts = append(parts, "fingerprint="+fingerprint)
	}
	return strings.Join(parts, " | ")
}

func formatDeviceDetails(devices []Device, selected *Device, status *clientagent.Status) string {
	return formatDeviceDetailsForNetwork(devices, selected, nil, status)
}

type networkGatewayDiagnostics struct {
	NetworkID       string
	RoutingPolicy   string
	PolicyStatus    string
	GatewayRole     string
	GatewayPeerID   string
	ConnectionState string
	TransportMode   string
	Reachability    string
	LastRTTMillis   int64
	Losses          int
	LastError       string
}

type networkTransportQualitySummary struct {
	NetworkID            string
	ConnectionCount      int
	ConnectedCount       int
	PendingCount         int
	FallbackReadyCount   int
	DirectCount          int
	RelayCount           int
	HealthyCount         int
	DegradedCount        int
	AverageRTTMillis     int64
	WorstLosses          int
	TransportPacketCount int
	LastTransportUnix    int64
	Quality              string
}

func formatDeviceDetailsForNetwork(devices []Device, selected *Device, network *Network, status *clientagent.Status) string {
	if status == nil || status.CurrentSession == nil {
		return "Sign in to inspect trusted devices."
	}
	if len(devices) == 0 {
		return "No devices are visible for the current account yet."
	}

	total := len(devices)
	trusted := 0
	revoked := 0
	for _, device := range devices {
		if strings.EqualFold(device.Status, "ACTIVE") && device.RevokedAtUnix <= 0 {
			trusted++
		} else {
			revoked++
		}
	}

	lines := []string{
		fmt.Sprintf("Summary: total=%d | trusted=%d | revoked=%d | current=%s | enrollment=%s",
			total,
			trusted,
			revoked,
			firstNonEmpty(status.Security.CurrentDeviceID, "-"),
			firstNonEmpty(status.Security.EnrollmentStatus, "-"),
		),
	}

	if selected == nil {
		lines = append(lines, "", "Select a device to inspect its fingerprint and full details.")
		return strings.Join(lines, "\r\n")
	}

	lines = append(lines,
		"",
		"Selected Device",
		"Name: "+firstNonEmpty(selected.Name, "Unnamed device"),
		"Trust: "+deviceTrustLabel(*selected, status),
		"Server Status: "+firstNonEmpty(selected.Status, "-"),
		"Fingerprint: "+firstNonEmpty(selected.Fingerprint, "-"),
		"ID: "+firstNonEmpty(selected.ID, "-"),
		"User ID: "+firstNonEmpty(selected.UserID, "-"),
		"Created: "+formatUnix(selected.CreatedAtUnix),
		"Revoked: "+formatUnix(selected.RevokedAtUnix),
	)
	if network != nil {
		selectedApproval := networkDeviceApprovalState(*network, firstNonEmpty(selected.ID, ""))
		lines = append(lines,
			"",
			"Selected Network",
			"ID: "+firstNonEmpty(network.ID, "-"),
			"Name: "+firstNonEmpty(network.Name, "-"),
			"Sensitive: "+yesNo(network.DeviceApprovalRequired),
			"Current Role: "+formatNetworkRole(firstNonEmpty(networkRoleForCurrentUser(*network, status), "OUTSIDER")),
			"Current Permissions: "+formatNetworkPermissionSummary(networkRoleForCurrentUser(*network, status)),
			"Routing Policy: "+formatNetworkRoutingPolicy(network.RoutingPolicy),
			"Group Traffic: "+formatNetworkGroupTrafficPolicy(network.GroupTrafficPolicy),
			"Name Resolution: "+formatNetworkNameResolution(network.NameResolutionMode, network.DNSLabel),
			"File Transfers: "+formatNetworkFileTransferPolicy(networkFileTransfersEnabledOrDefault(*network), network.FileTransferMaxBytes),
			"Selected Device Approval: "+selectedApproval,
		)
		lines = append(lines, formatNetworkPermissionMatrix()...)
		lines = append(lines, "Owner-only Note: deleting the network and changing member roles stay owner-only.")
		currentDeviceID := currentServiceDeviceID(status)
		if currentDeviceID != "" && currentDeviceID != selected.ID {
			lines = append(lines, "Current Service Device Approval: "+networkDeviceApprovalState(*network, currentDeviceID))
		}
		if network.DeviceApprovalRequired && strings.EqualFold(selectedApproval, "pending approval") {
			lines = append(lines, "Next Action: Press `Approve For Network` before `Connect This PC` or `Reconnect This PC`.")
		}
		if strings.EqualFold(networkRoutingPolicyOrDefault(*network), "FULL") {
			lines = append(lines, "Routing Note: FULL sends non-overlay IPv4 through an OWNER or ADMIN gateway on the selected network.")
			lines = append(lines, formatGatewaySummaryForNetwork(status, network)...)
			if events := gatewayHistoryForNetwork(status, network.ID); len(events) > 0 {
				lines = append(lines,
					"Gateway Last Change: "+formatGatewayEventSummary(events[0]),
					"Gateway Recent Changes: "+strconv.Itoa(len(events)),
				)
			}
		}
		if transportSummary := summarizeNetworkTransportQuality(status, network.ID); transportSummary != nil {
			lines = append(lines,
				"Transport Summary: "+transportSummary.Quality,
				"Transport Paths: "+formatTransportPathCounts(transportSummary),
				"Transport RTT: "+formatMillis(transportSummary.AverageRTTMillis),
				"Transport Worst Losses: "+strconv.Itoa(transportSummary.WorstLosses),
				"Transport Packets: "+strconv.Itoa(transportSummary.TransportPacketCount),
				"Transport Last Packet: "+formatUnix(transportSummary.LastTransportUnix),
				"Transport Next Action: "+formatTransportSummaryNextAction(transportSummary),
			)
		}
		if strings.EqualFold(networkGroupTrafficPolicyOrDefault(*network), "FLOOD") {
			lines = append(lines, "Group Traffic Note: FLOOD fans out IPv4 broadcast and multicast packets to connected peers on this network.")
		}
	}
	return strings.Join(lines, "\r\n")
}

func networkDeviceApproved(network Network, device Device) bool {
	if !network.DeviceApprovalRequired {
		return true
	}
	for _, approvedDeviceID := range network.ApprovedDeviceIDs {
		if approvedDeviceID == device.ID {
			return true
		}
	}
	return false
}

func networkDeviceApprovalState(network Network, deviceID string) string {
	if !network.DeviceApprovalRequired {
		return "not required"
	}
	if strings.TrimSpace(deviceID) == "" {
		return "unknown"
	}
	for _, approvedDeviceID := range network.ApprovedDeviceIDs {
		if approvedDeviceID == deviceID {
			return "approved"
		}
	}
	return "pending approval"
}

func currentServiceDeviceID(status *clientagent.Status) string {
	if status == nil {
		return ""
	}
	if status.CurrentDevice != nil && strings.TrimSpace(status.CurrentDevice.ID) != "" {
		return status.CurrentDevice.ID
	}
	return strings.TrimSpace(status.Security.CurrentDeviceID)
}

func peerOwnedByCurrentOperator(peer Peer, status *clientagent.Status) bool {
	if peer.ID == "" {
		return false
	}
	currentDeviceID := currentServiceDeviceID(status)
	if currentDeviceID != "" && strings.EqualFold(strings.TrimSpace(peer.DeviceID), currentDeviceID) {
		return true
	}
	userID := currentUserID(status)
	return userID != "" && strings.EqualFold(strings.TrimSpace(peer.UserID), userID)
}

func preferredOperatorPeerID(peers []Peer, status *clientagent.Status) string {
	currentDeviceID := currentServiceDeviceID(status)
	if currentDeviceID != "" {
		if peer := bestPeerByMatch(peers, func(candidate Peer) bool {
			return strings.EqualFold(strings.TrimSpace(candidate.DeviceID), currentDeviceID)
		}); peer != nil {
			return strings.TrimSpace(peer.ID)
		}
	}
	if peer := bestPeerByMatch(peers, func(candidate Peer) bool {
		return peerOwnedByCurrentOperator(candidate, status)
	}); peer != nil {
		return strings.TrimSpace(peer.ID)
	}
	return ""
}

func bestPeerByMatch(peers []Peer, match func(Peer) bool) *Peer {
	var best *Peer
	bestScore := -1
	var bestSeen int64
	for _, peer := range peers {
		if !match(peer) {
			continue
		}
		score := peerActivityScore(peer)
		if best == nil || score > bestScore || (score == bestScore && peer.LastSeenUnix > bestSeen) {
			candidate := peer
			best = &candidate
			bestScore = score
			bestSeen = peer.LastSeenUnix
		}
	}
	return best
}

func peerActivityScore(peer Peer) int {
	score := 0
	switch strings.ToUpper(strings.TrimSpace(peer.ConnectionState)) {
	case "CONNECTED":
		score += 120
	case "NEGOTIATING", "DIRECT_CANDIDATE", "RELAY_READY", "DISCOVERING":
		score += 80
	}
	if strings.EqualFold(strings.TrimSpace(peer.Status), "ONLINE") {
		score += 40
	}
	if peer.LastSeenUnix > 0 && time.Since(time.Unix(peer.LastSeenUnix, 0)) <= 2*time.Minute {
		score += 20
	}
	return score
}

func buildOperatorPeerChoices(peers []Peer, status *clientagent.Status, includePlaceholder bool) []peerChoice {
	owned := make([]Peer, 0, len(peers))
	for _, peer := range peers {
		if !peerOwnedByCurrentOperator(peer, status) {
			continue
		}
		owned = append(owned, peer)
	}
	owned = dedupePeersForChoices(owned)
	choices := make([]peerChoice, 0, len(owned))
	for _, peer := range owned {
		choices = append(choices, peerChoice{
			ID:    strings.TrimSpace(peer.ID),
			Label: peerChoiceLabel(peer, true),
		})
	}
	if len(choices) == 0 && includePlaceholder {
		return []peerChoice{{Label: "No local peer available"}}
	}
	return choices
}

func buildRecipientPeerChoices(peers []Peer, excludePeerID string) []peerChoice {
	filtered := make([]Peer, 0, len(peers))
	for _, peer := range peers {
		if strings.EqualFold(strings.TrimSpace(peer.ID), strings.TrimSpace(excludePeerID)) {
			continue
		}
		filtered = append(filtered, peer)
	}
	filtered = dedupePeersForChoices(filtered)
	choices := make([]peerChoice, 0, len(filtered))
	for _, peer := range filtered {
		choices = append(choices, peerChoice{
			ID:    strings.TrimSpace(peer.ID),
			Label: peerChoiceLabel(peer, false),
		})
	}
	if len(choices) == 0 {
		return []peerChoice{{Label: "No recipient peer available"}}
	}
	return choices
}

func buildFilterPeerChoices(peers []Peer) []peerChoice {
	choices := []peerChoice{{Label: "All Peers"}}
	for _, peer := range dedupePeersForChoices(peers) {
		choices = append(choices, peerChoice{
			ID:    strings.TrimSpace(peer.ID),
			Label: peerChoiceLabel(peer, false),
		})
	}
	return choices
}

func peerChoiceLabel(peer Peer, local bool) string {
	role := "remote"
	if local {
		role = "local"
	}
	parts := []string{
		firstNonEmpty(peer.ID, "-"),
		firstNonEmpty(peer.VirtualIP, "-"),
		role,
		firstNonEmpty(strings.ToLower(strings.TrimSpace(peer.Status)), "unknown"),
	}
	return strings.Join(parts, " | ")
}

func dedupePeersForChoices(peers []Peer) []Peer {
	if len(peers) < 2 {
		return peers
	}
	out := make([]Peer, 0, len(peers))
	indexByKey := make(map[string]int, len(peers))
	for _, peer := range peers {
		key := dedupePeerChoiceKey(peer)
		if key == "" {
			out = append(out, peer)
			continue
		}
		if idx, ok := indexByKey[key]; ok {
			if betterPeerChoice(peer, out[idx]) {
				out[idx] = peer
			}
			continue
		}
		indexByKey[key] = len(out)
		out = append(out, peer)
	}
	return out
}

func dedupePeerChoiceKey(peer Peer) string {
	userID := strings.TrimSpace(peer.UserID)
	virtualIP := strings.TrimSpace(peer.VirtualIP)
	if userID == "" || virtualIP == "" {
		return ""
	}
	networkID := strings.TrimSpace(peer.NetworkID)
	return strings.ToLower(networkID) + "|" + strings.ToLower(userID) + "|" + strings.ToLower(virtualIP)
}

func betterPeerChoice(candidate, current Peer) bool {
	if peerActivityScore(candidate) != peerActivityScore(current) {
		return peerActivityScore(candidate) > peerActivityScore(current)
	}
	if candidate.LastSeenUnix != current.LastSeenUnix {
		return candidate.LastSeenUnix > current.LastSeenUnix
	}
	return strings.Compare(strings.TrimSpace(candidate.ID), strings.TrimSpace(current.ID)) < 0
}

func peerLookupByID(peers []Peer) map[string]Peer {
	if len(peers) == 0 {
		return nil
	}
	lookup := make(map[string]Peer, len(peers))
	for _, peer := range peers {
		if strings.TrimSpace(peer.ID) == "" {
			continue
		}
		lookup[strings.TrimSpace(peer.ID)] = peer
	}
	return lookup
}

func peerReferenceLabel(peerID string, peersByID map[string]Peer) string {
	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return "-"
	}
	if peer, ok := peersByID[peerID]; ok {
		if strings.TrimSpace(peer.VirtualIP) != "" {
			return fmt.Sprintf("%s (%s)", peerID, peer.VirtualIP)
		}
	}
	return peerID
}

func messagePeerReferenceLabel(message Message, peersByID map[string]Peer, peers []Peer) string {
	peerID := strings.TrimSpace(message.FromPeerID)
	if peerID == "" {
		return "-"
	}
	peer, ok := peersByID[peerID]
	if !ok {
		return peerID
	}
	replacement := bestPeerForUserAndNetwork(peers, peer.UserID, peer.NetworkID)
	if replacement != nil && strings.TrimSpace(replacement.ID) != "" && !strings.EqualFold(strings.TrimSpace(replacement.ID), peerID) && betterPeerChoice(*replacement, peer) {
		replacementLabel := peerReferenceLabel(replacement.ID, peersByID)
		return fmt.Sprintf("%s -> %s", peerID, replacementLabel)
	}
	return peerReferenceLabel(peerID, peersByID)
}

func transferPeerReferenceLabel(peerID, userID, networkID string, peersByID map[string]Peer, peers []Peer) string {
	peerID = strings.TrimSpace(peerID)
	if peerID != "" {
		if _, ok := peersByID[peerID]; ok {
			return peerReferenceLabel(peerID, peersByID)
		}
	}
	userID = strings.TrimSpace(userID)
	networkID = strings.TrimSpace(networkID)
	if userID != "" {
		if replacement := findPeerByUserAndNetwork(peers, userID, networkID); replacement != nil && strings.TrimSpace(replacement.ID) != "" {
			replacementLabel := peerReferenceLabel(replacement.ID, peersByID)
			if peerID != "" && !strings.EqualFold(peerID, strings.TrimSpace(replacement.ID)) {
				return fmt.Sprintf("%s -> %s", peerID, replacementLabel)
			}
			return replacementLabel
		}
	}
	if peerID != "" {
		return peerID
	}
	return "-"
}

func bestPeerForUserAndNetwork(peers []Peer, userID, networkID string) *Peer {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil
	}
	return bestPeerByMatch(peers, func(candidate Peer) bool {
		if !strings.EqualFold(strings.TrimSpace(candidate.UserID), userID) {
			return false
		}
		if networkID == "" {
			return true
		}
		return strings.EqualFold(strings.TrimSpace(candidate.NetworkID), strings.TrimSpace(networkID))
	})
}

func findPeerByUserAndNetwork(peers []Peer, userID, networkID string) *Peer {
	for _, peer := range peers {
		if !strings.EqualFold(strings.TrimSpace(peer.UserID), strings.TrimSpace(userID)) {
			continue
		}
		if networkID != "" && !strings.EqualFold(strings.TrimSpace(peer.NetworkID), networkID) {
			continue
		}
		candidate := peer
		return &candidate
	}
	return nil
}

func filterMessages(messages []Message, query, fromPeerID string, peers []Peer) []Message {
	normalizedQuery := strings.ToLower(strings.TrimSpace(query))
	normalizedPeerID := strings.TrimSpace(fromPeerID)
	filtered := make([]Message, 0, len(messages))
	for _, message := range messages {
		if normalizedPeerID != "" && !messageMatchesPeerFilter(message, normalizedPeerID, peers) {
			continue
		}
		if normalizedQuery != "" && !matchesTextFilter(normalizedQuery, message.ID, message.FromPeerID, message.Text, message.Preview) {
			continue
		}
		filtered = append(filtered, message)
	}
	return filtered
}

func messageMatchesPeerFilter(message Message, peerID string, peers []Peer) bool {
	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(message.FromPeerID), peerID) {
		return true
	}
	var userID string
	var networkID string
	for _, peer := range peers {
		if !strings.EqualFold(strings.TrimSpace(peer.ID), peerID) {
			continue
		}
		userID = strings.TrimSpace(peer.UserID)
		networkID = strings.TrimSpace(peer.NetworkID)
		break
	}
	if userID == "" {
		return false
	}
	for _, peer := range peers {
		if !strings.EqualFold(strings.TrimSpace(peer.UserID), userID) {
			continue
		}
		if networkID != "" && strings.TrimSpace(message.NetworkID) != "" && !strings.EqualFold(strings.TrimSpace(peer.NetworkID), strings.TrimSpace(message.NetworkID)) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(message.FromPeerID), strings.TrimSpace(peer.ID)) {
			return true
		}
	}
	return false
}

func filterFileTransfers(transfers []FileTransfer, query, mailboxFilter, statusFilter, peerID string, peers []Peer, status *clientagent.Status) []FileTransfer {
	normalizedQuery := strings.ToLower(strings.TrimSpace(query))
	normalizedMailbox := strings.ToUpper(strings.TrimSpace(mailboxFilter))
	if normalizedMailbox == "ALL TRANSFERS" {
		normalizedMailbox = ""
	}
	normalizedStatus := strings.ToUpper(strings.TrimSpace(statusFilter))
	if normalizedStatus == "ALL STATUSES" {
		normalizedStatus = ""
	}
	normalizedPeerID := strings.TrimSpace(peerID)
	filtered := make([]FileTransfer, 0, len(transfers))
	for _, transfer := range transfers {
		if normalizedMailbox != "" && !matchesTransferMailbox(transfer, normalizedMailbox, peers, status) {
			continue
		}
		if normalizedStatus != "" && !matchesTransferStatus(transfer.Status, normalizedStatus) {
			continue
		}
		if normalizedPeerID != "" && !transferMatchesPeerFilter(transfer, normalizedPeerID, peers) {
			continue
		}
		if normalizedQuery != "" && !matchesTextFilter(normalizedQuery, transfer.ID, transfer.FileName, transfer.FromPeerID, transfer.ToPeerID, transfer.CancelReason) {
			continue
		}
		filtered = append(filtered, transfer)
	}
	return filtered
}

func matchesTransferMailbox(transfer FileTransfer, mailbox string, peers []Peer, status *clientagent.Status) bool {
	switch mailbox {
	case "INBOX":
		return transferPeerOwnedByCurrentOperator(transfer.ToPeerID, transfer.ToUserID, peers, status)
	case "SENT":
		return transferPeerOwnedByCurrentOperator(transfer.FromPeerID, transfer.FromUserID, peers, status)
	default:
		return true
	}
}

func matchesTransferStatus(statusValue, filter string) bool {
	statusValue = strings.ToUpper(strings.TrimSpace(statusValue))
	filter = strings.ToUpper(strings.TrimSpace(filter))
	if filter == "" {
		return true
	}
	if filter == "PENDING" && statusValue == "INIT" {
		return true
	}
	return statusValue == filter
}

func transferPeerOwnedByCurrentOperator(peerID, userID string, peers []Peer, status *clientagent.Status) bool {
	peerID = strings.TrimSpace(peerID)
	if peerID != "" {
		for _, peer := range peers {
			if strings.EqualFold(strings.TrimSpace(peer.ID), peerID) {
				return peerOwnedByCurrentOperator(peer, status)
			}
		}
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return false
	}
	return strings.EqualFold(userID, currentUserID(status))
}

func transferMatchesPeerFilter(transfer FileTransfer, peerID string, peers []Peer) bool {
	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(transfer.FromPeerID), peerID) || strings.EqualFold(strings.TrimSpace(transfer.ToPeerID), peerID) {
		return true
	}
	for _, peer := range peers {
		if !strings.EqualFold(strings.TrimSpace(peer.ID), peerID) {
			continue
		}
		userID := strings.TrimSpace(peer.UserID)
		if userID == "" {
			return false
		}
		if peer.NetworkID != "" && !strings.EqualFold(strings.TrimSpace(peer.NetworkID), strings.TrimSpace(transfer.NetworkID)) {
			return false
		}
		return strings.EqualFold(strings.TrimSpace(transfer.FromUserID), userID) || strings.EqualFold(strings.TrimSpace(transfer.ToUserID), userID)
	}
	return false
}

func matchesTextFilter(query string, values ...string) bool {
	if query == "" {
		return true
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(strings.TrimSpace(value)), query) {
			return true
		}
	}
	return false
}

func networkRequiresCurrentDeviceApproval(network *Network, status *clientagent.Status) bool {
	if network == nil || !network.DeviceApprovalRequired {
		return false
	}
	currentDeviceID := currentServiceDeviceID(status)
	if currentDeviceID == "" {
		return false
	}
	return !strings.EqualFold(networkDeviceApprovalState(*network, currentDeviceID), "approved")
}

func formatJoinStatus(network *Network, status *clientagent.Status) string {
	if network == nil {
		return "Joined network."
	}
	message := "Joined network: " + firstNonEmpty(network.Name, network.ID)
	if networkRequiresCurrentDeviceApproval(network, status) {
		return message + " | current device approval pending before `Connect This PC`."
	}
	return message
}

func formatNetworkSummaryLine(network Network, status *clientagent.Status) string {
	approvalMode := "auto-join"
	if network.DeviceApprovalRequired {
		switch networkDeviceApprovalState(network, currentServiceDeviceID(status)) {
		case "approved":
			approvalMode = "device-approval current-approved"
		case "pending approval":
			approvalMode = "device-approval current-pending"
		default:
			approvalMode = fmt.Sprintf("device-approval (%d)", len(network.ApprovedDeviceIDs))
		}
	}
	routingSummary := "routing=" + formatNetworkRoutingPolicy(network.RoutingPolicy)
	if strings.EqualFold(networkRoutingPolicyOrDefault(network), "FULL") {
		routingSummary += " (" + formatGatewaySummaryCompact(status, &network) + ")"
	}
	transportSummary := ""
	if summary := summarizeNetworkTransportQuality(status, network.ID); summary != nil {
		transportSummary = " | transport=" + summary.Quality
	}
	roleSummary := ""
	if role := networkRoleForCurrentUser(network, status); role != "" {
		roleSummary = " | role=" + formatNetworkRole(role)
	}
	return fmt.Sprintf(
		"%s | %s | %s | %s | %s%s | group=%s | dns=%s | files=%s | members: %d%s",
		network.ID,
		network.Name,
		network.Access,
		approvalMode,
		routingSummary,
		transportSummary,
		formatNetworkGroupTrafficPolicy(network.GroupTrafficPolicy),
		formatNetworkNameResolution(network.NameResolutionMode, network.DNSLabel),
		formatNetworkFileTransferPolicy(networkFileTransfersEnabledOrDefault(network), network.FileTransferMaxBytes),
		len(network.Members),
		roleSummary,
	)
}

func currentUserID(status *clientagent.Status) string {
	if status == nil {
		return ""
	}
	if status.CurrentUser != nil && strings.TrimSpace(status.CurrentUser.ID) != "" {
		return strings.TrimSpace(status.CurrentUser.ID)
	}
	if status.CurrentSession != nil {
		return strings.TrimSpace(status.CurrentSession.UserID)
	}
	return ""
}

func networkRoleForCurrentUser(network Network, status *clientagent.Status) string {
	userID := currentUserID(status)
	if userID == "" {
		return ""
	}
	if role, ok := network.MemberRoles[userID]; ok && strings.TrimSpace(role) != "" {
		return strings.TrimSpace(role)
	}
	if strings.EqualFold(strings.TrimSpace(network.OwnerID), userID) {
		return "OWNER"
	}
	for _, memberID := range network.Members {
		if strings.EqualFold(strings.TrimSpace(memberID), userID) {
			return "MEMBER"
		}
	}
	return ""
}

func formatNetworkRole(role string) string {
	switch strings.ToUpper(strings.TrimSpace(role)) {
	case "OWNER":
		return "owner"
	case "ADMIN":
		return "admin"
	case "MODERATOR":
		return "moderator"
	case "FILE_ADMIN":
		return "file-admin"
	case "MEMBER":
		return "member"
	case "READ_ONLY":
		return "read-only"
	case "OUTSIDER":
		return "outsider"
	default:
		return firstNonEmpty(strings.ToLower(strings.TrimSpace(role)), "-")
	}
}

func formatNetworkPermissionSummary(role string) string {
	capabilities := networkPermissionCapabilities(role)
	if len(capabilities) == 0 {
		return "none"
	}
	return strings.Join(capabilities, ", ")
}

func formatNetworkPermissionMatrix() []string {
	roles := []string{"OWNER", "ADMIN", "MODERATOR", "FILE_ADMIN", "MEMBER", "READ_ONLY"}
	lines := []string{"Role Matrix:"}
	for _, role := range roles {
		lines = append(lines, fmt.Sprintf("%s: %s", formatNetworkRole(role), formatNetworkPermissionSummary(role)))
	}
	return lines
}

func networkPermissionCapabilities(role string) []string {
	normalized := domain.NetworkRole(strings.ToUpper(strings.TrimSpace(role)))
	if normalized == "" {
		return nil
	}
	capabilities := make([]string, 0, 8)
	if domain.HasPermission(normalized, domain.PermissionViewNetwork) {
		capabilities = append(capabilities, "view")
	}
	if domain.HasPermission(normalized, domain.PermissionUseNetwork) {
		capabilities = append(capabilities, "use")
	}
	if domain.HasPermission(normalized, domain.PermissionManageNetworkSettings) {
		capabilities = append(capabilities, "settings")
	}
	if domain.HasPermission(normalized, domain.PermissionManageInvites) {
		capabilities = append(capabilities, "invites")
	}
	if domain.HasPermission(normalized, domain.PermissionManageMembers) {
		capabilities = append(capabilities, "members")
	}
	if domain.HasPermission(normalized, domain.PermissionManageFiles) {
		capabilities = append(capabilities, "files")
	}
	if domain.HasPermission(normalized, domain.PermissionModerate) {
		capabilities = append(capabilities, "moderate")
	}
	if domain.HasPermission(normalized, domain.PermissionDeleteNetwork) {
		capabilities = append(capabilities, "delete")
	}
	return capabilities
}

func networkRoutingPolicyOrDefault(network Network) string {
	policy := strings.ToUpper(strings.TrimSpace(network.RoutingPolicy))
	if policy == "" {
		return "SPLIT"
	}
	return policy
}

func networkGroupTrafficPolicyOrDefault(network Network) string {
	policy := strings.ToUpper(strings.TrimSpace(network.GroupTrafficPolicy))
	if policy == "" {
		return "BLOCKED"
	}
	return policy
}

func formatNetworkRoutingPolicy(policy string) string {
	normalized := strings.ToUpper(strings.TrimSpace(policy))
	if normalized == "" {
		normalized = "SPLIT"
	}
	switch normalized {
	case "FULL":
		return "full"
	default:
		return "split"
	}
}

func formatNetworkGroupTrafficPolicy(policy string) string {
	switch strings.ToUpper(strings.TrimSpace(policy)) {
	case "FLOOD":
		return "flood"
	default:
		return "blocked"
	}
}

func networkNameResolutionModeOrDefault(network Network) string {
	mode := strings.ToUpper(strings.TrimSpace(network.NameResolutionMode))
	if mode == "" {
		return "DEFAULT"
	}
	return mode
}

func formatNetworkNameResolution(mode, dnsLabel string) string {
	mode = strings.ToUpper(strings.TrimSpace(mode))
	if mode == "" {
		mode = "DEFAULT"
	}
	label := strings.TrimSpace(dnsLabel)
	switch mode {
	case "NETWORK_ONLY":
		if label == "" {
			return "network-only"
		}
		return "network-only (" + label + ")"
	case "DISABLED":
		return "disabled"
	default:
		if label == "" {
			return "default"
		}
		return "default (" + label + ")"
	}
}

func networkFileTransferMaxBytesOrDefault(network Network) int64 {
	if network.FileTransferMaxBytes > 0 {
		return network.FileTransferMaxBytes
	}
	return defaultNetworkFileTransferMaxBytes()
}

func networkFileTransfersEnabledOrDefault(network Network) bool {
	if !network.FileTransfersEnabled && network.FileTransferMaxBytes == 0 {
		return true
	}
	return network.FileTransfersEnabled
}

func formatNetworkFileTransferPolicy(enabled bool, maxBytes int64) string {
	if !enabled {
		return "disabled"
	}
	return fmt.Sprintf("enabled (%d bytes)", networkFileTransferMaxBytesOrDefault(Network{FileTransferMaxBytes: maxBytes}))
}

func parseFileTransferMaxBytes(raw string) (int64, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return defaultNetworkFileTransferMaxBytes(), nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("file transfer max bytes must be a whole number")
	}
	return parsed, nil
}

func defaultNetworkFileTransferMaxBytes() int64 {
	return domain.DefaultNetworkFileTransferMaxBytes
}

func defaultControlPlaneFileTransferPayloadMaxBytes() int64 {
	return domain.DefaultControlPlaneFileTransferPayloadMaxBytes
}

type transferDownloadTargetState int

const (
	transferDownloadTargetEmpty transferDownloadTargetState = iota
	transferDownloadTargetPartial
	transferDownloadTargetComplete
)

func readTransferSourceMetadata(sourcePath string) (string, int64, error) {
	path := strings.TrimSpace(sourcePath)
	if path == "" {
		return "", 0, fmt.Errorf("choose a local file first")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", 0, err
	}
	if info.IsDir() {
		return "", 0, fmt.Errorf("expected a file, got a directory")
	}
	if info.Size() <= 0 {
		return "", 0, fmt.Errorf("empty files are not supported yet")
	}
	return filepath.Base(path), info.Size(), nil
}

func validateTransferUploadSource(transfer FileTransfer, sourceSizeBytes int64) error {
	if transfer.SizeBytes <= 0 {
		return fmt.Errorf("file transfer size is invalid")
	}
	if sourceSizeBytes != transfer.SizeBytes {
		return fmt.Errorf("local file size %d does not match transfer size %d", sourceSizeBytes, transfer.SizeBytes)
	}
	if transfer.PayloadUploadedBytes < 0 {
		return fmt.Errorf("file transfer upload offset is invalid")
	}
	if transfer.PayloadUploadedBytes > transfer.SizeBytes {
		return fmt.Errorf("file transfer upload offset %d exceeds transfer size %d", transfer.PayloadUploadedBytes, transfer.SizeBytes)
	}
	return nil
}

func inspectTransferDownloadTarget(existingSize, totalSize int64) (transferDownloadTargetState, error) {
	switch {
	case existingSize <= 0:
		return transferDownloadTargetEmpty, nil
	case totalSize <= 0:
		return transferDownloadTargetEmpty, fmt.Errorf("file transfer size is invalid")
	case existingSize < totalSize:
		return transferDownloadTargetPartial, nil
	case existingSize == totalSize:
		return transferDownloadTargetComplete, nil
	default:
		return transferDownloadTargetEmpty, fmt.Errorf("existing file size %d exceeds transfer size %d", existingSize, totalSize)
	}
}

func inferFileTransferContentType(fileName string) string {
	return mime.TypeByExtension(strings.ToLower(filepath.Ext(strings.TrimSpace(fileName))))
}

func promptYesNo(owner walk.Form, title, message string) bool {
	return walk.MsgBox(owner, title, message, walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == walk.DlgCmdYes
}

func formatNetworkTransportSummaryLines(status *clientagent.Status, selected *Network) []string {
	if status == nil {
		return nil
	}
	targets := make([]string, 0, 1)
	if selected != nil {
		targets = append(targets, selected.ID)
	} else {
		seen := map[string]struct{}{}
		for _, connection := range status.Connections {
			networkID := strings.TrimSpace(connection.NetworkID)
			if networkID == "" {
				continue
			}
			if _, ok := seen[networkID]; ok {
				continue
			}
			seen[networkID] = struct{}{}
			targets = append(targets, networkID)
		}
	}
	lines := []string{}
	for _, networkID := range targets {
		summary := summarizeNetworkTransportQuality(status, networkID)
		if summary == nil {
			continue
		}
		lines = append(lines,
			fmt.Sprintf("[%s]", firstNonEmpty(summary.NetworkID, "-")),
			"Quality: "+summary.Quality,
			"Connections: "+formatTransportPathCounts(summary),
			"Connected Modes: direct="+strconv.Itoa(summary.DirectCount)+" | relay="+strconv.Itoa(summary.RelayCount),
			"Connection Quality: healthy="+strconv.Itoa(summary.HealthyCount)+" | degraded="+strconv.Itoa(summary.DegradedCount),
			"Average RTT: "+formatMillis(summary.AverageRTTMillis),
			"Worst Losses: "+strconv.Itoa(summary.WorstLosses),
			"Transport Packets: "+strconv.Itoa(summary.TransportPacketCount),
			"Last Transport Packet: "+formatUnix(summary.LastTransportUnix),
			"Next Action: "+formatTransportSummaryNextAction(summary),
			"",
		)
	}
	if len(lines) == 0 {
		return nil
	}
	return lines
}

func summarizeNetworkTransportQuality(status *clientagent.Status, networkID string) *networkTransportQualitySummary {
	if status == nil || strings.TrimSpace(networkID) == "" {
		return nil
	}
	summary := &networkTransportQualitySummary{NetworkID: networkID}
	rttSamples := int64(0)
	for _, connection := range status.Connections {
		if connection.NetworkID != networkID {
			continue
		}
		summary.ConnectionCount++
		switch connectionQualityClass(connection) {
		case "healthy":
			summary.HealthyCount++
		case "degraded":
			summary.DegradedCount++
		case "pending":
			summary.PendingCount++
		case "fallback-ready":
			summary.FallbackReadyCount++
		}
		if strings.EqualFold(connection.State, "CONNECTED") {
			summary.ConnectedCount++
		}
		if strings.EqualFold(connection.TransportMode, "DIRECT") || strings.EqualFold(connection.Reachability, "DIRECT") {
			if strings.EqualFold(connection.State, "CONNECTED") {
				summary.DirectCount++
			}
		}
		if strings.EqualFold(connection.TransportMode, "RELAY") || strings.EqualFold(connection.Reachability, "RELAY") {
			if strings.EqualFold(connection.State, "CONNECTED") {
				summary.RelayCount++
			}
		}
		if rtt := firstPositive(connection.AverageRTTMillis, connection.LastRTTMillis); rtt > 0 {
			summary.AverageRTTMillis += rtt
			rttSamples++
		}
		if connection.ConsecutiveLosses > summary.WorstLosses {
			summary.WorstLosses = connection.ConsecutiveLosses
		}
		summary.TransportPacketCount += connection.TransportPacketCount
		if connection.LastTransportUnix > summary.LastTransportUnix {
			summary.LastTransportUnix = connection.LastTransportUnix
		}
	}
	if summary.ConnectionCount == 0 {
		summary.Quality = "idle"
		return summary
	}
	if rttSamples > 0 {
		summary.AverageRTTMillis = summary.AverageRTTMillis / rttSamples
	}
	summary.Quality = deriveTransportSummaryQuality(summary)
	return summary
}

func connectionQualityClass(connection clientagent.ConnectionStatus) string {
	if strings.EqualFold(connection.State, "CONNECTED") {
		if connection.ConsecutiveLosses > 0 {
			return "degraded"
		}
		if strings.EqualFold(connection.TransportMode, "RELAY") || strings.EqualFold(connection.Reachability, "RELAY") {
			return "relay"
		}
		return "healthy"
	}
	switch strings.ToUpper(strings.TrimSpace(connection.State)) {
	case "NEGOTIATING", "DIRECT_CANDIDATE", "DISCOVERING":
		return "pending"
	case "RELAY_READY":
		return "fallback-ready"
	default:
		return "idle"
	}
}

func deriveTransportSummaryQuality(summary *networkTransportQualitySummary) string {
	if summary == nil || summary.ConnectionCount == 0 {
		return "idle"
	}
	if summary.ConnectedCount == 0 {
		if summary.PendingCount > 0 {
			return "pending"
		}
		if summary.FallbackReadyCount > 0 {
			return "fallback-ready"
		}
		return "idle"
	}
	if summary.DegradedCount > 0 {
		return "degraded"
	}
	if summary.RelayCount > 0 && summary.DirectCount > 0 {
		return "mixed"
	}
	if summary.RelayCount > 0 {
		return "relay"
	}
	return "healthy"
}

func formatTransportPathCounts(summary *networkTransportQualitySummary) string {
	if summary == nil {
		return "-"
	}
	return fmt.Sprintf(
		"total=%d | connected=%d | pending=%d | fallback-ready=%d",
		summary.ConnectionCount,
		summary.ConnectedCount,
		summary.PendingCount,
		summary.FallbackReadyCount,
	)
}

func formatTransportSummaryNextAction(summary *networkTransportQualitySummary) string {
	if summary == nil {
		return "-"
	}
	switch summary.Quality {
	case "pending":
		return "Wait for negotiation to finish, or use `Reconnect` / `Reconnect This PC` if the path stalls."
	case "fallback-ready":
		return "Relay fallback is prepared; wait for a live path to move into CONNECTED."
	case "relay":
		return "Traffic is flowing over relay; the agent will keep retrying direct paths automatically."
	case "degraded":
		return "Watch RTT and loss telemetry; use `Reconnect` if the degraded path does not recover."
	case "mixed":
		return "At least one path is healthy, but some peers are still on relay."
	case "healthy":
		return "No action is needed right now."
	default:
		return "No live transport paths are ready for this network yet."
	}
}

func formatGatewayDiagnosticsLines(status *clientagent.Status, selected *Network) []string {
	if status == nil {
		return nil
	}
	targets := make([]*Network, 0, 1)
	if selected != nil && strings.EqualFold(networkRoutingPolicyOrDefault(*selected), "FULL") {
		targets = append(targets, selected)
	} else if selected == nil {
		for idx := range status.Adapter.Networks {
			binding := status.Adapter.Networks[idx]
			if !strings.EqualFold(strings.TrimSpace(binding.RoutingPolicy), "FULL") {
				continue
			}
			network := &Network{
				ID:            binding.NetworkID,
				RoutingPolicy: binding.RoutingPolicy,
			}
			targets = append(targets, network)
		}
	}
	if len(targets) == 0 {
		return nil
	}

	lines := make([]string, 0, len(targets)*8)
	for _, network := range targets {
		diag := gatewayDiagnosticsForNetwork(status, network)
		if diag == nil {
			continue
		}
		lines = append(lines,
			fmt.Sprintf("[%s]", firstNonEmpty(diag.NetworkID, "-")),
			"Routing Policy: "+formatNetworkRoutingPolicy(diag.RoutingPolicy),
			"Gateway Status: "+formatGatewayPolicyStatus(diag.PolicyStatus),
			"Gateway Role: "+formatGatewayRole(diag.GatewayRole),
			"Gateway Peer: "+firstNonEmpty(diag.GatewayPeerID, "-"),
			"Gateway Path: "+formatGatewayPath(diag),
			"Gateway State: "+firstNonEmpty(diag.ConnectionState, "-"),
			"Gateway RTT: "+formatMillis(diag.LastRTTMillis),
			"Gateway Losses: "+strconv.Itoa(diag.Losses),
			"Gateway Next Action: "+formatGatewayNextAction(diag),
			"",
		)
	}
	if len(lines) == 0 {
		return nil
	}
	return lines
}

func formatGatewaySummaryForNetwork(status *clientagent.Status, network *Network) []string {
	diag := gatewayDiagnosticsForNetwork(status, network)
	if diag == nil {
		return nil
	}
	return []string{
		"Gateway Status: " + formatGatewayPolicyStatus(diag.PolicyStatus),
		"Gateway Role: " + formatGatewayRole(diag.GatewayRole),
		"Gateway Peer: " + firstNonEmpty(diag.GatewayPeerID, "-"),
		"Gateway Path: " + formatGatewayPath(diag),
		"Gateway Next Action: " + formatGatewayNextAction(diag),
	}
}

func formatGatewaySummaryCompact(status *clientagent.Status, network *Network) string {
	diag := gatewayDiagnosticsForNetwork(status, network)
	if diag == nil {
		return "gateway-unknown"
	}
	switch {
	case strings.EqualFold(diag.GatewayRole, "GATEWAY"):
		return "gateway-host"
	case strings.EqualFold(diag.PolicyStatus, "STANDBY_GATEWAY"):
		path := strings.ToLower(strings.TrimSpace(firstNonEmpty(diag.TransportMode, diag.Reachability)))
		if path == "" {
			path = "path-pending"
		}
		if strings.TrimSpace(diag.GatewayPeerID) != "" {
			return "standby via " + diag.GatewayPeerID + " " + path
		}
		return "standby-gateway"
	case strings.EqualFold(diag.PolicyStatus, "PENDING_GATEWAY"):
		return "pending-gateway"
	case strings.EqualFold(diag.GatewayRole, "CLIENT") && strings.TrimSpace(diag.GatewayPeerID) != "":
		path := strings.ToLower(strings.TrimSpace(firstNonEmpty(diag.TransportMode, diag.Reachability)))
		if path == "" {
			path = "path-pending"
		}
		return "via " + diag.GatewayPeerID + " " + path
	default:
		return "gateway-ready"
	}
}

func formatGatewayHistoryLines(status *clientagent.Status, selected *Network) []string {
	if status == nil {
		return nil
	}
	events := status.GatewayHistory
	if len(events) == 0 {
		return nil
	}
	lines := []string{}
	for _, event := range events {
		if selected != nil && event.NetworkID != selected.ID {
			continue
		}
		lines = append(lines, "- "+formatGatewayEventSummary(event))
	}
	if len(lines) == 0 {
		return nil
	}
	return lines
}

func gatewayHistoryForNetwork(status *clientagent.Status, networkID string) []clientagent.GatewayChangeEvent {
	if status == nil || strings.TrimSpace(networkID) == "" || len(status.GatewayHistory) == 0 {
		return nil
	}
	events := make([]clientagent.GatewayChangeEvent, 0, len(status.GatewayHistory))
	for _, event := range status.GatewayHistory {
		if event.NetworkID == networkID {
			events = append(events, event)
		}
	}
	return events
}

func formatGatewayEventSummary(event clientagent.GatewayChangeEvent) string {
	return fmt.Sprintf(
		"%s | %s | %s -> %s | %s -> %s | %s",
		firstNonEmpty(formatGatewayEventType(event.Event), "-"),
		firstNonEmpty(event.NetworkID, "-"),
		formatGatewayHistoryEndpoint(event.PreviousGatewayRole, event.PreviousGatewayPeerID, event.PreviousPolicyStatus),
		formatGatewayHistoryEndpoint(event.CurrentGatewayRole, event.CurrentGatewayPeerID, event.CurrentPolicyStatus),
		formatGatewayHistoryPath(event.PreviousPath),
		formatGatewayHistoryPath(event.CurrentPath),
		formatUnix(event.ChangedAtUnix),
	)
}

func formatGatewayEventType(eventType string) string {
	switch strings.ToUpper(strings.TrimSpace(eventType)) {
	case "FAILOVER":
		return "failover"
	case "FAILBACK":
		return "failback"
	case "PROMOTED":
		return "promoted"
	case "DEMOTED":
		return "demoted"
	case "SELECTED":
		return "selected"
	case "LOST":
		return "lost"
	case "LOCAL_GATEWAY_ACTIVE":
		return "local-gateway-active"
	case "LOCAL_GATEWAY_RELEASED":
		return "local-gateway-released"
	case "PATH_CHANGED":
		return "path-changed"
	case "STATUS_CHANGED":
		return "status-changed"
	case "REMOVED":
		return "removed"
	default:
		return firstNonEmpty(strings.ToLower(strings.TrimSpace(eventType)), "-")
	}
}

func formatGatewayHistoryEndpoint(role, peerID, policyStatus string) string {
	switch {
	case strings.EqualFold(strings.TrimSpace(role), "GATEWAY"):
		return "local gateway"
	case strings.TrimSpace(peerID) != "":
		return peerID
	case strings.EqualFold(strings.TrimSpace(policyStatus), "PENDING_GATEWAY"):
		return "pending gateway"
	case strings.EqualFold(strings.TrimSpace(policyStatus), "REMOVED"):
		return "removed"
	default:
		return "-"
	}
}

func formatGatewayHistoryPath(path string) string {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" {
		return "-"
	}
	switch path {
	case "local":
		return "local-gateway"
	default:
		return path
	}
}

func gatewayDiagnosticsForNetwork(status *clientagent.Status, network *Network) *networkGatewayDiagnostics {
	if status == nil || network == nil || !strings.EqualFold(networkRoutingPolicyOrDefault(*network), "FULL") {
		return nil
	}
	diag := &networkGatewayDiagnostics{
		NetworkID:     network.ID,
		RoutingPolicy: networkRoutingPolicyOrDefault(*network),
		PolicyStatus:  "PENDING_GATEWAY",
	}
	binding := adapterBindingForNetwork(status, network.ID)
	if binding != nil {
		diag.PolicyStatus = binding.PolicyStatus
		diag.GatewayRole = binding.GatewayRole
		diag.GatewayPeerID = binding.GatewayPeerID
	}
	if connection := gatewayConnectionForNetwork(status, network, binding); connection != nil {
		diag.ConnectionState = connection.State
		diag.TransportMode = connection.TransportMode
		diag.Reachability = connection.Reachability
		diag.LastRTTMillis = firstPositive(connection.AverageRTTMillis, connection.LastRTTMillis)
		diag.Losses = connection.ConsecutiveLosses
		diag.LastError = connection.LastError
		if diag.GatewayPeerID == "" || gatewayEligibleConnectionForNetwork(network, binding, connection) {
			diag.GatewayPeerID = connection.RemotePeerID
		}
	}
	return diag
}

func adapterBindingForNetwork(status *clientagent.Status, networkID string) *virtualadapter.NetworkBinding {
	if status == nil {
		return nil
	}
	for idx := range status.Adapter.Networks {
		binding := &status.Adapter.Networks[idx]
		if binding.NetworkID == networkID {
			return binding
		}
	}
	return nil
}

func gatewayConnectionForNetwork(status *clientagent.Status, network *Network, binding *virtualadapter.NetworkBinding) *clientagent.ConnectionStatus {
	if status == nil || network == nil {
		return nil
	}
	gatewayPeerID := ""
	if binding != nil {
		gatewayPeerID = strings.TrimSpace(binding.GatewayPeerID)
	}
	if strings.TrimSpace(gatewayPeerID) != "" {
		for idx := range status.Connections {
			connection := &status.Connections[idx]
			if connection.NetworkID == network.ID && connection.RemotePeerID == gatewayPeerID {
				return connection
			}
		}
	}
	bestEligible := bestGatewayConnectionForNetwork(status, network, binding, true)
	if bestEligible != nil {
		return bestEligible
	}
	return bestGatewayConnectionForNetwork(status, network, binding, false)
}

func bestGatewayConnectionForNetwork(status *clientagent.Status, network *Network, binding *virtualadapter.NetworkBinding, requireEligibility bool) *clientagent.ConnectionStatus {
	if status == nil || network == nil {
		return nil
	}
	var best *clientagent.ConnectionStatus
	bestScore := -1
	for idx := range status.Connections {
		connection := &status.Connections[idx]
		if connection.NetworkID != network.ID || !connection.TransportReady {
			continue
		}
		if requireEligibility && !gatewayEligibleConnectionForNetwork(network, binding, connection) {
			continue
		}
		score := peerConnectionScore(*connection)
		if best == nil || score > bestScore {
			best = connection
			bestScore = score
		}
	}
	return best
}

func gatewayEligibleConnectionForNetwork(network *Network, binding *virtualadapter.NetworkBinding, connection *clientagent.ConnectionStatus) bool {
	if network == nil || connection == nil {
		return false
	}
	if gatewayBindingConflictsWithConnection(binding, connection) {
		return false
	}
	userID := strings.TrimSpace(connection.RemoteUserID)
	if userID == "" && gatewayBindingMatchesConnection(binding, connection) {
		userID = strings.TrimSpace(binding.GatewayUserID)
	}
	if userID == "" {
		return false
	}
	if strings.TrimSpace(network.OwnerID) != "" && strings.EqualFold(strings.TrimSpace(network.OwnerID), userID) {
		return true
	}
	role := ""
	if network.MemberRoles != nil {
		role = network.MemberRoles[userID]
	}
	return strings.EqualFold(strings.TrimSpace(role), "ADMIN")
}

func gatewayBindingMatchesConnection(binding *virtualadapter.NetworkBinding, connection *clientagent.ConnectionStatus) bool {
	if binding == nil || connection == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(binding.NetworkID), strings.TrimSpace(connection.NetworkID)) {
		return false
	}
	bindingVirtualIP := strings.TrimSpace(binding.GatewayVirtualIP)
	connectionVirtualIP := strings.TrimSpace(connection.RemoteVirtualIP)
	if bindingVirtualIP == "" || connectionVirtualIP == "" || !strings.EqualFold(bindingVirtualIP, connectionVirtualIP) {
		return false
	}
	bindingUserID := strings.TrimSpace(binding.GatewayUserID)
	connectionUserID := strings.TrimSpace(connection.RemoteUserID)
	if bindingUserID != "" && connectionUserID != "" && !strings.EqualFold(bindingUserID, connectionUserID) {
		return false
	}
	return true
}

func gatewayBindingConflictsWithConnection(binding *virtualadapter.NetworkBinding, connection *clientagent.ConnectionStatus) bool {
	if binding == nil || connection == nil {
		return false
	}
	bindingVirtualIP := strings.TrimSpace(binding.GatewayVirtualIP)
	connectionVirtualIP := strings.TrimSpace(connection.RemoteVirtualIP)
	if bindingVirtualIP == "" || connectionVirtualIP == "" || !strings.EqualFold(bindingVirtualIP, connectionVirtualIP) {
		return false
	}
	bindingUserID := strings.TrimSpace(binding.GatewayUserID)
	connectionUserID := strings.TrimSpace(connection.RemoteUserID)
	return bindingUserID != "" && connectionUserID != "" && !strings.EqualFold(bindingUserID, connectionUserID)
}

func formatGatewayPolicyStatus(status string) string {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "ACTIVE":
		return "active"
	case "STANDBY_GATEWAY":
		return "standby gateway"
	case "PENDING_GATEWAY":
		return "pending gateway"
	default:
		return firstNonEmpty(strings.ToLower(strings.TrimSpace(status)), "-")
	}
}

func formatGatewayRole(role string) string {
	switch strings.ToUpper(strings.TrimSpace(role)) {
	case "GATEWAY":
		return "gateway-host"
	case "CLIENT":
		return "client"
	default:
		return firstNonEmpty(strings.ToLower(strings.TrimSpace(role)), "-")
	}
}

func formatGatewayPath(diag *networkGatewayDiagnostics) string {
	if diag == nil {
		return "-"
	}
	switch {
	case strings.EqualFold(diag.GatewayRole, "GATEWAY"):
		return "local gateway"
	case strings.TrimSpace(diag.TransportMode) != "":
		return strings.ToLower(strings.TrimSpace(diag.TransportMode))
	case strings.TrimSpace(diag.Reachability) != "":
		return strings.ToLower(strings.TrimSpace(diag.Reachability))
	case strings.EqualFold(diag.PolicyStatus, "STANDBY_GATEWAY"):
		return "standby"
	case strings.EqualFold(diag.PolicyStatus, "PENDING_GATEWAY"):
		return "pending"
	default:
		return "-"
	}
}

func formatGatewayNextAction(diag *networkGatewayDiagnostics) string {
	if diag == nil {
		return "-"
	}
	switch {
	case strings.EqualFold(diag.GatewayRole, "GATEWAY") && strings.EqualFold(diag.PolicyStatus, "ACTIVE"):
		return "This device is acting as the FULL gateway."
	case strings.EqualFold(diag.PolicyStatus, "STANDBY_GATEWAY"):
		return "Another FULL network currently owns the default route. Keep this gateway peer online until Ole promotes this network."
	case strings.EqualFold(diag.PolicyStatus, "PENDING_GATEWAY"):
		return "Wait for an OWNER or ADMIN peer to become transport-ready, or switch the network back to SPLIT."
	case strings.EqualFold(diag.GatewayRole, "CLIENT") && strings.TrimSpace(diag.GatewayPeerID) != "" && !strings.EqualFold(diag.ConnectionState, "CONNECTED"):
		return "Keep the selected gateway peer online until the FULL path reaches CONNECTED."
	case strings.EqualFold(diag.GatewayRole, "CLIENT") && strings.TrimSpace(diag.GatewayPeerID) != "":
		return "Gateway path is active."
	default:
		return "No gateway action is required right now."
	}
}

func firstPositive(values ...int64) int64 {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func currentComboBoxText(box *walk.ComboBox) string {
	if box == nil {
		return ""
	}
	return strings.TrimSpace(box.Text())
}

func textOfLineEdit(edit *walk.LineEdit) string {
	if edit == nil {
		return ""
	}
	return edit.Text()
}

func firstDeviceOrNil(devices []Device) *Device {
	if len(devices) == 0 {
		return nil
	}
	return &devices[0]
}

func shortFingerprint(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "-"
	}
	if len(trimmed) <= 18 {
		return trimmed
	}
	return trimmed[:8] + "..." + trimmed[len(trimmed)-8:]
}

func deviceTrustLabel(device Device, status *clientagent.Status) string {
	isCurrent := status != nil && device.ID != "" && device.ID == status.Security.CurrentDeviceID
	isTrusted := strings.EqualFold(device.Status, "ACTIVE") && device.RevokedAtUnix <= 0

	switch {
	case isCurrent && isTrusted:
		return "current-trusted"
	case isCurrent:
		return "current-revoked"
	case isTrusted:
		return "trusted"
	default:
		return "revoked"
	}
}

func hasConnectedPath(status *clientagent.Status, selected *Network) bool {
	if status == nil {
		return false
	}
	for _, connection := range status.Connections {
		if selected != nil && connection.NetworkID != selected.ID {
			continue
		}
		if strings.EqualFold(connection.State, "CONNECTED") && connection.TransportReady {
			return true
		}
	}
	return false
}

func formatAuditEvents(events []AuditEvent) string {
	if len(events) == 0 {
		return "No audit events match the current filters."
	}
	lines := make([]string, 0, len(events)*2)
	for _, event := range events {
		target := firstNonEmpty(event.ActorUserID, "-")
		if strings.TrimSpace(event.NetworkID) != "" {
			target = target + " | net=" + strings.TrimSpace(event.NetworkID)
		}
		lines = append(lines, fmt.Sprintf(
			"%s | %s | %s | %s",
			formatUnix(event.CreatedAtUnix),
			target,
			firstNonEmpty(event.Type, "-"),
			firstNonEmpty(event.Details, "-"),
		))
	}
	return strings.Join(lines, "\r\n")
}

func formatIncidentReports(reports []IncidentReport) string {
	if len(reports) == 0 {
		return "No active incident reports."
	}
	lines := make([]string, 0, len(reports)*2)
	for _, report := range reports {
		lines = append(lines, fmt.Sprintf(
			"%s | %s | %s | %s | events=%d",
			firstNonEmpty(strings.ToLower(strings.TrimSpace(report.Severity)), "-"),
			firstNonEmpty(report.Category, "-"),
			firstNonEmpty(report.Source, "-"),
			firstNonEmpty(report.Summary, "-"),
			report.EventCount,
		))
		lines = append(lines, fmt.Sprintf(
			"  status=%s | detected=%s | updated=%s",
			firstNonEmpty(strings.ToLower(strings.TrimSpace(report.Status)), "-"),
			formatUnix(report.DetectedAtUnix),
			formatUnix(report.UpdatedAtUnix),
		))
		if strings.TrimSpace(report.Detail) != "" {
			lines = append(lines, "  detail: "+strings.TrimSpace(report.Detail))
		}
		if strings.TrimSpace(report.RecommendedAction) != "" {
			lines = append(lines, "  next action: "+strings.TrimSpace(report.RecommendedAction))
		}
	}
	return strings.Join(lines, "\r\n")
}

func formatAuditPresetLabel(preset AuditPreset) string {
	parts := []string{firstNonEmpty(preset.Name, "Unnamed preset")}
	if strings.TrimSpace(preset.ActorUserID) != "" {
		parts = append(parts, "actor="+strings.TrimSpace(preset.ActorUserID))
	}
	if strings.TrimSpace(preset.Type) != "" {
		parts = append(parts, "type="+strings.TrimSpace(preset.Type))
	}
	if strings.TrimSpace(preset.Query) != "" {
		parts = append(parts, "query="+strings.TrimSpace(preset.Query))
	}
	if preset.FromUnix > 0 || preset.ToUnix > 0 {
		rangeParts := []string{}
		if preset.FromUnix > 0 {
			rangeParts = append(rangeParts, "from="+strconv.FormatInt(preset.FromUnix, 10))
		}
		if preset.ToUnix > 0 {
			rangeParts = append(rangeParts, "to="+strconv.FormatInt(preset.ToUnix, 10))
		}
		parts = append(parts, strings.Join(rangeParts, " "))
	}
	return strings.Join(parts, " | ")
}

func formatPeerLine(peer Peer, status *clientagent.Status, selected *Network) string {
	connection := bestPeerConnection(status, peer, selected)
	presence := peerPresence(peer, connection)
	quality := peerQuality(peer, connection)
	return fmt.Sprintf(
		"%s | %s | %s | quality=%s | latency=%s | path=%s | state=%s | endpoint=%s | last seen=%s",
		peer.ID,
		firstNonEmpty(peer.VirtualIP, "-"),
		presence,
		quality,
		peerLatency(connection),
		peerPath(connection),
		peerState(peer, connection),
		firstNonEmpty(peer.Endpoint, "-"),
		formatUnix(peer.LastSeenUnix),
	)
}

func bestPeerConnection(status *clientagent.Status, peer Peer, selected *Network) *clientagent.ConnectionStatus {
	if status == nil {
		return nil
	}
	if best := bestPeerConnectionByMatch(status, peer, selected, func(connection *clientagent.ConnectionStatus) bool {
		return connection.RemotePeerID == peer.ID
	}); best != nil {
		return best
	}
	return bestPeerConnectionByMatch(status, peer, selected, func(connection *clientagent.ConnectionStatus) bool {
		return samePeerConnectionTarget(peer, connection)
	})
}

func samePeerConnectionTarget(peer Peer, connection *clientagent.ConnectionStatus) bool {
	if connection == nil {
		return false
	}
	peerVirtualIP := strings.TrimSpace(peer.VirtualIP)
	connectionVirtualIP := strings.TrimSpace(connection.RemoteVirtualIP)
	if peerVirtualIP != "" || connectionVirtualIP != "" {
		if peerVirtualIP == "" || connectionVirtualIP == "" || !strings.EqualFold(peerVirtualIP, connectionVirtualIP) {
			return false
		}
		peerUserID := strings.TrimSpace(peer.UserID)
		connectionUserID := strings.TrimSpace(connection.RemoteUserID)
		if peerUserID != "" && connectionUserID != "" && !strings.EqualFold(peerUserID, connectionUserID) {
			return false
		}
		return true
	}
	peerUserID := strings.TrimSpace(peer.UserID)
	connectionUserID := strings.TrimSpace(connection.RemoteUserID)
	if peerUserID == "" || connectionUserID == "" {
		return false
	}
	return strings.EqualFold(peerUserID, connectionUserID)
}

func bestPeerConnectionByMatch(status *clientagent.Status, peer Peer, selected *Network, match func(*clientagent.ConnectionStatus) bool) *clientagent.ConnectionStatus {
	if status == nil {
		return nil
	}
	var best *clientagent.ConnectionStatus
	bestScore := -1
	for idx := range status.Connections {
		connection := &status.Connections[idx]
		if selected != nil && connection.NetworkID != selected.ID {
			continue
		}
		if selected == nil && peer.NetworkID != "" && connection.NetworkID != peer.NetworkID {
			continue
		}
		if !match(connection) {
			continue
		}
		score := peerConnectionScore(*connection)
		if best == nil || score > bestScore {
			best = connection
			bestScore = score
		}
	}
	return best
}

func peerConnectionScore(connection clientagent.ConnectionStatus) int {
	score := 0
	switch strings.ToUpper(strings.TrimSpace(connection.State)) {
	case "CONNECTED":
		score += 100
	case "NEGOTIATING":
		score += 80
	case "DIRECT_CANDIDATE":
		score += 60
	case "RELAY_READY":
		score += 40
	case "DISCOVERING":
		score += 20
	}
	if connection.TransportReady {
		score += 20
	}
	if strings.EqualFold(connection.TransportMode, "DIRECT") || strings.EqualFold(connection.Reachability, "DIRECT") {
		score += 5
	}
	if connection.AverageRTTMillis > 0 {
		score++
	}
	return score
}

func peerPresence(peer Peer, connection *clientagent.ConnectionStatus) string {
	if connection != nil && strings.EqualFold(connection.State, "CONNECTED") {
		return "online"
	}
	if strings.EqualFold(peer.Status, "ONLINE") {
		return "online"
	}
	if peer.LastSeenUnix > 0 && time.Since(time.Unix(peer.LastSeenUnix, 0)) <= 2*time.Minute {
		return "recent"
	}
	return "offline"
}

func peerQuality(peer Peer, connection *clientagent.ConnectionStatus) string {
	if connection == nil {
		if strings.EqualFold(peer.Status, "ONLINE") {
			return "pending"
		}
		return "offline"
	}
	if strings.EqualFold(connection.State, "CONNECTED") {
		if connection.ConsecutiveLosses > 0 {
			return "degraded"
		}
		if strings.EqualFold(connection.TransportMode, "RELAY") || strings.EqualFold(connection.Reachability, "RELAY") {
			return "relay"
		}
		return "healthy"
	}
	switch strings.ToUpper(strings.TrimSpace(connection.State)) {
	case "NEGOTIATING", "DIRECT_CANDIDATE", "DISCOVERING":
		return "pending"
	case "RELAY_READY":
		return "fallback-ready"
	default:
		if strings.EqualFold(peer.Status, "ONLINE") {
			return "pending"
		}
		return "offline"
	}
}

func peerLatency(connection *clientagent.ConnectionStatus) string {
	if connection == nil {
		return "-"
	}
	if connection.AverageRTTMillis > 0 {
		return formatMillis(connection.AverageRTTMillis)
	}
	if connection.LastRTTMillis > 0 {
		return formatMillis(connection.LastRTTMillis)
	}
	return "-"
}

func peerPath(connection *clientagent.ConnectionStatus) string {
	if connection == nil {
		return "offline"
	}
	if strings.EqualFold(connection.TransportMode, "RELAY") || strings.EqualFold(connection.Reachability, "RELAY") {
		if strings.EqualFold(connection.State, "CONNECTED") {
			return "relay"
		}
		return "relay-ready"
	}
	if strings.EqualFold(connection.TransportMode, "DIRECT") || strings.EqualFold(connection.Reachability, "DIRECT") {
		if strings.EqualFold(connection.State, "CONNECTED") {
			return "direct"
		}
		return "direct-candidate"
	}
	if strings.TrimSpace(connection.State) != "" {
		return strings.ToLower(connection.State)
	}
	return "offline"
}

func peerState(peer Peer, connection *clientagent.ConnectionStatus) string {
	if connection != nil && strings.TrimSpace(connection.State) != "" {
		return connection.State
	}
	if strings.TrimSpace(peer.ConnectionState) != "" {
		return peer.ConnectionState
	}
	return firstNonEmpty(peer.Status, "-")
}

func formatUserSummary(user *User) string {
	if user == nil {
		return "-"
	}
	return fmt.Sprintf("%s (%s)", firstNonEmpty(user.Email, "-"), firstNonEmpty(user.ID, "-"))
}

func formatDeviceSummary(device *Device) string {
	if device == nil {
		return "-"
	}
	return fmt.Sprintf("%s (%s)", firstNonEmpty(device.Name, "-"), firstNonEmpty(device.ID, "-"))
}

func formatMessages(messages []Message) string {
	return formatMessagesWithPeers(messages, nil)
}

func formatMessagesWithPeers(messages []Message, peers []Peer) string {
	if len(messages) == 0 {
		return "No messages have been sent on the selected network yet."
	}
	peersByID := peerLookupByID(peers)
	lines := make([]string, 0, len(messages))
	for _, message := range messages {
		lines = append(lines, fmt.Sprintf(
			"%s | from=%s | %s",
			formatUnix(message.SentAtUnix),
			messagePeerReferenceLabel(message, peersByID, peers),
			firstNonEmpty(strings.TrimSpace(message.Text), firstNonEmpty(message.Preview, "-")),
		))
	}
	return strings.Join(lines, "\r\n")
}

func formatFileTransferSummaryLine(transfer FileTransfer) string {
	return formatFileTransferSummaryLineWithPeers(transfer, nil)
}

func formatFileTransferSummaryLineWithPeers(transfer FileTransfer, peers []Peer) string {
	peersByID := peerLookupByID(peers)
	parts := []string{
		firstNonEmpty(transfer.FileName, "unnamed"),
		"status=" + strings.ToLower(formatTransferStatus(transfer.Status)),
		"payload=" + transferPayloadLabel(transfer),
		fmt.Sprintf("progress=%d%%", transfer.ProgressPercent),
		"from=" + transferPeerReferenceLabel(transfer.FromPeerID, transfer.FromUserID, transfer.NetworkID, peersByID, peers),
		"to=" + transferPeerReferenceLabel(transfer.ToPeerID, transfer.ToUserID, transfer.NetworkID, peersByID, peers),
	}
	return strings.Join(parts, " | ")
}

func formatFileTransferDetails(transfer *FileTransfer) string {
	return formatFileTransferDetailsWithPeersAndLocalState(transfer, nil, nil)
}

func formatFileTransferDetailsWithPeers(transfer *FileTransfer, peers []Peer) string {
	return formatFileTransferDetailsWithPeersAndLocalState(transfer, peers, nil)
}

func formatFileTransferDetailsWithPeersAndLocalState(transfer *FileTransfer, peers []Peer, localState *clientagent.FileTransferLocalState) string {
	if transfer == nil {
		return "Select a file transfer to inspect or manage it."
	}
	peersByID := peerLookupByID(peers)
	lines := []string{
		"ID: " + firstNonEmpty(transfer.ID, "-"),
		"Network: " + firstNonEmpty(transfer.NetworkID, "-"),
		"File: " + firstNonEmpty(transfer.FileName, "-"),
		"Size Bytes: " + strconv.FormatInt(transfer.SizeBytes, 10),
		"Uploaded Bytes: " + strconv.FormatInt(transfer.PayloadUploadedBytes, 10),
		"Status: " + formatTransferStatus(transfer.Status),
		fmt.Sprintf("Progress: %d%%", transfer.ProgressPercent),
		"From Peer: " + transferPeerReferenceLabel(transfer.FromPeerID, transfer.FromUserID, transfer.NetworkID, peersByID, peers),
		"To Peer: " + transferPeerReferenceLabel(transfer.ToPeerID, transfer.ToUserID, transfer.NetworkID, peersByID, peers),
		"Payload Ready: " + yesNo(transfer.PayloadReady),
		"Content Type: " + firstNonEmpty(transfer.ContentType, "-"),
		"Payload SHA256: " + firstNonEmpty(transfer.PayloadSHA256, "-"),
		"Uploaded: " + formatUnix(transfer.UploadedAtUnix),
		"Downloaded: " + formatUnix(transfer.DownloadedAtUnix),
	}
	if strings.TrimSpace(transfer.CancelReason) != "" {
		lines = append(lines, "Cancel Reason: "+strings.TrimSpace(transfer.CancelReason))
	}
	if localState != nil {
		lines = append(lines, "Sender Source Registered: "+yesNo(localState.SenderSourceRegistered))
		if strings.TrimSpace(localState.SenderSourcePath) != "" {
			lines = append(lines, "Sender Source Path: "+strings.TrimSpace(localState.SenderSourcePath))
		}
		if localState.SenderSourceRegistered {
			lines = append(lines, "Sender Source Available: "+yesNo(localState.SenderSourceAvailable))
		}
		if localState.SenderSourceSizeBytes > 0 {
			lines = append(lines, "Sender Source Size Bytes: "+strconv.FormatInt(localState.SenderSourceSizeBytes, 10))
		}
		lines = append(lines, "Receiver Cache Available: "+yesNo(localState.ReceiverCacheAvailable))
		if strings.TrimSpace(localState.ReceiverCachePath) != "" {
			lines = append(lines, "Receiver Cache Path: "+strings.TrimSpace(localState.ReceiverCachePath))
		}
		if localState.ReceiverCacheSizeBytes > 0 {
			lines = append(lines, fmt.Sprintf("Receiver Cache Bytes: %d/%d", localState.ReceiverCachedBytes, localState.ReceiverCacheSizeBytes))
			lines = append(lines, "Receiver Cache Complete: "+yesNo(localState.ReceiverCacheComplete))
		}
	}
	return strings.Join(lines, "\r\n")
}

func formatMillis(value int64) string {
	if value <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d ms", value)
}

func formatTimestampAndAgeMillis(value int64, now time.Time) string {
	if value <= 0 {
		return "-"
	}
	return fmt.Sprintf("%s (%s)", formatUnixMillis(value), formatSinceAt(time.UnixMilli(value), now))
}

func formatTimestampAndAge(value int64, now time.Time) string {
	if value <= 0 {
		return "-"
	}
	return fmt.Sprintf("%s (%s)", formatUnix(value), formatSinceUnixAt(value, now))
}

func formatSinceUnixAt(value int64, now time.Time) string {
	if value <= 0 {
		return "-"
	}
	return formatSinceAt(time.Unix(value, 0), now)
}

func formatReconnectStateLabel(status *clientagent.Status) string {
	if status == nil {
		return "-"
	}
	switch strings.ToUpper(strings.TrimSpace(status.ReconnectState)) {
	case "CONNECTED":
		return "connected"
	case "NONE":
		return "none"
	case "PERSISTED":
		return "persisted session available"
	case "READY":
		return "ready to retry"
	case "BACKOFF":
		if status.ReconnectRemainingMs > 0 {
			return "waiting " + formatDurationMillis(status.ReconnectRemainingMs)
		}
		return "waiting"
	default:
		if status.ReconnectBackoffActive && status.ReconnectRemainingMs > 0 {
			return "waiting " + formatDurationMillis(status.ReconnectRemainingMs)
		}
		return firstNonEmpty(status.ReconnectState, "-")
	}
}

func formatReconnectNextRetry(status *clientagent.Status, now time.Time) string {
	if status == nil || status.NextReconnectAttemptMs <= 0 {
		return "-"
	}
	return fmt.Sprintf("%s (%s)", formatUnixMillis(status.NextReconnectAttemptMs), formatUntilAt(time.UnixMilli(status.NextReconnectAttemptMs), now))
}

func formatUpdateChannel(status *clientagent.Status) string {
	if status == nil || strings.TrimSpace(status.Update.ManifestURL) == "" {
		return "disabled"
	}
	return "configured"
}

func formatUpdateState(status *clientagent.Status) string {
	if status == nil {
		return "-"
	}
	switch {
	case strings.TrimSpace(status.Update.ManifestURL) == "":
		return "disabled"
	case status.Update.Checking:
		return "checking"
	case status.Update.Downloaded:
		return "downloaded"
	case status.Update.Available:
		return "available"
	case strings.TrimSpace(status.Update.LastError) != "":
		return "error"
	case status.Update.LastCheckedUnix > 0:
		return "up-to-date"
	default:
		return "idle"
	}
}

func updatePolicyBlocked(status string) bool {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "BLOCKED_SERVER_TOO_OLD", "BLOCKED_SERVER_TOO_NEW":
		return true
	default:
		return false
	}
}

func formatUpdateCheckPeriod(seconds int64) string {
	if seconds <= 0 {
		return "-"
	}
	return (time.Duration(seconds) * time.Second).String()
}

func formatDurationMillis(value int64) string {
	if value <= 0 {
		return "0s"
	}
	return formatRoundedDuration(time.Duration(value) * time.Millisecond)
}

func formatUntilAt(then, now time.Time) string {
	if !then.After(now) {
		return "ready now"
	}
	return "in " + formatRoundedDuration(then.Sub(now))
}

func formatSinceAt(then, now time.Time) string {
	if now.Before(then) {
		return "just now"
	}
	return formatRoundedDuration(now.Sub(then))
}

func formatRoundedDuration(value time.Duration) string {
	elapsed := value.Round(time.Second)
	switch {
	case elapsed < time.Minute:
		return fmt.Sprintf("%ds", int(elapsed.Seconds()))
	case elapsed < time.Hour:
		return fmt.Sprintf("%dm %ds", int(elapsed.Minutes()), int(elapsed.Seconds())%60)
	case elapsed < 24*time.Hour:
		return fmt.Sprintf("%dh %dm", int(elapsed.Hours()), int(elapsed.Minutes())%60)
	default:
		return fmt.Sprintf("%dd %dh", int(elapsed.Hours())/24, int(elapsed.Hours())%24)
	}
}

func formatInt(value int) string {
	if value <= 0 {
		return "-"
	}
	return strconv.Itoa(value)
}

func formatPercent(value int) string {
	if value < 0 {
		value = 0
	}
	return fmt.Sprintf("%d%%", value)
}

func formatTransferStatus(status string) string {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "INIT":
		return "PENDING"
	default:
		return firstNonEmpty(strings.ToUpper(strings.TrimSpace(status)), "-")
	}
}

func transferPayloadLabel(transfer FileTransfer) string {
	switch {
	case transfer.PayloadReady:
		return "ready"
	case transfer.PayloadUploadedBytes > 0:
		return fmt.Sprintf("partial (%d/%d bytes)", transfer.PayloadUploadedBytes, transfer.SizeBytes)
	case strings.EqualFold(strings.TrimSpace(transfer.Status), "CANCELED"):
		return "canceled"
	default:
		return "pending"
	}
}

func connectedLabel(value bool) string {
	if value {
		return "connected"
	}
	return "disconnected"
}

func diagnosticsExportDir() string {
	home, err := os.UserHomeDir()
	if err == nil && strings.TrimSpace(home) != "" {
		return home
	}
	return os.TempDir()
}

func diagnosticsExportName() string {
	return filepath.Join(diagnosticsExportDir(), "ole-diagnostics-"+time.Now().Format("20060102-150405")+".json")
}

func auditExportName() string {
	return filepath.Join(diagnosticsExportDir(), "ole-audit-"+time.Now().Format("20060102-150405")+".json")
}

func incidentExportName() string {
	return filepath.Join(diagnosticsExportDir(), "ole-incidents-"+time.Now().Format("20060102-150405")+".json")
}

func fileTransferDownloadDir() string {
	home, err := os.UserHomeDir()
	if err == nil && strings.TrimSpace(home) != "" {
		downloads := filepath.Join(home, "Downloads")
		if _, statErr := os.Stat(downloads); statErr == nil {
			return downloads
		}
		return home
	}
	return os.TempDir()
}

func defaultFileTransferDownloadPath(fileName string) string {
	name := strings.TrimSpace(fileName)
	if name == "" {
		name = "ole-transfer.bin"
	}
	return filepath.Join(fileTransferDownloadDir(), name)
}

func joinOrDash(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, ", ")
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func showWinError(owner walk.Form, err error) {
	message := formatGUIError(err)
	walk.MsgBox(owner, message.Title, message.Message, walk.MsgBoxIconError)
}
