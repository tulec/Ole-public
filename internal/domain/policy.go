package domain

type Permission string

const (
	PermissionViewNetwork           Permission = "VIEW_NETWORK"
	PermissionUseNetwork            Permission = "USE_NETWORK"
	PermissionManageNetworkSettings Permission = "MANAGE_NETWORK_SETTINGS"
	PermissionDeleteNetwork         Permission = "DELETE_NETWORK"
	PermissionManageInvites         Permission = "MANAGE_INVITES"
	PermissionManageMembers         Permission = "MANAGE_MEMBERS"
	PermissionManageFiles           Permission = "MANAGE_FILES"
	PermissionModerate              Permission = "MODERATE"
)

func HasPermission(role NetworkRole, permission Permission) bool {
	switch role {
	case NetworkRoleOwner:
		return true
	case NetworkRoleAdmin:
		return permission == PermissionViewNetwork || permission == PermissionUseNetwork || permission == PermissionManageNetworkSettings || permission == PermissionManageInvites || permission == PermissionManageMembers || permission == PermissionManageFiles || permission == PermissionModerate
	case NetworkRoleModerator:
		return permission == PermissionViewNetwork || permission == PermissionUseNetwork || permission == PermissionModerate
	case NetworkRoleFileAdmin:
		return permission == PermissionViewNetwork || permission == PermissionUseNetwork || permission == PermissionManageFiles
	case NetworkRoleMember:
		return permission == PermissionViewNetwork || permission == PermissionUseNetwork
	case NetworkRoleReadOnly:
		return permission == PermissionViewNetwork
	default:
		return false
	}
}

type NetworkOperation string

const (
	NetworkOperationViewNetwork                 NetworkOperation = "VIEW_NETWORK"
	NetworkOperationViewMessages                NetworkOperation = "VIEW_MESSAGES"
	NetworkOperationViewPeers                   NetworkOperation = "VIEW_PEERS"
	NetworkOperationViewPeer                    NetworkOperation = "VIEW_PEER"
	NetworkOperationViewFileTransfers           NetworkOperation = "VIEW_FILE_TRANSFERS"
	NetworkOperationViewNetworkAudit            NetworkOperation = "VIEW_NETWORK_AUDIT"
	NetworkOperationListCandidates              NetworkOperation = "LIST_CANDIDATES"
	NetworkOperationViewTunnels                 NetworkOperation = "VIEW_TUNNELS"
	NetworkOperationViewTunnel                  NetworkOperation = "VIEW_TUNNEL"
	NetworkOperationSendMessage                 NetworkOperation = "SEND_MESSAGE"
	NetworkOperationRegisterPeer                NetworkOperation = "REGISTER_PEER"
	NetworkOperationHeartbeatPeer               NetworkOperation = "HEARTBEAT_PEER"
	NetworkOperationDisconnectPeer              NetworkOperation = "DISCONNECT_PEER"
	NetworkOperationUpdatePeerSignaling         NetworkOperation = "UPDATE_PEER_SIGNALING"
	NetworkOperationPublishCandidate            NetworkOperation = "PUBLISH_CANDIDATE"
	NetworkOperationCreateFileTransfer          NetworkOperation = "CREATE_FILE_TRANSFER"
	NetworkOperationAcceptFileTransfer          NetworkOperation = "ACCEPT_FILE_TRANSFER"
	NetworkOperationCancelFileTransfer          NetworkOperation = "CANCEL_FILE_TRANSFER"
	NetworkOperationUpdateTransferProgress      NetworkOperation = "UPDATE_FILE_TRANSFER_PROGRESS"
	NetworkOperationUploadFileTransferContent   NetworkOperation = "UPLOAD_FILE_TRANSFER_CONTENT"
	NetworkOperationDownloadFileTransferContent NetworkOperation = "DOWNLOAD_FILE_TRANSFER_CONTENT"
	NetworkOperationManageFileTransfers         NetworkOperation = "MANAGE_FILE_TRANSFERS"
	NetworkOperationRequestTunnel               NetworkOperation = "REQUEST_TUNNEL"
	NetworkOperationUpdateTunnelState           NetworkOperation = "UPDATE_TUNNEL_STATE"
	NetworkOperationDeleteNetwork               NetworkOperation = "DELETE_NETWORK"
	NetworkOperationUpdateRoutingPolicy         NetworkOperation = "UPDATE_ROUTING_POLICY"
	NetworkOperationUpdateNameResolution        NetworkOperation = "UPDATE_NAME_RESOLUTION"
	NetworkOperationUpdateGroupTraffic          NetworkOperation = "UPDATE_GROUP_TRAFFIC"
	NetworkOperationUpdateFileTransfers         NetworkOperation = "UPDATE_FILE_TRANSFERS"
	NetworkOperationAddMember                   NetworkOperation = "ADD_MEMBER"
	NetworkOperationRemoveMember                NetworkOperation = "REMOVE_MEMBER"
	NetworkOperationChangeMemberRole            NetworkOperation = "CHANGE_MEMBER_ROLE"
	NetworkOperationManageMembers               NetworkOperation = "MANAGE_MEMBERS"
	NetworkOperationGenerateInvite              NetworkOperation = "GENERATE_INVITE"
	NetworkOperationManageInvites               NetworkOperation = "MANAGE_INVITES"
	NetworkOperationApproveDevice               NetworkOperation = "APPROVE_DEVICE"
	NetworkOperationRevokeDeviceApproval        NetworkOperation = "REVOKE_DEVICE_APPROVAL"
)

func PermissionForNetworkOperation(operation NetworkOperation) Permission {
	switch operation {
	case NetworkOperationSendMessage, NetworkOperationRegisterPeer, NetworkOperationHeartbeatPeer, NetworkOperationDisconnectPeer, NetworkOperationUpdatePeerSignaling, NetworkOperationPublishCandidate, NetworkOperationListCandidates, NetworkOperationCreateFileTransfer, NetworkOperationAcceptFileTransfer, NetworkOperationCancelFileTransfer, NetworkOperationUpdateTransferProgress, NetworkOperationUploadFileTransferContent, NetworkOperationDownloadFileTransferContent, NetworkOperationRequestTunnel, NetworkOperationUpdateTunnelState:
		return PermissionUseNetwork
	case NetworkOperationManageFileTransfers:
		return PermissionManageFiles
	case NetworkOperationDeleteNetwork:
		return PermissionDeleteNetwork
	case NetworkOperationUpdateRoutingPolicy, NetworkOperationUpdateNameResolution, NetworkOperationUpdateGroupTraffic, NetworkOperationUpdateFileTransfers:
		return PermissionManageNetworkSettings
	case NetworkOperationAddMember, NetworkOperationRemoveMember, NetworkOperationChangeMemberRole, NetworkOperationManageMembers, NetworkOperationApproveDevice, NetworkOperationRevokeDeviceApproval:
		return PermissionManageMembers
	case NetworkOperationGenerateInvite, NetworkOperationManageInvites:
		return PermissionManageInvites
	case NetworkOperationViewNetworkAudit:
		return PermissionModerate
	case NetworkOperationViewNetwork, NetworkOperationViewMessages, NetworkOperationViewPeers, NetworkOperationViewPeer, NetworkOperationViewFileTransfers, NetworkOperationViewTunnels, NetworkOperationViewTunnel:
		return PermissionViewNetwork
	default:
		return ""
	}
}

func HasPermissionForNetworkOperation(role NetworkRole, operation NetworkOperation) bool {
	permission := PermissionForNetworkOperation(operation)
	if permission == "" {
		return false
	}
	return HasPermission(role, permission)
}
