package postgres

import (
	"Ole/internal/domain"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

type UserRepo struct {
	db *sql.DB
}

func NewUserRepo(db *sql.DB) *UserRepo {
	return &UserRepo{db: db}
}

func (r *UserRepo) Create(u *domain.User) error {
	_, err := r.db.ExecContext(context.Background(), `
		INSERT INTO users(id, email, password_hash, status)
		VALUES ($1, $2, $3, $4)
	`, u.ID.String(), strings.ToLower(u.Email), u.PasswordHash, string(u.Status))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return domain.ErrAlreadyExists
	}
	return err
}

func (r *UserRepo) Save(u *domain.User) error {
	_, err := r.db.ExecContext(context.Background(), `
		INSERT INTO users(id, email, password_hash, status)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE SET
			email = EXCLUDED.email,
			password_hash = EXCLUDED.password_hash,
			status = EXCLUDED.status
	`, u.ID.String(), strings.ToLower(u.Email), u.PasswordHash, string(u.Status))
	return err
}

func (r *UserRepo) CompareAndSwapPassword(userID domain.UserID, oldHash, newHash string) (bool, error) {
	result, err := r.db.ExecContext(context.Background(), `UPDATE users SET password_hash=$3
		WHERE id=$1 AND password_hash=$2`, userID.String(), oldHash, newHash)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

func (r *UserRepo) FindByEmail(email string) (*domain.User, error) {
	row := r.db.QueryRowContext(context.Background(), `
		SELECT id, email, password_hash, status
		FROM users
		WHERE email = $1
	`, strings.ToLower(email))
	return scanUser(row)
}

func (r *UserRepo) FindByID(id domain.UserID) (*domain.User, error) {
	row := r.db.QueryRowContext(context.Background(), `
		SELECT id, email, password_hash, status
		FROM users
		WHERE id = $1
	`, id.String())
	return scanUser(row)
}

type DeviceRepo struct {
	db *sql.DB
}

func NewDeviceRepo(db *sql.DB) *DeviceRepo {
	return &DeviceRepo{db: db}
}

func (r *DeviceRepo) Save(device *domain.Device) error {
	_, err := r.db.ExecContext(context.Background(), `
		INSERT INTO devices(id, user_id, name, public_key, fingerprint, status, created_at_unix, revoked_at_unix)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			name = EXCLUDED.name,
			public_key = EXCLUDED.public_key,
			fingerprint = EXCLUDED.fingerprint,
			status = EXCLUDED.status,
			created_at_unix = EXCLUDED.created_at_unix,
			revoked_at_unix = EXCLUDED.revoked_at_unix
	`, device.ID.String(), device.UserID.String(), device.Name, device.PublicKey, device.Fingerprint, string(device.Status), device.CreatedAtUnix, device.RevokedAtUnix)
	return err
}

func (r *DeviceRepo) FindByID(id domain.DeviceID) (*domain.Device, error) {
	row := r.db.QueryRowContext(context.Background(), `
		SELECT id, user_id, name, public_key, fingerprint, status, created_at_unix, revoked_at_unix
		FROM devices
		WHERE id = $1
	`, id.String())
	return scanDevice(row)
}

func (r *DeviceRepo) ListByUserID(userID domain.UserID, limit, offset int) ([]*domain.Device, int, error) {
	if limit <= 0 {
		limit = 20
	}
	var total int
	if err := r.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM devices WHERE user_id = $1
	`, userID.String()).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.db.QueryContext(context.Background(), `
		SELECT id, user_id, name, public_key, fingerprint, status, created_at_unix, revoked_at_unix
		FROM devices
		WHERE user_id = $1
		ORDER BY created_at_unix DESC, id DESC
		LIMIT $2 OFFSET $3
	`, userID.String(), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var result []*domain.Device
	for rows.Next() {
		device, err := scanDevice(rows)
		if err != nil {
			return nil, 0, err
		}
		if device != nil {
			result = append(result, device)
		}
	}
	return result, total, rows.Err()
}

type NetworkRepo struct {
	db *sql.DB
}

func NewNetworkRepo(db *sql.DB) *NetworkRepo {
	return &NetworkRepo{db: db}
}

func (r *NetworkRepo) Save(n *domain.Network) error {
	tx, err := r.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(context.Background(), `
		INSERT INTO networks(id, name, owner_id, access, device_approval_required, routing_policy, group_traffic_policy, name_resolution_mode, dns_label, file_transfers_enabled, file_transfer_max_bytes)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			owner_id = EXCLUDED.owner_id,
			access = EXCLUDED.access,
			device_approval_required = EXCLUDED.device_approval_required,
			routing_policy = EXCLUDED.routing_policy,
			group_traffic_policy = EXCLUDED.group_traffic_policy,
			name_resolution_mode = EXCLUDED.name_resolution_mode,
			dns_label = EXCLUDED.dns_label,
			file_transfers_enabled = EXCLUDED.file_transfers_enabled,
			file_transfer_max_bytes = EXCLUDED.file_transfer_max_bytes
	`, n.ID.String(), n.Name, n.OwnerID.String(), string(n.Access), n.DeviceApprovalRequired, string(n.RoutingPolicy), string(n.GroupTrafficPolicy), string(n.NameResolutionMode), n.DNSLabel, n.FileTransfersEnabled, n.FileTransferMaxBytes); err != nil {
		return err
	}

	if _, err = tx.ExecContext(context.Background(), `DELETE FROM network_members WHERE network_id = $1`, n.ID.String()); err != nil {
		return err
	}
	for _, memberID := range n.MemberIDs() {
		role, _ := n.RoleOf(memberID)
		if _, err = tx.ExecContext(context.Background(), `
			INSERT INTO network_members(network_id, user_id, role) VALUES ($1, $2, $3)
		`, n.ID.String(), memberID.String(), string(role)); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(context.Background(), `DELETE FROM network_device_approvals WHERE network_id = $1`, n.ID.String()); err != nil {
		return err
	}
	for _, deviceID := range n.ApprovedDeviceIDs() {
		if _, err = tx.ExecContext(context.Background(), `
			INSERT INTO network_device_approvals(network_id, device_id) VALUES ($1, $2)
		`, n.ID.String(), deviceID.String()); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *NetworkRepo) FindByID(id domain.NetworkID) (*domain.Network, error) {
	row := r.db.QueryRowContext(context.Background(), `
		SELECT id, name, owner_id, access, device_approval_required, routing_policy, group_traffic_policy, name_resolution_mode, dns_label, file_transfers_enabled, file_transfer_max_bytes
		FROM networks
		WHERE id = $1
	`, id.String())

	var networkID, name, ownerID, access, routingPolicy, groupTrafficPolicy, nameResolutionMode, dnsLabel string
	var deviceApprovalRequired bool
	var fileTransfersEnabled bool
	var fileTransferMaxBytes int64
	if err := row.Scan(&networkID, &name, &ownerID, &access, &deviceApprovalRequired, &routingPolicy, &groupTrafficPolicy, &nameResolutionMode, &dnsLabel, &fileTransfersEnabled, &fileTransferMaxBytes); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	network := domain.NewNetwork(domain.NetworkID{Value: networkID}, domain.UserID{Value: ownerID}, name, domain.NetworkAccess(access), deviceApprovalRequired)
	network.RoutingPolicy = domain.NetworkRoutingPolicy(routingPolicy)
	network.GroupTrafficPolicy = domain.NetworkGroupTrafficPolicy(groupTrafficPolicy)
	network.NameResolutionMode = domain.NetworkNameResolutionMode(nameResolutionMode)
	network.DNSLabel = dnsLabel
	network.FileTransfersEnabled = fileTransfersEnabled
	network.FileTransferMaxBytes = fileTransferMaxBytes
	network.Members = map[string]domain.NetworkRole{}
	network.ApprovedDevices = map[string]bool{}

	rows, err := r.db.QueryContext(context.Background(), `
		SELECT user_id, role FROM network_members WHERE network_id = $1
	`, id.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var memberID string
		var role string
		if err := rows.Scan(&memberID, &role); err != nil {
			return nil, err
		}
		network.Members[memberID] = domain.NetworkRole(role)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	approvalRows, err := r.db.QueryContext(context.Background(), `
		SELECT device_id FROM network_device_approvals WHERE network_id = $1 ORDER BY device_id
	`, id.String())
	if err != nil {
		return nil, err
	}
	defer approvalRows.Close()
	for approvalRows.Next() {
		var deviceID string
		if err := approvalRows.Scan(&deviceID); err != nil {
			return nil, err
		}
		network.ApprovedDevices[deviceID] = true
	}
	return network, approvalRows.Err()
}

func (r *NetworkRepo) Delete(id domain.NetworkID) error {
	_, err := r.db.ExecContext(context.Background(), `DELETE FROM networks WHERE id = $1`, id.String())
	return err
}

func (r *NetworkRepo) List() ([]*domain.Network, error) {
	rows, err := r.db.QueryContext(context.Background(), `SELECT id FROM networks ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Drain and release the cursor before FindByID requests another connection.
	// Otherwise a pool with one available connection waits on itself forever.
	var ids []domain.NetworkID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, domain.NetworkID{Value: id})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	var result []*domain.Network
	for _, id := range ids {
		network, err := r.FindByID(id)
		if err != nil {
			return nil, err
		}
		if network != nil {
			result = append(result, network)
		}
	}
	return result, nil
}

type PeerRepo struct {
	db *sql.DB
}

func NewPeerRepo(db *sql.DB) *PeerRepo {
	return &PeerRepo{db: db}
}

func (r *PeerRepo) Save(p *domain.Peer) error {
	_, err := r.db.ExecContext(context.Background(), `
		INSERT INTO peers(id, user_id, device_id, network_id, virtual_ip, endpoint, status, reachability, connection_state, last_seen_unix, last_signaled_at_unix)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			device_id = EXCLUDED.device_id,
			network_id = EXCLUDED.network_id,
			virtual_ip = EXCLUDED.virtual_ip,
			endpoint = EXCLUDED.endpoint,
			status = EXCLUDED.status,
			reachability = EXCLUDED.reachability,
			connection_state = EXCLUDED.connection_state,
			last_seen_unix = EXCLUDED.last_seen_unix,
			last_signaled_at_unix = EXCLUDED.last_signaled_at_unix
	`, p.ID.String(), p.UserID.String(), p.DeviceID.String(), p.NetworkID.String(), p.VirtualIP, p.Endpoint, string(p.Status), string(p.Reachability), string(p.ConnectionState), p.LastSeenUnix, p.LastSignaledAtUnix)
	return err
}

func (r *PeerRepo) FindByID(id domain.PeerID) (*domain.Peer, error) {
	row := r.db.QueryRowContext(context.Background(), `
		SELECT id, user_id, device_id, network_id, virtual_ip, endpoint, status, reachability, connection_state, last_seen_unix, last_signaled_at_unix
		FROM peers
		WHERE id = $1
	`, id.String())
	return scanPeer(row)
}

func (r *PeerRepo) ListByNetwork(networkID domain.NetworkID) ([]*domain.Peer, error) {
	rows, err := r.db.QueryContext(context.Background(), `
		SELECT id, user_id, device_id, network_id, virtual_ip, endpoint, status, reachability, connection_state, last_seen_unix, last_signaled_at_unix
		FROM peers
		WHERE network_id = $1
		ORDER BY id
	`, networkID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*domain.Peer
	for rows.Next() {
		peer, err := scanPeer(rows)
		if err != nil {
			return nil, err
		}
		if peer != nil {
			result = append(result, peer)
		}
	}
	return result, rows.Err()
}

type MessageRepo struct {
	db *sql.DB
}

func NewMessageRepo(db *sql.DB) *MessageRepo {
	return &MessageRepo{db: db}
}

func (r *MessageRepo) Save(message *domain.Message) error {
	_, err := r.db.ExecContext(context.Background(), `
		INSERT INTO messages(id, network_id, from_peer_id, text, sent_at_unix)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO UPDATE SET
			network_id = EXCLUDED.network_id,
			from_peer_id = EXCLUDED.from_peer_id,
			text = EXCLUDED.text,
			sent_at_unix = EXCLUDED.sent_at_unix
	`, message.ID, message.NetworkID.String(), message.FromPeerID.String(), message.Text, message.SentAtUnix)
	return err
}

func (r *MessageRepo) FindByID(id string) (*domain.Message, error) {
	row := r.db.QueryRowContext(context.Background(), `
		SELECT id, network_id, from_peer_id, text, sent_at_unix
		FROM messages
		WHERE id = $1
	`, id)
	return scanMessage(row)
}

func (r *MessageRepo) ListByNetwork(networkID domain.NetworkID) ([]*domain.Message, error) {
	rows, err := r.db.QueryContext(context.Background(), `
		SELECT id, network_id, from_peer_id, text, sent_at_unix
		FROM messages
		WHERE network_id = $1
		ORDER BY sent_at_unix DESC, id DESC
	`, networkID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*domain.Message
	for rows.Next() {
		message, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		if message != nil {
			result = append(result, message)
		}
	}
	return result, rows.Err()
}

type FileTransferRepo struct {
	db *sql.DB
}

func NewFileTransferRepo(db *sql.DB) *FileTransferRepo {
	return &FileTransferRepo{db: db}
}

func (r *FileTransferRepo) Save(transfer *domain.FileTransfer) error {
	_, err := r.db.ExecContext(context.Background(), `
		INSERT INTO file_transfers(id, network_id, from_peer_id, from_user_id, to_peer_id, to_user_id, file_name, size_bytes, status, progress_percent, cancel_reason, content_type, payload_sha256, payload_ready, payload_uploaded_bytes, uploaded_at_unix, downloaded_at_unix)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		ON CONFLICT (id) DO UPDATE SET
			network_id = EXCLUDED.network_id,
			from_peer_id = EXCLUDED.from_peer_id,
			from_user_id = EXCLUDED.from_user_id,
			to_peer_id = EXCLUDED.to_peer_id,
			to_user_id = EXCLUDED.to_user_id,
			file_name = EXCLUDED.file_name,
			size_bytes = EXCLUDED.size_bytes,
			status = EXCLUDED.status,
			progress_percent = EXCLUDED.progress_percent,
			cancel_reason = EXCLUDED.cancel_reason,
			content_type = EXCLUDED.content_type,
			payload_sha256 = EXCLUDED.payload_sha256,
			payload_ready = EXCLUDED.payload_ready,
			payload_uploaded_bytes = EXCLUDED.payload_uploaded_bytes,
			uploaded_at_unix = EXCLUDED.uploaded_at_unix,
			downloaded_at_unix = EXCLUDED.downloaded_at_unix
	`, transfer.ID, transfer.NetworkID.String(), transfer.FromPeerID.String(), transfer.FromUserID.String(), transfer.ToPeerID.String(), transfer.ToUserID.String(), transfer.FileName, transfer.SizeBytes, string(transfer.Status), transfer.ProgressPercent, nullableString(transfer.CancelReason), nullableString(transfer.ContentType), nullableString(transfer.PayloadSHA256), transfer.PayloadReady, transfer.PayloadUploadedBytes, transfer.UploadedAtUnix, transfer.DownloadedAtUnix)
	return err
}

func (r *FileTransferRepo) FindByID(id string) (*domain.FileTransfer, error) {
	row := r.db.QueryRowContext(context.Background(), `
		SELECT id, network_id, from_peer_id, from_user_id, to_peer_id, to_user_id, file_name, size_bytes, status, progress_percent, cancel_reason, content_type, payload_sha256, payload_ready, payload_uploaded_bytes, uploaded_at_unix, downloaded_at_unix
		FROM file_transfers
		WHERE id = $1
	`, id)
	return scanFileTransfer(row)
}

func (r *FileTransferRepo) ListByNetwork(networkID domain.NetworkID) ([]*domain.FileTransfer, error) {
	rows, err := r.db.QueryContext(context.Background(), `
		SELECT id, network_id, from_peer_id, from_user_id, to_peer_id, to_user_id, file_name, size_bytes, status, progress_percent, cancel_reason, content_type, payload_sha256, payload_ready, payload_uploaded_bytes, uploaded_at_unix, downloaded_at_unix
		FROM file_transfers
		WHERE network_id = $1
		ORDER BY id DESC
	`, networkID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*domain.FileTransfer
	for rows.Next() {
		transfer, err := scanFileTransfer(rows)
		if err != nil {
			return nil, err
		}
		if transfer != nil {
			result = append(result, transfer)
		}
	}
	return result, rows.Err()
}

type FileTransferPayloadRepo struct {
	db *sql.DB
}

func NewFileTransferPayloadRepo(db *sql.DB) *FileTransferPayloadRepo {
	return &FileTransferPayloadRepo{db: db}
}

func (r *FileTransferPayloadRepo) Save(payload *domain.FileTransferPayload) error {
	_, err := r.db.ExecContext(context.Background(), `
		INSERT INTO file_transfer_payloads(transfer_id, payload)
		VALUES ($1, $2)
		ON CONFLICT (transfer_id) DO UPDATE SET
			payload = EXCLUDED.payload
	`, payload.TransferID, payload.Payload)
	return err
}

func (r *FileTransferPayloadRepo) FindByTransferID(transferID string) (*domain.FileTransferPayload, error) {
	row := r.db.QueryRowContext(context.Background(), `
		SELECT ft.id, ft.content_type, ft.size_bytes, ft.payload_sha256, ftp.payload, ft.uploaded_at_unix, ft.downloaded_at_unix
		FROM file_transfers ft
		JOIN file_transfer_payloads ftp ON ftp.transfer_id = ft.id
		WHERE ft.id = $1
	`, transferID)
	return scanFileTransferPayload(row)
}

type SignalCandidateRepo struct {
	db *sql.DB
}

func NewSignalCandidateRepo(db *sql.DB) *SignalCandidateRepo {
	return &SignalCandidateRepo{db: db}
}

func (r *SignalCandidateRepo) Save(candidate *domain.SignalCandidate) error {
	_, err := r.db.ExecContext(context.Background(), `
		INSERT INTO signal_candidates(id, peer_id, network_id, type, protocol, address, preference, reachable, created_at_unix, expires_at_unix)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE SET
			peer_id = EXCLUDED.peer_id,
			network_id = EXCLUDED.network_id,
			type = EXCLUDED.type,
			protocol = EXCLUDED.protocol,
			address = EXCLUDED.address,
			preference = EXCLUDED.preference,
			reachable = EXCLUDED.reachable,
			created_at_unix = EXCLUDED.created_at_unix,
			expires_at_unix = EXCLUDED.expires_at_unix
	`, candidate.ID, candidate.PeerID.String(), candidate.NetworkID.String(), string(candidate.Type), string(candidate.Protocol), candidate.Address, candidate.Preference, candidate.Reachable, candidate.CreatedAtUnix, candidate.ExpiresAtUnix)
	return err
}

func (r *SignalCandidateRepo) ListByPeerID(peerID domain.PeerID) ([]*domain.SignalCandidate, error) {
	rows, err := r.db.QueryContext(context.Background(), `
		SELECT id, peer_id, network_id, type, protocol, address, preference, reachable, created_at_unix, expires_at_unix
		FROM signal_candidates
		WHERE peer_id = $1
		ORDER BY preference DESC, created_at_unix DESC, id DESC
	`, peerID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*domain.SignalCandidate
	for rows.Next() {
		candidate, err := scanSignalCandidate(rows)
		if err != nil {
			return nil, err
		}
		if candidate != nil {
			result = append(result, candidate)
		}
	}
	return result, rows.Err()
}

func (r *SignalCandidateRepo) DeleteExpired(nowUnix int64) error {
	_, err := r.db.ExecContext(context.Background(), `
		DELETE FROM signal_candidates WHERE expires_at_unix <= $1
	`, nowUnix)
	return err
}

type TunnelRepo struct {
	db *sql.DB
}

func NewTunnelRepo(db *sql.DB) *TunnelRepo {
	return &TunnelRepo{db: db}
}

func (r *TunnelRepo) Save(t *domain.Tunnel) error {
	_, err := r.db.ExecContext(context.Background(), `
		INSERT INTO tunnels(id, network_id, peer_a, peer_b, mode, state, created_at_unix)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (id) DO UPDATE SET
			network_id = EXCLUDED.network_id,
			peer_a = EXCLUDED.peer_a,
			peer_b = EXCLUDED.peer_b,
			mode = EXCLUDED.mode,
			state = EXCLUDED.state,
			created_at_unix = EXCLUDED.created_at_unix
	`, t.ID.String(), t.NetworkID.String(), t.A.String(), t.B.String(), string(t.Mode), string(t.State), t.CreatedAtUnix)
	return err
}

func (r *TunnelRepo) FindByID(id domain.TunnelID) (*domain.Tunnel, error) {
	row := r.db.QueryRowContext(context.Background(), `
		SELECT id, network_id, peer_a, peer_b, mode, state, created_at_unix
		FROM tunnels
		WHERE id = $1
	`, id.String())
	return scanTunnel(row)
}

func (r *TunnelRepo) FindByPeers(networkID domain.NetworkID, a, b domain.PeerID) (*domain.Tunnel, error) {
	row := r.db.QueryRowContext(context.Background(), `
		SELECT id, network_id, peer_a, peer_b, mode, state, created_at_unix
		FROM tunnels
		WHERE network_id = $1
		  AND ((peer_a = $2 AND peer_b = $3) OR (peer_a = $3 AND peer_b = $2))
		ORDER BY created_at_unix DESC, id DESC
		LIMIT 1
	`, networkID.String(), a.String(), b.String())
	return scanTunnel(row)
}

func (r *TunnelRepo) ListByNetwork(networkID domain.NetworkID) ([]*domain.Tunnel, error) {
	rows, err := r.db.QueryContext(context.Background(), `
		SELECT id, network_id, peer_a, peer_b, mode, state, created_at_unix
		FROM tunnels
		WHERE network_id = $1
		ORDER BY created_at_unix DESC, id DESC
	`, networkID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*domain.Tunnel
	for rows.Next() {
		tunnel, err := scanTunnel(rows)
		if err != nil {
			return nil, err
		}
		if tunnel != nil {
			result = append(result, tunnel)
		}
	}
	return result, rows.Err()
}

type InviteRepo struct {
	db *sql.DB
}

func NewInviteRepo(db *sql.DB) *InviteRepo {
	return &InviteRepo{db: db}
}

func (r *InviteRepo) Save(i *domain.Invite) error {
	_, err := r.db.ExecContext(context.Background(), `
		INSERT INTO invites(code, network_id, expires_at_unix, max_uses, uses)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (code) DO UPDATE SET
			network_id = EXCLUDED.network_id,
			expires_at_unix = EXCLUDED.expires_at_unix,
			max_uses = EXCLUDED.max_uses,
			uses = EXCLUDED.uses
	`, i.Code, i.NetworkID.String(), i.ExpiresAtUnix, i.MaxUses, i.Uses)
	return err
}

func (r *InviteRepo) FindByCode(code string) (*domain.Invite, error) {
	row := r.db.QueryRowContext(context.Background(), `
		SELECT code, network_id, expires_at_unix, max_uses, uses
		FROM invites
		WHERE code = $1
	`, code)
	var invite domain.Invite
	var networkID string
	if err := row.Scan(&invite.Code, &networkID, &invite.ExpiresAtUnix, &invite.MaxUses, &invite.Uses); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	invite.NetworkID = domain.NetworkID{Value: networkID}
	return &invite, nil
}

func (r *InviteRepo) DeleteStale(nowUnix int64) error {
	_, err := r.db.ExecContext(context.Background(), `
		DELETE FROM invites
		WHERE expires_at_unix <= $1
		   OR (max_uses > 0 AND uses >= max_uses)
	`, nowUnix)
	return err
}

type AuditRepo struct {
	db *sql.DB
}

func NewAuditRepo(db *sql.DB) *AuditRepo {
	return &AuditRepo{db: db}
}

func (r *AuditRepo) Append(e *domain.AuditEvent) error {
	var networkID any
	if e.NetworkID.String() != "" {
		networkID = e.NetworkID.String()
	}
	_, err := r.db.ExecContext(context.Background(), `
		INSERT INTO audit_events(id, actor_user_id, network_id, type, details, created_at_unix)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, e.ID, e.ActorUserID.String(), networkID, e.Type, e.Details, e.CreatedAtUnix)
	return err
}

func (r *AuditRepo) ListRecent(limit int) ([]*domain.AuditEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.QueryContext(context.Background(), `
		SELECT id, actor_user_id, network_id, type, details, created_at_unix
		FROM audit_events
		ORDER BY created_at_unix DESC, id DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*domain.AuditEvent
	for rows.Next() {
		var event domain.AuditEvent
		var actorUserID string
		var networkID sql.NullString
		if err := rows.Scan(&event.ID, &actorUserID, &networkID, &event.Type, &event.Details, &event.CreatedAtUnix); err != nil {
			return nil, err
		}
		event.ActorUserID = domain.UserID{Value: actorUserID}
		if networkID.Valid {
			event.NetworkID = domain.NetworkID{Value: networkID.String}
		}
		result = append(result, &event)
	}
	return result, rows.Err()
}

func (r *AuditRepo) ListByNetworkID(networkID domain.NetworkID, limit int) ([]*domain.AuditEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.QueryContext(context.Background(), `
		SELECT id, actor_user_id, network_id, type, details, created_at_unix
		FROM audit_events
		WHERE network_id = $1
		ORDER BY created_at_unix DESC, id DESC
		LIMIT $2
	`, networkID.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*domain.AuditEvent
	for rows.Next() {
		var event domain.AuditEvent
		var actorUserID string
		var storedNetworkID sql.NullString
		if err := rows.Scan(&event.ID, &actorUserID, &storedNetworkID, &event.Type, &event.Details, &event.CreatedAtUnix); err != nil {
			return nil, err
		}
		event.ActorUserID = domain.UserID{Value: actorUserID}
		if storedNetworkID.Valid {
			event.NetworkID = domain.NetworkID{Value: storedNetworkID.String}
		}
		result = append(result, &event)
	}
	return result, rows.Err()
}

type SessionRepo struct {
	db *sql.DB
}

func NewSessionRepo(db *sql.DB) *SessionRepo {
	return &SessionRepo{db: db}
}

func (r *SessionRepo) FindByRefreshToken(refreshToken string) (*domain.SessionToken, error) {
	row := r.db.QueryRowContext(context.Background(), `
		SELECT id, user_id, family_id, access_token, refresh_token, device_name, ip, user_agent, last_used_at_unix, expires_at_unix, replaced_by_token, revoked_at_unix, reuse_detected_at_unix
		FROM session_tokens
		WHERE refresh_token = $1
	`, refreshToken)
	return scanSession(row)
}

func (r *SessionRepo) FindByAccessToken(accessToken string) (*domain.SessionToken, error) {
	row := r.db.QueryRowContext(context.Background(), `
		SELECT id, user_id, family_id, access_token, refresh_token, device_name, ip, user_agent, last_used_at_unix, expires_at_unix, replaced_by_token, revoked_at_unix, reuse_detected_at_unix
		FROM session_tokens
		WHERE access_token = $1
	`, accessToken)
	return scanSession(row)
}

func (r *SessionRepo) ListByUserID(userID domain.UserID, limit, offset int) ([]*domain.SessionToken, int, error) {
	if limit <= 0 {
		limit = 20
	}
	var total int
	if err := r.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM (
			SELECT DISTINCT ON (family_id) family_id
			FROM session_tokens
			WHERE user_id = $1
			ORDER BY family_id, (replaced_by_token = '') DESC, last_used_at_unix DESC, id DESC
		) s
	`, userID.String()).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.db.QueryContext(context.Background(), `
		SELECT DISTINCT ON (family_id) id, user_id, family_id, access_token, refresh_token, device_name, ip, user_agent, last_used_at_unix, expires_at_unix, replaced_by_token, revoked_at_unix, reuse_detected_at_unix
		FROM session_tokens
		WHERE user_id = $1
		ORDER BY family_id, (replaced_by_token = '') DESC, last_used_at_unix DESC, id DESC
		LIMIT $2 OFFSET $3
	`, userID.String(), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*domain.SessionToken
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil, 0, err
		}
		if session != nil {
			out = append(out, session)
		}
	}
	return out, total, rows.Err()
}

func (r *SessionRepo) DeleteExpired(nowUnix int64) error {
	_, err := r.db.ExecContext(context.Background(), `
		DELETE FROM session_tokens WHERE expires_at_unix <= $1
	`, nowUnix)
	return err
}

type VirtualIPPoolRepo struct {
	db *sql.DB
}

func NewVirtualIPPoolRepo(db *sql.DB) *VirtualIPPoolRepo {
	return &VirtualIPPoolRepo{db: db}
}

func (r *VirtualIPPoolRepo) Save(pool *domain.VirtualIPPool) error {
	tx, err := r.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(context.Background(), `
		INSERT INTO virtual_ip_pools(network_id, cidr)
		VALUES ($1, $2)
		ON CONFLICT (network_id) DO UPDATE SET
			cidr = EXCLUDED.cidr
	`, pool.NetworkID.String(), pool.CIDR); err != nil {
		return err
	}
	if _, err = tx.ExecContext(context.Background(), `DELETE FROM virtual_ip_leases WHERE network_id = $1`, pool.NetworkID.String()); err != nil {
		return err
	}
	for ip, peerID := range pool.Leases {
		if _, err = tx.ExecContext(context.Background(), `
			INSERT INTO virtual_ip_leases(network_id, ip, peer_id)
			VALUES ($1, $2, $3)
		`, pool.NetworkID.String(), ip, peerID.String()); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *VirtualIPPoolRepo) FindByNetworkID(networkID domain.NetworkID) (*domain.VirtualIPPool, error) {
	row := r.db.QueryRowContext(context.Background(), `
		SELECT network_id, cidr
		FROM virtual_ip_pools
		WHERE network_id = $1
	`, networkID.String())
	var storedNetworkID string
	var cidr string
	if err := row.Scan(&storedNetworkID, &cidr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	pool := domain.NewVirtualIPPool(domain.NetworkID{Value: storedNetworkID}, cidr)
	rows, err := r.db.QueryContext(context.Background(), `
		SELECT ip, peer_id
		FROM virtual_ip_leases
		WHERE network_id = $1
	`, networkID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ip, peerID string
		if err := rows.Scan(&ip, &peerID); err != nil {
			return nil, err
		}
		pool.Leases[ip] = domain.PeerID{Value: peerID}
	}
	return pool, rows.Err()
}

func (r *VirtualIPPoolRepo) List() ([]*domain.VirtualIPPool, error) {
	rows, err := r.db.QueryContext(context.Background(), `
		SELECT network_id, cidr
		FROM virtual_ip_pools
		ORDER BY network_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	pools := []*domain.VirtualIPPool{}
	for rows.Next() {
		var networkID string
		var cidr string
		if err := rows.Scan(&networkID, &cidr); err != nil {
			return nil, err
		}
		pool := domain.NewVirtualIPPool(domain.NetworkID{Value: networkID}, cidr)
		pools = append(pools, pool)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, pool := range pools {
		leaseRows, err := r.db.QueryContext(context.Background(), `
			SELECT ip, peer_id
			FROM virtual_ip_leases
			WHERE network_id = $1
			ORDER BY ip
		`, pool.NetworkID.String())
		if err != nil {
			return nil, err
		}
		for leaseRows.Next() {
			var ip string
			var peerID string
			if err := leaseRows.Scan(&ip, &peerID); err != nil {
				leaseRows.Close()
				return nil, err
			}
			pool.Leases[ip] = domain.PeerID{Value: peerID}
		}
		if err := leaseRows.Err(); err != nil {
			leaseRows.Close()
			return nil, err
		}
		leaseRows.Close()
	}
	return pools, nil
}

func scanUser(scanner interface{ Scan(dest ...any) error }) (*domain.User, error) {
	var user domain.User
	var status string
	if err := scanner.Scan(&user.ID.Value, &user.Email, &user.PasswordHash, &status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	user.Status = domain.UserStatus(status)
	return &user, nil
}

func scanPeer(scanner interface{ Scan(dest ...any) error }) (*domain.Peer, error) {
	var peer domain.Peer
	var userID, deviceID, networkID, status, reachability, connectionState string
	if err := scanner.Scan(&peer.ID.Value, &userID, &deviceID, &networkID, &peer.VirtualIP, &peer.Endpoint, &status, &reachability, &connectionState, &peer.LastSeenUnix, &peer.LastSignaledAtUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	peer.UserID = domain.UserID{Value: userID}
	peer.DeviceID = domain.DeviceID{Value: deviceID}
	peer.NetworkID = domain.NetworkID{Value: networkID}
	peer.Status = domain.PeerStatus(status)
	peer.Reachability = domain.PeerReachability(reachability)
	peer.ConnectionState = domain.ConnectionState(connectionState)
	return &peer, nil
}

func scanMessage(scanner interface{ Scan(dest ...any) error }) (*domain.Message, error) {
	var message domain.Message
	var networkID, fromPeerID string
	if err := scanner.Scan(&message.ID, &networkID, &fromPeerID, &message.Text, &message.SentAtUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	message.NetworkID = domain.NetworkID{Value: networkID}
	message.FromPeerID = domain.PeerID{Value: fromPeerID}
	return &message, nil
}

func scanFileTransfer(scanner interface{ Scan(dest ...any) error }) (*domain.FileTransfer, error) {
	var transfer domain.FileTransfer
	var networkID, fromPeerID, fromUserID, toPeerID, toUserID, status string
	var cancelReason sql.NullString
	var contentType, payloadSHA256 sql.NullString
	if err := scanner.Scan(&transfer.ID, &networkID, &fromPeerID, &fromUserID, &toPeerID, &toUserID, &transfer.FileName, &transfer.SizeBytes, &status, &transfer.ProgressPercent, &cancelReason, &contentType, &payloadSHA256, &transfer.PayloadReady, &transfer.PayloadUploadedBytes, &transfer.UploadedAtUnix, &transfer.DownloadedAtUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	transfer.NetworkID = domain.NetworkID{Value: networkID}
	transfer.FromPeerID = domain.PeerID{Value: fromPeerID}
	transfer.FromUserID = domain.UserID{Value: fromUserID}
	transfer.ToPeerID = domain.PeerID{Value: toPeerID}
	transfer.ToUserID = domain.UserID{Value: toUserID}
	transfer.Status = domain.TransferStatus(status)
	if cancelReason.Valid {
		transfer.CancelReason = cancelReason.String
	}
	if contentType.Valid {
		transfer.ContentType = contentType.String
	}
	if payloadSHA256.Valid {
		transfer.PayloadSHA256 = payloadSHA256.String
	}
	if transfer.PayloadReady && transfer.PayloadUploadedBytes == 0 {
		transfer.PayloadUploadedBytes = transfer.SizeBytes
	}
	return &transfer, nil
}

func scanFileTransferPayload(scanner interface{ Scan(dest ...any) error }) (*domain.FileTransferPayload, error) {
	var payload domain.FileTransferPayload
	var contentType, sha256 sql.NullString
	if err := scanner.Scan(&payload.TransferID, &contentType, &payload.SizeBytes, &sha256, &payload.Payload, &payload.UploadedAtUnix, &payload.DownloadedAtUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if contentType.Valid {
		payload.ContentType = contentType.String
	}
	if sha256.Valid {
		payload.SHA256 = sha256.String
	}
	return &payload, nil
}

func scanSignalCandidate(scanner interface{ Scan(dest ...any) error }) (*domain.SignalCandidate, error) {
	var candidate domain.SignalCandidate
	var peerID, networkID, candidateType, protocol string
	if err := scanner.Scan(&candidate.ID, &peerID, &networkID, &candidateType, &protocol, &candidate.Address, &candidate.Preference, &candidate.Reachable, &candidate.CreatedAtUnix, &candidate.ExpiresAtUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	candidate.PeerID = domain.PeerID{Value: peerID}
	candidate.NetworkID = domain.NetworkID{Value: networkID}
	candidate.Type = domain.SignalCandidateType(candidateType)
	candidate.Protocol = domain.SignalCandidateProtocol(protocol)
	return &candidate, nil
}

func scanDevice(scanner interface{ Scan(dest ...any) error }) (*domain.Device, error) {
	var device domain.Device
	var userID, status string
	if err := scanner.Scan(
		&device.ID.Value,
		&userID,
		&device.Name,
		&device.PublicKey,
		&device.Fingerprint,
		&status,
		&device.CreatedAtUnix,
		&device.RevokedAtUnix,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	device.UserID = domain.UserID{Value: userID}
	device.Status = domain.DeviceStatus(status)
	return &device, nil
}

func scanTunnel(scanner interface{ Scan(dest ...any) error }) (*domain.Tunnel, error) {
	var tunnel domain.Tunnel
	var networkID, peerA, peerB, mode, state string
	if err := scanner.Scan(&tunnel.ID.Value, &networkID, &peerA, &peerB, &mode, &state, &tunnel.CreatedAtUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	tunnel.NetworkID = domain.NetworkID{Value: networkID}
	tunnel.A = domain.PeerID{Value: peerA}
	tunnel.B = domain.PeerID{Value: peerB}
	tunnel.Mode = domain.TunnelMode(mode)
	tunnel.State = domain.TunnelState(state)
	return &tunnel, nil
}

func scanSession(scanner interface{ Scan(dest ...any) error }) (*domain.SessionToken, error) {
	var session domain.SessionToken
	var userID string
	if err := scanner.Scan(
		&session.ID,
		&userID,
		&session.FamilyID,
		&session.AccessToken,
		&session.RefreshToken,
		&session.DeviceName,
		&session.IP,
		&session.UserAgent,
		&session.LastUsedAtUnix,
		&session.ExpiresAtUnix,
		&session.ReplacedByToken,
		&session.RevokedAtUnix,
		&session.ReuseDetectedAtUnix,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	session.UserID = domain.UserID{Value: userID}
	return &session, nil
}

func Ping(db *sql.DB) error {
	if err := db.PingContext(context.Background()); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	return nil
}

func nullableString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
}
