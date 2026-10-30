package httpapi

import (
	"Ole/internal/domain"
	"net/http"
	"strconv"
	"strings"
)

func paginateSlice[T any](items []T, limit, offset int) ([]T, int) {
	total := len(items)
	if offset > total {
		return []T{}, total
	}
	if limit <= 0 {
		limit = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return items[offset:end], total
}

func filterDevices(items []*domain.Device, r *http.Request) []*domain.Device {
	status := strings.TrimSpace(strings.ToUpper(r.URL.Query().Get("status")))
	q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q")))

	out := make([]*domain.Device, 0, len(items))
	for _, item := range items {
		if status != "" && string(item.Status) != status {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(item.ID.String()), q) && !strings.Contains(strings.ToLower(item.Name), q) && !strings.Contains(strings.ToLower(item.Fingerprint), q) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func filterNetworks(items []*domain.Network, r *http.Request) []*domain.Network {
	ownerID := strings.TrimSpace(r.URL.Query().Get("ownerId"))
	memberID := strings.TrimSpace(r.URL.Query().Get("memberId"))
	access := strings.TrimSpace(strings.ToUpper(r.URL.Query().Get("access")))
	q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q")))

	out := make([]*domain.Network, 0, len(items))
	for _, item := range items {
		if ownerID != "" && item.OwnerID.String() != ownerID {
			continue
		}
		if memberID != "" && !item.HasMember(domain.UserID{Value: memberID}) {
			continue
		}
		if access != "" && string(item.Access) != access {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(item.Name), q) && !strings.Contains(strings.ToLower(item.ID.String()), q) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func filterPeers(items []*domain.Peer, r *http.Request) []*domain.Peer {
	status := strings.TrimSpace(strings.ToUpper(r.URL.Query().Get("status")))
	userID := strings.TrimSpace(r.URL.Query().Get("userId"))
	q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q")))

	out := make([]*domain.Peer, 0, len(items))
	for _, item := range items {
		if status != "" && string(item.Status) != status {
			continue
		}
		if userID != "" && item.UserID.String() != userID {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(item.ID.String()), q) && !strings.Contains(strings.ToLower(item.Endpoint), q) && !strings.Contains(strings.ToLower(item.VirtualIP), q) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func filterMessages(items []*domain.Message, r *http.Request) []*domain.Message {
	fromPeerID := strings.TrimSpace(r.URL.Query().Get("fromPeerId"))
	q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q")))

	out := make([]*domain.Message, 0, len(items))
	for _, item := range items {
		if fromPeerID != "" && item.FromPeerID.String() != fromPeerID {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(item.Text), q) && !strings.Contains(strings.ToLower(item.ID), q) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func filterFileTransfers(items []*domain.FileTransfer, r *http.Request) []*domain.FileTransfer {
	status := strings.TrimSpace(strings.ToUpper(r.URL.Query().Get("status")))
	fromPeerID := strings.TrimSpace(r.URL.Query().Get("fromPeerId"))
	toPeerID := strings.TrimSpace(r.URL.Query().Get("toPeerId"))
	q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q")))

	out := make([]*domain.FileTransfer, 0, len(items))
	for _, item := range items {
		if status != "" && string(item.Status) != status {
			continue
		}
		if fromPeerID != "" && item.FromPeerID.String() != fromPeerID {
			continue
		}
		if toPeerID != "" && item.ToPeerID.String() != toPeerID {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(item.FileName), q) && !strings.Contains(strings.ToLower(item.ID), q) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func filterTunnels(items []*domain.Tunnel, r *http.Request) []*domain.Tunnel {
	state := strings.TrimSpace(strings.ToUpper(r.URL.Query().Get("state")))
	mode := strings.TrimSpace(strings.ToUpper(r.URL.Query().Get("mode")))
	peerID := strings.TrimSpace(r.URL.Query().Get("peerId"))

	out := make([]*domain.Tunnel, 0, len(items))
	for _, item := range items {
		if state != "" && string(item.State) != state {
			continue
		}
		if mode != "" && string(item.Mode) != mode {
			continue
		}
		if peerID != "" && !item.Involves(domain.PeerID{Value: peerID}) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func filterAuditEvents(items []*domain.AuditEvent, r *http.Request) []*domain.AuditEvent {
	actorUserID := strings.TrimSpace(r.URL.Query().Get("actorUserId"))
	eventType := strings.TrimSpace(r.URL.Query().Get("type"))
	q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q")))
	fromUnix, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("fromUnix")), 10, 64)
	toUnix, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("toUnix")), 10, 64)

	out := make([]*domain.AuditEvent, 0, len(items))
	for _, item := range items {
		if actorUserID != "" && item.ActorUserID.String() != actorUserID {
			continue
		}
		if eventType != "" && item.Type != eventType {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(item.Type), q) && !strings.Contains(strings.ToLower(item.Details), q) {
			continue
		}
		if fromUnix > 0 && item.CreatedAtUnix < fromUnix {
			continue
		}
		if toUnix > 0 && item.CreatedAtUnix > toUnix {
			continue
		}
		out = append(out, item)
	}
	return out
}
