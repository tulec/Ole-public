package httpapi

import (
	"Ole/internal/domain"
	"errors"
	"net/http"
	"time"
)

func (api *API) getTransportIdentities(w http.ResponseWriter, r *http.Request, peerID string) {
	snapshot, err := api.app.PeerDirectory.TransportIdentities(currentUserID(r), domain.PeerID{Value: peerID}, time.Now())
	if err != nil {
		if errors.Is(err, domain.ErrUnauthorized) || errors.Is(err, domain.ErrNotFound) || errors.Is(err, domain.ErrDeviceNotActive) || errors.Is(err, domain.ErrDeviceApprovalRequired) {
			writeDomainError(w, err)
		} else {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "transport identities are unavailable"})
		}
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, envelope[*domain.TransportIdentitySnapshot]{Data: snapshot})
}
