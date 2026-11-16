package public

import (
	"net/http"
	"strings"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (h *handler) RetireConnectorPeerPair(w http.ResponseWriter, r *http.Request, serviceID controlv1.ServiceID, pairID string) {
	w.Header().Set("Cache-Control", "no-store")
	// presence is forbidden, including empty values and noncanonical map keys.
	for name := range r.Header {
		if strings.EqualFold(name, "Authorization") {
			writeProblem(w, http.StatusForbidden, controlv1.Forbidden, "connector pair retirement accepts only its exact body proof")
			return
		}
	}
	var body controlv1.ConnectorPeerPairRetireRequest
	if decodeJSONLimited(w, r, &body, 4096) != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid connector pair retirement request")
		return
	}
	proof, err := controlv1.ConnectorPeerPairRetireProof(serviceID, pairID, body)
	mac, signature, authErr := controlv1.ConnectorPeerPairRetireAuthentication(body)
	if err != nil || authErr != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid connector pair retirement proof")
		return
	}
	if h.dependencies.ConnectorPeerPairs == nil {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "connector pair retirement is unavailable")
		return
	}
	retired, err := h.dependencies.ConnectorPeerPairs.RetireConnectorPeerPair(r.Context(), serviceID, pairID,
		controlstate.ConnectorPeerPairRetireRequest{Proof: proof, SessionProof: mac, Signature: signature}, time.Now())
	if err != nil {
		switch err {
		case controlstate.ErrServiceAccess:
			writeProblem(w, http.StatusForbidden, controlv1.Forbidden, "connector pair retirement could not be authenticated within its retained scope")
		case controlstate.ErrServiceConflict:
			writeProblem(w, http.StatusConflict, controlv1.Conflict, "connector pair was retired with a different request")
		default:
			writeControlStateProblem(r.Context(), w, "retire connector peer pair", err)
		}
		return
	}
	result := controlv1.ConnectorPeerPairRetirement{
		ServiceId: retired.ServiceID, ServiceRunId: retired.ServiceRunID, RunNumber: retired.RunNumber,
		PublisherIdentityId: retired.PublisherIdentityID, PairId: retired.PairID, DeliveryId: retired.DeliveryID,
		IdempotencyKey: retired.IdempotencyKey, Disposition: controlv1.ConnectorPeerPairDispositionRetired, OwnerRevision: retired.OwnerRevision,
		Retirement: controlv1.ConnectorPeerPairRetirementObservation{
			ObservedAt: retired.Retirement.ObservedAt, RetiredAt: retired.Retirement.RetiredAt, RetainedUntil: retired.Retirement.RetainedUntil},
	}
	if err := result.ValidateFor(serviceID, pairID, body); err != nil {
		writeControlStateProblem(r.Context(), w, "validate connector pair retirement", err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
