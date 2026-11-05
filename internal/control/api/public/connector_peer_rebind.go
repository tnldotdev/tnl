package public

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (h *handler) RebindConnectorPeerPair(w http.ResponseWriter, r *http.Request, serviceID controlv1.ServiceID, pairID string) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.ConnectorPeerPairRebindRequest
	if decodeJSONLimited(w, r, &body, 16<<10) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid connector rebind request")
		return
	}
	proof, err := controlv1.ConnectorPeerPairRebindProof(serviceID, pairID, body)
	signature, sigErr := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	if err != nil || sigErr != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != body.Signature {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid connector rebind proof")
		return
	}
	sourceRequest := controlstate.ConnectorPeerPairRequest{Subject: proof.Subject}
	ctx, ok := h.connectorPairSource(w, r, controlv1.ConnectorPeerPairRequest{Source: body.Source}, &sourceRequest)
	if !ok {
		return
	}
	if h.dependencies.ConnectorPeerPairs == nil {
		writeProblem(w, 503, controlv1.Unavailable, "connector network rebinding is unavailable")
		return
	}
	state, err := h.dependencies.ConnectorPeerPairs.RebindConnectorPeerPair(ctx, serviceID, pairID, controlstate.ConnectorPeerPairRebindRequest{Proof: proof, Source: sourceRequest.Source, Signature: signature}, time.Now())
	if err != nil {
		connectorPairProblem(w, err)
		return
	}
	result := controlv1.ConnectorPeerPairRebindState{HighWaterGeneration: state.HighWaterGeneration, ReadyRelays: []controlv1.ConnectorPeerPairRelay{}}
	if state.Active != nil {
		active := connectorPairResponse(*state.Active)
		result.Active = &active
	}
	if state.Pending != nil {
		pending := connectorPairResponse(*state.Pending)
		result.Pending = &pending
	}
	if !state.PendingUntil.IsZero() {
		result.PendingUntil = &state.PendingUntil
	}
	for _, relay := range state.ReadyRelays {
		result.ReadyRelays = append(result.ReadyRelays, connectorPairRelays([2]controlstate.ConnectorPeerPairRelay{relay})[0])
	}
	if state.OperationID != "" {
		result.Operation = &controlv1.ConnectorPeerPairRebindOperation{OperationId: state.OperationID, DeliveryGeneration: state.OperationGeneration, Status: controlv1.ConnectorPeerPairRebindOperationStatus(state.OperationStatus)}
	}
	writeJSON(w, http.StatusOK, result)
}
