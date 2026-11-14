package public

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func publicURLConnectorPairResponse(pair controlstate.ConnectorPeerPair) controlv1.PublicURLConnectorPeerPair {
	result := controlv1.PublicURLConnectorPeerPair{PairId: pair.ID, PublicUrlId: pair.PublicURLID,
		PublishRunId: pair.PublishRunID, PublishRunNumber: pair.PublishRunNumber, PublisherIdentityId: pair.PublisherIdentityID,
		Subject: visitorsubject.Wire(pair.Subject), DeliveryId: base64.RawURLEncoding.EncodeToString(pair.DeliveryID[:]),
		DeliveryGeneration: pair.DeliveryGeneration, Key: pair.Key, SessionKey: pair.SessionKey, TrustRevision: pair.TrustRevision,
		OperationId: pair.OperationID, BindingChallenge: pair.BindingChallenge, BindingState: controlv1.ConnectorPeerPairBindingState(pair.BindingState),
		Relays: connectorPairRelays(pair.Relays), ObservedAt: pair.ObservedAt, ExpiresAt: pair.ExpiresAt}
	if pair.SourceIP.IsValid() {
		source := pair.SourceIP.String()
		result.SourceIp = &source
	}
	if !pair.PublisherPreparedUntil.IsZero() {
		result.PublisherPreparedUntil = &pair.PublisherPreparedUntil
	}
	if !pair.PublisherProvedUntil.IsZero() {
		result.PublisherProvedUntil = &pair.PublisherProvedUntil
	}
	return result
}

func (h *handler) publicURLConnectorPair(w http.ResponseWriter, r *http.Request, publicURLID, pairID string) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.PublicURLConnectorPeerPairRequest
	if decodeJSONLimited(w, r, &body, 8192) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid public URL connector pair request")
		return
	}
	proof, err := controlv1.PublicURLConnectorPeerPairProof(publicURLID, body)
	if err != nil || pairID == "" && proof.Action != "create" && proof.Action != "replace" ||
		pairID != "" && (proof.Action != "renew" || proof.PreviousPairID != pairID) {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid public URL connector pair proof")
		return
	}
	request, err := connectorPairProofInput(proof, body.Signature)
	if err != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid public URL connector pair signature")
		return
	}
	source, err := json.Marshal(body.Source)
	if err != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid public URL connector source")
		return
	}
	ctx, ok := h.connectorPairSource(w, r, controlv1.ConnectorPeerPairRequest{Source: source}, &request)
	if !ok {
		return
	}
	if h.dependencies.ConnectorPeerPairs == nil {
		writeProblem(w, 503, controlv1.Unavailable, "public URL connector pairs are unavailable")
		return
	}
	var pair controlstate.ConnectorPeerPair
	if pairID == "" {
		pair, err = h.dependencies.ConnectorPeerPairs.PrepareConnectorPeerPair(ctx, request, time.Now())
	} else {
		pair, err = h.dependencies.ConnectorPeerPairs.RenewConnectorPeerPair(ctx, h.config.ControlURL, request, time.Now())
	}
	if err != nil {
		connectorPairProblem(ctx, w, err)
		return
	}
	if pairID == "" {
		writeJSON(w, 200, publicURLConnectorPairResponse(pair))
		return
	}
	writeJSON(w, 200, controlv1.PublicURLConnectorPeerPairRenewal{Pair: publicURLConnectorPairResponse(pair),
		RunValidUntil: pair.RunValidUntil, Protocol: pair.Metadata.Protocol, TrustRevision: pair.Metadata.TrustRevision,
		Endpoint:          controlv1.ServiceEndpoint{Hostname: pair.Metadata.Endpoint.Hostname, Port: pair.Metadata.Endpoint.Port, Public: pair.Metadata.Endpoint.Public},
		VisitorPermission: visitorTokenResponse(pair.VisitorPermission)})
}

func (h *handler) PreparePublicURLConnectorPeerPair(w http.ResponseWriter, r *http.Request, publicURLID controlv1.PublicURLID) {
	h.publicURLConnectorPair(w, r, publicURLID, "")
}

func (h *handler) RenewPublicURLConnectorPeerPair(w http.ResponseWriter, r *http.Request, publicURLID controlv1.PublicURLID, pairID string) {
	h.publicURLConnectorPair(w, r, publicURLID, pairID)
}

func (h *handler) RebindPublicURLConnectorPeerPair(w http.ResponseWriter, r *http.Request, publicURLID controlv1.PublicURLID, pairID string) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.PublicURLConnectorPeerPairRebindRequest
	if decodeJSONLimited(w, r, &body, 16<<10) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid public URL connector rebind request")
		return
	}
	proof, err := controlv1.PublicURLConnectorPeerPairRebindProof(publicURLID, pairID, body)
	signature, sigErr := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	if err != nil || sigErr != nil || len(signature) != ed25519.SignatureSize {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid public URL connector rebind proof")
		return
	}
	source, err := json.Marshal(body.Source)
	if err != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid public URL connector source")
		return
	}
	request := controlstate.ConnectorPeerPairRequest{Subject: proof.Subject}
	ctx, ok := h.connectorPairSource(w, r, controlv1.ConnectorPeerPairRequest{Source: source}, &request)
	if !ok {
		return
	}
	if h.dependencies.ConnectorPeerPairs == nil {
		writeProblem(w, 503, controlv1.Unavailable, "public URL connector rebinding is unavailable")
		return
	}
	state, err := h.dependencies.ConnectorPeerPairs.RebindPublicURLConnectorPeerPair(ctx, publicURLID, pairID,
		controlstate.ConnectorPeerPairRebindRequest{Proof: proof, Source: request.Source, Signature: signature}, time.Now())
	if err != nil {
		connectorPairProblem(ctx, w, err)
		return
	}
	result := controlv1.PublicURLConnectorPeerPairRebindState{HighWaterGeneration: state.HighWaterGeneration, ReadyRelays: []controlv1.ConnectorPeerPairRelay{}}
	if state.Active != nil {
		active := publicURLConnectorPairResponse(*state.Active)
		result.Active = &active
	}
	if state.Pending != nil {
		pending := publicURLConnectorPairResponse(*state.Pending)
		result.Pending = &pending
	}
	if !state.PendingUntil.IsZero() {
		result.PendingUntil = &state.PendingUntil
	}
	for _, relay := range state.ReadyRelays {
		result.ReadyRelays = append(result.ReadyRelays, connectorPairRelays([2]controlstate.ConnectorPeerPairRelay{relay})[0])
	}
	if state.OperationID != "" {
		result.Operation = &controlv1.ConnectorPeerPairRebindOperation{OperationId: state.OperationID,
			DeliveryGeneration: state.OperationGeneration, Status: controlv1.ConnectorPeerPairRebindOperationStatus(state.OperationStatus)}
	}
	writeJSON(w, 200, result)
}

func publicURLConnectorPublisherProblem(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, controlstate.ErrPublishRunCredential) {
		writeBearerProblem(w)
		return
	}
	connectorPairProblem(r.Context(), w, err)
}

func (h *handler) ListPublicURLConnectorPeerPairs(w http.ResponseWriter, r *http.Request, runID controlv1.PublishRunID, params controlv1.ListPublicURLConnectorPeerPairsParams) {
	w.Header().Set("Cache-Control", "no-store")
	after := ""
	if params.After != nil {
		after = *params.After
	}
	if params.PublishRunNumber < 1 || after != "" && !opaqueid.Valid(after, "cpp_") {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid public URL connector candidate request")
		return
	}
	auth, ok := h.authenticatePublishRunRequest(w, r, runID, uint64(params.PublishRunNumber))
	if !ok {
		return
	}
	if h.dependencies.ConnectorPeerPairs == nil {
		writeProblem(w, 503, controlv1.Unavailable, "public URL connector discovery is unavailable")
		return
	}
	page, err := h.dependencies.ConnectorPeerPairs.ListPublicURLConnectorPeerPairs(r.Context(), auth, after, time.Now())
	if err != nil {
		publicURLConnectorPublisherProblem(w, r, err)
		return
	}
	writeJSON(w, 200, connectorPairCandidatesResponse(page))
}

func (h *handler) DeliverPublicURLConnectorPeerPair(w http.ResponseWriter, r *http.Request, runID controlv1.PublishRunID, pairID string) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.DeliverPublicURLConnectorPeerPairJSONRequestBody
	if decodeJSONLimited(w, r, &body, 1024) != nil || body.PublishRunNumber < 1 || body.DeliveryGeneration < 1 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid public URL connector delivery request")
		return
	}
	auth, ok := h.authenticatePublishRunRequest(w, r, runID, uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	if h.dependencies.ConnectorPeerPairs == nil {
		writeProblem(w, 503, controlv1.Unavailable, "public URL connector delivery is unavailable")
		return
	}
	delivery, err := h.dependencies.ConnectorPeerPairs.DeliverPublicURLConnectorPeerPair(r.Context(), auth, pairID, body.DeliveryGeneration, time.Now())
	if err != nil {
		publicURLConnectorPublisherProblem(w, r, err)
		return
	}
	writeJSON(w, 200, controlv1.PublicURLConnectorPeerPairDelivery{PairId: delivery.PairID, PublicUrlId: delivery.PublicURLID,
		PublishRunId: delivery.PublishRunID, PublishRunNumber: delivery.PublishRunNumber, PublisherIdentityId: delivery.PublisherIdentityID,
		Subject: visitorsubject.Wire(delivery.Subject), DeliveryGeneration: delivery.DeliveryGeneration,
		DeliveryId: base64.RawURLEncoding.EncodeToString(delivery.DeliveryID[:]), Key: delivery.Key, SessionKey: delivery.SessionKey,
		SourceIp: delivery.SourceIP.String(), Relays: connectorPairRelays(delivery.Relays), ObservedAt: delivery.ObservedAt, ExpiresAt: delivery.ExpiresAt,
		TrustRevision: delivery.TrustRevision, OperationId: delivery.OperationID, BindingChallenge: delivery.BindingChallenge,
		BindingState: controlv1.ConnectorPeerPairBindingState(delivery.BindingState)})
}

func (h *handler) ConfirmPublicURLConnectorPeerPairPrepared(w http.ResponseWriter, r *http.Request, runID controlv1.PublishRunID, pairID string) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.ConfirmPublicURLConnectorPeerPairPreparedJSONRequestBody
	if decodeJSONLimited(w, r, &body, 4096) != nil || body.PublishRunNumber < 1 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid public URL connector preparation report")
		return
	}
	prepared, err := connectorPairPreparedInput(body.Prepared)
	if err != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid public URL connector preparation report")
		return
	}
	auth, ok := h.authenticatePublishRunRequest(w, r, runID, uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	if h.dependencies.ConnectorPeerPairs == nil {
		writeProblem(w, 503, controlv1.Unavailable, "public URL connector preparation reports are unavailable")
		return
	}
	if err := h.dependencies.ConnectorPeerPairs.ConfirmPublicURLConnectorPeerPairPrepared(r.Context(), auth, pairID, prepared, time.Now()); err != nil {
		publicURLConnectorPublisherProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func connectorPairPreparedInput(body controlv1.ConnectorPeerPairPrepared) (controlstate.ConnectorPeerPairPrepared, error) {
	id, err := tunnelv1.ParsePeerDeliveryIdentifier(body.DeliveryId)
	if err != nil || !body.Phase.Valid() || body.DeliveryGeneration < 1 || body.BindingExpiresAt.IsZero() || len(body.PathProofs) > 2 {
		return controlstate.ConnectorPeerPairPrepared{}, controlstate.ErrServiceAccess
	}
	result := controlstate.ConnectorPeerPairPrepared{DeliveryID: id, DeliveryGeneration: body.DeliveryGeneration, BindingExpiresAt: body.BindingExpiresAt,
		Phase: string(body.Phase), OperationID: body.OperationId, BindingChallenge: body.BindingChallenge}
	for _, proof := range body.PathProofs {
		result.PathProofs = append(result.PathProofs, tunnelv1.ConnectorPeerPairPathProof{ConnectionSlot: proof.ConnectionSlot, ProbeNonce: proof.ProbeNonce, ReplyFrame: proof.ReplyFrame})
	}
	return result, nil
}
