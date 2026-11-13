package public

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type connectorPeerPairStore interface {
	PrepareConnectorPeerPair(context.Context, controlstate.ConnectorPeerPairRequest, time.Time) (controlstate.ConnectorPeerPair, error)
	RenewConnectorPeerPair(context.Context, string, controlstate.ConnectorPeerPairRequest, time.Time) (controlstate.ConnectorPeerPair, error)
}

func connectorPairRelays(relays [2]controlstate.ConnectorPeerPairRelay) []controlv1.ConnectorPeerPairRelay {
	result := make([]controlv1.ConnectorPeerPairRelay, 2)
	for i, relay := range relays {
		result[i] = controlv1.ConnectorPeerPairRelay{PublisherConnectionId: relay.PublisherConnectionID, AssignmentRevision: relay.AssignmentRevision,
			RelayLease: controlv1.ConnectorPeerRelayLease{RelayServiceId: relay.RelayLease.RelayServiceID, RelayId: relay.RelayLease.RelayID,
				RelayRunId: relay.RelayLease.RelayRunID, RelayLeaseRevision: int64(relay.RelayLease.RelayLeaseRevision)},
			RelayAddress: relay.RelayAddress, TlsServerName: relay.TLSServerName}
	}
	return result
}

func connectorPairResponse(pair controlstate.ConnectorPeerPair) controlv1.ConnectorPeerPair {
	result := controlv1.ConnectorPeerPair{PairId: pair.ID, ServiceId: pair.ServiceID, ServiceRunId: pair.ServiceRunID, RunNumber: pair.RunNumber,
		PublisherIdentityId: pair.PublisherIdentityID, Subject: visitorsubject.Wire(pair.Subject), DeliveryId: base64.RawURLEncoding.EncodeToString(pair.DeliveryID[:]), DeliveryGeneration: pair.DeliveryGeneration,
		Key: pair.Key, Relays: connectorPairRelays(pair.Relays), ObservedAt: pair.ObservedAt, ExpiresAt: pair.ExpiresAt}
	result.SessionKey, result.TrustRevision, result.OperationId, result.BindingChallenge, result.BindingState = pair.SessionKey, pair.TrustRevision, pair.OperationID, pair.BindingChallenge, controlv1.ConnectorPeerPairBindingState(pair.BindingState)
	if pair.SourceIP.IsValid() {
		source := pair.SourceIP.String()
		result.SourceIp = &source
	}
	if !pair.PublisherProvedUntil.IsZero() {
		result.PublisherProvedUntil = &pair.PublisherProvedUntil
	}
	if !pair.PublisherPreparedUntil.IsZero() {
		result.PublisherPreparedUntil = &pair.PublisherPreparedUntil
	}
	return result
}

func connectorPairInput(serviceID string, body controlv1.ConnectorPeerPairRequest) (controlstate.ConnectorPeerPairRequest, error) {
	proof, err := controlv1.ConnectorPeerPairProof(serviceID, body)
	if err != nil {
		return controlstate.ConnectorPeerPairRequest{}, controlstate.ErrServiceAccess
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return controlstate.ConnectorPeerPairRequest{}, controlstate.ErrServiceAccess
	}
	result := controlstate.ConnectorPeerPairRequest{ServiceID: proof.ServiceID, ServiceRunID: proof.ServiceRunID, RunNumber: proof.RunNumber,
		PublisherIdentityID: proof.PublisherIdentityID, Subject: proof.Subject, Action: proof.Action, IdempotencyKey: proof.IdempotencyKey,
		RequestedAt: proof.RequestedAt, PreviousPairID: proof.PreviousPairID, PreviousGeneration: proof.PreviousGeneration, Signature: signature}
	for i, relay := range proof.ExpectedRelays {
		result.ExpectedRelays[i] = controlstate.ConnectorPeerPairRelay{PublisherConnectionID: relay.PublisherConnectionID,
			AssignmentRevision: relay.AssignmentRevision, RelayAddress: relay.RelayAddress, TLSServerName: relay.TLSServerName,
			RelayLease: controlstate.RelayLeaseIdentity{RelayServiceID: relay.RelayLease.RelayServiceID, RelayID: relay.RelayLease.RelayID,
				RelayRunID: relay.RelayLease.RelayRunID, RelayLeaseRevision: relay.RelayLease.RelayLeaseRevision}}
	}
	return result, nil
}

func (h *handler) connectorPairSource(w http.ResponseWriter, r *http.Request, body controlv1.ConnectorPeerPairRequest, request *controlstate.ConnectorPeerPairRequest) (context.Context, bool) {
	source, human, err := parseVisitorTokenSource(body.Source)
	if err != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid connector peer pair source")
		return nil, false
	}
	if human {
		device, ok := source.(controlstate.DeviceTokenSource)
		if !ok || request.Subject.Kind != tunnelv1.VisitorHumanDevice || request.Subject.DeviceID != device.DeviceID {
			writeProblem(w, 403, controlv1.Forbidden, "connector peer pair source does not match the device")
			return nil, false
		}
		principal, ok := h.authorizeReads(w, r)
		if !ok {
			return nil, false
		}
		if principal.controlPrincipal.SessionID == "" || principal.identityID != request.Subject.IdentityID {
			writeProblem(w, 403, controlv1.Forbidden, "connector peer pair source does not match the session")
			return nil, false
		}
		request.Source = device
		return r.Context(), true
	}
	matched := false
	switch source.(type) {
	case controlstate.WorkloadTokenSource:
		matched = request.Subject.Kind == tunnelv1.VisitorWorkloadSession
	case controlstate.RegisteredKeyTokenSource:
		matched = request.Subject.Kind == tunnelv1.VisitorRegisteredKey
	}
	if !matched || len(r.Header.Values("Authorization")) != 0 {
		writeProblem(w, 403, controlv1.Forbidden, "select one connector peer pair source")
		return nil, false
	}
	request.Source = source
	return r.Context(), true
}

func connectorPairProblem(ctx context.Context, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, controlstate.ErrServiceAccess), errors.Is(err, controlstate.ErrVisitorPermission), errors.Is(err, controlstate.ErrPublisherIdentity), errors.Is(err, controlstate.ErrWorkloadDenied):
		writeProblem(w, 403, controlv1.Forbidden, "connector peer pair source or run is no longer authorized")
	case errors.Is(err, controlstate.ErrConnectorPeerBindingStale):
		writeProblem(w, 409, controlv1.StaleNetworkBinding, "connector network binding changed; inspect the retained owner")
	case errors.Is(err, controlstate.ErrServiceConflict):
		writeProblem(w, 409, controlv1.Conflict, "connector peer pair conflicts with the current delivery; inspect the retained owner")
	default:
		writeControlStateProblem(ctx, w, "authorize connector peer pair", err)
	}
}

func (h *handler) connectorPair(w http.ResponseWriter, r *http.Request, serviceID, pairID string) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.ConnectorPeerPairRequest
	if decodeJSONLimited(w, r, &body, 8192) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid connector peer pair request")
		return
	}
	request, err := connectorPairInput(serviceID, body)
	if err != nil || pairID == "" && request.Action != "create" && request.Action != "replace" || pairID != "" && (request.Action != "renew" || pairID != request.PreviousPairID) {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid connector peer pair request")
		return
	}
	ctx, ok := h.connectorPairSource(w, r, body, &request)
	if !ok {
		return
	}
	store, ok := h.dependencies.ConnectorPeerPairs, h.dependencies.ConnectorPeerPairs != nil
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "connector peer pairs are unavailable")
		return
	}
	var result controlstate.ConnectorPeerPair
	if pairID == "" {
		result, err = store.PrepareConnectorPeerPair(ctx, request, time.Now())
	} else {
		result, err = store.RenewConnectorPeerPair(ctx, h.config.ControlURL, request, time.Now())
	}
	if err != nil {
		connectorPairProblem(r.Context(), w, err)
		return
	}
	if pairID != "" {
		writeJSON(w, 200, controlv1.ConnectorPeerPairRenewal{Pair: connectorPairResponse(result), RunValidUntil: result.RunValidUntil,
			Protocol: controlv1.ServiceProtocol(result.Metadata.Protocol), TrustRevision: result.Metadata.TrustRevision,
			Endpoint:          controlv1.ServiceEndpoint{Hostname: result.Metadata.Endpoint.Hostname, Port: result.Metadata.Endpoint.Port, Public: result.Metadata.Endpoint.Public},
			VisitorPermission: visitorTokenResponse(result.VisitorPermission)})
		return
	}
	writeJSON(w, 200, connectorPairResponse(result))
}

func (h *handler) PrepareConnectorPeerPair(w http.ResponseWriter, r *http.Request, serviceID controlv1.ServiceID) {
	h.connectorPair(w, r, serviceID, "")
}

func (h *handler) RenewConnectorPeerPair(w http.ResponseWriter, r *http.Request, serviceID controlv1.ServiceID, pairID string) {
	h.connectorPair(w, r, serviceID, pairID)
}

func (h *handler) ListConnectorPeerPairs(w http.ResponseWriter, r *http.Request, serviceID controlv1.ServiceID, runID controlv1.ServiceRunID, params controlv1.ListConnectorPeerPairsParams) {
	w.Header().Set("Cache-Control", "no-store")
	after := ""
	if params.After != nil {
		after = *params.After
		if !opaqueid.Valid(after, "cpp_") {
			writeProblem(w, 400, controlv1.InvalidRequest, "invalid connector peer pair cursor")
			return
		}
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	store, ok := h.dependencies.ConnectorPeerPairs, h.dependencies.ConnectorPeerPairs != nil
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "connector peer pair discovery is unavailable")
		return
	}
	page, err := store.ListConnectorPeerPairs(r.Context(), serviceID, runID, after, token, time.Now())
	if err != nil {
		serviceRunProblem(r.Context(), w, "list connector peer pairs", err)
		return
	}
	result := controlv1.ConnectorPeerPairCandidates{Items: make([]controlv1.ConnectorPeerPairCandidate, 0, len(page.Items))}
	for _, item := range page.Items {
		candidate := controlv1.ConnectorPeerPairCandidate{PairId: item.PairID, DeliveryGeneration: item.DeliveryGeneration}
		if item.OwnerAuthority != nil {
			candidate.OwnerAuthority = &controlv1.ConnectorPeerPairOwnerAuthority{ObservedAt: item.OwnerAuthority.ObservedAt, ExpiresAt: item.OwnerAuthority.ExpiresAt}
		}
		result.Items = append(result.Items, candidate)
	}
	if page.NextAfter != "" {
		result.NextAfter = &page.NextAfter
	}
	writeJSON(w, 200, result)
}

func (h *handler) ConfirmConnectorPeerPairPrepared(w http.ResponseWriter, r *http.Request, serviceID controlv1.ServiceID, runID controlv1.ServiceRunID, pairID string) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.ConnectorPeerPairPrepared
	if decodeJSONLimited(w, r, &body, 4096) != nil || !body.Phase.Valid() || body.DeliveryGeneration < 1 || body.BindingExpiresAt.IsZero() {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid connector peer preparation report")
		return
	}
	id, err := tunnelv1.ParsePeerDeliveryIdentifier(body.DeliveryId)
	if err != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid connector peer preparation report")
		return
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	store, ok := h.dependencies.ConnectorPeerPairs, h.dependencies.ConnectorPeerPairs != nil
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "connector peer preparation reports are unavailable")
		return
	}
	prepared := controlstate.ConnectorPeerPairPrepared{DeliveryID: id, DeliveryGeneration: body.DeliveryGeneration, BindingExpiresAt: body.BindingExpiresAt,
		Phase: string(body.Phase), OperationID: body.OperationId, BindingChallenge: body.BindingChallenge}
	if len(body.PathProofs) > 2 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid connector peer path proofs")
		return
	}
	for _, proof := range body.PathProofs {
		prepared.PathProofs = append(prepared.PathProofs, tunnelv1.ConnectorPeerPairPathProof{ConnectionSlot: proof.ConnectionSlot, ProbeNonce: proof.ProbeNonce, ReplyFrame: proof.ReplyFrame})
	}
	err = store.ConfirmConnectorPeerPairPrepared(r.Context(), serviceID, runID, pairID, token, prepared, time.Now())
	if err != nil {
		serviceRunProblem(r.Context(), w, "confirm connector peer preparation", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) DeliverConnectorPeerPair(w http.ResponseWriter, r *http.Request, serviceID controlv1.ServiceID, runID controlv1.ServiceRunID, pairID string) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.DeliverConnectorPeerPairJSONRequestBody
	if decodeJSONLimited(w, r, &body, 1024) != nil || body.DeliveryGeneration < 1 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid connector peer pair delivery request")
		return
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	store, ok := h.dependencies.ConnectorPeerPairs, h.dependencies.ConnectorPeerPairs != nil
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "connector peer pair delivery is unavailable")
		return
	}
	delivery, err := store.DeliverConnectorPeerPair(r.Context(), serviceID, runID, pairID, body.DeliveryGeneration, token, time.Now())
	if err != nil {
		// an absent claim, changed source, or revoked parent never discloses key material.
		serviceRunProblem(r.Context(), w, "deliver connector peer pair", err)
		return
	}
	writeJSON(w, 200, controlv1.ConnectorPeerPairDelivery{
		PairId: delivery.PairID, ServiceId: delivery.ServiceID, ServiceRunId: delivery.ServiceRunID,
		RunNumber: delivery.RunNumber, PublisherIdentityId: delivery.PublisherIdentityID,
		Subject: visitorsubject.Wire(delivery.Subject), DeliveryGeneration: delivery.DeliveryGeneration,
		DeliveryId: base64.RawURLEncoding.EncodeToString(delivery.DeliveryID[:]), Key: delivery.Key,
		SourceIp: delivery.SourceIP.String(), Relays: connectorPairRelays(delivery.Relays), ObservedAt: delivery.ObservedAt, ExpiresAt: delivery.ExpiresAt,
		SessionKey: delivery.SessionKey, TrustRevision: delivery.TrustRevision, OperationId: delivery.OperationID, BindingChallenge: delivery.BindingChallenge, BindingState: controlv1.ConnectorPeerPairBindingState(delivery.BindingState),
	})
}
