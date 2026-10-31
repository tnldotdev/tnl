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

type nativePeerPairStore interface {
	PrepareNativePeerPair(context.Context, controlstate.NativePeerPairRequest, time.Time) (controlstate.NativePeerPair, error)
	RenewNativePeerPair(context.Context, controlstate.NativePeerPairRequest, time.Time) (controlstate.NativePeerPair, error)
}

func nativePairRelays(relays [2]controlstate.NativePeerPairRelay) []controlv1.NativePeerPairRelay {
	result := make([]controlv1.NativePeerPairRelay, 2)
	for i, relay := range relays {
		result[i] = controlv1.NativePeerPairRelay{PublisherConnectionId: relay.PublisherConnectionID, AssignmentRevision: relay.AssignmentRevision,
			RelayLease: controlv1.NativePeerRelayLease{RelayServiceId: relay.RelayLease.RelayServiceID, RelayId: relay.RelayLease.RelayID,
				RelayRunId: relay.RelayLease.RelayRunID, RelayLeaseRevision: int64(relay.RelayLease.RelayLeaseRevision)},
			RelayAddress: relay.RelayAddress, TlsServerName: relay.TLSServerName}
	}
	return result
}

func nativePairResponse(pair controlstate.NativePeerPair) controlv1.NativePeerPair {
	result := controlv1.NativePeerPair{PairId: pair.ID, ServiceId: pair.ServiceID, ServiceRunId: pair.ServiceRunID, RunNumber: pair.RunNumber,
		PublisherIdentityId: pair.PublisherIdentityID, Subject: visitorsubject.Wire(pair.Subject), DeliveryId: base64.RawURLEncoding.EncodeToString(pair.DeliveryID[:]), DeliveryGeneration: pair.DeliveryGeneration,
		Key: pair.Key, Relays: nativePairRelays(pair.Relays), ObservedAt: pair.ObservedAt, ExpiresAt: pair.ExpiresAt}
	if !pair.PublisherPreparedUntil.IsZero() {
		result.PublisherPreparedUntil = &pair.PublisherPreparedUntil
	}
	return result
}

func nativePairInput(serviceID string, body controlv1.NativePeerPairRequest) (controlstate.NativePeerPairRequest, error) {
	proof, err := controlv1.NativePeerPairProof(serviceID, body)
	if err != nil {
		return controlstate.NativePeerPairRequest{}, controlstate.ErrServiceAccess
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return controlstate.NativePeerPairRequest{}, controlstate.ErrServiceAccess
	}
	result := controlstate.NativePeerPairRequest{ServiceID: proof.ServiceID, ServiceRunID: proof.ServiceRunID, RunNumber: proof.RunNumber,
		PublisherIdentityID: proof.PublisherIdentityID, Subject: proof.Subject, Action: proof.Action, IdempotencyKey: proof.IdempotencyKey,
		RequestedAt: proof.RequestedAt, PreviousPairID: proof.PreviousPairID, PreviousGeneration: proof.PreviousGeneration, Signature: signature}
	for i, relay := range proof.ExpectedRelays {
		result.ExpectedRelays[i] = controlstate.NativePeerPairRelay{PublisherConnectionID: relay.PublisherConnectionID,
			AssignmentRevision: relay.AssignmentRevision, RelayAddress: relay.RelayAddress, TLSServerName: relay.TLSServerName,
			RelayLease: controlstate.RelayLeaseIdentity{RelayServiceID: relay.RelayLease.RelayServiceID, RelayID: relay.RelayLease.RelayID,
				RelayRunID: relay.RelayLease.RelayRunID, RelayLeaseRevision: relay.RelayLease.RelayLeaseRevision}}
	}
	return result, nil
}

func (h *handler) nativePairSource(w http.ResponseWriter, r *http.Request, body controlv1.NativePeerPairRequest, request *controlstate.NativePeerPairRequest) (context.Context, bool) {
	source, human, err := parseVisitorTokenSource(body.Source)
	if err != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid native peer pair source")
		return nil, false
	}
	if human {
		device, ok := source.(controlstate.DeviceTokenSource)
		if !ok || request.Subject.Kind != tunnelv1.VisitorHumanDevice || request.Subject.DeviceID != device.DeviceID {
			writeProblem(w, 403, controlv1.Forbidden, "native peer pair source does not match the device")
			return nil, false
		}
		principal, ok := h.authorizeReads(w, r)
		if !ok {
			return nil, false
		}
		if principal.controlPrincipal.SessionID == "" || principal.identityID != request.Subject.IdentityID {
			writeProblem(w, 403, controlv1.Forbidden, "native peer pair source does not match the session")
			return nil, false
		}
		request.Source = device
		return r.Context(), true
	}
	workload, ok := source.(controlstate.WorkloadTokenSource)
	if !ok || request.Subject.Kind != tunnelv1.VisitorWorkloadSession || len(r.Header.Values("Authorization")) != 0 {
		writeProblem(w, 403, controlv1.Forbidden, "select one native peer pair source")
		return nil, false
	}
	request.Source = workload
	return r.Context(), true
}

func nativePairProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, controlstate.ErrServiceConflict):
		writeProblem(w, 409, controlv1.Conflict, "native peer pair conflicts with the current delivery; select the run again")
	case errors.Is(err, controlstate.ErrServiceAccess), errors.Is(err, controlstate.ErrVisitorPermission), errors.Is(err, controlstate.ErrWorkloadDenied):
		writeProblem(w, 403, controlv1.Forbidden, "native peer pair source or run is no longer authorized")
	default:
		writeControlStateProblem(w, "authorize native peer pair", err)
	}
}

func (h *handler) nativePair(w http.ResponseWriter, r *http.Request, serviceID, pairID string) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.NativePeerPairRequest
	if decodeJSONLimited(w, r, &body, 8192) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid native peer pair request")
		return
	}
	request, err := nativePairInput(serviceID, body)
	if err != nil || pairID == "" && request.Action != "create" && request.Action != "replace" || pairID != "" && (request.Action != "renew" || pairID != request.PreviousPairID) {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid native peer pair request")
		return
	}
	ctx, ok := h.nativePairSource(w, r, body, &request)
	if !ok {
		return
	}
	store, ok := h.store.(nativePeerPairStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "native peer pairs are unavailable")
		return
	}
	var result controlstate.NativePeerPair
	if pairID == "" {
		result, err = store.PrepareNativePeerPair(ctx, request, time.Now())
	} else {
		result, err = store.RenewNativePeerPair(ctx, request, time.Now())
	}
	if err != nil {
		nativePairProblem(w, err)
		return
	}
	writeJSON(w, 200, nativePairResponse(result))
}

func (h *handler) PrepareNativePeerPair(w http.ResponseWriter, r *http.Request, serviceID controlv1.ServiceID) {
	h.nativePair(w, r, serviceID, "")
}

func (h *handler) RenewNativePeerPair(w http.ResponseWriter, r *http.Request, serviceID controlv1.ServiceID, pairID string) {
	h.nativePair(w, r, serviceID, pairID)
}

func (h *handler) ListNativePeerPairs(w http.ResponseWriter, r *http.Request, serviceID controlv1.ServiceID, runID controlv1.ServiceRunID, params controlv1.ListNativePeerPairsParams) {
	w.Header().Set("Cache-Control", "no-store")
	after := ""
	if params.After != nil {
		after = *params.After
		if !opaqueid.Valid(after, "npp_") {
			writeProblem(w, 400, controlv1.InvalidRequest, "invalid native peer pair cursor")
			return
		}
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	store, ok := h.store.(interface {
		ListNativePeerPairs(context.Context, string, string, string, string, time.Time) (controlstate.NativePeerPairCandidates, error)
	})
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "native peer pair discovery is unavailable")
		return
	}
	page, err := store.ListNativePeerPairs(r.Context(), serviceID, runID, after, token, time.Now())
	if err != nil {
		serviceRunProblem(w, "list native peer pairs", err)
		return
	}
	result := controlv1.NativePeerPairCandidates{Items: make([]controlv1.NativePeerPairCandidate, 0, len(page.Items))}
	for _, item := range page.Items {
		result.Items = append(result.Items, controlv1.NativePeerPairCandidate{PairId: item.PairID, DeliveryGeneration: item.DeliveryGeneration})
	}
	if page.NextAfter != "" {
		result.NextAfter = &page.NextAfter
	}
	writeJSON(w, 200, result)
}

func (h *handler) ConfirmNativePeerPairPrepared(w http.ResponseWriter, r *http.Request, serviceID controlv1.ServiceID, runID controlv1.ServiceRunID, pairID string) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.NativePeerPairPrepared
	if decodeJSONLimited(w, r, &body, 1024) != nil || body.DeliveryGeneration < 1 || body.BindingExpiresAt.IsZero() {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid native peer preparation report")
		return
	}
	id, err := tunnelv1.ParsePeerDeliveryIdentifier(body.DeliveryId)
	if err != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid native peer preparation report")
		return
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	store, ok := h.store.(interface {
		ConfirmNativePeerPairPrepared(context.Context, string, string, string, string, controlstate.NativePeerPairPrepared, time.Time) error
	})
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "native peer preparation reports are unavailable")
		return
	}
	err = store.ConfirmNativePeerPairPrepared(r.Context(), serviceID, runID, pairID, token, controlstate.NativePeerPairPrepared{
		DeliveryID: id, DeliveryGeneration: body.DeliveryGeneration, BindingExpiresAt: body.BindingExpiresAt}, time.Now())
	if err != nil {
		serviceRunProblem(w, "confirm native peer preparation", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) DeliverNativePeerPair(w http.ResponseWriter, r *http.Request, serviceID controlv1.ServiceID, runID controlv1.ServiceRunID, pairID string) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.DeliverNativePeerPairJSONRequestBody
	if decodeJSONLimited(w, r, &body, 1024) != nil || body.DeliveryGeneration < 1 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid native peer pair delivery request")
		return
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	store, ok := h.store.(interface {
		DeliverNativePeerPair(context.Context, string, string, string, int64, string, time.Time) (controlstate.NativePeerPairDelivery, error)
	})
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "native peer pair delivery is unavailable")
		return
	}
	delivery, err := store.DeliverNativePeerPair(r.Context(), serviceID, runID, pairID, body.DeliveryGeneration, token, time.Now())
	if err != nil {
		// an absent claim, changed source, or revoked parent never discloses key material.
		serviceRunProblem(w, "deliver native peer pair", err)
		return
	}
	writeJSON(w, 200, controlv1.NativePeerPairDelivery{
		PairId: delivery.PairID, ServiceId: delivery.ServiceID, ServiceRunId: delivery.ServiceRunID,
		RunNumber: delivery.RunNumber, PublisherIdentityId: delivery.PublisherIdentityID,
		Subject: visitorsubject.Wire(delivery.Subject), DeliveryGeneration: delivery.DeliveryGeneration,
		DeliveryId: base64.RawURLEncoding.EncodeToString(delivery.DeliveryID[:]), Key: delivery.Key,
		SourceIp: delivery.SourceIP.String(), Relays: nativePairRelays(delivery.Relays), ObservedAt: delivery.ObservedAt, ExpiresAt: delivery.ExpiresAt,
	})
}
