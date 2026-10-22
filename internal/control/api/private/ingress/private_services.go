package ingressapi

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type privateServiceStore interface {
	AuthenticateVisitorConnector(context.Context, controlstate.IngressLeaseIdentity, tunnelv1.VisitorConnectorClaim, netip.Addr, time.Time) (controlstate.PrivateConnectorSession, error)
	AuthorizePrivateServiceStream(context.Context, controlstate.IngressLeaseIdentity, string, string, string, string, int64, netip.Addr, time.Time) (controlstate.PrivateStreamAuthorization, error)
	ClosePrivateServiceStream(context.Context, controlstate.IngressLeaseIdentity, string, string, time.Time) error
	ReadPrivateServiceSnapshot(context.Context, controlstate.IngressLeaseIdentity, time.Time) (controlstate.PrivateServiceRoutingSnapshot, error)
	ReadPrivateServiceEvents(context.Context, controlstate.IngressLeaseIdentity, int64, time.Time) (controlstate.PrivateServiceRoutingSnapshot, error)
	RecheckVisitorServiceStream(context.Context, controlstate.IngressLeaseIdentity, string, string, string, string, controlstate.VisitorSubject, int64, netip.Addr, time.Time) (controlstate.PrivateVisitorValidity, error)
}

func (h *handler) closePrivateServiceStream(w http.ResponseWriter, r *http.Request, ingressID, visitorID string) {
	var body ingressv1.ClosePrivateServiceStreamJSONBody
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	lease, ok := ingressLeaseIdentity(ingressID, body.IngressRunId, body.IngressLeaseRevision)
	if !ok {
		serviceapi.WriteProblem(w, 400, "invalid_request", "invalid ingress lease")
		return
	}
	store, ok := h.privateStore(w)
	if !ok {
		return
	}
	if h.writeServiceError(w, r, store.ClosePrivateServiceStream(r.Context(), lease, body.ConnectorSessionId, visitorID, h.service.now())) {
		return
	}
	w.WriteHeader(204)
}

func (h *handler) recheckPrivateServiceVisitor(w http.ResponseWriter, r *http.Request, ingressID string) {
	var body ingressv1.PrivateServiceVisitorRecheck
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	lease, ok := ingressLeaseIdentity(ingressID, body.IngressRunId, body.IngressLeaseRevision)
	source, sourceOK := privateSource(body.ObservedSourceIp)
	subject, subjectErr := visitorsubject.Parse(body.Subject)
	if !ok || !sourceOK || body.RunNumber < 1 || body.VisitorConnectionId == "" ||
		body.PrivateServiceId == "" || body.PrivateRunId == "" || body.ConnectorSessionId == "" || subjectErr != nil {
		serviceapi.WriteProblem(w, http.StatusBadRequest, "invalid_request", "Private visitor recheck identity is invalid")
		return
	}
	store, ok := h.privateStore(w)
	if !ok {
		return
	}
	now := h.service.now()
	validity, err := store.RecheckVisitorServiceStream(r.Context(), lease, body.PrivateServiceId,
		body.PrivateRunId, body.ConnectorSessionId, body.VisitorConnectionId, subject,
		body.RunNumber, source, now)
	if errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		validity, err = controlstate.PrivateVisitorValidity{ValidUntil: now}, nil
	}
	if h.writeServiceError(w, r, err) {
		return
	}
	observability.AuthorizationDecision(r.Context(), "private_visitor_recheck", validity.Allowed)
	serviceapi.WriteJSON(w, http.StatusOK, privateVisitorRecheckResult(validity, now))
}

func (h *handler) privateStore(response http.ResponseWriter) (privateServiceStore, bool) {
	store, ok := h.service.store.(privateServiceStore)
	if !ok {
		serviceapi.WriteProblem(response, http.StatusServiceUnavailable, "unavailable", "Private service state is unavailable")
	}
	return store, ok
}

func privateSource(source string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(source)
	return ip, err == nil && ip.IsValid() && ip.Zone() == "" && ip.String() == source
}

func (h *handler) claimPrivateConnectorSession(w http.ResponseWriter, r *http.Request, ingressID string) {
	var body ingressv1.PrivateConnectorSessionClaim
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	lease, ok := ingressLeaseIdentity(ingressID, body.IngressRunId, body.IngressLeaseRevision)
	source, sourceOK := privateSource(body.ObservedSourceIp)
	if !ok || !sourceOK || body.ConnectorSessionId == "" || body.PrivateServiceId == "" || body.SessionCredential == "" {
		serviceapi.WriteProblem(w, 400, "invalid_request", "Private connector session claim is invalid")
		return
	}
	store, ok := h.privateStore(w)
	if !ok {
		return
	}
	nonce, nerr := hex.DecodeString(body.Nonce)
	sig, serr := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	subject, subjectErr := visitorsubject.Parse(body.Subject)
	if nerr != nil || serr != nil || subjectErr != nil {
		serviceapi.WriteProblem(w, 400, "invalid_request", "invalid visitor key proof")
		return
	}
	session, err := store.AuthenticateVisitorConnector(r.Context(), lease, tunnelv1.VisitorConnectorClaim{
		ServiceID: body.PrivateServiceId, SessionID: body.ConnectorSessionId,
		Credential: body.SessionCredential, Subject: subject, Nonce: nonce, Signature: sig}, source, h.service.now())
	if errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		serviceapi.WriteProblem(w, 403, "forbidden", "Private connector session is not current")
		return
	}
	if h.writeServiceError(w, r, err) {
		return
	}
	serviceapi.WriteJSON(w, 200, ingressv1.PrivateConnectorSessionResult{
		ConnectorSessionId: session.ID, PrivateServiceId: session.PrivateServiceID, Subject: visitorsubject.Wire(session.Subject),
		ObservedSourceIp: session.SourceIP.String(), ExpiresAt: session.ExpiresAt,
	})
}

func (h *handler) authorizePrivateServiceStream(w http.ResponseWriter, r *http.Request, ingressID string) {
	var body ingressv1.PrivateServiceStreamClaim
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	lease, ok := ingressLeaseIdentity(ingressID, body.IngressRunId, body.IngressLeaseRevision)
	source, sourceOK := privateSource(body.ObservedSourceIp)
	if !ok || !sourceOK || body.PrivateServiceId == "" || body.ConnectorSessionId == "" || body.PrivateRunId == "" || body.VisitorConnectionId == "" || body.RunNumber <= 0 {
		serviceapi.WriteProblem(w, 400, "invalid_request", "private service stream claim is invalid")
		return
	}
	store, ok := h.privateStore(w)
	if !ok {
		return
	}
	claimed, err := store.AuthorizePrivateServiceStream(r.Context(), lease, body.PrivateServiceId, body.PrivateRunId,
		body.ConnectorSessionId, body.VisitorConnectionId, body.RunNumber, source, h.service.now())
	if errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		serviceapi.WriteProblem(w, 403, "forbidden", "private service stream is not authorized")
		return
	}
	if h.writeServiceError(w, r, err) {
		return
	}
	serviceapi.WriteJSON(w, 200, ingressv1.PrivateServiceStreamResult{
		PrivateServiceId: claimed.PrivateServiceID, PrivateRunId: claimed.PrivateRunID,
		ConnectorSessionId: claimed.ConnectorSessionID, Subject: visitorsubject.Wire(claimed.Subject),
		RunNumber: claimed.RunNumber, ObservedSourceIp: claimed.SourceIP.String(),
		ExpiresAt: claimed.ExpiresAt, VisitorConnectionId: body.VisitorConnectionId,
		ValidUntil:    claimed.ValidUntil,
		GrantRevision: claimed.GrantRevision,
	})
}

func privateSnapshot(snapshot controlstate.PrivateServiceRoutingSnapshot) ingressv1.PrivateServiceSnapshot {
	result := ingressv1.PrivateServiceSnapshot{Revision: snapshot.Revision, Entries: make([]ingressv1.PrivateServiceProjection, 0, len(snapshot.Entries))}
	for _, row := range snapshot.Entries {
		entry := ingressv1.PrivateServiceProjection{PrivateServiceId: row.PrivateServiceID, Revision: row.Revision,
			Kind: ingressv1.PrivateServiceProjectionKind(row.Kind), ExpiresAt: row.ExpiresAt}
		if row.PrivateRunID != "" {
			entry.PrivateRunId, entry.RunNumber = &row.PrivateRunID, &row.RunNumber
		}
		if row.Kind == "upsert" {
			entry.PrivateRunId, entry.RunNumber = &row.PrivateRunID, &row.RunNumber
			relays := privateRelayResponses(row.ConnectedRelays)
			entry.ConnectedRelays = &relays
		}
		result.Entries = append(result.Entries, entry)
	}
	return result
}

func privateRelayResponses(rows []controlstate.PrivateServiceRelay) []ingressv1.PrivateServiceRelay {
	relays := make([]ingressv1.PrivateServiceRelay, 0, len(rows))
	for _, relay := range rows {
		relays = append(relays, ingressv1.PrivateServiceRelay{PublisherConnectionId: relay.PublisherConnectionID,
			TlsServerName: relay.TLSServerName, ConnectionSlot: int(relay.ConnectionSlot), RelayServiceId: relay.RelayServiceID,
			RelayId: relay.RelayID, RelayRunId: relay.RelayRunID, RelayLeaseRevision: relay.RelayLeaseRevision,
			ConnectionAssignmentRevision: relay.ConnectionAssignmentRevision, InternalRelayAddress: relay.InternalRelayAddress,
			LeaseExpiresAt: relay.LeaseExpiresAt})
	}
	return relays
}

func (h *handler) privateServiceSnapshot(w http.ResponseWriter, r *http.Request, id string, params ingressv1.GetPrivateServiceSnapshotParams) {
	lease, ok := ingressLeaseIdentity(id, params.IngressRunId, params.IngressLeaseRevision)
	if !ok {
		serviceapi.WriteProblem(w, 400, "invalid_request", "Ingress lease identity is invalid")
		return
	}
	store, ok := h.privateStore(w)
	if !ok {
		return
	}
	snapshot, err := store.ReadPrivateServiceSnapshot(r.Context(), lease, h.service.now())
	if h.writeServiceError(w, r, err) {
		return
	}
	serviceapi.WriteJSON(w, 200, privateSnapshot(snapshot))
}

func (h *handler) privateServiceEvents(w http.ResponseWriter, r *http.Request, id string, params ingressv1.GetPrivateServiceEventsParams) {
	lease, ok := ingressLeaseIdentity(id, params.IngressRunId, params.IngressLeaseRevision)
	if !ok || params.After < 0 {
		serviceapi.WriteProblem(w, 400, "invalid_request", "Ingress lease or revision is invalid")
		return
	}
	store, ok := h.privateStore(w)
	if !ok {
		return
	}
	events, err := store.ReadPrivateServiceEvents(r.Context(), lease, params.After, h.service.now())
	if h.writeServiceError(w, r, err) {
		return
	}
	serviceapi.WriteJSON(w, 200, privateSnapshot(events))
}
