package ingress

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
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type serviceStore interface {
	AuthenticateVisitorConnector(context.Context, controlstate.IngressLeaseIdentity, tunnelv1.VisitorConnectorClaim, netip.Addr, time.Time) (controlstate.ConnectorSession, error)
	AuthorizeServiceStream(context.Context, controlstate.IngressLeaseIdentity, string, string, string, string, int64, netip.Addr, time.Time) (controlstate.ServiceStreamAuthorization, error)
	CloseServiceStream(context.Context, controlstate.IngressLeaseIdentity, string, string, time.Time) error
	ReadServiceSnapshot(context.Context, controlstate.IngressLeaseIdentity, time.Time) (controlstate.ServiceRoutingSnapshot, error)
	ReadServiceEvents(context.Context, controlstate.IngressLeaseIdentity, int64, time.Time) (controlstate.ServiceRoutingSnapshot, error)
	RecheckVisitorServiceStream(context.Context, controlstate.IngressLeaseIdentity, string, string, string, string, controlstate.VisitorSubject, int64, netip.Addr, time.Time) (controlstate.ServiceVisitorValidity, error)
}

func (h *handler) closeServiceStream(w http.ResponseWriter, r *http.Request, ingressID, visitorID string) {
	var body ingressv1.CloseServiceStreamJSONBody
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
	if h.writeServiceError(w, r, store.CloseServiceStream(r.Context(), lease, body.ConnectorSessionId, visitorID, h.service.now())) {
		return
	}
	w.WriteHeader(204)
}

func (h *handler) recheckServiceVisitor(w http.ResponseWriter, r *http.Request, ingressID string) {
	var body ingressv1.ServiceVisitorRecheck
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	lease, ok := ingressLeaseIdentity(ingressID, body.IngressRunId, body.IngressLeaseRevision)
	source, sourceOK := privateSource(body.ObservedSourceIp)
	subject, subjectErr := visitorsubject.Parse(body.Subject)
	if !ok || !sourceOK || body.RunNumber < 1 || body.VisitorConnectionId == "" ||
		body.ServiceId == "" || body.ServiceRunId == "" || body.ConnectorSessionId == "" || subjectErr != nil {
		serviceapi.WriteProblem(w, http.StatusBadRequest, "invalid_request", "Private visitor recheck identity is invalid")
		return
	}
	store, ok := h.privateStore(w)
	if !ok {
		return
	}
	now := h.service.now()
	validity, err := store.RecheckVisitorServiceStream(r.Context(), lease, body.ServiceId,
		body.ServiceRunId, body.ConnectorSessionId, body.VisitorConnectionId, subject,
		body.RunNumber, source, now)
	if errors.Is(err, controlstate.ErrServiceAccess) {
		validity, err = controlstate.ServiceVisitorValidity{ValidUntil: now}, nil
	}
	if h.writeServiceError(w, r, err) {
		return
	}
	observability.AuthorizationDecision(r.Context(), "connector_visitor_recheck", validity.Allowed)
	serviceapi.WriteJSON(w, http.StatusOK, privateVisitorRecheckResult(validity, now))
}

func (h *handler) privateStore(response http.ResponseWriter) (serviceStore, bool) {
	store, ok := h.service.store.(serviceStore)
	if !ok {
		serviceapi.WriteProblem(response, http.StatusServiceUnavailable, "unavailable", "service state is unavailable")
	}
	return store, ok
}

func privateSource(source string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(source)
	return ip, err == nil && ip.IsValid() && ip.Zone() == "" && ip.String() == source
}

func (h *handler) claimConnectorSession(w http.ResponseWriter, r *http.Request, ingressID string) {
	var body ingressv1.ConnectorSessionClaim
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	lease, ok := ingressLeaseIdentity(ingressID, body.IngressRunId, body.IngressLeaseRevision)
	source, sourceOK := privateSource(body.ObservedSourceIp)
	if !ok || !sourceOK || body.ConnectorSessionId == "" || body.ServiceId == "" || body.SessionCredential == "" {
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
		ServiceID: body.ServiceId, SessionID: body.ConnectorSessionId,
		Credential: body.SessionCredential, Subject: subject, Nonce: nonce, Signature: sig}, source, h.service.now())
	if errors.Is(err, controlstate.ErrServiceAccess) {
		serviceapi.WriteProblem(w, 403, "forbidden", "Private connector session is not current")
		return
	}
	if h.writeServiceError(w, r, err) {
		return
	}
	serviceapi.WriteJSON(w, 200, ingressv1.ConnectorSessionResult{
		ConnectorSessionId: session.ID, ServiceId: session.ServiceID, Subject: visitorsubject.Wire(session.Subject),
		ObservedSourceIp: session.SourceIP.String(), ExpiresAt: session.ExpiresAt,
	})
}

func (h *handler) authorizeServiceStream(w http.ResponseWriter, r *http.Request, ingressID string) {
	var body ingressv1.ServiceStreamClaim
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	lease, ok := ingressLeaseIdentity(ingressID, body.IngressRunId, body.IngressLeaseRevision)
	source, sourceOK := privateSource(body.ObservedSourceIp)
	if !ok || !sourceOK || body.ServiceId == "" || body.ConnectorSessionId == "" || body.ServiceRunId == "" || body.VisitorConnectionId == "" || body.RunNumber <= 0 {
		serviceapi.WriteProblem(w, 400, "invalid_request", "service stream claim is invalid")
		return
	}
	store, ok := h.privateStore(w)
	if !ok {
		return
	}
	claimed, err := store.AuthorizeServiceStream(r.Context(), lease, body.ServiceId, body.ServiceRunId,
		body.ConnectorSessionId, body.VisitorConnectionId, body.RunNumber, source, h.service.now())
	if errors.Is(err, controlstate.ErrServiceAccess) {
		serviceapi.WriteProblem(w, 403, "forbidden", "service stream is not authorized")
		return
	}
	if h.writeServiceError(w, r, err) {
		return
	}
	serviceapi.WriteJSON(w, 200, ingressv1.ServiceStreamResult{
		ServiceId: claimed.ServiceID, ServiceRunId: claimed.ServiceRunID,
		ConnectorSessionId: claimed.ConnectorSessionID, Subject: visitorsubject.Wire(claimed.Subject),
		RunNumber: claimed.RunNumber, ObservedSourceIp: claimed.SourceIP.String(),
		ExpiresAt: claimed.ExpiresAt, VisitorConnectionId: body.VisitorConnectionId,
		ValidUntil:    claimed.ValidUntil,
		GrantRevision: claimed.GrantRevision,
	})
}

func privateSnapshot(snapshot controlstate.ServiceRoutingSnapshot) ingressv1.ServiceSnapshot {
	result := ingressv1.ServiceSnapshot{Revision: snapshot.Revision, Entries: make([]ingressv1.ServiceProjection, 0, len(snapshot.Entries))}
	for _, row := range snapshot.Entries {
		entry := ingressv1.ServiceProjection{ServiceId: row.ServiceID, Revision: row.Revision,
			Kind: ingressv1.ServiceProjectionKind(row.Kind), ExpiresAt: row.ExpiresAt}
		if row.ServiceRunID != "" {
			entry.ServiceRunId, entry.RunNumber = &row.ServiceRunID, &row.RunNumber
		}
		if row.Kind == "upsert" {
			entry.ServiceRunId, entry.RunNumber = &row.ServiceRunID, &row.RunNumber
			relays := privateRelayResponses(row.ConnectedRelays)
			entry.ConnectedRelays = &relays
		}
		result.Entries = append(result.Entries, entry)
	}
	return result
}

func privateRelayResponses(rows []controlstate.ServiceRelay) []ingressv1.ServiceRelay {
	relays := make([]ingressv1.ServiceRelay, 0, len(rows))
	for _, relay := range rows {
		relays = append(relays, ingressv1.ServiceRelay{PublisherConnectionId: relay.PublisherConnectionID,
			TlsServerName: relay.TLSServerName, ConnectionSlot: int(relay.ConnectionSlot), RelayServiceId: relay.RelayServiceID,
			RelayId: relay.RelayID, RelayRunId: relay.RelayRunID, RelayLeaseRevision: relay.RelayLeaseRevision,
			ConnectionAssignmentRevision: relay.ConnectionAssignmentRevision, InternalRelayAddress: relay.InternalRelayAddress,
			LeaseExpiresAt: relay.LeaseExpiresAt})
	}
	return relays
}

func (h *handler) serviceSnapshot(w http.ResponseWriter, r *http.Request, id string, params ingressv1.GetServiceSnapshotParams) {
	lease, ok := ingressLeaseIdentity(id, params.IngressRunId, params.IngressLeaseRevision)
	if !ok {
		serviceapi.WriteProblem(w, 400, "invalid_request", "Ingress lease identity is invalid")
		return
	}
	store, ok := h.privateStore(w)
	if !ok {
		return
	}
	snapshot, err := store.ReadServiceSnapshot(r.Context(), lease, h.service.now())
	if h.writeServiceError(w, r, err) {
		return
	}
	serviceapi.WriteJSON(w, 200, privateSnapshot(snapshot))
}

func (h *handler) serviceEvents(w http.ResponseWriter, r *http.Request, id string, params ingressv1.GetServiceEventsParams) {
	lease, ok := ingressLeaseIdentity(id, params.IngressRunId, params.IngressLeaseRevision)
	if !ok || params.After < 0 {
		serviceapi.WriteProblem(w, 400, "invalid_request", "Ingress lease or revision is invalid")
		return
	}
	store, ok := h.privateStore(w)
	if !ok {
		return
	}
	events, err := store.ReadServiceEvents(r.Context(), lease, params.After, h.service.now())
	if h.writeServiceError(w, r, err) {
		return
	}
	serviceapi.WriteJSON(w, 200, privateSnapshot(events))
}
