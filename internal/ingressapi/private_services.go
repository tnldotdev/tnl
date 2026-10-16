package ingressapi

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

type privateServiceStore interface {
	ClaimPrivateConnectorSession(context.Context, controlstate.IngressLeaseIdentity, string, string, string, netip.Addr, time.Time) (controlstate.PrivateConnectorSession, error)
	ClaimPrivateServiceTicket(context.Context, controlstate.IngressLeaseIdentity, string, string, string, string, string, int64, netip.Addr, time.Time) (controlstate.PrivateServiceTicket, error)
	ReadPrivateServiceSnapshot(context.Context, controlstate.IngressLeaseIdentity, time.Time) (controlstate.PrivateServiceRoutingSnapshot, error)
	ReadPrivateServiceEvents(context.Context, controlstate.IngressLeaseIdentity, int64, time.Time) (controlstate.PrivateServiceRoutingSnapshot, error)
	RecheckPrivateServiceVisitor(context.Context, controlstate.IngressLeaseIdentity, string, string, string, string, string, int64, netip.Addr, time.Time) (controlstate.PrivateVisitorValidity, error)
}

func (h *handler) recheckPrivateServiceVisitor(w http.ResponseWriter, r *http.Request, ingressID string) {
	var body ingressv1.PrivateServiceVisitorRecheck
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	lease, ok := ingressLeaseIdentity(ingressID, body.IngressRunId, body.IngressLeaseRevision)
	source, sourceOK := privateSource(body.ObservedSourceIp)
	if !ok || !sourceOK || body.RunNumber < 1 || body.VisitorConnectionId == "" ||
		body.PrivateServiceId == "" || body.PrivateRunId == "" || body.ConnectorSessionId == "" || body.IdentityId == "" {
		serviceapi.WriteProblem(w, http.StatusBadRequest, "invalid_request", "Private visitor recheck identity is invalid")
		return
	}
	store, ok := h.privateStore(w)
	if !ok {
		return
	}
	now := h.service.now()
	validity, err := store.RecheckPrivateServiceVisitor(r.Context(), lease, body.PrivateServiceId,
		body.PrivateRunId, body.ConnectorSessionId, body.IdentityId, body.VisitorConnectionId,
		body.RunNumber, source, now)
	if errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		validity, err = controlstate.PrivateVisitorValidity{ValidUntil: now}, nil
	}
	if h.writeServiceError(w, r, err) {
		return
	}
	next := now
	if validity.Allowed {
		next = now.Add(30 * time.Second)
		if before := validity.ValidUntil.Add(-5 * time.Second); before.Before(next) {
			next = before
		}
		if !next.After(now) {
			next = now.Add(time.Millisecond)
			if validity.ValidUntil.Before(next) {
				next = validity.ValidUntil
			}
		}
	}
	serviceapi.WriteJSON(w, http.StatusOK, ingressv1.PrivateServiceVisitorRecheckResult{
		Allowed: validity.Allowed, RecheckAt: next, ValidUntil: validity.ValidUntil,
	})
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
	session, err := store.ClaimPrivateConnectorSession(r.Context(), lease, body.PrivateServiceId, body.ConnectorSessionId, body.SessionCredential, source, h.service.now())
	if errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		serviceapi.WriteProblem(w, 403, "forbidden", "Private connector session is not current")
		return
	}
	if h.writeServiceError(w, r, err) {
		return
	}
	serviceapi.WriteJSON(w, 200, ingressv1.PrivateConnectorSessionResult{
		ConnectorSessionId: session.ID, PrivateServiceId: session.PrivateServiceID, IdentityId: session.IdentityID,
		ObservedSourceIp: session.SourceIP.String(), ExpiresAt: session.ExpiresAt,
	})
}

func (h *handler) claimPrivateServiceTicket(w http.ResponseWriter, r *http.Request, ingressID string) {
	var body ingressv1.PrivateServiceTicketClaim
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	lease, ok := ingressLeaseIdentity(ingressID, body.IngressRunId, body.IngressLeaseRevision)
	source, sourceOK := privateSource(body.ObservedSourceIp)
	if !ok || !sourceOK || body.PrivateServiceId == "" || body.ConnectorSessionId == "" || body.PrivateRunId == "" || body.Ticket == "" || body.VisitorConnectionId == "" || body.RunNumber <= 0 {
		serviceapi.WriteProblem(w, 400, "invalid_request", "Private service ticket claim is invalid")
		return
	}
	store, ok := h.privateStore(w)
	if !ok {
		return
	}
	claimed, err := store.ClaimPrivateServiceTicket(r.Context(), lease, body.PrivateServiceId, body.PrivateRunId,
		body.ConnectorSessionId, body.Ticket, body.VisitorConnectionId, body.RunNumber, source, h.service.now())
	if errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		serviceapi.WriteProblem(w, 403, "forbidden", "Private service ticket is not current")
		return
	}
	if h.writeServiceError(w, r, err) {
		return
	}
	serviceapi.WriteJSON(w, 200, ingressv1.PrivateServiceTicketResult{
		PrivateServiceId: claimed.PrivateServiceID, PrivateRunId: claimed.PrivateRunID,
		ConnectorSessionId: claimed.ConnectorSessionID, IdentityId: claimed.IdentityID,
		RunNumber: claimed.RunNumber, ObservedSourceIp: claimed.SourceIP.String(),
		ExpiresAt: claimed.ExpiresAt, VisitorConnectionId: body.VisitorConnectionId,
		ValidUntil: claimed.ValidUntil,
	})
}

func privateSnapshot(snapshot controlstate.PrivateServiceRoutingSnapshot) ingressv1.PrivateServiceSnapshot {
	result := ingressv1.PrivateServiceSnapshot{Revision: snapshot.Revision, Entries: make([]ingressv1.PrivateServiceProjection, 0, len(snapshot.Entries))}
	for _, row := range snapshot.Entries {
		entry := ingressv1.PrivateServiceProjection{PrivateServiceId: row.PrivateServiceID, Revision: row.Revision,
			Kind: ingressv1.PrivateServiceProjectionKind(row.Kind), ExpiresAt: row.ExpiresAt}
		if row.Kind == "upsert" {
			entry.PrivateRunId, entry.RunNumber = &row.PrivateRunID, &row.RunNumber
			relays := make([]ingressv1.PrivateServiceRelay, 0, len(row.ConnectedRelays))
			for _, relay := range row.ConnectedRelays {
				relays = append(relays, ingressv1.PrivateServiceRelay{PublisherConnectionId: relay.PublisherConnectionID,
					ConnectionSlot: int(relay.ConnectionSlot),
					RelayServiceId: relay.RelayServiceID,
					RelayId:        relay.RelayID, RelayRunId: relay.RelayRunID, RelayLeaseRevision: relay.RelayLeaseRevision,
					ConnectionAssignmentRevision: relay.ConnectionAssignmentRevision, InternalRelayAddress: relay.InternalRelayAddress,
					LeaseExpiresAt: relay.LeaseExpiresAt})
			}
			entry.ConnectedRelays = &relays
		}
		result.Entries = append(result.Entries, entry)
	}
	return result
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
