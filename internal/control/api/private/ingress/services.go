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
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type serviceStore interface {
	AuthenticateVisitorConnector(context.Context, controlstate.IngressLeaseIdentity, tunnelv1.VisitorConnectorClaim, netip.Addr, time.Time) (controlstate.ConnectorSession, error)
	ReadServiceSnapshot(context.Context, controlstate.IngressLeaseIdentity, time.Time) (controlstate.ServiceRoutingSnapshot, error)
	ReadServiceEvents(context.Context, controlstate.IngressLeaseIdentity, int64, time.Time) (controlstate.ServiceRoutingSnapshot, error)
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
