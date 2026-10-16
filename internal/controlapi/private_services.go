package controlapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type privateVisitorStore interface {
	CreatePrivateService(context.Context, string, string, string, string, time.Time) (controlstate.PrivateServiceRecord, error)
	GetPrivateService(context.Context, string, string) (controlstate.PrivateServiceRecord, error)
	DeletePrivateService(context.Context, string, string, time.Time) error
	CreatePrivateServiceGrant(context.Context, string, string, string, string, string, *time.Time, time.Time) (controlstate.PrivateServiceGrant, error)
	ListPrivateServiceGrants(context.Context, string, string) ([]controlstate.PrivateServiceGrant, error)
	RevokePrivateServiceGrant(context.Context, string, string, string, time.Time) error
	InvitePrivateServiceVisitor(context.Context, string, string, string, string, time.Time, time.Time) (controlstate.PrivateServiceInvitation, error)
	ListPrivateServiceInvitations(context.Context, string, string) ([]controlstate.PrivateServiceInvitation, error)
	AcceptPrivateServiceInvitation(context.Context, string, string, time.Time) (controlstate.PrivateServiceGrant, error)
	RevokePrivateServiceInvitation(context.Context, string, string, string, time.Time) error
	ListPrivateServices(context.Context, string, string, string) ([]controlstate.PrivateServiceRecord, string, error)
	ListAvailablePrivateServices(context.Context, string, string, time.Time) ([]controlstate.PrivateServiceInventory, string, error)
	CreatePrivateConnectorSession(context.Context, string, string, time.Time) (controlstate.PrivateConnectorSession, error)
	IssuePrivateServiceTicket(context.Context, string, string, string, time.Time) (controlstate.PrivateServiceTicket, error)
}

func (h *handler) privateVisitor(w http.ResponseWriter, r *http.Request) (privateVisitorStore, string, bool) {
	principal, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return nil, "", false
	}
	store, ok := h.store.(privateVisitorStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "private services are unavailable")
		return nil, "", false
	}
	return store, principal.identityID, true
}

func privateVisitorError(w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrPrivateServiceAccess):
		writeProblem(w, 404, controlv1.NotFound, "private service not found or unavailable")
	case errors.Is(err, controlstate.ErrPrivateServiceConflict):
		writeProblem(w, 409, controlv1.Conflict, "private service conflicts with an existing name or request")
	default:
		writeControlStateProblem(w, operation, err)
	}
}

func privateRecord(record controlstate.PrivateServiceRecord) controlv1.PrivateService {
	return controlv1.PrivateService{Id: record.ID, TeamId: record.TeamID, Name: record.Name,
		Enabled: record.Enabled, CreatedAt: record.CreatedAt}
}

func (h *handler) CreatePrivateService(w http.ResponseWriter, r *http.Request, _ controlv1.CreatePrivateServiceParams) {
	var body controlv1.CreatePrivateServiceRequest
	if decodeJSON(w, r, &body) != nil || r.Header.Get("Idempotency-Key") == "" {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid private service request")
		return
	}
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	record, err := store.CreatePrivateService(r.Context(), body.TeamId, identity, body.Name, r.Header.Get("Idempotency-Key"), time.Now())
	if err != nil {
		privateVisitorError(w, "create private service", err)
		return
	}
	writeJSON(w, 201, privateRecord(record))
}

func (h *handler) ListPrivateServices(w http.ResponseWriter, r *http.Request, params controlv1.ListPrivateServicesParams) {
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	cursor := ""
	if params.Cursor != nil {
		cursor = *params.Cursor
	}
	rows, next, err := store.ListPrivateServices(r.Context(), params.TeamId, identity, cursor)
	if err != nil {
		privateVisitorError(w, "list private services", err)
		return
	}
	page := controlv1.PrivateServicePage{Services: make([]controlv1.PrivateService, 0, len(rows))}
	for _, row := range rows {
		page.Services = append(page.Services, privateRecord(row))
	}
	if next != "" {
		page.NextCursor = &next
	}
	writeJSON(w, 200, page)
}

func (h *handler) GetPrivateService(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID) {
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	record, err := store.GetPrivateService(r.Context(), id, identity)
	if err != nil {
		privateVisitorError(w, "get private service", err)
		return
	}
	writeJSON(w, 200, privateRecord(record))
}

func (h *handler) DeletePrivateService(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID) {
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	if err := store.DeletePrivateService(r.Context(), id, identity, time.Now()); err != nil {
		privateVisitorError(w, "delete private service", err)
		return
	}
	w.WriteHeader(204)
}

func privateGrant(grant controlstate.PrivateServiceGrant) controlv1.PrivateServiceGrant {
	result := controlv1.PrivateServiceGrant{Id: grant.ID, PrivateServiceId: grant.PrivateServiceID,
		Kind: controlv1.PrivateServiceGrantKind(grant.Kind), CreatedAt: grant.CreatedAt,
		ExpiresAt: grant.ExpiresAt, RevokedAt: grant.RevokedAt}
	if grant.IdentityID != "" {
		result.IdentityId = &grant.IdentityID
	}
	if grant.InvitationID != "" {
		result.InvitationId = &grant.InvitationID
	}
	return result
}

func (h *handler) CreatePrivateServiceGrant(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID, _ controlv1.CreatePrivateServiceGrantParams) {
	var body controlv1.CreatePrivateServiceGrantRequest
	if decodeJSON(w, r, &body) != nil || !body.Kind.Valid() || r.Header.Get("Idempotency-Key") == "" {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid private service grant")
		return
	}
	identityID := ""
	if body.IdentityId != nil {
		identityID = *body.IdentityId
	}
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	grant, err := store.CreatePrivateServiceGrant(r.Context(), id, identity, r.Header.Get("Idempotency-Key"), string(body.Kind), identityID, body.ExpiresAt, time.Now())
	if err != nil {
		privateVisitorError(w, "create private service grant", err)
		return
	}
	writeJSON(w, 201, privateGrant(grant))
}

func (h *handler) ListPrivateServiceGrants(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID) {
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	grants, err := store.ListPrivateServiceGrants(r.Context(), id, identity)
	if err != nil {
		privateVisitorError(w, "list private service grants", err)
		return
	}
	result := make([]controlv1.PrivateServiceGrant, 0, len(grants))
	for _, grant := range grants {
		result = append(result, privateGrant(grant))
	}
	writeJSON(w, 200, result)
}

func (h *handler) RevokePrivateServiceGrant(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID, grantID controlv1.PrivateServiceGrantID) {
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	if err := store.RevokePrivateServiceGrant(r.Context(), id, identity, grantID, time.Now()); err != nil {
		privateVisitorError(w, "revoke private service grant", err)
		return
	}
	w.WriteHeader(204)
}

func privateInvitation(invitation controlstate.PrivateServiceInvitation) controlv1.PrivateServiceInvitation {
	result := controlv1.PrivateServiceInvitation{Id: invitation.ID, PrivateServiceId: invitation.PrivateServiceID,
		Email: openapi_types.Email(invitation.Email), ExpiresAt: invitation.ExpiresAt,
		AcceptedAt: invitation.AcceptedAt, RevokedAt: invitation.RevokedAt}
	if invitation.Secret != "" {
		result.Secret = &invitation.Secret
	}
	return result
}

func (h *handler) InvitePrivateServiceVisitor(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID, _ controlv1.InvitePrivateServiceVisitorParams) {
	var body controlv1.CreatePrivateServiceInvitationRequest
	if decodeJSON(w, r, &body) != nil || r.Header.Get("Idempotency-Key") == "" {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid private service invitation")
		return
	}
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	invitation, err := store.InvitePrivateServiceVisitor(r.Context(), id, identity, r.Header.Get("Idempotency-Key"), string(body.Email), body.ExpiresAt, time.Now())
	if err != nil {
		privateVisitorError(w, "invite private service visitor", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, privateInvitation(invitation))
}

func (h *handler) ListPrivateServiceInvitations(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID) {
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	rows, err := store.ListPrivateServiceInvitations(r.Context(), id, identity)
	if err != nil {
		privateVisitorError(w, "list private service invitations", err)
		return
	}
	result := make([]controlv1.PrivateServiceInvitation, 0, len(rows))
	for _, row := range rows {
		result = append(result, privateInvitation(row))
	}
	writeJSON(w, 200, result)
}

func (h *handler) AcceptPrivateServiceInvitation(w http.ResponseWriter, r *http.Request) {
	var body controlv1.AcceptPrivateServiceInvitationJSONBody
	if decodeJSON(w, r, &body) != nil || len(body.Secret) < 32 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid private service invitation secret")
		return
	}
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	grant, err := store.AcceptPrivateServiceInvitation(r.Context(), identity, body.Secret, time.Now())
	if err != nil {
		privateVisitorError(w, "accept private service invitation", err)
		return
	}
	writeJSON(w, 200, privateGrant(grant))
}

func (h *handler) RevokePrivateServiceInvitation(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID, invitationID controlv1.PrivateServiceInvitationID) {
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	if err := store.RevokePrivateServiceInvitation(r.Context(), id, identity, invitationID, time.Now()); err != nil {
		privateVisitorError(w, "revoke private service invitation", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) ListAvailablePrivateServices(w http.ResponseWriter, r *http.Request, params controlv1.ListAvailablePrivateServicesParams) {
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	cursor := ""
	if params.Cursor != nil {
		cursor = *params.Cursor
	}
	rows, next, err := store.ListAvailablePrivateServices(r.Context(), identity, cursor, time.Now())
	if err != nil {
		privateVisitorError(w, "list available private services", err)
		return
	}
	page := controlv1.PrivateServicePage{Services: make([]controlv1.PrivateService, 0, len(rows))}
	for _, row := range rows {
		entry := controlv1.PrivateService{Id: row.ID, TeamId: row.TeamID, Name: row.Name, Enabled: true, CreatedAt: row.CreatedAt}
		if row.PrivateRunID != "" {
			entry.PrivateRunId, entry.RunNumber = &row.PrivateRunID, &row.RunNumber
		}
		page.Services = append(page.Services, entry)
	}
	if next != "" {
		page.NextCursor = &next
	}
	writeJSON(w, 200, page)
}

func (h *handler) CreatePrivateConnectorSession(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID) {
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	ingress := (tnldconfig.Config{Role: h.config.Role, ServerDomain: h.config.ServerDomain}).IngressHostname()
	if ingress == "" {
		writeProblem(w, 503, controlv1.Unavailable, "ingress address is unavailable")
		return
	}
	session, err := store.CreatePrivateConnectorSession(r.Context(), id, identity, time.Now())
	if err != nil {
		privateVisitorError(w, "create private connector session", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, controlv1.PrivateConnectorSessionSetup{ConnectorSessionId: session.ID,
		PrivateServiceId: session.PrivateServiceID, SessionCredential: session.Credential,
		IngressAddress: net.JoinHostPort(ingress, "443"),
		ExpiresAt:      session.ExpiresAt})
}

func (h *handler) CreatePrivateServiceTicket(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID) {
	var body controlv1.CreatePrivateServiceTicketRequest
	if decodeJSON(w, r, &body) != nil || !opaqueid.Valid(id, opaqueid.PrivateServicePrefix) ||
		!opaqueid.Valid(body.ConnectorSessionId, opaqueid.PrivateConnectorSessionPrefix) {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid private service ticket request")
		return
	}
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	ticket, err := store.IssuePrivateServiceTicket(r.Context(), id, body.ConnectorSessionId, identity, time.Now())
	if err != nil {
		privateVisitorError(w, "create private service ticket", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, controlv1.PrivateServiceConnection{
		PrivateServiceId: ticket.PrivateServiceID, PrivateRunId: ticket.PrivateRunID,
		ConnectorSessionId: ticket.ConnectorSessionID, IdentityId: ticket.IdentityID,
		ObservedSourceIp: ticket.SourceIP.String(), RunNumber: ticket.RunNumber,
		StreamPublicKey: hex.EncodeToString(ticket.StreamPublicKey),
		Ticket:          ticket.Ticket, ExpiresAt: ticket.ExpiresAt,
	})
}
