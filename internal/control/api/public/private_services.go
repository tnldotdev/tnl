package controlapi

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/control/api/serviceaccess"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type privateVisitorStore interface {
	CreatePrivateServiceAt(context.Context, string, string, string, string, controlstate.PrivateServicePlacement, time.Time, ...controlstate.PrivateServiceMetadata) (controlstate.PrivateServiceRecord, error)
	ConfigurePrivateService(context.Context, string, string, controlstate.PrivateServiceMetadata, time.Time) (controlstate.PrivateServiceRecord, error)
	GetPrivateService(context.Context, string, string) (controlstate.PrivateServiceRecord, error)
	DeletePrivateService(context.Context, string, string, time.Time) error
	CreatePrivateServiceGrant(context.Context, string, string, string, string, string, *time.Time, time.Time) (controlstate.PrivateServiceGrant, error)
	ListPrivateServiceGrants(context.Context, string, string, string) ([]controlstate.PrivateServiceGrant, string, error)
	RevokePrivateServiceGrant(context.Context, string, string, string, time.Time) error
	InvitePrivateServiceVisitor(context.Context, string, string, string, string, time.Time, time.Time) (controlstate.PrivateServiceInvitation, error)
	ListPrivateServiceInvitations(context.Context, string, string, string) ([]controlstate.PrivateServiceInvitation, string, error)
	AcceptPrivateServiceInvitation(context.Context, string, string, time.Time) (controlstate.PrivateServiceGrant, error)
	RevokePrivateServiceInvitation(context.Context, string, string, string, time.Time) error
	ListPrivateServices(context.Context, string, string, string) ([]controlstate.PrivateServiceRecord, string, error)
	ListAvailablePrivateServices(context.Context, string, string, time.Time) ([]controlstate.PrivateServiceInventory, string, error)
	EnrollVisitorDevice(context.Context, string, ed25519.PublicKey, time.Time) (controlstate.VisitorDevice, error)
	RevokeVisitorDevice(context.Context, string, string, time.Time) error
	CreateVisitorIngressAssignments(context.Context, string, string, string, string, time.Time) ([]controlstate.PrivateConnectorSession, error)
	SelectPrivateServiceRun(context.Context, string, string, string, time.Time) (controlstate.PrivateServiceSelection, error)
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
	case errors.Is(err, controlstate.ErrProjectConfigurationInvalid):
		writeProblem(w, 400, controlv1.InvalidRequest, "select a ready team domain and a valid source-bound worktree placement")
	case errors.Is(err, controlstate.ErrPrivateServiceAccess):
		writeProblem(w, 404, controlv1.NotFound, "private service not found or unavailable")
	case errors.Is(err, controlstate.ErrPrivateServiceConflict):
		writeProblem(w, 409, controlv1.Conflict, "private service state or idempotency key conflicts with this request; read the current service and retry")
	case errors.Is(err, controlstate.ErrInsufficientPrivateIngresses):
		writeProblem(w, 503, controlv1.Unavailable, "two live ingress connector addresses are required")
	case errors.Is(err, controlstate.ErrPrivateIngressUnavailable):
		writeProblem(w, 503, controlv1.PlacementUnavailable, "no live ingress connector address has capacity; release unused assignments and retry")
	default:
		writeControlStateProblem(w, operation, err)
	}
}

func managedTLSResponse(value *controlstate.ManagedServiceTLS) *controlv1.ManagedServiceTLS {
	if value == nil {
		return nil
	}
	return &controlv1.ManagedServiceTLS{Hostname: value.Hostname, Port: value.Port, Public: value.Public}
}

func privateTLSInput(t *controlv1.PrivateServiceTLS) *controlstate.PrivateServiceTLS {
	if t == nil {
		return nil
	}
	return &controlstate.PrivateServiceTLS{Hostname: t.Hostname, System: t.System, Digest: t.Digest, PEM: optionalFeedbackString(t.Pem)}
}

func (h *handler) ConfigurePrivateService(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID) {
	var body controlv1.PrivateServiceMetadata
	if decodeJSONLimited(w, r, &body, 2<<20) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid private service metadata")
		return
	}
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	metadata := controlstate.PrivateServiceMetadata{Protocol: string(body.Protocol), PublisherPool: body.PublisherPool, TLS: privateTLSInput(body.TargetTls), TrustRevision: body.TrustRevision}
	if metadata.Validate() != nil || metadata.TrustRevision < 1 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid private service protocol or TLS trust")
		return
	}
	record, err := store.ConfigurePrivateService(r.Context(), id, identity, metadata, time.Now())
	if err != nil {
		privateVisitorError(w, "configure private service", err)
		return
	}
	writeJSON(w, 200, serviceaccess.Service(record))
}

func (h *handler) CreatePrivateService(w http.ResponseWriter, r *http.Request, _ controlv1.CreatePrivateServiceParams) {
	var body controlv1.CreatePrivateServiceRequest
	if decodeJSONLimited(w, r, &body, 2<<20) != nil || r.Header.Get("Idempotency-Key") == "" {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid private service request")
		return
	}
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	metadata := controlstate.PrivateServiceMetadata{Protocol: "tcp", TLS: privateTLSInput(body.TargetTls)}
	if body.Protocol != nil {
		metadata.Protocol = string(*body.Protocol)
	}
	if body.PublisherPool != nil {
		metadata.PublisherPool = *body.PublisherPool
	}
	if metadata.Validate() != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid private service protocol or TLS trust")
		return
	}
	placement := controlstate.PrivateServicePlacement{DNSAutomation: h.config.DNSAutomation}
	if body.Placement != nil {
		placement.DomainID = optionalFeedbackString(body.Placement.DomainId)
		placement.WorktreeKey = optionalFeedbackString(body.Placement.WorktreeKey)
		placement.WorktreeLabel = optionalFeedbackString(body.Placement.WorktreeLabel)
	}
	record, err := store.CreatePrivateServiceAt(r.Context(), body.TeamId, identity, body.Name, r.Header.Get("Idempotency-Key"), placement, time.Now(), metadata)
	if err != nil {
		privateVisitorError(w, "create private service", err)
		return
	}
	writeJSON(w, 201, serviceaccess.Service(record))
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
		page.Services = append(page.Services, serviceaccess.Summary(row))
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
	writeJSON(w, 200, serviceaccess.Service(record))
}

func (h *handler) GetPublisherPrivateService(w http.ResponseWriter, r *http.Request) {
	_, publisher, ok := h.authenticatePublisher(w, r)
	if !ok {
		return
	}
	if publisher.Scope.Kind != "private_service" {
		writeProblem(w, 404, controlv1.NotFound, "private service not found")
		return
	}
	store, ok := h.store.(interface {
		GetPrivateServiceForPublisher(context.Context, string, controlstate.PublisherIdentity, time.Time) (controlstate.PrivateServiceRecord, error)
	})
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "private service state is unavailable")
		return
	}
	record, err := store.GetPrivateServiceForPublisher(r.Context(), publisher.Scope.PrivateServiceID, publisher, time.Now())
	if err != nil {
		privateVisitorError(w, "read publisher private service", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, serviceaccess.Service(record))
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
	writeJSON(w, 201, serviceaccess.Grant(grant))
}

func (h *handler) ListPrivateServiceGrants(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID, params controlv1.ListPrivateServiceGrantsParams) {
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	grants, next, err := store.ListPrivateServiceGrants(r.Context(), id, identity, optionalFeedbackString(params.Cursor))
	if err != nil {
		privateVisitorError(w, "list private service grants", err)
		return
	}
	result := controlv1.PrivateServiceGrantPage{Grants: make([]controlv1.PrivateServiceGrant, 0, len(grants))}
	for _, grant := range grants {
		result.Grants = append(result.Grants, serviceaccess.Grant(grant))
	}
	if next != "" {
		result.NextCursor = &next
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
	status := http.StatusCreated
	if invitation.Secret == "" {
		status = http.StatusOK
	}
	writeJSON(w, status, serviceaccess.Invitation(invitation))
}

func (h *handler) ListPrivateServiceInvitations(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID, params controlv1.ListPrivateServiceInvitationsParams) {
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	rows, next, err := store.ListPrivateServiceInvitations(r.Context(), id, identity, optionalFeedbackString(params.Cursor))
	if err != nil {
		privateVisitorError(w, "list private service invitations", err)
		return
	}
	result := controlv1.PrivateServiceInvitationPage{Invitations: make([]controlv1.PrivateServiceInvitation, 0, len(rows))}
	for _, row := range rows {
		result.Invitations = append(result.Invitations, serviceaccess.Invitation(row))
	}
	if next != "" {
		result.NextCursor = &next
	}
	writeJSON(w, 200, result)
}

func (h *handler) AcceptPrivateServiceInvitation(w http.ResponseWriter, r *http.Request) {
	var body controlv1.PrivateServiceInvitationCredential
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
	writeJSON(w, 200, serviceaccess.Grant(grant))
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
		entry := serviceaccess.Summary(controlstate.PrivateServiceRecord{ID: row.ID, TeamID: row.TeamID, Name: row.Name, Enabled: true, CreatedAt: row.CreatedAt, PrivateServiceMetadata: row.PrivateServiceMetadata})
		entry.KubernetesAuth = row.KubernetesAuth
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

func (h *handler) CreateVisitorIngressAssignments(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID) {
	var body controlv1.CreateVisitorIngressAssignmentsJSONBody
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "device identity is required")
		return
	}
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	sessions, err := store.CreateVisitorIngressAssignments(r.Context(), identity, body.DeviceId, id, body.IdempotencyKey, time.Now())
	if err != nil {
		privateVisitorError(w, "create private connector session", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	result := make([]controlv1.PrivateConnectorSessionSetup, 0, 2)
	for _, session := range sessions {
		result = append(result, privateConnectorSessionSetup(session))
	}
	writeJSON(w, 201, result)
}

func privateConnectorSessionSetup(session controlstate.PrivateConnectorSession) controlv1.PrivateConnectorSessionSetup {
	return controlv1.PrivateConnectorSessionSetup{ConnectorSessionId: session.ID, PrivateServiceId: session.PrivateServiceID, SessionCredential: session.Credential, IngressId: session.IngressID, IngressAddress: session.IngressAddress, TlsServerName: session.TLSServerName, Subject: visitorsubject.Wire(tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: session.IdentityID, DeviceID: session.DeviceID}), ExpiresAt: session.ExpiresAt}
}

func (h *handler) CreateVisitorIngressAssignment(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID) {
	var body controlv1.CreateVisitorIngressAssignmentJSONBody
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "device identity is required")
		return
	}
	principal, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return
	}
	store, ok := h.store.(interface {
		CreateVisitorIngressAssignment(context.Context, string, string, string, string, string, time.Time) (controlstate.PrivateConnectorSession, error)
	})
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "private services are unavailable")
		return
	}
	session, err := store.CreateVisitorIngressAssignment(r.Context(), principal.identityID, body.DeviceId, id, optionalFeedbackString(body.ExcludeIngressId), body.IdempotencyKey, time.Now())
	if err != nil {
		privateVisitorError(w, "create private connector assignment", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, privateConnectorSessionSetup(session))
}

func (h *handler) SelectPrivateServiceRun(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID) {
	var body controlv1.SelectPrivateServiceRunJSONBody
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid private service selection")
		return
	}
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	selected, err := store.SelectPrivateServiceRun(r.Context(), id, identity, body.DeviceId, time.Now())
	if err != nil {
		privateVisitorError(w, "select private service run", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, privateSelectionResponse(selected))
}

func (h *handler) EnrollVisitorDevice(w http.ResponseWriter, r *http.Request) {
	var body controlv1.EnrollVisitorDeviceJSONBody
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid visitor device")
		return
	}
	key, err := hex.DecodeString(body.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || hex.EncodeToString(key) != body.PublicKey {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid Ed25519 device key")
		return
	}
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	device, err := store.EnrollVisitorDevice(r.Context(), identity, ed25519.PublicKey(key), time.Now())
	if err != nil {
		privateVisitorError(w, "enroll visitor device", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, device)
}

func (h *handler) RevokeVisitorDevice(w http.ResponseWriter, r *http.Request, id string) {
	store, identity, ok := h.privateVisitor(w, r)
	if !ok {
		return
	}
	if err := store.RevokeVisitorDevice(r.Context(), identity, id, time.Now()); err != nil {
		privateVisitorError(w, "revoke visitor device", err)
		return
	}
	w.WriteHeader(204)
}
