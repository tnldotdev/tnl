package public

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
	"github.com/tnldotdev/tnl/internal/region"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type serviceVisitorStore interface {
	CreateServiceAt(context.Context, string, string, string, string, controlstate.ServicePlacement, time.Time, controlstate.ServiceMetadata) (controlstate.ServiceRecord, error)
	ConfigureService(context.Context, string, string, controlstate.ServiceMetadata, time.Time) (controlstate.ServiceRecord, error)
	GetService(context.Context, string, string) (controlstate.ServiceRecord, error)
	DeleteService(context.Context, string, string, time.Time) error
	CreateServiceGrant(context.Context, string, string, string, string, string, *time.Time, time.Time) (controlstate.ServiceGrant, error)
	ListServiceGrants(context.Context, string, string, string) ([]controlstate.ServiceGrant, string, error)
	RevokeServiceGrant(context.Context, string, string, string, time.Time) error
	InviteServiceVisitor(context.Context, string, string, string, string, time.Time, time.Time) (controlstate.ServiceInvitation, error)
	ListServiceInvitations(context.Context, string, string, string) ([]controlstate.ServiceInvitation, string, error)
	AcceptServiceInvitation(context.Context, string, string, time.Time) (controlstate.ServiceGrant, error)
	RevokeServiceInvitation(context.Context, string, string, string, time.Time) error
	ListServices(context.Context, string, string, string) ([]controlstate.ServiceRecord, string, error)
	ListAvailableServices(context.Context, string, string, time.Time) ([]controlstate.ServiceInventory, string, error)
	EnrollVisitorDevice(context.Context, string, ed25519.PublicKey, time.Time) (controlstate.VisitorDevice, error)
	RevokeVisitorDevice(context.Context, string, string, time.Time) error
	CreateVisitorIngressAssignments(context.Context, string, string, string, string, time.Time, ...string) ([]controlstate.ConnectorSession, error)
	SelectServiceRun(context.Context, string, string, string, time.Time) (controlstate.ServiceSelection, error)
}

func (h *handler) serviceVisitor(w http.ResponseWriter, r *http.Request) (serviceVisitorStore, string, bool) {
	principal, ok := h.authorizeReads(w, r)
	if !ok {
		return nil, "", false
	}
	store, ok := h.store.(serviceVisitorStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "services are unavailable")
		return nil, "", false
	}
	return store, principal.identityID, true
}

func serviceVisitorError(w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrProjectConfigurationInvalid):
		writeProblem(w, 400, controlv1.InvalidRequest, "select a ready team domain and a valid source-bound worktree placement")
	case errors.Is(err, controlstate.ErrServiceRunUnavailable):
		writeProblem(w, 503, controlv1.Unavailable, "no service run has a free visitor stream; retry when capacity returns")
	case errors.Is(err, controlstate.ErrServiceAccess):
		writeProblem(w, 404, controlv1.NotFound, "service not found or unavailable")
	case errors.Is(err, controlstate.ErrServiceConflict):
		writeProblem(w, 409, controlv1.Conflict, "service state or idempotency key conflicts with this request; read the current service and retry")
	case errors.Is(err, controlstate.ErrInsufficientPrivateIngresses):
		writeProblem(w, 503, controlv1.Unavailable, "two live ingress connector addresses are required")
	case errors.Is(err, controlstate.ErrPrivateIngressUnavailable):
		writeProblem(w, 503, controlv1.PlacementUnavailable, "no live ingress connector address has capacity; release unused assignments and retry")
	default:
		writeControlStateProblem(w, operation, err)
	}
}

func endpointResponse(value *controlstate.ServiceEndpoint) *controlv1.ServiceEndpoint {
	if value == nil {
		return nil
	}
	return &controlv1.ServiceEndpoint{Hostname: value.Hostname, Port: value.Port, Public: value.Public}
}

func targetTLSInput(t *controlv1.ServiceTargetTLS) *controlstate.ServiceTargetTLS {
	if t == nil {
		return nil
	}
	return &controlstate.ServiceTargetTLS{Hostname: t.Hostname, System: t.System, Digest: t.Digest, PEM: optionalFeedbackString(t.Pem)}
}

func (h *handler) ConfigureService(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID) {
	var body controlv1.ServiceMetadata
	if decodeJSONLimited(w, r, &body, 2<<20) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid service metadata")
		return
	}
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	metadata := controlstate.ServiceMetadata{Protocol: string(body.Protocol), PublisherPool: body.PublisherPool, TLS: targetTLSInput(body.TargetTls), TrustRevision: body.TrustRevision}
	if metadata.Validate() != nil || metadata.TrustRevision < 1 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid service protocol or TLS trust")
		return
	}
	record, err := store.ConfigureService(r.Context(), id, identity, metadata, time.Now())
	if err != nil {
		serviceVisitorError(w, "configure service", err)
		return
	}
	writeJSON(w, 200, serviceaccess.Service(record))
}

func (h *handler) CreateService(w http.ResponseWriter, r *http.Request, _ controlv1.CreateServiceParams) {
	var body controlv1.CreateServiceRequest
	if decodeJSONLimited(w, r, &body, 2<<20) != nil || r.Header.Get("Idempotency-Key") == "" {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid service request")
		return
	}
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	metadata := controlstate.ServiceMetadata{Protocol: "tcp", TLS: targetTLSInput(body.TargetTls)}
	if body.Protocol != nil {
		metadata.Protocol = string(*body.Protocol)
	}
	if body.PublisherPool != nil {
		metadata.PublisherPool = *body.PublisherPool
	}
	if metadata.Validate() != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid service protocol or TLS trust")
		return
	}
	placement := controlstate.ServicePlacement{DNSAutomation: h.config.DNSAutomation}
	if body.Placement != nil {
		placement.DomainID = optionalFeedbackString(body.Placement.DomainId)
		placement.WorktreeKey = optionalFeedbackString(body.Placement.WorktreeKey)
		placement.WorktreeLabel = optionalFeedbackString(body.Placement.WorktreeLabel)
	}
	record, err := store.CreateServiceAt(r.Context(), body.TeamId, identity, body.Name, r.Header.Get("Idempotency-Key"), placement, time.Now(), metadata)
	if err != nil {
		serviceVisitorError(w, "create service", err)
		return
	}
	writeJSON(w, 201, serviceaccess.Service(record))
}

func (h *handler) ListServices(w http.ResponseWriter, r *http.Request, params controlv1.ListServicesParams) {
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	cursor := ""
	if params.Cursor != nil {
		cursor = *params.Cursor
	}
	rows, next, err := store.ListServices(r.Context(), params.TeamId, identity, cursor)
	if err != nil {
		serviceVisitorError(w, "list services", err)
		return
	}
	page := controlv1.ServicePage{Services: make([]controlv1.Service, 0, len(rows))}
	for _, row := range rows {
		page.Services = append(page.Services, serviceaccess.Summary(row))
	}
	if next != "" {
		page.NextCursor = &next
	}
	writeJSON(w, 200, page)
}

func (h *handler) GetService(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID) {
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	record, err := store.GetService(r.Context(), id, identity)
	if err != nil {
		serviceVisitorError(w, "get service", err)
		return
	}
	writeJSON(w, 200, serviceaccess.Service(record))
}

func (h *handler) GetPublisherService(w http.ResponseWriter, r *http.Request) {
	_, publisher, ok := h.authenticatePublisher(w, r)
	if !ok {
		return
	}
	if publisher.Scope.Kind != "service" {
		writeProblem(w, 404, controlv1.NotFound, "service not found")
		return
	}
	store, ok := h.store.(interface {
		GetServiceForPublisher(context.Context, string, controlstate.PublisherIdentity, time.Time) (controlstate.ServiceRecord, error)
	})
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "service state is unavailable")
		return
	}
	record, err := store.GetServiceForPublisher(r.Context(), publisher.Scope.ServiceID, publisher, time.Now())
	if err != nil {
		serviceVisitorError(w, "read publisher service", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, serviceaccess.Service(record))
}

func (h *handler) DeleteService(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID) {
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	if err := store.DeleteService(r.Context(), id, identity, time.Now()); err != nil {
		serviceVisitorError(w, "delete service", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) CreateServiceGrant(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID, _ controlv1.CreateServiceGrantParams) {
	var body controlv1.CreateServiceGrantRequest
	if decodeJSON(w, r, &body) != nil || !body.Kind.Valid() || r.Header.Get("Idempotency-Key") == "" {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid service grant")
		return
	}
	identityID := ""
	if body.IdentityId != nil {
		identityID = *body.IdentityId
	}
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	grant, err := store.CreateServiceGrant(r.Context(), id, identity, r.Header.Get("Idempotency-Key"), string(body.Kind), identityID, body.ExpiresAt, time.Now())
	if err != nil {
		serviceVisitorError(w, "create service grant", err)
		return
	}
	writeJSON(w, 201, serviceaccess.Grant(grant))
}

func (h *handler) ListServiceGrants(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID, params controlv1.ListServiceGrantsParams) {
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	grants, next, err := store.ListServiceGrants(r.Context(), id, identity, optionalFeedbackString(params.Cursor))
	if err != nil {
		serviceVisitorError(w, "list service grants", err)
		return
	}
	result := controlv1.ServiceGrantPage{Grants: make([]controlv1.ServiceGrant, 0, len(grants))}
	for _, grant := range grants {
		result.Grants = append(result.Grants, serviceaccess.Grant(grant))
	}
	if next != "" {
		result.NextCursor = &next
	}
	writeJSON(w, 200, result)
}

func (h *handler) RevokeServiceGrant(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID, grantID controlv1.ServiceGrantID) {
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	if err := store.RevokeServiceGrant(r.Context(), id, identity, grantID, time.Now()); err != nil {
		serviceVisitorError(w, "revoke service grant", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) InviteServiceVisitor(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID, _ controlv1.InviteServiceVisitorParams) {
	var body controlv1.CreateServiceInvitationRequest
	if decodeJSON(w, r, &body) != nil || r.Header.Get("Idempotency-Key") == "" {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid service invitation")
		return
	}
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	invitation, err := store.InviteServiceVisitor(r.Context(), id, identity, r.Header.Get("Idempotency-Key"), string(body.Email), body.ExpiresAt, time.Now())
	if err != nil {
		serviceVisitorError(w, "invite service visitor", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	status := http.StatusCreated
	if invitation.Secret == "" {
		status = http.StatusOK
	}
	writeJSON(w, status, serviceaccess.Invitation(invitation))
}

func (h *handler) ListServiceInvitations(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID, params controlv1.ListServiceInvitationsParams) {
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	rows, next, err := store.ListServiceInvitations(r.Context(), id, identity, optionalFeedbackString(params.Cursor))
	if err != nil {
		serviceVisitorError(w, "list service invitations", err)
		return
	}
	result := controlv1.ServiceInvitationPage{Invitations: make([]controlv1.ServiceInvitation, 0, len(rows))}
	for _, row := range rows {
		result.Invitations = append(result.Invitations, serviceaccess.Invitation(row))
	}
	if next != "" {
		result.NextCursor = &next
	}
	writeJSON(w, 200, result)
}

func (h *handler) AcceptServiceInvitation(w http.ResponseWriter, r *http.Request) {
	var body controlv1.ServiceInvitationCredential
	if decodeJSON(w, r, &body) != nil || len(body.Secret) < 32 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid service invitation secret")
		return
	}
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	grant, err := store.AcceptServiceInvitation(r.Context(), identity, body.Secret, time.Now())
	if err != nil {
		serviceVisitorError(w, "accept service invitation", err)
		return
	}
	writeJSON(w, 200, serviceaccess.Grant(grant))
}

func (h *handler) RevokeServiceInvitation(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID, invitationID controlv1.ServiceInvitationID) {
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	if err := store.RevokeServiceInvitation(r.Context(), id, identity, invitationID, time.Now()); err != nil {
		serviceVisitorError(w, "revoke service invitation", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) ListAvailableServices(w http.ResponseWriter, r *http.Request, params controlv1.ListAvailableServicesParams) {
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	cursor := ""
	if params.Cursor != nil {
		cursor = *params.Cursor
	}
	rows, next, err := store.ListAvailableServices(r.Context(), identity, cursor, time.Now())
	if err != nil {
		serviceVisitorError(w, "list available services", err)
		return
	}
	page := controlv1.ServicePage{Services: make([]controlv1.Service, 0, len(rows))}
	for _, row := range rows {
		entry := serviceaccess.Summary(controlstate.ServiceRecord{ID: row.ID, TeamID: row.TeamID, Name: row.Name, Enabled: true, CreatedAt: row.CreatedAt, ServiceMetadata: row.ServiceMetadata})
		entry.KubernetesAuth = row.KubernetesAuth
		if row.ServiceRunID != "" {
			entry.ServiceRunId, entry.RunNumber = &row.ServiceRunID, &row.RunNumber
		}
		page.Services = append(page.Services, entry)
	}
	if next != "" {
		page.NextCursor = &next
	}
	writeJSON(w, 200, page)
}

func (h *handler) CreateVisitorIngressAssignments(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID) {
	var body controlv1.CreateVisitorIngressAssignmentsJSONBody
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "device identity is required")
		return
	}
	preferences, err := normalizedLocationPreferences(body.PreferredRegions)
	if err != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid preferred regions")
		return
	}
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	sessions, err := store.CreateVisitorIngressAssignments(r.Context(), identity, body.DeviceId, id, body.IdempotencyKey, time.Now(), preferences...)
	if err != nil {
		serviceVisitorError(w, "create private connector session", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	result := make([]controlv1.ConnectorSessionSetup, 0, 2)
	for _, session := range sessions {
		result = append(result, connectorSessionSetup(session))
	}
	writeJSON(w, 201, result)
}

func connectorSessionSetup(session controlstate.ConnectorSession) controlv1.ConnectorSessionSetup {
	return controlv1.ConnectorSessionSetup{ConnectorSessionId: session.ID, ServiceId: session.ServiceID, SessionCredential: session.Credential, IngressId: session.IngressID, Region: string(session.Region), IngressAddress: session.IngressAddress, TlsServerName: session.TLSServerName, Subject: visitorsubject.Wire(tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: session.IdentityID, DeviceID: session.DeviceID}), ExpiresAt: session.ExpiresAt}
}

func normalizedLocationPreferences(values *controlv1.LocationPreferences) ([]string, error) {
	if values == nil {
		return nil, nil
	}
	codes, err := region.Preferences(*values)
	if err != nil {
		return nil, err
	}
	result := make([]string, len(codes))
	for index, code := range codes {
		result[index] = string(code)
	}
	return result, nil
}

func (h *handler) CreateVisitorIngressAssignment(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID) {
	var body controlv1.CreateVisitorIngressAssignmentJSONBody
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "device identity is required")
		return
	}
	preferences, err := normalizedLocationPreferences(body.PreferredRegions)
	if err != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid preferred regions")
		return
	}
	principal, ok := h.authorizeReads(w, r)
	if !ok {
		return
	}
	store, ok := h.store.(interface {
		CreateVisitorIngressAssignment(context.Context, string, string, string, string, string, time.Time, ...string) (controlstate.ConnectorSession, error)
	})
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "services are unavailable")
		return
	}
	session, err := store.CreateVisitorIngressAssignment(r.Context(), principal.identityID, body.DeviceId, id, optionalFeedbackString(body.ExcludeIngressId), body.IdempotencyKey, time.Now(), preferences...)
	if err != nil {
		serviceVisitorError(w, "create private connector assignment", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, connectorSessionSetup(session))
}

func (h *handler) SelectServiceRun(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID) {
	var body controlv1.SelectServiceRunJSONBody
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid service selection")
		return
	}
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	selected, err := store.SelectServiceRun(r.Context(), id, identity, body.DeviceId, time.Now())
	if err != nil {
		serviceVisitorError(w, "select service run", err)
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
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	device, err := store.EnrollVisitorDevice(r.Context(), identity, ed25519.PublicKey(key), time.Now())
	if err != nil {
		serviceVisitorError(w, "enroll visitor device", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, device)
}

func (h *handler) RevokeVisitorDevice(w http.ResponseWriter, r *http.Request, id string) {
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	if err := store.RevokeVisitorDevice(r.Context(), identity, id, time.Now()); err != nil {
		serviceVisitorError(w, "revoke visitor device", err)
		return
	}
	w.WriteHeader(204)
}
