package authorityapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/serviceaccess"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type serviceAccessStore interface {
	ResolveCompanyAccount(context.Context, string, string) (string, error)
	ListPrivateServices(context.Context, string, string, string) ([]controlstate.PrivateServiceRecord, string, error)
	GetPrivateService(context.Context, string, string) (controlstate.PrivateServiceRecord, error)
	ListPrivateServiceGrants(context.Context, string, string, string) ([]controlstate.PrivateServiceGrant, string, error)
	ListPrivateServiceInvitations(context.Context, string, string, string) ([]controlstate.PrivateServiceInvitation, string, error)
	InvitePrivateServiceVisitor(context.Context, string, string, string, string, time.Time, time.Time) (controlstate.PrivateServiceInvitation, error)
	PreviewPrivateServiceInvitation(context.Context, string, string, time.Time) (controlstate.PrivateServiceInvitationPreview, error)
	AcceptPrivateServiceInvitation(context.Context, string, string, time.Time) (controlstate.PrivateServiceGrant, error)
	RevokePrivateServiceGrant(context.Context, string, string, string, time.Time) error
	RevokePrivateServiceInvitation(context.Context, string, string, string, time.Time) error
	CreateManagedHTTPGrant(context.Context, string, string, controlv1.CreateManagedHTTPGrantRequest, time.Time) (controlv1.ManagedHTTPGrant, error)
	ListManagedHTTPGrants(context.Context, string, string, time.Time) ([]controlv1.ManagedHTTPGrantSummary, error)
	RevokeManagedHTTPGrant(context.Context, string, string, string, time.Time) error
}

func serviceAccessError(w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrServiceManagerRequired):
		writeProblem(w, 403, authorityv1.ManagerRequired, "current service manager permission is required")
	case errors.Is(err, controlstate.ErrServiceSourceSignInRequired):
		writeProblem(w, 403, authorityv1.SourceSignInRequired, "sign in through the current company source")
	case errors.Is(err, controlstate.ErrServiceVerifiedEmailRequired):
		writeProblem(w, 403, authorityv1.VerifiedEmailRequired, "sign in with a verified email")
	case errors.Is(err, controlstate.ErrPrivateServiceAccess):
		writeProblem(w, 403, authorityv1.Forbidden, "service access denied")
	case errors.Is(err, controlstate.ErrPrivateServiceConflict):
		writeProblem(w, 409, authorityv1.Conflict, "service access state or idempotency key conflicts")
	default:
		companyError(w, operation, err)
	}
}

func (h *handler) serviceHuman(w http.ResponseWriter, r *http.Request, body any) (serviceAccessStore, string, bool) {
	i, nonce, ok := h.verifiedHumanRequest(w, r, body, controlstate.ServiceActorNonce, true)
	if !ok {
		return nil, "", false
	}
	s, ok := h.store.(serviceAccessStore)
	if !ok {
		writeProblem(w, 503, authorityv1.Unavailable, "service access is unavailable")
		return nil, "", false
	}
	actor, err := s.ResolveCompanyAccount(r.Context(), i.Issuer, i.Subject)
	if err != nil {
		if errors.Is(err, controlstate.ErrControlIdentity) || errors.Is(err, controlstate.ErrAuthorityAccess) {
			writeBearerProblem(w)
		} else {
			serviceAccessError(w, "resolve service actor", err)
		}
		return nil, "", false
	}
	*r = *r.WithContext(controlstate.WithServiceActorProof(r.Context(), companyOIDCIdentity(i), nonce))
	return s, actor, true
}

func (h *handler) ListWebsitePrivateServices(w http.ResponseWriter, r *http.Request, team authorityv1.TeamID, p authorityv1.ListWebsitePrivateServicesParams) {
	s, actor, ok := h.serviceHuman(w, r, nil)
	if !ok {
		return
	}
	cursor := ""
	if p.Cursor != nil {
		cursor = *p.Cursor
	}
	rows, next, err := s.ListPrivateServices(r.Context(), team, actor, cursor)
	if err != nil {
		serviceAccessError(w, "list website services", err)
		return
	}
	page := controlv1.PrivateServicePage{Services: make([]controlv1.PrivateService, 0, len(rows))}
	for _, row := range rows {
		page.Services = append(page.Services, serviceaccess.Service(row))
	}
	if next != "" {
		page.NextCursor = &next
	}
	writeJSON(w, 200, page)
}

func (h *handler) GetWebsitePrivateService(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID, _ authorityv1.GetWebsitePrivateServiceParams) {
	s, actor, ok := h.serviceHuman(w, r, nil)
	if !ok {
		return
	}
	row, err := s.GetPrivateService(r.Context(), id, actor)
	if err != nil {
		serviceAccessError(w, "get website service", err)
		return
	}
	writeJSON(w, 200, serviceaccess.Service(row))
}

func (h *handler) ListWebsitePrivateServiceGrants(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID, p authorityv1.ListWebsitePrivateServiceGrantsParams) {
	s, actor, ok := h.serviceHuman(w, r, nil)
	if !ok {
		return
	}
	cursor := ""
	if p.Cursor != nil {
		cursor = *p.Cursor
	}
	rows, next, err := s.ListPrivateServiceGrants(r.Context(), id, actor, cursor)
	if err != nil {
		serviceAccessError(w, "list website service grants", err)
		return
	}
	result := controlv1.PrivateServiceGrantPage{Grants: make([]controlv1.PrivateServiceGrant, 0, len(rows))}
	for _, row := range rows {
		result.Grants = append(result.Grants, serviceaccess.Grant(row))
	}
	if next != "" {
		result.NextCursor = &next
	}
	writeJSON(w, 200, result)
}

func (h *handler) ListWebsitePrivateServiceInvitations(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID, p authorityv1.ListWebsitePrivateServiceInvitationsParams) {
	s, actor, ok := h.serviceHuman(w, r, nil)
	if !ok {
		return
	}
	cursor := ""
	if p.Cursor != nil {
		cursor = *p.Cursor
	}
	rows, next, err := s.ListPrivateServiceInvitations(r.Context(), id, actor, cursor)
	if err != nil {
		serviceAccessError(w, "list website service invitations", err)
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

func (h *handler) InviteWebsitePrivateServiceVisitor(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID, p authorityv1.InviteWebsitePrivateServiceVisitorParams) {
	var body controlv1.CreatePrivateServiceInvitationRequest
	s, actor, ok := h.serviceHuman(w, r, &body)
	if !ok {
		return
	}
	row, err := s.InvitePrivateServiceVisitor(r.Context(), id, actor, p.IdempotencyKey, string(body.Email), body.ExpiresAt, time.Now())
	if err != nil {
		serviceAccessError(w, "invite website service visitor", err)
		return
	}
	status := http.StatusCreated
	if row.Secret == "" {
		status = http.StatusOK
	}
	writeJSON(w, status, serviceaccess.Invitation(row))
}

func (h *handler) PreviewWebsitePrivateServiceInvitation(w http.ResponseWriter, r *http.Request, _ authorityv1.PreviewWebsitePrivateServiceInvitationParams) {
	var body authorityv1.PrivateServiceInvitationCredential
	s, actor, ok := h.serviceHuman(w, r, &body)
	if !ok {
		return
	}
	row, err := s.PreviewPrivateServiceInvitation(r.Context(), actor, body.Secret, time.Now())
	if err != nil {
		serviceAccessError(w, "preview website service invitation", err)
		return
	}
	writeJSON(w, 200, row)
}

func (h *handler) AcceptWebsitePrivateServiceInvitation(w http.ResponseWriter, r *http.Request, _ authorityv1.AcceptWebsitePrivateServiceInvitationParams) {
	var body authorityv1.PrivateServiceInvitationCredential
	s, actor, ok := h.serviceHuman(w, r, &body)
	if !ok {
		return
	}
	row, err := s.AcceptPrivateServiceInvitation(r.Context(), actor, body.Secret, time.Now())
	if err != nil {
		serviceAccessError(w, "accept website service invitation", err)
		return
	}
	writeJSON(w, 200, serviceaccess.Grant(row))
}

func (h *handler) RevokeWebsitePrivateServiceGrant(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID, grant controlv1.PrivateServiceGrantID, _ authorityv1.RevokeWebsitePrivateServiceGrantParams) {
	s, actor, ok := h.serviceHuman(w, r, nil)
	if !ok {
		return
	}
	if err := s.RevokePrivateServiceGrant(r.Context(), id, actor, grant, time.Now()); err != nil {
		serviceAccessError(w, "revoke website service grant", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) RevokeWebsitePrivateServiceInvitation(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID, invitation controlv1.PrivateServiceInvitationID, _ authorityv1.RevokeWebsitePrivateServiceInvitationParams) {
	s, actor, ok := h.serviceHuman(w, r, nil)
	if !ok {
		return
	}
	if err := s.RevokePrivateServiceInvitation(r.Context(), id, actor, invitation, time.Now()); err != nil {
		serviceAccessError(w, "revoke website service invitation", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) ListWebsiteManagedHTTPGrants(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID, _ authorityv1.ListWebsiteManagedHTTPGrantsParams) {
	s, actor, ok := h.serviceHuman(w, r, nil)
	if !ok {
		return
	}
	rows, err := s.ListManagedHTTPGrants(r.Context(), id, actor, time.Now())
	if err != nil {
		serviceAccessError(w, "list website HTTP grants", err)
		return
	}
	writeJSON(w, 200, rows)
}

func (h *handler) CreateWebsiteManagedHTTPGrant(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID, _ authorityv1.CreateWebsiteManagedHTTPGrantParams) {
	var body controlv1.CreateManagedHTTPGrantRequest
	s, actor, ok := h.serviceHuman(w, r, &body)
	if !ok {
		return
	}
	row, err := s.CreateManagedHTTPGrant(r.Context(), id, actor, body, time.Now())
	if err != nil {
		serviceAccessError(w, "create website HTTP grant", err)
		return
	}
	writeJSON(w, 201, row)
}

func (h *handler) RevokeWebsiteManagedHTTPGrant(w http.ResponseWriter, r *http.Request, id controlv1.PrivateServiceID, grant string, _ authorityv1.RevokeWebsiteManagedHTTPGrantParams) {
	s, actor, ok := h.serviceHuman(w, r, nil)
	if !ok {
		return
	}
	if err := s.RevokeManagedHTTPGrant(r.Context(), id, actor, grant, time.Now()); err != nil {
		serviceAccessError(w, "revoke website HTTP grant", err)
		return
	}
	w.WriteHeader(204)
}
