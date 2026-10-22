package authority

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/control/api/serviceaccess"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceAccessStore interface {
	ResolveCompanyAccount(context.Context, string, string) (string, error)
	ListServices(context.Context, string, string, string) ([]controlstate.ServiceRecord, string, error)
	GetService(context.Context, string, string) (controlstate.ServiceRecord, error)
	ListServiceGrants(context.Context, string, string, string) ([]controlstate.ServiceGrant, string, error)
	ListServiceInvitations(context.Context, string, string, string) ([]controlstate.ServiceInvitation, string, error)
	InviteServiceVisitor(context.Context, string, string, string, string, time.Time, time.Time) (controlstate.ServiceInvitation, error)
	PreviewServiceInvitation(context.Context, string, string, time.Time) (controlstate.ServiceInvitationPreview, error)
	AcceptServiceInvitation(context.Context, string, string, time.Time) (controlstate.ServiceGrant, error)
	RevokeServiceGrant(context.Context, string, string, string, time.Time) error
	RevokeServiceInvitation(context.Context, string, string, string, time.Time) error
	CreateServiceHTTPGrant(context.Context, string, string, controlv1.CreateServiceHTTPGrantRequest, time.Time) (controlv1.ServiceHTTPGrant, error)
	ListServiceHTTPGrants(context.Context, string, string, time.Time) ([]controlv1.ServiceHTTPGrantSummary, error)
	RevokeServiceHTTPGrant(context.Context, string, string, string, time.Time) error
}

func serviceAccessError(w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrServiceManagerRequired):
		writeProblem(w, 403, authorityv1.ManagerRequired, "current service manager permission is required")
	case errors.Is(err, controlstate.ErrServiceSourceSignInRequired):
		writeProblem(w, 403, authorityv1.SourceSignInRequired, "sign in through the current company source")
	case errors.Is(err, controlstate.ErrServiceVerifiedEmailRequired):
		writeProblem(w, 403, authorityv1.VerifiedEmailRequired, "sign in with a verified email")
	case errors.Is(err, controlstate.ErrServiceAccess):
		writeProblem(w, 403, authorityv1.Forbidden, "service access denied")
	case errors.Is(err, controlstate.ErrServiceConflict):
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

func (h *handler) ListWebsiteServices(w http.ResponseWriter, r *http.Request, team authorityv1.TeamID, p authorityv1.ListWebsiteServicesParams) {
	s, actor, ok := h.serviceHuman(w, r, nil)
	if !ok {
		return
	}
	cursor := ""
	if p.Cursor != nil {
		cursor = *p.Cursor
	}
	rows, next, err := s.ListServices(r.Context(), team, actor, cursor)
	if err != nil {
		serviceAccessError(w, "list website services", err)
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

func (h *handler) GetWebsiteService(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID, _ authorityv1.GetWebsiteServiceParams) {
	s, actor, ok := h.serviceHuman(w, r, nil)
	if !ok {
		return
	}
	row, err := s.GetService(r.Context(), id, actor)
	if err != nil {
		serviceAccessError(w, "get website service", err)
		return
	}
	writeJSON(w, 200, serviceaccess.Service(row))
}

func (h *handler) ListWebsiteServiceGrants(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID, p authorityv1.ListWebsiteServiceGrantsParams) {
	s, actor, ok := h.serviceHuman(w, r, nil)
	if !ok {
		return
	}
	cursor := ""
	if p.Cursor != nil {
		cursor = *p.Cursor
	}
	rows, next, err := s.ListServiceGrants(r.Context(), id, actor, cursor)
	if err != nil {
		serviceAccessError(w, "list website service grants", err)
		return
	}
	result := controlv1.ServiceGrantPage{Grants: make([]controlv1.ServiceGrant, 0, len(rows))}
	for _, row := range rows {
		result.Grants = append(result.Grants, serviceaccess.Grant(row))
	}
	if next != "" {
		result.NextCursor = &next
	}
	writeJSON(w, 200, result)
}

func (h *handler) ListWebsiteServiceInvitations(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID, p authorityv1.ListWebsiteServiceInvitationsParams) {
	s, actor, ok := h.serviceHuman(w, r, nil)
	if !ok {
		return
	}
	cursor := ""
	if p.Cursor != nil {
		cursor = *p.Cursor
	}
	rows, next, err := s.ListServiceInvitations(r.Context(), id, actor, cursor)
	if err != nil {
		serviceAccessError(w, "list website service invitations", err)
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

func (h *handler) InviteWebsiteServiceVisitor(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID, p authorityv1.InviteWebsiteServiceVisitorParams) {
	var body controlv1.CreateServiceInvitationRequest
	s, actor, ok := h.serviceHuman(w, r, &body)
	if !ok {
		return
	}
	row, err := s.InviteServiceVisitor(r.Context(), id, actor, p.IdempotencyKey, string(body.Email), body.ExpiresAt, time.Now())
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

func (h *handler) PreviewWebsiteServiceInvitation(w http.ResponseWriter, r *http.Request, _ authorityv1.PreviewWebsiteServiceInvitationParams) {
	var body authorityv1.ServiceInvitationCredential
	s, actor, ok := h.serviceHuman(w, r, &body)
	if !ok {
		return
	}
	row, err := s.PreviewServiceInvitation(r.Context(), actor, body.Secret, time.Now())
	if err != nil {
		serviceAccessError(w, "preview website service invitation", err)
		return
	}
	writeJSON(w, 200, row)
}

func (h *handler) AcceptWebsiteServiceInvitation(w http.ResponseWriter, r *http.Request, _ authorityv1.AcceptWebsiteServiceInvitationParams) {
	var body authorityv1.ServiceInvitationCredential
	s, actor, ok := h.serviceHuman(w, r, &body)
	if !ok {
		return
	}
	row, err := s.AcceptServiceInvitation(r.Context(), actor, body.Secret, time.Now())
	if err != nil {
		serviceAccessError(w, "accept website service invitation", err)
		return
	}
	writeJSON(w, 200, serviceaccess.Grant(row))
}

func (h *handler) RevokeWebsiteServiceGrant(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID, grant controlv1.ServiceGrantID, _ authorityv1.RevokeWebsiteServiceGrantParams) {
	s, actor, ok := h.serviceHuman(w, r, nil)
	if !ok {
		return
	}
	if err := s.RevokeServiceGrant(r.Context(), id, actor, grant, time.Now()); err != nil {
		serviceAccessError(w, "revoke website service grant", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) RevokeWebsiteServiceInvitation(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID, invitation controlv1.ServiceInvitationID, _ authorityv1.RevokeWebsiteServiceInvitationParams) {
	s, actor, ok := h.serviceHuman(w, r, nil)
	if !ok {
		return
	}
	if err := s.RevokeServiceInvitation(r.Context(), id, actor, invitation, time.Now()); err != nil {
		serviceAccessError(w, "revoke website service invitation", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) ListWebsiteServiceHTTPGrants(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID, _ authorityv1.ListWebsiteServiceHTTPGrantsParams) {
	s, actor, ok := h.serviceHuman(w, r, nil)
	if !ok {
		return
	}
	rows, err := s.ListServiceHTTPGrants(r.Context(), id, actor, time.Now())
	if err != nil {
		serviceAccessError(w, "list website HTTP grants", err)
		return
	}
	writeJSON(w, 200, rows)
}

func (h *handler) CreateWebsiteServiceHTTPGrant(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID, _ authorityv1.CreateWebsiteServiceHTTPGrantParams) {
	var body controlv1.CreateServiceHTTPGrantRequest
	s, actor, ok := h.serviceHuman(w, r, &body)
	if !ok {
		return
	}
	row, err := s.CreateServiceHTTPGrant(r.Context(), id, actor, body, time.Now())
	if err != nil {
		serviceAccessError(w, "create website HTTP grant", err)
		return
	}
	writeJSON(w, 201, row)
}

func (h *handler) RevokeWebsiteServiceHTTPGrant(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID, grant string, _ authorityv1.RevokeWebsiteServiceHTTPGrantParams) {
	s, actor, ok := h.serviceHuman(w, r, nil)
	if !ok {
		return
	}
	if err := s.RevokeServiceHTTPGrant(r.Context(), id, actor, grant, time.Now()); err != nil {
		serviceAccessError(w, "revoke website HTTP grant", err)
		return
	}
	w.WriteHeader(204)
}
