package authorityapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type companyAccessStore interface {
	ReadCompanyConnections(context.Context, controlstate.ControlPrincipal, string, time.Time) (controlstate.CompanyConnections, error)
	BeginIdentityConnectionSetup(context.Context, controlstate.ControlPrincipal, controlstate.CreateIdentityConnectionRequest, time.Time) (controlstate.IdentityConnectionSetup, error)
	ActivateIdentityConnection(context.Context, controlstate.ControlPrincipal, string, string, string, int64, controlstate.OIDCIdentity, time.Time) (controlstate.IdentityConnectionSecret, error)
	DisconnectIdentityConnection(context.Context, controlstate.ControlPrincipal, string, string, int64, time.Time) error
	RotateCompanyProvisioningToken(context.Context, controlstate.ControlPrincipal, string, string, int64, time.Time) (controlstate.IdentityConnectionSecret, error)
	ResolveCompanyAccount(context.Context, string, string) (string, error)
	ProvisionCompanyEligibility(context.Context, string, controlstate.ProvisionCompanyEligibilityRequest, time.Time) error
	SetCompanyMembershipDecision(context.Context, controlstate.ControlPrincipal, string, string, bool, bool, bool, time.Time) error
	SetCompanyInvitationException(context.Context, controlstate.ControlPrincipal, string, string, bool, time.Time) error
	RequestCompanyAdmission(context.Context, controlstate.ControlPrincipal, string, string, int64, string, time.Time) (controlstate.CompanyAdmissionRequest, error)
	ListCompanyAdmissions(context.Context, controlstate.ControlPrincipal, string, string, time.Time) (controlstate.CompanyAdmissionPage, error)
	DecideCompanyAdmission(context.Context, controlstate.ControlPrincipal, string, string, int64, string, time.Time) error
	CreateCompanyLoginIntent(context.Context, string, string, string, string, time.Time) (controlstate.CompanyLoginIntent, error)
	ResolveCompanyLoginIntent(context.Context, string, string, time.Time) (controlstate.CompanyLoginIntent, error)
}

func (h *handler) companyStore(w http.ResponseWriter) (companyAccessStore, bool) {
	s, ok := h.store.(companyAccessStore)
	if !ok {
		writeProblem(w, 503, authorityv1.Unavailable, "company authority is unavailable")
	}
	return s, ok
}

func companyError(w http.ResponseWriter, operation string, err error) {
	if errors.Is(err, controlstate.ErrControlIdentity) {
		writeProblem(w, 404, authorityv1.NotFound, "OIDC account identity not found")
		return
	}
	if errors.Is(err, controlstate.ErrControlAuthentication) || errors.Is(err, controlstate.ErrOIDCAssertionReplay) || errors.Is(err, oidcauth.ErrUnauthenticated) {
		writeBearerProblem(w)
		return
	}
	if errors.Is(err, oidcauth.ErrUnavailable) {
		writeAuthenticationUnavailable(w, operation, err)
		return
	}
	writeControlStateProblem(w, operation, err)
}

func companyOIDCIdentity(i oidcauth.Identity) controlstate.OIDCIdentity {
	return controlstate.OIDCIdentity{Issuer: i.Issuer, Subject: i.Subject, DisplayName: i.DisplayName, NormalizedEmail: i.NormalizedEmail, EmailVerified: i.EmailVerified, AssertionDigest: i.AssertionDigest, AssertionID: i.AssertionID, AssertionExpiry: i.ExpiresAt, TeamContexts: i.TeamContexts, Nonce: i.Nonce, ClientID: i.ClientID, IssuedAt: i.IssuedAt, AuthenticatedAt: i.AuthenticatedAt, TenantID: i.TenantID, HostedDomain: i.HostedDomain, Groups: i.Groups}
}

func (h *handler) companyOwner(w http.ResponseWriter, r *http.Request, body any) (companyAccessStore, bool) {
	i, nonce, ok := h.verifiedHumanRequest(w, r, body, controlstate.CompanyActorNonce, true)
	if !ok {
		return nil, false
	}
	s, ok := h.companyStore(w)
	if !ok {
		return nil, false
	}
	*r = *r.WithContext(controlstate.WithCompanyActorProof(r.Context(), companyOIDCIdentity(i), nonce))
	w.Header().Set("Cache-Control", "no-store")
	return s, true
}

func (h *handler) ReadCompanyConnections(w http.ResponseWriter, r *http.Request, team string, _ authorityv1.ReadCompanyConnectionsParams) {
	s, ok := h.companyOwner(w, r, nil)
	if !ok {
		return
	}
	result, err := s.ReadCompanyConnections(r.Context(), controlstate.ControlPrincipal{}, team, time.Now())
	if err != nil {
		companyError(w, "read company connections", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) BeginIdentityConnectionSetup(w http.ResponseWriter, r *http.Request, team string, _ authorityv1.BeginIdentityConnectionSetupParams) {
	var body authorityv1.CreateIdentityConnectionRequest
	s, ok := h.companyOwner(w, r, &body)
	if !ok {
		return
	}
	request := controlstate.CreateIdentityConnectionRequest{TeamID: team, Issuer: h.config.OIDCIssuer, SourceID: body.SourceId, Admission: string(body.Admission)}
	if body.ReplaceId != nil {
		request.ReplaceID = *body.ReplaceId
	}
	if body.ExpectedRevision != nil {
		request.ExpectedRevision = *body.ExpectedRevision
	}
	result, err := s.BeginIdentityConnectionSetup(r.Context(), controlstate.ControlPrincipal{}, request, time.Now())
	if err != nil {
		companyError(w, "begin company setup", err)
		return
	}
	writeJSON(w, 201, result)
}

func (h *handler) ActivateIdentityConnection(w http.ResponseWriter, r *http.Request, team, id string, _ authorityv1.ActivateIdentityConnectionParams) {
	var body authorityv1.ActivateIdentityConnectionJSONBody
	s, ok := h.companyOwner(w, r, &body)
	if !ok {
		return
	}
	result, err := s.ActivateIdentityConnection(r.Context(), controlstate.ControlPrincipal{}, team, id, body.SetupToken, body.ExpectedRevision, controlstate.OIDCIdentity{}, time.Now())
	if err != nil {
		companyError(w, "activate company connection", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) DisconnectIdentityConnection(w http.ResponseWriter, r *http.Request, team, id string, _ authorityv1.DisconnectIdentityConnectionParams) {
	var body authorityv1.DisconnectIdentityConnectionJSONBody
	s, ok := h.companyOwner(w, r, &body)
	if !ok {
		return
	}
	if err := s.DisconnectIdentityConnection(r.Context(), controlstate.ControlPrincipal{}, team, id, body.ExpectedRevision, time.Now()); err != nil {
		companyError(w, "disconnect company connection", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) RotateCompanyProvisioningToken(w http.ResponseWriter, r *http.Request, team, id string, _ authorityv1.RotateCompanyProvisioningTokenParams) {
	var body authorityv1.RotateCompanyProvisioningTokenJSONBody
	s, ok := h.companyOwner(w, r, &body)
	if !ok {
		return
	}
	result, err := s.RotateCompanyProvisioningToken(r.Context(), controlstate.ControlPrincipal{}, team, id, body.ExpectedRevision, time.Now())
	if err != nil {
		companyError(w, "rotate company provisioning token", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) ProvisionCompanyEligibility(w http.ResponseWriter, r *http.Request, params authorityv1.ProvisionCompanyEligibilityParams) {
	if !h.authenticateWebService(w, r) {
		return
	}
	s, ok := h.companyStore(w)
	if !ok {
		return
	}
	var body authorityv1.CompanyEligibilityRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid eligibility delta")
		return
	}
	identity, err := s.ResolveCompanyAccount(r.Context(), h.config.OIDCIssuer, body.AccountSubject)
	if err != nil {
		companyError(w, "resolve company account", err)
		return
	}
	err = s.ProvisionCompanyEligibility(r.Context(), params.XTnlProvisioningToken, controlstate.ProvisionCompanyEligibilityRequest{TeamID: body.TeamId, IdentityConnectionID: body.IdentityConnectionId, ConnectionRevision: body.ConnectionRevision, IdentityID: identity, Subject: body.Subject, Revision: body.Revision, Eligible: body.Eligible, ValidUntil: body.ValidUntil, MemberSlug: body.MemberSlug}, time.Now())
	if err != nil {
		companyError(w, "provision company eligibility", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) SetCompanyMembershipDecision(w http.ResponseWriter, r *http.Request, team, member string, _ authorityv1.SetCompanyMembershipDecisionParams) {
	var body authorityv1.SetCompanyMembershipDecisionJSONBody
	s, ok := h.companyOwner(w, r, &body)
	if !ok {
		return
	}
	if err := s.SetCompanyMembershipDecision(r.Context(), controlstate.ControlPrincipal{}, team, member, body.Suspended, body.PersonalAccountException, false, time.Now()); err != nil {
		companyError(w, "company membership decision", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) SetCompanyInvitationException(w http.ResponseWriter, r *http.Request, team, invitation string, _ authorityv1.SetCompanyInvitationExceptionParams) {
	var body authorityv1.SetCompanyInvitationExceptionJSONBody
	s, ok := h.companyOwner(w, r, &body)
	if !ok {
		return
	}
	if err := s.SetCompanyInvitationException(r.Context(), controlstate.ControlPrincipal{}, team, invitation, body.PersonalAccountException, time.Now()); err != nil {
		companyError(w, "company invitation exception", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) ListCompanyAdmissions(w http.ResponseWriter, r *http.Request, team string, params authorityv1.ListCompanyAdmissionsParams) {
	s, ok := h.companyOwner(w, r, nil)
	if !ok {
		return
	}
	after := ""
	if params.Cursor != nil {
		after = *params.Cursor
	}
	result, err := s.ListCompanyAdmissions(r.Context(), controlstate.ControlPrincipal{}, team, after, time.Now())
	if err != nil {
		companyError(w, "list company admissions", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) DecideCompanyAdmission(w http.ResponseWriter, r *http.Request, team, id string, _ authorityv1.DecideCompanyAdmissionParams) {
	var body authorityv1.DecideCompanyAdmissionJSONBody
	s, ok := h.companyOwner(w, r, &body)
	if !ok {
		return
	}
	if err := s.DecideCompanyAdmission(r.Context(), controlstate.ControlPrincipal{}, team, id, body.ConnectionRevision, string(body.Decision), time.Now()); err != nil {
		companyError(w, "decide company admission", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) RequestCompanyAdmission(w http.ResponseWriter, r *http.Request) {
	p, ok := h.authenticateControlRequest(w, r)
	if !ok {
		return
	}
	s, ok := h.companyStore(w)
	if !ok {
		return
	}
	var body authorityv1.RequestCompanyAdmissionJSONBody
	if err := decodeJSON(w, r, &body); err != nil {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid admission request")
		return
	}
	result, err := s.RequestCompanyAdmission(r.Context(), p, body.TeamId, body.IdentityConnectionId, body.ConnectionRevision, body.MemberSlug, time.Now())
	if err != nil {
		companyError(w, "request company admission", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) CreateCompanyLoginIntent(w http.ResponseWriter, r *http.Request) {
	s, ok := h.companyStore(w)
	if !ok {
		return
	}
	var body authorityv1.CreateCompanyLoginIntentJSONBody
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid company login selection")
		return
	}
	if h.config.OIDCVerifier == nil || h.config.OIDCClientID == "" || h.config.ControlURL == "" {
		writeAuthenticationUnavailable(w, "create company login intent", nil)
		return
	}
	result, err := s.CreateCompanyLoginIntent(r.Context(), body.TeamId, h.config.OIDCIssuer, h.config.OIDCClientID, h.config.ControlURL+"/v1/auth/device/callback", time.Now())
	if err != nil {
		companyError(w, "create company login intent", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, result)
}

func (h *handler) ResolveCompanyLoginIntent(w http.ResponseWriter, r *http.Request, id string) {
	s, ok := h.companyStore(w)
	if !ok {
		return
	}
	var body authorityv1.CompanyIntentCredential
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid company login binding")
		return
	}
	result, err := s.ResolveCompanyLoginIntent(r.Context(), id, body.BindingToken, time.Now())
	if err != nil {
		companyError(w, "resolve company login intent", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, result)
}

func (h *handler) RecoverCompanyOwner(w http.ResponseWriter, r *http.Request) {
	p, ok := h.authenticateControlRequest(w, r)
	if !ok {
		return
	}
	s, ok := h.companyStore(w)
	if !ok {
		return
	}
	var body authorityv1.RecoverCompanyOwnerJSONBody
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid recovery request")
		return
	}
	if err := s.SetCompanyMembershipDecision(r.Context(), p, body.TeamId, body.MembershipId, false, true, true, time.Now()); err != nil {
		companyError(w, "recover company owner", err)
		return
	}
	w.WriteHeader(204)
}
