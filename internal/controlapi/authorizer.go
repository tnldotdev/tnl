package controlapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/operatorlog"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type localAuthorizer struct {
	store                             AuthorizationStore
	sourceRevision                    int64
	dnsAutomation                     bool
	managedDomainMaxMemberChildLabels int
	managedURLMode                    naming.ManagedURLMode
}

type publicURLReadPrincipal struct {
	identityID    string
	displayName   string
	teamIDs       map[string]struct{}
	administrator bool
}

type publicURLAuthorizer interface {
	authorization.Authorizer
	AuthorizePublicURLReads(context.Context, string) (publicURLReadPrincipal, error)
}

func (a localAuthorizer) AuthorizePublicURLReads(ctx context.Context, accessToken string) (publicURLReadPrincipal, error) {
	principal, err := a.store.AuthenticateAccessToken(
		ctx, credentials.AccessToken(accessToken), a.sourceRevision, time.Now(),
	)
	if errors.Is(err, controlstate.ErrControlAuthentication) {
		return publicURLReadPrincipal{}, authorization.ErrUnauthenticated
	}
	if err != nil {
		return publicURLReadPrincipal{}, errors.Join(authorization.ErrUnavailable, err)
	}
	identity, err := a.store.IdentityContext(ctx, principal.IdentityID)
	if err != nil {
		return publicURLReadPrincipal{}, authorization.ErrUnavailable
	}
	teamIDs := make(map[string]struct{}, len(identity.Memberships))
	for _, membership := range identity.Memberships {
		teamIDs[membership.TeamID] = struct{}{}
	}
	return publicURLReadPrincipal{
		identityID: principal.IdentityID, displayName: identity.Identity.DisplayName, teamIDs: teamIDs, administrator: principal.Administrator,
	}, nil
}

func (a localAuthorizer) Authorize(ctx context.Context, request authorization.Request) (authorization.Decision, error) {
	principal, err := a.store.AuthenticateAccessToken(
		ctx, credentials.AccessToken(request.AccessToken), a.sourceRevision, time.Now(),
	)
	if errors.Is(err, controlstate.ErrControlAuthentication) {
		return authorization.Decision{}, authorization.ErrUnauthenticated
	}
	if err != nil {
		return authorization.Decision{}, errors.Join(authorization.ErrUnavailable, err)
	}
	identity, err := a.store.IdentityContext(ctx, principal.IdentityID)
	if err != nil {
		return authorization.Decision{}, authorization.ErrUnavailable
	}
	var acting controlstate.Membership
	for _, membership := range identity.Memberships {
		if membership.TeamID == request.TeamID &&
			(request.ActingMembershipID == "" || membership.ID == request.ActingMembershipID) {
			acting = membership
			break
		}
	}
	if acting.ID == "" {
		return authorization.Decision{}, authorization.ErrForbidden
	}
	if request.Operation == authorization.OperationCredentialRevoke {
		if request.PublicURLMembershipID != acting.ID && acting.Role != controlstate.TeamRoleAdmin && acting.Role != controlstate.TeamRoleOwner {
			return authorization.Decision{}, authorization.ErrForbidden
		}
		return authorization.Decision{IdentityID: principal.IdentityID, TeamID: request.TeamID,
			ActingMembershipID: acting.ID, ActingRole: string(acting.Role), PolicyRevision: uint64(acting.PolicyRevision)}, nil
	}
	if request.Operation == authorization.OperationFeedbackManage || request.Operation == authorization.OperationPreviewVisit {
		if request.PublicURLID == "" || request.PublicURLMutationRevision == 0 {
			return authorization.Decision{}, authorization.ErrForbidden
		}
		if request.PublicURLScope == authorization.PublicURLScopeMember && (request.PublicURLMembershipID == "" || request.Operation != authorization.OperationPreviewVisit && request.PublicURLMembershipID != acting.ID) ||
			request.PublicURLScope == authorization.PublicURLScopeShared && (request.PublicURLMembershipID != "" || request.Operation != authorization.OperationPreviewVisit && acting.Role != controlstate.TeamRoleAdmin && acting.Role != controlstate.TeamRoleOwner) || !request.PublicURLScope.Valid() {
			return authorization.Decision{}, authorization.ErrForbidden
		}
		return authorization.Decision{IdentityID: principal.IdentityID, TeamID: request.TeamID, ActingMembershipID: acting.ID, ActingRole: string(acting.Role), PublicURLMembershipID: request.PublicURLMembershipID,
			PolicyRevision: uint64(acting.PolicyRevision), DomainID: request.DomainID, CanonicalHostname: request.CanonicalHostname, PublicURLScope: request.PublicURLScope, RetrySecret: principal.RetrySecret}, nil
	}
	domains, err := a.store.ListTeamDomains(ctx, principal.IdentityID, request.TeamID)
	if err != nil {
		return authorization.Decision{}, authorization.ErrUnavailable
	}
	var domain controlstate.Domain
	for _, candidate := range domains {
		if candidate.ID == request.DomainID {
			domain = candidate
			break
		}
	}
	if domain.ID == "" || domain.State != controlstate.DomainReady && request.Operation != authorization.OperationPublicURLDelete {
		return authorization.Decision{}, authorization.ErrForbidden
	}
	publicURLMembershipID := request.PublicURLMembershipID
	if request.PublicURLScope == authorization.PublicURLScopeMember {
		if publicURLMembershipID == "" {
			if request.Operation == authorization.OperationPublicURLCreate || request.Operation == authorization.OperationCredentialCreate {
				publicURLMembershipID = acting.ID
			} else {
				return authorization.Decision{}, authorization.ErrForbidden
			}
		}
		if publicURLMembershipID != acting.ID && (request.Operation != authorization.OperationPublicURLDelete ||
			acting.Role != controlstate.TeamRoleAdmin && acting.Role != controlstate.TeamRoleOwner) {
			return authorization.Decision{}, authorization.ErrForbidden
		}
	} else if request.PublicURLScope != authorization.PublicURLScopeShared || publicURLMembershipID != "" ||
		acting.Role != controlstate.TeamRoleAdmin && acting.Role != controlstate.TeamRoleOwner {
		return authorization.Decision{}, authorization.ErrForbidden
	}
	decision := authorization.Decision{
		IdentityID: principal.IdentityID, TeamID: request.TeamID, ActingMembershipID: acting.ID,
		ActingRole: string(acting.Role), PublicURLMembershipID: publicURLMembershipID,
		PolicyRevision: uint64(acting.PolicyRevision), DomainID: request.DomainID,
		CanonicalHostname: request.CanonicalHostname, PublicURLScope: request.PublicURLScope,
		DNSAuthorityReference: domain.DNSAuthorityReference, RetrySecret: principal.RetrySecret,
	}
	namespace, direct := naming.PublicURLNamespace(naming.NamespaceFacts{
		Domain: domain.CanonicalDomain, Managed: domain.Kind == controlstate.DomainKindManaged,
		Mode: a.managedURLMode, Personal: acting.TeamKind == controlstate.TeamKindPersonal,
		Builtin:  principal.Administrator && acting.TeamKind == controlstate.TeamKindPersonal,
		TeamName: acting.TeamDisplayName, MemberSlug: acting.MemberSlug, ManagedLabel: acting.ManagedLabel,
	})
	if request.PublicURLScope == authorization.PublicURLScopeShared {
		namespace = domain.CanonicalDomain
	}
	decision.Namespace = namespace
	if request.PublicURLScope == authorization.PublicURLScopeMember &&
		(request.Operation == authorization.OperationPublicURLCreate || request.Operation == authorization.OperationPublishRunCreate) {
		depth, within := naming.ChildDepth(request.CanonicalHostname, namespace)
		if direct || !within || depth == 0 {
			return authorization.Decision{}, authorization.ErrForbidden
		}
		if domain.Kind == controlstate.DomainKindManaged && a.managedDomainMaxMemberChildLabels > 0 && depth > a.managedDomainMaxMemberChildLabels {
			return authorization.Decision{}, errMemberHostnameDepth
		}
	}
	if request.Operation == authorization.OperationPublishRunCreate {
		decision.CertificatePlan = authorization.PublicURLCertificatePlan(request.CanonicalHostname, namespace,
			domain.Kind == controlstate.DomainKindCustom && request.PublicURLScope == authorization.PublicURLScopeShared, a.dnsAutomation)
	}
	if request.Operation == authorization.OperationCredentialCreate {
		decision.CertificatePlan = authorization.PublicURLCertificatePlan("eph-aaaaaaaaaaaaaaaaaaaaaaaaaa."+namespace, namespace,
			domain.Kind == controlstate.DomainKindCustom && request.PublicURLScope == authorization.PublicURLScopeShared, a.dnsAutomation)
	}
	return decision, nil
}

func (h *handler) authorizeMutation(
	response http.ResponseWriter,
	request *http.Request,
	operation authorization.Request,
) (authorization.Decision, bool) {
	token, ok := requestBearerToken(request)
	if !ok {
		writeBearerProblem(response)
		return authorization.Decision{}, false
	}
	operation.AccessToken = token
	if h.authorizer == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authorization is unavailable")
		return authorization.Decision{}, false
	}
	decision, err := h.authorizer.Authorize(request.Context(), operation)
	switch {
	case errors.Is(err, errMemberHostnameDepth):
		writeProblem(response, http.StatusForbidden, controlv1.MemberHostnameDepthExceeded,
			"this hostname exceeds the server's member URL depth limit on its managed domain; use fewer labels beneath your namespace")
	case errors.Is(err, authorization.ErrUnauthenticated):
		writeBearerProblem(response)
	case errors.Is(err, controlstate.ErrGuestTrialSpent):
		writeProblem(response, http.StatusForbidden, controlv1.GuestTrialExhausted, "guest demo trial ended; run tnl auth login to continue")
	case errors.Is(err, authorization.ErrGuestDemoOnly):
		writeProblem(response, http.StatusForbidden, controlv1.GuestDemoOnly, "guest access only publishes the built-in demo; run tnl auth login for your own app or settings")
	case errors.Is(err, authorization.ErrGuestIPChanged):
		writeProblem(response, http.StatusForbidden, controlv1.GuestIpChanged, "your IP changed since this guest trial started; run tnl auth login to continue")
	case errors.Is(err, authorization.ErrForbidden):
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "operation is not authorized")
	case err != nil:
		requestID := writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authorization is unavailable")
		operatorlog.Report("authorize public URL mutation", failure.ServerAPIInternal, requestID, err)
	default:
		return decision, true
	}
	return authorization.Decision{}, false
}

func (h *handler) authorizeExistingRouteMutation(
	response http.ResponseWriter,
	request *http.Request,
	principal publicURLReadPrincipal,
	operation authorization.Request,
) (authorization.Decision, bool) {
	if _, authorized := principal.teamIDs[operation.TeamID]; !authorized {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return authorization.Decision{}, false
	}
	return h.authorizeMutation(response, request, operation)
}

func (h *handler) authorizeRouteReads(
	response http.ResponseWriter,
	request *http.Request,
) (publicURLReadPrincipal, bool) {
	token, ok := requestBearerToken(request)
	if !ok {
		writeBearerProblem(response)
		return publicURLReadPrincipal{}, false
	}
	if h.authorizer == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authorization is unavailable")
		return publicURLReadPrincipal{}, false
	}
	principal, err := h.authorizer.AuthorizePublicURLReads(request.Context(), token)
	switch {
	case errors.Is(err, authorization.ErrUnauthenticated):
		writeBearerProblem(response)
	case errors.Is(err, authorization.ErrForbidden):
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "operation is not authorized")
	case err != nil:
		requestID := writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authorization is unavailable")
		operatorlog.Report("authorize public URL reads", failure.ServerAPIInternal, requestID, err)
	default:
		return principal, true
	}
	return publicURLReadPrincipal{}, false
}
