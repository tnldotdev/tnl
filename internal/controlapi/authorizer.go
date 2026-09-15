package controlapi

import (
	"context"
	"errors"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type localAuthorizer struct {
	store          BuiltinAuthorizationStore
	sourceRevision int64
	dnsAutomation  bool
}

type routeReadPrincipal struct {
	identityID    string
	teamIDs       map[string]struct{}
	administrator bool
}

type routeAuthorizer interface {
	authorization.Authorizer
	AuthorizeRouteReads(context.Context, string) (routeReadPrincipal, error)
}

func (a localAuthorizer) AuthorizeRouteReads(ctx context.Context, accessToken string) (routeReadPrincipal, error) {
	principal, err := a.store.AuthenticateAccessToken(
		ctx, credentials.AccessToken(accessToken), a.sourceRevision, time.Now(),
	)
	if errors.Is(err, controlstate.ErrControlAuthentication) {
		return routeReadPrincipal{}, authorization.ErrUnauthenticated
	}
	if err != nil {
		return routeReadPrincipal{}, authorization.ErrUnavailable
	}
	identity, err := a.store.IdentityContext(ctx, principal.IdentityID)
	if err != nil {
		return routeReadPrincipal{}, authorization.ErrUnavailable
	}
	teamIDs := make(map[string]struct{}, len(identity.Memberships))
	for _, membership := range identity.Memberships {
		teamIDs[membership.TeamID] = struct{}{}
	}
	return routeReadPrincipal{
		identityID: principal.IdentityID, teamIDs: teamIDs, administrator: principal.Administrator,
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
		return authorization.Decision{}, authorization.ErrUnavailable
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
	if domain.ID == "" || domain.State != "ready" && request.Operation != authorization.OperationRouteDelete {
		return authorization.Decision{}, authorization.ErrForbidden
	}
	routeMembershipID := request.RouteMembershipID
	if request.RouteScope == string(controlv1.Member) {
		if routeMembershipID == "" {
			if request.Operation == authorization.OperationRouteCreate {
				routeMembershipID = acting.ID
			} else {
				return authorization.Decision{}, authorization.ErrForbidden
			}
		}
		if routeMembershipID != acting.ID && (request.Operation != authorization.OperationRouteDelete ||
			acting.Role != "admin" && acting.Role != "owner") {
			return authorization.Decision{}, authorization.ErrForbidden
		}
	} else if request.RouteScope != string(controlv1.Shared) || routeMembershipID != "" ||
		acting.Role != "admin" && acting.Role != "owner" {
		return authorization.Decision{}, authorization.ErrForbidden
	}
	decision := authorization.Decision{
		IdentityID: principal.IdentityID, TeamID: request.TeamID, ActingMembershipID: acting.ID,
		ActingRole: acting.Role, RouteMembershipID: routeMembershipID,
		TeamPolicyRevision: uint64(acting.PolicyRevision), DomainID: request.DomainID,
		CanonicalHostname: request.CanonicalHostname, RouteScope: request.RouteScope,
		DNSAuthorityReference: domain.DNSAuthorityReference, RetrySecret: principal.RetrySecret,
	}
	if request.Operation == authorization.OperationRouteSessionCreate {
		decision.CertificatePlan = &authorization.CertificatePlan{
			CacheKey: request.CanonicalHostname, Scope: request.CanonicalHostname,
			Identifiers: []string{request.CanonicalHostname}, ChallengeMethod: string(controlv1.TlsAlpn01),
		}
		if a.dnsAutomation {
			plan := decision.CertificatePlan
			plan.ChallengeMethod = string(controlv1.Dns01)
			if request.RouteScope == string(controlv1.Member) {
				label := acting.MemberSlug
				if domain.Kind == "managed" {
					label = acting.ManagedLabel
				}
				namespace := label + "." + domain.CanonicalDomain
				plan.CacheKey, plan.Scope = namespace, namespace
				plan.Identifiers = []string{"*." + namespace, namespace}
			}
		}
	}
	return decision, nil
}

type hostedAuthorizer struct {
	client *authorityclient.Client
	secret string
	store  externalPrincipalStore
}

type externalPrincipalStore interface {
	EnsureExternalAuthorityPrincipal(context.Context, string, time.Time) ([32]byte, error)
}

func (a hostedAuthorizer) AuthorizeRouteReads(ctx context.Context, accessToken string) (routeReadPrincipal, error) {
	identity, err := a.client.IdentityContextWithAccessToken(ctx, credentials.AccessToken(accessToken))
	if err != nil {
		return routeReadPrincipal{}, hostedAuthorizationError(err)
	}
	if identity.Identity.Id == "" {
		return routeReadPrincipal{}, authorization.ErrUnavailable
	}
	teamIDs := make(map[string]struct{}, len(identity.Memberships))
	for _, membership := range identity.Memberships {
		if membership.TeamId == "" {
			return routeReadPrincipal{}, authorization.ErrUnavailable
		}
		teamIDs[membership.TeamId] = struct{}{}
	}
	if a.store != nil {
		if _, err := a.store.EnsureExternalAuthorityPrincipal(ctx, identity.Identity.Id, time.Now()); err != nil {
			return routeReadPrincipal{}, authorization.ErrUnavailable
		}
	}
	return routeReadPrincipal{
		identityID: identity.Identity.Id, teamIDs: teamIDs,
		administrator: identity.Identity.Administrator,
	}, nil
}

func (a hostedAuthorizer) Authorize(ctx context.Context, request authorization.Request) (authorization.Decision, error) {
	body := authorityv1.ServiceAuthorizationRequest{
		AccessToken: request.AccessToken, Operation: authorityv1.AuthorizationOperation(request.Operation),
		TeamId: request.TeamID, DomainId: request.DomainID, CanonicalHostname: request.CanonicalHostname,
		RouteScope: authorityv1.RouteScope(request.RouteScope), Target: request.Target,
		AllowedIpPrefixes: slices.Clone(request.AllowedIPPrefixes), Ephemeral: request.Ephemeral,
	}
	if body.AllowedIpPrefixes == nil {
		body.AllowedIpPrefixes = []string{}
	}
	if request.ActingMembershipID != "" {
		body.ActingMembershipId = &request.ActingMembershipID
	}
	if request.RouteMembershipID != "" {
		body.RouteMembershipId = &request.RouteMembershipID
	}
	if request.RouteID != "" {
		body.RouteId = &request.RouteID
	}
	if request.RouteVersion != 0 {
		if request.RouteVersion > math.MaxInt64 {
			return authorization.Decision{}, authorization.ErrForbidden
		}
		value := int64(request.RouteVersion)
		body.RouteVersion = &value
	}
	if request.RouteMutationRevision != 0 {
		if request.RouteMutationRevision > math.MaxInt64 {
			return authorization.Decision{}, authorization.ErrForbidden
		}
		value := int64(request.RouteMutationRevision)
		body.RouteMutationRevision = &value
	}
	wire, err := a.client.AuthorizeServiceOperation(ctx, a.secret, body)
	if err != nil {
		return authorization.Decision{}, hostedAuthorizationError(err)
	}
	decision := authorization.Decision{
		IdentityID: wire.IdentityId, TeamID: wire.TeamId, ActingMembershipID: wire.ActingMembershipId,
		ActingRole: string(wire.ActingRole), TeamPolicyRevision: uint64(wire.TeamPolicyRevision),
		DomainID: wire.DomainId, CanonicalHostname: wire.CanonicalHostname, RouteScope: string(wire.RouteScope),
		DNSAuthorityReference: wire.DnsAuthorityReference,
	}
	if wire.RouteMembershipId != nil {
		decision.RouteMembershipID = *wire.RouteMembershipId
	}
	if wire.CertificatePlan != nil {
		decision.CertificatePlan = &authorization.CertificatePlan{
			CacheKey: wire.CertificatePlan.CacheKey, Scope: wire.CertificatePlan.Scope,
			Identifiers:     slices.Clone(wire.CertificatePlan.Identifiers),
			ChallengeMethod: string(wire.CertificatePlan.ChallengeMethod),
		}
	}
	if !validAuthorizationDecision(request, decision) {
		return authorization.Decision{}, authorization.ErrUnavailable
	}
	decision.RetrySecret, err = a.store.EnsureExternalAuthorityPrincipal(ctx, decision.IdentityID, time.Now())
	if err != nil {
		return authorization.Decision{}, authorization.ErrUnavailable
	}
	return decision, nil
}

func validAuthorizationDecision(request authorization.Request, decision authorization.Decision) bool {
	if decision.IdentityID == "" || decision.TeamID != request.TeamID || decision.ActingMembershipID == "" ||
		decision.ActingRole != "member" && decision.ActingRole != "admin" && decision.ActingRole != "owner" ||
		decision.TeamPolicyRevision == 0 || decision.DomainID != request.DomainID ||
		decision.CanonicalHostname != request.CanonicalHostname || decision.RouteScope != request.RouteScope ||
		strings.TrimSpace(decision.DNSAuthorityReference) == "" {
		return false
	}
	if request.ActingMembershipID != "" && decision.ActingMembershipID != request.ActingMembershipID ||
		request.RouteMembershipID != "" && decision.RouteMembershipID != request.RouteMembershipID ||
		request.RouteScope == string(controlv1.Member) && decision.RouteMembershipID == "" ||
		request.RouteScope == string(controlv1.Shared) && decision.RouteMembershipID != "" {
		return false
	}
	if request.Operation == authorization.OperationRouteSessionCreate {
		return decision.CertificatePlan != nil && decision.CertificatePlan.CacheKey != "" &&
			decision.CertificatePlan.Scope != "" && len(decision.CertificatePlan.Identifiers) != 0 &&
			(decision.CertificatePlan.ChallengeMethod == string(controlv1.Dns01) ||
				decision.CertificatePlan.ChallengeMethod == string(controlv1.TlsAlpn01))
	}
	return decision.CertificatePlan == nil
}

func hostedAuthorizationError(err error) error {
	if errors.Is(err, authorityclient.ErrUnauthenticated) {
		return authorization.ErrUnauthenticated
	}
	if errors.Is(err, authorityclient.ErrUnavailable) || errors.Is(err, authorityclient.ErrRateLimited) {
		return authorization.ErrUnavailable
	}
	var problem *authorityclient.ProblemError
	if errors.As(err, &problem) && (problem.Status == http.StatusForbidden || problem.Status == http.StatusNotFound) {
		return authorization.ErrForbidden
	}
	return authorization.ErrUnavailable
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
	case errors.Is(err, authorization.ErrUnauthenticated):
		writeBearerProblem(response)
	case errors.Is(err, authorization.ErrForbidden):
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "operation is not authorized")
	case err != nil:
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authorization is unavailable")
	default:
		return decision, true
	}
	return authorization.Decision{}, false
}

func (h *handler) authorizeExistingRouteMutation(
	response http.ResponseWriter,
	request *http.Request,
	principal routeReadPrincipal,
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
) (routeReadPrincipal, bool) {
	token, ok := requestBearerToken(request)
	if !ok {
		writeBearerProblem(response)
		return routeReadPrincipal{}, false
	}
	if h.authorizer == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authorization is unavailable")
		return routeReadPrincipal{}, false
	}
	principal, err := h.authorizer.AuthorizeRouteReads(request.Context(), token)
	switch {
	case errors.Is(err, authorization.ErrUnauthenticated):
		writeBearerProblem(response)
	case errors.Is(err, authorization.ErrForbidden):
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "operation is not authorized")
	case err != nil:
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authorization is unavailable")
	default:
		return principal, true
	}
	return routeReadPrincipal{}, false
}
