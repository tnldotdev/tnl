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
	store          localAuthorizationStore
	sourceRevision int64
}

type localAuthorizationStore interface {
	AuthenticateAccessToken(context.Context, credentials.AccessToken, int64, time.Time) (controlstate.ControlPrincipal, error)
	IdentityContext(context.Context, string) (controlstate.IdentityContext, error)
	ListTeamDomains(context.Context, string, string) ([]controlstate.Domain, error)
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
	if domain.ID == "" || domain.State != "ready" {
		return authorization.Decision{}, authorization.ErrForbidden
	}
	routeMembershipID := request.RouteMembershipID
	if request.RouteScope == string(controlv1.Member) {
		if routeMembershipID == "" {
			routeMembershipID = acting.ID
		}
		if routeMembershipID != acting.ID {
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

func (a hostedAuthorizer) Authorize(ctx context.Context, request authorization.Request) (authorization.Decision, error) {
	body := authorityv1.ServiceAuthorizationRequest{
		AccessToken: request.AccessToken, Operation: authorityv1.AuthorizationOperation(request.Operation),
		TeamId: request.TeamID, DomainId: request.DomainID, CanonicalHostname: request.CanonicalHostname,
		RouteScope: authorityv1.RouteScope(request.RouteScope), Target: request.Target,
		AllowedIpPrefixes: slices.Clone(request.AllowedIPPrefixes),
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
