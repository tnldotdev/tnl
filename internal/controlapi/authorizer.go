package controlapi

import (
	"context"
	"errors"
	"log"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
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

type publicURLReadPrincipal struct {
	identityID    string
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
			if request.Operation == authorization.OperationPublicURLCreate {
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
	if request.Operation == authorization.OperationPublishRunCreate {
		decision.CertificatePlan = &authorization.CertificatePlan{
			CacheKey: request.CanonicalHostname, Scope: request.CanonicalHostname,
			Identifiers: []string{request.CanonicalHostname}, ChallengeMethod: certificateidentity.ChallengeTLSALPN01,
		}
		if a.dnsAutomation {
			plan := decision.CertificatePlan
			plan.ChallengeMethod = certificateidentity.ChallengeDNS01
			if request.PublicURLScope == authorization.PublicURLScopeMember {
				label := acting.MemberSlug
				if domain.Kind == controlstate.DomainKindManaged {
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

func (a hostedAuthorizer) AuthorizePublicURLReads(ctx context.Context, accessToken string) (publicURLReadPrincipal, error) {
	identity, err := a.client.IdentityContextWithAccessToken(ctx, credentials.AccessToken(accessToken))
	if err != nil {
		return publicURLReadPrincipal{}, hostedAuthorizationError(err)
	}
	if identity.Identity.Id == "" {
		return publicURLReadPrincipal{}, authorization.ErrUnavailable
	}
	teamIDs := make(map[string]struct{}, len(identity.Memberships))
	for _, membership := range identity.Memberships {
		if membership.TeamId == "" {
			return publicURLReadPrincipal{}, authorization.ErrUnavailable
		}
		teamIDs[membership.TeamId] = struct{}{}
	}
	if a.store != nil {
		if _, err := a.store.EnsureExternalAuthorityPrincipal(ctx, identity.Identity.Id, time.Now()); err != nil {
			return publicURLReadPrincipal{}, authorization.ErrUnavailable
		}
	}
	return publicURLReadPrincipal{
		identityID: identity.Identity.Id, teamIDs: teamIDs,
		administrator: identity.Identity.Administrator,
	}, nil
}

func (a hostedAuthorizer) Authorize(ctx context.Context, request authorization.Request) (authorization.Decision, error) {
	if !request.PublicURLScope.Valid() {
		return authorization.Decision{}, authorization.ErrForbidden
	}
	body := authorityv1.ServiceAuthorizationRequest{
		AccessToken: request.AccessToken, Operation: authorityv1.AuthorizationOperation(request.Operation),
		TeamId: request.TeamID, DomainId: request.DomainID, CanonicalHostname: request.CanonicalHostname,
		PublicUrlScope: authorityv1.PublicURLScope(request.PublicURLScope), Target: request.Target,
		AllowedIpPrefixes: slices.Clone(request.AllowedIPPrefixes), Ephemeral: request.Ephemeral,
	}
	if body.AllowedIpPrefixes == nil {
		body.AllowedIpPrefixes = []string{}
	}
	if request.ActingMembershipID != "" {
		body.ActingMembershipId = &request.ActingMembershipID
	}
	if request.PublicURLMembershipID != "" {
		body.PublicUrlMembershipId = &request.PublicURLMembershipID
	}
	if request.PublicURLID != "" {
		body.PublicUrlId = &request.PublicURLID
	}
	if request.PublishRunNumber != 0 {
		if request.PublishRunNumber > math.MaxInt64 {
			return authorization.Decision{}, authorization.ErrForbidden
		}
		value := int64(request.PublishRunNumber)
		body.PublishRunNumber = &value
	}
	if request.PublicURLMutationRevision != 0 {
		if request.PublicURLMutationRevision > math.MaxInt64 {
			return authorization.Decision{}, authorization.ErrForbidden
		}
		value := int64(request.PublicURLMutationRevision)
		body.PublicUrlMutationRevision = &value
	}
	wire, err := a.client.AuthorizeServiceOperation(ctx, a.secret, body)
	if err != nil {
		return authorization.Decision{}, hostedAuthorizationError(err)
	}
	decision := authorization.Decision{
		IdentityID: wire.IdentityId, TeamID: wire.TeamId, ActingMembershipID: wire.ActingMembershipId,
		ActingRole: string(wire.ActingRole), PolicyRevision: uint64(wire.PolicyRevision),
		DomainID: wire.DomainId, CanonicalHostname: wire.CanonicalHostname, PublicURLScope: authorization.PublicURLScope(wire.PublicUrlScope),
		DNSAuthorityReference: wire.DnsAuthorityReference,
	}
	if wire.PublicUrlMembershipId != nil {
		decision.PublicURLMembershipID = *wire.PublicUrlMembershipId
	}
	if wire.CertificatePlan != nil {
		decision.CertificatePlan = &authorization.CertificatePlan{
			CacheKey: wire.CertificatePlan.CacheKey, Scope: wire.CertificatePlan.Scope,
			Identifiers:     slices.Clone(wire.CertificatePlan.Identifiers),
			ChallengeMethod: certificateidentity.ChallengeMethod(wire.CertificatePlan.ChallengeMethod),
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
		decision.PolicyRevision == 0 || decision.DomainID != request.DomainID ||
		decision.CanonicalHostname != request.CanonicalHostname || !decision.PublicURLScope.Valid() || decision.PublicURLScope != request.PublicURLScope ||
		strings.TrimSpace(decision.DNSAuthorityReference) == "" {
		return false
	}
	if request.ActingMembershipID != "" && decision.ActingMembershipID != request.ActingMembershipID ||
		request.PublicURLMembershipID != "" && decision.PublicURLMembershipID != request.PublicURLMembershipID ||
		request.PublicURLScope == authorization.PublicURLScopeMember && decision.PublicURLMembershipID == "" ||
		request.PublicURLScope == authorization.PublicURLScopeShared && decision.PublicURLMembershipID != "" {
		return false
	}
	if request.Operation == authorization.OperationPublishRunCreate {
		return validHostedCertificatePlan(decision.CertificatePlan, decision.CanonicalHostname)
	}
	return decision.CertificatePlan == nil
}

func validHostedCertificatePlan(plan *authorization.CertificatePlan, hostname string) bool {
	if plan == nil {
		return false
	}
	canonical, err := certificateidentity.CanonicalPlan(controlv1.CertificatePlan{
		CacheKey: plan.CacheKey, Scope: plan.Scope,
		Identifiers: plan.Identifiers, ChallengeMethod: controlv1.CertificateChallengeMethod(plan.ChallengeMethod),
	})
	return err == nil && slices.Equal(canonical.Identifiers, plan.Identifiers) &&
		certificateidentity.Covers(canonical.Identifiers, hostname)
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
	case errors.Is(err, controlstate.ErrGuestTrialSpent):
		writeProblem(response, http.StatusForbidden, controlv1.GuestTrialExhausted, "guest demo trial ended; run tnl login to continue")
	case errors.Is(err, authorization.ErrGuestDemoOnly):
		writeProblem(response, http.StatusForbidden, controlv1.GuestDemoOnly, "guest access only publishes the built-in demo; run tnl login for your own app or settings")
	case errors.Is(err, authorization.ErrForbidden):
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "operation is not authorized")
	case err != nil:
		requestID := writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authorization is unavailable")
		log.Printf("authorize public URL mutation request_id=%s: %v", requestID, err)
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
		log.Printf("authorize public URL reads request_id=%s: %v", requestID, err)
	default:
		return principal, true
	}
	return publicURLReadPrincipal{}, false
}
