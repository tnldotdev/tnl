package authorityapi

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func (h *handler) ExchangeLoginToken(response http.ResponseWriter, request *http.Request) {
	var body authorityv1.LoginTokenExchangeRequest
	if err := decodeJSON(response, request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid request")
		return
	}
	token := credentials.LoginToken(body.LoginToken)
	if h.config.LoginToken == "" || !h.loginVerifier.Matches(token) {
		writeBearerProblem(response)
		return
	}
	if h.store == nil {
		writeAuthenticationUnavailable(response, "exchange login token", nil)
		return
	}
	issued, err := h.store.CreateBuiltinControlSession(
		request.Context(), h.config.ManagedDeploymentDomain, h.loginSourceRevision,
		h.config.AccessTokenLifetime, h.config.RefreshTokenLifetime, time.Now(),
	)
	if err != nil {
		writeAuthenticationUnavailable(response, "exchange login token", err)
		return
	}
	writeJSON(response, http.StatusOK, controlSessionResponse(issued))
}

func (h *handler) ExchangeOIDCToken(response http.ResponseWriter, request *http.Request) {
	var body authorityv1.OIDCTokenExchangeRequest
	if err := decodeJSON(response, request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid request")
		return
	}
	if h.config.OIDCVerifier == nil {
		writeProblem(response, http.StatusNotFound, authorityv1.NotFound, "resource not found")
		return
	}
	if h.store == nil {
		writeAuthenticationUnavailable(response, "exchange OIDC token", nil)
		return
	}
	identity, err := h.config.OIDCVerifier.Verify(request.Context(), body.IdToken)
	if errors.Is(err, oidcauth.ErrUnauthenticated) {
		writeProblem(response, http.StatusUnauthorized, authorityv1.Unauthenticated, "authentication required")
		return
	}
	if errors.Is(err, oidcauth.ErrUnavailable) {
		writeProblem(response, http.StatusServiceUnavailable, authorityv1.Unavailable, "OIDC provider unavailable")
		return
	}
	if err != nil {
		log.Printf("verify OIDC token: %v", err)
		writeProblem(response, http.StatusInternalServerError, authorityv1.Internal, "internal server error")
		return
	}
	issued, err := h.store.CreateOIDCControlSession(request.Context(), h.config.ManagedDeploymentDomain, controlstate.OIDCIdentity{
		Issuer: identity.Issuer, Subject: identity.Subject, DisplayName: identity.DisplayName,
		NormalizedEmail: identity.NormalizedEmail, EmailVerified: identity.EmailVerified,
		AssertionDigest: identity.AssertionDigest, AssertionExpiry: identity.ExpiresAt,
	}, h.config.AccessTokenLifetime, h.config.RefreshTokenLifetime, time.Now())
	if errors.Is(err, controlstate.ErrControlAuthentication) || errors.Is(err, controlstate.ErrOIDCAssertionReplay) {
		writeProblem(response, http.StatusUnauthorized, authorityv1.Unauthenticated, "authentication required")
		return
	}
	if err != nil {
		writeAuthenticationUnavailable(response, "exchange OIDC token", err)
		return
	}
	writeJSON(response, http.StatusOK, controlSessionResponse(issued))
}

func (h *handler) RefreshControlSession(response http.ResponseWriter, request *http.Request) {
	var body authorityv1.RefreshControlSessionRequest
	if err := decodeJSON(response, request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid request")
		return
	}
	if h.store == nil {
		writeAuthenticationUnavailable(response, "refresh control session", nil)
		return
	}
	issued, err := h.store.RefreshControlSession(
		request.Context(), credentials.RefreshToken(body.RefreshToken), h.loginSourceRevision,
		h.config.AccessTokenLifetime, time.Now(),
	)
	if errors.Is(err, controlstate.ErrControlAuthentication) {
		writeBearerProblem(response)
		return
	}
	if err != nil {
		writeAuthenticationUnavailable(response, "refresh control session", err)
		return
	}
	writeJSON(response, http.StatusOK, controlSessionResponse(issued))
}

func (h *handler) LogoutControlSession(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	if err := h.store.RevokeControlSession(request.Context(), principal, time.Now()); errors.Is(err, controlstate.ErrControlAuthentication) {
		writeBearerProblem(response)
		return
	} else if err != nil {
		writeAuthenticationUnavailable(response, "revoke control session", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *handler) GetIdentityContext(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	identity, err := h.store.IdentityContext(request.Context(), principal.IdentityID)
	if err != nil {
		log.Printf("read identity context: %v", err)
		writeProblem(response, http.StatusInternalServerError, authorityv1.Internal, "internal server error")
		return
	}
	writeJSON(response, http.StatusOK, identityContextResponse(identity))
}

func (h *handler) ListTeams(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	teams, err := h.store.ListTeams(request.Context(), principal.IdentityID)
	if err != nil {
		log.Printf("list teams: %v", err)
		writeProblem(response, http.StatusInternalServerError, authorityv1.Internal, "internal server error")
		return
	}
	page := authorityv1.TeamPage{Teams: make([]authorityv1.Team, len(teams))}
	for index, team := range teams {
		page.Teams[index] = teamResponse(team)
	}
	writeJSON(response, http.StatusOK, page)
}

func (h *handler) CreateTeam(
	response http.ResponseWriter,
	request *http.Request,
	params authorityv1.CreateTeamParams,
) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	var body authorityv1.CreateTeamRequest
	if err := decodeJSON(response, request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid request")
		return
	}
	digest, err := authorityRequestDigest(body)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid request")
		return
	}
	team, err := h.store.CreateTeam(request.Context(), controlstate.CreateTeamRequest{
		IdentityID: principal.IdentityID, IdempotencyKey: params.IdempotencyKey,
		RequestDigest: digest, DisplayName: string(body.DisplayName), MemberSlug: optionalMemberSlug(body.MemberSlug),
	}, time.Now())
	if err != nil {
		writeControlStateProblem(response, "create team", err)
		return
	}
	writeJSON(response, http.StatusCreated, teamResponse(team))
}

func optionalMemberSlug(value *authorityv1.CanonicalLabel) string {
	if value == nil {
		return ""
	}
	return string(*value)
}

func (h *handler) GetTeam(response http.ResponseWriter, request *http.Request, teamID authorityv1.TeamID) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	team, err := h.store.GetTeam(request.Context(), principal.IdentityID, string(teamID))
	if errors.Is(err, controlstate.ErrTeamNotFound) {
		writeProblem(response, http.StatusNotFound, authorityv1.NotFound, "team not found")
		return
	}
	if err != nil {
		log.Printf("get team: %v", err)
		writeProblem(response, http.StatusInternalServerError, authorityv1.Internal, "internal server error")
		return
	}
	writeJSON(response, http.StatusOK, teamResponse(team))
}

func (h *handler) ListTeamMemberships(response http.ResponseWriter, request *http.Request, teamID authorityv1.TeamID) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	memberships, err := h.store.ListTeamMemberships(request.Context(), principal.IdentityID, string(teamID))
	if err != nil {
		writeControlStateProblem(response, "list team memberships", err)
		return
	}
	page := authorityv1.MembershipPage{Memberships: make([]authorityv1.Membership, len(memberships))}
	for index, membership := range memberships {
		page.Memberships[index] = membershipResponse(membership)
	}
	writeJSON(response, http.StatusOK, page)
}

func (h *handler) SetMembershipRole(
	response http.ResponseWriter,
	request *http.Request,
	teamID authorityv1.TeamID,
	membershipID authorityv1.MembershipID,
) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	var body authorityv1.SetMembershipRoleRequest
	if err := decodeJSON(response, request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid request")
		return
	}
	membership, err := h.store.SetMembershipRole(
		request.Context(), principal.IdentityID, string(teamID), string(membershipID), controlstate.TeamRole(body.Role), time.Now(),
	)
	if err != nil {
		writeControlStateProblem(response, "set membership role", err)
		return
	}
	writeJSON(response, http.StatusOK, membershipResponse(membership))
}

func (h *handler) RemoveMembership(
	response http.ResponseWriter,
	request *http.Request,
	teamID authorityv1.TeamID,
	membershipID authorityv1.MembershipID,
) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	if err := h.store.RemoveMembership(
		request.Context(), principal.IdentityID, string(teamID), string(membershipID), time.Now(),
	); err != nil {
		writeControlStateProblem(response, "remove membership", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *handler) ListTeamInvitations(response http.ResponseWriter, request *http.Request, teamID authorityv1.TeamID) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	invitations, err := h.store.ListTeamInvitations(request.Context(), principal.IdentityID, string(teamID), time.Now())
	if err != nil {
		writeControlStateProblem(response, "list team invitations", err)
		return
	}
	page := authorityv1.InvitationPage{Invitations: make([]authorityv1.Invitation, len(invitations))}
	for index, invitation := range invitations {
		page.Invitations[index] = invitationResponse(invitation)
	}
	writeJSON(response, http.StatusOK, page)
}

func (h *handler) CreateTeamInvitation(
	response http.ResponseWriter,
	request *http.Request,
	teamID authorityv1.TeamID,
	params authorityv1.CreateTeamInvitationParams,
) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	var body authorityv1.CreateInvitationRequest
	if err := decodeJSON(response, request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid request")
		return
	}
	email := ""
	if body.EmailRestriction != nil {
		email = strings.ToLower(strings.TrimSpace(string(*body.EmailRestriction)))
	}
	digest, err := authorityRequestDigest(struct {
		MemberSlug       string               `json:"member_slug"`
		InitialRole      authorityv1.TeamRole `json:"initial_role"`
		ExpiresAt        time.Time            `json:"expires_at"`
		EmailRestriction string               `json:"email_restriction,omitempty"`
	}{body.MemberSlug, body.InitialRole, body.ExpiresAt.UTC(), email})
	if err != nil {
		writeProblem(response, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid request")
		return
	}
	created, err := h.store.CreateTeamInvitation(request.Context(), controlstate.CreateInvitationRequest{
		IdentityID: principal.IdentityID, TeamID: string(teamID), IdempotencyKey: params.IdempotencyKey,
		RequestDigest: digest, MemberSlug: body.MemberSlug, InitialRole: controlstate.TeamRole(body.InitialRole),
		ExpiresAt: body.ExpiresAt, EmailRestriction: email, RetrySecret: principal.RetrySecret[:],
	}, time.Now())
	if err != nil {
		writeControlStateProblem(response, "create team invitation", err)
		return
	}
	writeJSON(response, http.StatusCreated, authorityv1.InvitationSecret{
		Invitation: invitationResponse(created.Invitation), Secret: created.Secret,
	})
}

func (h *handler) RevokeTeamInvitation(
	response http.ResponseWriter,
	request *http.Request,
	teamID authorityv1.TeamID,
	invitationID authorityv1.InvitationID,
) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	if err := h.store.RevokeTeamInvitation(
		request.Context(), principal.IdentityID, string(teamID), string(invitationID), time.Now(),
	); err != nil {
		writeControlStateProblem(response, "revoke team invitation", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *handler) AcceptInvitation(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	var body authorityv1.AcceptInvitationRequest
	if err := decodeJSON(response, request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid request")
		return
	}
	membership, err := h.store.AcceptInvitation(
		request.Context(), principal.IdentityID, credentials.InvitationToken(body.Secret), time.Now(),
	)
	if err != nil {
		writeControlStateProblem(response, "accept invitation", err)
		return
	}
	writeJSON(response, http.StatusOK, membershipResponse(membership))
}

func (h *handler) ListTeamDomains(response http.ResponseWriter, request *http.Request, teamID authorityv1.TeamID) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	domains, err := h.store.ListTeamDomains(request.Context(), principal.IdentityID, string(teamID))
	if errors.Is(err, controlstate.ErrTeamNotFound) {
		writeProblem(response, http.StatusNotFound, authorityv1.NotFound, "team not found")
		return
	}
	if err != nil {
		log.Printf("list team domains: %v", err)
		writeProblem(response, http.StatusInternalServerError, authorityv1.Internal, "internal server error")
		return
	}
	page := authorityv1.DomainPage{Domains: make([]authorityv1.Domain, len(domains))}
	for index, domain := range domains {
		page.Domains[index] = domainResponse(domain)
	}
	writeJSON(response, http.StatusOK, page)
}

func (h *handler) ClaimTeamDomain(
	response http.ResponseWriter,
	request *http.Request,
	teamID authorityv1.TeamID,
	params authorityv1.ClaimTeamDomainParams,
) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	if !h.config.DNSAutomation {
		writeProblem(response, http.StatusServiceUnavailable, authorityv1.Unavailable, "DNS automation is unavailable")
		return
	}
	var body authorityv1.ClaimDomainRequest
	if err := decodeJSON(response, request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid request")
		return
	}
	makeDefault := body.MakeDefault != nil && *body.MakeDefault
	digest, err := authorityRequestDigest(struct {
		Domain      string `json:"domain"`
		MakeDefault bool   `json:"make_default"`
	}{body.Domain, makeDefault})
	if err != nil {
		writeProblem(response, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid request")
		return
	}
	domain, err := h.store.ClaimTeamDomain(request.Context(), controlstate.ClaimDomainRequest{
		IdentityID: principal.IdentityID, TeamID: string(teamID), IdempotencyKey: params.IdempotencyKey,
		RequestDigest: digest, Domain: body.Domain, MakeDefault: makeDefault,
	}, time.Now())
	if err != nil {
		writeControlStateProblem(response, "claim team domain", err)
		return
	}
	writeJSON(response, http.StatusCreated, domainResponse(domain))
}

func (h *handler) SetTeamDefaultDomain(
	response http.ResponseWriter,
	request *http.Request,
	teamID authorityv1.TeamID,
	domainID authorityv1.DomainID,
) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	team, err := h.store.SetTeamDefaultDomain(
		request.Context(), principal.IdentityID, string(teamID), string(domainID), time.Now(),
	)
	if err != nil {
		writeControlStateProblem(response, "set team default domain", err)
		return
	}
	writeJSON(response, http.StatusOK, teamResponse(team))
}

func (h *handler) ReleaseTeamDomain(
	response http.ResponseWriter,
	request *http.Request,
	teamID authorityv1.TeamID,
	domainID authorityv1.DomainID,
) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	if err := h.store.ReleaseTeamDomain(
		request.Context(), principal.IdentityID, string(teamID), string(domainID), time.Now(),
	); err != nil {
		writeControlStateProblem(response, "release team domain", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func authorityRequestDigest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
