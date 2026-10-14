package controlapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) CreateShareGrant(response http.ResponseWriter, request *http.Request, _ controlv1.CreateShareGrantParams) {
	var body controlv1.CreateShareGrantRequest
	if err := decodeJSON(response, request, &body); err != nil || body.TeamId == "" || body.PublicUrlId == "" {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "choose one team and public URL to share")
		return
	}
	key := request.Header.Get("Idempotency-Key")
	if key == "" || len(key) > 128 || strings.TrimSpace(key) != key {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid share idempotency key")
		return
	}
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	if h.visitorGrants == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "share grants are unavailable")
		return
	}
	if _, member := principal.teamIDs[body.TeamId]; !member {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	url, err := h.store.GetPublicURLForAuthorization(request.Context(), body.PublicUrlId)
	if errors.Is(err, controlstate.ErrPublicURLNotFound) || err == nil && url.TeamID != body.TeamId {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	if err != nil {
		writeControlStateProblem(response, "read shared public URL", err)
		return
	}
	if url.Purpose != controlstate.PublicURLPurposeApp || url.ServiceProtocol != controlstate.PublicURLServiceHTTP &&
		url.ServiceProtocol != controlstate.PublicURLServicePostgres && url.ServiceProtocol != controlstate.PublicURLServiceMySQL &&
		url.ServiceProtocol != controlstate.PublicURLServiceRedis {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "team sharing requires an app or database public URL")
		return
	}
	if url.ServiceProtocol == controlstate.PublicURLServiceHTTP && h.config.BrowserOIDCClientID == "" {
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "team browser access requires an OIDC client configured on control")
		return
	}
	prefixes := make([]string, len(url.AllowedIPPrefixes))
	for index, prefix := range url.AllowedIPPrefixes {
		prefixes[index] = prefix.String()
	}
	decision, ok := h.authorizeExistingRouteMutation(response, request, principal, authorization.Request{
		Operation: authorization.OperationShareCreate, TeamID: url.TeamID,
		PublicURLMembershipID: url.MembershipID, DomainID: url.DomainID,
		CanonicalHostname: url.CanonicalHostname, PublicURLScope: authorization.PublicURLScope(url.PublicURLScope),
		Target: url.Target, AllowedIPPrefixes: prefixes, Ephemeral: url.Ephemeral,
		PublicURLID: url.ID, PublicURLMutationRevision: url.MutationRevision,
	})
	if !ok {
		return
	}
	grant, err := h.visitorGrants.CreateTeamURLShareGrant(request.Context(), controlstate.CreateTeamURLShareGrantRequest{
		TeamID: body.TeamId, PublicURLID: url.ID, ActingIdentityID: decision.IdentityID,
		IdempotencyKey: key, PolicyRevision: decision.PolicyRevision,
		ExpectedMutationRevision: url.MutationRevision, ExpiresAt: body.ExpiresAt,
	}, time.Now())
	if err != nil {
		writeControlStateProblem(response, "create team share", err)
		return
	}
	writeJSON(response, http.StatusCreated, visitorGrantResponse(grant))
}

func (h *handler) ListShareGrants(response http.ResponseWriter, request *http.Request, _ controlv1.ListShareGrantsParams) {
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	teamID := request.URL.Query().Get("team_id")
	if _, member := principal.teamIDs[teamID]; !member {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	if h.visitorGrants == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "share grants are unavailable")
		return
	}
	page, err := h.visitorGrants.ListTeamURLShareGrants(request.Context(), teamID, principal.identityID, request.URL.Query().Get("cursor"))
	if err != nil {
		writeControlStateProblem(response, "list team shares", err)
		return
	}
	items := make([]controlv1.ShareGrant, len(page.Shares))
	for index, grant := range page.Shares {
		items[index] = visitorGrantResponse(grant)
	}
	result := controlv1.ShareGrantPage{Shares: items}
	if page.NextCursor != "" {
		result.NextCursor = &page.NextCursor
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *handler) RevokeShareGrant(response http.ResponseWriter, request *http.Request, shareID controlv1.ShareID) {
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	if h.visitorGrants == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "share grants are unavailable")
		return
	}
	grant, err := h.visitorGrants.GetTeamURLShareGrant(request.Context(), string(shareID))
	if errors.Is(err, controlstate.ErrShareNotFound) || err == nil && !hasTeam(principal, grant.TeamID) {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	if err != nil {
		writeControlStateProblem(response, "read team share", err)
		return
	}
	updated, err := h.visitorGrants.RevokeTeamURLShareGrant(request.Context(), grant.ID, grant.TeamID, principal.identityID, time.Now())
	if err != nil {
		writeControlStateProblem(response, "revoke team share", err)
		return
	}
	writeJSON(response, http.StatusOK, visitorGrantResponse(updated))
}

func hasTeam(principal publicURLReadPrincipal, teamID string) bool {
	_, found := principal.teamIDs[teamID]
	return found
}

func visitorGrantResponse(grant controlstate.VisitorShareGrant) controlv1.ShareGrant {
	return controlv1.ShareGrant{
		Id: grant.ID, TeamId: grant.TeamID, Kind: controlv1.ShareGrantKind(grant.Kind),
		PublicUrlId: grant.PublicURLID, CreatedByIdentityId: grant.CreatedByIdentityID,
		CreatedAt: grant.CreatedAt, ExpiresAt: grant.ExpiresAt, RevokedAt: grant.RevokedAt,
	}
}
