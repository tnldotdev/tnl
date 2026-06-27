package controlapi

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) ExchangeLoginToken(response http.ResponseWriter, request *http.Request) {
	var body authorityv1.LoginTokenExchangeRequest
	if err := decodeJSON(request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	token := credentials.LoginToken(body.LoginToken)
	if h.store == nil || h.config.LoginToken == "" || !h.loginVerifier.Matches(token) {
		writeBearerProblem(response)
		return
	}
	issued, err := h.store.CreateBuiltinControlSession(
		request.Context(), h.config.ManagedDeploymentDomain, h.loginSourceRevision,
		h.config.AccessTokenLifetime, h.config.RefreshTokenLifetime, time.Now(),
	)
	if err != nil {
		log.Printf("exchange login token: %v", err)
		writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
		return
	}
	writeJSON(response, http.StatusOK, controlSessionResponse(issued))
}

func (h *handler) RefreshControlSession(response http.ResponseWriter, request *http.Request) {
	var body authorityv1.RefreshControlSessionRequest
	if err := decodeJSON(request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	if h.store == nil {
		writeBearerProblem(response)
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
		log.Printf("refresh control session: %v", err)
		writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
		return
	}
	writeJSON(response, http.StatusOK, controlSessionResponse(issued))
}

func (h *handler) LogoutControlSession(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	if err := h.store.RevokeControlSession(request.Context(), principal, time.Now()); err != nil {
		log.Printf("revoke control session: %v", err)
		writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
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
		writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
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
		writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
		return
	}
	page := authorityv1.TeamPage{Teams: make([]authorityv1.Team, len(teams))}
	for index, team := range teams {
		page.Teams[index] = teamResponse(team)
	}
	writeJSON(response, http.StatusOK, page)
}

func (h *handler) GetTeam(response http.ResponseWriter, request *http.Request, teamID authorityv1.TeamID) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	team, err := h.store.GetTeam(request.Context(), principal.IdentityID, string(teamID))
	if errors.Is(err, controlstate.ErrTeamNotFound) {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "team not found")
		return
	}
	if err != nil {
		log.Printf("get team: %v", err)
		writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
		return
	}
	writeJSON(response, http.StatusOK, teamResponse(team))
}

func (h *handler) ListTeamDomains(response http.ResponseWriter, request *http.Request, teamID authorityv1.TeamID) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	domains, err := h.store.ListTeamDomains(request.Context(), principal.IdentityID, string(teamID))
	if errors.Is(err, controlstate.ErrTeamNotFound) {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "team not found")
		return
	}
	if err != nil {
		log.Printf("list team domains: %v", err)
		writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
		return
	}
	page := authorityv1.DomainPage{Domains: make([]authorityv1.Domain, len(domains))}
	for index, domain := range domains {
		page.Domains[index] = domainResponse(domain)
	}
	writeJSON(response, http.StatusOK, page)
}
