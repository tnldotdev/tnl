package authority

import (
	"net/http"
	"time"

	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func (h *handler) GetTeamDomain(response http.ResponseWriter, request *http.Request, teamID authorityv1.TeamID, domainID authorityv1.DomainID) {
	response.Header().Set("Cache-Control", "no-store")
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	domain, err := h.store.GetTeamDomain(request.Context(), principal.IdentityID, teamID, domainID, time.Now())
	if err != nil {
		writeControlStateProblem(request.Context(), response, "read team domain", err)
		return
	}
	writeJSON(response, http.StatusOK, domainResponse(domain))
}
