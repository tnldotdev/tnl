package authorityapi

import (
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func (h *handler) GetTeamFeedbackPolicy(response http.ResponseWriter, request *http.Request, teamID authorityv1.TeamID) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	policy, err := h.store.GetTeamFeedbackPolicy(request.Context(), principal.IdentityID, teamID)
	if err != nil {
		writeControlStateProblem(response, "read team feedback policy", err)
		return
	}
	writeJSON(response, http.StatusOK, authorityv1.TeamFeedbackPolicy{RequireSignIn: policy.RequireSignIn})
}

func (h *handler) SetTeamFeedbackPolicy(response http.ResponseWriter, request *http.Request, teamID authorityv1.TeamID) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	var body struct {
		RequireSignIn *bool `json:"require_sign_in"`
	}
	if err := decodeJSON(response, request, &body); err != nil || body.RequireSignIn == nil {
		writeProblem(response, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid feedback policy")
		return
	}
	if *body.RequireSignIn && h.config.BrowserOIDCVerifier == nil {
		writeProblem(response, http.StatusServiceUnavailable, authorityv1.Unavailable, "browser sign-in is unavailable; configure browser OIDC before requiring feedback sign-in")
		return
	}
	policy, err := h.store.SetTeamFeedbackPolicy(request.Context(), principal.IdentityID, teamID, *body.RequireSignIn, time.Now())
	if err != nil {
		writeControlStateProblem(response, "set team feedback policy", err)
		return
	}
	writeJSON(response, http.StatusOK, authorityv1.TeamFeedbackPolicy{RequireSignIn: policy.RequireSignIn})
}
