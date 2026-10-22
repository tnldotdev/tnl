package authority

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

type visitorAuthorityStore interface {
	GetTeamFeedbackPolicy(context.Context, string, string) (controlstate.TeamFeedbackPolicy, error)
	SetTeamFeedbackPolicy(context.Context, string, string, string, time.Time) (controlstate.TeamFeedbackPolicy, error)
	IssueControlBrowserHandoff(context.Context, credentials.AccessToken, credentials.RefreshToken, string, time.Duration, time.Duration, time.Time) (controlstate.BrowserHandoff, string, error)
}

func (h *handler) GetTeamFeedbackPolicy(w http.ResponseWriter, r *http.Request, teamID string) {
	principal, ok := h.authenticateControlRequest(w, r)
	if !ok {
		return
	}
	store, ok := h.store.(visitorAuthorityStore)
	if !ok {
		writeAuthenticationUnavailable(w, "read feedback author policy", nil)
		return
	}
	policy, err := store.GetTeamFeedbackPolicy(r.Context(), principal.IdentityID, teamID)
	if err != nil {
		writeControlStateProblem(w, "read feedback author policy", err)
		return
	}
	writeJSON(w, 200, policy)
}
func (h *handler) SetTeamFeedbackPolicy(w http.ResponseWriter, r *http.Request, teamID string) {
	principal, ok := h.authenticateControlRequest(w, r)
	if !ok {
		return
	}
	store, ok := h.store.(visitorAuthorityStore)
	if !ok {
		writeAuthenticationUnavailable(w, "set feedback author policy", nil)
		return
	}
	var body authorityv1.TeamFeedbackPolicy
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid feedback author policy")
		return
	}
	policy, err := store.SetTeamFeedbackPolicy(r.Context(), principal.IdentityID, teamID, string(body.Authors), time.Now())
	if err != nil {
		writeControlStateProblem(w, "set feedback author policy", err)
		return
	}
	writeJSON(w, 200, policy)
}
func (h *handler) IssueControlBrowserHandoff(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authenticateControlRequest(w, r); !ok {
		return
	}
	store, ok := h.store.(visitorAuthorityStore)
	if !ok {
		writeAuthenticationUnavailable(w, "create browser handoff", nil)
		return
	}
	var body authorityv1.IssueControlBrowserHandoffJSONRequestBody
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid browser handoff")
		return
	}
	access, err := credentials.Bearer(r.Header)
	if err != nil {
		writeBearerProblem(w)
		return
	}
	handoff, host, err := store.IssueControlBrowserHandoff(r.Context(), credentials.AccessToken(access), credentials.RefreshToken(body.RefreshToken), body.PublicUrlId, h.config.AccessTokenLifetime, h.config.RefreshTokenLifetime, time.Now())
	if err != nil {
		switch {
		case errors.Is(err, controlstate.ErrControlAuthentication):
			writeBearerProblem(w)
		case errors.Is(err, controlstate.ErrPreviewAccess):
			writeProblem(w, 403, authorityv1.Forbidden, "browser access denied")
		default:
			writeAuthenticationUnavailable(w, "create browser handoff", err)
		}
		return
	}
	writeJSON(w, 201, struct {
		URL string `json:"url"`
	}{URL: "https://" + host + "/__tnl/team/handoff/" + handoff.Token})
}
