package public

import (
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (h *handler) SetPreviewTeamAccess(response http.ResponseWriter, request *http.Request, id controlv1.PreviewID) {
	var body controlv1.SetPreviewTeamAccessRequest
	if decodeJSON(response, request, &body) != nil {
		writeProblem(response, 400, controlv1.InvalidRequest, "invalid preview access request")
		return
	}
	principal, ok := h.authorizeReads(response, request)
	if !ok {
		return
	}
	preview, ok := h.readPreview(response, request, id, principal)
	if !ok {
		return
	}
	if h.previewTeamAccess == nil {
		writeProblem(response, 503, controlv1.Unavailable, "team access is unavailable")
		return
	}
	if body.Enabled && h.config.OIDCClientID == "" {
		writeProblem(response, 409, controlv1.Conflict, "browser sign-in requires an OIDC client configured on control")
		return
	}
	updated, err := h.previewTeamAccess.SetPreviewTeamAccess(request.Context(), controlstate.SetPreviewTeamAccessRequest{
		PreviewID: preview.ID, TeamID: preview.TeamID, IdentityID: principal.identityID, Enabled: body.Enabled}, time.Now())
	if err != nil {
		writeControlStateProblem(request.Context(), response, "set preview team access", err)
		return
	}
	writeJSON(response, 200, previewResponse(updated))
}
