package public

import (
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (h *handler) SetPreviewTeamAccess(response http.ResponseWriter, request *http.Request, previewID controlv1.PreviewID) {
	var body controlv1.SetPreviewTeamAccessRequest
	if err := decodeJSON(response, request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid preview access request")
		return
	}
	principal, ok := h.authorizeReads(response, request)
	if !ok {
		return
	}
	preview, ok := h.readPreview(response, request, string(previewID), principal)
	if !ok {
		return
	}
	if h.previewTeamAccess == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "team access is unavailable")
		return
	}
	if body.Enabled && h.config.OIDCClientID == "" {
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "browser sign-in requires an OIDC client configured on control")
		return
	}
	write := controlstate.SetPreviewTeamAccessRequest{
		PreviewID: preview.ID, TeamID: preview.TeamID, IdentityID: principal.identityID, Enabled: body.Enabled,
	}
	if body.Enabled {
		if len(preview.PublicURLIDs) == 0 || len(preview.PublicURLIDs) > 32 {
			writeProblem(response, http.StatusConflict, controlv1.Conflict, "start a configured app service to add public URLs to this preview")
			return
		}
		token, _ := requestBearerToken(request)
		for _, id := range preview.PublicURLIDs {
			publicURL, err := h.store.GetPublicURLForAuthorization(request.Context(), id)
			if errors.Is(err, controlstate.ErrPublicURLNotFound) {
				writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
				return
			}
			if err != nil {
				writeControlStateProblem(response, "read team preview public URL", err)
				return
			}
			if publicURL.TeamID != preview.TeamID || publicURL.LifecycleState != controlstate.PublicURLLifecycleEnabled {
				writeProblem(response, http.StatusConflict, controlv1.Conflict, "public URL is not enabled for team access")
				return
			}
			prefixes := make([]string, len(publicURL.AllowedIPPrefixes))
			for index, prefix := range publicURL.AllowedIPPrefixes {
				prefixes[index] = prefix.String()
			}
			decision, err := h.authorizer.Authorize(request.Context(), authorization.Request{
				AccessToken: token, Operation: authorization.OperationShareCreate,
				TeamID: publicURL.TeamID, PublicURLMembershipID: publicURL.MembershipID, DomainID: publicURL.DomainID,
				CanonicalHostname: publicURL.CanonicalHostname, PublicURLScope: authorization.PublicURLScope(publicURL.PublicURLScope),
				Target: publicURL.Target, AllowedIPPrefixes: prefixes, Ephemeral: publicURL.Ephemeral,
				PublicURLID: publicURL.ID, PublicURLMutationRevision: publicURL.MutationRevision,
			})
			if err != nil {
				feedbackOwnerFailure(response, err)
				return
			}
			if decision.IdentityID != principal.identityID || decision.TeamID != preview.TeamID ||
				write.PolicyRevision != 0 && write.PolicyRevision != decision.PolicyRevision {
				writeProblem(response, http.StatusConflict, controlv1.Conflict, "team access authorization changed; retry")
				return
			}
			write.PolicyRevision = decision.PolicyRevision
			write.PublicURLs = append(write.PublicURLs, controlstate.AuthorizedSharePublicURL{
				PublicURLID: publicURL.ID, ExpectedMutationRevision: publicURL.MutationRevision,
			})
		}
	}
	updated, err := h.previewTeamAccess.SetPreviewTeamAccess(request.Context(), write, time.Now())
	if err != nil {
		writeControlStateProblem(response, "set preview team access", err)
		return
	}
	writeJSON(response, http.StatusOK, previewResponse(updated))
}
