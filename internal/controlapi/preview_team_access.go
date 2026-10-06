package controlapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) SetPreviewTeamAccess(response http.ResponseWriter, request *http.Request, previewID controlv1.PreviewID) {
	var body controlv1.SetPreviewTeamAccessRequest
	if err := decodeJSON(response, request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid preview access request")
		return
	}
	principal, ok := h.authorizeRouteReads(response, request)
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
	write := controlstate.SetPreviewTeamAccessRequest{
		PreviewID: preview.ID, TeamID: preview.TeamID, IdentityID: principal.identityID, Enabled: body.Enabled,
	}
	if body.Enabled {
		if len(preview.PublicURLIDs) == 0 || len(preview.PublicURLIDs) > 32 {
			writeProblem(response, http.StatusConflict, controlv1.Conflict, "run tnl dev to add public URLs to this preview")
			return
		}
		token, _ := requestBearerToken(request)
		for _, id := range preview.PublicURLIDs {
			route, err := h.store.GetPublicURLForAuthorization(request.Context(), id)
			if errors.Is(err, controlstate.ErrPublicURLNotFound) {
				writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
				return
			}
			if err != nil {
				writeControlStateProblem(response, "read team preview public URL", err)
				return
			}
			if route.TeamID != preview.TeamID || route.LifecycleState != controlstate.PublicURLLifecycleEnabled {
				writeProblem(response, http.StatusConflict, controlv1.Conflict, "public URL is not enabled for team access")
				return
			}
			prefixes := make([]string, len(route.AllowedIPPrefixes))
			for index, prefix := range route.AllowedIPPrefixes {
				prefixes[index] = prefix.String()
			}
			decision, err := h.authorizer.Authorize(request.Context(), authorization.Request{
				AccessToken: token, Operation: authorization.OperationShareCreate,
				TeamID: route.TeamID, PublicURLMembershipID: route.MembershipID, DomainID: route.DomainID,
				CanonicalHostname: route.CanonicalHostname, PublicURLScope: authorization.PublicURLScope(route.PublicURLScope),
				Target: route.Target, AllowedIPPrefixes: prefixes, Ephemeral: route.Ephemeral,
				PublicURLID: route.ID, PublicURLMutationRevision: route.MutationRevision,
			})
			if err != nil {
				feedbackOwnerFailure(response, err)
				return
			}
			if decision.IdentityID != principal.identityID || decision.TeamID != preview.TeamID ||
				write.PolicyRevision != 0 && (write.PolicyRevision != decision.PolicyRevision || write.AuthorityIssuer != h.authorityIssuerFor(decision)) {
				writeProblem(response, http.StatusConflict, controlv1.Conflict, "team access authorization changed; retry")
				return
			}
			write.PolicyRevision, write.AuthorityIssuer = decision.PolicyRevision, h.authorityIssuerFor(decision)
			write.PublicURLs = append(write.PublicURLs, controlstate.AuthorizedSharePublicURL{
				PublicURLID: route.ID, ExpectedMutationRevision: route.MutationRevision,
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
