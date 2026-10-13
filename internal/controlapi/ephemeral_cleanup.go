package controlapi

import (
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) DeleteEphemeralPublicURL(response http.ResponseWriter, request *http.Request, publicURLID controlv1.PublicURLID) {
	if h.store == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "temporary public URL cleanup is unavailable")
		return
	}
	identity, ok := h.authenticatePublisherAccess(response, request)
	if !ok {
		return
	}
	if identity.Scope.Kind != "namespace" || identity.CreatorID == "" || identity.GuestID != "" {
		writeBearerProblem(response)
		return
	}
	err := h.store.DeleteAuthorizedPublicURL(request.Context(), controlstate.AuthorizedPublicURLDeleteRequest{
		PublicURLID: string(publicURLID), TeamID: identity.Scope.TeamID, ActingIdentityID: identity.CreatorID,
		PublisherIdentityID: identity.ID, PublisherGrantID: identity.GrantID,
	}, time.Now().UTC())
	if err != nil {
		writeControlStateProblem(response, "remove publisher public URL", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}
