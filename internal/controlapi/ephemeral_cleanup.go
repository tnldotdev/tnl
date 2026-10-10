package controlapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) DeleteEphemeralPublicURL(response http.ResponseWriter, request *http.Request, publicURLID controlv1.PublicURLID) {
	token, ok := requestBearerToken(request)
	if !ok {
		writeBearerProblem(response)
		return
	}
	if h.publishCredentials == nil || h.store == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "ad-hoc cleanup is unavailable")
		return
	}
	now := time.Now()
	credential, err := h.publishCredentials.AuthenticateEphemeralCredential(request.Context(), credentials.EphemeralCredential(token), now)
	if errors.Is(err, controlstate.ErrEphemeralCredential) {
		writeBearerProblem(response)
		return
	}
	if err != nil {
		writeControlStateProblem(response, "authenticate ad-hoc cleanup", err)
		return
	}
	err = h.store.DeleteAuthorizedPublicURL(request.Context(), controlstate.AuthorizedPublicURLDeleteRequest{
		PublicURLID: string(publicURLID), TeamID: credential.TeamID,
		ActingIdentityID: credential.IdentityID, EphemeralCredential: credentials.EphemeralCredential(token),
	}, now)
	if err != nil {
		writeControlStateProblem(response, "delete ad-hoc public URL", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}
