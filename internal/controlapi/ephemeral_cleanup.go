package controlapi

import (
	"errors"
	"net/http"
	"strings"
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
	if strings.HasPrefix(token, "pta_") {
		machine, ok := h.authenticatePublisherAccess(response, request)
		if !ok {
			return
		}
		if machine.Scope.Kind != "namespace" || machine.CreatorID == "" {
			writeBearerProblem(response)
			return
		}
		err := h.store.DeleteAuthorizedPublicURL(request.Context(), controlstate.AuthorizedPublicURLDeleteRequest{
			PublicURLID: string(publicURLID), TeamID: machine.Scope.TeamID, ActingIdentityID: machine.CreatorID,
			PublisherIdentityID: machine.ID, PublisherGrantID: machine.GrantID,
		}, time.Now().UTC())
		if err != nil {
			writeControlStateProblem(response, "delete publisher public URL", err)
			return
		}
		response.WriteHeader(http.StatusNoContent)
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
