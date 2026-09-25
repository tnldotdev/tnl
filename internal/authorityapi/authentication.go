package authorityapi

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func (h *handler) authenticateControlRequest(
	response http.ResponseWriter,
	request *http.Request,
) (controlstate.ControlPrincipal, bool) {
	token, err := credentials.Bearer(request.Header)
	if err != nil {
		writeBearerProblem(response)
		return controlstate.ControlPrincipal{}, false
	}
	if h.store == nil {
		writeAuthenticationUnavailable(response, "authenticate control request", nil)
		return controlstate.ControlPrincipal{}, false
	}
	principal, err := h.store.AuthenticateAccessToken(
		request.Context(), credentials.AccessToken(token), h.loginSourceRevision, time.Now(),
	)
	if errors.Is(err, controlstate.ErrControlAuthentication) {
		writeBearerProblem(response)
		return controlstate.ControlPrincipal{}, false
	}
	if err != nil {
		writeAuthenticationUnavailable(response, "authenticate control request", err)
		return controlstate.ControlPrincipal{}, false
	}
	return principal, true
}

func writeAuthenticationUnavailable(response http.ResponseWriter, operation string, err error) {
	requestID := writeProblem(response, http.StatusServiceUnavailable, authorityv1.Unavailable, "authentication is unavailable")
	if err == nil {
		log.Printf("%s request_id=%s: store unavailable", operation, requestID)
		return
	}
	log.Printf("%s request_id=%s: %v", operation, requestID, err)
}
