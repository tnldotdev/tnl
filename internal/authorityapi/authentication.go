package authorityapi

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
)

func (h *handler) authenticateControlRequest(
	response http.ResponseWriter,
	request *http.Request,
) (controlstate.ControlPrincipal, bool) {
	token, err := credentials.Bearer(request.Header)
	if h.store == nil || err != nil {
		writeBearerProblem(response)
		return controlstate.ControlPrincipal{}, false
	}
	principal, err := h.store.AuthenticateAccessToken(
		request.Context(), credentials.AccessToken(token), h.loginSourceRevision, time.Now(),
	)
	if err != nil {
		if !errors.Is(err, controlstate.ErrControlAuthentication) {
			log.Printf("authenticate control request: %v", err)
		}
		writeBearerProblem(response)
		return controlstate.ControlPrincipal{}, false
	}
	return principal, true
}
