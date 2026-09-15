package controlapi

import (
	"errors"
	"log"
	"net/http"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
)

func (h *handler) authenticateRouteSessionRequest(
	response http.ResponseWriter,
	request *http.Request,
	routeSessionID string,
	routeVersion uint64,
) (controlstate.RouteSessionAuthentication, bool) {
	token, ok := requestBearerToken(request)
	if h.store == nil || !ok {
		writeBearerProblem(response)
		return controlstate.RouteSessionAuthentication{}, false
	}
	authentication, err := h.store.RouteSessionAuthentication(
		request.Context(), routeSessionID, routeVersion, credentials.RouteSessionToken(token),
	)
	if err != nil {
		if !errors.Is(err, controlstate.ErrRouteSessionCredential) {
			log.Printf("authenticate route session: %v", err)
		}
		writeBearerProblem(response)
		return controlstate.RouteSessionAuthentication{}, false
	}
	return authentication, true
}

func requestBearerToken(request *http.Request) (string, bool) {
	token, err := credentials.Bearer(request.Header)
	return token, err == nil
}
