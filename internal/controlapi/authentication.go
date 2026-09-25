package controlapi

import (
	"errors"
	"log"
	"net/http"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) authenticateRouteSessionRequest(
	response http.ResponseWriter,
	request *http.Request,
	routeSessionID string,
	routeVersion uint64,
) (controlstate.RouteSessionAuthentication, bool) {
	token, ok := requestBearerToken(request)
	if !ok {
		writeBearerProblem(response)
		return controlstate.RouteSessionAuthentication{}, false
	}
	if h.store == nil {
		requestID := writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authentication is unavailable")
		log.Printf("authenticate route session request_id=%s: store unavailable", requestID)
		return controlstate.RouteSessionAuthentication{}, false
	}
	authentication, err := h.store.RouteSessionAuthentication(
		request.Context(), routeSessionID, routeVersion, credentials.RouteSessionToken(token),
	)
	if errors.Is(err, controlstate.ErrRouteSessionCredential) {
		writeBearerProblem(response)
		return controlstate.RouteSessionAuthentication{}, false
	}
	if err != nil {
		requestID := writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authentication is unavailable")
		log.Printf("authenticate route session request_id=%s: %v", requestID, err)
		return controlstate.RouteSessionAuthentication{}, false
	}
	return authentication, true
}

func requestBearerToken(request *http.Request) (string, bool) {
	token, err := credentials.Bearer(request.Header)
	return token, err == nil
}
