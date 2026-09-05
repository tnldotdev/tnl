package controlapi

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func credentialSourceRevision(token string) int64 {
	digest := sha256.Sum256([]byte(token))
	revision := int64(binary.BigEndian.Uint64(digest[:8]) & uint64(^uint64(0)>>1))
	if revision == 0 {
		return 1
	}
	return revision
}

func (h *handler) authenticateControlRequest(
	response http.ResponseWriter,
	request *http.Request,
) (controlstate.ControlPrincipal, bool) {
	value := request.Header.Get("Authorization")
	token, found := strings.CutPrefix(value, "Bearer ")
	if h.store == nil || !found || token == "" || strings.ContainsAny(token, " \t\r\n") {
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

func (h *handler) authenticateAdminRequest(
	response http.ResponseWriter,
	request *http.Request,
) (controlstate.ControlPrincipal, bool) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return controlstate.ControlPrincipal{}, false
	}
	if !principal.Administrator {
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "administrator access is required")
		return controlstate.ControlPrincipal{}, false
	}
	return principal, true
}

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
		request.Context(), routeSessionID, routeVersion, credentials.SessionToken(token),
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
	value := request.Header.Get("Authorization")
	token, found := strings.CutPrefix(value, "Bearer ")
	return token, found && token != "" && !strings.ContainsAny(token, " \t\r\n")
}
