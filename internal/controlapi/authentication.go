package controlapi

import (
	"errors"
	"log"
	"net/http"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) authenticatePublishRunRequest(
	response http.ResponseWriter,
	request *http.Request,
	publishRunID string,
	publishRunNumber uint64,
) (controlstate.PublishRunAuthentication, bool) {
	token, ok := requestBearerToken(request)
	if !ok {
		writeBearerProblem(response)
		return controlstate.PublishRunAuthentication{}, false
	}
	if h.store == nil {
		requestID := writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authentication is unavailable")
		log.Printf("authenticate publish run request_id=%s: store unavailable", requestID)
		return controlstate.PublishRunAuthentication{}, false
	}
	authentication, err := h.store.PublishRunAuthentication(
		request.Context(), publishRunID, publishRunNumber, credentials.PublishRunToken(token),
	)
	if errors.Is(err, controlstate.ErrPublishRunCredential) {
		writeBearerProblem(response)
		return controlstate.PublishRunAuthentication{}, false
	}
	if err != nil {
		requestID := writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authentication is unavailable")
		log.Printf("authenticate publish run request_id=%s: %v", requestID, err)
		return controlstate.PublishRunAuthentication{}, false
	}
	return authentication, true
}

func requestBearerToken(request *http.Request) (string, bool) {
	token, err := credentials.Bearer(request.Header)
	return token, err == nil
}
