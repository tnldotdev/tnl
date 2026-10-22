package public

import (
	"errors"
	"net/http"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
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
		operatorlog.ReportContext(request.Context(), "authenticate publish run", failure.ServerAPIInternal, requestID, errors.New("store unavailable"))
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
		operatorlog.ReportContext(request.Context(), "authenticate publish run", failure.ServerAPIInternal, requestID, err)
		return controlstate.PublishRunAuthentication{}, false
	}
	return authentication, true
}

func requestBearerToken(request *http.Request) (string, bool) {
	token, err := credentials.Bearer(request.Header)
	return token, err == nil
}
