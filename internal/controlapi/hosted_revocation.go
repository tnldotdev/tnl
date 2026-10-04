package controlapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/operatorlog"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) RevokeHostedPolicy(response http.ResponseWriter, request *http.Request) {
	if !h.hostedSecrets.Valid() || !h.hostedSecrets.Authenticate(request.Header) {
		writeBearerProblem(response)
		return
	}
	var body controlv1.HostedPolicyRevocation
	if err := decodeJSON(response, request, &body); err != nil || body.PolicyRevision <= 0 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	_, _, err := h.revocations.ApplyHostedPolicyRevocation(
		request.Context(), h.externalAuthorityIssuer(), body.TeamId, uint64(body.PolicyRevision),
		body.AllSessions, body.MembershipIds, body.DomainIds, time.Now(),
	)
	if errors.Is(err, controlstate.ErrHostedPolicyRevocationInvalid) {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	if err != nil {
		requestID := writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
		operatorlog.Report("apply hosted policy revocation", failure.ServerAPIInternal, requestID, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}
