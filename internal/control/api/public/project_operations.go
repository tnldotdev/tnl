package public

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func projectOperationProblem(ctx context.Context, w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrProjectConfigurationInvalid):
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid local service declaration")
	case errors.Is(err, controlstate.ErrProjectConfigurationStale):
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "local service declaration changed; read the current service and try again")
	case errors.Is(err, controlstate.ErrProjectSourceConflict):
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "project label belongs to another source; select a different project label")
	case errors.Is(err, controlstate.ErrProjectManaged):
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "this resource is managed by an environment or local app registration")
	case errors.Is(err, controlstate.ErrServicePortsExhausted):
		writeProblem(w, http.StatusServiceUnavailable, controlv1.PlacementUnavailable, "ingress pool has no available service port; ask the operator to extend its service port inventory")
	case errors.Is(err, controlstate.ErrServicePoolPinned):
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "service port reservation belongs to another ingress pool; keep its saved pool or create a separate service")
	case errors.Is(err, controlstate.ErrServiceConflict), errors.Is(err, controlstate.ErrPublicURLConflict):
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "a service name or public hostname is already in use")
	case errors.Is(err, controlstate.ErrServiceAccess), errors.Is(err, controlstate.ErrPublicURLAccess):
		writeProblem(w, http.StatusForbidden, controlv1.Forbidden, "this operation requires current team manager access")
	case errors.Is(err, pgx.ErrNoRows):
		writeProblem(w, http.StatusNotFound, controlv1.NotFound, "project or service not found")
	default:
		writeControlStateProblem(ctx, w, operation, err)
	}
}

func (h *handler) projectManager(w http.ResponseWriter, r *http.Request, team string) (string, bool) {
	p, ok := h.authorizeReads(w, r)
	if !ok {
		return "", false
	}
	if _, ok = p.teamIDs[team]; !ok {
		writeProblem(w, http.StatusNotFound, controlv1.NotFound, "project not found")
		return "", false
	}
	return p.identityID, true
}
