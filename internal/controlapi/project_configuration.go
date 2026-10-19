package controlapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type ProjectConfigurationStore interface {
	ResolveProjectConfiguration(context.Context, string, string, controlstate.ProjectConfiguration) (controlstate.ProjectConfiguration, error)
	ApplyProjectConfiguration(context.Context, controlstate.ApplyProjectConfigurationRequest) (controlstate.AppliedProjectConfiguration, error)
	GetProjectConfiguration(context.Context, string, string, string) (controlstate.AppliedProjectConfiguration, error)
}

func projectConfigurationProblem(w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrProjectConfigurationInvalid):
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid normalized project configuration")
	case errors.Is(err, controlstate.ErrProjectConfigurationStale):
		writeProblem(w, 409, controlv1.Conflict, "project configuration changed; read the current revision and apply again")
	case errors.Is(err, controlstate.ErrProjectSourceConflict):
		writeProblem(w, 409, controlv1.Conflict, "project label belongs to another source; select a different project label")
	case errors.Is(err, controlstate.ErrManagedPortsExhausted):
		writeProblem(w, 503, controlv1.PlacementUnavailable, "ingress pool has no available service port; ask the operator to extend its service port inventory")
	case errors.Is(err, controlstate.ErrPrivateServiceConflict), errors.Is(err, controlstate.ErrPublicURLConflict):
		writeProblem(w, 409, controlv1.Conflict, "a declared service name or public hostname is already in use")
	case errors.Is(err, controlstate.ErrPrivateServiceAccess), errors.Is(err, controlstate.ErrPublicURLAccess):
		writeProblem(w, 403, controlv1.Forbidden, "project configuration requires current team manager access")
	case errors.Is(err, controlstate.ErrPublisherGroup):
		writeBearerProblem(w)
	case errors.Is(err, pgx.ErrNoRows):
		writeProblem(w, 404, controlv1.NotFound, "project or publisher group not found")
	default:
		writeControlStateProblem(w, operation, err)
	}
}

func (h *handler) projectManager(w http.ResponseWriter, r *http.Request, team string) (string, bool) {
	p, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return "", false
	}
	if _, ok = p.teamIDs[team]; !ok {
		writeProblem(w, 404, controlv1.NotFound, "project not found")
		return "", false
	}
	return p.identityID, true
}

func (h *handler) GetProjectConfiguration(w http.ResponseWriter, r *http.Request, project string, params controlv1.GetProjectConfigurationParams) {
	w.Header().Set("Cache-Control", "no-store")
	store, ok := h.store.(ProjectConfigurationStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "project configuration is unavailable")
		return
	}
	actor, ok := h.projectManager(w, r, params.TeamId)
	if !ok {
		return
	}
	result, err := store.GetProjectConfiguration(r.Context(), params.TeamId, project, actor)
	if err != nil {
		projectConfigurationProblem(w, "get project configuration", err)
		return
	}
	writeJSON(w, 200, result)
}
