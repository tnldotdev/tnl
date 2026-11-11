package public

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type ProjectConfigurationStore interface {
	ResolveProjectConfiguration(context.Context, string, string, controlstate.ProjectConfiguration) (controlstate.ProjectConfiguration, error)
	ApplyProjectConfiguration(context.Context, controlstate.ApplyProjectConfigurationRequest) (controlstate.AppliedProjectConfiguration, error)
	GetProjectConfiguration(context.Context, string, string, string) (controlstate.AppliedProjectConfiguration, error)
}

func projectConfigurationProblem(ctx context.Context, w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrMachineDenied):
		writeProblem(w, 403, controlv1.Forbidden, "current machine permission does not authorize this publisher group operation")
	case errors.Is(err, controlstate.ErrPublisherGroupRetired):
		writeProblem(w, 409, controlv1.Conflict, "publisher group was retired; its creation key cannot be reused")
	case errors.Is(err, controlstate.ErrPublisherTemplateInUse):
		writeProblem(w, 409, controlv1.Conflict, "publisher template has dependent groups; remove them before removing or converting the template")
	case errors.Is(err, controlstate.ErrWorkloadBinding):
		writeProblem(w, 400, controlv1.InvalidRequest, "GitHub workload policy requires verified repository and owner IDs; apply from a trusted operator with repository metadata access")
	case errors.Is(err, controlstate.ErrProjectConfigurationInvalid):
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid normalized project configuration")
	case errors.Is(err, controlstate.ErrProjectConfigurationStale):
		writeProblem(w, 409, controlv1.Conflict, "project configuration changed; read the current revision and apply again")
	case errors.Is(err, controlstate.ErrProjectSourceConflict):
		writeProblem(w, 409, controlv1.Conflict, "project label belongs to another source; select a different project label")
	case errors.Is(err, controlstate.ErrProjectManaged):
		writeProblem(w, 409, controlv1.Conflict, "this resource is managed by project configuration; change its declaration and apply again")
	case errors.Is(err, controlstate.ErrServicePortsExhausted):
		writeProblem(w, 503, controlv1.PlacementUnavailable, "ingress pool has no available service port; ask the operator to extend its service port inventory")
	case errors.Is(err, controlstate.ErrServicePoolPinned):
		writeProblem(w, 409, controlv1.Conflict, "service port reservation belongs to another ingress pool; keep the service in a group on its saved pool or create a separate service")
	case errors.Is(err, controlstate.ErrServiceConflict), errors.Is(err, controlstate.ErrPublicURLConflict):
		writeProblem(w, 409, controlv1.Conflict, "a declared service name or public hostname is already in use")
	case errors.Is(err, controlstate.ErrServiceAccess), errors.Is(err, controlstate.ErrPublicURLAccess):
		writeProblem(w, 403, controlv1.Forbidden, "project configuration requires current team manager access")
	case errors.Is(err, controlstate.ErrPublisherGroup):
		writeBearerProblem(w)
	case errors.Is(err, pgx.ErrNoRows):
		writeProblem(w, 404, controlv1.NotFound, "project or publisher group not found")
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
		writeProblem(w, 404, controlv1.NotFound, "project not found")
		return "", false
	}
	return p.identityID, true
}

func (h *handler) ApplyProjectConfiguration(w http.ResponseWriter, r *http.Request, project string) {
	w.Header().Set("Cache-Control", "no-store")
	store, ok := h.dependencies.ProjectConfiguration, h.dependencies.ProjectConfiguration != nil
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "project configuration is unavailable")
		return
	}
	var body struct {
		TeamID            string                                         `json:"team_id"`
		SourceFingerprint string                                         `json:"source_fingerprint"`
		ProjectLabel      string                                         `json:"project_label"`
		ExpectedRevision  *int64                                         `json:"expected_revision"`
		Configuration     *controlstate.ProjectConfiguration             `json:"configuration"`
		GroupBindings     map[string]controlstate.PublisherGroupBindings `json:"group_bindings"`
	}
	if decodeJSONLimited(w, r, &body, 4<<20) != nil || body.ExpectedRevision == nil || body.Configuration == nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid normalized project configuration")
		return
	}
	actor, ok := h.projectManager(w, r, body.TeamID)
	if !ok {
		return
	}
	c, _, err := controlstate.NormalizeProjectConfiguration(*body.Configuration)
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "validate project configuration", err)
		return
	}
	c, err = store.ResolveProjectConfiguration(r.Context(), body.TeamID, actor, c)
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "resolve project public hostnames", err)
		return
	}
	result, err := store.ApplyProjectConfiguration(r.Context(), controlstate.ApplyProjectConfigurationRequest{GroupBindings: body.GroupBindings, TeamID: body.TeamID, ProjectKey: project, SourceFingerprint: body.SourceFingerprint, ProjectLabel: body.ProjectLabel, ActorID: actor, ExpectedRevision: *body.ExpectedRevision, Configuration: c, DNSAutomation: h.config.DNSAutomation, TrafficDefaults: h.config.TrafficDefaults, TrafficCeiling: h.config.TrafficCeiling, Now: time.Now()})
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "apply project configuration", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) GetProjectConfiguration(w http.ResponseWriter, r *http.Request, project string, params controlv1.GetProjectConfigurationParams) {
	w.Header().Set("Cache-Control", "no-store")
	store, ok := h.dependencies.ProjectConfiguration, h.dependencies.ProjectConfiguration != nil
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
		projectConfigurationProblem(r.Context(), w, "get project configuration", err)
		return
	}
	writeJSON(w, 200, result)
}
