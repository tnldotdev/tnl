package public

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type ProjectConfigurationStore interface {
	RetireProject(context.Context, string, string, string, int64, time.Time) (controlstate.AppliedProjectConfiguration, error)
	GetProjectStatus(context.Context, string, string, string, string, time.Time) (controlstate.ProjectStatus, error)
	ListProjects(context.Context, string, string, string) (controlstate.ProjectPage, error)
	ApplyProjectConfiguration(context.Context, controlstate.ApplyProjectConfigurationRequest) (controlstate.AppliedProjectConfiguration, error)
	GetProjectConfiguration(context.Context, string, string, string, string) (controlstate.AppliedProjectConfiguration, error)
}

func (h *handler) RetireProject(w http.ResponseWriter, r *http.Request, project string) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.RetireProjectJSONRequestBody
	if decodeJSONLimited(w, r, &body, 16<<10) != nil || body.ExpectedRevision < 1 {
		writeProblem(w, 400, controlv1.InvalidRequest, "retiring a project requires its current revision")
		return
	}
	actor, ok := h.projectManager(w, r, body.TeamId)
	if !ok {
		return
	}
	store := h.dependencies.ProjectConfiguration
	if store == nil {
		writeProblem(w, 503, controlv1.Unavailable, "project retirement is unavailable")
		return
	}
	result, err := store.RetireProject(r.Context(), body.TeamId, project, actor, body.ExpectedRevision, time.Now().UTC())
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "retire project", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) GetProjectStatus(w http.ResponseWriter, r *http.Request, project string, params controlv1.GetProjectStatusParams) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := h.projectManager(w, r, params.TeamId)
	if !ok {
		return
	}
	store := h.dependencies.ProjectConfiguration
	if store == nil {
		writeProblem(w, 503, controlv1.Unavailable, "project status is unavailable")
		return
	}
	cursor := ""
	if params.Cursor != nil {
		cursor = *params.Cursor
	}
	result, err := store.GetProjectStatus(r.Context(), params.TeamId, project, actor, cursor, time.Now().UTC())
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "read project status", err)
		return
	}
	writeJSON(w, 200, result)
}

func projectConfigurationProblem(ctx context.Context, w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrDiscoveryCursor):
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid discovery cursor")
	case errors.Is(err, controlstate.ErrWorkloadBinding):
		writeProblem(w, 400, controlv1.InvalidRequest, "GitHub workload policy requires verified repository and owner IDs; apply from a trusted operator with repository metadata access")
	case errors.Is(err, controlstate.ErrProjectConfigurationInvalid):
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid normalized project configuration")
	case errors.Is(err, controlstate.ErrProjectConfigurationStale):
		writeProblem(w, 409, controlv1.Conflict, "project configuration changed; read the current revision and apply again")
	case errors.Is(err, controlstate.ErrProjectSourceConflict):
		writeProblem(w, 409, controlv1.Conflict, "project key is bound to another source")
	case errors.Is(err, controlstate.ErrServicePortsExhausted):
		writeProblem(w, 503, controlv1.PlacementUnavailable, "ingress pool has no available service port; ask the operator to extend its service port inventory")
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

func (h *handler) ListProjects(w http.ResponseWriter, r *http.Request, params controlv1.ListProjectsParams) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := h.projectManager(w, r, params.TeamId)
	if !ok {
		return
	}
	if h.dependencies.ProjectConfiguration == nil {
		writeProblem(w, 503, controlv1.Unavailable, "project configuration is unavailable")
		return
	}
	cursor := ""
	if params.Cursor != nil {
		cursor = *params.Cursor
	}
	page, err := h.dependencies.ProjectConfiguration.ListProjects(r.Context(), params.TeamId, actor, cursor)
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "list projects", err)
		return
	}
	writeJSON(w, 200, page)
}

func (h *handler) ResolveProjectSource(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, ok := h.authorizeReads(w, r); !ok {
		return
	}
	var source naming.GitProjectSource
	if decodeJSONLimited(w, r, &source, 16<<10) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid project source")
		return
	}
	identity, err := source.Identity()
	if err != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "project source requires a network Git origin and repository-relative configuration path")
		return
	}
	writeJSON(w, 200, controlv1.ProjectSourceIdentity{ProjectKey: identity.Key, SourceFingerprint: identity.Fingerprint, ProjectLabel: identity.Label})
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
		TeamID              string                             `json:"team_id"`
		Source              *naming.GitProjectSource           `json:"source"`
		ProjectLabel        string                             `json:"project_label"`
		ExpectedRevision    *int64                             `json:"expected_revision,string"`
		Configuration       *controlstate.ProjectConfiguration `json:"configuration"`
		Deployment          string                             `json:"deployment"`
		ServiceDeclarations map[string]string                  `json:"service_declarations"`
	}
	if decodeJSONLimited(w, r, &body, 4<<20) != nil || body.ExpectedRevision == nil || body.Configuration == nil || body.ServiceDeclarations == nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid normalized project configuration")
		return
	}
	actor, ok := h.projectManager(w, r, body.TeamID)
	if !ok {
		return
	}
	result, err := store.ApplyProjectConfiguration(r.Context(), controlstate.ApplyProjectConfigurationRequest{Deployment: body.Deployment, ServiceDeclarations: body.ServiceDeclarations, TeamID: body.TeamID, ProjectKey: project, Source: body.Source, ProjectLabel: body.ProjectLabel, ActorID: actor, ExpectedRevision: *body.ExpectedRevision, Configuration: *body.Configuration, DNSAutomation: h.config.DNSAutomation, TrafficDefaults: h.config.TrafficDefaults, TrafficCeiling: h.config.TrafficCeiling, Now: time.Now()})
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
	result, err := store.GetProjectConfiguration(r.Context(), params.TeamId, project, actor, params.Deployment)
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "get project configuration", err)
		return
	}
	writeJSON(w, 200, result)
}
