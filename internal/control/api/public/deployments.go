package public

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type DeploymentStore interface {
	CreateDeployment(context.Context, controlstate.CreateDeploymentRequest) (controlstate.Deployment, error)
	UpdateDeployment(context.Context, controlstate.UpdateDeploymentRequest) (controlstate.Deployment, error)
	GetDeployment(context.Context, controlstate.DeploymentScope, string) (controlstate.Deployment, error)
	ListDeployments(context.Context, controlstate.DeploymentScope, string, int) ([]controlstate.Deployment, error)
	DeleteDeployment(context.Context, controlstate.DeploymentScope, string, int64, time.Time) error
}

func (h *handler) deploymentManager(w http.ResponseWriter, r *http.Request, team, project string) (controlstate.DeploymentScope, bool) {
	w.Header().Set("Cache-Control", "no-store")
	if h.dependencies.Deployments == nil {
		writeProblem(w, 503, controlv1.Unavailable, "deployment management is unavailable")
		return controlstate.DeploymentScope{}, false
	}
	actor, ok := h.projectManager(w, r, team)
	return controlstate.DeploymentScope{TeamID: team, ProjectKey: project, ActorID: actor}, ok
}

func deploymentProblem(ctx context.Context, w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrDeploymentNotFound):
		writeProblem(w, 404, controlv1.NotFound, "deployment not found")
	case errors.Is(err, controlstate.ErrDeploymentStale):
		writeProblem(w, http.StatusPreconditionFailed, controlv1.Conflict, "deployment changed; read it again and use its current ETag")
	case errors.Is(err, controlstate.ErrProjectConfigurationInvalid):
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid deployment name, target, or TLS settings; use declared service names and explicit addresses")
	default:
		projectConfigurationProblem(ctx, w, operation, err)
	}
}

func writeDeployment(w http.ResponseWriter, status int, deployment controlstate.Deployment) {
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(deployment.Revision, 10)))
	writeJSON(w, status, deployment)
}

func deploymentCondition(w http.ResponseWriter, r *http.Request) (int64, bool) {
	value := r.Header.Get("If-Match")
	if value == "" {
		writeProblem(w, http.StatusPreconditionRequired, controlv1.InvalidRequest, "send the deployment's current ETag in If-Match")
		return 0, false
	}
	unquoted, err := strconv.Unquote(value)
	revision, parseErr := strconv.ParseInt(unquoted, 10, 64)
	if err != nil || parseErr != nil || revision < 1 || strconv.Quote(strconv.FormatInt(revision, 10)) != value {
		writeProblem(w, 400, controlv1.InvalidRequest, "If-Match must contain one current strong deployment ETag")
		return 0, false
	}
	return revision, true
}

func (h *handler) CreateDeployment(w http.ResponseWriter, r *http.Request, project string, params controlv1.CreateDeploymentParams) {
	scope, ok := h.deploymentManager(w, r, params.TeamId, project)
	if !ok {
		return
	}
	var body struct {
		Name    string                                   `json:"name"`
		Targets map[string]controlstate.DeploymentTarget `json:"targets"`
	}
	if decodeJSONLimited(w, r, &body, 512<<10) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid deployment request")
		return
	}
	result, err := h.dependencies.Deployments.CreateDeployment(r.Context(), controlstate.CreateDeploymentRequest{
		DeploymentScope: scope, Name: body.Name, Targets: body.Targets, IdempotencyKey: params.IdempotencyKey, DNSAutomation: h.config.DNSAutomation, Now: time.Now(),
	})
	if err != nil {
		deploymentProblem(r.Context(), w, "create deployment", err)
		return
	}
	writeDeployment(w, 201, result)
}

func (h *handler) ListDeployments(w http.ResponseWriter, r *http.Request, project string, params controlv1.ListDeploymentsParams) {
	scope, ok := h.deploymentManager(w, r, params.TeamId, project)
	if !ok {
		return
	}
	limit, after := 50, ""
	if params.Limit != nil {
		limit = *params.Limit
	}
	if params.After != nil {
		after = *params.After
	}
	result, err := h.dependencies.Deployments.ListDeployments(r.Context(), scope, after, limit)
	if err != nil {
		deploymentProblem(r.Context(), w, "list deployments", err)
		return
	}
	page := struct {
		Deployments []controlstate.Deployment `json:"deployments"`
		NextCursor  string                    `json:"next_cursor,omitempty"`
	}{Deployments: result}
	if len(result) == limit {
		page.NextCursor = result[len(result)-1].ID
	}
	writeJSON(w, 200, page)
}

func (h *handler) GetDeployment(w http.ResponseWriter, r *http.Request, project, selector string, params controlv1.GetDeploymentParams) {
	scope, ok := h.deploymentManager(w, r, params.TeamId, project)
	if !ok {
		return
	}
	result, err := h.dependencies.Deployments.GetDeployment(r.Context(), scope, selector)
	if err != nil {
		deploymentProblem(r.Context(), w, "get deployment", err)
		return
	}
	writeDeployment(w, 200, result)
}

func (h *handler) UpdateDeployment(w http.ResponseWriter, r *http.Request, project, selector string, params controlv1.UpdateDeploymentParams) {
	scope, ok := h.deploymentManager(w, r, params.TeamId, project)
	if !ok {
		return
	}
	revision, ok := deploymentCondition(w, r)
	if !ok {
		return
	}
	var body struct {
		Targets map[string]controlstate.DeploymentTarget `json:"targets"`
	}
	if decodeJSONLimited(w, r, &body, 512<<10) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid deployment target update")
		return
	}
	result, err := h.dependencies.Deployments.UpdateDeployment(r.Context(), controlstate.UpdateDeploymentRequest{
		DeploymentScope: scope, Selector: selector, ExpectedRevision: revision, Targets: body.Targets, Now: time.Now(),
	})
	if err != nil {
		deploymentProblem(r.Context(), w, "update deployment", err)
		return
	}
	writeDeployment(w, 200, result)
}

func (h *handler) DeleteDeployment(w http.ResponseWriter, r *http.Request, project, selector string, params controlv1.DeleteDeploymentParams) {
	scope, ok := h.deploymentManager(w, r, params.TeamId, project)
	if !ok {
		return
	}
	revision, ok := deploymentCondition(w, r)
	if !ok {
		return
	}
	if err := h.dependencies.Deployments.DeleteDeployment(r.Context(), scope, selector, revision, time.Now()); err != nil {
		deploymentProblem(r.Context(), w, "delete deployment", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
