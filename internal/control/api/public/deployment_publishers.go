package public

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type DeploymentPublisherStore interface {
	CreateDeploymentPublisherEnrollment(context.Context, controlstate.CreateDeploymentPublisherEnrollmentRequest) (controlstate.DeploymentPublisherEnrollment, error)
	ListDeploymentPublishers(context.Context, controlstate.DeploymentScope, string, string, int) ([]controlstate.DeploymentPublisher, error)
	GetDeploymentPublisher(context.Context, controlstate.DeploymentScope, string, string) (controlstate.DeploymentPublisher, error)
	RevokeDeploymentPublisher(context.Context, controlstate.DeploymentScope, string, string, time.Time) error
}

func (h *handler) deploymentPublisherManager(w http.ResponseWriter, r *http.Request, team, project string) (controlstate.DeploymentScope, bool) {
	w.Header().Set("Cache-Control", "no-store")
	if h.dependencies.DeploymentPublishers == nil {
		writeProblem(w, 503, controlv1.Unavailable, "deployment publisher management is unavailable")
		return controlstate.DeploymentScope{}, false
	}
	return h.deploymentPrincipal(w, r, team, project)
}

func deploymentPublisherProblem(ctx context.Context, w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrServiceConflict):
		writeProblem(w, 409, controlv1.Conflict, "publisher enrollment request key was already used for different setup settings")
	case errors.Is(err, controlstate.ErrDeploymentPublisherNotFound):
		writeProblem(w, 404, controlv1.NotFound, "publisher not found in this deployment")
	case errors.Is(err, controlstate.ErrPublisherEnrollment):
		writeProblem(w, 409, controlv1.Conflict, "publisher setup is expired, consumed, revoked, or its saved service approval changed; create a new enrollment with a new request key")
	case errors.Is(err, controlstate.ErrProjectConfigurationInvalid):
		writeProblem(w, 400, controlv1.InvalidRequest, "select existing deployment services and bounded publisher enrollment settings")
	default:
		deploymentProblem(ctx, w, operation, err)
	}
}

func (h *handler) CreateDeploymentPublisherEnrollment(w http.ResponseWriter, r *http.Request, project, deployment string, params controlv1.CreateDeploymentPublisherEnrollmentParams) {
	scope, ok := h.deploymentPublisherManager(w, r, params.TeamId, project)
	if !ok {
		return
	}
	var body controlv1.CreateDeploymentPublisherEnrollmentRequest
	if decodeJSONLimited(w, r, &body, 16<<10) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid deployment publisher enrollment")
		return
	}
	maxMembers, expiresIn := 1, 600
	if body.MaxMembers != nil {
		maxMembers = *body.MaxMembers
	}
	if body.ExpiresIn != nil {
		expiresIn = *body.ExpiresIn
	}
	// bound seconds before converting to a duration, including overflow inputs.
	if expiresIn < 60 || expiresIn > 86400 {
		writeProblem(w, 400, controlv1.InvalidRequest, "publisher enrollment expires_in must be between 60 and 86400 seconds")
		return
	}
	result, err := h.dependencies.DeploymentPublishers.CreateDeploymentPublisherEnrollment(r.Context(), controlstate.CreateDeploymentPublisherEnrollmentRequest{
		DeploymentScope: scope, Selector: deployment, IdempotencyKey: params.IdempotencyKey, Services: body.Services, MaxMembers: maxMembers, Lifetime: time.Duration(expiresIn) * time.Second, Now: time.Now(),
	})
	if err != nil {
		deploymentPublisherProblem(r.Context(), w, "create deployment publisher enrollment", err)
		return
	}
	writeJSON(w, 201, result)
}

func (h *handler) ListDeploymentPublishers(w http.ResponseWriter, r *http.Request, project, deployment string, params controlv1.ListDeploymentPublishersParams) {
	scope, ok := h.deploymentPublisherManager(w, r, params.TeamId, project)
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
	result, err := h.dependencies.DeploymentPublishers.ListDeploymentPublishers(r.Context(), scope, deployment, after, limit)
	if err != nil {
		deploymentPublisherProblem(r.Context(), w, "list deployment publishers", err)
		return
	}
	page := struct {
		Publishers []controlstate.DeploymentPublisher `json:"publishers"`
		NextCursor string                             `json:"next_cursor,omitempty"`
	}{Publishers: result}
	if len(result) == limit {
		page.NextCursor = result[len(result)-1].PublisherIdentityID
	}
	writeJSON(w, 200, page)
}

func (h *handler) GetDeploymentPublisher(w http.ResponseWriter, r *http.Request, project, deployment, publisher string, params controlv1.GetDeploymentPublisherParams) {
	scope, ok := h.deploymentPublisherManager(w, r, params.TeamId, project)
	if !ok {
		return
	}
	result, err := h.dependencies.DeploymentPublishers.GetDeploymentPublisher(r.Context(), scope, deployment, publisher)
	if err != nil {
		deploymentPublisherProblem(r.Context(), w, "get deployment publisher", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) RevokeDeploymentPublisher(w http.ResponseWriter, r *http.Request, project, deployment, publisher string, params controlv1.RevokeDeploymentPublisherParams) {
	scope, ok := h.deploymentPublisherManager(w, r, params.TeamId, project)
	if !ok {
		return
	}
	if err := h.dependencies.DeploymentPublishers.RevokeDeploymentPublisher(r.Context(), scope, deployment, publisher, time.Now()); err != nil {
		deploymentPublisherProblem(r.Context(), w, "revoke deployment publisher", err)
		return
	}
	w.WriteHeader(204)
}
