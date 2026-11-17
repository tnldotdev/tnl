package public

import (
	"context"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/control/api/serviceaccess"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type DeploymentPublicationStore interface {
	GetDeploymentPublication(context.Context, controlstate.DeploymentScope, string, string, time.Time) (controlstate.ServiceRecord, error)
	AllocateDeploymentPublication(context.Context, controlstate.AllocateDeploymentPublicationRequest) (controlstate.ServiceRecord, error)
}

func (h *handler) deploymentPublicationPrincipal(w http.ResponseWriter, r *http.Request, team, project string) (controlstate.DeploymentScope, bool) {
	w.Header().Set("Cache-Control", "no-store")
	if h.dependencies.DeploymentPublication == nil {
		writeProblem(w, 503, controlv1.Unavailable, "deployment publication is unavailable")
		return controlstate.DeploymentScope{}, false
	}
	_, p, ok := h.authenticatePublisher(w, r)
	if !ok {
		return controlstate.DeploymentScope{}, false
	}
	if p.Scope.TeamID != team || p.Scope.Kind != controlstate.DeploymentCredentialGrant {
		writeProblem(w, 403, controlv1.Forbidden, "credential does not approve deployment publication")
		return controlstate.DeploymentScope{}, false
	}
	token, _ := requestBearerToken(r)
	return controlstate.DeploymentScope{TeamID: team, ProjectKey: project, AccessToken: token}, true
}

func (h *handler) GetDeploymentPublication(w http.ResponseWriter, r *http.Request, project, deployment, service string, params controlv1.GetDeploymentPublicationParams) {
	scope, ok := h.deploymentPublicationPrincipal(w, r, params.TeamId, project)
	if !ok {
		return
	}
	result, err := h.dependencies.DeploymentPublication.GetDeploymentPublication(r.Context(), scope, deployment, service, time.Now())
	if err != nil {
		deploymentProblem(r.Context(), w, "resolve deployment publication", err)
		return
	}
	writeJSON(w, 200, serviceaccess.Service(result))
}

func (h *handler) AllocateDeploymentPublication(w http.ResponseWriter, r *http.Request, project, deployment string, params controlv1.AllocateDeploymentPublicationParams) {
	scope, ok := h.deploymentPublicationPrincipal(w, r, params.TeamId, project)
	if !ok {
		return
	}
	if !h.config.DNSAutomation {
		writeProblem(w, 409, controlv1.Conflict, "temporary publication requires automated DNS")
		return
	}
	b, ok := publisherAllocationInput(w, r)
	if !ok {
		return
	}
	service, err := h.dependencies.DeploymentPublication.AllocateDeploymentPublication(r.Context(), controlstate.AllocateDeploymentPublicationRequest{DeploymentScope: scope, Deployment: deployment, AllocateServiceRequest: b, Now: time.Now()})
	if err != nil {
		deploymentProblem(r.Context(), w, "allocate deployment publication", err)
		return
	}
	writeJSON(w, 201, serviceaccess.Service(service))
}
