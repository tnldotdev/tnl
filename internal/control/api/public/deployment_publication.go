package public

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type DeploymentPublicationStore interface {
	GetDeploymentPublication(context.Context, controlstate.DeploymentScope, string, string, time.Time) (controlstate.DeploymentPublication, error)
	AllocateDeploymentPublication(context.Context, controlstate.AllocateDeploymentPublicationRequest) (controlstate.PublicURL, error)
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
	var limits *controlv1.ProjectPublicLimits
	if result.Limits != nil {
		data, err := json.Marshal(result.Limits)
		if err != nil {
			writeControlStateProblem(r.Context(), w, "encode publication limits", err)
			return
		}
		if err = json.Unmarshal(data, &limits); err != nil {
			writeControlStateProblem(r.Context(), w, "encode publication limits", err)
			return
		}
	}
	writeJSON(w, 200, controlv1.DeploymentPublication{PublicUrl: publicURLResponse(result.PublicURL), Limits: limits})
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
	b, prefixes, mode, binding, ok := publisherAllocationInput(w, r)
	if !ok {
		return
	}
	u, err := h.dependencies.DeploymentPublication.AllocateDeploymentPublication(r.Context(), controlstate.AllocateDeploymentPublicationRequest{DeploymentScope: scope, Deployment: deployment, Invocation: b.InvocationId, Target: b.Target, Prefixes: prefixes, Binding: binding, Options: controlstate.PublisherPublicURLOptions{AccessMode: mode, RequirePostQuantum: b.RequirePostQuantum != nil && *b.RequirePostQuantum}, Now: time.Now()})
	if err != nil {
		deploymentProblem(r.Context(), w, "allocate deployment publication", err)
		return
	}
	writeJSON(w, 201, publicURLResponse(u))
}
