package public

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type DeploymentCredentialStore interface {
	RegisterDeploymentCredential(context.Context, controlstate.RegisterDeploymentCredentialRequest) (controlstate.DeploymentCredential, error)
}

func (h *handler) deploymentPrincipal(w http.ResponseWriter, r *http.Request, team, project string) (controlstate.DeploymentScope, bool) {
	if token, ok := requestBearerToken(r); ok && strings.HasPrefix(token, "pta_") {
		_, identity, authenticated := h.authenticatePublisher(w, r)
		if !authenticated {
			return controlstate.DeploymentScope{}, false
		}
		if identity.Scope.TeamID != team || identity.Scope.Kind != controlstate.DeploymentCredentialGrant {
			writeProblem(w, 403, controlv1.Forbidden, "credential does not approve deployment management")
			return controlstate.DeploymentScope{}, false
		}
		return controlstate.DeploymentScope{TeamID: team, ProjectKey: project, AccessToken: token}, true
	}
	actor, ok := h.projectManager(w, r, team)
	return controlstate.DeploymentScope{TeamID: team, ProjectKey: project, ActorID: actor}, ok
}

func (h *handler) RegisterDeploymentCredential(w http.ResponseWriter, r *http.Request, project string, params controlv1.RegisterDeploymentCredentialParams) {
	w.Header().Set("Cache-Control", "no-store")
	if h.dependencies.DeploymentCredentials == nil {
		writeProblem(w, 503, controlv1.Unavailable, "deployment credential registration is unavailable")
		return
	}
	actor, ok := h.projectManager(w, r, params.TeamId)
	if !ok {
		return
	}
	// retain the generated fields, but not the union's permissive JSON decoder.
	// the serving boundary rejects unknown fields before authorizing registration.
	type registrationBody controlv1.RegisterDeploymentCredentialRequest
	var body registrationBody
	if decodeJSONLimited(w, r, &body, 32<<10) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid deployment credential registration")
		return
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(body.PublicKey)
	if err != nil || len(public) != 32 || body.ExpiresIn < 60 || body.ExpiresIn > 2592000 ||
		(body.AllDeployments == nil) == (body.DeploymentIds == nil) || body.AllDeployments != nil && !*body.AllDeployments || body.DeploymentIds != nil && len(*body.DeploymentIds) == 0 {
		writeProblem(w, 400, controlv1.InvalidRequest, "select a public signing key, existing services, exact deployment IDs or all_deployments, and a lifetime of 60-2592000 seconds")
		return
	}
	permissions := map[string][]string{}
	if body.Permissions.Manage != nil {
		permissions["manage"] = *body.Permissions.Manage
	}
	if body.Permissions.Connect != nil {
		permissions["connect"] = *body.Permissions.Connect
	}
	request := controlstate.RegisterDeploymentCredentialRequest{
		DeploymentScope: controlstate.DeploymentScope{TeamID: params.TeamId, ProjectKey: project, ActorID: actor},
		Name:            body.Name, IdempotencyKey: params.IdempotencyKey, PublicKey: public, Permissions: permissions,
		AllDeployments: body.AllDeployments != nil, Lifetime: time.Duration(body.ExpiresIn) * time.Second, Now: time.Now(),
	}
	if body.DeploymentIds != nil {
		request.DeploymentIDs = *body.DeploymentIds
	}
	result, err := h.dependencies.DeploymentCredentials.RegisterDeploymentCredential(r.Context(), request)
	if err != nil {
		deploymentProblem(r.Context(), w, "register deployment credential", err)
		return
	}
	writeJSON(w, 201, result)
}
