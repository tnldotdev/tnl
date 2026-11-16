package public

import (
	"context"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type DeploymentConnectStore interface {
	SelectDeploymentServiceRun(context.Context, string, string, string, string, controlstate.VisitorTokenSource, time.Time) (controlstate.ServiceSelection, error)
}

func (h *handler) SelectDeploymentServiceRun(w http.ResponseWriter, r *http.Request, project, deployment, service string, params controlv1.SelectDeploymentServiceRunParams) {
	w.Header().Set("Cache-Control", "no-store")
	if h.dependencies.DeploymentConnect == nil {
		writeProblem(w, 503, controlv1.Unavailable, "deployment service selection is unavailable")
		return
	}
	var body controlv1.SelectDeploymentServiceRunJSONRequestBody
	if decodeJSONLimited(w, r, &body, 8<<10) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid deployment service selection")
		return
	}
	source, human, err := parseVisitorTokenSource(body.Source)
	if err != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid deployment visitor source")
		return
	}
	ctx := r.Context()
	if human {
		var ok bool
		ctx, ok = h.visitorTokenPrincipal(w, r)
		if !ok {
			return
		}
	} else if len(r.Header.Values("Authorization")) != 0 {
		writeProblem(w, 400, controlv1.InvalidRequest, "select one deployment visitor source")
		return
	}
	selected, err := h.dependencies.DeploymentConnect.SelectDeploymentServiceRun(ctx, params.TeamId, project, deployment, service, source, time.Now())
	if err != nil {
		writeVisitorTokenProblem(r.Context(), w, err)
		return
	}
	writeJSON(w, 200, privateSelectionResponse(selected))
}
