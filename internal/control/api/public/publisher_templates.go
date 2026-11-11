package public

import (
	"net/http"
	"slices"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (h *handler) CreatePublisherGroup(w http.ResponseWriter, r *http.Request, project, name string) {
	w.Header().Set("Cache-Control", "no-store")
	var body struct {
		TeamId           string                              `json:"team_id"`
		From             string                              `json:"from"`
		Name             string                              `json:"name"`
		ExpectedRevision *int64                              `json:"expected_revision"`
		IdempotencyKey   string                              `json:"idempotency_key"`
		Bindings         controlstate.PublisherGroupBindings `json:"bindings"`
	}
	if decodeJSONLimited(w, r, &body, 4<<20) != nil || body.ExpectedRevision == nil || *body.ExpectedRevision < 1 || body.Name != "" && body.Name != name {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid publisher group creation")
		return
	}
	actor, ok := h.projectManager(w, r, body.TeamId)
	if !ok {
		return
	}
	if h.dependencies.PublisherGroups == nil {
		writeProblem(w, 503, controlv1.Unavailable, "publisher groups are unavailable")
		return
	}
	resource, err := h.dependencies.PublisherGroups.CreateBoundPublisherGroup(r.Context(), controlstate.CreateBoundPublisherGroupRequest{TeamID: body.TeamId, ProjectKey: project, ActorID: actor, ExpectedRevision: *body.ExpectedRevision, DNSAutomation: h.config.DNSAutomation, Now: time.Now(), Creation: controlstate.PublisherGroupCreation{Name: name, Template: body.From, Bindings: body.Bindings, IdempotencyKey: body.IdempotencyKey}})
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "create publisher group", err)
		return
	}
	if resource.Retired {
		writeProblem(w, 409, controlv1.Conflict, "publisher group was retired")
		return
	}
	if h.dependencies.ProjectConfiguration == nil {
		writeProblem(w, 503, controlv1.Unavailable, "project configuration is unavailable")
		return
	}
	result, err := h.dependencies.ProjectConfiguration.GetProjectConfiguration(r.Context(), body.TeamId, project, actor)
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "read publisher group connection", err)
		return
	}
	h.writeGroupConnection(w, result, name)
}

func (h *handler) RemovePublisherGroup(w http.ResponseWriter, r *http.Request, project, name string, params controlv1.RemovePublisherGroupParams) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := h.groupCaller(w, r, params.TeamId)
	if !ok {
		return
	}
	if h.dependencies.PublisherGroups == nil {
		writeProblem(w, 503, controlv1.Unavailable, "publisher groups are unavailable")
		return
	}
	err := h.dependencies.PublisherGroups.RetireBoundPublisherGroup(r.Context(), controlstate.GroupBindingMutationRequest{TeamID: params.TeamId, ProjectKey: project, Group: name, Caller: actor, ExpectedRevision: params.ExpectedRevision, DNSAutomation: h.config.DNSAutomation, Now: time.Now()})
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "remove publisher group", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) GetPublisherGroupConnection(w http.ResponseWriter, r *http.Request, project, name string, params controlv1.GetPublisherGroupConnectionParams) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := h.projectManager(w, r, params.TeamId)
	if !ok {
		return
	}
	if h.dependencies.ProjectConfiguration == nil {
		writeProblem(w, 503, controlv1.Unavailable, "project configuration is unavailable")
		return
	}
	result, err := h.dependencies.ProjectConfiguration.GetProjectConfiguration(r.Context(), params.TeamId, project, actor)
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "read publisher group connection", err)
		return
	}
	h.writeGroupConnection(w, result, name)
}

func (h *handler) writeGroupConnection(w http.ResponseWriter, project controlstate.AppliedProjectConfiguration, name string) {
	var group *controlstate.AppliedPublisherGroup
	for i := range project.Groups {
		candidate := &project.Groups[i]
		if candidate.ID == name || slices.Contains(candidate.GroupNames, name) {
			group = candidate
			break
		}
	}
	if group == nil {
		writeProblem(w, 404, controlv1.NotFound, "concrete publisher group not found")
		return
	}
	definition := group.Name
	if group.Template != "" {
		definition = group.Template
	}
	// the descriptor contains selection and protocol metadata only. saved workload
	// policy and current assertions remain the authority for every connection.
	services := map[string]controlv1.ServiceProtocol{}
	for key, service := range project.Configuration.Services {
		if service.PublisherGroup == definition {
			services[key] = controlv1.ServiceProtocol(service.Protocol)
		}
	}
	workloads := map[string]controlv1.PublisherGroupConnectionWorkload{}
	for key, policy := range project.Configuration.Workloads {
		selected := []string{}
		for _, service := range policy.Services {
			if _, found := services[service]; found {
				selected = append(selected, service)
			}
		}
		if len(selected) != 0 {
			workloads[key] = controlv1.PublisherGroupConnectionWorkload{MaxDurationSeconds: policy.MaxDurationSeconds, Provider: controlv1.WorkloadProvider(policy.Provider), Services: selected}
		}
	}
	label := project.ProjectLabel
	if label == "" {
		label = project.ProjectKey
	}
	writeJSON(w, 200, controlv1.PublisherGroupConnection{Schema: 1, Server: h.config.ControlURL, TeamId: project.TeamID, ProjectKey: project.ProjectKey, SourceFingerprint: project.SourceFingerprint, ProjectLabel: label, GroupId: group.ID, GroupName: group.Name, Services: services, Workloads: workloads})
}
