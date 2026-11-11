package public

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (h *handler) groupCaller(w http.ResponseWriter, r *http.Request, team string) (controlstate.GroupCaller, bool) {
	if credential, ok := requestBearerToken(r); ok && strings.HasPrefix(credential, "mpc_") {
		return controlstate.ProvisioningGroupCaller(credential), true
	}
	identity, ok := h.projectManager(w, r, team)
	return controlstate.HumanGroupCaller(identity), ok
}

func (h *handler) createBoundPublisherGroup(w http.ResponseWriter, r *http.Request, project, selector string) (controlstate.PublisherGroupResource, bool) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.CreatePublisherGroupRequest
	if decodeJSONLimited(w, r, &body, 4<<20) != nil || body.ExpectedRevision < 1 || selector != "" && body.Name != nil && *body.Name != "" && selector != *body.Name {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid publisher group creation")
		return controlstate.PublisherGroupResource{}, false
	}
	name, key := "", ""
	if body.Name != nil {
		name = *body.Name
	}
	if body.IdempotencyKey != nil {
		key = *body.IdempotencyKey
	}
	if selector != "" {
		name = selector
	}
	actor, ok := h.groupCaller(w, r, body.TeamId)
	if !ok {
		return controlstate.PublisherGroupResource{}, false
	}
	if h.dependencies.PublisherGroups == nil {
		writeProblem(w, 503, controlv1.Unavailable, "publisher groups are unavailable")
		return controlstate.PublisherGroupResource{}, false
	}
	var bindings controlstate.PublisherGroupBindings
	if body.Bindings != nil {
		var err error
		bindings, err = publisherGroupBindingsFromAPI(*body.Bindings)
		if err != nil {
			projectConfigurationProblem(r.Context(), w, "validate publisher group bindings", err)
			return controlstate.PublisherGroupResource{}, false
		}
	}
	resource, err := h.dependencies.PublisherGroups.CreateBoundPublisherGroup(r.Context(), controlstate.CreateBoundPublisherGroupRequest{TeamID: body.TeamId, ProjectKey: project, Caller: actor, ExpectedRevision: body.ExpectedRevision, DNSAutomation: h.config.DNSAutomation, Now: time.Now(), Creation: controlstate.PublisherGroupCreation{Name: name, Template: body.From, IdempotencyKey: key, Bindings: bindings}})
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "create publisher group", err)
		return resource, false
	}
	return resource, true
}

func (h *handler) CreateBoundPublisherGroup(w http.ResponseWriter, r *http.Request, project string) {
	resource, ok := h.createBoundPublisherGroup(w, r, project, "")
	if ok {
		writeJSON(w, 200, resource)
	}
}

func (h *handler) ListPublisherGroups(w http.ResponseWriter, r *http.Request, project string, params controlv1.ListPublisherGroupsParams) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := h.groupCaller(w, r, params.TeamId)
	if !ok {
		return
	}
	if h.dependencies.PublisherGroups == nil {
		writeProblem(w, 503, controlv1.Unavailable, "project configuration is unavailable")
		return
	}
	result, err := h.dependencies.PublisherGroups.ListManagedPublisherGroups(r.Context(), params.TeamId, project, actor, time.Now())
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "list publisher groups", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) GetPublisherGroup(w http.ResponseWriter, r *http.Request, project, id string, params controlv1.GetPublisherGroupParams) {
	resource, ok := h.managedPublisherGroup(w, r, params.TeamId, project, id)
	if ok {
		writeJSON(w, 200, resource)
	}
}

func (h *handler) managedPublisherGroup(w http.ResponseWriter, r *http.Request, team, project, id string) (controlstate.PublisherGroupResource, bool) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := h.groupCaller(w, r, team)
	if !ok {
		return controlstate.PublisherGroupResource{}, false
	}
	if h.dependencies.PublisherGroups == nil {
		writeProblem(w, 503, controlv1.Unavailable, "publisher groups are unavailable")
		return controlstate.PublisherGroupResource{}, false
	}
	result, err := h.dependencies.PublisherGroups.GetManagedPublisherGroupForCaller(r.Context(), team, project, id, actor, time.Now())
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "get publisher group", err)
		return result, false
	}
	return result, true
}

func (h *handler) ListPublisherGroupMembers(w http.ResponseWriter, r *http.Request, project, id string, params controlv1.ListPublisherGroupMembersParams) {
	resource, ok := h.managedPublisherGroup(w, r, params.TeamId, project, id)
	if ok {
		writeJSON(w, 200, resource.Members)
	}
}

func (h *handler) UpdatePublisherGroupBindings(w http.ResponseWriter, r *http.Request, project, id string) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.UpdatePublisherGroupBindingsRequest
	if decodeJSONLimited(w, r, &body, 4<<20) != nil || body.ExpectedRevision < 1 || body.Bindings == nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid publisher group bindings")
		return
	}
	actor, ok := h.groupCaller(w, r, body.TeamId)
	if !ok {
		return
	}
	if h.dependencies.PublisherGroups == nil {
		writeProblem(w, 503, controlv1.Unavailable, "publisher groups are unavailable")
		return
	}
	bindings, err := publisherGroupBindingsFromAPI(body.Bindings)
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "validate publisher group bindings", err)
		return
	}
	result, err := h.dependencies.PublisherGroups.UpdateBoundPublisherGroup(r.Context(), controlstate.GroupBindingMutationRequest{TeamID: body.TeamId, ProjectKey: project, Group: id, Caller: actor, ExpectedRevision: body.ExpectedRevision, Bindings: bindings, DNSAutomation: h.config.DNSAutomation, Now: time.Now()})
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "update publisher group bindings", err)
		return
	}
	writeJSON(w, 200, result)
}

// the generated contract owns decoding; state owns normalization and authority.
func publisherGroupBindingsFromAPI(input controlv1.PublisherGroupBindings) (controlstate.PublisherGroupBindings, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	var bindings controlstate.PublisherGroupBindings
	if err := json.Unmarshal(encoded, &bindings); err != nil {
		return nil, err
	}
	return bindings, nil
}
