package public

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// EnvironmentStore owns pinned definitions, exact environment mutations and
// their publication projections. current authorization is not definition history.
type EnvironmentStore interface {
	CreateServiceDefinition(context.Context, controlstate.CreateServiceDefinitionRequest) (controlstate.ServiceDefinitionRevision, error)
	CreateEnvironment(context.Context, controlstate.CreateEnvironmentRequest) (controlstate.Environment, error)
	GetEnvironment(context.Context, string, string, string, string) (controlstate.Environment, error)
	ListEnvironments(context.Context, string, string, string) ([]controlstate.Environment, error)
	ApplyEnvironment(context.Context, controlstate.ApplyEnvironmentRequest) (controlstate.Environment, error)
	ApplyEnvironments(context.Context, controlstate.ApplyEnvironmentsRequest) ([]controlstate.Environment, error)
	RetireEnvironment(context.Context, controlstate.RetireEnvironmentRequest) error
}

func (h *handler) environmentStore(w http.ResponseWriter) (EnvironmentStore, bool) {
	w.Header().Set("Cache-Control", "no-store")
	if h.dependencies.Environments == nil || h.config.ControlURL == "" {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "environment management is unavailable on this server")
		return nil, false
	}
	return h.dependencies.Environments, true
}

func environmentProblem(ctx context.Context, w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrEnvironmentInvalid), errors.Is(err, controlstate.ErrServiceDefinitionInvalid), errors.Is(err, controlstate.ErrProjectConfigurationInvalid), errors.Is(err, controlstate.ErrCollectionInvalid):
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid service definition or environment targets; protocol changes require complete replacement targets")
	case errors.Is(err, controlstate.ErrCollectionStale):
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "collection changed; read its current mutation revision and use a new environment creation request")
	case errors.Is(err, controlstate.ErrCollectionNotFound):
		writeProblem(w, http.StatusNotFound, controlv1.NotFound, "collection or service definition not found in this project")
	case errors.Is(err, controlstate.ErrEnvironmentStale):
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "environment changed; read its current mutation revision and apply again")
	case errors.Is(err, controlstate.ErrEnvironmentRetired):
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "environment was retired; its creation key cannot be reused")
	case errors.Is(err, controlstate.ErrEnvironmentNotFound), errors.Is(err, pgx.ErrNoRows):
		writeProblem(w, http.StatusNotFound, controlv1.NotFound, "environment or service definition not found in this project")
	case errors.Is(err, controlstate.ErrServiceAccess), errors.Is(err, controlstate.ErrPublicURLAccess), errors.Is(err, controlstate.ErrMachineDenied):
		writeProblem(w, http.StatusForbidden, controlv1.Forbidden, "environment management requires current team manager access")
	case errors.Is(err, controlstate.ErrProjectSourceConflict):
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "project belongs to another source; select a different project")
	case errors.Is(err, controlstate.ErrServiceConflict), errors.Is(err, controlstate.ErrPublicURLConflict):
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "environment name or creation key conflicts with a saved resource")
	case errors.Is(err, controlstate.ErrServicePortsExhausted):
		writeProblem(w, http.StatusServiceUnavailable, controlv1.PlacementUnavailable, "ingress pool has no available service port; ask the operator to extend its service port inventory")
	case errors.Is(err, controlstate.ErrServicePoolPinned):
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "environment has no room in its saved ingress pool; ask the operator to extend that pool")
	case errors.Is(err, controlstate.ErrProjectManaged):
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "resource is managed by an environment; update that environment")
	default:
		writeControlStateProblem(ctx, w, operation, err)
	}
}

func environmentJSONProblem(w http.ResponseWriter, err error, message string) {
	if errors.Is(err, errEnvironmentJSONNull) {
		message = "explicit null is not allowed; omit optional fields or use tls: {} for verified system-CA trust"
	}
	writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, message)
}

func (h *handler) CreateServiceDefinition(w http.ResponseWriter, r *http.Request, project string) {
	store, ok := h.environmentStore(w)
	if !ok {
		return
	}
	var body controlv1.CreateServiceDefinitionRequest
	if err := decodeEnvironmentJSON(w, r, &body); err != nil {
		environmentJSONProblem(w, err, "invalid service definition request")
		return
	}
	actor, ok := h.projectManager(w, r, body.TeamId)
	if !ok {
		return
	}
	if len(body.Definition.Services) == 0 || len(body.Definition.Services) > 128 {
		environmentProblem(r.Context(), w, "validate service definition", controlstate.ErrServiceDefinitionInvalid)
		return
	}
	definition := controlstate.ServiceDefinition{Services: make(map[string]controlstate.ServiceDefinitionService, len(body.Definition.Services))}
	for name, service := range body.Definition.Services {
		definition.Services[name] = controlstate.ServiceDefinitionService{Protocol: string(service.Protocol)}
	}
	result, err := store.CreateServiceDefinition(r.Context(), controlstate.CreateServiceDefinitionRequest{
		TeamID: body.TeamId, ProjectKey: project, SourceFingerprint: body.SourceFingerprint,
		ProjectLabel: optionalFeedbackString(body.ProjectLabel), ActorID: actor, Definition: definition, Now: time.Now(),
	})
	if err != nil {
		environmentProblem(r.Context(), w, "create service definition", err)
		return
	}
	response := controlv1.ServiceDefinitionRevision{
		TeamId: result.TeamID, ProjectKey: result.ProjectKey, SourceFingerprint: result.SourceFingerprint,
		Revision: result.Revision, ConfigurationHash: result.ConfigurationHash,
		Definition: controlv1.ServiceDefinition{Services: make(map[string]controlv1.ServiceDefinitionService, len(result.Definition.Services))},
	}
	for name, service := range result.Definition.Services {
		response.Definition.Services[name] = controlv1.ServiceDefinitionService{Protocol: controlv1.ServiceProtocol(service.Protocol)}
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *handler) CreateEnvironment(w http.ResponseWriter, r *http.Request, project string) {
	store, ok := h.environmentStore(w)
	if !ok {
		return
	}
	var body controlv1.CreateEnvironmentRequest
	if err := decodeEnvironmentJSON(w, r, &body); err != nil {
		environmentJSONProblem(w, err, "invalid environment creation request")
		return
	}
	actor, ok := h.projectManager(w, r, body.TeamId)
	if !ok {
		return
	}
	request, err := environmentCreationFromAPI(r.Context(), body)
	if err != nil {
		environmentProblem(r.Context(), w, "validate environment creation", err)
		return
	}
	request.ProjectKey, request.ActorID = project, actor
	request.DNSAutomation, request.Now = h.config.DNSAutomation, time.Now()
	result, err := store.CreateEnvironment(r.Context(), request)
	if err != nil {
		environmentProblem(r.Context(), w, "create environment", err)
		return
	}
	writeJSON(w, http.StatusOK, h.environmentResponse(result))
}

func (h *handler) GetEnvironment(w http.ResponseWriter, r *http.Request, project, id string, params controlv1.GetEnvironmentParams) {
	store, ok := h.environmentStore(w)
	if !ok {
		return
	}
	actor, ok := h.projectManager(w, r, params.TeamId)
	if !ok {
		return
	}
	result, err := store.GetEnvironment(r.Context(), params.TeamId, project, id, actor)
	if err != nil {
		environmentProblem(r.Context(), w, "get environment", err)
		return
	}
	if result.Retired {
		environmentProblem(r.Context(), w, "get environment", controlstate.ErrEnvironmentNotFound)
		return
	}
	writeJSON(w, http.StatusOK, h.environmentResponse(result))
}

func (h *handler) ListEnvironments(w http.ResponseWriter, r *http.Request, project string, params controlv1.ListEnvironmentsParams) {
	store, ok := h.environmentStore(w)
	if !ok {
		return
	}
	actor, ok := h.projectManager(w, r, params.TeamId)
	if !ok {
		return
	}
	result, err := store.ListEnvironments(r.Context(), params.TeamId, project, actor)
	if err != nil {
		environmentProblem(r.Context(), w, "list environments", err)
		return
	}
	response := make([]controlv1.Environment, 0, len(result))
	for _, environment := range result {
		if !environment.Retired {
			response = append(response, h.environmentResponse(environment))
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *handler) ApplyEnvironment(w http.ResponseWriter, r *http.Request, project, id string) {
	store, ok := h.environmentStore(w)
	if !ok {
		return
	}
	var body controlv1.ApplyEnvironmentRequest
	if err := decodeEnvironmentJSON(w, r, &body); err != nil {
		environmentJSONProblem(w, err, "invalid environment apply request")
		return
	}
	actor, ok := h.projectManager(w, r, body.TeamId)
	if !ok {
		return
	}
	application, err := environmentApplicationFromAPI(r.Context(), controlv1.EnvironmentApplication{EnvironmentId: id, DefinitionRevision: body.DefinitionRevision, ExpectedRevision: body.ExpectedRevision, Targets: body.Targets})
	if err != nil {
		environmentProblem(r.Context(), w, "validate environment targets", err)
		return
	}
	result, err := store.ApplyEnvironment(r.Context(), controlstate.ApplyEnvironmentRequest{
		TeamID: body.TeamId, ProjectKey: project, ActorID: actor, EnvironmentApplication: application,
		DNSAutomation: h.config.DNSAutomation, Now: time.Now(),
	})
	if err != nil {
		environmentProblem(r.Context(), w, "apply environment", err)
		return
	}
	writeJSON(w, http.StatusOK, h.environmentResponse(result))
}

func (h *handler) ApplyEnvironments(w http.ResponseWriter, r *http.Request, project string) {
	store, ok := h.environmentStore(w)
	if !ok {
		return
	}
	var body controlv1.ApplyEnvironmentsRequest
	if err := decodeEnvironmentJSON(w, r, &body); err != nil {
		environmentJSONProblem(w, err, "invalid environment rollout request")
		return
	}
	actor, ok := h.projectManager(w, r, body.TeamId)
	if !ok {
		return
	}
	if len(body.Environments) == 0 || len(body.Environments) > 128 {
		environmentProblem(r.Context(), w, "validate environment rollout", controlstate.ErrEnvironmentInvalid)
		return
	}
	items := make([]controlstate.EnvironmentApplication, 0, len(body.Environments))
	for _, input := range body.Environments {
		application, err := environmentApplicationFromAPI(r.Context(), input)
		if err != nil {
			environmentProblem(r.Context(), w, "validate environment rollout", err)
			return
		}
		items = append(items, application)
	}
	result, err := store.ApplyEnvironments(r.Context(), controlstate.ApplyEnvironmentsRequest{
		TeamID: body.TeamId, ProjectKey: project, ActorID: actor, Items: items,
		DNSAutomation: h.config.DNSAutomation, Now: time.Now(),
	})
	if err != nil {
		environmentProblem(r.Context(), w, "apply environments", err)
		return
	}
	response := make([]controlv1.Environment, 0, len(result))
	for _, environment := range result {
		response = append(response, h.environmentResponse(environment))
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *handler) RetireEnvironment(w http.ResponseWriter, r *http.Request, project, id string, params controlv1.RetireEnvironmentParams) {
	store, ok := h.environmentStore(w)
	if !ok {
		return
	}
	actor, ok := h.projectManager(w, r, params.TeamId)
	if !ok {
		return
	}
	if err := store.RetireEnvironment(r.Context(), controlstate.RetireEnvironmentRequest{
		TeamID: params.TeamId, ProjectKey: project, ActorID: actor, EnvironmentID: id, ExpectedRevision: params.ExpectedRevision, Now: time.Now(),
	}); err != nil {
		environmentProblem(r.Context(), w, "retire environment", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func environmentCreationFromAPI(ctx context.Context, input controlv1.CreateEnvironmentRequest) (controlstate.CreateEnvironmentRequest, error) {
	if input.IdempotencyKey == "" || input.Targets == nil || (input.CollectionId == nil) != (input.ExpectedCollectionRevision == nil) || input.DefinitionRevision != nil && *input.DefinitionRevision < 1 || input.CollectionId == nil && input.DefinitionRevision == nil {
		return controlstate.CreateEnvironmentRequest{}, controlstate.ErrEnvironmentInvalid
	}
	result := controlstate.CreateEnvironmentRequest{TeamID: input.TeamId, SourceFingerprint: input.SourceFingerprint, ProjectLabel: optionalFeedbackString(input.ProjectLabel), Name: input.Name, IdempotencyKey: input.IdempotencyKey}
	if input.CollectionId != nil {
		if !opaqueid.Valid(*input.CollectionId, opaqueid.CollectionPrefix) || *input.ExpectedCollectionRevision < 1 {
			return result, controlstate.ErrEnvironmentInvalid
		}
		result.CollectionID, result.ExpectedCollectionRevision = *input.CollectionId, *input.ExpectedCollectionRevision
	}
	// only wire omission with a collection maps to the state default selector.
	if input.DefinitionRevision != nil {
		result.DefinitionRevision = *input.DefinitionRevision
	}
	var err error
	result.Targets, err = environmentTargetsFromAPI(ctx, input.Targets)
	return result, err
}

func environmentApplicationFromAPI(ctx context.Context, input controlv1.EnvironmentApplication) (controlstate.EnvironmentApplication, error) {
	result := controlstate.EnvironmentApplication{EnvironmentID: input.EnvironmentId, DefinitionRevision: input.DefinitionRevision, ExpectedRevision: input.ExpectedRevision}
	if input.Targets != nil {
		var err error
		result.Targets, err = environmentTargetsFromAPI(ctx, *input.Targets)
		if err != nil {
			return controlstate.EnvironmentApplication{}, err
		}
	}
	return result, nil
}

func environmentTargetsFromAPI(ctx context.Context, input controlv1.EnvironmentTargets) (controlstate.EnvironmentTargets, error) {
	if len(input) > 128 {
		return nil, controlstate.ErrEnvironmentInvalid
	}
	result := make(controlstate.EnvironmentTargets, len(input))
	for name, target := range input {
		value := controlstate.EnvironmentTarget{Address: optionalFeedbackString(target.Address)}
		if target.Discovery != nil {
			if target.Address != nil || target.Tls != nil {
				return nil, controlstate.ErrEnvironmentInvalid
			}
			value.Discovery = &controlstate.ProjectTargetDiscovery{
				Type: string(target.Discovery.Type), Region: target.Discovery.Region,
				Cluster: target.Discovery.Cluster, Instance: target.Discovery.Instance,
			}
			if target.Discovery.Endpoint != nil {
				value.Discovery.Endpoint = new(string(*target.Discovery.Endpoint))
			}
		}
		if target.Tls != nil {
			trust, err := environmentTargetTrust(ctx, value.Address, *target.Tls)
			if err != nil {
				return nil, err
			}
			value.TLS = trust
		}
		result[name] = value
	}
	return result, nil
}

func environmentTargetTrust(ctx context.Context, address string, input controlv1.EnvironmentTargetTLS) (*controlstate.ProjectTargetTLS, error) {
	target := address
	if strings.Contains(address, "://") {
		canonical, err := targetsyntax.NormalizeTarget(strings.TrimSuffix(address, "/"))
		if err != nil {
			return nil, controlstate.ErrEnvironmentInvalid
		}
		origin, err := targetsyntax.ParseCanonicalTarget(canonical)
		if err != nil {
			return nil, controlstate.ErrEnvironmentInvalid
		}
		target = origin.Host
	}
	// fixed system trust cannot read a local file or fetch a caller-supplied URL.
	snapshot, err := targettrust.NewCache(nil).Capture(ctx, "", target, config.TrustSource{CA: "system", Hostname: input.Hostname})
	if err != nil {
		if ctx.Err() != nil {
			return nil, err
		}
		return nil, errors.Join(controlstate.ErrEnvironmentInvalid, err)
	}
	if input.CaPem != nil && *input.CaPem != "" {
		snapshot, err = targettrust.CapturePEM(snapshot.Hostname, []byte(*input.CaPem))
		if err != nil {
			return nil, errors.Join(controlstate.ErrEnvironmentInvalid, err)
		}
	}
	declaration, err := snapshot.Declaration()
	if err != nil || input.Digest != nil && *input.Digest != declaration.Digest {
		return nil, controlstate.ErrEnvironmentInvalid
	}
	return &controlstate.ProjectTargetTLS{Hostname: declaration.Hostname, CAPEM: string(declaration.CAPEM), Digest: declaration.Digest}, nil
}

func (h *handler) environmentResponse(input controlstate.Environment) controlv1.Environment {
	result := controlv1.Environment{
		Id: input.ID, TeamId: input.TeamID, ProjectKey: input.ProjectKey, Name: input.Name,
		AppliedDefinitionRevision: input.AppliedDefinitionRevision, MutationRevision: input.MutationRevision, ConfigurationHash: input.ConfigurationHash,
		Ref:     controlv1.EnvironmentReference{Server: h.config.ControlURL, ProjectKey: input.ProjectKey, EnvironmentId: input.ID},
		Targets: make(controlv1.EnvironmentTargets, len(input.Targets)), Services: make([]controlv1.EnvironmentService, 0, len(input.Services)),
	}
	if input.CollectionID != "" {
		result.CollectionId = new(input.CollectionID)
	}
	for _, service := range input.Services {
		result.Services = append(result.Services, controlv1.EnvironmentService{
			Service: service.Service, ServiceId: service.ServiceID, Protocol: controlv1.ServiceProtocol(service.Protocol),
			Hostname: service.Hostname, Port: service.Port, Public: service.Public, TrustRevision: service.TrustRevision,
		})
	}
	for name, target := range input.Targets {
		value := controlv1.EnvironmentTarget{}
		if target.Address != "" {
			value.Address = new(target.Address)
		}
		if target.TLS != nil {
			value.Tls = &controlv1.EnvironmentTargetTLS{Hostname: new(target.TLS.Hostname), Digest: new(target.TLS.Digest)}
			if target.TLS.CAPEM != "" {
				value.Tls.CaPem = new(target.TLS.CAPEM)
			}
		}
		if target.Discovery != nil {
			value.Discovery = &controlv1.ProjectTargetDiscovery{
				Type: controlv1.ProjectTargetDiscoveryType(target.Discovery.Type), Region: target.Discovery.Region,
				Cluster: target.Discovery.Cluster, Instance: target.Discovery.Instance,
			}
			if target.Discovery.Endpoint != nil {
				value.Discovery.Endpoint = new(controlv1.ProjectTargetDiscoveryEndpoint(*target.Discovery.Endpoint))
			}
		}
		result.Targets[name] = value
	}
	return result
}
