package public

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// collection management is an explicit capability, separate from environment
// creation and its atomic membership/default selection.
type CollectionStore interface {
	CreateCollection(context.Context, controlstate.CreateCollectionRequest) (controlstate.Collection, error)
	GetCollection(context.Context, string, string, string, string) (controlstate.Collection, error)
	ListCollections(context.Context, string, string, string) ([]controlstate.Collection, error)
	UpdateCollectionDefault(context.Context, controlstate.UpdateCollectionDefaultRequest) (controlstate.Collection, error)
}

func (h *handler) collectionStore(w http.ResponseWriter) (CollectionStore, bool) {
	w.Header().Set("Cache-Control", "no-store")
	if h.dependencies.Collections == nil || h.config.ControlURL == "" {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "collection management is unavailable on this server")
		return nil, false
	}
	return h.dependencies.Collections, true
}

func collectionProblem(ctx context.Context, w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrCollectionInvalid):
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid collection or default definition")
	case errors.Is(err, controlstate.ErrCollectionStale):
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "collection changed; read its current mutation revision and retry")
	case errors.Is(err, controlstate.ErrCollectionNotFound):
		writeProblem(w, http.StatusNotFound, controlv1.NotFound, "collection or service definition not found in this project")
	case errors.Is(err, controlstate.ErrServiceAccess):
		writeProblem(w, http.StatusForbidden, controlv1.Forbidden, "collection management requires current team manager access")
	case errors.Is(err, controlstate.ErrServiceConflict):
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "collection name conflicts with its saved creation request")
	default:
		environmentProblem(ctx, w, operation, err)
	}
}

func (h *handler) CreateCollection(w http.ResponseWriter, r *http.Request, project string) {
	store, ok := h.collectionStore(w)
	if !ok {
		return
	}
	var body controlv1.CreateCollectionRequest
	if err := decodeEnvironmentJSON(w, r, &body); err != nil {
		environmentJSONProblem(w, err, "invalid collection creation request")
		return
	}
	if body.TeamId == "" || body.Name == "" || body.DefaultDefinitionRevision < 1 {
		collectionProblem(r.Context(), w, "validate collection", controlstate.ErrCollectionInvalid)
		return
	}
	actor, ok := h.projectManager(w, r, body.TeamId)
	if !ok {
		return
	}
	result, err := store.CreateCollection(r.Context(), controlstate.CreateCollectionRequest{TeamID: body.TeamId, ProjectKey: project, ActorID: actor, Name: body.Name, DefaultDefinitionRevision: body.DefaultDefinitionRevision, Now: time.Now()})
	if err != nil {
		collectionProblem(r.Context(), w, "create collection", err)
		return
	}
	writeJSON(w, http.StatusOK, h.collectionResponse(result))
}

func (h *handler) GetCollection(w http.ResponseWriter, r *http.Request, project, id string, params controlv1.GetCollectionParams) {
	store, ok := h.collectionStore(w)
	if !ok {
		return
	}
	actor, ok := h.projectManager(w, r, params.TeamId)
	if !ok {
		return
	}
	result, err := store.GetCollection(r.Context(), params.TeamId, project, id, actor)
	if err != nil {
		collectionProblem(r.Context(), w, "get collection", err)
		return
	}
	writeJSON(w, http.StatusOK, h.collectionResponse(result))
}

func (h *handler) ListCollections(w http.ResponseWriter, r *http.Request, project string, params controlv1.ListCollectionsParams) {
	store, ok := h.collectionStore(w)
	if !ok {
		return
	}
	actor, ok := h.projectManager(w, r, params.TeamId)
	if !ok {
		return
	}
	result, err := store.ListCollections(r.Context(), params.TeamId, project, actor)
	if err != nil {
		collectionProblem(r.Context(), w, "list collections", err)
		return
	}
	response := make([]controlv1.Collection, 0, len(result))
	for _, collection := range result {
		response = append(response, h.collectionResponse(collection))
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *handler) UpdateCollectionDefault(w http.ResponseWriter, r *http.Request, project, id string) {
	store, ok := h.collectionStore(w)
	if !ok {
		return
	}
	var body controlv1.UpdateCollectionDefaultRequest
	if err := decodeEnvironmentJSON(w, r, &body); err != nil {
		environmentJSONProblem(w, err, "invalid collection default request")
		return
	}
	if body.TeamId == "" || body.ExpectedRevision < 1 || body.ExpectedRevision == 1<<63-1 || body.DefinitionRevision < 1 {
		collectionProblem(r.Context(), w, "validate collection default", controlstate.ErrCollectionInvalid)
		return
	}
	actor, ok := h.projectManager(w, r, body.TeamId)
	if !ok {
		return
	}
	result, err := store.UpdateCollectionDefault(r.Context(), controlstate.UpdateCollectionDefaultRequest{TeamID: body.TeamId, ProjectKey: project, ActorID: actor, CollectionID: id, ExpectedRevision: body.ExpectedRevision, DefinitionRevision: body.DefinitionRevision, Now: time.Now()})
	if err != nil {
		collectionProblem(r.Context(), w, "update collection default", err)
		return
	}
	writeJSON(w, http.StatusOK, h.collectionResponse(result))
}

func (h *handler) collectionResponse(input controlstate.Collection) controlv1.Collection {
	return controlv1.Collection{CollectionId: input.ID, TeamId: input.TeamID, ProjectKey: input.ProjectKey, Name: input.Name, DefaultDefinitionRevision: input.DefaultDefinitionRevision, MutationRevision: input.MutationRevision, Ref: controlv1.CollectionReference{Server: h.config.ControlURL, ProjectKey: input.ProjectKey, CollectionId: input.ID}}
}
