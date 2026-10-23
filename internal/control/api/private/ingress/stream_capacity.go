package ingress

import (
	"context"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type streamCapacityStore interface {
	AllocateStreamCapacity(context.Context, controlstate.StreamCapacityRequest, time.Time) (controlstate.StreamCapacityAllocation, error)
	RetireStreamCapacity(context.Context, controlstate.IngressLeaseIdentity, string, time.Time) error
}

func (s *service) AllocateStreamCapacity(ctx context.Context, id string, body ingressv1.StreamCapacityRequest) (controlv1.StreamCapacityAllocation, error) {
	owner, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	scope := visitorscope.Scope{Kind: visitorscope.Kind(body.Resource.Kind), ID: body.Resource.Id}
	if !ok || !scope.Valid() || body.Capacity < 1 || body.Capacity > 1<<20 {
		return controlv1.StreamCapacityAllocation{}, serviceapi.NewProblemError(http.StatusBadRequest, "invalid_request", "invalid stream capacity request")
	}
	store, ok := s.store.(streamCapacityStore)
	if !ok {
		return controlv1.StreamCapacityAllocation{}, serviceapi.NewProblemError(http.StatusServiceUnavailable, "unavailable", "stream capacity is unavailable")
	}
	result, err := store.AllocateStreamCapacity(ctx, controlstate.StreamCapacityRequest{Owner: owner, Scope: scope, RunID: body.RunId, RunNumber: body.RunNumber, RequestID: body.RequestId, Capacity: int32(body.Capacity)}, s.now())
	if err != nil {
		return controlv1.StreamCapacityAllocation{}, s.privateStateError(ctx, err)
	}
	return result.Wire(), nil
}

func (s *service) RetireStreamCapacity(ctx context.Context, id, allocation string, body ingressv1.StreamCapacityRetirement) error {
	owner, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	if !ok {
		return serviceapi.NewProblemError(http.StatusBadRequest, "invalid_request", "invalid stream capacity owner")
	}
	store, ok := s.store.(streamCapacityStore)
	if !ok {
		return serviceapi.NewProblemError(http.StatusServiceUnavailable, "unavailable", "stream capacity is unavailable")
	}
	return s.privateStateError(ctx, store.RetireStreamCapacity(ctx, owner, allocation, s.now()))
}

func (s generatedServer) AllocateStreamCapacity(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID) {
	var body ingressv1.StreamCapacityRequest
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	result, err := s.handler.service.AllocateStreamCapacity(r.Context(), id, body)
	if s.handler.writeServiceError(w, r, err) {
		return
	}
	serviceapi.WriteJSON(w, http.StatusOK, result)
}

func (s generatedServer) RetireStreamCapacity(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID, allocation string) {
	var body ingressv1.StreamCapacityRetirement
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	if s.handler.writeServiceError(w, r, s.handler.service.RetireStreamCapacity(r.Context(), id, allocation, body)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
