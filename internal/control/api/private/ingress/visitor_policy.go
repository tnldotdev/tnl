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

type visitorPolicyStore interface {
	ReadIngressVisitorPolicy(context.Context, controlstate.IngressLeaseIdentity, visitorscope.Scope, int64, time.Time) (controlv1.VisitorPolicyUpdate, error)
}

func (s *service) ReadIngressVisitorPolicy(ctx context.Context, id string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
	identity, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	scope := visitorscope.Scope{Kind: visitorscope.Kind(body.Resource.Kind), ID: body.Resource.Id}
	if !ok || !scope.Valid() || body.AfterRevision < 0 {
		return controlv1.VisitorPolicyUpdate{}, serviceapi.NewProblemError(http.StatusBadRequest, "invalid_request", "invalid ingress visitor policy request")
	}
	store, ok := s.store.(visitorPolicyStore)
	if !ok {
		return controlv1.VisitorPolicyUpdate{}, serviceapi.NewProblemError(http.StatusServiceUnavailable, "unavailable", "visitor policy is unavailable")
	}
	result, err := store.ReadIngressVisitorPolicy(ctx, identity, scope, body.AfterRevision, s.now())
	return result, s.privateStateError(ctx, err)
}

func (s generatedServer) ReadIngressVisitorPolicy(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID) {
	var body ingressv1.IngressVisitorPolicyRequest
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	result, err := s.handler.service.ReadIngressVisitorPolicy(r.Context(), id, body)
	if s.handler.writeServiceError(w, r, err) {
		return
	}
	serviceapi.WriteJSON(w, http.StatusOK, result)
}
