package ingress

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type visitorPolicyStore interface {
	ReadIngressVisitorPolicy(context.Context, controlstate.IngressLeaseIdentity, visitorscope.Scope, string, int64, int64, int64, time.Time) (controlv1.VisitorPolicyUpdate, error)
}

func (s *service) ReadIngressVisitorPolicy(ctx context.Context, id string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
	identity, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	scope := visitorscope.Scope{Kind: visitorscope.Kind(body.Resource.Kind), ID: body.Resource.Id}
	if !ok || scope.Kind != visitorscope.PublicURL || !scope.Valid() || !serviceapi.ValidIdentifiers(body.PublishRunId) || body.PublishRunNumber < 1 || body.PolicyRevision < 1 || body.AfterRevision < 0 {
		return controlv1.VisitorPolicyUpdate{}, serviceapi.NewProblemError(http.StatusBadRequest, "invalid_request", "invalid ingress visitor policy request")
	}
	result, err := s.store.ReadIngressVisitorPolicy(ctx, identity, scope, body.PublishRunId, body.PublishRunNumber, body.PolicyRevision, body.AfterRevision, s.now())
	if errors.Is(err, controlstate.ErrVisitorPolicy) {
		return controlv1.VisitorPolicyUpdate{}, serviceapi.NewProblemError(http.StatusConflict, "visitor_policy_stale", "visitor policy does not match this run")
	}
	if err != nil {
		return controlv1.VisitorPolicyUpdate{}, s.storeError(ctx, err)
	}
	return result, nil
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
