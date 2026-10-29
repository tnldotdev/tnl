package ingress

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type visitorPolicyClient interface {
	ReadIngressVisitorPolicy(context.Context, string, ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error)
}

func (c *HTTPControlClient) ReadIngressVisitorPolicy(ctx context.Context, id string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
	response, err := c.client.ReadIngressVisitorPolicyWithResponse(ctx, id, body)
	if err != nil {
		return controlv1.VisitorPolicyUpdate{}, err
	}
	if response == nil {
		return controlv1.VisitorPolicyUpdate{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return controlv1.VisitorPolicyUpdate{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

type visitorPolicy struct {
	lease        *visitorlease.Lease
	client       visitorPolicyClient
	scope        visitorscope.Scope
	currentLease func() ingressv1.IngressLease
	observations func() []ingressv1.IngressStreamAllocationObservation
}

func newVisitorPolicy(client visitorPolicyClient, scope visitorscope.Scope, current func() ingressv1.IngressLease) (*visitorPolicy, error) {
	if client == nil || current == nil {
		return nil, errors.New("visitor policy needs the current ingress lease")
	}
	lease, err := visitorlease.New(scope, nil)
	if err != nil {
		return nil, err
	}
	return &visitorPolicy{lease: lease, client: client, scope: scope, currentLease: current}, nil
}

func (p *visitorPolicy) refresh(ctx context.Context) error {
	request := p.lease.Begin()
	process := p.currentLease()
	body := ingressv1.IngressVisitorPolicyRequest{IngressRunId: process.IngressRunId, IngressLeaseRevision: process.IngressLeaseRevision, Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKind(p.scope.Kind), Id: p.scope.ID}, AfterRevision: request.AfterRevision}
	if request.Snapshot {
		body.AfterRevision = 0
	}
	if p.observations != nil && !request.Snapshot {
		observed := p.observations()
		body.ObservedAllocations = &observed
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	response, err := p.client.ReadIngressVisitorPolicy(call, process.IngressId, body)
	if err != nil {
		return err
	}
	if err := call.Err(); err != nil {
		return err
	}
	update, err := visitorlease.Decode(response)
	if err != nil {
		return err
	}
	return p.lease.Apply(request, update)
}

func (p *visitorPolicy) Close() {
	p.lease.Close()
}
