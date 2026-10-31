package publisher

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type visitorPolicyClient interface {
	ReadPublisherVisitorPolicy(context.Context, controlv1.PublisherVisitorPolicyRequest, string) (controlv1.VisitorPolicyUpdate, error)
}

type visitorPolicy struct {
	lease     *visitorlease.Lease
	client    visitorPolicyClient
	request   controlv1.PublisherVisitorPolicyRequest
	token     string
	sourceKey [32]byte
	cancel    context.CancelFunc
	done      chan struct{}
	gate      chan struct{}
}

func prepareVisitorPolicy(ctx context.Context, client visitorPolicyClient, scope visitorscope.Scope, run string, number int64, token string, report func(error)) (*visitorPolicy, error) {
	if client == nil || run == "" || number < 1 || token == "" {
		return nil, errors.New("visitor policy needs the current publisher run")
	}
	lease, err := visitorlease.New(scope, nil)
	if err != nil {
		return nil, err
	}
	p := &visitorPolicy{lease: lease, client: client, token: token, done: make(chan struct{}), gate: make(chan struct{}, 1), request: controlv1.PublisherVisitorPolicyRequest{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKind(scope.Kind), Id: scope.ID}, RunId: run, RunNumber: number}}
	if err := p.refresh(ctx); err != nil {
		lease.Close()
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	go func() {
		defer close(p.done)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-lifetime.Done():
				return
			case <-ticker.C:
				if err := p.refresh(lifetime); err != nil && lifetime.Err() == nil && report != nil {
					report(err)
				}
			}
		}
	}()
	return p, nil
}

func (p *visitorPolicy) refresh(ctx context.Context) error {
	// preparation and renewal share one fetch-through-apply owner. waiting spends
	// the same fixed request budget and cannot queue another control request.
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	select {
	case p.gate <- struct{}{}:
		defer func() { <-p.gate }()
	case <-call.Done():
		return context.Cause(call)
	}
	if err := refreshContextError(call); err != nil {
		return err
	}
	request := p.lease.Begin()
	request.Deadline, _ = call.Deadline()
	body := p.request
	body.AfterRevision = request.AfterRevision
	if request.Snapshot {
		body.AfterRevision = 0
	}
	response, err := p.client.ReadPublisherVisitorPolicy(call, body, p.token)
	if err != nil {
		return err
	}
	if err := refreshContextError(call); err != nil {
		return err
	}
	update, err := visitorlease.Decode(response)
	if err != nil {
		return err
	}
	key := p.sourceKey
	if p.request.Resource.Kind == "public_url" {
		if response.VisitorSourceKey == nil || len(*response.VisitorSourceKey) != 32 || response.VisitorSourceAuthority != nil {
			return visitorlease.ErrUpdate
		}
		key = [32]byte(*response.VisitorSourceKey)
		if key == ([32]byte{}) || p.sourceKey != ([32]byte{}) && p.sourceKey != key {
			return visitorlease.ErrUpdate
		}
	}
	if err := p.lease.Apply(request, update); err != nil {
		return err
	}
	if p.sourceKey == ([32]byte{}) {
		p.sourceKey = key
	}
	return nil
}

// timer callbacks can lag their absolute deadline. neither a queued fetch nor
// a late response may spend that delay as additional preparation authority.
func refreshContextError(ctx context.Context) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func (p *visitorPolicy) Close() {
	p.cancel()
	<-p.done
	p.lease.Close()
}
