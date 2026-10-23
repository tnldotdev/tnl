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
	lease   *visitorlease.Lease
	client  visitorPolicyClient
	request controlv1.PublisherVisitorPolicyRequest
	token   string
	cancel  context.CancelFunc
	done    chan struct{}
}

func prepareVisitorPolicy(ctx context.Context, client visitorPolicyClient, scope visitorscope.Scope, run string, number int64, token string, report func(error)) (*visitorPolicy, error) {
	if client == nil || run == "" || number < 1 || token == "" {
		return nil, errors.New("visitor policy needs the current publisher run")
	}
	lease, err := visitorlease.New(scope, nil)
	if err != nil {
		return nil, err
	}
	p := &visitorPolicy{lease: lease, client: client, token: token, done: make(chan struct{}), request: controlv1.PublisherVisitorPolicyRequest{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKind(scope.Kind), Id: scope.ID}, RunId: run, RunNumber: number}}
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
	request := p.lease.Begin()
	body := p.request
	body.AfterRevision = request.AfterRevision
	if request.Snapshot {
		body.AfterRevision = 0
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	response, err := p.client.ReadPublisherVisitorPolicy(call, body, p.token)
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
	p.cancel()
	<-p.done
	p.lease.Close()
}
