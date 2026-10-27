// package visitorpolicy owns run-bound policy fetching for public URL and service
// publishers. both runtimes compose this lifetime; it depends only on policy
// mechanics and control contracts, never on either publication orchestrator.
package visitorpolicy

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type Client interface {
	ReadPublisherVisitorPolicy(context.Context, controlv1.PublisherVisitorPolicyRequest, string) (controlv1.VisitorPolicyUpdate, error)
}

type Policy struct {
	Lease   *visitorlease.Lease
	client  Client
	request controlv1.PublisherVisitorPolicyRequest
	token   string
	cancel  context.CancelFunc
	done    chan struct{}
}

func Prepare(ctx context.Context, client Client, scope visitorscope.Scope, run string, number int64, token string, report func(error)) (*Policy, error) {
	if client == nil || run == "" || number < 1 || token == "" {
		return nil, errors.New("visitor policy needs the current publisher run")
	}
	lease, err := visitorlease.New(scope, nil)
	if err != nil {
		return nil, err
	}
	p := &Policy{Lease: lease, client: client, token: token, done: make(chan struct{}), request: controlv1.PublisherVisitorPolicyRequest{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKind(scope.Kind), Id: scope.ID}, RunId: run, RunNumber: number}}
	if err := p.prepare(ctx); err != nil {
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
				if err := p.Refresh(lifetime); err != nil && lifetime.Err() == nil && report != nil {
					report(err)
				}
			}
		}
	}()
	return p, nil
}

// the first repeatable-read policy snapshot can lose a serialization race with
// run startup. retry only temporary control failures before any visitor is
// admitted, with the same run token and a fresh lease observation per attempt.
func (p *Policy) prepare(ctx context.Context) error {
	startup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	delay := 100 * time.Millisecond
	for {
		err := p.Refresh(startup)
		if err == nil {
			return nil
		}
		if startup.Err() != nil {
			return errors.Join(context.Cause(startup), err)
		}
		reason, known := failure.ReasonOf(err)
		if !errors.Is(err, context.DeadlineExceeded) && (!known || reason != failure.ServerUnavailable && reason != failure.ServerRateLimited) {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-startup.Done():
			timer.Stop()
			return errors.Join(context.Cause(startup), err)
		case <-timer.C:
		}
		delay = min(2*delay, time.Second)
	}
}

func (p *Policy) Refresh(ctx context.Context) error {
	request := p.Lease.Begin()
	body := p.request
	body.ObservedAllocations = p.Lease.ObservedAllocations(body.RunId)
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
	return p.Lease.Apply(request, update)
}

func (p *Policy) Close() {
	p.cancel()
	<-p.done
	p.Lease.Close()
}

func (*Policy) String() string   { return "publisher visitor policy" }
func (*Policy) GoString() string { return "publisher visitor policy" }
