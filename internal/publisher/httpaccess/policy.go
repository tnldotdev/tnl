package httpaccess

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type PolicyClient interface {
	ReadPublisherVisitorPolicy(context.Context, controlv1.PublisherVisitorPolicyRequest, string) (controlv1.VisitorPolicyUpdate, error)
}

type Policy struct {
	lease     *visitorlease.Lease
	client    PolicyClient
	request   controlv1.PublisherVisitorPolicyRequest
	token     string
	cancel    context.CancelFunc
	done      chan struct{}
	gate      chan struct{}
	reconcile chan struct{}
}

// PreparePolicy starts one run-bound policy owner. close joins refresh before
// retiring its guards; the same owner serves HTTP and connector admission.
func PreparePolicy(ctx context.Context, client PolicyClient, scope visitorscope.Scope, run string, number int64, token string, report func(error), hostnames ...string) (*Policy, error) {
	if client == nil || run == "" || number < 1 || token == "" || len(hostnames) > 1 {
		return nil, errors.New("visitor policy needs the current publisher run")
	}
	lease, err := visitorlease.New(scope, nil)
	if err != nil {
		return nil, err
	}
	p := &Policy{lease: lease, client: client, token: token, done: make(chan struct{}), gate: make(chan struct{}, 1), reconcile: make(chan struct{}, 1), request: controlv1.PublisherVisitorPolicyRequest{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKind(scope.Kind), Id: scope.ID}, RunId: run, RunNumber: number}}
	if len(hostnames) == 1 {
		p.request.Hostname = hostnames[0]
	}
	if err := p.Refresh(ctx); err != nil {
		lease.Close()
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	go p.maintain(lifetime, report)
	return p, nil
}

func (p *Policy) Lease() *visitorlease.Lease { return p.lease }

// ObserveRenewal runs only after the service owner has accepted the exact run's
// heartbeat. mismatched evidence requests a full observation; it never moves
// the local deadline. the alias has its own independent policy owner.
func (p *Policy) ObserveRenewal(request visitorlease.Request, evidence *controlv1.PublisherPolicyConfirmation, observed, until time.Time) {
	if evidence != nil && evidence.ObservedAt.Equal(observed) && !evidence.ValidUntil.After(until) && p.lease.Confirm(request, *evidence) == nil {
		return
	}
	if evidence != nil || request.Confirmable() {
		select {
		case p.reconcile <- struct{}{}:
		default:
		}
	}
}

func (p *Policy) maintain(ctx context.Context, report func(error)) {
	defer close(p.done)
	timer := time.NewTimer(0)
	timer.Stop()
	defer timer.Stop()
	const freshReadInterval = 2 * time.Second
	var nextAttempt time.Time
	for {
		observed, until, confirmable, changed := p.lease.RefreshTiming()
		now := time.Now()
		due := now.Add(freshReadInterval)
		if !until.IsZero() {
			if confirmable {
				// healthy exact-run renewals move this deadline without reading.
				// only fetch here when a deadline is about to run out.
				due = until.Add(-min(freshReadInterval, until.Sub(observed)/2))
			} else {
				// aliases and time-dependent parents still need fresh facts.
				due = observed.Add(freshReadInterval)
			}
		}
		if nextAttempt.After(due) {
			due = nextAttempt
		}
		timer.Reset(max(0, time.Until(due)))
		select {
		case <-ctx.Done():
			return
		case <-changed:
			timer.Stop()
			continue
		case <-p.reconcile:
			timer.Stop()
		case <-timer.C:
			// a confirmation might have won at the same instant as the timer.
			select {
			case <-changed:
				continue
			default:
			}
		}
		nextAttempt = time.Now().Add(freshReadInterval)
		if err := p.Refresh(ctx); err != nil && ctx.Err() == nil && report != nil {
			report(err)
		}
	}
}

// Refresh shares the same bounded fetch-through-apply operation between explicit
// credential preparation and the background owner; ordinary requests never call it.
func (p *Policy) Refresh(ctx context.Context) error {
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
	if body.Hostname != "" && response.Policy.Hostname != body.Hostname {
		return visitortoken.ErrBinding
	}
	update, err := visitorlease.Decode(response)
	if err != nil {
		return err
	}
	return p.lease.Apply(request, update)
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

func (p *Policy) Close() {
	p.cancel()
	<-p.done
	p.lease.Close()
}
