package httpaccess

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
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
	sourceKey [32]byte
	cancel    context.CancelFunc
	done      chan struct{}
	gate      chan struct{}
	mu        sync.RWMutex
	blocks    httpprotection.Blocks
}

// PreparePolicy starts one run-bound policy owner. close joins refresh before
// retiring its guards; the same owner serves HTTP and connector admission.
func PreparePolicy(ctx context.Context, client PolicyClient, scope visitorscope.Scope, run string, number int64, token string, report func(error)) (*Policy, error) {
	if client == nil || run == "" || number < 1 || token == "" {
		return nil, errors.New("visitor policy needs the current publisher run")
	}
	lease, err := visitorlease.New(scope, nil)
	if err != nil {
		return nil, err
	}
	p := &Policy{lease: lease, client: client, token: token, done: make(chan struct{}), gate: make(chan struct{}, 1), request: controlv1.PublisherVisitorPolicyRequest{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKind(scope.Kind), Id: scope.ID}, RunId: run, RunNumber: number}}
	if err := p.Refresh(ctx); err != nil {
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

func (p *Policy) Lease() *visitorlease.Lease { return p.lease }

// SourceKey is fixed by the initial policy snapshot before the owner is shared.
func (p *Policy) SourceKey() [32]byte { return p.sourceKey }

func (p *Policy) SourceBlocked(source netip.Addr, now time.Time) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.blocks.Blocked(source, now)
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
	update, err := visitorlease.Decode(response)
	if err != nil {
		return err
	}
	blocks, err := httpprotection.DecodeBlocks(response.TemporaryBlocks)
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
	p.mu.Lock()
	p.blocks = blocks
	p.mu.Unlock()
	// services have no source key; keep their zero value immutable too.
	if key != ([32]byte{}) && p.sourceKey == ([32]byte{}) {
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

func (p *Policy) Close() {
	p.cancel()
	<-p.done
	p.lease.Close()
}
