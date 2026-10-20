package targetdiscovery

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

type Provider interface {
	Discover(context.Context, Request) (ResolvedTarget, error)
}

type Options struct {
	TTL, MaxStaleness, Timeout, RetryInterval time.Duration
	Capacity                                  int
}

type entry struct {
	target               ResolvedTarget
	lastSuccess, retryAt time.Time
	err                  error
	blocked              bool
	generation           uint64
	done                 chan struct{}
}

// Resolver bounds entries and concurrent lookups together. shared work has its
// own deadline: canceling one waiter cannot cancel another waiter's discovery.
// entries are retained until Close, so a failed refresh cannot reset a pin.
type Resolver struct {
	provider Provider
	options  Options
	mu       sync.Mutex
	entries  map[Request]*entry
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	now      func() time.Time
}

func New(provider Provider, options Options) (*Resolver, error) {
	if provider == nil {
		provider = AWS{}
	}
	if options.TTL == 0 {
		options.TTL = time.Minute
	}
	if options.MaxStaleness == 0 {
		options.MaxStaleness = 5 * time.Minute
	}
	if options.Timeout == 0 {
		options.Timeout = 10 * time.Second
	}
	if options.RetryInterval == 0 {
		options.RetryInterval = min(5*time.Second, options.TTL)
	}
	if options.Capacity == 0 {
		options.Capacity = 128
	}
	if options.TTL < time.Millisecond || options.TTL > 5*time.Minute || options.MaxStaleness < options.TTL || options.MaxStaleness > 15*time.Minute || options.Timeout < time.Millisecond || options.Timeout > 30*time.Second || options.RetryInterval < time.Millisecond || options.RetryInterval > options.TTL || options.Capacity < 1 || options.Capacity > 1024 {
		return nil, discoveryError(Invalid, nil)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Resolver{provider: provider, options: options, entries: map[Request]*entry{}, ctx: ctx, cancel: cancel, now: time.Now}, nil
}

func (r *Resolver) Close() { r.mu.Lock(); r.cancel(); r.mu.Unlock(); r.wg.Wait() }

// Resolve refreshes expired metadata before returning it. only transient AWS
// unavailability permits last-success fallback, and never beyond MaxStaleness.
func (r *Resolver) Resolve(ctx context.Context, request Request) (ResolvedTarget, error) {
	key, err := request.Normalize()
	if err != nil {
		return ResolvedTarget{}, err
	}
	if err := ctx.Err(); err != nil {
		return ResolvedTarget{}, context.Cause(ctx)
	}
	r.mu.Lock()
	if r.ctx.Err() != nil {
		r.mu.Unlock()
		return ResolvedTarget{}, context.Canceled
	}
	e := r.entries[key]
	if e == nil {
		if len(r.entries) >= r.options.Capacity {
			r.mu.Unlock()
			return ResolvedTarget{}, discoveryError(Unavailable, nil)
		}
		e = &entry{}
		r.entries[key] = e
	}
	if e.done == nil && !r.now().Before(e.retryAt) {
		e.done = make(chan struct{})
		r.wg.Add(1)
		go r.refresh(context.WithoutCancel(ctx), key, e)
	}
	done := e.done
	r.mu.Unlock()
	if done != nil {
		select {
		case <-ctx.Done():
			return ResolvedTarget{}, context.Cause(ctx)
		case <-done:
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	state := "fresh"
	err = e.err
	if err != nil && (ErrorKind(err) != Unavailable || e.blocked) {
		state = "failed"
	} else if e.lastSuccess.IsZero() {
		state = "failed"
	} else if !now.Before(e.lastSuccess.Add(r.options.MaxStaleness)) {
		state, err = "stale", discoveryError(Stale, e.err)
	} else if err != nil {
		state, err = "last_success", nil
	}
	observability.TargetDiscoveryCache(ctx, key.Type, key.Protocol, state, e.lastSuccess)
	if err != nil {
		return ResolvedTarget{}, err
	}
	return e.target, nil
}

func (r *Resolver) refresh(parent context.Context, key Request, e *entry) {
	defer r.wg.Done()
	ctx, cancel := context.WithTimeout(parent, r.options.Timeout)
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	defer cancel()
	started := time.Now()
	ctx, finish := observability.Start(ctx, "publisher.target_discovery")
	target, err := r.provider.Discover(ctx, key)
	if ctx.Err() != nil {
		err = context.Cause(ctx)
	}
	if err == nil {
		err = target.validate(key)
	}
	// a provider deadline is transient; caller cancellation is handled only by
	// the waiter and never changes the shared result.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		err = discoveryError(Unavailable, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	outcome := "success"
	if err == nil {
		observability.TargetDiscoveryIdentity(ctx, target.ARN, target.ResourceID)
	}
	finish(err)
	if err == nil {
		if !e.lastSuccess.IsZero() && !samePin(e.target, target) {
			outcome = "changed"
			e.generation++
		}
		if e.generation == 0 {
			e.generation = 1
		}
		target.generation = e.generation
		e.target, e.lastSuccess, e.retryAt = target, r.now(), r.now().Add(r.options.TTL)
		e.blocked = false
	} else {
		if ErrorKind(err) != Unavailable {
			e.blocked = true
		}
		e.retryAt = r.now().Add(r.options.RetryInterval)
		outcome = string(ErrorKind(err))
	}
	e.err = err
	observability.TargetDiscovery(ctx, key.Type, key.Protocol, outcome, time.Since(started))
	close(e.done)
	e.done = nil
}

// Preparation pins resource identity and CA for one publication. a subsequent
// preparation can accept changed metadata; an existing one always fences it.
type Preparation struct {
	resolver *Resolver
	request  Request
	pin      ResolvedTarget
	fenced   atomic.Bool
}

func (r *Resolver) Prepare(ctx context.Context, request Request) (*Preparation, error) {
	target, err := r.Resolve(ctx, request)
	if err != nil {
		return nil, err
	}
	return &Preparation{resolver: r, request: request, pin: target}, nil
}

func samePin(a, b ResolvedTarget) bool {
	return a.ARN == b.ARN && a.ResourceID == b.ResourceID && a.CADigest == b.CADigest && a.CAIdentifier == b.CAIdentifier && a.Protocol == b.Protocol
}

// ResolveTarget captures a fresh DNS endpoint and verified TLS config for a NEW
// connection. it cannot reconnect, replay, or mutate an already captured stream.
func (p *Preparation) ResolveTarget(ctx context.Context) (string, *tls.Config, error) {
	if p.fenced.Load() {
		return "", nil, discoveryError(Changed, nil)
	}
	target, err := p.resolver.Resolve(ctx, p.request)
	if err != nil {
		return "", nil, err
	}
	if !samePin(p.pin, target) || p.pin.generation != target.generation {
		p.fenced.Store(true)
		return "", nil, discoveryError(Changed, nil)
	}
	verifier, err := target.Verifier()
	if p.fenced.Load() {
		return "", nil, discoveryError(Changed, nil)
	}
	return target.Address, verifier, err
}
