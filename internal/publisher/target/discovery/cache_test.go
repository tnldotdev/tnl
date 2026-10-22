package discovery

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type providerFunc func(context.Context, Request) (ResolvedTarget, error)

func (f providerFunc) Discover(ctx context.Context, r Request) (ResolvedTarget, error) {
	return f(ctx, r)
}

func targetFixture(t *testing.T) ResolvedTarget {
	ca, _ := certificate(t, fixtureHost, 1)
	return ResolvedTarget{Address: fixtureHost + ":443", ServerName: fixtureHost, CA: ca, CADigest: digest(ca), ARN: "arn:aws:eks:us-east-1:123456789012:cluster/demo", ResourceID: "2026-10-20T00:00:00Z", Protocol: "kubernetes"}
}
func requestFixture() Request {
	return Request{Type: "eks", Region: "us-east-1", Cluster: "demo", Protocol: "kubernetes"}
}

func resolverFixture(t *testing.T, provider Provider, options Options) (*Resolver, func(time.Duration)) {
	t.Helper()
	r, err := New(provider, options)
	if err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	r.now = func() time.Time { return time.Unix(0, clock.Load()) }
	t.Cleanup(r.Close)
	return r, func(d time.Duration) { clock.Add(int64(d)) }
}

func TestCacheCoalescesCanceledWaitersAndBoundsConcurrentKeys(t *testing.T) {
	target := targetFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	r, _ := resolverFixture(t, providerFunc(func(ctx context.Context, request Request) (ResolvedTarget, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return target, nil
		case <-ctx.Done():
			return ResolvedTarget{}, context.Cause(ctx)
		}
	}), Options{Capacity: 1})
	ctx, cancel := context.WithCancel(t.Context())
	first := make(chan error, 1)
	go func() { _, err := r.Resolve(ctx, requestFixture()); first <- err }()
	<-started
	var workers sync.WaitGroup
	errorsOut := make(chan error, 32)
	for range 32 {
		workers.Go(func() { _, err := r.Resolve(t.Context(), requestFixture()); errorsOut <- err })
	}
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter: %v", err)
	}
	other := requestFixture()
	other.Cluster = "other"
	if _, err := r.Resolve(t.Context(), other); err == nil || ErrorKind(err) != Unavailable {
		t.Fatal("capacity did not bound in-flight keys", err)
	}
	close(release)
	workers.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal("one canceled waiter killed shared work", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("duplicate lookups: %d", calls.Load())
	}
	if _, err := r.Resolve(t.Context(), requestFixture()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("fresh cache missed")
	}
}

func TestCacheFreshnessTransientFallbackAndHardFailureBarrier(t *testing.T) {
	for _, hard := range []Kind{"", Permission, NotFound, NotReady, Metadata, Authentication} {
		t.Run(string(hard), func(t *testing.T) {
			target := targetFixture(t)
			var next atomic.Int32
			r, advance := resolverFixture(t, providerFunc(func(context.Context, Request) (ResolvedTarget, error) {
				switch next.Load() {
				case 0:
					return target, nil
				case 1:
					return ResolvedTarget{}, discoveryError(hard, nil)
				default:
					return ResolvedTarget{}, discoveryError(Unavailable, nil)
				}
			}), Options{TTL: time.Second, MaxStaleness: 3 * time.Second, RetryInterval: time.Second})
			if _, err := r.Resolve(t.Context(), requestFixture()); err != nil {
				t.Fatal(err)
			}
			advance(time.Second)
			if hard != "" {
				next.Store(1)
				if _, err := r.Resolve(t.Context(), requestFixture()); err == nil || ErrorKind(err) != hard {
					t.Fatal("hard error used last-good target", err)
				}
				advance(time.Second)
			}
			next.Store(2)
			_, err := r.Resolve(t.Context(), requestFixture())
			if hard == "" && err != nil {
				t.Fatal("transient fallback was not usable inside bound", err)
			}
			if hard != "" && err == nil {
				t.Fatal("transient error resurrected target after hard rejection")
			}
			advance(3 * time.Second)
			if _, err := r.Resolve(t.Context(), requestFixture()); err == nil {
				t.Fatal("stale target accepted")
			}
		})
	}
}

func TestObservedReplacementCannotBeHiddenByARevertedCacheResult(t *testing.T) {
	target := targetFixture(t)
	var replaced atomic.Bool
	r, advance := resolverFixture(t, providerFunc(func(context.Context, Request) (ResolvedTarget, error) {
		result := target
		if replaced.Load() {
			result.ResourceID = "replacement"
		}
		return result, nil
	}), Options{TTL: time.Second})
	old, err := r.Prepare(t.Context(), requestFixture())
	if err != nil {
		t.Fatal(err)
	}
	replaced.Store(true)
	advance(time.Second)
	if _, err := r.Resolve(t.Context(), requestFixture()); err != nil {
		t.Fatal(err)
	}
	replaced.Store(false)
	advance(time.Second)
	if _, err := r.Resolve(t.Context(), requestFixture()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := old.ResolveTarget(t.Context()); err == nil || ErrorKind(err) != Changed {
		t.Fatal("an observed replacement was hidden from an old preparation", err)
	}
}

func TestPublicationPinsReplacementCARotationAndEndpointRefresh(t *testing.T) {
	for _, change := range []string{"resource", "arn", "ca", "ca-identifier", "endpoint"} {
		t.Run(change, func(t *testing.T) {
			original := targetFixture(t)
			changed := original
			switch change {
			case "resource":
				changed.ResourceID = "replacement"
			case "arn":
				changed.ARN = "arn:aws:eks:us-east-1:123456789012:cluster/replacement"
			case "ca":
				changed.CA, _ = certificate(t, fixtureHost, 2)
				changed.CADigest = digest(changed.CA)
			case "ca-identifier":
				changed.CAIdentifier = "rotated"
			case "endpoint":
				changed.ServerName = "failover.example.us-east-1.eks.amazonaws.com"
				changed.Address = changed.ServerName + ":443"
			}
			var useChanged atomic.Bool
			r, advance := resolverFixture(t, providerFunc(func(context.Context, Request) (ResolvedTarget, error) {
				if useChanged.Load() {
					return changed, nil
				}
				return original, nil
			}), Options{TTL: time.Second})
			prepared, err := r.Prepare(t.Context(), requestFixture())
			if err != nil {
				t.Fatal(err)
			}
			useChanged.Store(true)
			advance(time.Second)
			address, _, err := prepared.ResolveTarget(t.Context())
			if change == "endpoint" {
				if err != nil || address != changed.Address {
					t.Fatal("new connection did not capture refreshed DNS endpoint", err)
				}
			} else {
				if err == nil || ErrorKind(err) != Changed {
					t.Fatal("changed trust/resource silently reused preparation", err)
				}
				// a reverted response does not un-fence an old publication.
				useChanged.Store(false)
				advance(time.Second)
				if _, _, err := prepared.ResolveTarget(t.Context()); err == nil {
					t.Fatal("old preparation was revived")
				}
			}
			if _, err := r.Prepare(t.Context(), requestFixture()); err != nil {
				t.Fatal("fresh preparation could not accept current resource", err)
			}
			if original.ServerName != fixtureHost {
				t.Fatal("captured target mutated")
			}
		})
	}
}

func TestCacheProviderDeadlineAndCloseJoinSharedWork(t *testing.T) {
	var active atomic.Int32
	r, err := New(providerFunc(func(ctx context.Context, _ Request) (ResolvedTarget, error) {
		active.Add(1)
		defer active.Add(-1)
		<-ctx.Done()
		return ResolvedTarget{}, context.Cause(ctx)
	}), Options{Timeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := r.Resolve(t.Context(), requestFixture()); err == nil || ErrorKind(err) != Unavailable {
		t.Fatal("provider timeout not classified", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("provider deadline exceeded bound")
	}
	r.Close()
	if active.Load() != 0 {
		t.Fatal("Close did not join work")
	}
	if _, err := r.Resolve(t.Context(), requestFixture()); !errors.Is(err, context.Canceled) {
		t.Fatal("closed resolver admitted work")
	}
}

func TestRequestValidationDoesNotLoadAWS(t *testing.T) {
	base := requestFixture()
	for _, change := range []func(*Request){
		func(r *Request) { r.Type = "other" }, func(r *Request) { r.Protocol = "http" }, func(r *Request) { r.Region = "https://private.invalid" }, func(r *Request) { r.Account = "*" }, func(r *Request) { r.Instance = "extra" }, func(r *Request) { r.Cluster = "arn:aws:eks:us-east-1:123456789012:cluster/demo" },
		func(r *Request) { r.Type, r.Protocol = "rds", "postgres"; r.Instance = "extra" }, func(r *Request) {
			r.Type, r.Protocol, r.Cluster, r.Instance, r.Endpoint = "rds", "postgres", "", "demo", "reader"
		},
	} {
		r := base
		change(&r)
		provider := AWS{Load: func(context.Context, string) (Clients, error) {
			t.Fatal("invalid selector loaded credentials")
			return Clients{}, nil
		}}
		if _, err := provider.Discover(t.Context(), r); err == nil || ErrorKind(err) != Invalid {
			t.Fatal("invalid request accepted", err)
		}
	}
}
