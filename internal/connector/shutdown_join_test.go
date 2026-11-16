package connector

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestConnectorBackendCloseJoinsCleanupAfterCallerCancellation(t *testing.T) {
	for _, stop := range []string{"cancel", "deadline"} {
		t.Run(stop, func(t *testing.T) {
			independent := errors.New("independent joined cleanup failure")
			entered := make(chan struct{})
			b := &connectorConnectionBackend{
				cancel: func() { close(entered) }, cleanupErr: errors.Join(context.Canceled, independent),
			}
			b.workers.Add(1)
			release := sync.OnceFunc(b.workers.Done)
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			joined := false
			go func() { done <- b.Close(ctx) }()
			defer func() {
				release()
				if !joined {
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Error("failed test did not join its shutdown worker")
					}
				}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("shutdown did not publish its stop fence")
			}
			if stop == "cancel" {
				cancel()
			}
			<-ctx.Done()
			select {
			case err := <-done:
				joined = true
				t.Fatal("caller cancellation was mistaken for joined cleanup", err)
			default:
			}
			release()
			select {
			case err := <-done:
				joined = true
				if !errors.Is(err, independent) || !errors.Is(err, context.Cause(ctx)) {
					t.Fatal("shutdown lost its independent joined failure", err)
				}
			case <-time.After(time.Second):
				t.Fatal("shutdown did not return after actual cleanup joined")
			}
		})
	}
}

func TestConnectorBackendCloseKeepsCompletedResultAfterContextCancellation(t *testing.T) {
	independent := errors.New("independent completed cleanup failure")
	for _, test := range []struct {
		name    string
		cleanup error
	}{
		{name: "clean"},
		{name: "independent", cleanup: independent},
		{name: "canceled independent", cleanup: errors.Join(context.Canceled, independent)},
		{name: "deadline independent", cleanup: errors.Join(context.DeadlineExceeded, independent)},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stops atomic.Int32
			b := &connectorConnectionBackend{cancel: func() { stops.Add(1) }, cleanupErr: test.cleanup}
			firstContext, cancelFirst := context.WithCancel(t.Context())
			defer cancelFirst()
			first := b.Close(firstContext)
			if test.cleanup == nil && first != nil || test.cleanup != nil && !errors.Is(first, test.cleanup) {
				t.Fatal("first cleanup lost its actual result", first)
			}
			cancelFirst()
			// both a fresh caller and the canceled original context must see
			// the completed result, not another cleanup or a new stop cause.
			for _, later := range []context.Context{t.Context(), firstContext} {
				if got := b.Close(later); got != first {
					t.Fatal("later cancellation changed the completed cleanup result", got, first)
				}
			}
			if stops.Load() != 1 {
				t.Fatal("completed cleanup ran its stop fence more than once", stops.Load())
			}
		})
	}
}

func TestConnectorBackendCloseRetainsFirstCanceledOrExpiredBudget(t *testing.T) {
	for _, stop := range []string{"cancel", "deadline"} {
		for _, failed := range []bool{false, true} {
			name := stop + "/clean"
			if failed {
				name = stop + "/independent"
			}
			t.Run(name, func(t *testing.T) {
				independent := errors.New("independent first-budget cleanup failure")
				b := &connectorConnectionBackend{}
				if failed {
					b.cleanupErr = errors.Join(context.Canceled, independent)
				}
				ctx, cancel := context.WithCancel(t.Context())
				if stop == "deadline" {
					cancel()
					ctx, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
				} else {
					cancel()
				}
				defer cancel()
				first := b.Close(ctx)
				if !errors.Is(first, context.Cause(ctx)) || failed && !errors.Is(first, independent) {
					t.Fatal("first spent budget or independent cleanup cause was erased", first)
				}
				if got := b.Close(t.Context()); got != first {
					t.Fatal("fresh caller retried or erased a failed first cleanup", got, first)
				}
			})
		}
	}
}

func TestConnectorBackendCloseConcurrentCallersShareBudgetAndJoin(t *testing.T) {
	independent := errors.New("independent concurrent cleanup failure")
	entered, ownedEntered, ownedExited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var stops atomic.Int32
	announce := sync.OnceFunc(func() { close(entered) })
	b := &connectorConnectionBackend{
		cancel:     func() { stops.Add(1); announce() },
		cleanupErr: errors.Join(context.Canceled, independent),
	}
	held := make(chan struct{})
	release := sync.OnceFunc(func() { close(held) })
	b.workers.Go(func() {
		close(ownedEntered)
		<-held
		close(ownedExited)
	})
	var callers sync.WaitGroup
	defer func() { release(); callers.Wait(); b.workers.Wait() }()
	select {
	case <-ownedEntered:
	case <-time.After(time.Second):
		t.Fatal("owned cleanup worker did not start")
	}
	firstContext, cancelFirst := context.WithCancel(t.Context())
	defer cancelFirst()
	results := make(chan error, 3)
	callers.Go(func() { results <- b.Close(firstContext) })
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first Close did not enter its stop fence")
	}
	laterContext, cancelLater := context.WithCancel(t.Context())
	cancelLater()
	started := make(chan struct{}, 2)
	for _, later := range []context.Context{laterContext, t.Context()} {
		callers.Go(func() {
			started <- struct{}{}
			results <- b.Close(later)
		})
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("concurrent Close caller did not start")
		}
	}
	cancelFirst()
	if got := b.cleanup(); got != firstContext {
		t.Fatal("concurrent caller replaced the first cleanup budget")
	}
	select {
	case err := <-results:
		t.Fatal("Close returned while owned cleanup was still held", err)
	default:
	}
	release()
	until := time.NewTimer(time.Second)
	defer until.Stop()
	var first error
	for i := range 3 {
		select {
		case err := <-results:
			if !errors.Is(err, context.Canceled) || !errors.Is(err, independent) {
				t.Fatal("concurrent caller lost first-budget or independent failure", err)
			}
			if i == 0 {
				first = err
			} else if err != first {
				t.Fatal("concurrent callers did not observe one completed result", err, first)
			}
		case <-until.C:
			t.Fatal("concurrent Close did not join after releasing owned work")
		}
	}
	callers.Wait()
	select {
	case <-ownedExited:
	default:
		t.Fatal("Close callers returned before their owned worker exited")
	}
	if stops.Load() != 1 {
		t.Fatal("concurrent Close repeated the stop fence", stops.Load())
	}
	if got := b.Close(t.Context()); got != first {
		t.Fatal("completed concurrent shutdown changed on replay", got, first)
	}
}

func TestConnectorBackendCloseRevokesRealSessionOnlyOnce(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var revocations atomic.Int32
			b := connectionBackendFixture(t, func(w http.ResponseWriter, r *http.Request, session authorityv1.WorkloadSession) {
				if r.Method != http.MethodDelete || r.URL.Path != "/v1/workload-sessions/"+session.Id {
					t.Error("shutdown performed unrelated authority work", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				revocations.Add(1)
				w.WriteHeader(status)
			})
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			first := b.Close(ctx)
			if status == http.StatusNoContent && first != nil || status != http.StatusNoContent && first == nil {
				t.Fatal("real revocation result changed", status, first)
			}
			if context.Cause(ctx) != nil {
				t.Fatal("first revocation ended by budget expiry instead of its actual response", context.Cause(ctx))
			}
			cancel()
			fresh, cancelFresh := context.WithTimeout(t.Context(), time.Second)
			defer cancelFresh()
			for _, later := range []context.Context{fresh, ctx} {
				if got := b.Close(later); got != first {
					t.Fatal("repeated Close changed a completed real revocation", got, first)
				}
			}
			if revocations.Load() != 1 {
				t.Fatal("Close retried completed or failed revocation", revocations.Load())
			}
		})
	}
}
