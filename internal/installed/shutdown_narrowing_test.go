package installed

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
)

func TestInstalledShutdownNarrowsWhenParentStartsLater(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var parent time.Time
		deadline, _, join := installedShutdown(t.Context(), 10*time.Second, func() time.Time { return parent }, nil)
		defer join()
		first := deadline()
		time.Sleep(time.Second)
		parent = time.Now().Add(2 * time.Second)
		if got := deadline(); !got.Equal(parent) {
			t.Errorf("late parent was not applied: child=%s parent=%s", got.Sub(first), parent.Sub(first))
		}
		narrowed := parent
		parent = first.Add(time.Hour)
		if got := deadline(); !got.Equal(narrowed) {
			t.Error("later parent observation extended the narrowed local cap", got, narrowed)
		}
	})
}

func TestInstalledEngineLateParentDeadlineBoundsAlreadyDrainingJob(t *testing.T) {
	for _, parentBudget := range []time.Duration{2 * time.Second, 10 * time.Second} {
		t.Run(parentBudget.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				registry := userRegistry(t)
				job, _, _ := kindFixture(t, KindConnector)
				job, err := registry.InstallConnector(t.Context(), job)
				if err != nil {
					t.Fatal(err)
				}
				type drain struct {
					ctx      context.Context
					deadline func() time.Time
					ioJoined <-chan struct{}
				}
				started := make(chan struct{})
				draining := make(chan drain)
				joined := make(chan time.Time, 1)
				parentStarted := make(chan time.Time, 1)
				cleanupFailure := errors.New("independent cleanup failure")
				operationFailure := errors.New("independent operation failure")
				parent := sync.OnceValue(func() time.Time {
					until := time.Now().Add(parentBudget)
					parentStarted <- until
					return until
				})
				engine := Engine{Registry: registry, PollInterval: time.Millisecond, ShutdownDeadline: parent,
					Connect: func(ctx context.Context, _ Job, _ *clienttelemetry.Collector, _ func() error, deadline func() time.Time, shutdown context.Context) error {
						close(started)
						<-ctx.Done()
						// match the installed connector's detached cleanup-context
						// boundary without starting a listener or remote backend.
						finish, cancel := context.WithDeadline(shutdown, deadline())
						defer cancel()
						owned, peer := net.Pipe()
						defer peer.Close()
						defer owned.Close()
						copied, ioJoined := make(chan error, 1), make(chan struct{})
						go func() {
							_, err := io.Copy(io.Discard, owned)
							copied <- err
							close(ioJoined)
						}()
						forced := make(chan struct{})
						stopForce := context.AfterFunc(finish, func() {
							defer close(forced)
							_ = owned.Close()
						})
						defer stopForce()
						draining <- drain{ctx: finish, deadline: deadline, ioJoined: ioJoined}
						<-finish.Done()
						<-forced
						if err := <-copied; err == nil {
							t.Error("forced cleanup did not interrupt its owned pipe read")
						}
						<-ioJoined
						joined <- time.Now()
						return errors.Join(finish.Err(), operationFailure, cleanupFailure)
					}}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- engine.Serve(ctx) }()
				<-started
				if err := registry.Stop(t.Context(), job.ID); err != nil {
					t.Fatal(err)
				}
				active := <-draining
				first, ok := active.ctx.Deadline()
				if !ok || time.Until(first) != 10*time.Second || ctx.Err() != nil {
					t.Fatal("job did not begin its default drain while the supervisor remained alive", first, ctx.Err())
				}
				select {
				case <-parentStarted:
					t.Fatal("individual job stop consumed the supervisor's exit budget")
				default:
				}
				time.Sleep(time.Second)
				select {
				case <-active.ioJoined:
					t.Fatal("owned I/O ended before the remaining shutdown budget expired")
				default:
				}
				cancel()
				outer := <-parentStarted
				synctest.Wait()
				want := first
				if outer.Before(want) {
					want = outer
				}
				// do not query the child getter again to trigger a narrow timer.
				// its already-active context must receive the parent expiry.
				time.Sleep(time.Until(want))
				synctest.Wait()
				if got := active.deadline(); !got.Equal(want) {
					t.Errorf("job retained its earlier cached budget: got=%s want=%s", got, want)
				}
				if got, _ := active.ctx.Deadline(); !got.Equal(first) || !errors.Is(context.Cause(active.ctx), context.DeadlineExceeded) {
					t.Error("active context lost its standard deadline or expiry cause", got, context.Cause(active.ctx))
				}
				if outer.Before(first) && active.ctx.Err() != context.Canceled {
					t.Error("parent cancellation was misreported as the child's original deadline", active.ctx.Err())
				}
				var joinedAt time.Time
				select {
				case joinedAt = <-joined:
				default:
					t.Error("owned job cleanup was not joined at the effective parent deadline")
				}
				select {
				case err := <-done:
					if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, cleanupFailure) || !errors.Is(err, operationFailure) {
						t.Error("supervisor lost timeout or independent cleanup failure", err)
					}
				default:
					t.Error("supervisor was still waiting for its already-draining job after its deadline")
					// retain and join the actual late outcome instead of leaking
					// the red fixture's worker or masking its independent failure.
					err := <-done
					if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, cleanupFailure) || !errors.Is(err, operationFailure) {
						t.Error("late supervisor outcome lost cleanup failures", err)
					}
				}
				if joinedAt.IsZero() {
					joinedAt = <-joined
				}
				if joinedAt.After(want) {
					t.Errorf("job joined %s after the effective deadline", joinedAt.Sub(want))
				}
			})
		})
	}
}
