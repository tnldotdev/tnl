package integrations

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
)

func TestIntegrationPublisherCanceledStandbyHasNoFailure(t *testing.T) {
	for _, independent := range []bool{false, true} {
		t.Run(map[bool]string{false: "contention", true: "independent_failure"}[independent], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			problem := errors.New("election storage failed")
			worker := Publisher{lock: func() (io.Closer, error) {
				cancel()
				if independent {
					return nil, errors.Join(clientstate.ErrLocked, problem)
				}
				return nil, clientstate.ErrLocked
			}}
			err := worker.Maintain(ctx)
			if independent && !errors.Is(err, problem) || !independent && err != nil {
				t.Fatal("standby cancellation lost its actual election outcome", err)
			}
		})
	}
}

func TestIntegrationPublisherCanceledCurrentReadyHasNoStaleFailure(t *testing.T) {
	for _, independent := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancellation", true: "independent_failure"}[independent], func(t *testing.T) {
			state := integrationURLState(t)
			fixture := newIntegrationPublisherFixture(t, state)
			store, err := state.Server(t.Context(), testPublisherServer)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			problem := errors.New("publisher cleanup failed after cancellation")
			worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost,
				Prepare: func(context.Context) (Snapshot, error) { return fixture.snapshot(), nil },
				run: func(ctx context.Context, cfg publisherservice.RunConfig) error {
					ready := cfg.Ready
					cfg.Ready = func() error { cancel(); return ready() }
					_, err := fixture.ready(ctx, cfg)
					if independent {
						err = errors.Join(err, problem)
					}
					return err
				}}
			err = worker.Maintain(ctx)
			if independent && !errors.Is(err, problem) || !independent && err != nil {
				t.Fatal("current readiness cancellation lost its actual outcome", err)
			}
		})
	}
}

func TestIntegrationPublisherReadinessCleanupUsesParentBudget(t *testing.T) {
	state := integrationURLState(t)
	fixture := newIntegrationPublisherFixture(t, state)
	store, err := state.Server(t.Context(), testPublisherServer)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	deadline := time.Now().Add(time.Second)
	cleanupBudget := make(chan time.Time, 1)
	worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost,
		Prepare: func(context.Context) (Snapshot, error) {
			snapshot := fixture.snapshot()
			snapshot.Config.ShutdownDeadline = func() time.Time { return deadline }
			snapshot.Readiness = func(ctx context.Context, ready bool) error {
				if !ready {
					until, _ := ctx.Deadline()
					cleanupBudget <- until
				}
				return nil
			}
			return snapshot, nil
		},
		run: func(context.Context, publisherservice.RunConfig) error { cancel(); return nil }}
	if err := worker.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	if got := <-cleanupBudget; got.After(deadline) {
		t.Fatal("readiness cleanup extended the original deadline", got, deadline)
	}
}

func TestIntegrationPublisherFailedCleanupSurvivesRetryHandoff(t *testing.T) {
	state := integrationURLState(t)
	fixture := newIntegrationPublisherFixture(t, state)
	store, err := state.Server(t.Context(), testPublisherServer)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	problem := errors.New("ownership release failed")
	worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost,
		Prepare: func(context.Context) (Snapshot, error) { return fixture.snapshot(), nil },
		run:     func(context.Context, publisherservice.RunConfig) error { return nil },
		lock:    func() (io.Closer, error) { return integrationLockClose(func() error { return problem }), nil },
		Report:  func(bool, error) { cancel() }}
	if err := worker.Maintain(ctx); !errors.Is(err, problem) {
		t.Fatal("cancellation in retry handoff lost an unrecovered cleanup failure", err)
	}
}

func TestIntegrationPublisherCleanupFailureRetainedUntilReadyRecovery(t *testing.T) {
	for _, recover := range []bool{false, true} {
		t.Run(map[bool]string{false: "unready_retry", true: "ready_recovery"}[recover], func(t *testing.T) {
			state := integrationURLState(t)
			fixture := newIntegrationPublisherFixture(t, state)
			store, err := state.Server(t.Context(), testPublisherServer)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cleanupProblem, operationProblem := errors.New("ownership release failed"), errors.New("temporary preparation failure")
			var releases, attempts, reports atomic.Int32
			worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost,
				interval: time.Millisecond,
				Prepare:  func(context.Context) (Snapshot, error) { return fixture.snapshot(), nil },
				run: func(ctx context.Context, cfg publisherservice.RunConfig) error {
					if attempts.Add(1) == 1 {
						return nil
					}
					if !recover {
						return operationProblem
					}
					if _, err := fixture.ready(ctx, cfg); err != nil {
						return err
					}
					<-ctx.Done()
					return context.Canceled
				},
				lock: func() (io.Closer, error) {
					lock, err := store.LockHostname("companion:" + testPublisherHost)
					if err != nil {
						return nil, err
					}
					return integrationLockClose(func() error {
						err := lock.Close()
						if releases.Add(1) == 1 {
							err = errors.Join(err, cleanupProblem)
						}
						return err
					}), nil
				},
				Report: func(ready bool, _ error) {
					if ready || reports.Add(1) == 2 {
						cancel()
					}
				}}
			err = worker.Maintain(ctx)
			if recover && err != nil || !recover && (!errors.Is(err, cleanupProblem) || errors.Is(err, operationProblem)) {
				t.Fatal("cleanup provenance was lost or recovered attempt errors leaked into shutdown", err)
			}
			if attempts.Load() != 2 || releases.Load() != 2 {
				t.Fatal("did not cross one failed attempt and one joined retry", attempts.Load(), releases.Load())
			}
		})
	}
}

func TestIntegrationPublisherReadinessCleanupUsesActiveOwnerFence(t *testing.T) {
	state := integrationURLState(t)
	fixture := newIntegrationPublisherFixture(t, state)
	store, err := state.Server(t.Context(), testPublisherServer)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	fence, expire := context.WithCancelCause(context.Background())
	problem := errors.New("original owner shutdown budget expired")
	started, clearing := make(chan struct{}), make(chan struct{})
	worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost,
		Prepare: func(context.Context) (Snapshot, error) {
			snapshot := fixture.snapshot()
			snapshot.Config.ShutdownContext = fence
			snapshot.Readiness = func(ctx context.Context, ready bool) error {
				if ready {
					t.Error("unprepared worker announced readiness")
				}
				close(clearing)
				<-ctx.Done()
				return ctx.Err()
			}
			return snapshot, nil
		},
		run: func(ctx context.Context, _ publisherservice.RunConfig) error {
			close(started)
			<-ctx.Done()
			return context.Canceled
		}}
	result, done := make(chan error, 1), make(chan struct{})
	go func() { defer close(done); result <- worker.Maintain(ctx) }()
	t.Cleanup(func() { cancel(); expire(problem); waitIntegrationURLPublisher(t, done) })
	waitIntegrationURLPublisher(t, started)
	cancel()
	waitIntegrationURLPublisher(t, clearing)
	select {
	case err := <-result:
		t.Fatal("publisher returned before its readiness cleanup joined", err)
	default:
	}
	expire(problem)
	if err := waitIntegrationURLPublisher(t, result); !errors.Is(err, problem) {
		t.Fatal("readiness cleanup lost its active owner fence or expiry cause", err)
	}
}
