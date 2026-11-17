package integrations

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
)

type integrationLockClose func() error

func (close integrationLockClose) Close() error { return close() }

func TestIntegrationURLPublisherMaintainReturnsFinalShutdownFailures(t *testing.T) {
	for _, problem := range []string{"cancellation", "worker", "readiness", "lock", "all"} {
		t.Run(problem, func(t *testing.T) {
			state := integrationURLState(t)
			fixture := newIntegrationPublisherFixture(t, state)
			store, err := state.Server(t.Context(), testPublisherServer)
			if err != nil {
				t.Fatal(err)
			}
			workerProblem := errors.New("worker shutdown failed")
			readinessProblem := errors.New("readiness cleanup failed")
			lockProblem := errors.New("ownership release failed")
			include := func(kind string) bool { return problem == kind || problem == "all" }
			started, draining, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			releaseRun := sync.OnceFunc(func() { close(release) })
			var clears, releases atomic.Int32
			worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost,
				Prepare: func(context.Context) (Snapshot, error) {
					snapshot := fixture.snapshot()
					announced := false
					snapshot.Readiness = func(_ context.Context, ready bool) error {
						if ready {
							announced = true
						} else if announced {
							clears.Add(1)
							if include("readiness") {
								return readinessProblem
							}
						}
						return nil
					}
					return snapshot, nil
				},
				lock: func() (io.Closer, error) {
					lock, err := store.LockHostname("companion:" + testPublisherHost)
					if err != nil {
						return nil, err
					}
					return integrationLockClose(func() error {
						releases.Add(1)
						err := lock.Close()
						if include("lock") {
							err = errors.Join(err, lockProblem)
						}
						return err
					}), nil
				},
				run: func(ctx context.Context, config publisherservice.RunConfig) error {
					if _, err := fixture.ready(ctx, config); err != nil {
						return err
					}
					close(started)
					<-ctx.Done()
					close(draining)
					<-release
					if include("worker") {
						return errors.Join(context.Canceled, workerProblem)
					}
					return errors.Join(context.Canceled, context.Canceled)
				}}
			ctx, cancel := context.WithCancel(t.Context())
			result, done := make(chan error, 1), make(chan struct{})
			go func() { defer close(done); result <- worker.Maintain(ctx) }()
			t.Cleanup(func() { cancel(); releaseRun(); waitIntegrationURLPublisher(t, done) })
			waitIntegrationURLPublisher(t, started)
			cancel()
			waitIntegrationURLPublisher(t, draining)
			select {
			case <-done:
				t.Fatal("publisher returned before its worker joined")
			default:
			}
			if releases.Load() != 0 {
				t.Fatal("ownership released before the worker joined")
			}
			releaseRun()
			err = waitIntegrationURLPublisher(t, result)
			for kind, target := range map[string]error{"worker": workerProblem, "readiness": readinessProblem, "lock": lockProblem} {
				if errors.Is(err, target) != include(kind) {
					t.Fatalf("%s shutdown result did not retain exactly its owned failures: %v", problem, err)
				}
			}
			if problem == "cancellation" && err != nil {
				t.Fatal("expected cancellation became a shutdown failure", err)
			}
			if clears.Load() != 1 || releases.Load() != 1 {
				t.Fatal("final shutdown repeated readiness or ownership cleanup", clears.Load(), releases.Load())
			}
			lock, err := store.LockHostname("companion:" + testPublisherHost)
			if err != nil {
				t.Fatal("shutdown result returned before ownership was released", err)
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIntegrationURLPublisherMaintainDoesNotRetainRecoveredAttempts(t *testing.T) {
	state := integrationURLState(t)
	fixture := newIntegrationPublisherFixture(t, state)
	store, err := state.Server(t.Context(), testPublisherServer)
	if err != nil {
		t.Fatal(err)
	}
	transient := errors.New("temporary publication failure")
	var attempts atomic.Int32
	reported, ready := make(chan error, 1), make(chan struct{})
	worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost, interval: time.Millisecond,
		Prepare: func(context.Context) (Snapshot, error) { return fixture.snapshot(), nil },
		Report: func(ready bool, err error) {
			if !ready {
				reported <- err
			}
		},
		run: func(ctx context.Context, config publisherservice.RunConfig) error {
			if attempts.Add(1) == 1 {
				return transient
			}
			if _, err := fixture.ready(ctx, config); err != nil {
				return err
			}
			close(ready)
			<-ctx.Done()
			return context.Canceled
		}}
	ctx, cancel := context.WithCancel(t.Context())
	result, done := make(chan error, 1), make(chan struct{})
	go func() { defer close(done); result <- worker.Maintain(ctx) }()
	t.Cleanup(func() { cancel(); waitIntegrationURLPublisher(t, done) })
	if err := waitIntegrationURLPublisher(t, reported); !errors.Is(err, transient) {
		t.Fatal("transient attempt was not reported", err)
	}
	waitIntegrationURLPublisher(t, ready)
	cancel()
	if err := waitIntegrationURLPublisher(t, result); err != nil {
		t.Fatal("recovered attempt became a final shutdown failure", err)
	}
}
