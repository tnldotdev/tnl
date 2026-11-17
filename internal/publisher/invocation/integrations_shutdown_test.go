package invocation

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func awaitIntegrationShutdown[T any](t *testing.T, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("integration shutdown did not join")
		var zero T
		return zero
	}
}

func TestIntegrationWorkersStopJoinsEveryResultOnce(t *testing.T) {
	firstProblem, secondProblem := errors.New("publisher shutdown failed"), errors.New("observer cleanup failed")
	started, canceled := make(chan struct{}, 2), make(chan struct{}, 2)
	release := make(chan struct{})
	releaseWorker := sync.OnceFunc(func() { close(release) })
	var joined atomic.Int32
	stop := startIntegrationWorkers(t.Context(),
		func(ctx context.Context) error {
			started <- struct{}{}
			<-ctx.Done()
			canceled <- struct{}{}
			joined.Add(1)
			return errors.Join(context.Canceled, firstProblem)
		},
		func(ctx context.Context) error {
			started <- struct{}{}
			<-ctx.Done()
			canceled <- struct{}{}
			<-release
			joined.Add(1)
			return secondProblem
		})
	t.Cleanup(func() { releaseWorker(); _ = stop() })
	awaitIntegrationShutdown(t, started)
	awaitIntegrationShutdown(t, started)
	result := make(chan error, 1)
	go func() { result <- stop() }()
	awaitIntegrationShutdown(t, canceled)
	awaitIntegrationShutdown(t, canceled)
	select {
	case err := <-result:
		t.Fatal("stop returned before every worker joined", err)
	default:
	}
	releaseWorker()
	err := awaitIntegrationShutdown(t, result)
	if !errors.Is(err, firstProblem) || !errors.Is(err, secondProblem) || joined.Load() != 2 {
		t.Fatal("stop lost a worker failure or left work running", err, joined.Load())
	}
	if again := stop(); again != err || joined.Load() != 2 {
		t.Fatal("repeated stop changed the result or repeated worker cleanup", again, joined.Load())
	}
}

func TestIntegrationAttachmentJoinsStopAndSetupFailures(t *testing.T) {
	for _, setupFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal_stop", true: "failed_setup"}[setupFailure], func(t *testing.T) {
			setupProblem := errors.New("integration setup failed")
			firstProblem, secondProblem := errors.New("oauth shutdown failed"), errors.New("alias shutdown failed")
			var joined, stopped, finished atomic.Int32
			stop, err := attachIntegrationWorkers(t.Context(), func() {
				if joined.Load() != 2 || stopped.Load() != 2 {
					t.Error("telemetry closed before all integration cleanup joined", joined.Load(), stopped.Load())
				}
				finished.Add(1)
			}, func(ctx context.Context, add func(func() error)) error {
				for _, problem := range []error{firstProblem, secondProblem} {
					workerStop := startIntegrationWorkers(ctx, func(ctx context.Context) error {
						<-ctx.Done()
						joined.Add(1)
						return errors.Join(context.Canceled, problem)
					})
					add(func() error {
						if ctx.Err() == nil {
							t.Error("stop joined one integration before canceling its siblings")
						}
						stopped.Add(1)
						return workerStop()
					})
				}
				if setupFailure {
					return setupProblem
				}
				return nil
			})
			if setupFailure {
				if stop != nil || !errors.Is(err, setupProblem) {
					t.Fatal("failed setup transferred ownership or lost its operation error", err)
				}
			} else {
				if err != nil || stop == nil {
					t.Fatal("successful setup did not transfer its joined stop", err)
				}
				err = stop()
				if again := stop(); again != err {
					t.Fatal("repeated attachment stop changed its retained error", again)
				}
			}
			if !errors.Is(err, firstProblem) || !errors.Is(err, secondProblem) || stopped.Load() != 2 || finished.Load() != 1 {
				t.Fatal("attachment lost shutdown failures or repeated cleanup", err, stopped.Load(), finished.Load())
			}
		})
	}
}

func TestIntegrationAttachmentCancelsAllBeforeJoiningWithinParentBound(t *testing.T) {
	for _, setupFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "publication_failure", true: "partial_setup_failure"}[setupFailure], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				startedAt := time.Now()
				deadline := startedAt.Add(3 * time.Second)
				parent, cancel := context.WithDeadline(t.Context(), deadline)
				defer cancel()
				operationProblem := errors.New("publication setup or serving failed")
				cleanupProblem := errors.New("integration cleanup failed")
				started := make(chan struct{}, 2)
				var joined, finished atomic.Int32
				stop, err := attachIntegrationWorkers(parent, func() {
					if joined.Load() != 2 {
						t.Error("telemetry finished before all drains joined")
					}
					finished.Add(1)
				}, func(ctx context.Context, add func(func() error)) error {
					for range 2 {
						add(startIntegrationWorkers(ctx, func(ctx context.Context) error {
							if inherited, ok := ctx.Deadline(); !ok || inherited != deadline {
								t.Error("integration replaced the original parent bound")
							}
							started <- struct{}{}
							<-ctx.Done()
							// each worker already owns a two-second drain. canceling
							// them serially would consume four seconds, not two.
							time.Sleep(2 * time.Second)
							joined.Add(1)
							return cleanupProblem
						}))
					}
					<-started
					<-started
					if setupFailure {
						return operationProblem
					}
					return nil
				})
				if setupFailure {
					if stop != nil {
						t.Fatal("partial setup transferred unfinished cleanup")
					}
				} else {
					if err != nil || stop == nil {
						t.Fatal("attachment failed before publication stopped", err)
					}
					err = errors.Join(operationProblem, stop())
				}
				if !errors.Is(err, operationProblem) || !errors.Is(err, cleanupProblem) || joined.Load() != 2 || finished.Load() != 1 {
					t.Fatal("failed publication did not join every integration and telemetry", err, joined.Load(), finished.Load())
				}
				if elapsed := time.Since(startedAt); elapsed != 2*time.Second || parent.Err() != nil {
					t.Fatal("integration stops received serial drain budgets or outlived their parent bound", elapsed, parent.Err())
				}
			})
		})
	}
}
