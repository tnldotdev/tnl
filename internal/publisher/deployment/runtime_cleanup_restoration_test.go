package deployment

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// deploymentCleanupControl delegates successful owner operations to the existing
// fixture. faults affect only renewal or stop; no assignment or grant is invented.
type deploymentCleanupControl struct {
	*deploymentControl
	stopFailure    error
	denyRenew      atomic.Bool
	renewDenials   atomic.Int32
	renewEvents    chan int32
	requestsMu     sync.Mutex
	starts         []controlv1.PublisherRuntimeRequest
	stops          []controlv1.PublisherRuntimeRequest
	stopContext    error
	stopBudget     time.Duration
	joined         func() bool
	stopBeforeJoin bool
}

func (c *deploymentCleanupControl) PublisherRuntime(ctx context.Context, request controlv1.PublisherRuntimeRequest) (controlv1.PublisherRuntimeResponse, error) {
	if request.Action == controlv1.RuntimeRenew && c.denyRenew.Load() {
		count := c.renewDenials.Add(1)
		if c.renewEvents != nil {
			select {
			case c.renewEvents <- count:
			default:
			}
		}
		return controlv1.PublisherRuntimeResponse{}, clientcontrol.ErrUnavailable
	}
	c.requestsMu.Lock()
	switch request.Action {
	case controlv1.RuntimeStart:
		c.starts = append(c.starts, request)
	case controlv1.RuntimeStop:
		c.stops = append(c.stops, request)
		c.stopBeforeJoin = c.joined != nil && !c.joined()
		c.stopContext = ctx.Err()
		if until, ok := ctx.Deadline(); ok {
			c.stopBudget = time.Until(until)
		}
	}
	c.requestsMu.Unlock()
	response, err := c.deploymentControl.PublisherRuntime(ctx, request)
	if request.Action == controlv1.RuntimeStop && c.stopFailure != nil {
		err = errors.Join(err, context.Canceled, c.stopFailure)
	}
	return response, err
}

func (c *deploymentCleanupControl) assertOwnerStopped(t *testing.T) {
	t.Helper()
	c.requestsMu.Lock()
	defer c.requestsMu.Unlock()
	if len(c.starts) != 1 || len(c.stops) != 1 {
		t.Fatal("deployment did not start and stop its one actual process owner", len(c.starts), len(c.stops))
	}
	start, stop := c.starts[0], c.stops[0]
	if start.ProcessRunId == "" || start.Assertion == "" || stop.Assertion == "" ||
		stop.ProcessRunId != start.ProcessRunId || stop.PublisherIdentityId != start.PublisherIdentityId ||
		stop.ScopeId != start.ScopeId || stop.ExpectedEpoch != start.ExpectedEpoch+1 {
		t.Error("shutdown changed the process owner's signed identity, scope, run or epoch")
	}
	if c.stopContext != nil || c.stopBudget <= 0 || c.stopBudget > 5*time.Second {
		t.Error("process stop lost its uncanceled original five-second shutdown budget", c.stopContext, c.stopBudget)
	}
	if c.stopBeforeJoin {
		t.Error("process identity stop overtook unjoined publication cleanup")
	}
}

type deploymentCleanupRun struct {
	ctx      context.Context
	cancel   context.CancelFunc
	finished chan struct{}
	result   error // read only after finished closes
}

func startDeploymentCleanupRun(t *testing.T, runtime Runtime, release func()) *deploymentCleanupRun {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	run := &deploymentCleanupRun{ctx: ctx, cancel: cancel, finished: make(chan struct{})}
	t.Cleanup(func() {
		cancel()
		release()
		select {
		case <-run.finished:
		case <-time.After(3 * time.Second):
			t.Error("deployment runtime did not join within its existing fixture bound")
		}
	})
	go func() {
		run.result = runtime.Serve(ctx)
		close(run.finished)
	}()
	return run
}

func awaitDeploymentCleanup[T any](t *testing.T, events <-chan T) T {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(3 * time.Second):
		t.Fatal("deployment cleanup boundary did not make progress")
		var zero T
		return zero
	}
}

func assertDeploymentCleanupResult(t *testing.T, run *deploymentCleanupRun, worker, stop error) {
	t.Helper()
	awaitDeploymentCleanup(t, run.finished)
	if worker == nil && stop == nil && run.result != nil {
		t.Error("pure cancellation became an independent deployment failure", run.result)
	}
	if worker != nil && !errors.Is(run.result, worker) {
		t.Error("deployment lost its joined independent publication failure", run.result)
	}
	if stop != nil && !errors.Is(run.result, stop) {
		t.Error("deployment lost its independent process stop failure", run.result)
	}
}

func TestDeploymentRuntimeCancellationKeepsIndependentWorkerAndStopFailures(t *testing.T) {
	for _, test := range []struct {
		name         string
		worker, stop bool
	}{
		{"pure_cancellation", false, false},
		{"worker_failure", true, false},
		{"process_stop_failure", false, true},
		{"worker_and_process_stop_failures", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			base, key := deploymentFixture(t)
			control := &deploymentCleanupControl{deploymentControl: base}
			var workerFailure error
			if test.worker {
				workerFailure = errors.New("independent publication cleanup failure")
			}
			if test.stop {
				control.stopFailure = errors.New("independent process identity stop failure")
			}
			expected := base.assignment.Services[0]
			started := make(chan controlv1.DeploymentPublisherServiceAssignment, 1)
			canceled, releaseCleanup := make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(releaseCleanup) })
			var joined atomic.Bool
			var attempts atomic.Int32
			control.joined = joined.Load
			run := startDeploymentCleanupRun(t, Runtime{
				Control: control, Member: base.assignment.Member, Private: key, PollInterval: time.Millisecond,
				Publish: func(ctx context.Context, assignment controlv1.DeploymentPublisherServiceAssignment, healthy func(bool)) error {
					if attempts.Add(1) != 1 {
						return errors.New("shutdown restarted the exact fixture assignment")
					}
					started <- assignment
					healthy(true)
					<-ctx.Done()
					close(canceled)
					<-releaseCleanup
					joined.Store(true)
					return errors.Join(context.Cause(ctx), workerFailure)
				},
			}, release)
			if actual := awaitDeploymentCleanup(t, started); !reflect.DeepEqual(actual, expected) {
				t.Fatal("runtime did not publish the existing fixture's exact assignment")
			}
			run.cancel()
			awaitDeploymentCleanup(t, canceled)
			select {
			case <-run.finished:
				t.Error("runtime returned before its entered publication cleanup joined")
			default:
			}
			control.requestsMu.Lock()
			stops := len(control.stops)
			control.requestsMu.Unlock()
			if joined.Load() || stops != 0 {
				t.Error("process stop overtook held publication cleanup", joined.Load(), stops)
			}
			release()
			assertDeploymentCleanupResult(t, run, workerFailure, control.stopFailure)
			if !joined.Load() || attempts.Load() != 1 {
				t.Error("deployment returned without one exact joined publication", attempts.Load())
			}
			control.assertOwnerStopped(t)
		})
	}
}

func TestDeploymentRuntimeReplacementKeepsJoinedFailureAndNonoverlap(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "pure_cancellation"
		if fail {
			name = "independent_cleanup_failure"
		}
		t.Run(name, func(t *testing.T) {
			base, key := deploymentFixture(t)
			control := &deploymentCleanupControl{deploymentControl: base}
			original := base.assignment.Services[0]
			replacement := original
			replacement.Configuration.Target = "replacement.internal:5432"
			var cleanupFailure error
			if fail {
				cleanupFailure = errors.New("replaced publication cleanup failed")
			}
			entered := make(chan controlv1.DeploymentPublisherServiceAssignment, 4)
			oldCanceled, releaseCleanup := make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(releaseCleanup) })
			var active, starts atomic.Int32
			var oldJoined, replacementJoined atomic.Bool
			control.joined = func() bool { return active.Load() == 0 && oldJoined.Load() }
			run := startDeploymentCleanupRun(t, Runtime{
				Control: control, Member: base.assignment.Member, Private: key, PollInterval: time.Millisecond,
				Publish: func(ctx context.Context, assignment controlv1.DeploymentPublisherServiceAssignment, healthy func(bool)) error {
					starts.Add(1)
					if active.Add(1) != 1 {
						t.Error("replacement overlapped an unjoined publication")
					}
					defer active.Add(-1)
					entered <- assignment
					healthy(true)
					<-ctx.Done()
					if reflect.DeepEqual(assignment, original) {
						close(oldCanceled)
						<-releaseCleanup
						oldJoined.Store(true)
						return errors.Join(context.Cause(ctx), cleanupFailure)
					}
					if !reflect.DeepEqual(assignment, replacement) || !oldJoined.Load() {
						t.Error("replacement changed its exact assignment or started before old cleanup joined")
					}
					replacementJoined.Store(true)
					return context.Cause(ctx)
				},
			}, release)
			if actual := awaitDeploymentCleanup(t, entered); !reflect.DeepEqual(actual, original) {
				t.Fatal("initial publication changed its exact fixture assignment")
			}
			base.mu.Lock()
			base.assignment.Services = append([]controlv1.DeploymentPublisherServiceAssignment(nil), base.assignment.Services...)
			base.assignment.Services[0] = replacement
			base.assignment.Revision = 2
			base.assignment.ConfigurationHash = strings.Repeat("b", 64)
			base.mu.Unlock()
			awaitDeploymentCleanup(t, oldCanceled)
			if starts.Load() != 1 || active.Load() != 1 || oldJoined.Load() {
				t.Error("replacement did not retain the old publication through held cleanup", starts.Load(), active.Load())
			}
			select {
			case <-run.finished:
				t.Error("replacement returned before joining old publication cleanup")
			default:
			}
			release()
			// an independent failure may stop reconciliation immediately or be
			// retained until shutdown. either choice must preserve its cause.
			select {
			case actual := <-entered:
				if !reflect.DeepEqual(actual, replacement) || !oldJoined.Load() {
					t.Error("replacement lost its exact assignment or old-worker join")
				}
			case <-run.finished:
				if !fail {
					t.Error("pure cancellation prevented the replacement publication", run.result)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("replacement neither started nor returned its cleanup failure")
			}
			run.cancel()
			assertDeploymentCleanupResult(t, run, cleanupFailure, nil)
			if !oldJoined.Load() || active.Load() != 0 || starts.Load() < 1 || starts.Load() > 2 {
				t.Error("replacement returned with unjoined or repeated publications", starts.Load(), active.Load())
			}
			if starts.Load() == 2 && !replacementJoined.Load() {
				t.Error("deployment did not join its replacement publication")
			}
			if !fail && starts.Load() != 2 {
				t.Error("pure cancellation did not retain the existing replacement workload", starts.Load())
			}
			control.assertOwnerStopped(t)
		})
	}
}

func TestDeploymentRuntimeLeaseLossKeepsJoinedPublicationFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "pure_cancellation"
		if fail {
			name = "independent_cleanup_failure"
		}
		t.Run(name, func(t *testing.T) {
			base, key := deploymentFixture(t)
			control := &deploymentCleanupControl{deploymentControl: base, renewEvents: make(chan int32, 64)}
			control.denyRenew.Store(true)
			var cleanupFailure error
			if fail {
				cleanupFailure = errors.New("lease-expired publication cleanup failed")
			}
			expected := base.assignment.Services[0]
			started := make(chan controlv1.DeploymentPublisherServiceAssignment, 2)
			canceled, joined, releaseCleanup := make(chan struct{}), make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(releaseCleanup) })
			var attempts atomic.Int32
			var workerFinished atomic.Bool
			control.joined = workerFinished.Load
			// retain the existing lease-expiry fixture's actual forty-millisecond
			// lease and one-millisecond polling, not a manufactured cancellation.
			base.expires = time.Now().Add(40 * time.Millisecond)
			until := base.expires
			run := startDeploymentCleanupRun(t, Runtime{
				Control: control, Member: base.assignment.Member, Private: key, PollInterval: time.Millisecond,
				Publish: func(ctx context.Context, assignment controlv1.DeploymentPublisherServiceAssignment, healthy func(bool)) error {
					if attempts.Add(1) != 1 {
						return errors.New("expired lease restarted the exact fixture assignment")
					}
					defer workerFinished.Store(true)
					started <- assignment
					healthy(true)
					<-ctx.Done()
					close(canceled)
					<-releaseCleanup
					close(joined)
					return errors.Join(context.Cause(ctx), cleanupFailure)
				},
			}, release)
			if actual := awaitDeploymentCleanup(t, started); !reflect.DeepEqual(actual, expected) {
				t.Fatal("lease test did not enter the existing exact assignment")
			}
			awaitDeploymentCleanup(t, canceled)
			if run.ctx.Err() != nil || time.Now().Before(until) {
				t.Error("caller cancellation or an early stop replaced actual lease expiry", run.ctx.Err())
			}
			select {
			case <-run.finished:
				t.Error("lease loss returned before held publication cleanup joined")
			default:
			}
			release()
			awaitDeploymentCleanup(t, joined)
			// two later denied renewals prove the serving loop has passed its
			// expired-lease stop/join path before caller cancellation. do not rely
			// on a deduplicated healthy=false observation being emitted again.
			afterJoin := control.renewDenials.Load()
			progress := time.NewTimer(3 * time.Second)
			defer progress.Stop()
			stopped := false
			for !stopped {
				select {
				case count := <-control.renewEvents:
					stopped = count >= afterJoin+2
				case <-run.finished:
					if !fail {
						t.Error("pure lease-loss cancellation stopped the deployment runtime", run.result)
					}
					stopped = true
				case <-progress.C:
					t.Fatal("runtime neither passed its expired-lease join nor returned its independent failure")
				}
			}
			run.cancel()
			assertDeploymentCleanupResult(t, run, cleanupFailure, nil)
			if attempts.Load() != 1 || control.renewDenials.Load() == 0 {
				t.Error("expired lease was renewed or its publication restarted", attempts.Load(), control.renewDenials.Load())
			}
			control.assertOwnerStopped(t)
		})
	}
}
