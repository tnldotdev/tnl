package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/observability"
)

func TestNativeProcessFinalFlushesShareCommandCleanupBudget(t *testing.T) {
	for _, test := range []struct {
		name    string
		expired bool
		parent  bool
	}{
		{name: "remaining"},
		{name: "spent", expired: true},
		{name: "earlier-parent-remaining", parent: true},
		{name: "earlier-parent-spent", parent: true, expired: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent := t.Context()
				until := time.Now().Add(250 * time.Millisecond)
				if test.parent {
					var cancel context.CancelFunc
					parent, cancel = context.WithDeadline(parent, until)
					defer cancel()
				}
				cleanupFailure := errors.New("independent command cleanup failure")
				operationResult := errors.Join(context.Canceled, cleanupFailure)
				exportFailure := errors.New("best-effort export delivery failed")
				var cleanupJoined atomic.Bool
				var flushes []string
				assertFlush := func(ctx context.Context, stage string) {
					t.Helper()
					if !cleanupJoined.Load() {
						t.Error(stage, "started before command cleanup joined")
					}
					got, ok := ctx.Deadline()
					if !ok || !got.Equal(until) {
						t.Errorf("%s received a fresh flush window: got %s, original %s", stage, got, until)
					}
					if test.expired && ctx.Err() != context.DeadlineExceeded {
						t.Error(stage, "received a live export window after cleanup spent the budget")
					}
					flushes = append(flushes, stage)
				}
				result := runNativeCommand(parent, func(ctx context.Context, _ telemetryFactory) error {
					process := ctx.Value(nativeProcessKey{}).(*nativeProcess)
					process.metricsTimeout = observability.ShutdownTimeout
					process.shutdownMetrics = func(ctx context.Context) error {
						assertFlush(ctx, "metrics")
						return exportFailure
					}
					process.closeTelemetry = func(ctx context.Context) { assertFlush(ctx, "telemetry") }
					proposed := until
					if test.parent {
						proposed = proposed.Add(time.Hour)
					}
					cleanup, cancel := context.WithDeadline(context.WithoutCancel(ctx), observability.ShutdownDeadline(ctx, proposed))
					defer cancel()
					if test.expired {
						<-cleanup.Done()
					} else {
						time.Sleep(100 * time.Millisecond)
					}
					cleanupJoined.Store(true)
					return operationResult
				})
				if result != operationResult || !errors.Is(result, cleanupFailure) || !errors.Is(result, context.Canceled) || errors.Is(result, exportFailure) {
					t.Fatal("process changed command/cancellation/independent cleanup result", result)
				}
				if len(flushes) != 2 || flushes[0] != "metrics" || flushes[1] != "telemetry" {
					t.Fatal("process did not join both final flushes in order", flushes)
				}
			})
		})
	}
}

func TestNativeProcessTelemetryCannotRestartBudgetSpentByMetrics(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		until := time.Now().Add(time.Second)
		exportFailure := errors.New("optional export failed")
		joined := false
		result := runNativeCommand(t.Context(), func(ctx context.Context, _ telemetryFactory) error {
			process := ctx.Value(nativeProcessKey{}).(*nativeProcess)
			process.metricsTimeout = observability.ShutdownTimeout
			process.shutdownMetrics = func(ctx context.Context) error {
				<-ctx.Done()
				joined = true
				return exportFailure
			}
			process.closeTelemetry = func(ctx context.Context) {
				if !joined || ctx.Err() != context.DeadlineExceeded {
					t.Error("telemetry did not inherit metrics' already-spent budget after its join")
				}
				if got, _ := ctx.Deadline(); !got.Equal(until) {
					t.Error("telemetry replaced the original stop deadline", got, until)
				}
			}
			observability.ShutdownDeadline(ctx, until)
			time.Sleep(500 * time.Millisecond)
			return nil
		})
		if result != nil {
			t.Fatal("optional export delivery became a command success requirement", result)
		}
	})
}

func TestNativeProcessSignalRecordsBudgetBeforeCommandCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		process := &nativeProcess{}
		received := make(chan os.Signal, 1)
		unregistered := false
		ctx, stop := processSignalContext(process.context(t.Context()), received, func() { unregistered = true })
		defer stop()
		started := time.Now()
		result := runNativeCommand(ctx, func(ctx context.Context, _ telemetryFactory) error {
			process.metricsTimeout = observability.ShutdownTimeout
			assertExpired := func(ctx context.Context) {
				t.Helper()
				if got, _ := ctx.Deadline(); !got.Equal(started.Add(10*time.Second)) || ctx.Err() != context.DeadlineExceeded {
					t.Error("final flush did not inherit the original signal deadline after cleanup", got, ctx.Err())
				}
			}
			process.shutdownMetrics = func(ctx context.Context) error { assertExpired(ctx); return ctx.Err() }
			process.closeTelemetry = assertExpired
			received <- os.Interrupt
			<-ctx.Done()
			if !unregistered {
				t.Fatal("signal cancellation preceded restoring default termination")
			}
			process.shutdownMu.Lock()
			until := process.shutdownUntil
			process.shutdownMu.Unlock()
			if !until.Equal(started.Add(10 * time.Second)) {
				t.Fatal("signal did not record the original stop deadline before waking command cleanup", until)
			}
			time.Sleep(10 * time.Second)
			return context.Canceled
		})
		if result != context.Canceled {
			t.Fatal("signal shutdown changed the command result", result)
		}
	})
}

func TestNativeProcessFiniteCommandSharesItsBoundedFinalFlush(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		result := runNativeCommand(t.Context(), func(ctx context.Context, _ telemetryFactory) error {
			process := ctx.Value(nativeProcessKey{}).(*nativeProcess)
			process.metricsTimeout = observability.CLIShutdownTimeout
			process.shutdownMetrics = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
			process.closeTelemetry = func(ctx context.Context) {
				if ctx.Err() != context.DeadlineExceeded {
					t.Error("finite command telemetry started another final flush window")
				}
			}
			return nil
		})
		if result != nil || time.Since(started) != observability.CLIShutdownTimeout {
			t.Fatal("finite command lost its bounded, best-effort final flush", result, time.Since(started))
		}
	})
}

func TestNativeProcessExpiredTelemetryCloseInterruptsOwnedIOAndJoins(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.OpenWithOptions(t.Context(), root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	err = state.SetTelemetryEnabled(t.Context(), true)
	err = errors.Join(err, state.Close())
	if err != nil {
		t.Fatal(err)
	}
	entered, interrupted, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	closing, joined, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	releaseIO := sync.OnceFunc(func() { close(release) })
	parent, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	cleanupFailure := errors.New("independent publication cleanup failure")
	t.Cleanup(func() {
		releaseIO()
		cancel()
		<-finished
	})
	go func() {
		defer close(finished)
		done <- runNativeCommand(parent, func(ctx context.Context, factory telemetryFactory) error {
			collector := factory(clienttelemetry.Config{Root: root, Protection: clientstate.ProtectionFile, Interval: time.Hour,
				Client: &http.Client{Transport: telemetryTransport(func(request *http.Request) (*http.Response, error) {
					close(entered)
					<-request.Context().Done()
					close(interrupted)
					<-release
					return nil, request.Context().Err()
				})}})
			if collector == nil {
				return errors.New("could not initialize fixture telemetry")
			}
			process := ctx.Value(nativeProcessKey{}).(*nativeProcess)
			actualClose := process.closeTelemetry
			process.closeTelemetry = func(ctx context.Context) {
				close(closing)
				actualClose(ctx)
				close(joined)
			}
			process.metricsTimeout = observability.ShutdownTimeout
			process.shutdownMetrics = func(ctx context.Context) error {
				if ctx.Err() != context.DeadlineExceeded {
					t.Error("metrics received a fresh window after publication cleanup")
				}
				return ctx.Err()
			}
			collector.Report(clienttelemetry.Demo())
			collector.Flush()
			select {
			case <-entered:
			case <-ctx.Done():
				return ctx.Err()
			}
			until := observability.ShutdownDeadline(ctx, time.Now().Add(25*time.Millisecond))
			cleanup, stop := context.WithDeadline(context.WithoutCancel(ctx), until)
			defer stop()
			<-cleanup.Done()
			return errors.Join(context.Canceled, cleanupFailure)
		})
	}()
	for _, stage := range []<-chan struct{}{closing, interrupted} {
		select {
		case <-stage:
		case <-time.After(3 * time.Second):
			t.Fatal("expired process budget did not interrupt telemetry delivery")
		}
	}
	select {
	case <-joined:
		t.Fatal("telemetry close returned before its owned I/O joined")
	case <-done:
		t.Fatal("process returned before its telemetry owner joined")
	default:
	}
	releaseIO()
	select {
	case result := <-done:
		if !errors.Is(result, cleanupFailure) || !errors.Is(result, context.Canceled) {
			t.Fatal("process lost publication cleanup/cancellation failures", result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("process did not join interrupted telemetry delivery")
	}
}
