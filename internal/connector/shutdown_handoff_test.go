package connector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"testing/synctest"
	"time"

	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	"github.com/tnldotdev/tnl/internal/observability"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type shutdownHandoffListener struct {
	net.Listener
	closes int
}

func (l *shutdownHandoffListener) Close() error { l.closes++; return nil }

func TestConnectMetadataMixedFailureRetainsResultAndProcessBudget(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		for _, kind := range []string{"cleanup", "wrapped-cleanup", "cleanup-canceled", "cleanup-wrapped-reload", "unowned-canceled", "single-failure"} {
			t.Run(fmt.Sprintf("%s/canceled=%t", kind, canceled), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					var recorded time.Time
					parent := observability.WithShutdownDeadline(t.Context(), func(until time.Time) time.Time {
						recorded = until
						return until
					})
					parent, cancel := context.WithCancel(parent)
					defer cancel()
					reload := &connectorstream.MetadataReloadError{ServiceID: "selected-service", ApprovedRevision: 1, SelectedRevision: 2}
					independent := errors.New("independent owned cleanup failure")
					cleanup := &connectorstream.CleanupError{Err: independent}
					var original error = errors.Join(reload, cleanup)
					switch kind {
					case "wrapped-cleanup":
						original = fmt.Errorf("runner: %w", errors.Join(fmt.Errorf("reload: %w", reload), context.Canceled, cleanup))
					case "cleanup-canceled":
						cleanup.Err = context.Canceled
						independent = context.Canceled
					case "cleanup-wrapped-reload":
						cleanup.Err = reload
						independent = reload
						original = cleanup
					case "unowned-canceled":
						original = errors.Join(reload, context.Canceled)
						independent = context.Canceled
					case "single-failure":
						original = cleanup
					}
					until := time.Now().Add(5 * time.Second)
					listener := &shutdownHandoffListener{}
					calls, reads, reopened := 0, 0, 0
					job := installedjobs.Job{ServiceID: reload.ServiceID, Name: "database", Protocol: "tcp", TrustRevision: 1}
					result := runConnectorLifecycle(parent, listener, job, "", connectorLifecycle{
						services: connectServiceReaderFunc(func(context.Context) ([]controlv1.ServiceSummary, error) {
							reads++
							return []controlv1.ServiceSummary{{Id: job.ServiceID, Name: job.Name, Protocol: "tcp", TrustRevision: 2}}, nil
						}),
						listen: func(context.Context, installedjobs.Job) (net.Listener, error) {
							reopened++
							return &shutdownHandoffListener{}, nil
						},
						serve: func(ctx context.Context, _ net.Listener, _ installedjobs.Job, _ func() error) error {
							calls++
							if calls != 1 {
								return errors.New("unexpected replacement runner")
							}
							ctx, finish := connectorShutdownHandoff(ctx)
							observability.ShutdownDeadline(ctx, until)
							if canceled {
								cancel()
							}
							// cancellation is not a cleanup result. spend the exact
							// original drain budget, then report every joined cause.
							time.Sleep(5 * time.Second)
							finish(original)
							return original
						},
					})
					if result != original || !errors.Is(result, independent) {
						t.Error("foreground owner replaced or discarded the original failure", result)
					}
					if kind != "single-failure" {
						var retained *connectorstream.MetadataReloadError
						if !errors.As(result, &retained) || retained != reload {
							t.Error("foreground owner discarded the original metadata cause", result)
						}
					}
					if kind != "unowned-canceled" {
						var retained *connectorstream.CleanupError
						if !errors.As(result, &retained) || retained != cleanup {
							t.Error("foreground owner discarded the owned cleanup report", result)
						}
					}
					if calls != 1 || reads != 0 || reopened != 0 || listener.closes != 1 {
						t.Error("mixed failure continued metadata replacement", calls, reads, reopened, listener.closes)
					}
					if !recorded.Equal(until) {
						t.Error("terminal failure did not hand its original spent cleanup deadline to the process", recorded, until)
					}
				})
			})
		}
	}
}

func TestConnectPureMetadataCancellationDoesNotConsumeProcessBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var recorded time.Time
		parent := observability.WithShutdownDeadline(t.Context(), func(until time.Time) time.Time {
			recorded = until
			return until
		})
		parent, cancel := context.WithCancel(parent)
		defer cancel()
		listener := &shutdownHandoffListener{}
		calls, reads, reopened := 0, 0, 0
		result := runConnectorLifecycle(parent, listener, installedjobs.Job{}, "", connectorLifecycle{
			services: connectServiceReaderFunc(func(context.Context) ([]controlv1.ServiceSummary, error) {
				reads++
				return nil, nil
			}),
			listen: func(context.Context, installedjobs.Job) (net.Listener, error) {
				reopened++
				return nil, errors.New("unexpected replacement listener")
			},
			serve: func(ctx context.Context, _ net.Listener, _ installedjobs.Job, _ func() error) error {
				calls++
				ctx, finish := connectorShutdownHandoff(ctx)
				observability.ShutdownDeadline(ctx, time.Now().Add(5*time.Second))
				cancel()
				time.Sleep(5 * time.Second)
				pure := errors.Join(&connectorstream.MetadataReloadError{}, fmt.Errorf("runner: %w", &connectorstream.MetadataReloadError{}))
				finish(pure)
				return pure
			},
		})
		if result != nil || calls != 1 || reads != 0 || reopened != 0 || listener.closes != 1 {
			t.Error("pure metadata cancellation changed its established stop behavior", result, calls, reads, reopened, listener.closes)
		}
		if !recorded.IsZero() {
			t.Error("pure metadata retirement consumed the process exit budget", recorded)
		}
	})
}

func TestForegroundConnectorOnlyHandsFinalStopBudgetToProcess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var recorded time.Time
		parent := observability.WithShutdownDeadline(t.Context(), func(until time.Time) time.Time {
			recorded = until
			return until
		})
		ctx, finish := connectorShutdownHandoff(parent)
		replaced := time.Now().Add(5 * time.Second)
		observability.ShutdownDeadline(ctx, replaced)
		finish(&connectorstream.MetadataReloadError{})
		if !recorded.IsZero() {
			t.Fatal("metadata replacement consumed the process exit budget", recorded)
		}
		time.Sleep(10 * time.Second)
		ctx, finish = connectorShutdownHandoff(parent)
		stopped := time.Now().Add(5 * time.Second)
		cleanup, cancel := context.WithDeadline(context.WithoutCancel(ctx), observability.ShutdownDeadline(ctx, stopped))
		defer cancel()
		<-cleanup.Done()
		finish(context.Canceled)
		if !recorded.Equal(stopped) {
			t.Fatal("final foreground stop lost its already-spent cleanup budget", recorded, stopped)
		}
	})
}
