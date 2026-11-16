package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type canceledInitialHeartbeat struct {
	*lifecycleControl
	entered            chan struct{}
	operation, cleanup error
}

func (c canceledInitialHeartbeat) HeartbeatServiceRun(ctx context.Context, _, _ string, _ credentials.ServiceRunToken, _ controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	close(c.entered)
	<-ctx.Done()
	return controlv1.ServiceRunState{}, errors.Join(context.Cause(ctx), c.operation)
}

func (c canceledInitialHeartbeat) CloseServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken) error {
	return errors.Join(c.lifecycleControl.CloseServiceRun(ctx, service, run, token), c.cleanup)
}

func TestInitialHeartbeatCancellationRetainsOnlyActualOperationAndCleanupFailures(t *testing.T) {
	for _, scenario := range []string{"canceled", "operation failure", "cleanup failure"} {
		t.Run(scenario, func(t *testing.T) {
			config, state := lifecycleFixture(t)
			cause := errors.New("independent lifecycle failure")
			control := canceledInitialHeartbeat{lifecycleControl: state, entered: make(chan struct{})}
			if scenario == "operation failure" {
				control.operation = cause
			}
			if scenario == "cleanup failure" {
				control.cleanup = cause
			}
			config.Control = control
			config.Connect = func(context.Context, *Bound, uint8, ConnectOptions) (SlotSession, error) {
				t.Error("canceled initial heartbeat started a relay worker")
				return nil, ErrPrivateStream
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- Publish(ctx, config) }()
			select {
			case <-control.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("initial heartbeat did not start")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) || errors.Is(err, ErrPrivateStream) {
					t.Fatal("cancellation invented an invalid-stream failure", err)
				}
				if scenario == "canceled" {
					if !failure.Only(err, context.Canceled) {
						t.Fatal("ordinary cancellation acquired a cleanup failure", err)
					}
				} else if !errors.Is(err, cause) {
					t.Fatal("cancellation hid an independent failure", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("canceled startup did not join cleanup")
			}
			if state.closes != 1 {
				t.Fatal("canceled startup did not close its exact started run", state.closes)
			}
		})
	}
}

func TestInitialPublisherAccessCancellationRetainsOnlyActualFailures(t *testing.T) {
	for _, independent := range []bool{false, true} {
		t.Run(map[bool]string{false: "canceled", true: "independent failure"}[independent], func(t *testing.T) {
			config, state := lifecycleFixture(t)
			entered := make(chan struct{})
			cause := errors.New("independent access failure")
			config.Access = func(ctx context.Context) (string, error) {
				close(entered)
				<-ctx.Done()
				if independent {
					return "", errors.Join(context.Cause(ctx), cause)
				}
				return "", context.Cause(ctx)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- Publish(ctx, config) }()
			serviceHTTPAwait(t, entered)
			cancel()
			err := serviceHTTPAwait(t, done)
			if !errors.Is(err, context.Canceled) || errors.Is(err, ErrPrivateStream) {
				t.Fatal("access cancellation invented an invalid-stream failure", err)
			}
			if independent {
				if !errors.Is(err, cause) {
					t.Fatal("access cancellation hid an independent failure", err)
				}
			} else if !failure.Only(err, context.Canceled) {
				t.Fatal("ordinary access cancellation acquired another failure", err)
			}
			if state.prepares != 0 || state.binds != 0 || state.closes != 0 {
				t.Fatal("canceled access prepared, started, or closed a service run", state.prepares, state.binds, state.closes)
			}
		})
	}
}
