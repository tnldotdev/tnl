package service

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type startupCancellationControl struct {
	*lifecycleControl
	boundary string
	entered  chan context.Context
	closed   chan context.Context
	release  chan struct{}
	failure  error
}

func (c *startupCancellationControl) wait(ctx context.Context) error {
	c.entered <- ctx
	select {
	case <-ctx.Done():
	case <-c.release:
	}
	return errors.Join(context.Cause(ctx), c.failure)
}

func (c *startupCancellationControl) Discovery(ctx context.Context) (controlv1.ControlDiscovery, error) {
	if c.boundary == "discovery" {
		return controlv1.ControlDiscovery{}, c.wait(ctx)
	}
	return c.lifecycleControl.Discovery(ctx)
}

func (c *startupCancellationControl) CreateServiceRunPreview(ctx context.Context, service, run string, number int64, token credentials.ServiceRunToken) (controlv1.Preview, error) {
	if service != c.prep.ServiceId || run != c.prep.ServiceRunId || number != c.prep.RunNumber || token.String() != c.prep.RunToken {
		return controlv1.Preview{}, ErrPrivateStream
	}
	return controlv1.Preview{}, c.wait(ctx)
}

func (c *startupCancellationControl) CloseServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken) error {
	c.closed <- ctx
	return errors.Join(context.Cause(ctx), c.lifecycleControl.CloseServiceRun(ctx, service, run, token))
}

func TestServiceSynchronousStartupCancellationLeavesTimeForExactCleanup(t *testing.T) {
	for _, boundary := range []string{"discovery", "demo-preview"} {
		t.Run(boundary, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg, authority, _ := readyAuthorityFixture(t)
				authority.approved.Endpoint.Public = true
				cfg.BrowserLoginAvailable = nil
				cfg.Demo = boundary == "demo-preview"
				failure := errors.New("independent synchronous setup failure")
				control := &startupCancellationControl{lifecycleControl: authority.lifecycleControl,
					boundary: boundary, entered: make(chan context.Context, 1), closed: make(chan context.Context, 1), release: make(chan struct{}), failure: failure}
				cfg.Control = control
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan error, 1)
				go func() { done <- Publish(ctx, cfg) }()
				setup := <-control.entered
				canceledAt := time.Now()
				cancel()
				synctest.Wait()
				// release even a broken implementation so the bubble can join.
				if setup.Err() == nil {
					t.Error("caller cancellation did not interrupt synchronous startup")
					close(control.release)
					<-done
					return
				}
				err := <-done
				closeContext := <-control.closed
				until, bounded := closeContext.Deadline()
				if !bounded || !until.Equal(canceledAt.Add(10*time.Second)) || !time.Now().Before(until) {
					t.Fatal("exact-run cleanup lost the original remaining shutdown budget", until, time.Now())
				}
				if control.closes != 1 || control.heartbeats != 0 || control.bad != nil {
					t.Fatal("startup cancellation skipped exact cleanup or started serving", control.closes, control.heartbeats, control.bad)
				}
				if !errors.Is(err, context.Canceled) || !errors.Is(err, failure) || errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("startup cancellation lost an independent failure or exhausted cleanup", err)
				}
			})
		})
	}
}
