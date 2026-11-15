package ingress

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	controlingress "github.com/tnldotdev/tnl/internal/control/api/private/ingress"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func TestDirectStaleLeaseClearsController(t *testing.T) {
	client, err := controlingress.NewDirectClient(controlingress.DirectConfig{Store: staleLeaseStore{}, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RenewIngress(t.Context(), "ingress-1", ingressv1.IngressRenewal{
		IngressId: "ingress-1", IngressRunId: "run-1", IngressLeaseRevision: 1,
	})
	if err == nil {
		t.Fatal("direct adapter accepted a stale lease")
	}
	controller := &Controller{lease: ingressv1.IngressLease{IngressLeaseRevision: 1}}
	controller.responseError("renew", err)
	if controller.lease.IngressLeaseRevision != 0 || !controller.leaseLost {
		t.Fatalf("stale state retained: %#v", controller)
	}
}

type staleLeaseStore struct{ controlingress.Store }

func (staleLeaseStore) RenewIngress(context.Context, controlstate.IngressRenewal, time.Time, time.Duration) (controlstate.IngressLease, error) {
	return controlstate.IngressLease{}, controlstate.ErrIngressLeaseStale
}

func TestRunUntilEitherStopsJoinsSibling(t *testing.T) {
	failure := errors.New("renewal stopped")
	siblingDone := make(chan struct{})
	err := runUntilEitherStops(t.Context(),
		func(context.Context) error { return failure },
		func(ctx context.Context) error {
			defer close(siblingDone)
			<-ctx.Done()
			return nil
		},
	)
	if !errors.Is(err, failure) {
		t.Fatalf("loop failure = %v", err)
	}
	select {
	case <-siblingDone:
	default:
		t.Fatal("controller returned before its sibling exited")
	}
}

func TestRunUntilEitherStopsRetainsIndependentFailureDuringCancellation(t *testing.T) {
	failure := errors.New("renewal failed during shutdown")
	ctx, cancel := context.WithCancel(t.Context())
	entered := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- runUntilEitherStops(ctx,
			func(context.Context) error {
				close(entered)
				<-ctx.Done()
				return failure
			},
			func(runCtx context.Context) error {
				<-runCtx.Done()
				return nil
			},
		)
	}()
	<-entered
	cancel()
	if err := <-result; !errors.Is(err, failure) {
		t.Fatalf("independent renewal failure lost during cancellation: %v", err)
	}
}

type leaseTestClient struct {
	ControlClient
	register func(context.Context, ingressv1.IngressRegistration) (ingressv1.IngressLease, error)
	renew    func(context.Context) (ingressv1.IngressLease, error)
}

func (c leaseTestClient) RegisterIngress(ctx context.Context, registration ingressv1.IngressRegistration) (ingressv1.IngressLease, error) {
	return c.register(ctx, registration)
}
func (c leaseTestClient) RenewIngress(ctx context.Context, _ ingressv1.IngressID, _ ingressv1.IngressRenewal) (ingressv1.IngressLease, error) {
	return c.renew(ctx)
}

func testIngressLease(now time.Time) ingressv1.IngressLease {
	return ingressv1.IngressLease{IngressId: "ingress", IngressRunId: "run", IngressLeaseRevision: 1, ProtocolVersion: 1, ConnectionCapacity: 10, RegisteredAt: now, RenewedAt: now, LeaseExpiresAt: now.Add(time.Hour)}
}

func testLeaseController(t *testing.T, client ControlClient) *Controller {
	t.Helper()
	controller, err := NewController(ControllerConfig{Client: client, Registration: ingressv1.IngressRegistration{IngressId: "ingress", IngressRunId: "run", ProtocolVersion: 1, ConnectionCapacity: 10}, RenewalInterval: time.Millisecond, RetryInterval: time.Millisecond, Report: func(error) {}})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func TestControllerRetriesTransientErrorsButTerminatesStaleRun(t *testing.T) {
	lease := testIngressLease(time.Now())
	var registrations, renewals atomic.Int32
	client := leaseTestClient{
		register: func(_ context.Context, registration ingressv1.IngressRegistration) (ingressv1.IngressLease, error) {
			if registration.IngressRunId != "run" {
				t.Error("controller silently replaced run ID")
			}
			if registrations.Add(1) == 1 {
				return ingressv1.IngressLease{}, errors.New("startup transport failure")
			}
			return lease, nil
		},
		renew: func(context.Context) (ingressv1.IngressLease, error) {
			if renewals.Add(1) == 1 {
				return ingressv1.IngressLease{}, errors.New("temporary renewal transport failure")
			}
			return ingressv1.IngressLease{}, serverhttp.NewProblemError(409, "ingress_lease_stale", "lease lost")
		},
	}
	controller := testLeaseController(t, client)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := controller.Run(ctx); !errors.Is(err, ErrIngressLeaseLost) {
		t.Fatalf("Run = %v", err)
	}
	if registrations.Load() != 3 || renewals.Load() != 2 || controller.Ready(time.Now()) {
		t.Fatalf("registrations=%d renewals=%d ready=%t", registrations.Load(), renewals.Load(), controller.Ready(time.Now()))
	}
}

func TestControllerExpiresWhileRenewalIsBlocked(t *testing.T) {
	lease := testIngressLease(time.Now())
	lease.LeaseExpiresAt = time.Now().Add(50 * time.Millisecond)
	var registrations atomic.Int32
	client := leaseTestClient{
		register: func(context.Context, ingressv1.IngressRegistration) (ingressv1.IngressLease, error) {
			registrations.Add(1)
			return lease, nil
		},
		renew: func(ctx context.Context) (ingressv1.IngressLease, error) {
			<-ctx.Done()
			return ingressv1.IngressLease{}, ctx.Err()
		},
	}
	controller := testLeaseController(t, client)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := controller.Run(ctx); !errors.Is(err, ErrIngressLeaseLost) {
		t.Fatalf("Run = %v", err)
	}
	if registrations.Load() != 1 || controller.Ready(time.Now()) {
		t.Fatal("expired run retried or remained ready")
	}
}

func TestControllerRejectsLateRenewalAndChangedRevision(t *testing.T) {
	for _, mode := range []string{"late-valid", "expired-response", "changed-revision"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Date(2026, 9, 18, 23, 30, 0, 0, time.UTC)
			controller := testLeaseController(t, leaseTestClient{})
			controller.now = func() time.Time { return now }
			lease := testIngressLease(now)
			if err := controller.setLease(lease); err != nil {
				t.Fatal(err)
			}
			updated := lease
			switch mode {
			case "late-valid":
				now = lease.LeaseExpiresAt
				updated = testIngressLease(now)
				updated.RegisteredAt = lease.RegisteredAt
			case "expired-response":
				updated.LeaseExpiresAt = now
			case "changed-revision":
				updated.IngressLeaseRevision++
			}
			if err := controller.setLease(updated); !errors.Is(err, ErrIngressLeaseLost) {
				t.Fatalf("setLease = %v", err)
			}
		})
	}
}
