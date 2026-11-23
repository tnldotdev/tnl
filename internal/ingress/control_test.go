package ingress

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
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
	drain    func(context.Context, ingressv1.IngressDrainRequest) (ingressv1.IngressLease, error)
}

func (c leaseTestClient) RegisterIngress(ctx context.Context, registration ingressv1.IngressRegistration) (ingressv1.IngressLease, error) {
	return c.register(ctx, registration)
}
func (c leaseTestClient) RenewIngress(ctx context.Context, _ ingressv1.IngressID, _ ingressv1.IngressRenewal) (ingressv1.IngressLease, error) {
	return c.renew(ctx)
}
func (c leaseTestClient) DrainIngress(ctx context.Context, _ ingressv1.IngressID, request ingressv1.IngressDrainRequest) (ingressv1.IngressLease, error) {
	return c.drain(ctx, request)
}

func testIngressLease(now time.Time) ingressv1.IngressLease {
	return ingressv1.IngressLease{IngressId: "ingress", IngressRunId: "run", IngressLeaseRevision: 1, ProtocolVersion: 1, ConnectionCapacity: 10, RegisteredAt: now, RenewedAt: now, ServingUntil: now.Add(time.Hour)}
}

func testLeaseController(t *testing.T, client ControlClient) *Controller {
	t.Helper()
	controller, err := NewController(ControllerConfig{Client: client, Registration: ingressv1.IngressRegistration{IngressId: "ingress", IngressRunId: "run", ProtocolVersion: 1, ConnectionCapacity: 10}, RenewalInterval: time.Millisecond, RetryInterval: time.Millisecond, Report: func(error) {}})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func TestIngressRenewalDuringDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease := testIngressLease(time.Now())
		deadline := time.Now().Add(time.Minute)
		release := make(chan struct{})
		renewals := 0
		client := leaseTestClient{
			register: func(context.Context, ingressv1.IngressRegistration) (ingressv1.IngressLease, error) {
				return lease, nil
			},
			drain: func(_ context.Context, request ingressv1.IngressDrainRequest) (ingressv1.IngressLease, error) {
				lease.Draining, lease.DrainDeadline = true, &request.Deadline
				reply := lease
				<-release
				return reply, nil
			},
			renew: func(context.Context) (ingressv1.IngressLease, error) {
				renewals++
				reply := lease
				reply.RenewedAt = time.Now()
				return reply, nil
			},
		}
		controller := testLeaseController(t, client)
		if err := controller.register(t.Context()); err != nil {
			t.Fatal(err)
		}
		drained := make(chan error, 1)
		go func() { drained <- controller.Drain(t.Context(), deadline) }()
		synctest.Wait()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- controller.renewLoop(ctx) }()
		time.Sleep(controller.renewalInterval)
		synctest.Wait()
		close(release)
		if err := <-drained; err != nil {
			t.Fatalf("drain lost a current lease: %v", err)
		}
		synctest.Wait()
		got := controller.Lease()
		if renewals != 1 || !got.RenewedAt.Equal(time.Now()) || !got.Draining || got.DrainDeadline == nil || !got.DrainDeadline.Equal(deadline) {
			t.Fatalf("renewals=%d lease=%+v", renewals, got)
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestIngressDrainDeadlineDuringRenewal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease := testIngressLease(time.Now())
		release := make(chan struct{})
		client := leaseTestClient{
			renew: func(context.Context) (ingressv1.IngressLease, error) {
				<-release
				return lease, nil
			},
			drain: func(context.Context, ingressv1.IngressDrainRequest) (ingressv1.IngressLease, error) {
				t.Error("expired drain reached control")
				return lease, nil
			},
		}
		c := testLeaseController(t, client)
		if err := c.setLease(lease); err != nil {
			t.Fatal(err)
		}
		renewed := make(chan error, 1)
		go func() { renewed <- c.renew(t.Context()) }()
		synctest.Wait()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		deadline, _ := ctx.Deadline()
		drained := make(chan error, 1)
		go func() { drained <- c.Drain(ctx, deadline) }()
		synctest.Wait()
		if c.Ready(time.Now()) {
			t.Error("ingress still ready while drain waited for renewal")
		}
		if err := <-drained; !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("waiting for renewal: %v", err)
		}
		close(release)
		if err := <-renewed; err != nil || c.Ready(time.Now()) {
			t.Fatalf("renew after drain: err=%v ready=%t", err, c.Ready(time.Now()))
		}
	})
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
	lease.ServingUntil = time.Now().Add(50 * time.Millisecond)
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
				now = lease.ServingUntil
				updated = testIngressLease(now)
				updated.RegisteredAt = lease.RegisteredAt
			case "expired-response":
				updated.ServingUntil = now
			case "changed-revision":
				updated.IngressLeaseRevision++
			}
			if err := controller.setLease(updated); !errors.Is(err, ErrIngressLeaseLost) {
				t.Fatalf("setLease = %v", err)
			}
		})
	}
}
