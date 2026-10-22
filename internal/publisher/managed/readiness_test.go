package privatepublisher

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type failingHeartbeatControl struct {
	*lifecycleControl
	fail atomic.Bool
}

type invalidLeaseControl struct{ *lifecycleControl }

func (c *invalidLeaseControl) HeartbeatPrivateServiceRunHealth(ctx context.Context, id, run string, token credentials.ManagedRunToken, h controlv1.PrivateServiceRunHeartbeat) (controlv1.PrivateServiceRunState, error) {
	state, err := c.lifecycleControl.HeartbeatPrivateServiceRunHealth(ctx, id, run, token, h)
	if state.State == "closed" {
		state.PublisherExpiresAt = time.Now().Add(2 * time.Hour)
	}
	return state, err
}

func TestRejectedHeartbeatCannotAdvanceConfirmedLeaseMeasurement(t *testing.T) {
	config, control := lifecycleFixture(t)
	control.revoke = true
	config.Control = &invalidLeaseControl{lifecycleControl: control}
	config.Connect = func(context.Context, *Bound, uint8) (SlotSession, error) {
		return &heldSlot{stopped: make(chan struct{})}, nil
	}
	metrics := observability.New("publisher")
	t.Cleanup(func() { _ = metrics.Shutdown(context.Background()) })
	ctx, cancel := context.WithTimeout(observability.WithMetrics(t.Context(), metrics), 3*time.Second)
	defer cancel()
	if err := Publish(ctx, config); !errors.Is(err, ErrPrivateStream) {
		t.Fatal("invalid heartbeat did not stop the run", err)
	}
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var lease float64
	for _, family := range families {
		if family.GetName() == "tnl_publisher_lease_expiration_timestamp_seconds" {
			for _, point := range family.Metric {
				lease = point.GetGauge().GetValue()
			}
		}
	}
	if lease <= float64(time.Now().Unix()) || lease > float64(time.Now().Add(2*time.Minute).Unix()) {
		t.Fatal("rejected heartbeat extended the last confirmed lease", lease)
	}
}

func (c *failingHeartbeatControl) HeartbeatPrivateServiceRunHealth(ctx context.Context, id, run string, token credentials.ManagedRunToken, h controlv1.PrivateServiceRunHeartbeat) (controlv1.PrivateServiceRunState, error) {
	if c.fail.Swap(false) {
		return controlv1.PrivateServiceRunState{}, failure.Wrap("refresh publisher", failure.ServerUnavailable, errors.New("fixture heartbeat failed"))
	}
	return c.lifecycleControl.HeartbeatPrivateServiceRunHealth(ctx, id, run, token, h)
}

func TestReadinessRecoversAfterHeartbeatFailureWithoutRepeatingReady(t *testing.T) {
	config, control := lifecycleFixture(t)
	flaky := &failingHeartbeatControl{lifecycleControl: control}
	config.Control = flaky
	var readyCalls atomic.Int32
	var healthy atomic.Bool
	healthy.Store(true)
	config.Ready = func() error { readyCalls.Add(1); return nil }
	config.Healthy = func(context.Context) bool { return healthy.Load() }
	config.Connect = func(context.Context, *Bound, uint8) (SlotSession, error) {
		return &heldSlot{stopped: make(chan struct{})}, nil
	}
	statuses := make(chan RunStatus, 128)
	config.ObserveReadiness = func(status RunStatus) { statuses <- status }
	metrics := observability.New("publisher")
	t.Cleanup(func() { _ = metrics.Shutdown(context.Background()) })
	ctx, cancel := context.WithTimeout(observability.WithMetrics(t.Context(), metrics), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Publish(ctx, config) }()
	wait := func(predicate func(RunStatus) bool) RunStatus {
		t.Helper()
		for {
			select {
			case status := <-statuses:
				if predicate(status) {
					return status
				}
			case err := <-done:
				t.Fatal("publisher ended before readiness observation", err)
			case <-ctx.Done():
				t.Fatal("readiness observation timed out")
			}
		}
	}
	initial := wait(func(s RunStatus) bool { return s.Ready })
	flaky.fail.Store(true)
	failed := wait(func(s RunStatus) bool { return !s.Ready && s.LastCheck.After(initial.LastCheck) })
	if !failed.TargetHealthy || !failed.ConfigurationCurrent || failed.LastSuccess.IsZero() || failed.LastSuccess.After(failed.LastCheck) || !failed.LeaseExpiresAt.After(failed.LastCheck) {
		t.Fatalf("transient heartbeat failure conflated health, configuration or lease: %+v", failed)
	}
	recovered := wait(func(s RunStatus) bool { return s.Ready && s.LastSuccess.After(failed.LastCheck) })
	if readyCalls.Load() != 1 || !recovered.LastCheck.After(failed.LastCheck) {
		t.Fatal("recovery repeated the one-time callback or left the check stale", readyCalls.Load())
	}
	healthy.Store(false)
	unhealthy := wait(func(s RunStatus) bool { return !s.TargetHealthy })
	if unhealthy.Ready || !unhealthy.ConfigurationCurrent || !unhealthy.LeaseExpiresAt.After(unhealthy.LastCheck) {
		t.Fatalf("target failure changed authority facts: %+v", unhealthy)
	}
	healthy.Store(true)
	wait(func(s RunStatus) bool { return s.Ready && s.LastCheck.After(unhealthy.LastCheck) })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, family := range families {
		switch family.GetName() {
		case "tnl_publisher_ready":
			if len(family.Metric) != 1 || family.Metric[0].GetGauge().GetValue() != 0 {
				t.Fatal("stopped publisher retained ready measurement")
			}
			seen[family.GetName()] = true
		case "tnl_publisher_readiness_last_check_timestamp_seconds", "tnl_publisher_readiness_last_success_timestamp_seconds", "tnl_publisher_lease_expiration_timestamp_seconds", "tnl_publisher_target_healthy", "tnl_publisher_configuration_current":
			seen[family.GetName()] = true
		}
	}
	if len(seen) != 6 {
		t.Fatal("missing independent readiness measurements", seen)
	}
}
