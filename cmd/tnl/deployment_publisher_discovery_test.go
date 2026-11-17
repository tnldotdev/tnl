package main

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	"github.com/tnldotdev/tnl/internal/testutil/deploymentdiscovery"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestDeploymentPublisherDiscoveryForegroundUsesNativeTLS(t *testing.T) {
	fixture := deploymentdiscovery.New(t)
	fixture.HoldPublication.Store(true)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	var result error
	go func() {
		defer close(done)
		result = serveDeploymentPublisherWithDiscovery(ctx, fixture.Job, fixture.Profile, fixture.Key, nil, nil, fixture, nil, nil)
	}()
	defer func() { cancel(); <-done }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	select {
	case health := <-fixture.Heartbeat:
		if !health.Healthy {
			t.Fatal("foreground deployment reported unhealthy discovered EKS target TLS")
		}
	case <-done:
		t.Fatal("foreground deployment ended before target preflight", result)
	case <-deadline.C:
		t.Fatal("foreground deployment did not publish its cloud assignment")
	}
	// the client may finish TLS before the server records its handshake.
	// join that observation inside the same preparation budget.
	select {
	case <-fixture.TargetHandshake:
		if fixture.TargetHandshakes.Load() == 0 {
			t.Fatal("foreground deployment did not verify discovered EKS target TLS")
		}
	case <-done:
		t.Fatal("foreground deployment ended before target recorded TLS", result)
	case <-deadline.C:
		t.Fatal("target did not record the verified TLS handshake")
	}
	cancel()
	select {
	case <-done:
		if result != nil {
			t.Fatal(result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("foreground deployment did not join")
	}
	if fixture.Requests.Load() != 1 || fixture.Stops.Load() != 1 {
		t.Fatal("foreground deployment did not own one shared discovery lifetime")
	}
}

func TestDeploymentPublisherDiscoveryRetainsHeartbeatFailureBeforeCancellation(t *testing.T) {
	fixture := deploymentdiscovery.New(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	var result error
	go func() {
		defer close(done)
		result = serveDeploymentPublisherWithDiscovery(ctx, fixture.Job, fixture.Profile, fixture.Key, nil, nil, fixture, nil, nil)
	}()
	defer func() { cancel(); <-done }()
	select {
	case health := <-fixture.Heartbeat:
		if !health.Healthy {
			t.Fatal("foreground deployment reported unhealthy discovered target")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("foreground deployment did not reach the actual heartbeat")
	}
	// cleanup starts only after the independent heartbeat failure was received.
	// cancel while the deployment still owns that failed assignment.
	select {
	case <-fixture.RunClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("failed assignment did not reach exact run cleanup")
	}
	cancel()
	select {
	case <-done:
		var problem *clientcontrol.ProblemError
		if !errors.Is(result, clientcontrol.ErrUnavailable) || !errors.As(result, &problem) ||
			problem.Status != http.StatusServiceUnavailable || problem.Problem.Code != controlv1.Unavailable {
			t.Fatal("independent heartbeat failure was discarded or reclassified", result)
		}
		var onlyHeartbeat func(error) bool
		onlyHeartbeat = func(err error) bool {
			if err == problem || err == clientcontrol.ErrUnavailable {
				return true
			}
			if joined, ok := err.(interface{ Unwrap() []error }); ok {
				for _, cause := range joined.Unwrap() {
					if !onlyHeartbeat(cause) {
						return false
					}
				}
				return len(joined.Unwrap()) != 0
			}
			if cause := errors.Unwrap(err); cause != nil {
				return onlyHeartbeat(cause)
			}
			return false
		}
		if !onlyHeartbeat(result) {
			t.Fatal("heartbeat result contains an independent operation or cleanup failure", result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("foreground deployment did not join after heartbeat failure")
	}
	if fixture.Requests.Load() != 1 || fixture.Stops.Load() != 1 {
		t.Fatal("failed foreground deployment left discovery or process ownership behind")
	}
}

func TestDeploymentPublisherDiscoveryShutdownJoinsAWSLookupsAndWorkers(t *testing.T) {
	for _, installed := range []bool{false, true} {
		name := "foreground"
		if installed {
			name = "installed"
		}
		t.Run(name, func(t *testing.T) {
			fixture := deploymentdiscovery.New(t)
			fixture.Block.Store(true)
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			var result error
			if installed {
				parent, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				registry, err := installedjobs.Open(t.Context(), installedjobs.OpenOptions{Root: filepath.Join(parent, "registry"), User: true})
				if err != nil {
					t.Fatal(err)
				}
				defer registry.Close()
				if err := registry.InstallDeployment(t.Context(), fixture.Job, *fixture.Job.DeploymentMember, fixture.Key); err != nil {
					t.Fatal(err)
				}
				engine := installedjobs.Engine{Registry: registry, PollInterval: 5 * time.Millisecond, Deployment: func(ctx context.Context, job installedjobs.Job, telemetry *clienttelemetry.Collector, observe func(int64, bool) error, deadline func() time.Time, shutdown context.Context) error {
					_, private, profile, err := registry.DeploymentIdentity(ctx, job)
					if err != nil {
						return err
					}
					return serveDeploymentPublisherWithDiscovery(ctx, job, profile, private, telemetry, observe, fixture, deadline, shutdown)
				}}
				go func() { defer close(done); result = engine.Serve(ctx) }()
			} else {
				go func() {
					defer close(done)
					result = serveDeploymentPublisherWithDiscovery(ctx, fixture.Job, fixture.Profile, fixture.Key, nil, nil, fixture, nil, nil)
				}()
			}
			defer func() { cancel(); <-done }()
			select {
			case <-fixture.DiscoveryStarted:
			case <-done:
				t.Fatal("deployment ended before discovery", result)
			case <-time.After(5 * time.Second):
				t.Fatal("deployment did not call DescribeCluster")
			}
			cancel()
			select {
			case <-done:
				if result != nil {
					t.Fatal(result)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("deployment shutdown waited for discovery's normal timeout")
			}
			select {
			case <-fixture.DiscoveryStopped:
			case <-time.After(time.Second):
				t.Fatal("deployment returned with an AWS lookup still running")
			}
			if fixture.Requests.Load() != 1 || fixture.Stops.Load() != 1 || fixture.TargetHandshakes.Load() != 0 {
				t.Fatal("unexpected target work or unjoined deployment lifetime")
			}
		})
	}
}
