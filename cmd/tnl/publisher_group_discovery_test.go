package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	"github.com/tnldotdev/tnl/internal/testutil/groupdiscovery"
)

func TestPublisherGroupDiscoveryForegroundUsesNativeTLS(t *testing.T) {
	fixture := groupdiscovery.New(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	var result error
	go func() {
		defer close(done)
		result = servePublisherGroupWithDiscovery(ctx, fixture.Job, fixture.Profile, fixture.Key, nil, fixture)
	}()
	defer func() { cancel(); <-done }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	select {
	case health := <-fixture.Heartbeat:
		if !health.Healthy {
			t.Fatal("foreground group reported unhealthy discovered EKS target TLS")
		}
	case <-done:
		t.Fatal("foreground group ended before target preflight", result)
	case <-deadline.C:
		t.Fatal("foreground group did not publish its cloud assignment")
	}
	// the client may finish TLS before the server records its handshake.
	// join that observation inside the same preparation budget.
	select {
	case <-fixture.TargetHandshake:
		if fixture.TargetHandshakes.Load() == 0 {
			t.Fatal("foreground group did not verify discovered EKS target TLS")
		}
	case <-done:
		t.Fatal("foreground group ended before target recorded TLS", result)
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
		t.Fatal("foreground group did not join")
	}
	if fixture.Requests.Load() != 1 || fixture.Stops.Load() != 1 {
		t.Fatal("foreground group did not own one shared discovery lifetime")
	}
}

func TestPublisherGroupDiscoveryShutdownJoinsAWSLookupsAndWorkers(t *testing.T) {
	for _, installed := range []bool{false, true} {
		name := "foreground"
		if installed {
			name = "installed"
		}
		t.Run(name, func(t *testing.T) {
			fixture := groupdiscovery.New(t)
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
				if err := registry.InstallGroup(t.Context(), fixture.Job, *fixture.Job.GroupMember, fixture.Key); err != nil {
					t.Fatal(err)
				}
				engine := installedjobs.Engine{Registry: registry, PollInterval: 5 * time.Millisecond, Group: func(ctx context.Context, job installedjobs.Job, observe func(int64, bool) error) error {
					_, private, profile, err := registry.GroupIdentity(ctx, job)
					if err != nil {
						return err
					}
					return servePublisherGroupWithDiscovery(ctx, job, profile, private, observe, fixture)
				}}
				go func() { defer close(done); result = engine.Serve(ctx) }()
			} else {
				go func() {
					defer close(done)
					result = servePublisherGroupWithDiscovery(ctx, fixture.Job, fixture.Profile, fixture.Key, nil, fixture)
				}()
			}
			defer func() { cancel(); <-done }()
			select {
			case <-fixture.DiscoveryStarted:
			case <-done:
				t.Fatal("group ended before discovery", result)
			case <-time.After(5 * time.Second):
				t.Fatal("group did not call DescribeCluster")
			}
			cancel()
			select {
			case <-done:
				if result != nil {
					t.Fatal(result)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("group shutdown waited for discovery's normal timeout")
			}
			select {
			case <-fixture.DiscoveryStopped:
			case <-time.After(time.Second):
				t.Fatal("group returned with an AWS lookup still running")
			}
			if fixture.Requests.Load() != 1 || fixture.Stops.Load() != 1 || fixture.TargetHandshakes.Load() != 0 {
				t.Fatal("unexpected target work or unjoined group lifetime")
			}
		})
	}
}
