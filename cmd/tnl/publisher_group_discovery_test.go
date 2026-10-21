package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisherjob"
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
	select {
	case health := <-fixture.Heartbeat:
		if !health.Healthy || fixture.TargetHandshakes.Load() == 0 {
			t.Fatal("foreground group did not verify discovered EKS target TLS")
		}
	case <-done:
		t.Fatal("foreground group ended before target preflight", result)
	case <-time.After(5 * time.Second):
		t.Fatal("foreground group did not publish its cloud assignment")
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
				registry, err := publisherjob.Open(t.Context(), publisherjob.OpenOptions{Root: filepath.Join(parent, "registry"), User: true})
				if err != nil {
					t.Fatal(err)
				}
				defer registry.Close()
				if err := registry.InstallGroup(t.Context(), fixture.Job, *fixture.Job.GroupMember, fixture.Key); err != nil {
					t.Fatal(err)
				}
				engine := publisherjob.Engine{Registry: registry, PollInterval: 5 * time.Millisecond, Group: func(ctx context.Context, job publisherjob.Job, observe func(int64, bool) error) error {
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
