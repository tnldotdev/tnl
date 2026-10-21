package grouppublisher_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/grouppublisher"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/internal/targetdiscovery"
	"github.com/tnldotdev/tnl/internal/testutil/groupdiscovery"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestSignedCloudAssignmentProductionCallbackAndTargetTLS(t *testing.T) {
	for _, installed := range []bool{false, true} {
		name := "foreground"
		if installed {
			name = "installed"
		}
		t.Run(name, func(t *testing.T) {
			fixture := groupdiscovery.New(t)
			metrics := observability.New("publisher")
			defer metrics.Shutdown(context.Background())
			ctx, cancel := context.WithCancel(observability.WithMetrics(t.Context(), metrics))
			defer cancel()
			client, err := publisherjob.GroupClient(fixture.Job)
			if err != nil {
				t.Fatal(err)
			}
			control, authority, err := publisherjob.Clients(fixture.Job)
			if err != nil {
				t.Fatal(err)
			}
			resolver, err := targetdiscovery.New(fixture, targetdiscovery.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer resolver.Close()
			publication := publisherjob.GroupPublisher{Member: *fixture.Job.GroupMember, Private: fixture.Key, State: fixture.Profile, Control: control, Authority: authority, Discovery: resolver}
			runtime := func(ctx context.Context, job publisherjob.Job, observe func(int64, bool) error) error {
				return (grouppublisher.Runtime{Control: client, Member: *job.GroupMember, Private: fixture.Key, PollInterval: 5 * time.Millisecond, Observe: observe, Publish: publication.Publish}).Serve(ctx)
			}
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
					member, key, profile, err := registry.GroupIdentity(ctx, job)
					if err != nil {
						return err
					}
					publication.Member, publication.Private, publication.State = member, key, profile
					return runtime(ctx, job, observe)
				}}
				go func() { defer close(done); result = engine.Serve(ctx) }()
			} else {
				go func() { defer close(done); result = runtime(ctx, fixture.Job, nil) }()
			}
			defer func() { cancel(); <-done }()
			select {
			case heartbeat := <-fixture.Heartbeat:
				if !heartbeat.Healthy || fixture.TargetHandshakes.Load() == 0 {
					t.Fatal("assigned EKS CA/SNI did not reach native target TLS preflight")
				}
			case <-done:
				t.Fatal("group exited before target preparation", result)
			case <-time.After(5 * time.Second):
				t.Fatal("signed assignment did not reach production callback and verified target")
			}
			cancel()
			select {
			case <-done:
				if result != nil {
					t.Fatal(result)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("group workers did not join")
			}
			if fixture.Requests.Load() != 1 || fixture.Stops.Load() != 1 || fixture.Closes.Load() != 1 {
				t.Fatalf("wrong shared discovery or lifecycle boundary: discovery=%d stop=%d close=%d", fixture.Requests.Load(), fixture.Stops.Load(), fixture.Closes.Load())
			}
			families, err := metrics.Gather()
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, family := range families {
				if family.GetName() != "tnl_target_discovery_duration_seconds" {
					continue
				}
				for _, point := range family.Metric {
					for _, label := range point.Label {
						if label.GetName() == "tnl_service_protocol" && label.GetValue() == "kubernetes" {
							found = true
						}
						if label.GetName() == "tnl_target_resource_id" || label.GetName() == "tnl_target_resource_arn" {
							t.Fatal("resource identity escaped the telemetry budget")
						}
					}
				}
			}
			if !found {
				t.Fatal("Kubernetes discovery protocol was rejected by the telemetry budget")
			}
		})
	}
}

func TestCloudAssignmentRejectsSavedServiceDriftBeforeAWS(t *testing.T) {
	for _, name := range []string{"protocol", "trust-revision", "service", "mixed-target", "mixed-trust", "empty-selector", "wrong-provider-protocol"} {
		t.Run(name, func(t *testing.T) {
			fixture := groupdiscovery.New(t)
			assignment := fixture.Assignment()
			switch name {
			case "protocol":
				fixture.ChangeService(func(s *controlv1.PrivateService) { s.Protocol = controlv1.PrivateServiceProtocol("postgres") })
			case "trust-revision":
				fixture.ChangeService(func(s *controlv1.PrivateService) { s.TrustRevision++ })
			case "service":
				fixture.ChangeService(func(s *controlv1.PrivateService) { s.Id = "another-service" })
			case "mixed-target":
				assignment.Configuration.Target = "unapproved.example:443"
			case "mixed-trust":
				assignment.Configuration.TargetTls = &controlv1.ProjectTargetTLS{Hostname: "unapproved.example"}
			case "empty-selector":
				assignment.Configuration.TargetDiscovery.Instance = new("")
			case "wrong-provider-protocol":
				assignment.Configuration.TargetDiscovery.Type = controlv1.Rds
			}
			control, authority, err := publisherjob.Clients(fixture.Job)
			if err != nil {
				t.Fatal(err)
			}
			resolver, err := targetdiscovery.New(fixture, targetdiscovery.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer resolver.Close()
			publication := publisherjob.GroupPublisher{Member: *fixture.Job.GroupMember, Private: fixture.Key, State: fixture.Profile, Control: control, Authority: authority, Discovery: resolver}
			if err := publication.Publish(t.Context(), assignment, nil); err == nil {
				t.Fatal("mismatched assignment was accepted")
			}
			if fixture.Requests.Load() != 0 || fixture.TargetHandshakes.Load() != 0 {
				t.Fatal("mismatched assignment consulted AWS or the target")
			}
		})
	}
}

func TestCloudAssignmentChangedDescriptorPreparesIndependentPin(t *testing.T) {
	fixture := groupdiscovery.New(t)
	client, err := publisherjob.GroupClient(fixture.Job)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := client.Lease(t.Context(), *fixture.Job.GroupMember, fixture.Key)
	if err != nil {
		t.Fatal(err)
	}
	control, authority, err := publisherjob.Clients(fixture.Job)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := targetdiscovery.New(fixture, targetdiscovery.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	publication := publisherjob.GroupPublisher{Member: *fixture.Job.GroupMember, Private: fixture.Key, State: fixture.Profile, Control: control, Authority: authority, Discovery: resolver}
	for _, cluster := range []string{"production", "replacement"} {
		assignment := fixture.Assignment()
		assignment.Configuration.TargetDiscovery.Cluster = new(cluster)
		fixture.SetAssignment(assignment)
		current, err := client.Assignments(t.Context(), lease.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		// the fixture ends at the first heartbeat after successful native target
		// TLS. the same resolver must allow the new declared selector its own pin.
		if err := publication.Publish(t.Context(), current.Services[0], nil); err == nil {
			t.Fatal("fixture heartbeat did not bound the publication")
		}
		select {
		case health := <-fixture.Heartbeat:
			if !health.Healthy {
				t.Fatal("new assignment inherited the previous target's pin")
			}
		default:
			t.Fatal("new assignment failed before target preflight")
		}
	}
	if fixture.Requests.Load() != 2 || fixture.Closes.Load() != 2 {
		t.Fatal("a replaced descriptor silently reused the previous preparation")
	}
}
