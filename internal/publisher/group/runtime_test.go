package group

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/observability"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type groupControl struct {
	mu         sync.Mutex
	assignment controlv1.EnvironmentPublisherAssignments
	expires    time.Time
	fail       bool
	acks       chan controlv1.EnvironmentPublisherAcknowledgement
}

func (c *groupControl) ServerURL() string { return "https://control.example" }
func (c *groupControl) PublisherRuntime(_ context.Context, r controlv1.PublisherRuntimeRequest) (controlv1.PublisherRuntimeResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return controlv1.PublisherRuntimeResponse{}, clientcontrol.ErrUnavailable
	}
	epoch := r.ExpectedEpoch
	if r.Action == controlv1.RuntimeStart {
		epoch++
	}
	return controlv1.PublisherRuntimeResponse{Epoch: epoch, LeaseExpiresAt: &c.expires, EnvironmentLease: &controlv1.EnvironmentPublisherLease{AccessToken: "environment-lease", ExpiresAt: c.expires}}, nil
}
func (c *groupControl) Assignments(context.Context, string) (controlv1.EnvironmentPublisherAssignments, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return controlv1.EnvironmentPublisherAssignments{}, clientcontrol.ErrUnavailable
	}
	return c.assignment, nil
}
func (c *groupControl) Acknowledge(_ context.Context, _ string, ack controlv1.EnvironmentPublisherAcknowledgement) error {
	select {
	case c.acks <- ack:
	default:
	}
	return nil
}
func groupFixture(t *testing.T) (*groupControl, ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &groupControl{expires: time.Now().Add(time.Second), acks: make(chan controlv1.EnvironmentPublisherAcknowledgement, 100), assignment: controlv1.EnvironmentPublisherAssignments{
		Publisher:   controlv1.EnvironmentPublisher{EnvironmentId: "environment-one", ProjectKey: "project-one", PublisherIdentityId: "publisher-one", KeyId: "key-one", TeamId: "team-one"},
		Environment: controlv1.EnvironmentPublication{EnvironmentId: "environment-one", MutationRevision: 1, ConfigurationHash: strings.Repeat("a", 64)},
		Services:    []controlv1.EnvironmentPublisherAssignment{{Service: "db", ServiceId: "private-one", GrantId: "exact-grant", TrustRevision: 1, Configuration: controlv1.EnvironmentServicePublication{Protocol: "postgres", Target: "db.internal:5432"}}},
	}}, key
}
func receive(t *testing.T, channel <-chan string) string {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("publisher boundary did not complete")
		return ""
	}
}
func TestReconcileJoinsOldAssignmentBeforeStartingReplacement(t *testing.T) {
	control, key := groupFixture(t)
	events := make(chan string, 10)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- (Runtime{Control: control, Publisher: control.assignment.Publisher, Private: key, PollInterval: time.Millisecond,
			Publish: func(ctx context.Context, publication controlv1.EnvironmentPublication, service controlv1.EnvironmentPublisherAssignment, health func(bool)) error {
				events <- "start:" + service.Configuration.Target
				health(true)
				<-ctx.Done()
				events <- "joined:" + service.Configuration.Target
				return ctx.Err()
			},
		}).Serve(ctx)
	}()
	if got := receive(t, events); got != "start:db.internal:5432" {
		t.Fatal(got)
	}
	control.mu.Lock()
	control.assignment.Services = append([]controlv1.EnvironmentPublisherAssignment(nil), control.assignment.Services...)
	control.assignment.Services[0].Configuration.Target = "replacement.internal:5432"
	control.assignment.Environment.MutationRevision = 2
	control.assignment.Environment.ConfigurationHash = strings.Repeat("b", 64)
	control.mu.Unlock()
	if got := receive(t, events); got != "joined:db.internal:5432" {
		t.Fatal(got)
	}
	if got := receive(t, events); got != "start:replacement.internal:5432" {
		t.Fatal(got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := receive(t, events); got != "joined:replacement.internal:5432" {
		t.Fatal(got)
	}
}

func TestWorkerMeasurementsKeepAcceptedDeploymentAndReplicaScope(t *testing.T) {
	control, key := groupFixture(t)
	member := control.assignment.Publisher
	report := &controlv1.PublisherDeploymentReport{DeploymentId: "aws-example", Provider: "aws", ReplicaKey: "replica-1", Instance: "instance-1", Image: "ghcr.io/tnldotdev/tnl@sha256:" + strings.Repeat("a", 64), SoftwareVersion: "devel", TemplateVersion: "1", TemplateSha256: strings.Repeat("b", 64)}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	identities := make(chan observability.Identity, 1)
	done := make(chan error, 1)
	go func() {
		done <- (Runtime{Control: control, Publisher: member, Private: key, Deployment: report, PollInterval: time.Millisecond, Publish: func(ctx context.Context, _ controlv1.EnvironmentPublication, a controlv1.EnvironmentPublisherAssignment, health func(bool)) error {
			identities <- observability.IdentityFromContext(ctx)
			health(true)
			<-ctx.Done()
			return ctx.Err()
		}}).Serve(ctx)
	}()
	select {
	case id := <-identities:
		if id.TeamID != member.TeamId || id.EnvironmentID != member.EnvironmentId || id.PublisherGroupID != "" || id.PublisherIdentityID != member.PublisherIdentityId || id.DeploymentID != report.DeploymentId || id.ReplicaKey != report.ReplicaKey || id.ServiceID != "private-one" || id.PublicURLID != "" {
			t.Fatal("worker lost accepted deployment scope", id)
		}
	case err := <-done:
		t.Fatal("group ended before starting scoped worker", err)
	case <-time.After(3 * time.Second):
		t.Fatal("group did not start scoped worker")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestLeaseExpiryStopsWorkersWhenAssignmentPollingFails(t *testing.T) {
	control, key := groupFixture(t)
	control.expires = time.Now().Add(40 * time.Millisecond)
	events := make(chan string, 4)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- (Runtime{Control: control, Publisher: control.assignment.Publisher, Private: key, PollInterval: time.Millisecond,
			Publish: func(ctx context.Context, _ controlv1.EnvironmentPublication, _ controlv1.EnvironmentPublisherAssignment, health func(bool)) error {
				events <- "start"
				health(true)
				<-ctx.Done()
				events <- "joined"
				return ctx.Err()
			},
		}).Serve(ctx)
	}()
	if got := receive(t, events); got != "start" {
		t.Fatal(got)
	}
	control.mu.Lock()
	control.fail = true
	control.mu.Unlock()
	if got := receive(t, events); got != "joined" {
		t.Fatal(got)
	}
	cancel()
	if err := <-done; !errors.Is(err, clientcontrol.ErrUnavailable) {
		t.Fatal("independent runtime-stop failure was hidden after lease expiration", err)
	}
}

func TestSelectorRenameDoesNotRestartPublication(t *testing.T) {
	control, key := groupFixture(t)
	member := control.assignment.Publisher
	events := make(chan string, 4)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- (Runtime{Control: control, Publisher: member, Private: key, PollInterval: time.Millisecond, Publish: func(ctx context.Context, _ controlv1.EnvironmentPublication, _ controlv1.EnvironmentPublisherAssignment, health func(bool)) error {
			events <- "start"
			health(true)
			<-ctx.Done()
			events <- "stop"
			return ctx.Err()
		}}).Serve(ctx)
	}()
	if receive(t, events) != "start" {
		t.Fatal("missing publication")
	}
	control.mu.Lock()
	// names are not part of assignments. a target-neutral environment mutation
	// may change the envelope without replacing an unchanged running service.
	control.assignment.Environment.MutationRevision++
	control.assignment.Environment.ConfigurationHash = strings.Repeat("b", 64)
	control.mu.Unlock()
	for {
		select {
		case ack := <-control.acks:
			if ack.Environment.MutationRevision == 2 && ack.Healthy {
				select {
				case event := <-events:
					t.Fatal("selector rename restarted publication", event)
				default:
				}
				cancel()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				return
			}
		case <-time.After(3 * time.Second):
			t.Fatal("rename not acknowledged")
		}
	}
}

func TestRevokedServiceGrantRefreshesAssignmentsWithoutLosingGroup(t *testing.T) {
	control, key := groupFixture(t)
	member := control.assignment.Publisher
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var attempts atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- (Runtime{Control: control, Publisher: member, Private: key, PollInterval: time.Millisecond, Publish: func(ctx context.Context, _ controlv1.EnvironmentPublication, a controlv1.EnvironmentPublisherAssignment, health func(bool)) error {
			if attempts.Add(1) == 1 {
				return clientcontrol.ErrUnauthenticated
			}
			if a.GrantId == "exact-grant" {
				control.mu.Lock()
				control.assignment.Services = append([]controlv1.EnvironmentPublisherAssignment(nil), control.assignment.Services...)
				control.assignment.Services[0].GrantId = "replacement-grant"
				control.assignment.Environment.MutationRevision = 2
				control.mu.Unlock()
			} else {
				health(true)
			}
			<-ctx.Done()
			return ctx.Err()
		}}).Serve(ctx)
	}()
	for {
		select {
		case err := <-done:
			t.Fatal("service revocation stopped the group task", err)
		case ack := <-control.acks:
			if ack.Environment.MutationRevision == 2 && ack.Healthy {
				cancel()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				return
			}
		case <-time.After(3 * time.Second):
			t.Fatal("replacement grant did not become healthy")
		}
	}
}

type cancellationControl struct {
	*groupControl
	phase     string
	cancel    context.CancelFunc
	operation error
	stop      error
}

func (c *cancellationControl) PublisherRuntime(ctx context.Context, request controlv1.PublisherRuntimeRequest) (controlv1.PublisherRuntimeResponse, error) {
	if request.Action == controlv1.RuntimeStop && c.stop != nil {
		return controlv1.PublisherRuntimeResponse{}, c.stop
	}
	if request.Action == controlv1.RuntimeInspect && c.phase == "lease" {
		c.cancel()
		return controlv1.PublisherRuntimeResponse{}, errors.Join(ctx.Err(), c.operation)
	}
	return c.groupControl.PublisherRuntime(ctx, request)
}

func (c *cancellationControl) Assignments(ctx context.Context, access string) (controlv1.EnvironmentPublisherAssignments, error) {
	if c.phase == "assignments" {
		c.cancel()
		return controlv1.EnvironmentPublisherAssignments{}, errors.Join(ctx.Err(), c.operation)
	}
	return c.groupControl.Assignments(ctx, access)
}

func (c *cancellationControl) Acknowledge(ctx context.Context, access string, ack controlv1.EnvironmentPublisherAcknowledgement) error {
	if c.phase == "acknowledge" {
		c.cancel()
		return errors.Join(ctx.Err(), c.operation)
	}
	return c.groupControl.Acknowledge(ctx, access, ack)
}

func TestCancellationDoesNotHideIndependentControlFailure(t *testing.T) {
	for _, phase := range []string{"lease", "assignments", "acknowledge"} {
		t.Run(phase, func(t *testing.T) {
			base, key := groupFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			operation := errors.New("independent control operation")
			control := &cancellationControl{groupControl: base, phase: phase, cancel: cancel, operation: operation}
			err := (Runtime{Control: control, Publisher: base.assignment.Publisher, Private: key, PollInterval: time.Millisecond,
				Publish: func(ctx context.Context, _ controlv1.EnvironmentPublication, _ controlv1.EnvironmentPublisherAssignment, _ func(bool)) error {
					<-ctx.Done()
					return ctx.Err()
				},
			}).Serve(ctx)
			if !errors.Is(err, operation) || !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation hid an independent control failure", err)
			}
		})
	}
}

func TestShutdownCancelsEverySiblingBeforeJoiningAndKeepsCleanupFailures(t *testing.T) {
	base, key := groupFixture(t)
	second := base.assignment.Services[0]
	second.Service, second.ServiceId = "second", "private-two"
	base.assignment.Services = append(base.assignment.Services, second)
	workerFailure, stopFailure := errors.New("independent publication failure"), errors.New("independent runtime stop failure")
	control := &cancellationControl{groupControl: base, stop: stopFailure}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := make(chan string, 2)
	canceled := map[string]chan struct{}{"db": make(chan struct{}), "second": make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- (Runtime{Control: control, Publisher: base.assignment.Publisher, Private: key, PollInterval: time.Millisecond,
			Publish: func(ctx context.Context, publication controlv1.EnvironmentPublication, assignment controlv1.EnvironmentPublisherAssignment, _ func(bool)) error {
				if publication != base.assignment.Environment {
					return errors.New("worker received another environment envelope")
				}
				started <- assignment.Service
				<-ctx.Done()
				close(canceled[assignment.Service])
				other := "db"
				if assignment.Service == other {
					other = "second"
				}
				<-canceled[other]
				if assignment.Service == "db" {
					return errors.Join(ctx.Err(), workerFailure)
				}
				return ctx.Err()
			},
		}).Serve(ctx)
	}()
	receive(t, started)
	receive(t, started)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, workerFailure) || !errors.Is(err, stopFailure) {
			t.Fatal("cleanup lost an independent worker or runtime failure", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown joined one worker before canceling its sibling")
	}
}

func TestReplacementKeepsIndependentFailureBesideRetryableCause(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrapped=%t", wrapped), func(t *testing.T) {
			control, key := groupFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cleanupFailure := errors.New("independent cleanup failure")
			started := make(chan string, 2)
			var attempts atomic.Int32
			done := make(chan error, 1)
			go func() {
				done <- (Runtime{Control: control, Publisher: control.assignment.Publisher, Private: key, PollInterval: time.Millisecond,
					Publish: func(ctx context.Context, _ controlv1.EnvironmentPublication, assignment controlv1.EnvironmentPublisherAssignment, _ func(bool)) error {
						attempts.Add(1)
						started <- assignment.Configuration.Target
						<-ctx.Done()
						joined := errors.Join(ctx.Err(), clientcontrol.ErrUnavailable, cleanupFailure)
						if wrapped {
							return fmt.Errorf("finish publication: %w", joined)
						}
						return joined
					},
				}).Serve(ctx)
			}()
			if got := receive(t, started); got != "db.internal:5432" {
				t.Fatal(got)
			}
			control.mu.Lock()
			control.assignment.Services = append([]controlv1.EnvironmentPublisherAssignment(nil), control.assignment.Services...)
			control.assignment.Services[0].Configuration.Target = "replacement.internal:5432"
			control.assignment.Environment.MutationRevision++
			control.assignment.Environment.ConfigurationHash = strings.Repeat("b", 64)
			control.mu.Unlock()
			select {
			case err := <-done:
				if !errors.Is(err, cleanupFailure) || !errors.Is(err, clientcontrol.ErrUnavailable) || attempts.Load() != 1 {
					t.Fatal("replacement discarded an independent cause", attempts.Load(), err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("independent cleanup failure was treated as a successful retry")
			}
		})
	}
}

type statusFailureControl struct {
	*groupControl
	phase string
	err error
	calls atomic.Int32
}

func (c *statusFailureControl) Assignments(ctx context.Context, access string) (controlv1.EnvironmentPublisherAssignments, error) {
	if c.phase == "assignments" && c.calls.Add(1) == 1 {
		return controlv1.EnvironmentPublisherAssignments{}, c.err
	}
	return c.groupControl.Assignments(ctx, access)
}

func (c *statusFailureControl) Acknowledge(ctx context.Context, access string, ack controlv1.EnvironmentPublisherAcknowledgement) error {
	if c.phase == "acknowledge" && c.calls.Add(1) == 1 {
		return c.err
	}
	return c.groupControl.Acknowledge(ctx, access, ack)
}

func TestToleratedControlStatusDoesNotHideIndependentCause(t *testing.T) {
	for _, phase := range []string{"assignments", "acknowledge"} {
		for _, wrapper := range []string{"direct", "wrapped", "canceled-sibling"} {
			t.Run(phase+"/"+wrapper, func(t *testing.T) {
				base, key := groupFixture(t)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				independent := errors.New("independent control cleanup failure")
				status := clientcontrol.ErrUnauthenticated
				if phase == "acknowledge" {
					status = clientcontrol.ErrStatusConflict
				}
				joined := errors.Join(status, independent)
				if wrapper == "wrapped" {
					joined = fmt.Errorf("control response: %w", joined)
				} else if wrapper == "canceled-sibling" {
					joined = errors.Join(context.Canceled, joined)
				}
				control := &statusFailureControl{groupControl: base, phase: phase, err: joined}
				done := make(chan error, 1)
				go func() {
					done <- (Runtime{Control: control, Publisher: base.assignment.Publisher, Private: key, PollInterval: time.Millisecond,
						Publish: func(ctx context.Context, _ controlv1.EnvironmentPublication, _ controlv1.EnvironmentPublisherAssignment, _ func(bool)) error {
							<-ctx.Done()
							return ctx.Err()
						},
					}).Serve(ctx)
				}()
				select {
				case err := <-done:
					if !errors.Is(err, independent) || !errors.Is(err, status) {
						t.Fatal("tolerated status discarded an independent cause", err)
					}
				case <-time.After(3 * time.Second):
					cancel()
					<-done
					t.Fatal("joined control failure was silently retried")
				}
			})
		}
	}
}
