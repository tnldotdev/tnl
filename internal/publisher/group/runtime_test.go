package group

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	assignment controlv1.PublisherGroupAssignments
	expires    time.Time
	fail       bool
	acks       chan controlv1.PublisherGroupAcknowledgement
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
	return controlv1.PublisherRuntimeResponse{Epoch: epoch, LeaseExpiresAt: &c.expires, GroupLease: &controlv1.PublisherGroupLease{AccessToken: "group-lease", ExpiresAt: c.expires}}, nil
}
func (c *groupControl) Assignments(context.Context, string) (controlv1.PublisherGroupAssignments, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return controlv1.PublisherGroupAssignments{}, clientcontrol.ErrUnavailable
	}
	return c.assignment, nil
}
func (c *groupControl) Acknowledge(_ context.Context, _ string, ack controlv1.PublisherGroupAcknowledgement) error {
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
	group := "cloud"
	return &groupControl{expires: time.Now().Add(time.Second), acks: make(chan controlv1.PublisherGroupAcknowledgement, 100), assignment: controlv1.PublisherGroupAssignments{
		Member: controlv1.PublisherGroupMember{GroupId: "group-one", GroupName: group, ProjectKey: "project-one", PublisherIdentityId: "publisher-one", KeyId: "key-one", TeamId: "team-one"}, Revision: 1, ConfigurationHash: strings.Repeat("a", 64),
		Services: []controlv1.PublisherGroupServiceAssignment{{Service: "db", ServiceId: "private-one", GrantId: "exact-grant", ServiceKind: "service", Configuration: controlv1.ProjectServiceConfiguration{PublisherGroup: &group, Target: "db.internal:5432"}}},
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
		done <- (Runtime{Control: control, Member: control.assignment.Member, Private: key, PollInterval: time.Millisecond,
			Publish: func(ctx context.Context, service controlv1.PublisherGroupServiceAssignment, health func(bool)) error {
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
	control.assignment.Services = append([]controlv1.PublisherGroupServiceAssignment(nil), control.assignment.Services...)
	control.assignment.Services[0].Configuration.Target = "replacement.internal:5432"
	control.assignment.Revision = 2
	control.assignment.ConfigurationHash = strings.Repeat("b", 64)
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
	member := control.assignment.Member
	report := &controlv1.PublisherDeploymentReport{DeploymentId: "aws-example", Provider: "aws", ReplicaKey: "replica-1", Instance: "instance-1", Image: "ghcr.io/tnldotdev/tnl@sha256:" + strings.Repeat("a", 64), SoftwareVersion: "devel", TemplateVersion: "2", TemplateSha256: strings.Repeat("b", 64)}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	identities := make(chan observability.Identity, 1)
	done := make(chan error, 1)
	go func() {
		done <- (Runtime{Control: control, Member: member, Private: key, Deployment: report, PollInterval: time.Millisecond, Publish: func(ctx context.Context, a controlv1.PublisherGroupServiceAssignment, health func(bool)) error {
			identities <- observability.IdentityFromContext(ctx)
			health(true)
			<-ctx.Done()
			return ctx.Err()
		}}).Serve(ctx)
	}()
	select {
	case id := <-identities:
		if id.TeamID != member.TeamId || id.PublisherGroupID != member.GroupId || id.PublisherIdentityID != member.PublisherIdentityId || id.DeploymentID != report.DeploymentId || id.ReplicaKey != report.ReplicaKey || id.ServiceID != "private-one" || id.PublicURLID != "" {
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
		done <- (Runtime{Control: control, Member: control.assignment.Member, Private: key, PollInterval: time.Millisecond,
			Publish: func(ctx context.Context, _ controlv1.PublisherGroupServiceAssignment, health func(bool)) error {
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
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSelectorRenameDoesNotRestartPublication(t *testing.T) {
	control, key := groupFixture(t)
	member := control.assignment.Member
	events := make(chan string, 4)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- (Runtime{Control: control, Member: member, Private: key, PollInterval: time.Millisecond, Publish: func(ctx context.Context, _ controlv1.PublisherGroupServiceAssignment, health func(bool)) error {
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
	control.assignment.Services = append([]controlv1.PublisherGroupServiceAssignment(nil), control.assignment.Services...)
	control.assignment.Member.GroupName = "renamed"
	control.assignment.Services[0].Configuration.PublisherGroup = new("renamed")
	control.assignment.Revision++
	control.assignment.ConfigurationHash = strings.Repeat("b", 64)
	control.mu.Unlock()
	for {
		select {
		case ack := <-control.acks:
			if ack.Revision == 2 && ack.Healthy {
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
	member := control.assignment.Member
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var attempts atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- (Runtime{Control: control, Member: member, Private: key, PollInterval: time.Millisecond, Publish: func(ctx context.Context, a controlv1.PublisherGroupServiceAssignment, health func(bool)) error {
			if attempts.Add(1) == 1 {
				return clientcontrol.ErrUnauthenticated
			}
			if a.GrantId == "exact-grant" {
				control.mu.Lock()
				control.assignment.Services = append([]controlv1.PublisherGroupServiceAssignment(nil), control.assignment.Services...)
				control.assignment.Services[0].GrantId = "replacement-grant"
				control.assignment.Revision = 2
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
			if ack.Revision == 2 && ack.Healthy {
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
