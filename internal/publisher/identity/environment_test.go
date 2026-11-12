package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type environmentFixtureControl struct {
	EnvironmentControl
	publisher    controlv1.EnvironmentPublisher
	public       ed25519.PublicKey
	assignment   controlv1.EnvironmentPublisherAssignment
	assignments  []controlv1.EnvironmentPublisherAssignment
	publication  controlv1.EnvironmentPublication
	leases, acks int
}

func (c *environmentFixtureControl) AcquireEnvironmentPublisherLease(_ context.Context, r controlv1.EnvironmentPublisherProof) (controlv1.EnvironmentPublisherLease, error) {
	if r.PublisherIdentityId != c.publisher.PublisherIdentityId || r.EnvironmentId != c.publisher.EnvironmentId {
		return controlv1.EnvironmentPublisherLease{}, ErrScope
	}
	if _, err := publisherproof.Verify(r.Assertion, c.publisher.PublisherIdentityId, c.publisher.KeyId, c.publisher.EnvironmentId, "https://control.example/v1/environment-publishers/lease", c.public, time.Now()); err != nil {
		return controlv1.EnvironmentPublisherLease{}, err
	}
	c.leases++
	return controlv1.EnvironmentPublisherLease{AccessToken: "lease", ExpiresAt: time.Now().Add(2 * time.Minute)}, nil
}

func (c *environmentFixtureControl) GetEnvironmentPublisherAssignments(_ context.Context, token string) (controlv1.EnvironmentPublisherAssignments, error) {
	if token != "lease" {
		return controlv1.EnvironmentPublisherAssignments{}, ErrScope
	}
	services := c.assignments
	if services == nil {
		services = []controlv1.EnvironmentPublisherAssignment{c.assignment}
	}
	return controlv1.EnvironmentPublisherAssignments{Publisher: c.publisher, Environment: c.publication, Services: services}, nil
}

func (c *environmentFixtureControl) AcknowledgeEnvironmentPublisher(_ context.Context, token string, b controlv1.EnvironmentPublisherAcknowledgement) error {
	if token != "lease" || b.Environment != c.publication {
		return ErrScope
	}
	c.acks++
	return nil
}

func newEnvironmentFixture(t *testing.T) (*Environment, *environmentFixtureControl, *privateScopeControl) {
	t.Helper()
	native, control := privateScopeFixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.EnvironmentPrefix)
	if err != nil {
		t.Fatal(err)
	}
	fake := &environmentFixtureControl{
		publisher: controlv1.EnvironmentPublisher{TeamId: native.identity.teamID, ProjectKey: "example", EnvironmentId: id, PublisherIdentityId: native.identity.clientID, KeyId: native.identity.keyID}, public: public,
		assignment: controlv1.EnvironmentPublisherAssignment{
			Service: "database", ServiceId: native.identity.serviceID, GrantId: native.identity.grantID, TrustRevision: control.service.TrustRevision,
			Configuration: controlv1.EnvironmentServicePublication{Protocol: "postgres", Target: "original.internal:5432"},
		},
		publication: controlv1.EnvironmentPublication{EnvironmentId: id, MutationRevision: 1, ConfigurationHash: strings.Repeat("a", 64)},
	}
	owner, err := NewEnvironment(NativeControl{PublicURLControl: control, Services: control}, fake, &lostEnrollmentResponse{}, "https://control.example", fake.publisher, private)
	if err != nil {
		t.Fatal(err)
	}
	return owner, fake, control
}

func TestGroupEnvironmentPublicationStaysPinnedAcrossPolls(t *testing.T) {
	owner, fake, control := newEnvironmentFixture(t)
	assigned, err := owner.Poll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	old, err := owner.Service(assigned.Environment, assigned.Services[0])
	if err != nil {
		t.Fatal(err)
	}
	expected := assigned.Environment
	assigned.Environment.MutationRevision = 99
	if _, err := owner.Service(assigned.Environment, assigned.Services[0]); !errors.Is(err, ErrScope) {
		t.Fatal("caller changed an assignment's environment application", err)
	}
	fake.publication.MutationRevision, fake.publication.ConfigurationHash = 2, strings.Repeat("b", 64)
	fake.assignment.Configuration.Target = "replacement.internal:5432"
	next, err := owner.Poll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	current, err := owner.Service(next.Environment, next.Services[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Service(expected, next.Services[0]); !errors.Is(err, ErrScope) {
		t.Fatal("stale caller silently adopted the current application", err)
	}
	// a current service metadata lookup cannot upgrade the old worker's fence.
	declaration := ServiceDeclaration(control.service)
	if _, err := old.PrepareServiceRun(t.Context(), control.service.Id, "old-worker", "access", declaration); err != nil {
		t.Fatal(err)
	}
	if len(control.declarations) != 1 || control.declarations[0].Environment == nil || *control.declarations[0].Environment != expected {
		t.Fatal("old worker silently adopted the latest environment application")
	}
	if _, err := current.PrepareServiceRun(t.Context(), control.service.Id, "current-worker", "access", declaration); err != nil {
		t.Fatal(err)
	}
	if len(control.declarations) != 2 || !sameEnvironmentPublication(control.declarations[1].Environment, &fake.publication) {
		t.Fatal("new worker did not forward its assigned environment application")
	}
}

func TestGroupRejectsInvalidEnvironmentPublication(t *testing.T) {
	owner, fake, _ := newEnvironmentFixture(t)
	valid := fake.publication
	for _, mutate := range []func(*controlv1.EnvironmentPublication){
		func(value *controlv1.EnvironmentPublication) { *value = controlv1.EnvironmentPublication{} },
		func(value *controlv1.EnvironmentPublication) { value.EnvironmentId = "pgrp_not-an-environment" },
		func(value *controlv1.EnvironmentPublication) { value.EnvironmentId = valid.EnvironmentId + "other" },
		func(value *controlv1.EnvironmentPublication) { value.MutationRevision = 0 },
		func(value *controlv1.EnvironmentPublication) { value.ConfigurationHash = strings.Repeat("A", 64) },
	} {
		fake.publication = valid
		mutate(&fake.publication)
		if _, err := owner.Poll(t.Context()); !errors.Is(err, ErrScope) {
			t.Fatal("invalid or mismatched environment application accepted", err)
		}
	}
	fake.publication = valid
	if _, err := owner.Poll(t.Context()); err != nil {
		t.Fatal("valid environment assignment rejected after invalid responses", err)
	}
	fake.publication.ConfigurationHash = strings.Repeat("b", 64)
	if _, err := owner.Poll(t.Context()); !errors.Is(err, ErrScope) {
		t.Fatal("same revision changed its configuration hash", err)
	}
	fake.publication.MutationRevision = 2
	if _, err := owner.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	fake.publication = valid
	if _, err := owner.Poll(t.Context()); !errors.Is(err, ErrScope) {
		t.Fatal("older mutation revision accepted after a current poll", err)
	}
}

func TestGroupPollReplacesOptionalAssignmentFields(t *testing.T) {
	owner, fake, _ := newEnvironmentFixture(t)
	fake.assignment.Configuration.Target = ""
	fake.assignment.Configuration.TargetDiscovery = &controlv1.ProjectTargetDiscovery{Type: "rds", Region: "us-east-1", Instance: new("original")}
	if _, err := owner.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	fake.publication.MutationRevision, fake.publication.ConfigurationHash = 2, strings.Repeat("b", 64)
	fake.assignment.Configuration.Target = "replacement.internal:5432"
	fake.assignment.Configuration.TargetDiscovery = nil
	assigned, err := owner.Poll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if assigned.Services[0].Configuration.TargetDiscovery != nil {
		t.Fatal("static assignment retained old discovery")
	}
	if _, err := owner.Service(assigned.Environment, assigned.Services[0]); err != nil {
		t.Fatal("current assignment did not replace omitted fields in the remembered snapshot", err)
	}
	fake.publication = controlv1.EnvironmentPublication{}
	if _, err := owner.Poll(t.Context()); !errors.Is(err, ErrScope) {
		t.Fatal("missing required environment fence accepted", err)
	}
	if _, err := owner.Service(assigned.Environment, assigned.Services[0]); err != nil {
		t.Fatal("invalid response overwrote the last accepted snapshot", err)
	}
}

func TestGroupRejectsMixedEnvironmentPublications(t *testing.T) {
	// one envelope now owns the required fence for every service. mixed scopes
	// cannot be represented; mismatched publisher and envelope scopes still fail.
	for _, difference := range []string{"publisher-environment", "publisher-project", "duplicate-name", "duplicate-id", "invalid-second"} {
		t.Run(difference, func(t *testing.T) {
			owner, fake, _ := newEnvironmentFixture(t)
			second := fake.assignment
			second.Service = "second"
			id, err := opaqueid.New(opaqueid.ServicePrefix)
			if err != nil {
				t.Fatal(err)
			}
			second.ServiceId = id
			switch difference {
			case "publisher-environment":
				fake.publisher.EnvironmentId, err = opaqueid.New(opaqueid.EnvironmentPrefix)
				if err != nil {
					t.Fatal(err)
				}
			case "publisher-project":
				fake.publisher.ProjectKey = "another"
			case "duplicate-name":
				second.Service = fake.assignment.Service
			case "duplicate-id":
				second.ServiceId = fake.assignment.ServiceId
			case "invalid-second":
				second.TrustRevision = 0
			}
			fake.assignments = []controlv1.EnvironmentPublisherAssignment{fake.assignment, second}
			if _, err := owner.Poll(t.Context()); !errors.Is(err, ErrScope) {
				t.Fatal("mixed or invalid second environment assignment accepted", err)
			}
		})
	}
	for _, hash := range []string{strings.Repeat("A", 64), strings.Repeat("z", 64)} {
		owner, fake, _ := newEnvironmentFixture(t)
		fake.publication.ConfigurationHash = hash
		if _, err := owner.Poll(t.Context()); !errors.Is(err, ErrScope) {
			t.Fatal("malformed configuration hash accepted", err)
		}
	}
}

func TestGroupUsesReplicaKeyAndOnlyLatestExactAssignments(t *testing.T) {
	owner, fake, _ := newEnvironmentFixture(t)
	assignments, err := owner.Poll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := owner.Service(assignments.Environment, assignments.Services[0])
	if err != nil || adapter.identity.grantID != fake.assignment.GrantId || !adapter.private.Equal(owner.private) {
		t.Fatal("exact native grant and replica key not adapted", err)
	}
	assignments.Services[0].Configuration.Target = "other.internal:5432"
	if _, err = owner.Service(assignments.Environment, assignments.Services[0]); !errors.Is(err, ErrScope) {
		t.Fatal("caller mutation widened the assignment", err)
	}
	wrong := assignments.Environment
	wrong.MutationRevision++
	if err = owner.Acknowledge(t.Context(), wrong, true); !errors.Is(err, ErrScope) || fake.acks != 0 {
		t.Fatal("unpolled revision acknowledged", err)
	}
	if err = owner.Acknowledge(t.Context(), assignments.Environment, true); err != nil || fake.acks != 1 {
		t.Fatal(err)
	}
	if _, err = owner.Poll(t.Context()); err != nil || fake.leases != 1 {
		t.Fatal("valid lease was not reused", err)
	}
	fake.publisher.EnvironmentId, err = opaqueid.New(opaqueid.EnvironmentPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = owner.Poll(t.Context()); !errors.Is(err, ErrScope) {
		t.Fatal("server response changed environment scope", err)
	}
}

type blockedEnvironmentControl struct {
	EnvironmentControl
	phase string
}

func (c blockedEnvironmentControl) GetEnvironmentPublisherAssignments(ctx context.Context, access string) (controlv1.EnvironmentPublisherAssignments, error) {
	if c.phase == "poll" {
		<-ctx.Done()
		return controlv1.EnvironmentPublisherAssignments{}, ctx.Err()
	}
	return c.EnvironmentControl.GetEnvironmentPublisherAssignments(ctx, access)
}

func (c blockedEnvironmentControl) AcknowledgeEnvironmentPublisher(ctx context.Context, _ string, _ controlv1.EnvironmentPublisherAcknowledgement) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestEnvironmentPublisherIdentityOperationsHaveDeadlines(t *testing.T) {
	for _, phase := range []string{"poll", "acknowledge"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				owner, fake, _ := newEnvironmentFixture(t)
				owner.environments = blockedEnvironmentControl{EnvironmentControl: fake, phase: phase}
				started := time.Now()
				var err error
				if phase == "poll" {
					_, err = owner.Poll(t.Context())
				} else {
					assigned, pollErr := owner.Poll(t.Context())
					if pollErr != nil {
						t.Fatal(pollErr)
					}
					err = owner.Acknowledge(t.Context(), assigned.Environment, true)
				}
				if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) != 10*time.Second {
					t.Fatal("identity operation escaped its deadline", time.Since(started), err)
				}
			})
		})
	}
}

func TestEnvironmentPublisherIdentityFormattingDoesNotExposeKey(t *testing.T) {
	owner, _, _ := newEnvironmentFixture(t)
	for _, rendered := range []string{fmt.Sprint(owner), fmt.Sprintf("%+v", owner), fmt.Sprintf("%#v", owner)} {
		if rendered != "environment publisher identity" {
			t.Fatal("identity formatting exposed private state")
		}
	}
}
