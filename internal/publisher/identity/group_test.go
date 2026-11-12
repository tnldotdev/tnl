package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type groupFixtureControl struct {
	GroupControl
	member       controlv1.PublisherGroupMember
	public       ed25519.PublicKey
	assignment   controlv1.PublisherGroupServiceAssignment
	assignments  []controlv1.PublisherGroupServiceAssignment
	revision     int64
	hash         string
	leases, acks int
}

func (c *groupFixtureControl) AcquirePublisherGroupLease(_ context.Context, r controlv1.PublisherGroupLeaseRequest) (controlv1.PublisherGroupLease, error) {
	if _, err := publisherproof.Verify(r.Assertion, c.member.PublisherIdentityId, c.member.KeyId, c.member.GroupId, "https://control.example/v1/publisher-groups/lease", c.public, time.Now()); err != nil {
		return controlv1.PublisherGroupLease{}, err
	}
	c.leases++
	return controlv1.PublisherGroupLease{AccessToken: "lease", ExpiresAt: time.Now().Add(2 * time.Minute)}, nil
}
func (c *groupFixtureControl) GetPublisherGroupAssignments(_ context.Context, token string) (controlv1.PublisherGroupAssignments, error) {
	if token != "lease" {
		return controlv1.PublisherGroupAssignments{}, ErrScope
	}
	revision, hash := c.revision, c.hash
	if revision == 0 {
		revision = 1
	}
	if hash == "" {
		hash = strings.Repeat("a", 64)
	}
	services := c.assignments
	if services == nil {
		services = []controlv1.PublisherGroupServiceAssignment{c.assignment}
	}
	return controlv1.PublisherGroupAssignments{Member: c.member, Revision: revision, ConfigurationHash: hash, Services: services}, nil
}

func newEnvironmentGroupFixture(t *testing.T) (*Group, *groupFixtureControl, *privateScopeControl) {
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
	name := "environment"
	fake := &groupFixtureControl{
		member: controlv1.PublisherGroupMember{TeamId: native.identity.teamID, ProjectKey: "example", GroupId: "pgrp_example", GroupName: name, PublisherIdentityId: native.identity.clientID, KeyId: native.identity.keyID}, public: public,
		assignment: controlv1.PublisherGroupServiceAssignment{
			Service: "database", ServiceId: native.identity.serviceID, ServiceKind: "service", GrantId: native.identity.grantID, TrustRevision: control.service.TrustRevision,
			Configuration: controlv1.ProjectServiceConfiguration{PublisherGroup: &name, Target: "original.internal:5432"},
			Environment:   &controlv1.EnvironmentPublication{EnvironmentId: id, MutationRevision: 1, ConfigurationHash: strings.Repeat("a", 64)},
		},
	}
	group, err := NewGroup(NativeControl{PublicURLControl: control, Services: control}, fake, &lostEnrollmentResponse{}, "https://control.example", fake.member, private)
	if err != nil {
		t.Fatal(err)
	}
	return group, fake, control
}

func TestGroupEnvironmentPublicationStaysPinnedAcrossPolls(t *testing.T) {
	group, fake, control := newEnvironmentGroupFixture(t)
	assigned, err := group.Poll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	old, err := group.Service(assigned.Services[0])
	if err != nil {
		t.Fatal(err)
	}
	expected := *assigned.Services[0].Environment
	assigned.Services[0].Environment.MutationRevision = 99
	if _, err := group.Service(assigned.Services[0]); !errors.Is(err, ErrScope) {
		t.Fatal("caller changed an assignment's environment application", err)
	}
	fake.revision, fake.hash = 2, strings.Repeat("b", 64)
	fake.assignment.Configuration.Target = "replacement.internal:5432"
	fake.assignment.Environment = &controlv1.EnvironmentPublication{EnvironmentId: expected.EnvironmentId, MutationRevision: 2, ConfigurationHash: fake.hash}
	next, err := group.Poll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	current, err := group.Service(next.Services[0])
	if err != nil {
		t.Fatal(err)
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
	if len(control.declarations) != 2 || !sameEnvironmentPublication(control.declarations[1].Environment, fake.assignment.Environment) {
		t.Fatal("new worker did not forward its assigned environment application")
	}
}

func TestGroupRejectsInvalidEnvironmentPublication(t *testing.T) {
	group, fake, _ := newEnvironmentGroupFixture(t)
	valid := *fake.assignment.Environment
	for _, mutate := range []func(*controlv1.EnvironmentPublication){
		func(value *controlv1.EnvironmentPublication) { value.EnvironmentId = "pgrp_not-an-environment" },
		func(value *controlv1.EnvironmentPublication) { value.MutationRevision = 0 },
		func(value *controlv1.EnvironmentPublication) { value.MutationRevision++ },
		func(value *controlv1.EnvironmentPublication) { value.ConfigurationHash = strings.Repeat("b", 64) },
		func(value *controlv1.EnvironmentPublication) { value.ConfigurationHash = strings.Repeat("A", 64) },
	} {
		copy := valid
		mutate(&copy)
		fake.assignment.Environment = &copy
		if _, err := group.Poll(t.Context()); !errors.Is(err, ErrScope) {
			t.Fatal("invalid or mismatched environment application accepted", err)
		}
	}
	fake.assignment.Environment = &valid
	if _, err := group.Poll(t.Context()); err != nil {
		t.Fatal("valid environment assignment rejected after invalid responses", err)
	}
}

func TestGroupPollReplacesOptionalAssignmentFields(t *testing.T) {
	group, fake, _ := newEnvironmentGroupFixture(t)
	fake.assignment.Configuration.Target = ""
	fake.assignment.Configuration.TargetDiscovery = &controlv1.ProjectTargetDiscovery{Type: "rds", Region: "us-east-1", Instance: new("original")}
	if _, err := group.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	fake.revision, fake.hash = 2, strings.Repeat("b", 64)
	fake.assignment.Environment = &controlv1.EnvironmentPublication{EnvironmentId: fake.assignment.Environment.EnvironmentId, MutationRevision: 2, ConfigurationHash: fake.hash}
	fake.assignment.Configuration.Target = "replacement.internal:5432"
	fake.assignment.Configuration.TargetDiscovery = nil
	assigned, err := group.Poll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if assigned.Services[0].Configuration.TargetDiscovery != nil {
		t.Fatal("static assignment retained old discovery")
	}
	if _, err := group.Service(assigned.Services[0]); err != nil {
		t.Fatal("current assignment did not replace omitted fields in the remembered snapshot", err)
	}
	fake.revision, fake.hash, fake.assignment.Environment = 3, strings.Repeat("c", 64), nil
	assigned, err = group.Poll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	native, err := group.Service(assigned.Services[0])
	if err != nil || native.environmentPublication != nil {
		t.Fatal("omitted environment fence retained the old snapshot", err)
	}
}

func TestGroupRejectsMixedEnvironmentPublications(t *testing.T) {
	for _, difference := range []string{"missing", "different-environment", "invalid-second"} {
		t.Run(difference, func(t *testing.T) {
			group, fake, _ := newEnvironmentGroupFixture(t)
			second := fake.assignment
			second.Service = "second"
			second.Environment = cloneEnvironmentPublication(second.Environment)
			switch difference {
			case "missing":
				second.Environment = nil
			case "different-environment":
				id, err := opaqueid.New(opaqueid.EnvironmentPrefix)
				if err != nil {
					t.Fatal(err)
				}
				second.Environment.EnvironmentId = id
			case "invalid-second":
				second.Environment.MutationRevision = 0
			}
			fake.assignments = []controlv1.PublisherGroupServiceAssignment{fake.assignment, second}
			if _, err := group.Poll(t.Context()); !errors.Is(err, ErrScope) {
				t.Fatal("mixed or invalid second environment assignment accepted", err)
			}
		})
	}
	for _, hash := range []string{strings.Repeat("A", 64), strings.Repeat("z", 64)} {
		group, fake, _ := newEnvironmentGroupFixture(t)
		fake.hash, fake.assignment.Environment.ConfigurationHash = hash, hash
		if _, err := group.Poll(t.Context()); !errors.Is(err, ErrScope) {
			t.Fatal("matching malformed top-level and nested hashes accepted", err)
		}
	}
}
func (c *groupFixtureControl) AcknowledgePublisherGroupConfiguration(_ context.Context, token string, b controlv1.PublisherGroupAcknowledgement) error {
	if token != "lease" || b.Revision != 1 {
		return ErrScope
	}
	c.acks++
	return nil
}

func TestGroupUsesReplicaKeyAndOnlyLatestExactAssignments(t *testing.T) {
	native, control := privateScopeFixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	groupName := "production"
	fake := &groupFixtureControl{member: controlv1.PublisherGroupMember{TeamId: native.identity.teamID, ProjectKey: "example", GroupId: "pgrp_example", GroupName: groupName, PublisherIdentityId: native.identity.clientID, KeyId: native.identity.keyID}, public: public}
	fake.assignment = controlv1.PublisherGroupServiceAssignment{Service: "db", ServiceId: native.identity.serviceID, ServiceKind: "service", GrantId: native.identity.grantID, TrustRevision: 3, Configuration: controlv1.ProjectServiceConfiguration{PublisherGroup: &groupName, Target: "db.internal:5432"}}
	group, err := NewGroup(NativeControl{PublicURLControl: control, Services: control}, fake, &lostEnrollmentResponse{}, "https://control.example", fake.member, private)
	if err != nil {
		t.Fatal(err)
	}
	assignments, err := group.Poll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := group.Service(assignments.Services[0])
	if err != nil || adapter.identity.grantID != native.identity.grantID {
		t.Fatal("exact native grant not adapted", err)
	}
	assignments.Services[0].Configuration.Target = "other.internal:5432"
	if _, err = group.Service(assignments.Services[0]); !errors.Is(err, ErrScope) {
		t.Fatal("caller mutation widened the assignment", err)
	}
	if err = group.Acknowledge(t.Context(), 2, assignments.ConfigurationHash, true); !errors.Is(err, ErrScope) || fake.acks != 0 {
		t.Fatal("unpolled revision acknowledged", err)
	}
	if err = group.Acknowledge(t.Context(), 1, assignments.ConfigurationHash, true); err != nil || fake.acks != 1 {
		t.Fatal(err)
	}
	if _, err = group.Poll(t.Context()); err != nil || fake.leases != 1 {
		t.Fatal("valid lease was not reused", err)
	}
	fake.member.GroupName = "other"
	if _, err = group.Poll(t.Context()); !errors.Is(err, ErrScope) {
		t.Fatal("server response changed group scope", err)
	}
}
