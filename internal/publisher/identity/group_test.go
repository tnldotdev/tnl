package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type groupFixtureControl struct {
	GroupControl
	member       controlv1.PublisherGroupMember
	public       ed25519.PublicKey
	assignment   controlv1.PublisherGroupServiceAssignment
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
	return controlv1.PublisherGroupAssignments{Member: c.member, Revision: 1, ConfigurationHash: strings.Repeat("a", 64), Services: []controlv1.PublisherGroupServiceAssignment{c.assignment}}, nil
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
	group, err := NewGroup(control, fake, &lostEnrollmentResponse{}, "https://control.example", fake.member, private)
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
