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

type deploymentFixtureControl struct {
	DeploymentControl
	member       controlv1.DeploymentPublisherIdentity
	public       ed25519.PublicKey
	assignment   controlv1.DeploymentPublisherServiceAssignment
	leases, acks int
}

func (c *deploymentFixtureControl) AcquireDeploymentPublisherLease(_ context.Context, r controlv1.DeploymentPublisherLeaseRequest) (controlv1.DeploymentPublisherLease, error) {
	if _, err := publisherproof.Verify(r.Assertion, c.member.PublisherIdentityId, c.member.KeyId, c.member.DeploymentId, "https://control.example/v1/publisher/deployments/lease", c.public, time.Now()); err != nil {
		return controlv1.DeploymentPublisherLease{}, err
	}
	c.leases++
	return controlv1.DeploymentPublisherLease{AccessToken: "lease", ExpiresAt: time.Now().Add(2 * time.Minute)}, nil
}
func (c *deploymentFixtureControl) GetDeploymentPublisherAssignments(_ context.Context, token string) (controlv1.DeploymentPublisherAssignments, error) {
	if token != "lease" {
		return controlv1.DeploymentPublisherAssignments{}, ErrScope
	}
	return controlv1.DeploymentPublisherAssignments{Member: c.member, Revision: 1, ConfigurationHash: strings.Repeat("a", 64), Services: []controlv1.DeploymentPublisherServiceAssignment{c.assignment}}, nil
}
func (c *deploymentFixtureControl) AcknowledgeDeploymentPublisherConfiguration(_ context.Context, token string, b controlv1.DeploymentPublisherAcknowledgement) error {
	if token != "lease" || b.Revision != 1 {
		return ErrScope
	}
	c.acks++
	return nil
}

func TestDeploymentUsesReplicaKeyAndOnlyLatestExactAssignments(t *testing.T) {
	native, control := privateScopeFixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deploymentName := "production"
	fake := &deploymentFixtureControl{member: controlv1.DeploymentPublisherIdentity{TeamId: native.identity.teamID, ProjectKey: "example", DeploymentId: "dpl_example", DeploymentName: deploymentName, PublisherIdentityId: native.identity.clientID, KeyId: native.identity.keyID}, public: public}
	fake.assignment = controlv1.DeploymentPublisherServiceAssignment{Service: "db", ServiceId: native.identity.serviceID, ServiceKind: "service", GrantId: native.identity.grantID, TrustRevision: 3, Configuration: controlv1.ProjectServiceConfiguration{Target: "db.internal:5432"}}
	deployment, err := NewDeployment(NativeControl{PublicURLControl: control, Services: control}, fake, &lostEnrollmentResponse{}, "https://control.example", fake.member, private)
	if err != nil {
		t.Fatal(err)
	}
	assignments, err := deployment.Poll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := deployment.Service(assignments.Services[0])
	if err != nil || adapter.identity.grantID != native.identity.grantID {
		t.Fatal("exact native grant not adapted", err)
	}
	assignments.Services[0].Configuration.Target = "other.internal:5432"
	if _, err = deployment.Service(assignments.Services[0]); !errors.Is(err, ErrScope) {
		t.Fatal("caller mutation widened the assignment", err)
	}
	if err = deployment.Acknowledge(t.Context(), 2, assignments.ConfigurationHash, true); !errors.Is(err, ErrScope) || fake.acks != 0 {
		t.Fatal("unpolled revision acknowledged", err)
	}
	if err = deployment.Acknowledge(t.Context(), 1, assignments.ConfigurationHash, true); err != nil || fake.acks != 1 {
		t.Fatal(err)
	}
	if _, err = deployment.Poll(t.Context()); err != nil || fake.leases != 1 {
		t.Fatal("valid lease was not reused", err)
	}
	fake.member.DeploymentName = "other"
	if _, err = deployment.Poll(t.Context()); err != nil {
		t.Fatal("selector rename changed the publisher's authority", err)
	}
	fake.member.DeploymentId = "another-deployment"
	if _, err = deployment.Poll(t.Context()); !errors.Is(err, ErrScope) {
		t.Fatal("server response changed deployment scope", err)
	}
}
