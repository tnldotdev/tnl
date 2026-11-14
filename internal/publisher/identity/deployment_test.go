package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
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

func deploymentIdentityFixture(t *testing.T, kind string) (*Deployment, *deploymentFixtureControl) {
	t.Helper()
	native, control := privateScopeFixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fake := &deploymentFixtureControl{
		member: controlv1.DeploymentPublisherIdentity{TeamId: native.identity.teamID, ProjectKey: "example", DeploymentId: "dpl_example", DeploymentName: "production", PublisherIdentityId: native.identity.clientID, KeyId: native.identity.keyID},
		public: public,
		assignment: controlv1.DeploymentPublisherServiceAssignment{
			Service: "db", ServiceId: native.identity.serviceID, ServiceKind: "service", GrantId: native.identity.grantID, TrustRevision: 3,
			Configuration: controlv1.ProjectServiceConfiguration{Protocol: new(controlv1.Postgres), Target: "db.internal:5432"},
		},
	}
	if kind == "public_url" {
		id, err := opaqueid.New(opaqueid.PublicURLPrefix)
		if err != nil {
			t.Fatal(err)
		}
		fake.assignment = controlv1.DeploymentPublisherServiceAssignment{
			Service: "web", ServiceId: id, ServiceKind: "public_url", GrantId: native.identity.grantID, Hostname: new("web.example"),
			Configuration: controlv1.ProjectServiceConfiguration{
				Protocol: new(controlv1.ServiceProtocolHTTP), Target: "https://web.internal:3000",
				TargetTls: &controlv1.ProjectTargetTLS{Hostname: "web.internal", Digest: strings.Repeat("a", 64)},
				PublicUrl: &controlv1.ProjectServicePublicURL{Access: &controlv1.ProjectPublicAccess{Mode: new(controlv1.Restricted)}},
			},
		}
	}
	deployment, err := NewDeployment(NativeControl{PublicURLControl: control, Services: control}, fake, &lostEnrollmentResponse{}, "https://control.example", fake.member, private)
	if err != nil {
		t.Fatal(err)
	}
	return deployment, fake
}

func TestDeploymentPublicURLPollAndServiceUseExactAssignmentWithoutTrustRevision(t *testing.T) {
	deployment, fake := deploymentIdentityFixture(t, "public_url")
	encoded, err := json.Marshal(fake.assignment)
	if err != nil || bytes.Contains(encoded, []byte(`"trust_revision"`)) {
		t.Fatal("public URL fixture did not use the canonical omitted trust revision", err)
	}
	if err := json.Unmarshal(encoded, &fake.assignment); err != nil {
		t.Fatal(err)
	}
	assignments, err := deployment.Poll(t.Context())
	if err != nil {
		t.Fatal("public URL without a service trust revision was rejected", err)
	}
	original := assignments.Services[0]
	adapter, err := deployment.Service(original)
	if err != nil || adapter.identity.kind != "saved_public_url" || adapter.identity.publicURLID != original.ServiceId || adapter.identity.serviceID != "" || adapter.identity.grantID != original.GrantId || adapter.identity.clientID != fake.member.PublisherIdentityId || adapter.identity.keyID != fake.member.KeyId || adapter.identity.teamID != fake.member.TeamId || !bytes.Equal(adapter.private, deployment.private) {
		t.Fatal("public URL adapter changed the exact signing identity or grant", err)
	}
	for name, mutate := range map[string]func(*controlv1.DeploymentPublisherServiceAssignment){
		"grant":    func(a *controlv1.DeploymentPublisherServiceAssignment) { a.GrantId = "pgrant_bbbbbbbbbbbbbbbbbbbbbb" },
		"URL ID":   func(a *controlv1.DeploymentPublisherServiceAssignment) { a.ServiceId = "url_bbbbbbbbbbbbbbbbbbbbbb" },
		"hostname": func(a *controlv1.DeploymentPublisherServiceAssignment) { *a.Hostname = "other.example" },
		"service":  func(a *controlv1.DeploymentPublisherServiceAssignment) { a.Service = "other" },
		"target": func(a *controlv1.DeploymentPublisherServiceAssignment) {
			a.Configuration.Target = "https://other.internal:3000"
		},
		"target TLS": func(a *controlv1.DeploymentPublisherServiceAssignment) {
			a.Configuration.TargetTls.Hostname = "other.internal"
		},
		"policy": func(a *controlv1.DeploymentPublisherServiceAssignment) {
			a.Configuration.PublicUrl.Access.Mode = new(controlv1.Anonymous)
		},
		"trust field": func(a *controlv1.DeploymentPublisherServiceAssignment) { a.TrustRevision = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			var changed controlv1.DeploymentPublisherServiceAssignment
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if _, err := deployment.Service(changed); !errors.Is(err, ErrScope) {
				t.Fatal("caller mutation escaped the latest exact assignment", err)
			}
			if _, err := deployment.Service(original); err != nil {
				t.Fatal("rejected caller mutation changed the retained assignment", err)
			}
		})
	}
	fake.assignment.Configuration.Target = "https://replacement.internal:3000"
	fake.assignment.GrantId = "pgrant_cccccccccccccccccccccc"
	current, err := deployment.Poll(t.Context())
	if err != nil || fake.leases != 1 {
		t.Fatal("public URL assignment refresh did not reuse its valid signed lease", err)
	}
	if _, err := deployment.Service(original); !errors.Is(err, ErrScope) {
		t.Fatal("replaced public URL assignment retained adapter authority", err)
	}
	adapter, err = deployment.Service(current.Services[0])
	if err != nil || adapter.identity.grantID != fake.assignment.GrantId || adapter.identity.publicURLID != original.ServiceId {
		t.Fatal("refreshed public URL assignment changed its canonical URL or lost its exact grant", err)
	}
}

func TestDeploymentPollRequiresTrustRevisionOnlyForSavedServices(t *testing.T) {
	for _, kind := range []string{"service", "public_url"} {
		t.Run(kind, func(t *testing.T) {
			for _, revision := range []int64{-1, 0, 1, 3} {
				deployment, fake := deploymentIdentityFixture(t, kind)
				fake.assignment.TrustRevision = revision
				accepted := kind == "service" && revision > 0 || kind == "public_url" && revision == 0
				assignments, err := deployment.Poll(t.Context())
				if !accepted {
					if !errors.Is(err, ErrScope) || len(assignments.Services) != 0 {
						t.Fatal("invalid trust revision was accepted or exposed assignments", kind, revision, err)
					}
					if _, err := deployment.Service(fake.assignment); !errors.Is(err, ErrScope) {
						t.Fatal("rejected poll installed an assignment", kind, revision, err)
					}
					continue
				}
				if err != nil || len(assignments.Services) != 1 {
					t.Fatal("valid assignment was rejected", kind, revision, err)
				}
				if _, err := deployment.Service(assignments.Services[0]); err != nil {
					t.Fatal("valid poll could not adapt its exact assignment", kind, revision, err)
				}
			}
		})
	}
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
