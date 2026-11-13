package state

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationDeploymentIdentityVerificationPreservesLease(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_verification")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{"api": {Target: "api.internal:3000"}}}
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := testDeploymentPublisherEnrollment(d, t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedDeployment(t, d, r, enrollment, now)
	const audience = "https://control.example/v1/deployment-runtime/verify"
	proof, err := publisherproof.Sign(replica.member.PublisherIdentityID, replica.member.KeyID, replica.member.DeploymentID, audience, replica.private, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := d.VerifyDeploymentIdentity(t.Context(), replica.member.PublisherIdentityID, replica.member.DeploymentID, proof, audience, now)
	if err != nil || verified.Member != replica.member || !slices.Equal(verified.DeploymentNames, []string{"production"}) {
		t.Fatal("verification lost exact deployment membership", err)
	}
	if _, err := d.VerifyDeploymentIdentity(t.Context(), replica.member.PublisherIdentityID, replica.member.DeploymentID, proof, audience, now); !errors.Is(err, ErrDeploymentPublisher) {
		t.Fatal("verification replay accepted", err)
	}
	if _, err := d.GetDeploymentPublisherAssignments(t.Context(), replica.lease.AccessToken, now); err != nil {
		t.Fatal("identity preflight invalidated the running publisher lease", err)
	}
	if _, err := d.RenameDeployment(t.Context(), r.TeamID, r.ProjectKey, "production", "live", r.ActorID, applied.Revision, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	proof, err = publisherproof.Sign(replica.member.PublisherIdentityID, replica.member.KeyID, replica.member.DeploymentID, audience, replica.private, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	verified, err = d.VerifyDeploymentIdentity(t.Context(), replica.member.PublisherIdentityID, replica.member.DeploymentID, proof, audience, now.Add(time.Second))
	if err != nil || verified.Member.DeploymentID != replica.member.DeploymentID || verified.Member.DeploymentName != "live" || !slices.Equal(verified.DeploymentNames, []string{"live", "production"}) {
		t.Fatal("verification did not return authoritative historical selectors", err)
	}
	if _, err := d.GetDeploymentPublisherAssignments(t.Context(), replica.lease.AccessToken, now.Add(time.Second)); err != nil {
		t.Fatal("renamed identity verification invalidated the current lease", err)
	}
}
