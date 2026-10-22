package state

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationGroupIdentityVerificationPreservesLease(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "group_verification")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{"api": {PublisherGroup: "production", Target: "api.internal:3000"}}}
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, enrollment, now)
	const audience = "https://control.example/v1/publisher-groups/verify"
	proof, err := publisherproof.Sign(replica.member.PublisherIdentityID, replica.member.KeyID, replica.member.GroupID, audience, replica.private, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := d.VerifyPublisherGroupIdentity(t.Context(), replica.member.PublisherIdentityID, replica.member.GroupID, proof, audience, now)
	if err != nil || verified.Member != replica.member || !slices.Equal(verified.GroupNames, []string{"production"}) {
		t.Fatal("verification lost exact group membership", err)
	}
	if _, err := d.VerifyPublisherGroupIdentity(t.Context(), replica.member.PublisherIdentityID, replica.member.GroupID, proof, audience, now); !errors.Is(err, ErrPublisherGroup) {
		t.Fatal("verification replay accepted", err)
	}
	if _, err := d.GetPublisherGroupAssignments(t.Context(), replica.lease.AccessToken, now); err != nil {
		t.Fatal("identity preflight invalidated the running publisher lease", err)
	}
	if _, err := d.RenamePublisherGroup(t.Context(), r.TeamID, r.ProjectKey, "production", "live", r.ActorID, applied.Revision, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	proof, err = publisherproof.Sign(replica.member.PublisherIdentityID, replica.member.KeyID, replica.member.GroupID, audience, replica.private, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	verified, err = d.VerifyPublisherGroupIdentity(t.Context(), replica.member.PublisherIdentityID, replica.member.GroupID, proof, audience, now.Add(time.Second))
	if err != nil || verified.Member.GroupID != replica.member.GroupID || verified.Member.GroupName != "live" || !slices.Equal(verified.GroupNames, []string{"live", "production"}) {
		t.Fatal("verification did not return authoritative historical selectors", err)
	}
	if _, err := d.GetPublisherGroupAssignments(t.Context(), replica.lease.AccessToken, now.Add(time.Second)); err != nil {
		t.Fatal("renamed identity verification invalidated the current lease", err)
	}
}
