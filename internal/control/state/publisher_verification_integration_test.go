package state

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationGroupIdentityVerificationPreservesLease(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "group_verification")
	r := retainedEnvironmentProject(t, d, now)
	applied, _ := retainedServiceEnvironment(t, d, r, "production", map[string]EnvironmentServicePublication{"api": {Protocol: "http", Target: "api.internal:3000"}})
	replica := enrollTestEnvironment(t, d, r, applied)
	const audience = "https://control.example/v1/environment-publishers/verify"
	proof, err := publisherproof.Sign(replica.member.PublisherIdentityID, replica.member.KeyID, replica.member.EnvironmentID, audience, replica.private, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := d.VerifyEnvironmentPublisher(t.Context(), replica.member.PublisherIdentityID, replica.member.EnvironmentID, proof, audience, now)
	if err != nil || verified != replica.member {
		t.Fatal("verification lost exact group membership", err)
	}
	if _, err := d.VerifyEnvironmentPublisher(t.Context(), replica.member.PublisherIdentityID, replica.member.EnvironmentID, proof, audience, now); !errors.Is(err, ErrEnvironmentPublisher) {
		t.Fatal("verification replay accepted", err)
	}
	if _, err := d.GetEnvironmentPublisherAssignments(t.Context(), replica.lease.AccessToken, now); err != nil {
		t.Fatal("identity preflight invalidated the running publisher lease", err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.environments SET name='live' WHERE id=$1`, applied.ID); err != nil {
		t.Fatal(err)
	}
	proof, err = publisherproof.Sign(replica.member.PublisherIdentityID, replica.member.KeyID, replica.member.EnvironmentID, audience, replica.private, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	verified, err = d.VerifyEnvironmentPublisher(t.Context(), replica.member.PublisherIdentityID, replica.member.EnvironmentID, proof, audience, now.Add(time.Second))
	if err != nil || verified != replica.member {
		t.Fatal("human selector change replaced immutable verification scope", err)
	}
	for _, name := range []string{"production", "live"} {
		proof, err := publisherproof.Sign(replica.member.PublisherIdentityID, replica.member.KeyID, name, audience, replica.private, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.VerifyEnvironmentPublisher(t.Context(), replica.member.PublisherIdentityID, name, proof, audience, now); !errors.Is(err, ErrEnvironmentPublisher) {
			t.Fatal("friendly historical name became proof authority", err)
		}
	}
	if _, err := d.GetEnvironmentPublisherAssignments(t.Context(), replica.lease.AccessToken, now.Add(time.Second)); err != nil {
		t.Fatal("renamed identity verification invalidated the current lease", err)
	}
}
