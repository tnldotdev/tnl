package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/publisherenrollment"
)

func TestIntegrationPublisherEnrollmentConfiguredCeilings(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	_, request := deploymentPublisherRequest(t, d, now)
	request.MaxMembers, request.Lifetime = 100000, 2160*time.Hour
	if _, err := d.CreateDeploymentPublisherEnrollment(t.Context(), request); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("default ceilings admitted oversized key", err)
	}
	limits := publisherenrollment.Limits{Members: 100000, Lifetime: 2160 * time.Hour, ProjectPublishers: 500}
	if err := d.ConfigurePublisherEnrollmentLimits(limits); err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.CreateDeploymentPublisherEnrollment(t.Context(), request)
	if err != nil || enrollment.MaxMembers != 100000 || !enrollment.ExpiresAt.Equal(request.Now.Add(request.Lifetime).Truncate(time.Microsecond)) {
		t.Fatal("configured capacity or lifetime lost", err)
	}
	for _, change := range []func(*CreateDeploymentPublisherEnrollmentRequest){
		func(r *CreateDeploymentPublisherEnrollmentRequest) { r.MaxMembers++ },
		func(r *CreateDeploymentPublisherEnrollmentRequest) { r.Lifetime += time.Second },
		func(r *CreateDeploymentPublisherEnrollmentRequest) { r.Lifetime += time.Nanosecond },
	} {
		other := request
		other.IdempotencyKey = "oversized"
		change(&other)
		if _, err := d.CreateDeploymentPublisherEnrollment(t.Context(), other); !errors.Is(err, ErrProjectConfigurationInvalid) {
			t.Fatal("request exceeded configured or whole-second bounds", err)
		}
	}
	if err := d.ConfigurePublisherEnrollmentLimits(publisherenrollment.Default()); err != nil {
		t.Fatal(err)
	}
	recovered, err := d.CreateDeploymentPublisherEnrollment(t.Context(), request)
	if err != nil || !reflect.DeepEqual(recovered, enrollment) {
		t.Fatal("lowering ceilings changed a committed key", err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.RedeemDeploymentPublisherEnrollment(t.Context(), enrollment.Key, public, now); err != nil {
		t.Fatal("lowering ceilings invalidated captured admission authority", err)
	}
	assertPublisherEnrollmentCounts(t, d, request, enrollment.ID, 1, 1)
}

func TestIntegrationPublisherEnrollmentConcurrentAccounting(t *testing.T) {
	for _, boundary := range []string{"key", "project"} {
		t.Run(boundary, func(t *testing.T) {
			d, now, _, _ := newPublishRunPrerequisites(t)
			_, request := deploymentPublisherRequest(t, d, now)
			limits := publisherenrollment.Default()
			limits.ProjectPublishers, request.MaxMembers = 3, 3
			if boundary == "project" {
				request.MaxMembers = 10
			}
			if err := d.ConfigurePublisherEnrollmentLimits(limits); err != nil {
				t.Fatal(err)
			}
			enrollment, err := d.CreateDeploymentPublisherEnrollment(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			type redemption struct {
				public ed25519.PublicKey
				member DeploymentPublisherIdentity
				err    error
			}
			results := make([]redemption, 10)
			start := make(chan struct{})
			var workers sync.WaitGroup
			for i := range results {
				public, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				results[i].public = public
				workers.Go(func() {
					<-start
					results[i].member, results[i].err = d.RedeemDeploymentPublisherEnrollment(t.Context(), enrollment.Key, public, now)
				})
			}
			close(start)
			workers.Wait()
			var admitted []redemption
			for _, r := range results {
				if r.err == nil {
					admitted = append(admitted, r)
				} else if !errors.Is(r.err, ErrDeploymentPublisher) {
					t.Fatal("concurrent redemption failed unexpectedly", r.err)
				}
			}
			if len(admitted) != 3 {
				t.Fatal("concurrent admissions exceeded or lost capacity", len(admitted))
			}
			assertPublisherEnrollmentCounts(t, d, request, enrollment.ID, 3, 3)
			staging := request
			staging.Selector, staging.Services, staging.IdempotencyKey = "staging", []string{"stage"}, "stage-key"
			sibling, err := d.CreateDeploymentPublisherEnrollment(t.Context(), staging)
			if err != nil {
				t.Fatal(err)
			}
			siblingPublic, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.RedeemDeploymentPublisherEnrollment(t.Context(), sibling.Key, siblingPublic, now); !errors.Is(err, ErrDeploymentPublisher) {
				t.Fatal("sibling deployment bypassed the project capacity", err)
			}
			assertPublisherEnrollmentCounts(t, d, request, sibling.ID, 0, 3)
			// recovering the same key does not consume another admission, even at capacity.
			recovered, err := d.RedeemDeploymentPublisherEnrollment(t.Context(), enrollment.Key, admitted[0].public, now)
			if err != nil || recovered != admitted[0].member {
				t.Fatal("committed redemption was not recoverable at capacity", err)
			}
			for range 2 {
				if err := d.RevokeDeploymentPublisher(t.Context(), request.DeploymentScope, request.Selector, admitted[0].member.PublisherIdentityID, now); err != nil {
					t.Fatal(err)
				}
			}
			assertPublisherEnrollmentCounts(t, d, request, enrollment.ID, 3, 2)
			if _, err := d.RedeemDeploymentPublisherEnrollment(t.Context(), enrollment.Key, admitted[0].public, now); !errors.Is(err, ErrDeploymentPublisher) {
				t.Fatal("retry restored a revoked identity", err)
			}
			public, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			_, err = d.RedeemDeploymentPublisherEnrollment(t.Context(), enrollment.Key, public, now)
			consumed, active := 3, 2
			if boundary == "project" {
				if err != nil {
					t.Fatal("revocation did not free project capacity", err)
				}
				consumed, active = 4, 3
			} else if !errors.Is(err, ErrDeploymentPublisher) {
				t.Fatal("revocation refunded lifetime key capacity", err)
			}
			assertPublisherEnrollmentCounts(t, d, request, enrollment.ID, consumed, active)
			// deployment deletion revokes every remaining member without refunding the key.
			deployment, err := d.GetDeployment(t.Context(), request.DeploymentScope, request.Selector)
			if err != nil {
				t.Fatal(err)
			}
			if err := d.DeleteDeployment(t.Context(), request.DeploymentScope, request.Selector, deployment.Revision, now); err != nil {
				t.Fatal(err)
			}
			assertPublisherEnrollmentCounts(t, d, request, enrollment.ID, consumed, 0)
		})
	}
}

func assertPublisherEnrollmentCounts(t *testing.T, d *Database, request CreateDeploymentPublisherEnrollmentRequest, enrollment string, consumed, active int) {
	t.Helper()
	var admissions, publishers, actualAdmissions, actualPublishers int
	err := d.pool.QueryRow(t.Context(), `SELECT enrollment.admitted_members,project.publisher_count,
		(SELECT count(*) FROM control.deployment_publisher_members WHERE enrollment_id=enrollment.id),
		(SELECT count(*) FROM control.deployment_publisher_members member
		JOIN control.deployments deployment ON deployment.id=member.deployment_id
		JOIN control.publisher_identities publisher ON publisher.id=member.publisher_identity_id
		WHERE deployment.team_id=project.team_id AND deployment.project_key=project.project_key AND publisher.revoked_at IS NULL)
		FROM control.deployment_publisher_enrollments enrollment,control.applied_projects project
		WHERE enrollment.id=$1 AND project.team_id=$2 AND project.project_key=$3`,
		enrollment, request.TeamID, request.ProjectKey).Scan(&admissions, &publishers, &actualAdmissions, &actualPublishers)
	if err != nil || admissions != consumed || publishers != active || admissions != actualAdmissions || publishers != actualPublishers {
		t.Fatalf("accounting: admissions=%d rows=%d want=%d; publishers=%d rows=%d want=%d: %v",
			admissions, actualAdmissions, consumed, publishers, actualPublishers, active, err)
	}
}
