package state

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationDeploymentBindingRestoredForeignKeyAndSiblingGrants(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "restored_deployment_binding")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"db": {Protocol: "postgres", Target: "production.internal:5432", Access: &ProjectServiceAccess{Team: true}},
	}}
	r = selectedProjectRequest(r, "production")
	productionProject, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	stagingRequest := r
	stagingRequest.Deployment, stagingRequest.ExpectedRevision = "staging", productionProject.Revision
	stagingRequest.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"db": {Protocol: "postgres", Target: "staging.internal:5432", Access: &ProjectServiceAccess{Team: true}},
	}}
	current, err := d.ApplyProjectConfiguration(ctx, stagingRequest)
	if err != nil {
		t.Fatal(err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
	production, err := d.GetDeployment(ctx, scope, "production")
	if err != nil {
		t.Fatal(err)
	}
	staging, err := d.GetDeployment(ctx, scope, "staging")
	if err != nil {
		t.Fatal(err)
	}
	productionID, stagingID := production.Services["db"].ID, staging.Services["db"].ID
	if productionID == "" || stagingID == "" || productionID == stagingID {
		t.Fatal("same logical service name did not produce two isolated bindings")
	}
	replicas := map[string]enrolledDeploymentReplica{}
	for _, name := range []string{"production", "staging"} {
		enrollment, err := testDeploymentPublisherEnrollment(d, ctx, r.TeamID, r.ProjectKey, name, r.ActorID, 1, time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		replica := enrollAppliedDeployment(t, d, r, enrollment, now)
		replicas[name] = replica
		want := productionID
		if name == "staging" {
			want = stagingID
		}
		if len(replica.assignments.Services) != 1 || replica.assignments.Services[0].Service != "db" ||
			replica.assignments.Services[0].ServiceID != want {
			t.Fatalf("%s publisher was assigned another deployment's service", name)
		}
	}
	// both records and both publishers are real. this mutation must fail on
	// their composite foreign key, not on a missing or fabricated identity.
	_, err = d.pool.Exec(ctx, `UPDATE control.deployment_publisher_service_grants
		SET deployment_id=$2 WHERE publisher_identity_id=$1`,
		replicas["production"].member.PublisherIdentityID, staging.ID)
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23503" {
		t.Fatalf("cross-deployment publisher rebinding error = %v, want 23503", err)
	}
	var visitorGrant, publisherGrant string
	if err := d.pool.QueryRow(ctx, `SELECT binding.visitor_grant_id,assignment.grant_id
		FROM control.applied_project_services binding
		JOIN control.deployment_publisher_service_grants assignment
		  ON assignment.deployment_id=binding.deployment_id AND assignment.service=binding.service
		WHERE binding.service_id=$1 AND assignment.publisher_identity_id=$2`,
		stagingID, replicas["staging"].member.PublisherIdentityID).Scan(&visitorGrant, &publisherGrant); err != nil ||
		visitorGrant == "" || publisherGrant == "" {
		t.Fatal("sibling fixture lacks real apply-issued visitor and enrolled publisher grants", err)
	}
	r.ExpectedRevision = current.Revision
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}}
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal("isolated production removal failed", err)
	}
	q := controlstatedb.New(d.pool)
	removed, err := q.ListDeploymentPublisherServices(ctx, production.ID)
	if err != nil || len(removed) != 0 {
		t.Fatal("removed production binding survived", err)
	}
	remaining, err := q.ListDeploymentPublisherServices(ctx, staging.ID)
	if err != nil || len(remaining) != 1 || remaining[0].ServiceID.String != stagingID ||
		remaining[0].VisitorGrantID.String != visitorGrant {
		t.Fatal("removal changed the sibling binding or visitor grant identity", err)
	}
	var active bool
	if err := d.pool.QueryRow(ctx, `SELECT service.enabled AND service.deleted_at IS NULL
		AND visitor.revoked_at IS NULL AND publisher.revoked_at IS NULL
		AND publisher.service_id=service.id AND publisher.publisher_identity_id=$4
		FROM control.services service
		JOIN control.visitor_grants visitor ON visitor.id=$2 AND visitor.service_id=service.id
		JOIN control.publisher_grants publisher ON publisher.id=$3
		WHERE service.id=$1`, stagingID, visitorGrant, publisherGrant,
		replicas["staging"].member.PublisherIdentityID).Scan(&active); err != nil || !active {
		t.Fatal("isolated removal revoked the sibling service or its actual grants", active, err)
	}
	assignments, err := d.GetDeploymentPublisherAssignments(ctx, replicas["staging"].lease.AccessToken, now)
	if err != nil || !reflect.DeepEqual(assignments, replicas["staging"].assignments) {
		t.Fatal("isolated removal changed the sibling publisher's current assignments", err)
	}
}
