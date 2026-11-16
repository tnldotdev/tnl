package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationDeploymentServiceBindingsAndRemovalAreIsolated(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_service_bindings")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{
		Settings: &DeploymentSettings{},
		Services: map[string]ProjectServiceConfiguration{
			"db": {Name: "db", Protocol: "postgres", Target: "production.internal:5432"},
		},
	}
	stagingRequest := projectServiceSelection(r, "staging")
	first, err := d.ApplyProjectConfiguration(ctx, stagingRequest)
	if err != nil {
		t.Fatal(err)
	}
	r = projectServiceSelection(r, "production", "db")
	r.ExpectedRevision = first.Revision
	status, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	deployments := map[string]string{}
	for _, deployment := range first.Deployments {
		deployments[deployment.Name] = deployment.ID
	}
	for _, deployment := range status.Deployments {
		deployments[deployment.Name] = deployment.ID
	}
	stagingRequest = r
	stagingRequest.Deployment, stagingRequest.ExpectedRevision = "staging", status.Revision
	stagingRequest.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"db": {Name: "db", Protocol: "postgres", Target: "staging.internal:5432"},
	}}
	if _, err = d.ApplyProjectConfiguration(ctx, stagingRequest); err != nil {
		t.Fatal(err)
	}

	// one logical name can bind different saved services in two deployments.
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, r.TeamID); err != nil {
		t.Fatal(err)
	}
	production, err := q.ListDeploymentPublisherServices(ctx, deployments["production"])
	if err != nil || len(production) != 1 {
		t.Fatalf("production bindings: %v %v", production, err)
	}
	stagingBindings, err := q.ListDeploymentPublisherServices(ctx, deployments["staging"])
	if err != nil || len(stagingBindings) != 1 {
		t.Fatal("same service name in another deployment", stagingBindings, err)
	}
	staging := stagingBindings[0]
	for _, binding := range []controlstatedb.ControlAppliedProjectService{production[0], staging} {
		if err = d.reconcileAppliedVisitorGrant(ctx, tx, binding, r.ActorID, true, now); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	publishers := map[string]string{}
	for _, name := range []string{"production", "staging"} {
		enrollment, err := testDeploymentPublisherEnrollment(d, ctx, r.TeamID, r.ProjectKey, name, r.ActorID, 1, time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		member, err := d.RedeemDeploymentPublisherEnrollment(ctx, enrollment.Key, public, now)
		if err != nil {
			t.Fatal(err)
		}
		publishers[name] = member.PublisherIdentityID
		var service string
		if err = d.pool.QueryRow(ctx, `SELECT publisher.service_id FROM control.deployment_publisher_service_grants assignment
			JOIN control.publisher_grants publisher ON publisher.id=assignment.grant_id
			WHERE assignment.publisher_identity_id=$1 AND assignment.service='db'`, member.PublisherIdentityID).Scan(&service); err != nil {
			t.Fatal(err)
		}
		want := production[0].ServiceID.String
		if name == "staging" {
			want = staging.ServiceID.String
		}
		if service != want {
			t.Fatalf("%s enrolled for another deployment's service: %s", name, service)
		}
	}
	_, err = d.pool.Exec(ctx, `UPDATE control.deployment_publisher_service_grants SET deployment_id=$2 WHERE publisher_identity_id=$1`, publishers["production"], deployments["staging"])
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23503" {
		t.Fatal("assignment accepted a publisher from another deployment", err)
	}

	tx, err = d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	q = controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, r.TeamID); err != nil {
		t.Fatal(err)
	}
	if err = d.removeAppliedService(ctx, tx, q, production[0], now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	remaining, err := q.ListDeploymentPublisherServices(ctx, staging.DeploymentID.String)
	if err != nil || len(remaining) != 1 || remaining[0].ServiceID != staging.ServiceID || !remaining[0].VisitorGrantID.Valid {
		t.Fatalf("removal changed the sibling binding or visitor grant: %v %v", remaining, err)
	}
	removed, err := q.ListDeploymentPublisherServices(ctx, production[0].DeploymentID.String)
	if err != nil || len(removed) != 0 {
		t.Fatalf("production binding retained: %v %v", removed, err)
	}
	var active bool
	if err = tx.QueryRow(ctx, `SELECT service.enabled AND service.deleted_at IS NULL
		AND visitor.revoked_at IS NULL AND publisher.revoked_at IS NULL
		FROM control.services service
		JOIN control.visitor_grants visitor ON visitor.id=$2
		JOIN control.publisher_grants publisher ON publisher.service_id=service.id AND publisher.publisher_identity_id=$3
		WHERE service.id=$1`, staging.ServiceID, remaining[0].VisitorGrantID, publishers["staging"]).Scan(&active); err != nil || !active {
		t.Fatal("removal revoked the sibling service or its grants", active, err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
