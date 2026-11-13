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
		PublisherGroups: map[string]ProjectPublisherGroup{"production": {}, "staging": {}},
		Services: map[string]ProjectServiceConfiguration{
			"db": {PublisherGroup: "production", Name: "db", Protocol: "postgres", Target: "production.internal:5432"},
		},
	}
	stagingRequest := deploymentProjectRequest(r, "staging")
	first, err := d.ApplyProjectConfiguration(ctx, stagingRequest)
	if err != nil {
		t.Fatal(err)
	}
	r = deploymentProjectRequest(r, "production")
	r.ExpectedRevision = first.Revision
	status, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	groups := map[string]string{}
	for _, group := range first.Groups {
		groups[group.Name] = group.ID
	}
	for _, group := range status.Groups {
		groups[group.Name] = group.ID
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
	production, err := q.ListPublisherGroupServices(ctx, groups["production"])
	if err != nil || len(production) != 1 {
		t.Fatalf("production bindings: %v %v", production, err)
	}
	staging := controlstatedb.ControlAppliedProjectService{
		TeamID: r.TeamID, ProjectKey: r.ProjectKey, Service: "db",
		GroupID: text(groups["staging"]), DesiredRevision: status.Revision,
	}
	id, err := d.createAppliedService(ctx, tx, q, r, "db", staging.GroupID.String, ProjectServiceConfiguration{
		PublisherGroup: "staging", Name: "db", Protocol: "postgres", Target: "staging.internal:5432",
	})
	if err != nil {
		t.Fatal(err)
	}
	staging.ServiceID = text(id)
	if _, err = tx.Exec(ctx, `INSERT INTO control.applied_project_services
		(team_id,project_key,service,group_id,service_id,desired_revision) VALUES($1,$2,$3,$4,$5,$6)`,
		staging.TeamID, staging.ProjectKey, staging.Service, staging.GroupID, staging.ServiceID, staging.DesiredRevision); err != nil {
		t.Fatal("same service name in another deployment", err)
	}
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
		enrollment, err := d.IssuePublisherGroupEnrollment(ctx, r.TeamID, r.ProjectKey, name, r.ActorID, 1, time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		member, err := d.RedeemPublisherGroupEnrollment(ctx, enrollment.Key, public, now)
		if err != nil {
			t.Fatal(err)
		}
		publishers[name] = member.PublisherIdentityID
		var service string
		if err = d.pool.QueryRow(ctx, `SELECT publisher.service_id FROM control.publisher_group_service_grants assignment
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
	_, err = d.pool.Exec(ctx, `UPDATE control.publisher_group_service_grants SET group_id=$2 WHERE publisher_identity_id=$1`, publishers["production"], groups["staging"])
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
	remaining, err := q.ListPublisherGroupServices(ctx, staging.GroupID.String)
	if err != nil || len(remaining) != 1 || remaining[0].ServiceID != staging.ServiceID || !remaining[0].VisitorGrantID.Valid {
		t.Fatalf("removal changed the sibling binding or visitor grant: %v %v", remaining, err)
	}
	removed, err := q.ListPublisherGroupServices(ctx, production[0].GroupID.String)
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
