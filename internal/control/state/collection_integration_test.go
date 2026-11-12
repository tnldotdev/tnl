package state

import (
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func createTestCollection(t *testing.T, d *Database, r environmentPublisherTestProject, name string, revision int64) (Collection, CreateCollectionRequest) {
	t.Helper()
	request := CreateCollectionRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, Name: name, DefaultDefinitionRevision: revision, Now: r.Now}
	collection, err := d.CreateCollection(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	return collection, request
}

func collectionEnvironmentRequest(r environmentPublisherTestProject, c Collection, name, address string) CreateEnvironmentRequest {
	return CreateEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, SourceFingerprint: r.SourceFingerprint, Name: name, IdempotencyKey: "collection/" + name, CollectionID: c.ID, ExpectedCollectionRevision: c.MutationRevision, Targets: EnvironmentTargets{"api": {Address: address}}, Now: r.Now}
}

func TestIntegrationCollectionDefaultsOnlySelectNewEnvironments(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	r := retainedEnvironmentProject(t, d, now)
	d1 := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	c, creation := createTestCollection(t, d, r, "Customer previews", d1.Revision)
	if !opaqueid.Valid(c.ID, opaqueid.CollectionPrefix) || c.MutationRevision != 1 || c.DefaultDefinitionRevision != d1.Revision {
		t.Fatal("collection did not receive its own identity and revision", c)
	}
	request := collectionEnvironmentRequest(r, c, "existing", "existing.internal:3000")
	existing, err := d.CreateEnvironment(t.Context(), request)
	if err != nil || existing.CollectionID != c.ID || existing.ID == c.ID || existing.AppliedDefinitionRevision != d1.Revision {
		t.Fatal("collection default was not pinned at creation", existing, err)
	}
	member := enrollTestEnvironment(t, d, r, existing)
	assignment := member.assignments.Services[0]
	if member.member.EnvironmentID == c.ID || assignment.ServiceID == c.ID || member.member.PublisherIdentityID == c.ID {
		t.Fatal("collection identity was reused for a publisher or service")
	}
	access := environmentAssignmentAccess(t, d, member, assignment, now)
	prepared, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "collection-default-run", now, ServiceMetadata{Protocol: "http", PublisherPool: true, TrustRevision: assignment.TrustRevision}, &member.assignments.Environment)
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(d.pool)
	beforeRun, err := q.LockServiceRun(t.Context(), controlstatedb.LockServiceRunParams{ID: run.RunID, ServiceID: run.ServiceID})
	if err != nil {
		t.Fatal(err)
	}
	visitor, err := d.CreateServiceGrant(t.Context(), assignment.ServiceID, r.ActorID, "revoked-collection-visitor", "identity", r.ActorID, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeServiceGrant(t.Context(), assignment.ServiceID, r.ActorID, visitor.ID, now); err != nil {
		t.Fatal(err)
	}
	before, err := d.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, existing.ID, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	d2 := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "postgres"}})
	update := UpdateCollectionDefaultRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, CollectionID: c.ID, ExpectedRevision: c.MutationRevision, DefinitionRevision: d2.Revision, Now: now}
	updated, err := d.UpdateCollectionDefault(t.Context(), update)
	if err != nil || updated.ID != c.ID || updated.MutationRevision != 2 || updated.DefaultDefinitionRevision != d2.Revision {
		t.Fatal("default update did not advance only the collection revision", updated, err)
	}
	if _, err := d.UpdateCollectionDefault(t.Context(), update); !errors.Is(err, ErrCollectionStale) {
		t.Fatal("default update ignored its optimistic precondition", err)
	}
	assertExisting := func() {
		t.Helper()
		after, err := d.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, existing.ID, r.ActorID)
		if err != nil || len(after.Members) != 1 {
			t.Fatal(after, err)
		}
		before.Members[0].SnapshotAt = after.Members[0].SnapshotAt
		if !reflect.DeepEqual(after, before) {
			t.Fatal("default update changed installed revision, approvals, service IDs or publisher state", after, before)
		}
		afterRun, err := q.LockServiceRun(t.Context(), controlstatedb.LockServiceRunParams{ID: run.RunID, ServiceID: run.ServiceID})
		if err != nil || !reflect.DeepEqual(afterRun, beforeRun) {
			t.Fatal("default update changed an installed service run", afterRun, err)
		}
		assignments, err := d.GetEnvironmentPublisherAssignments(t.Context(), member.lease.AccessToken, now)
		if err != nil || !reflect.DeepEqual(assignments, member.assignments) {
			t.Fatal("default update reconciled installed publisher assignments or grants", assignments, err)
		}
		grants, _, err := d.ListServiceGrants(t.Context(), assignment.ServiceID, r.ActorID, "")
		if err != nil || len(grants) != 1 || grants[0].ID != visitor.ID || grants[0].RevokedAt == nil {
			t.Fatal("default update restored revoked visitor authority", grants, err)
		}
	}
	assertExisting()
	replay, err := d.CreateEnvironment(t.Context(), request)
	if err != nil || replay.ID != existing.ID || replay.AppliedDefinitionRevision != d1.Revision {
		t.Fatal("default-selected retry followed the current default or rejected its old precondition", replay, err)
	}
	changedPrecondition := request
	changedPrecondition.ExpectedCollectionRevision = updated.MutationRevision
	if _, err := d.CreateEnvironment(t.Context(), changedPrecondition); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("used creation key accepted a changed collection precondition", err)
	}
	collectionReplay, err := d.CreateCollection(t.Context(), creation)
	if err != nil || collectionReplay != updated {
		t.Fatal("collection creation replay used the current default as creation intent", collectionReplay, err)
	}
	changed := creation
	changed.DefaultDefinitionRevision = d2.Revision
	if _, err := d.CreateCollection(t.Context(), changed); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("collection name was rebound to another creation request", err)
	}
	changedRequest := request
	changedRequest.DefinitionRevision = d1.Revision
	if _, err := d.CreateEnvironment(t.Context(), changedRequest); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("retry silently changed from default selection to explicit selection", err)
	}
	stale := collectionEnvironmentRequest(r, c, "stale", "stale.internal:5432")
	if _, err := d.CreateEnvironment(t.Context(), stale); !errors.Is(err, ErrCollectionStale) {
		t.Fatal("new member used a changed collection without its current precondition", err)
	}
	stale.DefinitionRevision = d1.Revision
	if _, err := d.CreateEnvironment(t.Context(), stale); !errors.Is(err, ErrCollectionStale) {
		t.Fatal("explicit definition bypassed the collection membership precondition", err)
	}
	next, err := d.CreateEnvironment(t.Context(), collectionEnvironmentRequest(r, updated, "new", "new.internal:5432"))
	if err != nil || next.AppliedDefinitionRevision != d2.Revision || next.Services[0].Protocol != "postgres" || next.CollectionID != c.ID || next.Services[0].ServiceID == assignment.ServiceID {
		t.Fatal("new member did not independently pin the new default", next, err)
	}
	explicit := collectionEnvironmentRequest(r, updated, "explicit", "explicit.internal:3000")
	explicit.DefinitionRevision = d1.Revision
	override, err := d.CreateEnvironment(t.Context(), explicit)
	if err != nil || override.AppliedDefinitionRevision != d1.Revision || override.Services[0].Protocol != "http" || override.CollectionID != c.ID {
		t.Fatal("explicit definition did not take precedence over the collection default", override, err)
	}
	update.ExpectedRevision, update.DefinitionRevision = updated.MutationRevision, d1.Revision
	rolledBack, err := d.UpdateCollectionDefault(t.Context(), update)
	if err != nil || rolledBack.MutationRevision != 3 || rolledBack.DefaultDefinitionRevision != d1.Revision {
		t.Fatal("default rollback did not advance its own mutation revision", rolledBack, err)
	}
	explicitReplay, err := d.CreateEnvironment(t.Context(), explicit)
	if err != nil || explicitReplay.ID != override.ID || explicitReplay.AppliedDefinitionRevision != d1.Revision {
		t.Fatal("explicit-definition retry rejected its original collection precondition", explicitReplay, err)
	}
	changedPrecondition = explicit
	changedPrecondition.ExpectedCollectionRevision = rolledBack.MutationRevision
	if _, err := d.CreateEnvironment(t.Context(), changedPrecondition); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("explicit-definition creation key accepted a changed collection precondition", err)
	}
	assertExisting()
	newAfter, err := d.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, next.ID, r.ActorID)
	if err != nil || !reflect.DeepEqual(newAfter, next) {
		t.Fatal("default rollback rolled back an installed member", newAfter, err)
	}
	listed, err := d.ListCollections(t.Context(), r.TeamID, r.ProjectKey, r.ActorID)
	if err != nil || !reflect.DeepEqual(listed, []Collection{rolledBack}) {
		t.Fatal("collection list did not read saved state", listed, err)
	}
	got, err := d.GetCollection(t.Context(), r.TeamID, r.ProjectKey, c.ID, r.ActorID)
	if err != nil || got != rolledBack {
		t.Fatal(got, err)
	}
	var visitors, publishers, provisioners int
	if err := d.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM control.visitor_grants WHERE team_id=$1),(SELECT count(*) FROM control.publisher_grants grant_record JOIN control.publisher_identities publisher ON publisher.id=grant_record.publisher_identity_id WHERE publisher.team_id=$1),(SELECT count(*) FROM control.machine_provisioning_grants WHERE team_id=$1)`, r.TeamID).Scan(&visitors, &publishers, &provisioners); err != nil || visitors != 1 || publishers != 1 || provisioners != 0 {
		t.Fatal("collection state manufactured or widened authority", visitors, publishers, provisioners, err)
	}
}

func TestIntegrationCollectionScopeAndDurableMembership(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "collection_scope")
	r := retainedEnvironmentProject(t, d, now)
	d1 := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	c, creation := createTestCollection(t, d, r, "same name", d1.Revision)
	member, err := d.CreateEnvironment(t.Context(), collectionEnvironmentRequest(r, c, "member", "member.internal:3000"))
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := createTestEnvironment(t, d, r, "not-a-member", d1.Revision, EnvironmentTargets{"api": {Address: "plain.internal:3000"}})
	otherCollection, _ := createTestCollection(t, d, r, "other collection", d1.Revision)
	for _, request := range []CreateEnvironmentRequest{
		collectionEnvironmentRequest(r, c, plain.Name, "plain.internal:3000"),
		collectionEnvironmentRequest(r, otherCollection, member.Name, "member.internal:3000"),
	} {
		if _, err := d.CreateEnvironment(t.Context(), request); !errors.Is(err, ErrServiceConflict) {
			t.Fatal("creation retry attached or transferred an existing environment", err)
		}
	}
	otherProject := r
	otherProject.ProjectKey = "other-project"
	team, err := d.CreateTeam(t.Context(), authorityTeamRequest(r.ActorID), now)
	if err != nil {
		t.Fatal(err)
	}
	otherTeam := r
	otherTeam.TeamID = team.ID
	for _, scope := range []environmentPublisherTestProject{otherProject, otherTeam} {
		foreignDefinition := environmentDefinition(t, d, scope, d1.Definition.Services)
		foreign, _ := createTestCollection(t, d, scope, creation.Name, foreignDefinition.Revision)
		if foreign.ID == c.ID {
			t.Fatal("same name derived a shared collection identity")
		}
		if _, err := d.GetCollection(t.Context(), scope.TeamID, scope.ProjectKey, c.ID, scope.ActorID); !errors.Is(err, ErrCollectionNotFound) {
			t.Fatal("collection ID escaped its team/project", err)
		}
		if _, err := d.UpdateCollectionDefault(t.Context(), UpdateCollectionDefaultRequest{TeamID: scope.TeamID, ProjectKey: scope.ProjectKey, ActorID: scope.ActorID, CollectionID: c.ID, ExpectedRevision: 1, DefinitionRevision: foreignDefinition.Revision, Now: now}); !errors.Is(err, ErrCollectionNotFound) {
			t.Fatal("default update joined another team's or project's collection", err)
		}
		bad := collectionEnvironmentRequest(scope, c, "cross-scope", "cross.internal:3000")
		if _, err := d.CreateEnvironment(t.Context(), bad); !errors.Is(err, ErrCollectionNotFound) {
			t.Fatal("environment joined a cross-scope collection", err)
		}
		// the composite FK also rejects a cross-scope association at insertion,
		// before a membership row can become durable.
		tx, err := d.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackTestTransaction(t, tx)
		if _, err := tx.Exec(t.Context(), `INSERT INTO control.project_publisher_groups(id,team_id,project_key,name) VALUES('pgrp_AAAAAAAAAAAAAAAAAAAAAA',$1,$2,'cross-scope-fk')`, r.TeamID, r.ProjectKey); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(t.Context(), `INSERT INTO control.environments(id,team_id,project_key,collection_id,name,group_id,applied_definition_revision,mutation_revision,configuration_hash,initial_definition_revision,creation_digest,created_by_identity_id,created_at,updated_at)
			SELECT 'env_AAAAAAAAAAAAAAAAAAAAAA',team_id,project_key,$2,'cross-scope-fk','pgrp_AAAAAAAAAAAAAAAAAAAAAA',applied_definition_revision,mutation_revision,configuration_hash,initial_definition_revision,creation_digest,created_by_identity_id,created_at,updated_at FROM control.environments WHERE id=$1`, member.ID, foreign.ID)
		var scopeConstraint *pgconn.PgError
		if !errors.As(err, &scopeConstraint) || scopeConstraint.Code != "23503" || scopeConstraint.ConstraintName != "environments_collection_id_team_id_project_key_fkey" {
			t.Fatal("database did not enforce collection team/project scope", err)
		}
		rollbackTestTransaction(t, tx)
		listed, err := d.ListCollections(t.Context(), scope.TeamID, scope.ProjectKey, scope.ActorID)
		if err != nil || !reflect.DeepEqual(listed, []Collection{foreign}) {
			t.Fatal("collection list crossed team/project scope", listed, err)
		}
		foreignOnly := environmentDefinition(t, d, scope, map[string]ServiceDefinitionService{"api": {Protocol: "postgres"}})
		badCreation := creation
		badCreation.Name, badCreation.DefaultDefinitionRevision = "foreign-definition", foreignOnly.Revision
		if _, err := d.CreateCollection(t.Context(), badCreation); !errors.Is(err, ErrCollectionNotFound) {
			t.Fatal("collection creation selected a foreign-only definition", err)
		}
		if _, err := d.UpdateCollectionDefault(t.Context(), UpdateCollectionDefaultRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, CollectionID: c.ID, ExpectedRevision: 1, DefinitionRevision: foreignOnly.Revision, Now: now}); !errors.Is(err, ErrCollectionNotFound) {
			t.Fatal("collection default selected a foreign-only definition", err)
		}
		bad = collectionEnvironmentRequest(r, c, "foreign-explicit-definition", "cross.internal:5432")
		bad.DefinitionRevision = foreignOnly.Revision
		if _, err := d.CreateEnvironment(t.Context(), bad); !errors.Is(err, ErrEnvironmentNotFound) {
			t.Fatal("collection member selected a foreign-only explicit definition", err)
		}
	}
	for _, move := range []struct{ environment, collection string }{
		{member.ID, ""}, {member.ID, otherCollection.ID}, {plain.ID, c.ID},
	} {
		_, err := d.pool.Exec(t.Context(), `UPDATE control.environments SET collection_id=NULLIF($2,'') WHERE id=$1`, move.environment, move.collection)
		var constraint *pgconn.PgError
		if !errors.As(err, &constraint) || constraint.Code != "23514" {
			t.Fatal("saved membership could be detached, moved or attached after creation", move, err)
		}
	}
	_, err = d.pool.Exec(t.Context(), `DELETE FROM control.collections WHERE id=$1`, c.ID)
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23503" {
		t.Fatal("collection deletion orphaned a saved member", err)
	}
	for _, before := range []Environment{member, plain} {
		after, err := d.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, before.ID, r.ActorID)
		if err != nil || !reflect.DeepEqual(after, before) {
			t.Fatal("scope rejection or membership mutation changed an environment", after, err)
		}
	}
	got, err := d.GetCollection(t.Context(), r.TeamID, r.ProjectKey, c.ID, r.ActorID)
	if err != nil || got != c {
		t.Fatal("failed default update changed collection state", got, err)
	}
}

func TestIntegrationCollectionEnvironmentCreationRollsBackMembershipAndResources(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "collection_rollback")
	r := retainedEnvironmentProject(t, d, now)
	d1 := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	c, _ := createTestCollection(t, d, r, "rollback", d1.Revision)
	counts := func() string {
		t.Helper()
		var result string
		if err := d.pool.QueryRow(t.Context(), `SELECT jsonb_build_array(
			(SELECT count(*) FROM control.environments),
			(SELECT count(*) FROM control.environment_creations),
			(SELECT count(*) FROM control.project_publisher_groups),
			(SELECT count(*) FROM control.applied_project_services),
			(SELECT count(*) FROM control.services),
			(SELECT count(*) FROM control.service_namespace_claims),
			(SELECT count(*) FROM control.service_endpoints),
			(SELECT count(*) FROM control.publisher_group_bindings))::text`).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := counts()
	var pool string
	var first, last int32
	if err := d.pool.QueryRow(t.Context(), `DELETE FROM control.ingress_service_port_ranges RETURNING ingress_pool_id,first_port,last_port`).Scan(&pool, &first, &last); err != nil {
		t.Fatal(err)
	}
	request := collectionEnvironmentRequest(r, c, "failed-member", "failed.internal:3000")
	if _, err := d.CreateEnvironment(t.Context(), request); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("expected real resource allocation failure", err)
	}
	if after := counts(); after != before {
		t.Fatal("failed materialization saved membership, creation key or resource state", after, before)
	}
	got, err := d.GetCollection(t.Context(), r.TeamID, r.ProjectKey, c.ID, r.ActorID)
	if err != nil || got != c {
		t.Fatal("failed materialization revised the collection", got, err)
	}
	if _, err := d.pool.Exec(t.Context(), `INSERT INTO control.ingress_service_port_ranges(ingress_pool_id,first_port,last_port) VALUES($1,$2,$3)`, pool, first, last); err != nil {
		t.Fatal(err)
	}
	member, err := d.CreateEnvironment(t.Context(), request)
	if err != nil || member.CollectionID != c.ID || member.MutationRevision != 1 {
		t.Fatal("rolled-back membership or creation key prevented retry", member, err)
	}
}
