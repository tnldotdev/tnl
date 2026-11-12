package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func environmentDefinition(t *testing.T, d *Database, r environmentPublisherTestProject, services map[string]ServiceDefinitionService) ServiceDefinitionRevision {
	t.Helper()
	definition, err := d.CreateServiceDefinition(t.Context(), CreateServiceDefinitionRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, ActorID: r.ActorID, Definition: ServiceDefinition{Services: services}, Now: r.Now})
	if err != nil {
		t.Fatal(err)
	}
	return definition
}

func createTestEnvironment(t *testing.T, d *Database, r environmentPublisherTestProject, name string, revision int64, targets EnvironmentTargets) (Environment, CreateEnvironmentRequest) {
	t.Helper()
	request := CreateEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, ActorID: r.ActorID, Name: name, DefinitionRevision: revision, Targets: targets, IdempotencyKey: "create/" + name, Now: r.Now}
	environment, err := d.CreateEnvironment(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	return environment, request
}

func enrollTestEnvironment(t *testing.T, d *Database, r environmentPublisherTestProject, e Environment) environmentPublisherReplica {
	t.Helper()
	return enrollEnvironmentPublisher(t, d, r, e)
}

func TestIntegrationEnvironmentPinnedDefinitionsIsolationAndRollback(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "environment_isolation")
	r := retainedEnvironmentProject(t, d, now)
	d1 := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	staging, creation := createTestEnvironment(t, d, r, "customer_staging", d1.Revision, EnvironmentTargets{"api": {Address: "stage.internal:3000"}})
	production, _ := createTestEnvironment(t, d, r, "production", d1.Revision, EnvironmentTargets{"api": {Address: "production.internal:3000"}})
	if staging.ID == production.ID || staging.Services[0].ServiceID == production.Services[0].ServiceID || staging.Services[0].Hostname == production.Services[0].Hostname || strings.Contains(staging.Services[0].Hostname, staging.Name) {
		t.Fatal("environments shared identities or derived DNS from a human selector")
	}
	var visitors, publishers, provisioners int
	if err := d.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM control.visitor_grants WHERE team_id=$1),(SELECT count(*) FROM control.publisher_grants grant_record JOIN control.publisher_identities publisher ON publisher.id=grant_record.publisher_identity_id WHERE publisher.team_id=$1),(SELECT count(*) FROM control.machine_provisioning_grants WHERE team_id=$1)`, r.TeamID).Scan(&visitors, &publishers, &provisioners); err != nil || visitors != 0 || publishers != 0 || provisioners != 0 {
		t.Fatal("environment creation manufactured authority", visitors, publishers, provisioners, err)
	}
	stageMember := enrollTestEnvironment(t, d, r, staging)
	prodMember := enrollTestEnvironment(t, d, r, production)
	for _, member := range []environmentPublisherReplica{stageMember, prodMember} {
		if len(member.assignments.Services) != 1 {
			t.Fatal("explicit enrollment did not assign an exact service")
		}
		if err := d.AcknowledgeEnvironmentPublisher(t.Context(), member.lease.AccessToken, member.assignments.Environment, true, now); err != nil {
			t.Fatal(err)
		}
	}
	grant, err := d.CreateServiceGrant(t.Context(), production.Services[0].ServiceID, r.ActorID, "explicit-production-visitor", "identity", r.ActorID, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	before, err := d.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, production.ID, r.ActorID)
	if err != nil || len(before.Members) != 1 || !before.Members[0].Healthy {
		t.Fatal("production was not healthy before apply", before, err)
	}
	// a newer incompatible definition must never replace an environment's pin.
	d2 := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "postgres"}})
	if d2.Revision != d1.Revision+1 || d2.ConfigurationHash == d1.ConfigurationHash {
		t.Fatal("definition revision/hash was not immutable")
	}
	for _, query := range []string{
		`UPDATE control.service_definitions SET definition=definition WHERE team_id=$1 AND project_key=$2 AND revision=$3`,
		`DELETE FROM control.service_definitions WHERE team_id=$1 AND project_key=$2 AND revision=$3`,
	} {
		_, err := d.pool.Exec(t.Context(), query, r.TeamID, r.ProjectKey, d1.Revision)
		var constraint *pgconn.PgError
		if !errors.As(err, &constraint) || constraint.Code != "23514" {
			t.Fatal("database accepted mutation of an immutable definition", err)
		}
	}
	if _, err := d.CreateServiceDefinition(t.Context(), CreateServiceDefinitionRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: strings.Repeat("b", 64), ActorID: r.ActorID, Definition: d2.Definition, Now: now}); !errors.Is(err, ErrProjectSourceConflict) {
		t.Fatal("definition publisher replaced project source provenance", err)
	}
	unchanged, err := d.GetEnvironmentPublisherAssignments(t.Context(), prodMember.lease.AccessToken, now)
	if err != nil || !reflect.DeepEqual(unchanged, prodMember.assignments) {
		t.Fatal("definition publication changed production", unchanged, err)
	}
	apply := ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: staging.ID, ExpectedRevision: staging.MutationRevision, DefinitionRevision: d2.Revision}, Now: now}
	if _, err := d.ApplyEnvironment(t.Context(), apply); !errors.Is(err, ErrEnvironmentInvalid) {
		t.Fatal("protocol changed without explicit target replacement", err)
	}
	apply.Targets = EnvironmentTargets{"api": {Address: "replacement.internal:5432"}}
	updated, err := d.ApplyEnvironment(t.Context(), apply)
	if err != nil {
		t.Fatal(err)
	}
	if updated.MutationRevision != staging.MutationRevision+1 || updated.AppliedDefinitionRevision != d2.Revision || updated.Services[0].Protocol != "postgres" || updated.Services[0].ServiceID != staging.Services[0].ServiceID || updated.Services[0].Hostname != staging.Services[0].Hostname || updated.Services[0].Port != staging.Services[0].Port {
		t.Fatal("scoped apply replaced service identity or endpoint", updated)
	}
	stageAssignments, err := d.GetEnvironmentPublisherAssignments(t.Context(), stageMember.lease.AccessToken, now)
	if err != nil || stageAssignments.Environment != environmentPublicationForTest(updated) || len(stageAssignments.Services) != 1 || stageAssignments.Services[0].Configuration.Target != "replacement.internal:5432" || stageAssignments.Services[0].Configuration.Protocol != "postgres" || stageAssignments.Services[0].GrantID != stageMember.assignments.Services[0].GrantID {
		t.Fatal("publisher assignments did not use the new pinned application", stageAssignments, err)
	}
	prodAssignments, err := d.GetEnvironmentPublisherAssignments(t.Context(), prodMember.lease.AccessToken, now)
	if err != nil || !reflect.DeepEqual(prodAssignments, prodMember.assignments) {
		t.Fatal("staging apply changed production assignments or authority", prodAssignments, err)
	}
	if err := d.AcknowledgeEnvironmentPublisher(t.Context(), stageMember.lease.AccessToken, stageMember.assignments.Environment, true, now); !errors.Is(err, ErrEnvironmentStale) {
		t.Fatal("publisher acknowledged an older environment application", err)
	}
	prodAfter, err := d.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, production.ID, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	before.Members[0].SnapshotAt = prodAfter.Members[0].SnapshotAt
	if !reflect.DeepEqual(prodAfter, before) {
		t.Fatal("staging apply changed production revision, health, bindings, grants or endpoints", prodAfter, before)
	}
	grants, _, err := d.ListServiceGrants(t.Context(), production.Services[0].ServiceID, r.ActorID, "")
	if err != nil || len(grants) != 1 || grants[0].ID != grant.ID || grants[0].RevokedAt != nil {
		t.Fatal("staging apply changed production visitor authority", grants, err)
	}
	available, _, err := d.ListAvailableServices(t.Context(), r.ActorID, "", now)
	if err != nil || len(available) != 1 || available[0].ID != production.Services[0].ServiceID {
		t.Fatal("visitor inventory did not use the granted saved environment identity", available, err)
	}
	var internalAssignment string
	if err := d.pool.QueryRow(t.Context(), `SELECT group_id FROM control.environments WHERE id=$1`, production.ID).Scan(&internalAssignment); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, internalAssignment, r.ActorID); !errors.Is(err, ErrEnvironmentInvalid) {
		t.Fatal("internal assignment ID selected an environment", err)
	}
	apply.ExpectedRevision = updated.MutationRevision
	apply.DefinitionRevision, apply.Targets = d1.Revision, creation.Targets
	rolledBack, err := d.ApplyEnvironment(t.Context(), apply)
	if err != nil || rolledBack.MutationRevision != updated.MutationRevision+1 || rolledBack.ConfigurationHash != staging.ConfigurationHash || rolledBack.Services[0].ServiceID != staging.Services[0].ServiceID {
		t.Fatal("rollback did not create a newer environment application", rolledBack, err)
	}
	replay, err := d.CreateEnvironment(t.Context(), creation)
	if err != nil || replay.ID != staging.ID || replay.MutationRevision != rolledBack.MutationRevision {
		t.Fatal("creation replay normalized against latest definition", replay, err)
	}
	if _, err := d.ApplyEnvironment(t.Context(), ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: production.ID, ExpectedRevision: 9, DefinitionRevision: d1.Revision, Targets: EnvironmentTargets{"api": {Address: "bypass.internal:3000"}}}, Now: now}); !errors.Is(err, ErrEnvironmentStale) {
		t.Fatal("target replacement bypassed the environment revision fence", err)
	}
	if _, err := d.ConfigureService(t.Context(), production.Services[0].ServiceID, r.ActorID, ServiceMetadata{Protocol: "tcp"}, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("direct resource mutation bypassed the environment owner", err)
	}
	protected, err := d.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, production.ID, r.ActorID)
	if err != nil || !protected.Members[0].Healthy || protected.ConfigurationHash != before.ConfigurationHash || protected.MutationRevision != before.MutationRevision || !reflect.DeepEqual(protected.Services, before.Services) {
		t.Fatal("denied mutations disturbed production", protected, err)
	}
}

func TestIntegrationEnvironmentBatchPreflightAndResourceRollback(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "environment_batch")
	r := retainedEnvironmentProject(t, d, now)
	d1 := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	one, _ := createTestEnvironment(t, d, r, "one", d1.Revision, EnvironmentTargets{"api": {Address: "one.internal:3000"}})
	two, _ := createTestEnvironment(t, d, r, "two", d1.Revision, EnvironmentTargets{"api": {Address: "two.internal:3000"}})
	batch := ApplyEnvironmentsRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, Items: []EnvironmentApplication{
		{EnvironmentID: one.ID, ExpectedRevision: 1, DefinitionRevision: d1.Revision, Targets: EnvironmentTargets{"api": {Address: "changed.internal:3000"}}},
		{EnvironmentID: two.ID, ExpectedRevision: 2, DefinitionRevision: d1.Revision},
	}, Now: now}
	assertUnchanged := func() {
		t.Helper()
		for _, before := range []Environment{one, two} {
			after, err := d.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, before.ID, r.ActorID)
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatal("failed batch partially committed", after, before, err)
			}
		}
		var count int
		if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.services WHERE team_id=$1 AND deleted_at IS NULL`, r.TeamID).Scan(&count); err != nil || count != 2 {
			t.Fatal("failed batch leaked a newly inserted resource", count, err)
		}
	}
	if _, err := d.ApplyEnvironments(t.Context(), batch); !errors.Is(err, ErrEnvironmentStale) {
		t.Fatal("stale member was accepted", err)
	}
	assertUnchanged()
	batch.Items[1].ExpectedRevision = 1
	batch.Items[1].Targets = EnvironmentTargets{}
	if _, err := d.ApplyEnvironments(t.Context(), batch); !errors.Is(err, ErrEnvironmentInvalid) {
		t.Fatal("incomplete member bindings were accepted", err)
	}
	assertUnchanged()
	wrong := batch
	wrong.ProjectKey = "other-project"
	otherProject := r
	otherProject.ProjectKey = wrong.ProjectKey
	environmentDefinition(t, d, otherProject, d1.Definition.Services)
	if _, err := d.ApplyEnvironments(t.Context(), wrong); !errors.Is(err, ErrEnvironmentNotFound) {
		t.Fatal("environment IDs escaped project scope", err)
	}
	assertUnchanged()
	otherTeam, err := d.CreateTeam(t.Context(), authorityTeamRequest(r.ActorID), now)
	if err != nil {
		t.Fatal(err)
	}
	otherScope := r
	otherScope.TeamID = otherTeam.ID
	environmentDefinition(t, d, otherScope, d1.Definition.Services)
	wrong = batch
	wrong.TeamID = otherTeam.ID
	if _, err := d.ApplyEnvironments(t.Context(), wrong); !errors.Is(err, ErrEnvironmentNotFound) {
		t.Fatal("environment IDs escaped team scope", err)
	}
	assertUnchanged()
	d2 := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "new": {Protocol: "tcp"}})
	// exhaust only this disposable fixture's inventory. sorted batch order makes
	// one valid mutation run first, then a real allocation failure rolls it back.
	if _, err := d.pool.Exec(t.Context(), `DELETE FROM control.ingress_service_port_ranges`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `INSERT INTO control.ingress_service_port_ranges(ingress_pool_id,first_port,last_port) VALUES($1,$2,$2)`, PrimaryIngressPoolID, one.Services[0].Port); err != nil {
		t.Fatal(err)
	}
	first, second := one, two
	if first.ID > second.ID {
		first, second = second, first
	}
	batch.Items = []EnvironmentApplication{
		{EnvironmentID: first.ID, ExpectedRevision: 1, DefinitionRevision: d1.Revision, Targets: EnvironmentTargets{"api": {Address: "changed.internal:3000"}}},
		{EnvironmentID: second.ID, ExpectedRevision: 1, DefinitionRevision: d2.Revision, Targets: EnvironmentTargets{"api": {Address: "retained.internal:3000"}, "new": {Address: "new.internal:5432"}}},
	}
	if _, err := d.ApplyEnvironments(t.Context(), batch); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("expected real second-member allocation failure", err)
	}
	assertUnchanged()
	batch.Items[1].DefinitionRevision, batch.Items[1].Targets = d1.Revision, nil
	updated, err := d.ApplyEnvironments(t.Context(), batch)
	if err != nil || len(updated) != 2 || updated[0].ID != first.ID || updated[1].ID != second.ID || updated[0].MutationRevision != 2 || updated[1].MutationRevision != 2 {
		t.Fatal("valid atomic batch failed", updated, err)
	}
}

func TestIntegrationEnvironmentTargetUpdateClosesOnlyOwnedRuns(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	r := retainedEnvironmentProject(t, d, now)
	d1 := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	staging, _ := createTestEnvironment(t, d, r, "staging", d1.Revision, EnvironmentTargets{"api": {Address: "staging.internal:3000"}})
	production, _ := createTestEnvironment(t, d, r, "production", d1.Revision, EnvironmentTargets{"api": {Address: "production.internal:3000"}})
	stageMember, prodMember := enrollTestEnvironment(t, d, r, staging), enrollTestEnvironment(t, d, r, production)
	start := func(member environmentPublisherReplica) ServiceRunState {
		t.Helper()
		assignment := member.assignments.Services[0]
		access := environmentAssignmentAccess(t, d, member, assignment, now)
		prepared, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "environment-run/"+assignment.GrantID, now, ServiceMetadata{Protocol: "http", PublisherPool: true, TrustRevision: assignment.TrustRevision}, &member.assignments.Environment)
		if err != nil {
			t.Fatal(err)
		}
		run, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
		if err != nil {
			t.Fatal(err)
		}
		return run
	}
	stageRun, prodRun := start(stageMember), start(prodMember)
	updated, err := d.ApplyEnvironment(t.Context(), ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: staging.ID, ExpectedRevision: 1, DefinitionRevision: d1.Revision, Targets: EnvironmentTargets{"api": {Address: "replacement.internal:3000"}}}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Services[0].ServiceID != staging.Services[0].ServiceID || updated.Services[0].Hostname != staging.Services[0].Hostname || updated.Services[0].Port != staging.Services[0].Port {
		t.Fatal("target update replaced a reserved endpoint")
	}
	if _, err := d.HeartbeatServiceRun(t.Context(), stageRun.ServiceID, stageRun.RunID, stageRun.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("stale staging worker retained its run", err)
	}
	if _, err := d.HeartbeatServiceRun(t.Context(), prodRun.ServiceID, prodRun.RunID, prodRun.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal("staging apply closed a production run", err)
	}
	for _, test := range []struct {
		run    ServiceRunState
		closed bool
	}{{stageRun, true}, {prodRun, false}} {
		var closed bool
		if err := d.pool.QueryRow(t.Context(), `SELECT closed_at IS NOT NULL FROM control.service_runs WHERE id=$1`, test.run.RunID).Scan(&closed); err != nil || closed != test.closed {
			t.Fatal("wrong publication lifetime after scoped apply", closed, err)
		}
	}
}

func TestIntegrationEnvironmentPinnedReadersAndLocalOwnership(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "environment_readers")
	r := retainedEnvironmentProject(t, d, now)
	d1 := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"cluster": {Protocol: "kubernetes"}})
	production, _ := createTestEnvironment(t, d, r, "production", d1.Revision, EnvironmentTargets{"cluster": {Discovery: &ProjectTargetDiscovery{Type: "eks", Region: "us-east-1", Cluster: new("production")}}})
	staging, _ := createTestEnvironment(t, d, r, "staging", d1.Revision, EnvironmentTargets{"cluster": {Discovery: &ProjectTargetDiscovery{Type: "eks", Region: "us-west-2", Cluster: new("staging")}}})
	localRequest := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "only-running-app", WorktreeKey: "checkout-a", WorktreeLabel: "checkout-a", ActorID: r.ActorID, Configuration: LocalServiceDeclaration{Protocol: "http", Target: "localhost:3000"}, Now: now}
	local, err := d.RealizeLocalProjectService(t.Context(), localRequest)
	if err != nil {
		t.Fatal("definition-only provenance fenced an app-owned registration", err)
	}
	q := controlstatedb.New(d.pool)
	before, err := q.GetService(t.Context(), local.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	public := true
	staging, err = d.ApplyEnvironment(t.Context(), ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: staging.ID, ExpectedRevision: staging.MutationRevision, DefinitionRevision: d1.Revision, Public: &public}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	apply := ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: staging.ID, ExpectedRevision: staging.MutationRevision, DefinitionRevision: d1.Revision, Targets: EnvironmentTargets{"cluster": {Discovery: &ProjectTargetDiscovery{Type: "eks", Region: "eu-west-1", Cluster: new("replacement")}}}}, Now: now}
	updated, err := d.ApplyEnvironment(t.Context(), apply)
	if err != nil || !updated.Services[0].Public || updated.Services[0].Hostname != staging.Services[0].Hostname || updated.Services[0].Port != staging.Services[0].Port {
		t.Fatal("definition apply reset current reachability or endpoint", updated, err)
	}
	after, err := q.GetService(t.Context(), local.ServiceID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("environment apply swept an app-owned realization", after, err)
	}
	for _, test := range []struct {
		environment     Environment
		cluster, region string
	}{{production, "production", "us-east-1"}, {updated, "replacement", "eu-west-1"}} {
		hint, err := d.visitorKubernetesAuth(t.Context(), q, test.environment.Services[0].ServiceID)
		if err != nil || hint == nil || hint.Cluster != test.cluster || hint.Region != test.region {
			t.Fatal("kubernetes hint did not use pinned environment targets", hint, err)
		}
		settings, err := d.serviceHTTPSettings(t.Context(), q, test.environment.Services[0].ServiceID)
		if err != nil || settings != nil {
			t.Fatal("protocol-only shape inherited live HTTP policy", settings, err)
		}
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.environments SET configuration_hash=$2 WHERE id=$1`, staging.ID, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.visitorKubernetesAuth(t.Context(), q, updated.Services[0].ServiceID); err == nil {
		t.Fatal("corrupt environment silently fell back to the global project")
	}
	if _, err := d.serviceHTTPSettings(t.Context(), q, updated.Services[0].ServiceID); err == nil {
		t.Fatal("corrupt environment bypassed the HTTP policy source check")
	}
}

func TestIntegrationEnvironmentRevocationSurvivesRollback(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "environment_revocation")
	r := retainedEnvironmentProject(t, d, now)
	d1 := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	environment, creation := createTestEnvironment(t, d, r, "production", d1.Revision, EnvironmentTargets{"api": {Address: "original.internal:3000"}})
	member := enrollTestEnvironment(t, d, r, environment)
	assignment := member.assignments.Services[0]
	access := environmentAssignmentAccess(t, d, member, assignment, now)
	unused, err := publisherproof.Sign(member.member.PublisherIdentityID, member.member.KeyID, assignment.GrantID, publisherTestAudience, member.private, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeEnvironmentPublisher(t.Context(), environmentPublisherSelection(t, d, r, environment), member.member.PublisherIdentityID, now); err != nil {
		t.Fatal(err)
	}
	grantOnly := enrollTestEnvironment(t, d, r, environment)
	grantOnlyAssignment := grantOnly.assignments.Services[0]
	grantOnlyAccess := environmentAssignmentAccess(t, d, grantOnly, grantOnlyAssignment, now)
	grantOnlyUnused, err := publisherproof.Sign(grantOnly.member.PublisherIdentityID, grantOnly.member.KeyID, grantOnlyAssignment.GrantID, publisherTestAudience, grantOnly.private, now)
	if err != nil {
		t.Fatal(err)
	}
	// retain the enrolled identity while revoking just its exact grant. this
	// state-owner fixture catches repair even when membership itself stays live.
	if n, err := controlstatedb.New(d.pool).RevokePublisherGrant(t.Context(), controlstatedb.RevokePublisherGrantParams{ID: grantOnlyAssignment.GrantID, PublisherIdentityID: grantOnly.member.PublisherIdentityID, Now: timestamptz(now)}); err != nil || n != 1 {
		t.Fatal("revoke exact fixture grant", n, err)
	}
	visitor, err := d.CreateServiceGrant(t.Context(), environment.Services[0].ServiceID, r.ActorID, "explicit-visitor", "identity", r.ActorID, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeServiceGrant(t.Context(), environment.Services[0].ServiceID, r.ActorID, visitor.ID, now); err != nil {
		t.Fatal(err)
	}
	apply := ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: environment.ID, ExpectedRevision: 1, DefinitionRevision: d1.Revision, Targets: EnvironmentTargets{"api": {Address: "replacement.internal:3000"}}}, Now: now}
	if _, err := d.ApplyEnvironment(t.Context(), apply); err != nil {
		t.Fatal(err)
	}
	apply.ExpectedRevision, apply.Targets = 2, creation.Targets
	if _, err := d.ApplyEnvironment(t.Context(), apply); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("rollback revived an old access token", err)
	}
	if _, err := d.AuthenticatePublisherAccess(t.Context(), grantOnlyAccess.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("rollback repaired a revoked grant for a live enrolled identity", err)
	}
	fresh, err := publisherproof.Sign(member.member.PublisherIdentityID, member.member.KeyID, assignment.GrantID, publisherTestAudience, member.private, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, assertion := range []string{unused, fresh} {
		if _, err := d.ExchangePublisherAssertion(t.Context(), member.member.PublisherIdentityID, assignment.GrantID, publisherTestAudience, assertion, "", now); !errors.Is(err, ErrPublisherIdentity) {
			t.Fatal("rollback revived old or unused valid publisher proof", err)
		}
	}
	grantOnlyFresh, err := publisherproof.Sign(grantOnly.member.PublisherIdentityID, grantOnly.member.KeyID, grantOnlyAssignment.GrantID, publisherTestAudience, grantOnly.private, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, assertion := range []string{grantOnlyUnused, grantOnlyFresh} {
		if _, err := d.ExchangePublisherAssertion(t.Context(), grantOnly.member.PublisherIdentityID, grantOnlyAssignment.GrantID, publisherTestAudience, assertion, "", now); !errors.Is(err, ErrPublisherIdentity) {
			t.Fatal("rollback repaired an exact revoked grant for old or new proof", err)
		}
	}
	var count, active int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*),count(*) FILTER(WHERE revoked_at IS NULL) FROM control.publisher_grants WHERE publisher_identity_id=$1`, member.member.PublisherIdentityID).Scan(&count, &active); err != nil || count != 1 || active != 0 {
		t.Fatal("definition apply repaired a revoked publisher grant", count, active, err)
	}
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*),count(*) FILTER(WHERE revoked_at IS NULL) FROM control.publisher_grants WHERE publisher_identity_id=$1`, grantOnly.member.PublisherIdentityID).Scan(&count, &active); err != nil || count != 1 || active != 0 {
		t.Fatal("definition apply repaired an exact grant for a live member", count, active, err)
	}
	available, _, err := d.ListAvailableServices(t.Context(), r.ActorID, "", now)
	if err != nil || len(available) != 0 {
		t.Fatal("rollback repaired revoked visitor authority", available, err)
	}
}

func TestIntegrationEnvironmentCurrentEnrollmentParentAndReplayAuthorization(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	r := retainedEnvironmentProject(t, d, now)
	// this fixture starts with a personal team. use an organization so a second
	// manager can lose authority independently from the owner doing rollback.
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	issuer, manager := retainedEnvironmentManager(t, d, r, "environment-manager")
	d1 := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	environment, creation := createTestEnvironment(t, d, r, "production", d1.Revision, EnvironmentTargets{"api": {Address: "original.internal:3000"}})
	member := enrollTestEnvironment(t, d, issuer, environment)
	assignment := member.assignments.Services[0]
	access := environmentAssignmentAccess(t, d, member, assignment, now)
	metadata := ServiceMetadata{Protocol: "http", PublisherPool: true, TrustRevision: assignment.TrustRevision}
	prepared, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "issuer-independent", now, metadata, &member.assignments.Environment)
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	unused, err := publisherproof.Sign(member.member.PublisherIdentityID, member.member.KeyID, assignment.GrantID, publisherTestAudience, member.private, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET role='member' WHERE id=$1`, manager.ID); err != nil {
		t.Fatal(err)
	}
	demotedRetry := creation
	demotedRetry.ActorID = manager.IdentityID
	if _, err := d.CreateEnvironment(t.Context(), demotedRetry); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("enabled demoted manager replayed environment creation", err)
	}
	if _, err := d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); err != nil {
		t.Error("installed team publisher depended on bootstrap issuer role", err)
	}
	if _, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Error("installed publisher renewal depended on bootstrap issuer role", err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, manager.IdentityID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.publisher_group_enrollments SET expires_at=$2,revoked_at=$3 WHERE group_id=(SELECT group_id FROM control.environments WHERE id=$1)`, environment.ID, now.Add(-time.Second), now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Error("installed renewal depended on bootstrap identity or key lifetime", err)
	}
	groupAudience := "https://control.example/v1/environment-publishers/lease"
	groupAssertion, err := publisherproof.Sign(member.member.PublisherIdentityID, member.member.KeyID, member.member.EnvironmentID, groupAudience, member.private, now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := d.AcquireEnvironmentPublisherLease(t.Context(), member.member.PublisherIdentityID, member.member.EnvironmentID, groupAssertion, groupAudience, now)
	if err != nil {
		t.Error("installed publisher could not renew its group lease independently", err)
	} else {
		member.lease = lease
	}
	apply := ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: environment.ID, ExpectedRevision: 1, DefinitionRevision: d1.Revision, Targets: EnvironmentTargets{"api": {Address: "replacement.internal:3000"}}}, Now: now}
	if _, err := d.ApplyEnvironment(t.Context(), apply); err != nil {
		t.Fatal(err)
	}
	apply.ExpectedRevision, apply.Targets = 2, creation.Targets
	if _, err := d.ApplyEnvironment(t.Context(), apply); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); err != nil {
		t.Error("installed team publisher depended on bootstrap identity or key lifetime", err)
	}
	fresh, err := publisherproof.Sign(member.member.PublisherIdentityID, member.member.KeyID, assignment.GrantID, publisherTestAudience, member.private, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, assertion := range []string{unused, fresh} {
		if _, err := d.ExchangePublisherAssertion(t.Context(), member.member.PublisherIdentityID, assignment.GrantID, publisherTestAudience, assertion, "", now); err != nil {
			t.Error("installed publisher proof depended on bootstrap issuer", err)
		}
	}
	assignments, err := d.GetEnvironmentPublisherAssignments(t.Context(), member.lease.AccessToken, now)
	if err != nil || len(assignments.Services) != 1 {
		t.Error("installed assignment depended on bootstrap issuer", assignments, err)
	} else {
		current := assignments.Services[0]
		prepared, err := d.PrepareServiceRun(t.Context(), current.ServiceID, access.PublisherIdentity, "issuer-independent-after-rollback", now, metadata, &assignments.Environment)
		if err != nil {
			t.Fatal("installed publisher could not prepare its current application", err)
		}
		run, err := d.StartServiceRun(t.Context(), current.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
			t.Error("current installed run could not renew independently", err)
		}
	}
	creation.ActorID = manager.IdentityID
	if _, err := d.CreateEnvironment(t.Context(), creation); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("idempotent creation bypassed current manager authorization", err)
	}
	var count int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.publisher_grants WHERE publisher_identity_id=$1`, member.member.PublisherIdentityID).Scan(&count); err != nil || count != 1 {
		t.Fatal("rollback minted new derivative authority", count, err)
	}
}

func TestIntegrationEnvironmentRetirementAndStorageRotation(t *testing.T) {
	d, url, now := newControlStateIntegrationDatabaseWithURL(t, "environment_rotation")
	r := retainedEnvironmentProject(t, d, now)
	d1 := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	digest := sha256.Sum256([]byte("tnl-target-tls/v1\x00equipment.internal\x00"))
	trust := &ProjectTargetTLS{Hostname: "equipment.internal", Digest: hex.EncodeToString(digest[:])}
	active, _ := createTestEnvironment(t, d, r, "active", d1.Revision, EnvironmentTargets{"api": {Address: "active.internal:8443", TLS: trust}})
	retired, creation := createTestEnvironment(t, d, r, "retired", d1.Revision, EnvironmentTargets{"api": {Address: "retired.internal:8443", TLS: trust}})
	if err := d.RetireEnvironment(t.Context(), RetireEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentID: retired.ID, ExpectedRevision: 1, Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateEnvironment(t.Context(), creation); !errors.Is(err, ErrEnvironmentRetired) {
		t.Fatal("retired creation key was reusable", err)
	}
	creation.IdempotencyKey = "another-key"
	if _, err := d.CreateEnvironment(t.Context(), creation); !errors.Is(err, ErrEnvironmentRetired) {
		t.Fatal("retired static name was reused", err)
	}
	var ciphertext []byte
	if err := d.pool.QueryRow(t.Context(), `SELECT bindings_ciphertext FROM control.publisher_group_bindings binding JOIN control.environments environment ON environment.group_id=binding.group_id WHERE environment.id=$1`, active.ID).Scan(&ciphertext); err != nil || bytes.Contains(ciphertext, []byte("active.internal")) {
		t.Fatal("environment targets were not encrypted", err)
	}
	d.Close()
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{19}, 32))
	rotating, err := Open(t.Context(), url, newKey, testStorageKey, naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rotating.Close)
	if err := rotating.CompleteStorageKeyRotation(t.Context()); err != nil {
		t.Fatal(err)
	}
	rotating.Close()
	reopened, err := Open(t.Context(), url, newKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	for _, before := range []Environment{active, retired} {
		after, err := reopened.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, before.ID, r.ActorID)
		if err != nil || after.ID != before.ID || !reflect.DeepEqual(after.Targets, before.Targets) || after.Retired != (before.ID == retired.ID) {
			t.Fatal("active or retired binding lost after key rotation", after, err)
		}
		if !after.Retired && !reflect.DeepEqual(after.Services, before.Services) {
			t.Fatal("key rotation changed saved endpoints")
		}
	}
}
