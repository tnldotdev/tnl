package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestIntegrationAppliedProjectPrivateOwnershipTransitions(t *testing.T) {
	for _, worktrees := range []int{0, 2} {
		for _, members := range []int{0, 2} {
			for _, active := range []bool{false, true} {
				for _, extra := range []bool{false, true} {
					t.Run(fmt.Sprintf("worktrees=%d/members=%d/active=%t/extra=%t", worktrees, members, active, extra), func(t *testing.T) { testAppliedPrivateOwnershipTransitions(t, worktrees, members, active, extra) })
				}
			}
		}
	}
}

func testAppliedPrivateOwnershipTransitions(t *testing.T, worktrees, members int, active, extra bool) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	ctx := t.Context()
	r := retainedEnvironmentProject(t, d, now)
	if _, err := d.pool.Exec(ctx, `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	reader := addAuthorityMember(t, d, now, r.ActorID, r.TeamID, "ownership-reader", TeamRoleMember)
	outsider := finalVisitorIdentity(t, d, now, "ownership-outsider@example.test")
	trust := appliedTargetTrust(t, "database.internal")
	local := LocalServiceDeclaration{Name: "database", Protocol: "postgres", Target: "localhost:5432", TargetTLS: trust, Access: &ProjectServiceAccess{Team: true}}
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"db": {Protocol: "postgres"}})
	var count int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.services WHERE team_id=$1`, r.TeamID).Scan(&count); err != nil || count != 0 {
		t.Fatal("definition allocated local resources", err)
	}
	environment, creation := createTestEnvironment(t, d, r, "production", definition.Revision, EnvironmentTargets{"db": {Address: "database.internal:5432", TLS: trust}})
	var replicas []environmentPublisherReplica
	enroll := func(e Environment) {
		t.Helper()
		enrollment := retainedPublisherEnrollment(t, d, r, e, 2)
		for range 2 {
			replicas = append(replicas, retainedPublisherReplica(t, d, enrollment, now))
		}
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.RedeemEnvironmentPublisherEnrollment(ctx, enrollment.Key, public, now); !errors.Is(err, ErrEnvironmentPublisher) {
			t.Fatal("enrollment capacity bypass", err)
		}
	}
	if members != 0 {
		enroll(environment)
	}
	var locals []appliedPrivateResource
	for i := range worktrees {
		request := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "db", WorktreeKey: fmt.Sprintf("checkout-%d", i), ActorID: r.ActorID, Configuration: local, Now: now}
		value, err := d.RealizeLocalProjectService(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		retry, err := d.RealizeLocalProjectService(ctx, request)
		if err != nil || !reflect.DeepEqual(value, retry) || value.Kind != "service" || value.Metadata == nil || value.Metadata.PublisherPool {
			t.Fatal("local realization changed identity/metadata", err)
		}
		resource := inspectAppliedPrivateResource(t, d, r, value.ServiceID, localProjectPrivateName(request, local.Name), false, trust, outsider, extra)
		if active {
			enrollment := publisherEnrollment(t, d, CreatePublicURLRequest{TeamID: r.TeamID, ActingIdentityID: r.ActorID}, PublisherScope{TeamID: r.TeamID, Kind: "service", ServiceID: value.ServiceID}, now)
			public, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, now)
			if err != nil {
				t.Fatal(err)
			}
			access := publisherAccess(t, d, publisher, key, "", now)
			resource.access = append(resource.access, access)
			resource.runs = append(resource.runs, readyAppliedServiceRun(t, d, access, key, resource.record, leases, now, nil))
		}
		locals = append(locals, resource)
	}
	assertPrivateOwnershipInventory(t, d, reader.IdentityID, locals, active, now)
	if extra {
		assertPrivateOwnershipInventory(t, d, outsider, locals, active, now)
	} else {
		assertPrivateOwnershipInventory(t, d, outsider, nil, false, now)
	}
	shared := inspectAppliedPrivateResource(t, d, r, environment.Services[0].ServiceID, "db", true, trust, outsider, extra)
	for _, resource := range locals {
		if resource.record.ID == shared.record.ID {
			t.Fatal("environment adopted a worktree resource")
		}
	}
	if members == 0 && active {
		enroll(environment)
	}
	assertPrivateOwnershipAssignments(t, d, replicas, environment, now)
	for _, replica := range replicas {
		a := replica.assignments.Services[0]
		access := environmentAssignmentAccess(t, d, replica, a, now)
		shared.access = append(shared.access, access)
		approved, err := d.GetServiceForPublisher(ctx, shared.record.ID, access.PublisherIdentity, now)
		if err != nil || !reflect.DeepEqual(approved, shared.record) {
			t.Fatal("exact assignment changed approved metadata", err)
		}
		if active {
			shared.runs = append(shared.runs, readyAppliedServiceRun(t, d, access, replica.private, approved, leases, now, &replica.assignments.Environment))
		}
	}
	resources := append(slices.Clone(locals), shared)
	assertPrivateOwnershipInventory(t, d, reader.IdentityID, resources, active && len(replicas) > 0, now)
	if extra {
		assertPrivateOwnershipInventory(t, d, outsider, resources, active && len(replicas) > 0, now)
	}
	if _, err := d.GetEnvironment(ctx, r.TeamID, r.ProjectKey, environment.ID, reader.IdentityID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("visitor read management configuration", err)
	}
	projection, err := d.GetProjectPublicMetadata(ctx, r.TeamID, r.ProjectKey, r.ActorID, now)
	if err != nil || len(projection.Services) != 0 {
		t.Fatal("private service leaked into public metadata", err)
	}
	if _, err := d.GetProjectPublicMetadata(ctx, r.TeamID, r.ProjectKey, reader.IdentityID, now); !errors.Is(err, ErrPublicURLAccess) {
		t.Fatal("private visitor read public project metadata", err)
	}
	// creation replay is idempotent even with live runs and explicit grants.
	before := privateOwnershipSnapshot(t, d)
	if _, err := d.CreateEnvironment(ctx, creation); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, privateOwnershipSnapshot(t, d)) {
		t.Fatal("creation replay changed resources/grants/runs")
	}
	rollback := worktrees == 2 && members == 2 && active && extra
	if rollback {
		assertPrivateOwnershipRollback(t, d, r, environment)
	}
	if err := d.RetireEnvironment(ctx, RetireEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentID: environment.ID, ExpectedRevision: environment.MutationRevision, Now: now}); err != nil {
		t.Fatal(err)
	}
	assertAppliedPrivateRetired(t, d, r, shared)
	for _, replica := range replicas {
		if _, err := d.GetEnvironmentPublisherAssignments(ctx, replica.lease.AccessToken, now); !errors.Is(err, ErrEnvironmentPublisher) {
			t.Fatal("retirement retained publisher lease", err)
		}
	}
	assertPrivateOwnershipInventory(t, d, reader.IdentityID, locals, active, now)
	if extra {
		assertPrivateOwnershipInventory(t, d, outsider, locals, active, now)
	} else {
		assertPrivateOwnershipInventory(t, d, outsider, nil, false, now)
	}
	assertPrivateOwnershipLocalCount(t, d, r, worktrees)
	// remote retirement never retires local worktrees. restarting each preserves
	// its existing exact ID, grants and runs instead of resurrecting the remote ID.
	for i, resource := range locals {
		value, err := d.RealizeLocalProjectService(ctx, RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "db", WorktreeKey: fmt.Sprintf("checkout-%d", i), ActorID: r.ActorID, Configuration: local, Now: now})
		if err != nil || value.ServiceID != resource.record.ID || value.ServiceID == shared.record.ID {
			t.Fatal("remote retirement altered local ownership", err)
		}
	}
	next, _ := createTestEnvironment(t, d, r, "production-next", definition.Revision, creation.Targets)
	if next.Services[0].ServiceID == shared.record.ID {
		t.Fatal("recreated environment resurrected retired service")
	}
	for _, resource := range locals {
		if next.Services[0].ServiceID == resource.record.ID {
			t.Fatal("recreated environment adopted local resource")
		}
	}
	replicas = nil
	enroll(next)
	assertPrivateOwnershipAssignments(t, d, replicas, next, now)
}

type appliedPrivateResource struct {
	record ServiceRecord
	grants []ServiceGrant
	access []PublisherAccess
	runs   []ServiceRunState
}

func inspectAppliedPrivateResource(t *testing.T, d *Database, r environmentPublisherTestProject, id, name string, pool bool, target *ProjectTargetTLS, outsider string, extra bool) appliedPrivateResource {
	t.Helper()
	ctx := t.Context()
	value, err := d.GetService(ctx, id, r.ActorID)
	trust, trustErr := appliedServiceTargetTrust(target)
	if err != nil || trustErr != nil || !opaqueid.Valid(id, opaqueid.ServicePrefix) || value.ID != id || value.TeamID != r.TeamID || value.Name != name || !value.Enabled || value.Protocol != "postgres" || value.PublisherPool != pool || value.TrustRevision != 1 || !reflect.DeepEqual(value.TLS, trust) {
		t.Fatal("incorrect saved private resource", err)
	}
	grants, _, err := d.ListServiceGrants(ctx, id, r.ActorID, "")
	if err != nil {
		t.Fatal(err)
	}
	if pool {
		if len(grants) != 0 {
			t.Fatal("environment materialization manufactured visitors")
		}
		for _, scope := range []struct{ kind, identity string }{{"identity", r.ActorID}, {"team", ""}} {
			g, err := d.CreateServiceGrant(ctx, id, r.ActorID, "ownership/"+scope.kind, ""+scope.kind, scope.identity, nil, r.Now)
			if err != nil {
				t.Fatal(err)
			}
			grants = append(grants, g)
		}
	}
	if len(grants) != 2 {
		t.Fatal("owner/team visitor scope not exact", len(grants))
	}
	owner, team := false, false
	for _, g := range grants {
		if g.ServiceID != id || g.RevokedAt != nil {
			t.Fatal("noncurrent or inexact visitor grant")
		}
		owner = owner || g.Kind == "identity" && g.IdentityID == r.ActorID
		team = team || g.Kind == "team" && g.IdentityID == ""
		if !pool && g.Kind == "team" {
			if err := d.RevokeServiceGrant(ctx, id, r.ActorID, g.ID, r.Now); !errors.Is(err, ErrProjectManaged) {
				t.Fatal("local declarative grant ownership lost", err)
			}
		}
	}
	if !owner || !team {
		t.Fatal("visitor grants inherited from another resource")
	}
	if extra {
		g, err := d.CreateServiceGrant(ctx, id, r.ActorID, "extra/"+id, "identity", outsider, nil, r.Now)
		if err != nil {
			t.Fatal(err)
		}
		grants = append(grants, g)
	}
	if err := d.DeleteService(ctx, id, r.ActorID, r.Now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("definition ownership lost", err)
	}
	return appliedPrivateResource{record: value, grants: grants}
}

func assertPrivateOwnershipAssignments(t *testing.T, d *Database, replicas []environmentPublisherReplica, environment Environment, now time.Time) {
	t.Helper()
	var count int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.publisher_group_service_grants mapping JOIN control.publisher_group_members member ON member.publisher_identity_id=mapping.publisher_identity_id JOIN control.environments environment ON environment.group_id=member.group_id WHERE environment.id=$1`, environment.ID).Scan(&count); err != nil || count != len(replicas) {
		t.Fatal("exact publisher grants", count, err)
	}
	for _, replica := range replicas {
		assignments, err := d.GetEnvironmentPublisherAssignments(t.Context(), replica.lease.AccessToken, now)
		if err != nil || assignments.Environment != environmentPublicationForTest(environment) || len(assignments.Services) != 1 {
			t.Fatal("publisher lost exact current application", err)
		}
		a := assignments.Services[0]
		if a.Service != "db" || a.ServiceID != environment.Services[0].ServiceID || a.TrustRevision != environment.Services[0].TrustRevision || a.Configuration.Protocol != "postgres" || a.Configuration.Target != environment.Targets["db"].Address {
			t.Fatal("wrong assigned resource/metadata")
		}
		var exact bool
		if err := d.pool.QueryRow(t.Context(), `SELECT kind='service' AND service_id=$2 AND public_url_id IS NULL AND revoked_at IS NULL FROM control.publisher_grants WHERE id=$1 AND publisher_identity_id=$3`, a.GrantID, a.ServiceID, replica.member.PublisherIdentityID).Scan(&exact); err != nil || !exact {
			t.Fatal("grant not exact", err)
		}
		if err := d.AcknowledgeEnvironmentPublisher(t.Context(), replica.lease.AccessToken, assignments.Environment, true, now); err != nil {
			t.Fatal(err)
		}
	}
}

func assertPrivateOwnershipInventory(t *testing.T, d *Database, actor string, resources []appliedPrivateResource, ready bool, now time.Time) {
	t.Helper()
	items, _, err := d.ListAvailableServices(t.Context(), actor, "", now)
	if err != nil || len(items) != len(resources) {
		t.Fatal("visitor inventory scope", items, err)
	}
	for _, resource := range resources {
		index := slices.IndexFunc(items, func(item ServiceInventory) bool { return item.ID == resource.record.ID })
		if index < 0 || !reflect.DeepEqual(items[index].ServiceMetadata, resource.record.ServiceMetadata) || (items[index].ServiceRunID != "") != ready {
			t.Fatal("inventory metadata/readiness", items)
		}
	}
}

func assertPrivateOwnershipLocalCount(t *testing.T, d *Database, r environmentPublisherTestProject, want int) {
	t.Helper()
	var count int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.local_project_services WHERE team_id=$1 AND project_key=$2`, r.TeamID, r.ProjectKey).Scan(&count); err != nil || count != want {
		t.Fatal("local scope count", count, err)
	}
}

func assertAppliedPrivateRetired(t *testing.T, d *Database, r environmentPublisherTestProject, resource appliedPrivateResource) {
	t.Helper()
	ctx := t.Context()
	var retired bool
	if err := d.pool.QueryRow(ctx, `SELECT NOT enabled AND deleted_at IS NOT NULL FROM control.services WHERE id=$1`, resource.record.ID).Scan(&retired); err != nil || !retired {
		t.Fatal("resource not retired", err)
	}
	for _, grant := range resource.grants {
		if err := d.pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM control.visitor_grants WHERE id=$1`, grant.ID).Scan(&retired); err != nil || !retired {
			t.Fatal("visitor grant survived", err)
		}
	}
	for _, access := range resource.access {
		if err := d.pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM control.publisher_grants WHERE id=$1`, access.GrantID).Scan(&retired); err != nil || !retired {
			t.Fatal("publisher grant survived", err)
		}
		if _, err := d.AuthenticatePublisherAccess(ctx, access.Token, "", r.Now); !errors.Is(err, ErrPublisherIdentity) {
			t.Fatal("access token survived retirement", err)
		}
		if _, err := d.GetServiceForPublisher(ctx, resource.record.ID, access.PublisherIdentity, r.Now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("retired metadata remained readable", err)
		}
	}
	for _, run := range resource.runs {
		if _, err := d.HeartbeatServiceRun(ctx, run.ServiceID, run.RunID, run.Token, r.Now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("run survived retirement", err)
		}
		if err := d.pool.QueryRow(ctx, `SELECT state='closed' AND closed_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM control.service_connection_slots WHERE service_run_id=$1 AND session_open) FROM control.service_runs WHERE id=$1`, run.RunID).Scan(&retired); err != nil || !retired {
			t.Fatal("retirement left slot/run open", err)
		}
	}
}

func readyAppliedServiceRun(t *testing.T, d *Database, access PublisherAccess, key ed25519.PrivateKey, service ServiceRecord, leases map[string]RelayLease, now time.Time, environment *EnvironmentPublication) ServiceRunState {
	t.Helper()
	prepared, err := d.PrepareServiceRun(t.Context(), service.ID, access.PublisherIdentity, "ownership", now, service.ServiceMetadata, environment)
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	installPrivateTestCertificate(t, d, prepared, run, now)
	for _, slot := range run.Connections {
		lease := leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := d.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadyServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	if state, err := d.HeartbeatServiceRun(t.Context(), service.ID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "ready" {
		t.Fatal("service run not ready", err)
	}
	return run
}

func assertPrivateOwnershipRollback(t *testing.T, d *Database, r environmentPublisherTestProject, e Environment) {
	t.Helper()
	ctx := t.Context()
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"db": {Protocol: "postgres"}, "a-new": {Protocol: "tcp"}, "zz-conflict": {Protocol: "tcp"}})
	request := ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: e.ID, ExpectedRevision: e.MutationRevision, DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"db": {Address: "replacement.internal:5432", TLS: e.Targets["db"].TLS}, "a-new": {Address: "localhost:9000"}, "zz-conflict": {Address: "localhost:9001"}}}, Now: r.Now}
	if _, err := d.pool.Exec(ctx, `ALTER TABLE control.services ADD CONSTRAINT reject_late_service CHECK (name<>'zz-conflict')`); err != nil {
		t.Fatal(err)
	}
	before := privateOwnershipSnapshot(t, d)
	for range 2 {
		_, err := d.ApplyEnvironment(ctx, request)
		var constraint *pgconn.PgError
		if !errors.As(err, &constraint) || constraint.Code != "23514" || constraint.ConstraintName != "reject_late_service" {
			t.Fatal("expected late materialization failure", err)
		}
		if !reflect.DeepEqual(before, privateOwnershipSnapshot(t, d)) {
			t.Fatal("late failure changed resource/grant/run state")
		}
	}
	if _, err := d.pool.Exec(ctx, `ALTER TABLE control.services DROP CONSTRAINT reject_late_service`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, fmt.Sprintf(`ALTER TABLE control.environments ADD CONSTRAINT reject_ownership_transition CHECK (mutation_revision<=%d AND retired_at IS NULL)`, e.MutationRevision)); err != nil {
		t.Fatal(err)
	}
	request.DefinitionRevision = e.AppliedDefinitionRevision
	request.Targets = EnvironmentTargets{"db": {Address: "replacement.internal:5432", TLS: e.Targets["db"].TLS}}
	for _, operation := range []func() error{func() error { _, err := d.ApplyEnvironment(ctx, request); return err }, func() error {
		return d.RetireEnvironment(ctx, RetireEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentID: e.ID, ExpectedRevision: e.MutationRevision, Now: r.Now})
	}} {
		_, _ = before, request
		err := operation()
		var constraint *pgconn.PgError
		if !errors.As(err, &constraint) || constraint.Code != "23514" || constraint.ConstraintName != "reject_ownership_transition" {
			t.Fatal("expected final revision/retirement write failure", err)
		}
		if !reflect.DeepEqual(before, privateOwnershipSnapshot(t, d)) {
			t.Fatal("final failure committed retirement/replacement")
		}
	}
	if _, err := d.pool.Exec(ctx, `ALTER TABLE control.environments DROP CONSTRAINT reject_ownership_transition`); err != nil {
		t.Fatal(err)
	}
}

func privateOwnershipSnapshot(t *testing.T, d *Database) map[string]string {
	t.Helper()
	result := map[string]string{}
	for _, table := range []string{"applied_projects", "service_definitions", "environments", "environment_creations", "applied_project_services", "local_project_services", "project_publisher_groups", "publisher_group_bindings", "publisher_group_service_grants", "services", "visitor_grants", "publisher_grants", "service_runs", "publisher_service_connection_slots", "connector_peer_pairs", "service_audit_events"} {
		var rows string
		if err := d.pool.QueryRow(t.Context(), `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM control.`+table+` r`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		result[table] = rows
	}
	return result
}
