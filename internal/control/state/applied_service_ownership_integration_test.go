package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
					t.Run(fmt.Sprintf("worktrees=%d/members=%d/active=%t/extra=%t", worktrees, members, active, extra), func(t *testing.T) {
						testAppliedPrivateOwnershipTransitions(t, worktrees, members, active, extra)
					})
				}
			}
		}
	}
}

func testAppliedPrivateOwnershipTransitions(t *testing.T, worktrees, members int, active, extra bool) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	if _, err := d.pool.Exec(ctx, `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	reader := addAuthorityMember(t, d, now, r.ActorID, r.TeamID, "ownership-reader", TeamRoleMember)
	outsider := finalVisitorIdentity(t, d, now, "ownership-outsider@example.test")
	digest := sha256.Sum256([]byte("tnl-target-tls/v1\x00database.internal\x00"))
	local := ProjectServiceConfiguration{Name: "database", Protocol: "postgres", Target: "localhost:5432", TargetTLS: &ProjectTargetTLS{Hostname: "database.internal", Digest: hex.EncodeToString(digest[:])}, Access: &ProjectServiceAccess{Team: true}}
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{"db": local}}
	initial := applyPrivateOwnershipRevision(t, d, r)
	assertPrivateOwnershipEntry(t, d, r, initial, "local")
	var replicas []enrolledGroupReplica
	enroll := func() {
		e, err := d.IssuePublisherGroupEnrollment(ctx, r.TeamID, r.ProjectKey, "production", r.ActorID, 2, time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			replicas = append(replicas, enrollAppliedGroup(t, d, r, e, now))
		}
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = d.RedeemPublisherGroupEnrollment(ctx, e.Key, public, now); !errors.Is(err, ErrPublisherGroup) {
			t.Fatal("ownership transition bypassed enrollment capacity", err)
		}
	}
	if members != 0 {
		enroll()
	}
	assertPrivateOwnershipAssignments(t, d, replicas, initial, now)
	realize := func() []appliedPrivateResource {
		var resources []appliedPrivateResource
		for i := range worktrees {
			request := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "db", WorktreeKey: fmt.Sprintf("checkout-%d", i), ActorID: r.ActorID, Configuration: local, Now: now}
			value, err := d.RealizeLocalProjectService(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			retry, err := d.RealizeLocalProjectService(ctx, request)
			if err != nil || !reflect.DeepEqual(value, retry) || value.Kind != "service" || value.Metadata == nil || value.Metadata.PublisherPool {
				t.Fatal("local realization lost its independent resource", value, retry, err)
			}
			resource := inspectAppliedPrivateResource(t, d, r, value.ServiceID, localProjectPrivateName(request, local.Name), false, outsider, extra)
			if active {
				e := publisherEnrollment(t, d, CreatePublicURLRequest{TeamID: r.TeamID, ActingIdentityID: r.ActorID}, PublisherScope{TeamID: r.TeamID, Kind: "service", ServiceID: value.ServiceID}, now)
				public, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				publisher, err := d.RedeemPublisherEnrollment(ctx, e.Key, public, now)
				if err != nil {
					t.Fatal(err)
				}
				access := publisherAccess(t, d, publisher, key, "", now)
				resource.access = append(resource.access, access)
				resource.runs = append(resource.runs, readyAppliedServiceRun(t, d, access, key, resource.record, leases, now))
			}
			resources = append(resources, resource)
		}
		assertPrivateOwnershipInventory(t, d, reader.IdentityID, resources, active, now)
		if extra {
			assertPrivateOwnershipInventory(t, d, outsider, resources, active, now)
		} else {
			assertPrivateOwnershipInventory(t, d, outsider, nil, false, now)
		}
		return resources
	}
	locals := realize()
	remote := local
	remote.PublisherGroup, remote.Target = "production", "database.internal:5432"
	r.ExpectedRevision = initial.Revision
	r.Configuration.Services["db"] = remote
	// exercise rollback after remote allocation/grants, and after remote retirement
	// on the reverse transition. the conflicting name belongs to another definition.
	rollback := worktrees == 2 && members == 2 && active && extra
	if rollback {
		assertPrivateOwnershipRollback(t, d, r)
	}
	group := applyPrivateOwnershipRevision(t, d, r)
	assertPrivateOwnershipEntry(t, d, r, group, "production")
	for _, resource := range locals {
		assertAppliedPrivateRetired(t, d, r, resource)
		if resource.record.ID == group.Services[0].ServiceID {
			t.Fatal("group adopted a worktree resource")
		}
	}
	assertPrivateOwnershipLocalCount(t, d, r, 0)
	shared := inspectAppliedPrivateResource(t, d, r, group.Services[0].ServiceID, local.Name, true, outsider, extra)
	assertPrivateOwnershipAssignments(t, d, replicas, group, now)
	if members == 0 && active {
		// enrollment after a committed apply must receive the same valid resource.
		enroll()
	}
	for _, replica := range replicas {
		assignments, err := d.GetPublisherGroupAssignments(ctx, replica.lease.AccessToken, now)
		if err != nil || len(assignments.Services) != 1 {
			t.Fatal("group cannot read its private assignment", err)
		}
		access := groupAssignmentAccess(t, d, replica, assignments.Services[0], now)
		shared.access = append(shared.access, access)
		approved, err := d.GetServiceForPublisher(ctx, shared.record.ID, access.PublisherIdentity, now)
		if err != nil || !reflect.DeepEqual(approved, shared.record) {
			t.Fatal("assignment did not authorize exact saved metadata", approved, err)
		}
		if active {
			shared.runs = append(shared.runs, readyAppliedServiceRun(t, d, access, replica.private, approved, leases, now))
		}
	}
	assertPrivateOwnershipAssignments(t, d, replicas, group, now)
	assertPrivateOwnershipInventory(t, d, reader.IdentityID, []appliedPrivateResource{shared}, active, now)
	if extra {
		assertPrivateOwnershipInventory(t, d, outsider, []appliedPrivateResource{shared}, active, now)
	}
	if _, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, reader.IdentityID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("visitor read manager configuration", err)
	}
	projection, err := d.GetProjectPublicMetadata(ctx, r.TeamID, r.ProjectKey, r.ActorID, now)
	if err != nil || len(projection.Services) != 0 {
		t.Fatal("private resource leaked into public metadata", projection, err)
	}
	if _, err = d.GetProjectPublicMetadata(ctx, r.TeamID, r.ProjectKey, reader.IdentityID, now); !errors.Is(err, ErrPublicURLAccess) {
		t.Fatal("private visitor permission authorized public project metadata", err)
	}
	applyPrivateOwnershipRevision(t, d, r)
	r.ExpectedRevision = group.Revision
	r.Configuration.Services["db"] = local
	if rollback {
		assertPrivateOwnershipRollback(t, d, r)
	}
	deferred := applyPrivateOwnershipRevision(t, d, r)
	assertPrivateOwnershipEntry(t, d, r, deferred, "local")
	assertAppliedPrivateRetired(t, d, r, shared)
	assertPrivateOwnershipLocalCount(t, d, r, 0)
	assertPrivateOwnershipAssignments(t, d, replicas, deferred, now)
	assertPrivateOwnershipInventory(t, d, reader.IdentityID, nil, false, now)
	assertPrivateOwnershipInventory(t, d, outsider, nil, false, now)
	newLocals := realize()
	for _, resource := range newLocals {
		if resource.record.ID == shared.record.ID {
			t.Fatal("local runtime adopted the retired group resource")
		}
		for _, old := range locals {
			if resource.record.ID == old.record.ID {
				t.Fatal("local runtime resurrected a retired worktree resource")
			}
		}
	}
	assertPrivateOwnershipLocalCount(t, d, r, worktrees)
	// repeating either normalized hash preserves grants and realizations too.
	applyPrivateOwnershipRevision(t, d, r)
	r.ExpectedRevision = deferred.Revision
	r.Configuration.Services["db"] = remote
	regrouped := applyPrivateOwnershipRevision(t, d, r)
	assertPrivateOwnershipEntry(t, d, r, regrouped, "production")
	if regrouped.Services[0].ServiceID == shared.record.ID {
		t.Fatal("reusing a definition name resurrected its retired resource")
	}
	for _, resource := range newLocals {
		assertAppliedPrivateRetired(t, d, r, resource)
	}
	assertPrivateOwnershipAssignments(t, d, replicas, regrouped, now)
	if len(replicas) == 0 {
		enroll()
		assertPrivateOwnershipAssignments(t, d, replicas, regrouped, now)
	}
}

type appliedPrivateResource struct {
	record ServiceRecord
	grants []ServiceGrant
	access []PublisherAccess
	runs   []ServiceRunState
}

func inspectAppliedPrivateResource(t *testing.T, d *Database, r ApplyProjectConfigurationRequest, id, name string, pool bool, outsider string, extra bool) appliedPrivateResource {
	t.Helper()
	ctx := t.Context()
	value, err := d.GetService(ctx, id, r.ActorID)
	trust, trustErr := appliedServiceTargetTrust(r.Configuration.Services["db"].TargetTLS)
	if err != nil || trustErr != nil || !opaqueid.Valid(id, opaqueid.ServicePrefix) || value.ID != id || value.TeamID != r.TeamID || value.Name != name || !value.Enabled || value.Protocol != "postgres" || value.PublisherPool != pool || value.TrustRevision != 1 || !reflect.DeepEqual(value.TLS, trust) {
		t.Fatal("incorrect saved private resource", value, err)
	}
	grants, _, err := d.ListServiceGrants(ctx, id, r.ActorID, "")
	if err != nil || len(grants) != 2 {
		t.Fatal("new resource must have exactly owner and configured team grants", grants, err)
	}
	owner, team := false, false
	for _, g := range grants {
		if g.ServiceID != id || g.RevokedAt != nil {
			t.Fatal("new visitor grant is not exact and current", g)
		}
		owner = owner || g.Kind == "identity" && g.IdentityID == r.ActorID
		team = team || g.Kind == "team" && g.IdentityID == ""
		if g.Kind == "team" {
			if err = d.RevokeServiceGrant(ctx, id, r.ActorID, g.ID, r.Now); !errors.Is(err, ErrProjectManaged) {
				t.Fatal("transition lost configured visitor grant ownership", err)
			}
		}
	}
	if !owner || !team {
		t.Fatal("new resource inherited old visitor grants", grants)
	}
	if extra {
		g, err := d.CreateServiceGrant(ctx, id, r.ActorID, "extra/"+id, "identity", outsider, nil, r.Now)
		if err != nil {
			t.Fatal(err)
		}
		grants = append(grants, g)
	}
	if err = d.DeleteService(ctx, id, r.ActorID, r.Now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("transition lost definition ownership", err)
	}
	return appliedPrivateResource{record: value, grants: grants}
}

func assertPrivateOwnershipEntry(t *testing.T, d *Database, r ApplyProjectConfigurationRequest, status AppliedProjectConfiguration, publisher string) {
	t.Helper()
	if len(status.Services) != 1 || status.Services[0].Service != "db" || status.Services[0].PublisherGroup != publisher || status.Services[0].DesiredRevision != status.Revision {
		t.Fatal("incorrect applied service", status.Services)
	}
	s := status.Services[0]
	var privateID, publicID, groupID, visitorGrant string
	if err := d.pool.QueryRow(t.Context(), `SELECT COALESCE(service_id,''),COALESCE(public_url_id,''),COALESCE(group_id,''),COALESCE(visitor_grant_id,'') FROM control.applied_project_services WHERE team_id=$1 AND project_key=$2 AND service='db'`, r.TeamID, r.ProjectKey).Scan(&privateID, &publicID, &groupID, &visitorGrant); err != nil {
		t.Fatal(err)
	}
	if publisher == "local" {
		if s.Kind != "local" || s.ServiceID != "" || s.TrustRevision != 0 || privateID != "" || publicID != "" || groupID != "" || visitorGrant != "" {
			t.Fatal("local apply must defer resource and grant allocation", s)
		}
	} else if s.Kind != "service" || !opaqueid.Valid(s.ServiceID, opaqueid.ServicePrefix) || privateID != s.ServiceID || publicID != "" || groupID == "" || visitorGrant == "" || s.TrustRevision != 1 {
		t.Fatal("group apply committed an incomplete private resource", s)
	}
}

func assertPrivateOwnershipAssignments(t *testing.T, d *Database, replicas []enrolledGroupReplica, status AppliedProjectConfiguration, now time.Time) {
	t.Helper()
	want := len(replicas)
	if status.Services[0].Kind == "local" {
		want = 0
	}
	var count int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.publisher_group_service_grants WHERE team_id=$1 AND project_key=$2`, status.TeamID, status.ProjectKey).Scan(&count); err != nil || count != want {
		t.Fatal("unexpected exact group grants", count, err)
	}
	for _, replica := range replicas {
		assignments, err := d.GetPublisherGroupAssignments(t.Context(), replica.lease.AccessToken, now)
		if err != nil || assignments.Revision != status.Revision || assignments.ConfigurationHash != status.ConfigurationHash {
			t.Fatal("group lost current configuration", err)
		}
		if status.Services[0].Kind == "local" {
			if len(assignments.Services) != 0 {
				t.Fatal("group retained a local assignment")
			}
			continue
		}
		if len(assignments.Services) != 1 {
			t.Fatal("group lost its private assignment")
		}
		a := assignments.Services[0]
		if a.Service != "db" || a.Kind != "service" || a.ServiceID != status.Services[0].ServiceID || a.TrustRevision != status.Services[0].TrustRevision || !reflect.DeepEqual(a.Configuration, status.Configuration.Services["db"]) {
			t.Fatal("group received wrong private resource or metadata", a)
		}
		var exact bool
		if err = d.pool.QueryRow(t.Context(), `SELECT kind='service' AND service_id=$2 AND public_url_id IS NULL AND revoked_at IS NULL FROM control.publisher_grants WHERE id=$1 AND publisher_identity_id=$3`, a.GrantID, a.ServiceID, replica.member.PublisherIdentityID).Scan(&exact); err != nil || !exact {
			t.Fatal("group grant is not exact", err)
		}
		if err = d.AcknowledgePublisherGroupConfiguration(t.Context(), replica.lease.AccessToken, status.Revision, status.ConfigurationHash, true, now); err != nil {
			t.Fatal(err)
		}
	}
}

func assertPrivateOwnershipInventory(t *testing.T, d *Database, actor string, resources []appliedPrivateResource, ready bool, now time.Time) {
	t.Helper()
	items, _, err := d.ListAvailableServices(t.Context(), actor, "", now)
	if err != nil || len(items) != len(resources) {
		t.Fatal("visitor inventory retained old resources or lost current resources", items, err)
	}
	for _, resource := range resources {
		index := slices.IndexFunc(items, func(item ServiceInventory) bool { return item.ID == resource.record.ID })
		if index < 0 || !reflect.DeepEqual(items[index].ServiceMetadata, resource.record.ServiceMetadata) || (items[index].ServiceRunID != "") != ready {
			t.Fatal("authorized inventory lost exact metadata or readiness", items)
		}
	}
}

func assertPrivateOwnershipLocalCount(t *testing.T, d *Database, r ApplyProjectConfigurationRequest, want int) {
	t.Helper()
	var count int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.local_project_services WHERE team_id=$1 AND project_key=$2`, r.TeamID, r.ProjectKey).Scan(&count); err != nil || count != want {
		t.Fatal("unexpected realized worktree resources", count, err)
	}
}

func assertAppliedPrivateRetired(t *testing.T, d *Database, r ApplyProjectConfigurationRequest, resource appliedPrivateResource) {
	t.Helper()
	ctx := t.Context()
	var retired bool
	if err := d.pool.QueryRow(ctx, `SELECT NOT enabled AND deleted_at IS NOT NULL FROM control.services WHERE id=$1`, resource.record.ID).Scan(&retired); err != nil || !retired {
		t.Fatal("old resource was not retired", err)
	}
	for _, g := range resource.grants {
		if err := d.pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM control.visitor_grants WHERE id=$1`, g.ID).Scan(&retired); err != nil || !retired {
			t.Fatal("old visitor grant survived retirement", g.ID, err)
		}
	}
	for _, access := range resource.access {
		if err := d.pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM control.publisher_grants WHERE id=$1`, access.GrantID).Scan(&retired); err != nil || !retired {
			t.Fatal("old publisher grant survived retirement", err)
		}
		if _, err := d.AuthenticatePublisherAccess(ctx, access.Token, "", r.Now); !errors.Is(err, ErrPublisherIdentity) {
			t.Fatal("old publisher access survived retirement", err)
		}
		if _, err := d.GetServiceForPublisher(ctx, resource.record.ID, access.PublisherIdentity, r.Now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("old publisher still reads retired metadata", err)
		}
	}
	for _, run := range resource.runs {
		if _, err := d.HeartbeatServiceRun(ctx, run.ServiceID, run.RunID, run.Token, r.Now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("old run survived retirement", err)
		}
		if err := d.pool.QueryRow(ctx, `SELECT state='closed' AND closed_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM control.service_connection_slots WHERE service_run_id=$1 AND session_open) FROM control.service_runs WHERE id=$1`, run.RunID).Scan(&retired); err != nil || !retired {
			t.Fatal("retirement left a run or connection slot open", err)
		}
	}
}

func readyAppliedServiceRun(t *testing.T, d *Database, access PublisherAccess, key ed25519.PrivateKey, service ServiceRecord, leases map[string]RelayLease, now time.Time) ServiceRunState {
	t.Helper()
	prepared, err := d.PrepareServiceRun(t.Context(), service.ID, access.PublisherIdentity, "ownership", now, service.ServiceMetadata)
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
		if _, err = d.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err = d.ReadyServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	if state, err := d.HeartbeatServiceRun(t.Context(), service.ID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "ready" {
		t.Fatal("private assignment is not ready", err)
	}
	return run
}

func applyPrivateOwnershipRevision(t *testing.T, d *Database, r ApplyProjectConfigurationRequest) AppliedProjectConfiguration {
	t.Helper()
	status, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal("apply ownership transition", err)
	}
	before := privateOwnershipSnapshot(t, d)
	retry, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal("retry ownership transition", err)
	}
	if !reflect.DeepEqual(before, privateOwnershipSnapshot(t, d)) {
		t.Fatal("same-hash retry changed resources, grants, runs, or saved state")
	}
	// observation time is fresh on each read; all saved and derived facts must
	// remain equal. clone members so this comparison does not alter the result.
	first, repeated := status, retry
	first.Members, repeated.Members = slices.Clone(status.Members), slices.Clone(retry.Members)
	for _, members := range [][]PublisherGroupMemberStatus{first.Members, repeated.Members} {
		for i := range members {
			if members[i].SnapshotAt.IsZero() {
				t.Fatal("member status omitted its observation time")
			}
			members[i].SnapshotAt = time.Time{}
		}
	}
	if !reflect.DeepEqual(first, repeated) {
		t.Fatal("same-hash retry changed publisher or configuration facts")
	}
	return status
}

func assertPrivateOwnershipRollback(t *testing.T, d *Database, r ApplyProjectConfigurationRequest) {
	t.Helper()
	var err error
	r.Configuration, _, err = NormalizeProjectConfiguration(r.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	r.Configuration.Services["z-conflict"] = ProjectServiceConfiguration{PublisherGroup: "production", Name: "conflict", Target: "localhost:9000"}
	r.Configuration.Services["zz-conflict"] = r.Configuration.Services["z-conflict"]
	before := privateOwnershipSnapshot(t, d)
	for range 2 {
		if _, err = d.ApplyProjectConfiguration(t.Context(), r); !errors.Is(err, ErrServiceConflict) {
			t.Fatal("expected late definition name conflict", err)
		}
		if !reflect.DeepEqual(before, privateOwnershipSnapshot(t, d)) {
			t.Fatal("failed ownership transition changed resources, grants, runs, or desired state")
		}
	}
	// force a final revision-write failure, after local realizations have also
	// been retired. their grants, runs, slots, and routing must all roll back.
	delete(r.Configuration.Services, "z-conflict")
	delete(r.Configuration.Services, "zz-conflict")
	if _, err = d.pool.Exec(t.Context(), fmt.Sprintf(`ALTER TABLE control.applied_projects ADD CONSTRAINT reject_ownership_transition CHECK (revision <= %d)`, r.ExpectedRevision)); err != nil {
		t.Fatal(err)
	}
	_, err = d.ApplyProjectConfiguration(t.Context(), r)
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23514" || constraint.ConstraintName != "reject_ownership_transition" {
		t.Fatal("expected final revision-write failure", err)
	}
	if !reflect.DeepEqual(before, privateOwnershipSnapshot(t, d)) {
		t.Fatal("final write failure committed retirement or replacement")
	}
	if _, err = d.pool.Exec(t.Context(), `ALTER TABLE control.applied_projects DROP CONSTRAINT reject_ownership_transition`); err != nil {
		t.Fatal(err)
	}
}

func privateOwnershipSnapshot(t *testing.T, d *Database) map[string]string {
	t.Helper()
	result := map[string]string{}
	for _, table := range []string{"applied_projects", "applied_project_services", "local_project_services", "project_publisher_groups", "publisher_group_service_grants", "services", "visitor_grants", "publisher_grants", "service_runs", "publisher_service_connection_slots", "connector_peer_pairs", "service_audit_events"} {
		var rows string
		if err := d.pool.QueryRow(t.Context(), `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM control.`+table+` r`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		result[table] = rows
	}
	return result
}
