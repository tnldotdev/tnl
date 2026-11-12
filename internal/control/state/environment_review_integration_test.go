package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationEnvironmentEnrollmentStillChecksCurrentManager(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "environment_bootstrap_manager")
	r := appliedProjectRequest(t, d, now)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	manager := addAuthorityMember(t, d, now, r.ActorID, r.TeamID, "bootstrap-manager", TeamRoleAdmin)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	environment, _ := createTestEnvironment(t, d, r, "production", definition.Revision, EnvironmentTargets{"api": {Address: "current.internal:3000"}})
	var group string
	if err := d.pool.QueryRow(t.Context(), `SELECT group_id FROM control.environments WHERE id=$1`, environment.ID).Scan(&group); err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, group, manager.IdentityID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET role='member' WHERE id=$1`, manager.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, group, manager.IdentityID, 1, time.Hour, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("demoted bootstrap issuer could issue enrollment", err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.RedeemPublisherGroupEnrollment(t.Context(), enrollment.Key, public, now); !errors.Is(err, ErrPublisherGroup) {
		t.Fatal("uninstalled enrollment ignored current manager authority", err)
	}
}

func TestIntegrationEnvironmentStaleWorkerPreparation(t *testing.T) {
	for _, change := range []string{"target", "discovery"} {
		t.Run(change, func(t *testing.T) { testEnvironmentStaleWorkerPreparation(t, change) })
	}
}

func testEnvironmentStaleWorkerPreparation(t *testing.T, change string) {
	t.Helper()
	d, now, _, _ := newPublishRunPrerequisites(t)
	r := appliedProjectRequest(t, d, now)
	protocol := "http"
	oldTargets := EnvironmentTargets{"api": {Address: "old.internal:3000"}}
	newTargets := EnvironmentTargets{"api": {Address: "new.internal:3000"}}
	if change == "discovery" {
		protocol = "postgres"
		oldTargets = EnvironmentTargets{"api": {Discovery: &ProjectTargetDiscovery{Type: "rds", Region: "us-east-1", Instance: new("old-instance")}}}
		newTargets = EnvironmentTargets{"api": {Discovery: &ProjectTargetDiscovery{Type: "rds", Region: "us-east-1", Instance: new("new-instance")}}}
	}
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: protocol}})
	environment, _ := createTestEnvironment(t, d, r, "production", definition.Revision, oldTargets)
	member := enrollTestEnvironment(t, d, r, environment)
	assignment := member.assignments.Services[0]
	expected := EnvironmentPublication{EnvironmentID: environment.ID, MutationRevision: environment.MutationRevision, ConfigurationHash: environment.ConfigurationHash}
	if assignment.Environment == nil || *assignment.Environment != expected {
		t.Fatal("assignment did not carry its exact environment snapshot", assignment.Environment)
	}
	access := groupAssignmentAccess(t, d, member, assignment, now)
	metadata := ServiceMetadata{Protocol: protocol, PublisherPool: true, TrustRevision: assignment.TrustRevision}
	prepared, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "before-target-change", now, metadata, assignment.Environment)
	if err != nil {
		t.Fatal(err)
	}
	row, err := controlstatedb.New(d.pool).LockServiceRun(t.Context(), controlstatedb.LockServiceRunParams{ID: prepared.RunID, ServiceID: assignment.ServiceID})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := preparedEnvironmentPublication(row)
	if err != nil || !sameEnvironmentPublication(stored, assignment.Environment) {
		t.Fatal("prepared run did not persist the assigned fence", stored, err)
	}
	_, err = d.pool.Exec(t.Context(), `UPDATE control.service_runs SET environment_mutation_revision=environment_mutation_revision+1 WHERE id=$1`, prepared.RunID)
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23514" {
		t.Fatal("prepared environment fence was mutable", err)
	}
	apply := ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: environment.ID, ExpectedRevision: 1, DefinitionRevision: definition.Revision, Targets: newTargets}, Now: now}
	updated, err := d.ApplyEnvironment(t.Context(), apply)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Services[0].TrustRevision != assignment.TrustRevision {
		t.Fatal("target-only update changed TLS/protocol trust revision")
	}
	if _, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "stale-fresh-key", now, metadata, assignment.Environment); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("stale target worker prepared a new run with old snapshot and fresh key")
	}
	if _, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "missing-fence", now, metadata, nil); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("mapped service accepted omitted publication fence", err)
	}
	if _, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("pre-update preparation started after target replacement", err)
	}
	current, err := d.GetPublisherGroupAssignments(t.Context(), member.lease.AccessToken, now)
	if err != nil || len(current.Services) != 1 || current.Services[0].Environment == nil {
		t.Fatal(current, err)
	}
	fence := current.Services[0].Environment
	for name, wrong := range map[string]EnvironmentPublication{
		"wrong ID":       {EnvironmentID: "env_AAAAAAAAAAAAAAAAAAAAAA", MutationRevision: fence.MutationRevision, ConfigurationHash: fence.ConfigurationHash},
		"wrong revision": {EnvironmentID: fence.EnvironmentID, MutationRevision: fence.MutationRevision + 1, ConfigurationHash: fence.ConfigurationHash},
		"wrong hash":     {EnvironmentID: fence.EnvironmentID, MutationRevision: fence.MutationRevision, ConfigurationHash: fmt.Sprintf("%064d", 0)},
	} {
		if _, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, name, now, metadata, &wrong); !errors.Is(err, ErrServiceConflict) {
			t.Fatal("publication context was not checked exactly", name, err)
		}
	}
	valid, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "current-fence", now, metadata, fence)
	if err != nil {
		t.Fatal("current assigned fence could not prepare", err)
	}
	currentRow, err := controlstatedb.New(d.pool).LockServiceRun(t.Context(), controlstatedb.LockServiceRunParams{ID: valid.RunID, ServiceID: assignment.ServiceID})
	if err != nil || bytes.Equal(currentRow.RequestDigest, row.RequestDigest) {
		t.Fatal("idempotency digest omitted the environment application", err)
	}
	replay, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "current-fence", now, metadata, fence)
	if err != nil || replay.RunID != valid.RunID {
		t.Fatal("same fenced preparation was not idempotent", replay, err)
	}
	if _, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "before-target-change", now, metadata, fence); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("old idempotency key was rebound to another application", err)
	}
	apply.ExpectedRevision, apply.Targets = updated.MutationRevision, oldTargets
	rolledBack, err := d.ApplyEnvironment(t.Context(), apply)
	if err != nil || rolledBack.ConfigurationHash != environment.ConfigurationHash || rolledBack.MutationRevision <= updated.MutationRevision {
		t.Fatal("rollback did not retain monotonic application identity", rolledBack, err)
	}
	if _, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "rollback-stale", now, metadata, assignment.Environment); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("rollback revived an old fence with the same hash", err)
	}
	latest, err := d.GetPublisherGroupAssignments(t.Context(), member.lease.AccessToken, now)
	if err != nil || len(latest.Services) != 1 {
		t.Fatal(latest, err)
	}
	if _, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "rollback-current", now, metadata, latest.Services[0].Environment); err != nil {
		t.Fatal("current rollback snapshot could not prepare", err)
	}
}

func TestIntegrationEnvironmentPreparedRunRechecksApplication(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	r := appliedProjectRequest(t, d, now)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	environment, _ := createTestEnvironment(t, d, r, "production", definition.Revision, EnvironmentTargets{"api": {Address: "same.internal:3000"}})
	member := enrollTestEnvironment(t, d, r, environment)
	assignment := member.assignments.Services[0]
	access := groupAssignmentAccess(t, d, member, assignment, now)
	metadata := ServiceMetadata{Protocol: "http", PublisherPool: true, TrustRevision: assignment.TrustRevision}
	prepared, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "before-apply", now, metadata, assignment.Environment)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ApplyEnvironment(t.Context(), ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: environment.ID, ExpectedRevision: 1, DefinitionRevision: definition.Revision}, Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("prepared run started after its environment application changed")
	}
	current, err := d.GetPublisherGroupAssignments(t.Context(), member.lease.AccessToken, now)
	if err != nil || len(current.Services) != 1 || current.Services[0].Environment == nil {
		t.Fatal(current, err)
	}
	if current.Services[0].Environment.ConfigurationHash != assignment.Environment.ConfigurationHash || current.Services[0].Environment.MutationRevision <= assignment.Environment.MutationRevision {
		t.Fatal("same-hash application did not advance the explicit fence")
	}
	newPreparation, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "current-application", now, metadata, current.Services[0].Environment)
	if err != nil {
		t.Fatal("stale preparation blocked a current application", err)
	}
	if _, err := d.StartServiceRun(t.Context(), assignment.ServiceID, newPreparation.RunID, newPreparation.RunNumber, access.PublisherIdentity, now); err != nil {
		t.Fatal("current prepared fence could not start", err)
	}
}

func TestIntegrationEnvironmentPublicationRejectedForLegacyService(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"legacy": {}}, Services: map[string]ProjectServiceConfiguration{"api": {Protocol: "http", PublisherGroup: "legacy", Target: "legacy.internal:3000"}}}
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, applied.Groups[0].ID, r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	member := enrollAppliedGroup(t, d, r, enrollment, now)
	assignment := member.assignments.Services[0]
	if assignment.Environment != nil {
		t.Fatal("legacy assignment acquired an environment context")
	}
	access := groupAssignmentAccess(t, d, member, assignment, now)
	metadata := ServiceMetadata{Protocol: "http", PublisherPool: true, TrustRevision: assignment.TrustRevision}
	foreign := &EnvironmentPublication{EnvironmentID: "env_AAAAAAAAAAAAAAAAAAAAAA", MutationRevision: 1, ConfigurationHash: fmt.Sprintf("%064d", 0)}
	if _, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "unexpected-fence", now, metadata, foreign); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("non-environment service accepted an environment context", err)
	}
	if _, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "legacy-explicit-nil", now, metadata, nil); err != nil {
		t.Fatal("explicit nil no longer prepares a legacy service", err)
	}
}

func TestIntegrationEnvironmentBrokenReverseMappingFailsClosed(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "environment_reverse_mapping")
	r := appliedProjectRequest(t, d, now)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"cluster": {Protocol: "kubernetes"}, "api": {Protocol: "http"}})
	environment, _ := createTestEnvironment(t, d, r, "production", definition.Revision, EnvironmentTargets{"cluster": {Discovery: &ProjectTargetDiscovery{Type: "eks", Region: "us-east-1", Cluster: new("pinned")}}, "api": {Address: "pinned.internal:3000"}})
	member := enrollTestEnvironment(t, d, r, environment)
	configuration, _, err := NormalizeProjectConfiguration(ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"legacy": {}}, Services: map[string]ProjectServiceConfiguration{
		"cluster": {Name: "cluster", PublisherGroup: "legacy", Protocol: "kubernetes", TargetDiscovery: &ProjectTargetDiscovery{Type: "eks", Region: "us-west-2", Cluster: new("wrong-live-parent")}},
		"api":     {Name: "api", PublisherGroup: "legacy", Protocol: "http", Target: "wrong.internal:3000", HTTP: &config.HTTPService{Access: &config.Access{Mode: "restricted", IP: []string{"203.0.113.0/24"}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := d.storageKey.Seal(appliedProjectContext(r.TeamID, r.ProjectKey), mustEnvironmentJSON(t, configuration))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.applied_projects SET configuration_ciphertext=$3 WHERE team_id=$1 AND project_key=$2`, r.TeamID, r.ProjectKey, sealed); err != nil {
		t.Fatal(err)
	}
	tx, err := d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Rollback(t.Context()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error(err)
		}
	}()
	if _, err := tx.Exec(t.Context(), `UPDATE control.project_publisher_groups SET environment_id=NULL WHERE id=$1`, member.member.GroupID); err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(tx)
	ids := map[string]string{}
	for _, service := range environment.Services {
		ids[service.Service] = service.ServiceID
	}
	if hint, err := d.visitorKubernetesAuth(t.Context(), q, ids["cluster"]); err == nil {
		t.Error("broken reverse association fell back to global EKS facts", hint)
	}
	if _, _, _, _, err := d.publisherGroupConfiguration(t.Context(), tx, member.member); err == nil {
		t.Error("broken reverse association selected legacy publisher configuration")
	}
	if settings, err := d.serviceHTTPSettings(t.Context(), q, ids["api"]); err == nil {
		t.Error("broken reverse association fell back to global IP facts", settings)
	}
	groups, err := q.ListProjectPublisherGroups(t.Context(), controlstatedb.ListProjectPublisherGroupsParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.expandedPublisherConfiguration(t.Context(), tx, configuration, groups); err == nil {
		t.Error("common publisher projection silently classified a broken environment as legacy")
	}
	err = tx.Commit(t.Context())
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23503" {
		t.Fatal("database committed a nonreciprocal environment association", err)
	}
}
