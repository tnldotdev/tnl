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
	r := retainedEnvironmentProject(t, d, now)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	issuer, manager := retainedEnvironmentManager(t, d, r, "bootstrap-manager")
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	environment, _ := createTestEnvironment(t, d, r, "production", definition.Revision, EnvironmentTargets{"api": {Address: "current.internal:3000"}})
	request := IssueEnvironmentPublisherEnrollmentRequest{EnvironmentPublisherSelection: environmentPublisherSelection(t, d, issuer, environment), ExpectedRevision: environment.MutationRevision, ExpectedConfigurationHash: environment.ConfigurationHash, Services: []string{"api"}, MaxMembers: 1, Lifetime: time.Hour, Now: now}
	enrollment, err := d.IssueEnvironmentPublisherEnrollment(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET role='member' WHERE id=$1`, manager.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssueEnvironmentPublisherEnrollment(t.Context(), request); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("demoted bootstrap issuer could issue enrollment", err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.RedeemEnvironmentPublisherEnrollment(t.Context(), enrollment.Key, public, now); !errors.Is(err, ErrEnvironmentPublisher) {
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
	r := retainedEnvironmentProject(t, d, now)
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
	if member.assignments.Environment != expected {
		t.Fatal("assignment did not carry its exact environment snapshot", member.assignments.Environment)
	}
	access := environmentAssignmentAccess(t, d, member, assignment, now)
	metadata := ServiceMetadata{Protocol: protocol, PublisherPool: true, TrustRevision: assignment.TrustRevision}
	prepared, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "before-target-change", now, metadata, &member.assignments.Environment)
	if err != nil {
		t.Fatal(err)
	}
	row, err := controlstatedb.New(d.pool).LockServiceRun(t.Context(), controlstatedb.LockServiceRunParams{ID: prepared.RunID, ServiceID: assignment.ServiceID})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := preparedEnvironmentPublication(row)
	if err != nil || !sameEnvironmentPublication(stored, &member.assignments.Environment) {
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
	if _, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "stale-fresh-key", now, metadata, &member.assignments.Environment); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("stale target worker prepared a new run with old snapshot and fresh key")
	}
	if _, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "missing-fence", now, metadata, nil); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("mapped service accepted omitted publication fence", err)
	}
	if _, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("pre-update preparation started after target replacement", err)
	}
	current, err := d.GetEnvironmentPublisherAssignments(t.Context(), member.lease.AccessToken, now)
	if err != nil || len(current.Services) != 1 {
		t.Fatal(current, err)
	}
	fence := &current.Environment
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
	if _, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "rollback-stale", now, metadata, &member.assignments.Environment); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("rollback revived an old fence with the same hash", err)
	}
	latest, err := d.GetEnvironmentPublisherAssignments(t.Context(), member.lease.AccessToken, now)
	if err != nil || len(latest.Services) != 1 {
		t.Fatal(latest, err)
	}
	if _, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "rollback-current", now, metadata, &latest.Environment); err != nil {
		t.Fatal("current rollback snapshot could not prepare", err)
	}
}

func TestIntegrationEnvironmentPreparedRunRechecksApplication(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	r := retainedEnvironmentProject(t, d, now)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	environment, _ := createTestEnvironment(t, d, r, "production", definition.Revision, EnvironmentTargets{"api": {Address: "same.internal:3000"}})
	member := enrollTestEnvironment(t, d, r, environment)
	assignment := member.assignments.Services[0]
	access := environmentAssignmentAccess(t, d, member, assignment, now)
	metadata := ServiceMetadata{Protocol: "http", PublisherPool: true, TrustRevision: assignment.TrustRevision}
	prepared, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "before-apply", now, metadata, &member.assignments.Environment)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ApplyEnvironment(t.Context(), ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: environment.ID, ExpectedRevision: 1, DefinitionRevision: definition.Revision}, Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("prepared run started after its environment application changed")
	}
	current, err := d.GetEnvironmentPublisherAssignments(t.Context(), member.lease.AccessToken, now)
	if err != nil || len(current.Services) != 1 {
		t.Fatal(current, err)
	}
	if current.Environment.ConfigurationHash != member.assignments.Environment.ConfigurationHash || current.Environment.MutationRevision <= member.assignments.Environment.MutationRevision {
		t.Fatal("same-hash application did not advance the explicit fence")
	}
	newPreparation, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "current-application", now, metadata, &current.Environment)
	if err != nil {
		t.Fatal("stale preparation blocked a current application", err)
	}
	if _, err := d.StartServiceRun(t.Context(), assignment.ServiceID, newPreparation.RunID, newPreparation.RunNumber, access.PublisherIdentity, now); err != nil {
		t.Fatal("current prepared fence could not start", err)
	}
}

func TestIntegrationEnvironmentPublicationRejectedForLegacyService(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	r := oidcRouteRequest(t, d, now)
	service, err := d.CreateServiceAt(t.Context(), r.TeamID, r.ActingIdentityID, "independent", "independent", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := publisherEnrollment(t, d, r, PublisherScope{TeamID: r.TeamID, Kind: "service", ServiceID: service.ID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	metadata := ServiceMetadata{Protocol: "http", TrustRevision: service.TrustRevision}
	foreign := &EnvironmentPublication{EnvironmentID: "env_AAAAAAAAAAAAAAAAAAAAAA", MutationRevision: 1, ConfigurationHash: fmt.Sprintf("%064d", 0)}
	if _, err := d.PrepareServiceRun(t.Context(), service.ID, publisher, "unexpected-fence", now, metadata, foreign); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("non-environment service accepted an environment context", err)
	}
	if _, err := d.PrepareServiceRun(t.Context(), service.ID, publisher, "independent-explicit-nil", now, metadata, nil); err != nil {
		t.Fatal("explicit nil no longer prepares an independent service", err)
	}
}

func TestIntegrationEnvironmentBrokenReverseMappingFailsClosed(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "environment_reverse_mapping")
	r := retainedEnvironmentProject(t, d, now)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"cluster": {Protocol: "kubernetes"}, "api": {Protocol: "http"}})
	environment, _ := createTestEnvironment(t, d, r, "production", definition.Revision, EnvironmentTargets{"cluster": {Discovery: &ProjectTargetDiscovery{Type: "eks", Region: "us-east-1", Cluster: new("pinned")}}, "api": {Address: "pinned.internal:3000"}})
	member := enrollTestEnvironment(t, d, r, environment)
	// a same-shaped sibling has deliberately different discovery and IP policy.
	// a broken association must not recover by a logical name or another owner.
	createTestEnvironment(t, d, r, "other", definition.Revision, EnvironmentTargets{
		"cluster": {Discovery: &ProjectTargetDiscovery{Type: "eks", Region: "us-west-2", Cluster: new("wrong-live-parent")}},
		"api":     {Address: "wrong.internal:3000", HTTP: &EnvironmentServiceHTTP{Access: &config.Access{Mode: "restricted", IP: []string{"203.0.113.0/24"}}}},
	})
	tx, err := d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Rollback(t.Context()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error(err)
		}
	}()
	installed, _, err := lockEnvironmentPublisherLease(t.Context(), tx, member.lease.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE control.project_publisher_groups SET environment_id=NULL WHERE id=$1`, installed.groupID); err != nil {
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
	if _, _, err := d.environmentPublisherConfiguration(t.Context(), tx, installed); err == nil {
		t.Error("broken reverse association selected publisher configuration")
	}
	if settings, err := d.serviceHTTPSettings(t.Context(), q, ids["api"]); err == nil {
		t.Error("broken reverse association fell back to global IP facts", settings)
	}
	if _, _, err := publisherGroupEnvironment(t.Context(), q, installed.groupID); err == nil {
		t.Error("common owner lookup silently classified a broken environment as independent")
	}
	err = tx.Commit(t.Context())
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23503" {
		t.Fatal("database committed a nonreciprocal environment association", err)
	}
}
