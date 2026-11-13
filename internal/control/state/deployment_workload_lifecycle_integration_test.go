package state

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
)

func TestIntegrationDeletedDeploymentNameCannotRebindHistoricalWorkload(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_workload_name_recreation")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
	production, err := d.GetDeployment(ctx, scope, "production")
	if err != nil {
		t.Fatal(err)
	}
	exchange, key := workloadExchange(t, r, now)
	old, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteDeployment(ctx, scope, production.ID, production.Revision, now); err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(d.pool)
	before, err := q.GetAppliedProject(ctx, controlstatedb.GetAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []struct {
		key string
		at  time.Time
	}{
		{"recreate-now", now},
		{"recreate-after-namespace-quarantine", now.Add(8 * 24 * time.Hour)},
	} {
		t.Run(attempt.key, func(t *testing.T) {
			if attempt.at.After(now) {
				var reusable bool
				if err := d.pool.QueryRow(ctx, `SELECT control.service_namespace_reusable(namespace,$2) FROM control.deployments WHERE id=$1`, production.ID, attempt.at).Scan(&reusable); err != nil || !reusable {
					t.Fatal("fixture did not pass namespace quarantine", reusable, err)
				}
			}
			_, err := d.CreateDeployment(ctx, CreateDeploymentRequest{
				DeploymentScope: scope, Name: "production", IdempotencyKey: attempt.key, Now: attempt.at,
				Targets: map[string]DeploymentTarget{"api": {Address: "replacement.internal:3000"}, "db": {Address: "replacement.internal:5432"}},
			})
			if !errors.Is(err, ErrServiceConflict) {
				t.Fatal("management creation rebound a deleted deployment name", err)
			}
			if _, err := d.WorkloadPolicy(ctx, r.TeamID, r.ProjectKey, exchange.Workload, r.SourceFingerprint); !errors.Is(err, ErrWorkloadDenied) {
				t.Fatal("failed recreation reactivated historical workload policy", err)
			}
			fresh, freshKey := workloadExchange(t, r, now)
			fresh.Execution.GitHub.RunID, fresh.Execution.GitHub.CheckRunID, fresh.Execution.GitHub.JTI = "777", "888", attempt.key
			signWorkloadRequest(&fresh, freshKey)
			if _, err := d.IdentifyWorkload(ctx, r.TeamID, r.ProjectKey, fresh.Workload, r.SourceFingerprint, fresh.Execution, now); !errors.Is(err, ErrWorkloadDenied) {
				t.Fatal("fresh execution identified a historical workload", err)
			}
			if _, err := d.ExchangeWorkload(ctx, fresh, now); !errors.Is(err, ErrWorkloadDenied) {
				t.Fatal("fresh execution gained recreated deployment authority", err)
			}
			if _, err := d.ExchangeWorkload(ctx, exchange, now); !errors.Is(err, ErrWorkloadDenied) {
				t.Fatal("old execution replay regained historical policy", err)
			}
			if _, err := d.AttachWorkloadAssertion(ctx, old.ID, old.Credential, exchange.Execution, ed25519.Sign(key, workloadproof.Attach(old.ID, exchange.Execution.AssertionDigest)), now); !errors.Is(err, ErrWorkloadDenied) {
				t.Fatal("old assertion regained historical policy", err)
			}
			for _, id := range old.ServiceIDs {
				if _, err := d.CheckWorkloadService(ctx, old.Credential, id, now); !errors.Is(err, ErrWorkloadDenied) && !errors.Is(err, ErrServiceAccess) {
					t.Fatal("old session recovered retired service rights", err)
				}
			}
		})
	}
	after, err := q.GetAppliedProject(ctx, controlstatedb.GetAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed management recreation changed desired history", err)
	}
	history, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID, "production")
	if err != nil || !reflect.DeepEqual(history.Configuration, applied.Configuration) || len(history.Services) != 0 {
		t.Fatal("deleted workload history was discarded or realized", history, err)
	}
	if deployments, err := d.ListDeployments(ctx, scope, "", 100); err != nil || len(deployments) != 0 {
		t.Fatal("failed recreation committed a replacement deployment", deployments, err)
	}
	var owner string
	if err := d.pool.QueryRow(ctx, `SELECT deployment_id FROM control.deployment_names WHERE team_id=$1 AND project_key=$2 AND name='production'`, r.TeamID, r.ProjectKey).Scan(&owner); err != nil || owner != production.ID {
		t.Fatal("deleted deployment name lost its immutable identity fence", owner, err)
	}
}

func TestIntegrationDeletedDeploymentWorkloadExchangeWaitsForRetirement(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_workload_delete_wait")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	r = selectedProjectRequest(r, "production")
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
	deployment, err := d.GetDeployment(t.Context(), scope, "production")
	if err != nil {
		t.Fatal(err)
	}
	exchange, _ := workloadExchange(t, r, now)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey}); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	deleted, authorized := make(chan error, 1), make(chan error, 1)
	workers.Go(func() {
		deleted <- d.DeleteDeployment(ctx, scope, deployment.ID, deployment.Revision, now)
	})
	deleting := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), deleted)
	workers.Go(func() {
		_, err := d.ExchangeWorkload(ctx, exchange, now)
		authorized <- err
	})
	waitForPostgresBlock(t, ctx, d, deleting, authorized)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, deleted); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, authorized); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("workload exchange authorized deleted desired history after waiting", err)
	}
	var sessions int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.workload_sessions WHERE team_id=$1 AND project_key=$2`, r.TeamID, r.ProjectKey).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatal("denied exchange saved a session", sessions, err)
	}
}

func TestIntegrationDeletedDeploymentWorkloadPolicyCannotAuthorize(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deleted_deployment_workload")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	exchange, key := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
	deployment, err := d.GetDeployment(ctx, scope, "production")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteDeployment(ctx, scope, deployment.ID, deployment.Revision, now); err != nil {
		t.Fatal(err)
	}
	for name, authorize := range map[string]func() error{
		"policy": func() error {
			_, err := d.WorkloadPolicy(ctx, r.TeamID, r.ProjectKey, exchange.Workload, r.SourceFingerprint)
			return err
		},
		"identify": func() error {
			_, err := d.IdentifyWorkload(ctx, r.TeamID, r.ProjectKey, exchange.Workload, r.SourceFingerprint, exchange.Execution, now)
			return err
		},
		"assertion-policy": func() error {
			_, err := d.WorkloadAssertionPolicy(ctx, session.ID, session.Credential)
			return err
		},
		"exchange-retry": func() error {
			_, err := d.ExchangeWorkload(ctx, exchange, now)
			return err
		},
		"fresh-exchange": func() error {
			fresh, freshKey := workloadExchange(t, r, now)
			fresh.Execution.GitHub.RunID, fresh.Execution.GitHub.CheckRunID, fresh.Execution.GitHub.JTI = "333", "444", "deleted"
			signWorkloadRequest(&fresh, freshKey)
			_, err := d.ExchangeWorkload(ctx, fresh, now)
			return err
		},
		"assertion-attachment": func() error {
			_, err := d.AttachWorkloadAssertion(ctx, session.ID, session.Credential, exchange.Execution, ed25519.Sign(key, workloadproof.Attach(session.ID, exchange.Execution.AssertionDigest)), now)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := authorize(); !errors.Is(err, ErrWorkloadDenied) {
				t.Fatal("deleted desired history still authorized a workload", err)
			}
		})
	}
	if _, err := d.CheckWorkloadService(ctx, session.Credential, session.ServiceIDs[0], now); !errors.Is(err, ErrServiceAccess) && !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("deleted workload binding still allowed service access", err)
	}
	// an unrelated apply must also exclude deleted policy from session reconciliation.
	r.Deployment, r.ExpectedRevision = "local", applied.Revision
	r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{}}
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	var revoked bool
	if err := d.pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM control.workload_sessions WHERE id=$1`, session.ID).Scan(&revoked); err != nil || !revoked {
		t.Fatal("sibling apply retained a session authorized only by deleted desired history", revoked, err)
	}
	if _, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, signWorkloadRenewal(session, key), now.Add(time.Second)); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("pruned workload session renewed", err)
	}
}

func TestIntegrationDeletedDeploymentReleasesWorkloadNameWithoutResurrection(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_workload_reuse")
	ctx := t.Context()
	local := appliedProjectRequest(t, d, now)
	local.ServiceDeclarations = map[string]string{"web": "http", "api": "http", "db": "postgres"}
	first, err := d.ApplyProjectConfiguration(ctx, local)
	if err != nil {
		t.Fatal(err)
	}
	r := local
	r.Configuration = workloadConfiguration()
	r = selectedProjectRequest(r, "production")
	r.ServiceDeclarations["web"] = "http"
	r.ExpectedRevision = first.Revision
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
	production, err := d.GetDeployment(ctx, scope, "production")
	if err != nil {
		t.Fatal(err)
	}
	customer, err := d.CreateDeployment(ctx, CreateDeploymentRequest{
		DeploymentScope: scope, Name: "customer", IdempotencyKey: "customer", Now: now,
		Targets: map[string]DeploymentTarget{"db": {Address: "customer.internal:5432"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	exchange, key := workloadExchange(t, r, now)
	old, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	staging := selectedProjectRequest(r, "staging")
	staging.ServiceDeclarations["web"] = "http"
	staging.ExpectedRevision = applied.Revision
	if _, err := d.ApplyProjectConfiguration(ctx, staging); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("live production policy did not reserve its workload name", err)
	}
	unchanged, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID, "production")
	if err != nil || unchanged.Revision != applied.Revision || !reflect.DeepEqual(unchanged.Configuration, applied.Configuration) {
		t.Fatal("rejected workload duplication changed production", unchanged, err)
	}
	if _, err := d.GetDeployment(ctx, scope, "staging"); !errors.Is(err, ErrDeploymentNotFound) {
		t.Fatal("rejected workload duplication saved a deployment", err)
	}
	if err := d.DeleteDeployment(ctx, scope, production.ID, production.Revision, now); err != nil {
		t.Fatal(err)
	}
	reused, err := d.ApplyProjectConfiguration(ctx, staging)
	if err != nil || reused.Revision != applied.Revision+1 {
		t.Fatal("deleted production history still reserved its workload name", reused, err)
	}
	staging.ExpectedRevision = reused.Revision
	if retry, err := d.ApplyProjectConfiguration(ctx, staging); err != nil || retry.Revision != reused.Revision {
		t.Fatal("historical duplicate policy broke unchanged apply", retry, err)
	}
	policy, err := d.WorkloadPolicy(ctx, r.TeamID, r.ProjectKey, exchange.Workload, r.SourceFingerprint)
	if err != nil || policy.Deployment != "staging" {
		t.Fatal("active policy did not follow the new explicit selection", policy, err)
	}
	history, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID, "production")
	if err != nil || !reflect.DeepEqual(history.Configuration, applied.Configuration) || len(history.Services) != 0 {
		t.Fatal("workload reuse changed desired history or resurrected its bindings", history, err)
	}
	if _, err := d.GetDeployment(ctx, scope, production.ID); !errors.Is(err, ErrDeploymentNotFound) {
		t.Fatal("workload reuse restored a deleted deployment", err)
	}
	if sibling, err := d.GetDeployment(ctx, scope, customer.ID); err != nil || !reflect.DeepEqual(sibling, customer) {
		t.Fatal("workload reuse changed a runtime-created sibling", sibling, err)
	}
	if saved, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID, "local"); err != nil || !reflect.DeepEqual(saved.Configuration, first.Configuration) {
		t.Fatal("workload reuse changed retained local input", saved, err)
	}
	fresh, freshKey := workloadExchange(t, staging, now)
	fresh.Execution.GitHub.RunID, fresh.Execution.GitHub.CheckRunID, fresh.Execution.GitHub.JTI = "555", "666", "staging"
	signWorkloadRequest(&fresh, freshKey)
	current, err := d.ExchangeWorkload(ctx, fresh, now)
	if err != nil || len(current.ServiceIDs) != 2 {
		t.Fatal("reused workload could not authorize its new bindings", current, err)
	}
	for _, service := range reused.Services {
		if _, err := d.CheckWorkloadService(ctx, current.Credential, service.ServiceID, now); err != nil {
			t.Fatal("replacement workload could not access staging", err)
		}
		if _, err := d.CheckWorkloadService(ctx, old.Credential, service.ServiceID, now); !errors.Is(err, ErrWorkloadDenied) && !errors.Is(err, ErrServiceAccess) {
			t.Fatal("old production session gained staging authority", err)
		}
	}
	// existing sessions keep only their issued service snapshot, even on replay.
	if replay, err := d.ExchangeWorkload(ctx, exchange, now); err != nil && !errors.Is(err, ErrWorkloadDenied) || err == nil && len(replay.ServiceIDs) != 0 {
		t.Fatal("replayed production session recovered rights or failed outside authorization", replay, err)
	}
	if attached, err := d.AttachWorkloadAssertion(ctx, old.ID, old.Credential, exchange.Execution, ed25519.Sign(key, workloadproof.Attach(old.ID, exchange.Execution.AssertionDigest)), now); err != nil && !errors.Is(err, ErrWorkloadDenied) || err == nil && len(attached.ServiceIDs) != 0 {
		t.Fatal("old assertion restored rights or failed outside authorization", attached, err)
	}
	row, err := controlstatedb.New(d.pool).GetAppliedProject(ctx, controlstatedb.GetAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		t.Fatal(err)
	}
	record, err := d.openAppliedProjectRecord(row)
	if err != nil || len(record.Deployments["production"].Workloads) != 1 || len(record.Deployments["staging"].Workloads) != 1 {
		t.Fatal("active registry discarded historical policy declarations", record, err)
	}
	retired, err := d.RetireProject(ctx, r.TeamID, r.ProjectKey, r.ActorID, reused.Revision, now)
	if err != nil || retired.RetiredAt == nil {
		t.Fatal("historical duplicate workload blocked project retirement", retired, err)
	}
	if _, err := d.WorkloadPolicy(ctx, r.TeamID, r.ProjectKey, exchange.Workload, r.SourceFingerprint); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("retired project retained workload policy", err)
	}
	if _, err := d.ListWorkloadServices(ctx, current.Credential, now); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("project retirement retained the replacement session", err)
	}
	if deployments, err := d.ListDeployments(ctx, scope, "", 100); err != nil || len(deployments) != 0 {
		t.Fatal("project retirement resurrected or retained a deployment", deployments, err)
	}
}
