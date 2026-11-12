package state

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func approvalRequest(f machineFixture) WorkloadApprovalRequest {
	return WorkloadApprovalRequest{ProjectKey: f.r.ProjectKey, EnvironmentID: f.environment.ID, ExpectedRevision: f.environment.MutationRevision, Workload: "test", IntentHash: strings.Repeat("a", 64), Trust: f.machine.Trust, Services: []string{"api"}, MaxDurationSeconds: 600, ExpiresAt: f.now.Add(time.Hour)}
}

func approvalManager(t *testing.T, f machineFixture) EnvironmentPublisherManager {
	t.Helper()
	manager, err := f.d.AuthenticateEnvironmentPublisherManager(t.Context(), f.r.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestIntegrationWorkloadApprovalExactRecoveryAndRevocation(t *testing.T) {
	f := newMachineFixture(t, "oidc")
	ctx := t.Context()
	r := approvalRequest(f)
	manager := approvalManager(t, f)
	approve := func(intent string, request WorkloadApprovalRequest, now time.Time) (WorkloadApproval, error) {
		return f.d.ApproveWorkload(ctx, f.r.TeamID, intent, manager, request, now)
	}
	first, err := approve("first", r, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Machine.ID != f.machine.ID || first.PermissionID == "" || first.Protocols["api"] != "http" || len(first.Protocols) != 1 {
		t.Fatalf("approval lost exact identity or service scope: %+v", first)
	}
	// discard the write response, then recover via the authenticated read path.
	recovered, err := f.d.GetWorkloadApproval(ctx, f.r.TeamID, "first", manager)
	if err != nil || recovered.Machine.ID != first.Machine.ID || recovered.PermissionID != first.PermissionID {
		t.Fatalf("lost-reply recovery: %+v, %v", recovered, err)
	}
	if _, err := f.d.GetWorkloadApproval(ctx, f.r.TeamID, "first", EnvironmentPublisherManager{}); err == nil {
		t.Fatal("receipt readable without current manager authority")
	}
	if _, err := f.d.ApproveWorkload(ctx, f.r.TeamID, "first", EnvironmentPublisherManager{}, r, f.now); err == nil {
		t.Fatal("retry bypassed current manager authority")
	}
	for _, change := range []string{"services", "trust", "expires", "environment", "revision", "hash"} {
		changed := r
		switch change {
		case "services":
			changed.Services = []string{"db"}
		case "trust":
			changed.Trust.Claims = map[string]string{"sub": "another-machine"}
		case "expires":
			changed.ExpiresAt = r.ExpiresAt.Add(time.Minute)
		case "environment":
			changed.EnvironmentID = "env_" + strings.Repeat("b", 22)
		case "revision":
			changed.ExpectedRevision++
		case "hash":
			changed.IntentHash = strings.Repeat("b", 64)
		}
		if _, err := approve("first", changed, f.now); !errors.Is(err, ErrWorkloadApprovalConflict) {
			t.Fatalf("changed %s reused intent: %v", change, err)
		}
	}
	if err := f.d.RevokeEnvironmentVisitorPermission(ctx, f.r.TeamID, first.PermissionID, f.r.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Time{f.now, f.now.Add(2 * time.Hour)} {
		retry, err := approve("first", r, now)
		if err != nil || retry.PermissionID != first.PermissionID || retry.Machine.ID != first.Machine.ID || retry.PermissionRevokedAt == nil {
			t.Fatalf("retry replaced revoked or expired permission: %+v, %v", retry, err)
		}
	}
	second, err := approve("new-explicit-intent", r, f.now)
	if err != nil || second.PermissionID == first.PermissionID || second.Machine.ID != first.Machine.ID || second.PermissionRevokedAt != nil {
		t.Fatalf("new explicit intent did not create independent permission: %+v, %v", second, err)
	}
	if err := f.d.RevokeMachineIdentity(ctx, f.r.TeamID, first.Machine.ID, f.r.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	retry, err := approve("first", r, f.now)
	if err != nil || retry.Machine.ID != first.Machine.ID || retry.MachineRevokedAt == nil {
		t.Fatalf("machine revocation lost on recovery: %+v, %v", retry, err)
	}
	if _, err := approve("after-machine-revocation", r, f.now); !errors.Is(err, ErrMachineDenied) {
		t.Fatalf("approval replaced revoked machine: %v", err)
	}
}

func TestIntegrationWorkloadApprovalAtomicFencesAndNoNameFallback(t *testing.T) {
	f := newMachineFixture(t, "oidc")
	ctx := t.Context()
	r := approvalRequest(f)
	manager := approvalManager(t, f)
	r.Trust.Claims = map[string]string{"sub": "new-identity"}
	for _, change := range []string{"revision", "service", "expiry", "duration"} {
		bad := r
		switch change {
		case "revision":
			bad.ExpectedRevision++
		case "service":
			bad.Services = []string{"not-in-definition"}
		case "expiry":
			bad.ExpiresAt = f.now.Add(-time.Second)
		case "duration":
			bad.MaxDurationSeconds = 31557601
		}
		if _, err := f.d.ApproveWorkload(ctx, f.r.TeamID, change, manager, bad, f.now); err == nil {
			t.Fatalf("accepted invalid %s", change)
		}
		var machines, permissions, receipts int
		if err := f.d.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.machine_identities WHERE trust->'claims'->>'sub'='new-identity'), (SELECT count(*) FROM control.machine_workload_permissions), (SELECT count(*) FROM control.workload_approvals)`).Scan(&machines, &permissions, &receipts); err != nil {
			t.Fatal(err)
		}
		if machines != 0 || permissions != 0 || receipts != 0 {
			t.Fatalf("%s leaked partial authority: %d/%d/%d", change, machines, permissions, receipts)
		}
	}
	first, err := f.d.ApproveWorkload(ctx, f.r.TeamID, "new", manager, r, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Machine.ID == f.machine.ID {
		t.Fatal("workload display name selected another trust")
	}
	r.Trust.Claims = map[string]string{"sub": "third-identity"}
	third, err := f.d.ApproveWorkload(ctx, f.r.TeamID, "third", manager, r, f.now)
	if err != nil || third.Machine.ID == first.Machine.ID || third.Machine.Name != first.Machine.Name {
		t.Fatalf("display name acted as identity: %+v, %v", third, err)
	}
	independent, err := f.d.CreateEnvironmentVisitorPermission(ctx, EnvironmentVisitorPermission{MachineID: first.Machine.ID, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Scope: EnvironmentPermissionScope{EnvironmentIDs: []string{f.environment.ID}}, Services: []string{"api"}, ExpiresAt: f.now.Add(time.Hour)}, f.r.ActorID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.d.pool.Exec(ctx, `INSERT INTO control.workload_approvals(team_id,intent_key,request,machine_id,permission_id,protocols,created_at) VALUES($1,'wrong-machine','{}'::jsonb,$2,$3,'{}'::jsonb,$4)`, f.r.TeamID, f.machine.ID, independent.ID, f.now)
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23503" {
		t.Fatalf("receipt FK accepted a permission belonging to another machine: %v", err)
	}
}

func TestIntegrationWorkloadApprovalConcurrentSameIntent(t *testing.T) {
	f := newMachineFixture(t, "oidc")
	r := approvalRequest(f)
	manager := approvalManager(t, f)
	r.Trust.Claims = map[string]string{"sub": "concurrent"}
	const count = 4
	results := make([]WorkloadApproval, count)
	errors := make([]error, count)
	var workers sync.WaitGroup
	for i := range count {
		workers.Go(func() {
			results[i], errors[i] = f.d.ApproveWorkload(t.Context(), f.r.TeamID, "same", manager, r, f.now)
		})
	}
	workers.Wait()
	for i := range count {
		if errors[i] != nil || results[i].Machine.ID != results[0].Machine.ID || results[i].PermissionID != results[0].PermissionID {
			t.Fatalf("concurrent intent created different authority: %+v, %v", results, errors)
		}
	}
}
