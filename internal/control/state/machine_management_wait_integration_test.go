package state

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func approvalFacts(t *testing.T, f machineFixture) []byte {
	t.Helper()
	var result []byte
	err := f.d.pool.QueryRow(t.Context(), `SELECT jsonb_build_object(
        'machines',(SELECT jsonb_agg(to_jsonb(m) ORDER BY id) FROM control.machine_identities m),
        'permissions',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM control.machine_workload_permissions p),
        'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY intent_key) FROM control.workload_approvals r))::text`).Scan(&result)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestIntegrationWorkloadApprovalSessionAuthorityAcrossLockWaits(t *testing.T) {
	for _, operation := range []string{"new", "retry", "read"} {
		boundaries := []string{"team", "session", "receipt"}
		if operation == "new" {
			boundaries = []string{"team", "project", "environment", "write", "session"}
		}
		for _, boundary := range boundaries {
			for _, change := range []string{"revoke", "rotate", "deadline"} {
				t.Run(operation+"/"+boundary+"/"+change, func(t *testing.T) {
					f := newMachineFixture(t, "oidc")
					session := newOIDCSession(t, f.d, f.now)
					if session.Identity.Identity.ID != f.r.ActorID {
						t.Fatal("session fixture changed identity")
					}
					r := approvalRequest(f)
					manager, err := f.d.AuthenticateEnvironmentPublisherManager(t.Context(), session.AccessToken)
					if err != nil {
						t.Fatal(err)
					}
					if operation != "new" {
						if _, err := f.d.ApproveWorkload(t.Context(), f.r.TeamID, "queued", manager, r, f.now); err != nil {
							t.Fatal(err)
						}
					}
					if change == "deadline" {
						if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, session.SessionID, time.Now().Add(2*time.Second)); err != nil {
							t.Fatal(err)
						}
						manager, err = f.d.AuthenticateEnvironmentPublisherManager(t.Context(), session.AccessToken)
						if err != nil {
							t.Fatal(err)
						}
					}
					before := approvalFacts(t, f)
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()
					workers := newIntegrationWorkers(t, cancel)
					gate, err := f.d.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer rollbackTestTransaction(t, gate)
					defer workers.stop()
					switch boundary {
					case "team":
						_, err = controlstatedb.New(gate).LockLocalTeamForMutation(ctx, f.r.TeamID)
					case "project":
						_, err = controlstatedb.New(gate).LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey})
					case "environment":
						_, err = controlstatedb.New(gate).LockEnvironment(ctx, controlstatedb.LockEnvironmentParams{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, ID: f.environment.ID})
					case "write":
						_, err = gate.Exec(ctx, `LOCK TABLE control.machine_workload_permissions IN SHARE MODE`)
					case "receipt":
						_, err = gate.Exec(ctx, `LOCK TABLE control.workload_approvals IN ACCESS EXCLUSIVE MODE`)
					case "session":
						_, err = gate.Exec(ctx, `SELECT id FROM control.control_sessions WHERE id=$1 FOR UPDATE`, session.SessionID)
					}
					if err != nil {
						t.Fatal(err)
					}
					done := make(chan error, 1)
					workers.Go(func() {
						var err error
						var result WorkloadApproval
						if operation == "read" {
							result, err = f.d.GetWorkloadApproval(ctx, f.r.TeamID, "queued", manager)
						} else {
							result, err = f.d.ApproveWorkload(ctx, f.r.TeamID, "queued", manager, r, f.now)
						}
						if err != nil && result.PermissionID != "" {
							err = errors.New("denied operation returned a receipt")
						}
						done <- err
					})
					waitForPostgresBlock(t, ctx, f.d, int32(gate.Conn().PgConn().PID()), done)
					switch change {
					case "revoke":
						if boundary == "session" {
							_, err = gate.Exec(ctx, `UPDATE control.control_sessions SET revoked_at=$2,revoked_by=$3 WHERE id=$1`, session.SessionID, time.Now(), f.r.ActorID)
						} else {
							err = f.d.RevokeControlSession(ctx, ControlPrincipal{SessionID: session.SessionID, IdentityID: f.r.ActorID}, time.Now())
						}
					case "rotate":
						if boundary == "session" {
							_, err = gate.Exec(ctx, `UPDATE control.control_sessions SET access_token_digest=decode(repeat('00',32),'hex') WHERE id=$1`, session.SessionID)
						} else {
							_, err = f.d.RefreshControlSession(ctx, session.RefreshToken, time.Hour, time.Now())
						}
					case "deadline":
						if boundary == "session" {
							_, err = gate.Exec(ctx, `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, session.SessionID, time.Now().Add(time.Hour))
						} else {
							_, err = f.d.pool.Exec(ctx, `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, session.SessionID, time.Now().Add(time.Hour))
						}
						if err != nil {
							t.Fatal(err)
						}
						timer := time.NewTimer(time.Until(manager.deadline))
						defer timer.Stop()
						select {
						case <-timer.C:
						case <-ctx.Done():
							t.Fatal(ctx.Err())
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					if err := gate.Commit(ctx); err != nil {
						t.Fatal(err)
					}
					if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrControlAuthentication) {
						t.Fatalf("session authority survived %s/%s: %v", boundary, change, err)
					}
					if !bytes.Equal(before, approvalFacts(t, f)) {
						t.Fatal("denied queued operation saved machine, permission or receipt")
					}
				})
			}
		}
	}
}

func TestIntegrationWorkloadApprovalRejectsMachineAndActorCapabilities(t *testing.T) {
	f := newMachineFixture(t, "oidc")
	provisioning, err := f.d.ExchangeProvisioning(t.Context(), f.machine.ID, f.grant.ID, ProvisioningRead, f.provisioningProof(t, ProvisioningRead), machineTestAudience, f.now)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := f.d.authenticateEnvironmentProvisioner(t.Context(), provisioning.Credential)
	if err != nil {
		t.Fatal(err)
	}
	for _, capability := range []EnvironmentPublisherManager{manager, {}, {identityID: f.r.ActorID, internalActor: true}} {
		if _, err := f.d.ApproveWorkload(t.Context(), f.r.TeamID, "not-human", capability, approvalRequest(f), f.now); !errors.Is(err, ErrControlAuthentication) {
			t.Fatal("non-human capability approved workload", err)
		}
		if _, err := f.d.GetWorkloadApproval(t.Context(), f.r.TeamID, "not-human", capability); !errors.Is(err, ErrControlAuthentication) {
			t.Fatal("non-human capability read receipt", err)
		}
	}
}
