package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var ErrWorkloadApprovalNotFound = errors.New("workload approval intent not found")
var ErrWorkloadApprovalConflict = errors.New("workload approval intent differs from its original request")

var approvalIntentPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var approvalHashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type WorkloadApprovalRequest struct {
	ProjectKey         string             `json:"project_key"`
	EnvironmentID      string             `json:"environment_id"`
	ExpectedRevision   int64              `json:"expected_revision"`
	Workload           string             `json:"workload"`
	IntentHash         string             `json:"intent_hash"`
	Trust              oidc.WorkloadTrust `json:"trust"`
	Services           []string           `json:"services"`
	MaxDurationSeconds int                `json:"max_duration_seconds"`
	ExpiresAt          time.Time          `json:"expires_at"`
}

type WorkloadApproval struct {
	IntentKey           string
	Request             WorkloadApprovalRequest
	Machine             MachineIdentity
	PermissionID        string
	Protocols           map[string]string
	MachineRevokedAt    *time.Time
	PermissionRevokedAt *time.Time
	CreatedAt           time.Time
}

// reads and retries take the same current manager guard as approval. receipts
// retain exact IDs after expiry, revocation, environment changes or retirement.
func (d *Database) GetWorkloadApproval(ctx context.Context, team, intent string, manager EnvironmentPublisherManager) (result WorkloadApproval, retErr error) {
	tx, err := d.workloadApprovalTransaction(ctx, team, manager)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read workload approval", &retErr)()
	result, err = readWorkloadApproval(ctx, tx, team, intent)
	if err != nil && !errors.Is(err, ErrWorkloadApprovalNotFound) {
		return result, err
	}
	if authErr := manager.finish(ctx, tx, team); authErr != nil {
		return WorkloadApproval{}, authErr
	}
	if err != nil {
		return WorkloadApproval{}, err
	}
	return result, tx.Commit(ctx)
}

func (d *Database) ApproveWorkload(ctx context.Context, team, intent string, manager EnvironmentPublisherManager, request WorkloadApprovalRequest, now time.Time) (result WorkloadApproval, retErr error) {
	clock := newAuthorizationClock(now)
	if !approvalIntentPattern.MatchString(intent) || !approvalHashPattern.MatchString(request.IntentHash) || !naming.ValidProjectKey(request.ProjectKey) || !opaqueid.Valid(request.EnvironmentID, opaqueid.EnvironmentPrefix) || !naming.ValidServiceName(request.Workload) || request.ExpectedRevision < 1 || request.Trust.Validate() != nil || len(request.Services) > 32 {
		return result, ErrEnvironmentInvalid
	}
	var err error
	request.Services, err = normalizeEnvironmentPermissionServices(request.Services)
	if err != nil {
		return result, err
	}
	request.ExpiresAt = request.ExpiresAt.UTC()
	payload, err := json.Marshal(request)
	if err != nil {
		return result, err
	}
	tx, err := d.workloadApprovalTransaction(ctx, team, manager)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "approve workload", &retErr)()
	previous, err := readWorkloadApproval(ctx, tx, team, intent)
	if err == nil {
		if err = manager.finish(ctx, tx, team); err != nil {
			return result, err
		}
		original, marshalErr := json.Marshal(previous.Request)
		if marshalErr != nil {
			return result, marshalErr
		}
		if !bytes.Equal(payload, original) {
			return result, ErrWorkloadApprovalConflict
		}
		// never execute the creation path for an existing intent, including when
		// its permission or machine has since been revoked.
		return previous, tx.Commit(ctx)
	}
	if !errors.Is(err, ErrWorkloadApprovalNotFound) {
		return result, err
	}
	q := controlstatedb.New(tx)
	if _, err = q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: team, ProjectKey: request.ProjectKey}); err != nil {
		return result, publisherLookupError(err, ErrMachineDenied)
	}
	environment, err := q.LockEnvironment(ctx, controlstatedb.LockEnvironmentParams{TeamID: team, ProjectKey: request.ProjectKey, ID: request.EnvironmentID})
	if err != nil {
		return result, publisherLookupError(err, ErrMachineDenied)
	}
	if environment.RetiredAt.Valid {
		return result, ErrMachineDenied
	}
	if environment.MutationRevision != request.ExpectedRevision {
		return result, ErrEnvironmentStale
	}
	definition, err := loadServiceDefinition(ctx, tx, team, request.ProjectKey, environment.AppliedDefinitionRevision)
	if err != nil {
		return result, err
	}
	protocols := make(map[string]string, len(request.Services))
	for _, name := range request.Services {
		service, found := definition.Definition.Services[name]
		if !found {
			return result, ErrEnvironmentInvalid
		}
		protocols[name] = service.Protocol
	}
	trust, err := json.Marshal(request.Trust)
	if err != nil {
		return result, err
	}
	var machine string
	var revoked *time.Time
	// exact provider policy is the only reusable identity selector. a name is
	// merely a display label; even exact trust cannot replace a revoked machine.
	err = tx.QueryRow(ctx, `SELECT id,revoked_at FROM control.machine_identities WHERE team_id=$1 AND proof_kind='oidc'
        AND trust-'events'=$2::jsonb-'events'
        AND COALESCE(trust->'events','[]'::jsonb) @> COALESCE($2::jsonb->'events','[]'::jsonb)
        AND COALESCE(trust->'events','[]'::jsonb) <@ COALESCE($2::jsonb->'events','[]'::jsonb)
        ORDER BY (revoked_at IS NOT NULL) DESC,id LIMIT 1`, team, string(trust)).Scan(&machine, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		registered, registerErr := registerMachineIdentity(ctx, tx, RegisterMachineRequest{TeamID: team, ActorID: manager.identityID, Name: request.Workload, ProofKind: "oidc", Trust: request.Trust}, clock.current())
		if registerErr != nil {
			return result, registerErr
		}
		machine = registered.ID
	} else if err != nil {
		return result, err
	} else if revoked != nil {
		return result, ErrMachineDenied
	}
	permission, err := createEnvironmentVisitorPermission(ctx, tx, EnvironmentVisitorPermission{MachineID: machine, TeamID: team, ProjectKey: request.ProjectKey, Scope: EnvironmentPermissionScope{EnvironmentIDs: []string{request.EnvironmentID}}, Services: request.Services, MaxDurationSeconds: request.MaxDurationSeconds, ExpiresAt: request.ExpiresAt}, clock.current())
	if err != nil {
		return result, err
	}
	encodedProtocols, err := json.Marshal(protocols)
	if err != nil {
		return result, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO control.workload_approvals(team_id,intent_key,request,machine_id,permission_id,protocols,created_at) VALUES($1,$2,$3::jsonb,$4,$5,$6::jsonb,$7)`, team, intent, string(payload), machine, permission.ID, string(encodedProtocols), now)
	if err != nil {
		return result, err
	}
	result, err = readWorkloadApproval(ctx, tx, team, intent)
	if err != nil {
		return result, err
	}
	if err = manager.finish(ctx, tx, team); err != nil {
		return WorkloadApproval{}, err
	}
	return result, tx.Commit(ctx)
}

// explicit approval is human-only. reuse the existing captured-session checks,
// but never let a provisioning capability or an internal actor stand in for it.
func (d *Database) workloadApprovalTransaction(ctx context.Context, team string, manager EnvironmentPublisherManager) (tx pgx.Tx, err error) {
	if manager.accessID == "" || manager.internalActor || manager.provisioningCredential != "" {
		return nil, ErrControlAuthentication
	}
	tx, err = d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if err = manager.start(ctx, tx, team); err != nil {
		rollback(ctx, tx, "authorize workload approval manager", &err)()
		return nil, err
	}
	return tx, nil
}

func readWorkloadApproval(ctx context.Context, tx pgx.Tx, team, intent string) (result WorkloadApproval, err error) {
	var request, trust, protocols []byte
	err = tx.QueryRow(ctx, `SELECT approval.intent_key,approval.request,approval.permission_id,approval.protocols,approval.created_at,
        machine.id,machine.team_id,machine.name,machine.proof_kind,machine.trust,machine.revision,machine.revoked_at,permission.revoked_at
        FROM control.workload_approvals approval
        JOIN control.machine_identities machine ON machine.id=approval.machine_id AND machine.team_id=approval.team_id
        JOIN control.machine_workload_permissions permission ON permission.id=approval.permission_id AND permission.team_id=approval.team_id AND permission.machine_id=approval.machine_id
        WHERE approval.team_id=$1 AND approval.intent_key=$2`, team, intent).Scan(&result.IntentKey, &request, &result.PermissionID, &protocols, &result.CreatedAt, &result.Machine.ID, &result.Machine.TeamID, &result.Machine.Name, &result.Machine.ProofKind, &trust, &result.Machine.Revision, &result.MachineRevokedAt, &result.PermissionRevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrWorkloadApprovalNotFound
	}
	if err != nil {
		return result, err
	}
	if err = json.Unmarshal(request, &result.Request); err != nil {
		return result, err
	}
	if err = json.Unmarshal(trust, &result.Machine.Trust); err != nil {
		return result, err
	}
	err = json.Unmarshal(protocols, &result.Protocols)
	return result, err
}
