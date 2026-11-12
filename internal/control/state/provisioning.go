package state

import (
	"context"
	"crypto/sha256"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
)

type ProvisioningOperation string

const (
	ProvisioningCreate       ProvisioningOperation = "create"
	ProvisioningRead         ProvisioningOperation = "read"
	ProvisioningUpdate       ProvisioningOperation = "update"
	ProvisioningEnroll       ProvisioningOperation = "enroll"
	ProvisioningRevokeMember ProvisioningOperation = "revoke_member"
	ProvisioningRetire       ProvisioningOperation = "retire"
)

func (op ProvisioningOperation) Valid() bool {
	switch op {
	case ProvisioningCreate, ProvisioningRead, ProvisioningUpdate, ProvisioningEnroll, ProvisioningRevokeMember, ProvisioningRetire:
		return true
	}
	return false
}

type ProvisioningGrant struct {
	ID                   string                     `json:"id"`
	MachineID            string                     `json:"machine_id"`
	TeamID               string                     `json:"team_id"`
	ProjectKey           string                     `json:"project_key"`
	Scope                EnvironmentPermissionScope `json:"scope"`
	Services             []string                   `json:"services"`
	Operations           []ProvisioningOperation    `json:"operations"`
	MaxEnrollmentMembers int                        `json:"max_enrollment_members"`
	MaxEnrollmentSeconds int                        `json:"max_enrollment_seconds"`
	EnrollmentBudget     int                        `json:"enrollment_budget"`
	ExpiresAt            time.Time                  `json:"expires_at"`
}

func (d *Database) CreateProvisioningGrant(ctx context.Context, g ProvisioningGrant, actor string, now time.Time) (result ProvisioningGrant, retErr error) {
	if !naming.ValidProjectKey(g.ProjectKey) || !validMachineOperations(g.Operations) || !g.ExpiresAt.After(now) || g.ExpiresAt.After(now.Add(366*24*time.Hour)) || g.MaxEnrollmentMembers < 0 || g.MaxEnrollmentMembers > 256 || g.MaxEnrollmentSeconds < 0 || g.MaxEnrollmentSeconds > 86400 || g.EnrollmentBudget < 0 || g.EnrollmentBudget > 65536 {
		return result, ErrEnvironmentInvalid
	}
	var err error
	if g.Scope, err = normalizeEnvironmentPermissionScope(g.Scope); err != nil {
		return result, err
	}
	if g.Services, err = normalizeEnvironmentPermissionServices(g.Services); err != nil {
		return result, err
	}
	for _, op := range g.Operations {
		if op == ProvisioningEnroll && (g.MaxEnrollmentMembers == 0 || g.MaxEnrollmentSeconds < 60 || g.EnrollmentBudget == 0) || op == ProvisioningCreate && (g.Scope.CollectionID == "" || !*g.Scope.IncludeFutureEnvironments) {
			return result, ErrEnvironmentInvalid
		}
	}
	tx, err := d.machineManagerTransaction(ctx, g.TeamID, actor)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create environment provisioning grant", &retErr)()
	if _, err = controlstatedb.New(tx).LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: g.TeamID, ProjectKey: g.ProjectKey}); err != nil {
		return result, publisherLookupError(err, ErrMachineDenied)
	}
	captured, err := captureEnvironmentPermissionScope(ctx, tx, g.TeamID, g.ProjectKey, g.Scope)
	if err != nil {
		return result, err
	}
	m, err := machineIdentity(ctx, tx, g.MachineID)
	if err != nil || m.TeamID != g.TeamID {
		if err == nil {
			err = ErrMachineDenied
		}
		return result, err
	}
	g.ID, err = opaqueid.New("mpg_")
	if err != nil {
		return result, err
	}
	ops := make([]string, len(g.Operations))
	for i, op := range g.Operations {
		ops[i] = string(op)
	}
	future := g.Scope.IncludeFutureEnvironments != nil && *g.Scope.IncludeFutureEnvironments
	_, err = tx.Exec(ctx, `INSERT INTO control.machine_provisioning_grants(id,machine_id,team_id,project_key,collection_id,include_future_environments,environment_ids,services,operations,max_enrollment_members,max_enrollment_seconds,enrollment_budget,expires_at) VALUES($1,$2,$3,$4,NULLIF($5,''),$6,$7,$8,$9,$10,$11,$12,$13)`, g.ID, g.MachineID, g.TeamID, g.ProjectKey, g.Scope.CollectionID, future, captured, g.Services, ops, g.MaxEnrollmentMembers, g.MaxEnrollmentSeconds, g.EnrollmentBudget, g.ExpiresAt)
	if err != nil {
		return result, err
	}
	if err = serviceManager(ctx, tx, g.TeamID, actor); err != nil {
		return result, err
	}
	return g, tx.Commit(ctx)
}

func (d *Database) RevokeProvisioningGrant(ctx context.Context, team, id, actor string, now time.Time) (retErr error) {
	tx, err := d.machineManagerTransaction(ctx, team, actor)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke environment provisioning grant", &retErr)()
	tag, err := tx.Exec(ctx, `UPDATE control.machine_provisioning_grants SET revoked_at=COALESCE(revoked_at,$3) WHERE id=$1 AND team_id=$2`, id, team, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrMachineDenied
	}
	return tx.Commit(ctx)
}

type ProvisioningSession struct {
	Credential string                     `json:"access_token"`
	TokenType  string                     `json:"token_type"`
	ExpiresAt  time.Time                  `json:"expires_at"`
	GrantID    string                     `json:"grant_id"`
	Operation  ProvisioningOperation      `json:"operation"`
	TeamID     string                     `json:"team_id"`
	ProjectKey string                     `json:"project_key"`
	Scope      EnvironmentPermissionScope `json:"scope"`
	Services   []string                   `json:"services"`
}

func (d *Database) ExchangeProvisioning(ctx context.Context, machine, grant string, operation ProvisioningOperation, proof MachineProof, audience string, now time.Time) (r ProvisioningSession, retErr error) {
	if !operation.Valid() {
		return r, ErrMachineDenied
	}
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer rollback(ctx, tx, "exchange environment provisioning proof", &retErr)()
	var selectedMachine string
	if err = tx.QueryRow(ctx, `SELECT machine_id,team_id FROM control.machine_provisioning_grants WHERE id=$1`, grant).Scan(&selectedMachine, &r.TeamID); err != nil {
		return r, publisherLookupError(err, ErrMachineDenied)
	}
	if machine != "" && machine != selectedMachine {
		return r, ErrMachineDenied
	}
	machine = selectedMachine
	if _, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, r.TeamID); err != nil {
		return r, publisherLookupError(err, ErrMachineDenied)
	}
	m, err := machineIdentity(ctx, tx, machine)
	if err != nil {
		return r, err
	}
	until, digest, err := verifyMachineProof(ctx, tx, m, proof, machineproof.Provisioning(grant, string(operation)), audience, clock.current())
	if err != nil {
		return r, err
	}
	var expires time.Time
	var collection string
	var future bool
	var ids []string
	err = tx.QueryRow(ctx, `SELECT project_key,COALESCE(collection_id,''),include_future_environments,environment_ids,services,expires_at FROM control.machine_provisioning_grants WHERE id=$1 AND machine_id=$2 AND team_id=$3 AND revoked_at IS NULL AND $4=ANY(operations) FOR UPDATE`, grant, machine, m.TeamID, string(operation)).Scan(&r.ProjectKey, &collection, &future, &ids, &r.Services, &expires)
	if err != nil {
		return r, publisherLookupError(err, ErrMachineDenied)
	}
	if collection == "" {
		r.Scope.EnvironmentIDs = ids
	} else {
		r.Scope = EnvironmentPermissionScope{CollectionID: collection, IncludeFutureEnvironments: new(future)}
	}
	proofUntil := until
	until = minTime(minTime(until, expires), now.Add(5*time.Minute))
	if !until.After(clock.current()) {
		return r, ErrMachineDenied
	}
	if m.ProofKind == "signing_key" {
		if err = consumeMachineProof(ctx, tx, machine, digest, proofUntil); err != nil {
			return r, err
		}
	}
	secret, _, err := privateSecret()
	if err != nil {
		return r, err
	}
	r.Credential, r.TokenType, r.ExpiresAt = "mpc_"+secret, "Bearer", until
	r.GrantID, r.Operation = grant, operation
	tokenDigest := sha256.Sum256([]byte(r.Credential))
	_, err = tx.Exec(ctx, `INSERT INTO control.machine_provisioning_sessions(credential_digest,machine_id,grant_id,identity_revision,operation,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, tokenDigest[:], machine, grant, m.Revision, string(operation), now, until)
	if err != nil {
		return ProvisioningSession{}, err
	}
	// proof consumption and session insertion can wait on database writes. spend
	// the originally selected deadline again rather than minting a fresh window.
	if !until.After(clock.current()) {
		return ProvisioningSession{}, ErrMachineDenied
	}
	return r, tx.Commit(ctx)
}

type ProvisioningScope struct {
	Operation                                       ProvisioningOperation
	TeamID, ProjectKey, EnvironmentID, CollectionID string
	Services                                        []string
	EnrollmentMembers                               int
	EnrollmentLifetime                              time.Duration
}

type ProvisioningPrincipal struct {
	MachineID, GrantID, TeamID, ProjectKey string
	ValidUntil                             time.Time
}

// authorization runs in the exact environment mutation transaction. the team
// guard pins identity and grant revocation; the original expiry still applies
// after every later lock wait and must be checked again before commit.
func (d *Database) AuthorizeProvisioning(ctx context.Context, tx pgx.Tx, credential string, scope ProvisioningScope, now time.Time) (r ProvisioningPrincipal, err error) {
	return authorizeProvisioning(ctx, tx, credential, scope, now, true)
}

func authorizeProvisioning(ctx context.Context, tx pgx.Tx, credential string, scope ProvisioningScope, now time.Time, spend bool) (r ProvisioningPrincipal, err error) {
	clock := newAuthorizationClock(now)
	if !strings.HasPrefix(credential, "mpc_") || len(credential) > 256 || !scope.Operation.Valid() || !opaqueid.Valid(scope.TeamID, opaqueid.TeamPrefix) || !naming.ValidProjectKey(scope.ProjectKey) || scope.EnvironmentID == "" && scope.Operation != ProvisioningCreate && (scope.Operation != ProvisioningRead || !opaqueid.Valid(scope.CollectionID, opaqueid.CollectionPrefix)) {
		return r, ErrMachineDenied
	}
	digest := sha256.Sum256([]byte(credential))
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, scope.TeamID); err != nil {
		return r, publisherLookupError(err, ErrMachineDenied)
	}
	if _, err = q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: scope.TeamID, ProjectKey: scope.ProjectKey}); err != nil {
		return r, publisherLookupError(err, ErrMachineDenied)
	}
	var collection string
	var future bool
	var captured, services []string
	var members, seconds, budget, used int
	var created, expires, grantExpires time.Time
	err = tx.QueryRow(ctx, `SELECT m.id,g.id,g.team_id,g.project_key,COALESCE(g.collection_id,''),g.include_future_environments,g.environment_ids,g.services,g.max_enrollment_members,g.max_enrollment_seconds,g.enrollment_budget,g.enrollment_used,s.created_at,s.expires_at,g.expires_at FROM control.machine_provisioning_sessions s JOIN control.machine_identities m ON m.id=s.machine_id JOIN control.machine_provisioning_grants g ON g.id=s.grant_id AND g.machine_id=m.id WHERE s.credential_digest=$1 AND m.team_id=$2 AND g.team_id=$2 AND g.project_key=$3 AND s.operation=$4 AND $4=ANY(g.operations) AND m.revoked_at IS NULL AND g.revoked_at IS NULL AND s.identity_revision=m.revision FOR UPDATE OF m,g,s`, digest[:], scope.TeamID, scope.ProjectKey, string(scope.Operation)).Scan(&r.MachineID, &r.GrantID, &r.TeamID, &r.ProjectKey, &collection, &future, &captured, &services, &members, &seconds, &budget, &used, &created, &expires, &grantExpires)
	if err != nil {
		return r, publisherLookupError(err, ErrMachineDenied)
	}
	r.ValidUntil = minTime(expires, grantExpires)
	if clock.current().Before(created) || !r.ValidUntil.After(clock.current()) || !environmentPermissionServicesContain(services, scope.Services) {
		return r, ErrMachineDenied
	}
	if scope.EnvironmentID == "" && scope.Operation == ProvisioningRead {
		if collection == "" || collection != scope.CollectionID {
			return r, ErrMachineDenied
		}
		if _, err = q.LockCollection(ctx, controlstatedb.LockCollectionParams{TeamID: scope.TeamID, ProjectKey: scope.ProjectKey, ID: scope.CollectionID}); err != nil {
			return r, publisherLookupError(err, ErrMachineDenied)
		}
	} else {
		if err = checkEnvironmentPermissionScope(ctx, tx, scope.TeamID, scope.ProjectKey, scope.EnvironmentID, scope.CollectionID, collection, future, captured); err != nil {
			return r, err
		}
	}
	if scope.Operation == ProvisioningEnroll {
		if !r.ValidUntil.After(clock.current()) || scope.EnrollmentMembers < 1 || scope.EnrollmentMembers > members || spend && scope.EnrollmentMembers > budget-used || scope.EnrollmentLifetime < time.Minute || scope.EnrollmentLifetime > time.Duration(seconds)*time.Second {
			return r, ErrMachineDenied
		}
		if spend {
			if _, err = tx.Exec(ctx, `UPDATE control.machine_provisioning_grants SET enrollment_used=enrollment_used+$2 WHERE id=$1`, r.GrantID, scope.EnrollmentMembers); err != nil {
				return r, err
			}
		}
	}
	if !r.ValidUntil.After(clock.current()) {
		return ProvisioningPrincipal{}, ErrMachineDenied
	}
	return r, nil
}
