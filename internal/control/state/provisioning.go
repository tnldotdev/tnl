package state

import (
	"context"
	"crypto/sha256"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
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
	ID                   string                  `json:"id"`
	MachineID            string                  `json:"machine_id"`
	TeamID               string                  `json:"team_id"`
	ProjectKey           string                  `json:"project_key"`
	Templates            []string                `json:"templates"`
	Operations           []ProvisioningOperation `json:"operations"`
	MaxEnrollmentMembers int                     `json:"max_enrollment_members"`
	MaxEnrollmentSeconds int                     `json:"max_enrollment_seconds"`
	EnrollmentBudget     int                     `json:"enrollment_budget"`
	ExpiresAt            time.Time               `json:"expires_at"`
}

func (d *Database) CreateProvisioningGrant(ctx context.Context, g ProvisioningGrant, actor string, now time.Time) (result ProvisioningGrant, retErr error) {
	if !validMachineOperations(g.Operations) || !g.ExpiresAt.After(now) || g.ExpiresAt.After(now.Add(366*24*time.Hour)) || g.MaxEnrollmentMembers < 0 || g.MaxEnrollmentMembers > 256 || g.MaxEnrollmentSeconds < 0 || g.MaxEnrollmentSeconds > 86400 || g.EnrollmentBudget < 0 || g.EnrollmentBudget > 65536 {
		return result, ErrProjectConfigurationInvalid
	}
	for _, op := range g.Operations {
		if op == ProvisioningEnroll && (g.MaxEnrollmentMembers == 0 || g.MaxEnrollmentSeconds < 60 || g.EnrollmentBudget == 0) {
			return result, ErrProjectConfigurationInvalid
		}
	}
	tx, err := d.machineManagerTransaction(ctx, g.TeamID, actor)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create provisioning grant", &retErr)()
	m, err := machineIdentity(ctx, tx, g.MachineID)
	if err != nil {
		return result, err
	}
	if m.TeamID != g.TeamID {
		return result, ErrMachineDenied
	}
	row, err := controlstatedb.New(tx).LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: g.TeamID, ProjectKey: g.ProjectKey})
	if err != nil {
		return result, publisherLookupError(err, ErrMachineDenied)
	}
	c, err := d.openAppliedProject(row)
	if err != nil {
		return result, err
	}
	if !approvedTemplates(c, g.Templates) {
		return result, ErrProjectConfigurationInvalid
	}
	g.Templates = sortedTemplates(g.Templates)
	g.ID, err = opaqueid.New("mpg_")
	if err != nil {
		return result, err
	}
	ops := make([]string, len(g.Operations))
	for i, op := range g.Operations {
		ops[i] = string(op)
	}
	_, err = tx.Exec(ctx, `INSERT INTO control.machine_provisioning_grants(id,machine_id,team_id,project_key,templates,operations,max_enrollment_members,max_enrollment_seconds,enrollment_budget,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, g.ID, g.MachineID, g.TeamID, g.ProjectKey, g.Templates, ops, g.MaxEnrollmentMembers, g.MaxEnrollmentSeconds, g.EnrollmentBudget, g.ExpiresAt)
	if err != nil {
		return result, err
	}
	return g, tx.Commit(ctx)
}

func (d *Database) RevokeProvisioningGrant(ctx context.Context, team, id, actor string, now time.Time) (retErr error) {
	tx, err := d.machineManagerTransaction(ctx, team, actor)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke provisioning grant", &retErr)()
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
	Credential        string                `json:"access_token"`
	TokenType         string                `json:"token_type"`
	ExpiresAt         time.Time             `json:"expires_at"`
	GrantID           string                `json:"grant_id"`
	Operation         ProvisioningOperation `json:"operation"`
	TeamID            string                `json:"team_id"`
	ProjectKey        string                `json:"project_key"`
	Templates         []string              `json:"templates"`
	ProjectRevision   int64                 `json:"project_revision"`
	SourceFingerprint string                `json:"source_fingerprint"`
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
	defer rollback(ctx, tx, "exchange provisioning proof", &retErr)()
	if machine == "" {
		if err = tx.QueryRow(ctx, `SELECT machine_id FROM control.machine_provisioning_grants WHERE id=$1`, grant).Scan(&machine); err != nil {
			return r, publisherLookupError(err, ErrMachineDenied)
		}
	}
	var team string
	if err = tx.QueryRow(ctx, `SELECT team_id FROM control.machine_identities WHERE id=$1`, machine).Scan(&team); err != nil {
		return r, publisherLookupError(err, ErrMachineDenied)
	}
	if _, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, team); err != nil {
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
	if err = tx.QueryRow(ctx, `SELECT team_id,project_key,templates,expires_at FROM control.machine_provisioning_grants WHERE id=$1 AND machine_id=$2 AND team_id=$4 AND revoked_at IS NULL AND $3=ANY(operations) FOR UPDATE`, grant, machine, string(operation), m.TeamID).Scan(&r.TeamID, &r.ProjectKey, &r.Templates, &expires); err != nil {
		return r, publisherLookupError(err, ErrMachineDenied)
	}
	project, err := controlstatedb.New(tx).LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		return r, publisherLookupError(err, ErrMachineDenied)
	}
	c, err := d.openAppliedProject(project)
	if err != nil {
		return r, err
	}
	// a removed template cannot be resurrected by exchanging an old grant.
	if !approvedTemplates(c, r.Templates) {
		return r, ErrMachineDenied
	}
	r.ProjectRevision = project.Revision
	r.SourceFingerprint = project.SourceFingerprint
	current := clock.current()
	proofUntil := until
	until = minTime(minTime(until, expires), now.Add(5*time.Minute))
	if !until.After(current) {
		return r, ErrMachineDenied
	}
	// platform tokens are reusable credentials. every exchange verifies them and
	// checks current grants again. only registered-key JTIs are single-use, and
	// replay records outlive the full proof, not merely the issued token.
	if m.ProofKind == "signing_key" {
		if err = consumeMachineProof(ctx, tx, machine, digest, proofUntil); err != nil {
			return r, err
		}
	}
	secret, _, err := privateSecret()
	if err != nil {
		return r, err
	}
	r.Credential = "mpc_" + secret
	r.TokenType = "Bearer"
	r.ExpiresAt = until
	r.GrantID = grant
	r.Operation = operation
	tokenDigest := sha256.Sum256([]byte(r.Credential))
	_, err = tx.Exec(ctx, `INSERT INTO control.machine_provisioning_sessions(credential_digest,machine_id,grant_id,identity_revision,operation,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, tokenDigest[:], machine, grant, m.Revision, string(operation), now, until)
	if err != nil {
		return ProvisioningSession{}, err
	}
	return r, tx.Commit(ctx)
}

type ProvisioningScope struct {
	Operation                             ProvisioningOperation
	TeamID, ProjectKey, Template, GroupID string
	EnrollmentMembers                     int
	EnrollmentLifetime                    time.Duration
}

type ProvisioningPrincipal struct {
	MachineID, GrantID, TeamID, ProjectKey, Template, GroupID string
	Templates                                                 []string
	ValidUntil                                                time.Time
}

// AuthorizeProvisioning must be called in the binding mutation's transaction,
// before changing state, including on idempotent retries. it retains the team,
// identity, grant, project and group locks until the caller commits or rolls back.
// this capability cannot authorize template edits, people, or visitor access.
func (d *Database) AuthorizeProvisioning(ctx context.Context, tx pgx.Tx, credential string, scope ProvisioningScope, now time.Time) (r ProvisioningPrincipal, err error) {
	clock := newAuthorizationClock(now)
	if !strings.HasPrefix(credential, "mpc_") || len(credential) > 256 || !scope.Operation.Valid() || scope.TeamID == "" || scope.ProjectKey == "" {
		return r, ErrMachineDenied
	}
	digest := sha256.Sum256([]byte(credential))
	if _, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, scope.TeamID); err != nil {
		return r, publisherLookupError(err, ErrMachineDenied)
	}
	var templates []string
	var members, seconds, budget, used int
	var created, expires, grantExpires time.Time
	err = tx.QueryRow(ctx, `SELECT m.id,g.id,g.team_id,g.project_key,g.templates,g.max_enrollment_members,g.max_enrollment_seconds,g.enrollment_budget,g.enrollment_used,s.created_at,s.expires_at,g.expires_at FROM control.machine_provisioning_sessions s JOIN control.machine_identities m ON m.id=s.machine_id JOIN control.machine_provisioning_grants g ON g.id=s.grant_id AND g.machine_id=m.id WHERE s.credential_digest=$1 AND m.team_id=$2 AND g.team_id=$2 AND g.project_key=$3 AND s.operation=$4 AND $4=ANY(g.operations) AND m.revoked_at IS NULL AND g.revoked_at IS NULL AND s.identity_revision=m.revision FOR UPDATE OF m,g,s`, digest[:], scope.TeamID, scope.ProjectKey, string(scope.Operation)).Scan(&r.MachineID, &r.GrantID, &r.TeamID, &r.ProjectKey, &templates, &members, &seconds, &budget, &used, &created, &expires, &grantExpires)
	if err != nil {
		return r, publisherLookupError(err, ErrMachineDenied)
	}
	current := clock.current()
	if current.Before(created) || !expires.After(current) || !grantExpires.After(current) {
		return r, ErrMachineDenied
	}
	row, err := controlstatedb.New(tx).LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: scope.TeamID, ProjectKey: scope.ProjectKey})
	if err != nil {
		return r, publisherLookupError(err, ErrMachineDenied)
	}
	c, err := d.openAppliedProject(row)
	if err != nil {
		return r, err
	}
	template := scope.Template
	if scope.GroupID != "" {
		var actual string
		if err = tx.QueryRow(ctx, `SELECT template_name FROM control.project_publisher_groups publisher_group WHERE id=$1 AND team_id=$2 AND project_key=$3 AND environment_id IS NULL AND NOT EXISTS(SELECT 1 FROM control.environments reverse_owner WHERE reverse_owner.group_id=publisher_group.id) AND deleted_at IS NULL FOR UPDATE`, scope.GroupID, scope.TeamID, scope.ProjectKey).Scan(&actual); err != nil {
			return r, publisherLookupError(err, ErrMachineDenied)
		}
		if template != "" && template != actual {
			return r, ErrMachineDenied
		}
		template = actual
	} else if scope.Operation != ProvisioningCreate && scope.Operation != ProvisioningRead {
		return r, ErrMachineDenied
	}
	approved := false
	for _, v := range templates {
		if c.PublisherGroups[v].Template {
			r.Templates = append(r.Templates, v)
		}
		approved = approved || v == template
	}
	list := scope.Operation == ProvisioningRead && scope.GroupID == "" && scope.Template == ""
	if !list && (!approved || !c.PublisherGroups[template].Template) {
		return r, ErrMachineDenied
	}
	if scope.Operation == ProvisioningEnroll {
		if scope.EnrollmentMembers < 1 || scope.EnrollmentMembers > members || scope.EnrollmentMembers > budget-used || scope.EnrollmentLifetime < time.Minute || scope.EnrollmentLifetime > time.Duration(seconds)*time.Second {
			return r, ErrMachineDenied
		}
		if _, err = tx.Exec(ctx, `UPDATE control.machine_provisioning_grants SET enrollment_used=enrollment_used+$2 WHERE id=$1`, r.GrantID, scope.EnrollmentMembers); err != nil {
			return r, err
		}
	}
	r.Template = template
	r.GroupID = scope.GroupID
	r.ValidUntil = minTime(expires, grantExpires)
	if !r.ValidUntil.After(clock.current()) {
		return ProvisioningPrincipal{}, ErrMachineDenied
	}
	return r, nil
}
