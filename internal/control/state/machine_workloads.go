package state

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type MachineWorkloadPermission struct {
	ID         string    `json:"id"`
	MachineID  string    `json:"machine_id"`
	TeamID     string    `json:"team_id"`
	ProjectKey string    `json:"project_key"`
	Workload   string    `json:"workload"`
	Templates  []string  `json:"templates"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (d *Database) CreateMachineWorkloadPermission(ctx context.Context, p MachineWorkloadPermission, actor string, now time.Time) (r MachineWorkloadPermission, retErr error) {
	if !p.ExpiresAt.After(now) || p.ExpiresAt.After(now.Add(366*24*time.Hour)) {
		return r, ErrProjectConfigurationInvalid
	}
	tx, err := d.machineManagerTransaction(ctx, p.TeamID, actor)
	if err != nil {
		return r, err
	}
	defer rollback(ctx, tx, "approve machine workload", &retErr)()
	m, err := machineIdentity(ctx, tx, p.MachineID)
	if err != nil {
		return r, err
	}
	if m.TeamID != p.TeamID {
		return r, ErrMachineDenied
	}
	row, err := controlstatedb.New(tx).LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: p.TeamID, ProjectKey: p.ProjectKey})
	if err != nil {
		return r, publisherLookupError(err, ErrMachineDenied)
	}
	c, err := d.openAppliedProject(row)
	if err != nil {
		return r, err
	}
	w, found := c.Workloads[p.Workload]
	if !found || !approvedTemplates(c, p.Templates) || m.ProofKind == "signing_key" && w.Provider != "oidc" {
		return r, ErrProjectConfigurationInvalid
	}
	// OIDC permission cannot turn one registered subject into another policy's
	// subject. both policies must independently verify the supplied assertion.
	if m.ProofKind == "oidc" && (w.Provider != "oidc" || w.Trust.Digest() != m.Trust.Digest()) {
		return r, ErrProjectConfigurationInvalid
	}
	p.ID, err = opaqueid.New("mwp_")
	if err != nil {
		return r, err
	}
	p.Templates = sortedTemplates(p.Templates)
	_, err = tx.Exec(ctx, `INSERT INTO control.machine_workload_permissions(id,machine_id,team_id,project_key,workload,templates,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, p.ID, p.MachineID, p.TeamID, p.ProjectKey, p.Workload, p.Templates, p.ExpiresAt)
	if err != nil {
		return r, err
	}
	return p, tx.Commit(ctx)
}

func (d *Database) RevokeMachineWorkloadPermission(ctx context.Context, team, id, actor string, now time.Time) (retErr error) {
	tx, err := d.machineManagerTransaction(ctx, team, actor)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke machine workload permission", &retErr)()
	tag, err := tx.Exec(ctx, `UPDATE control.machine_workload_permissions SET revoked_at=COALESCE(revoked_at,$3) WHERE id=$1 AND team_id=$2`, id, team, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrMachineDenied
	}
	return tx.Commit(ctx)
}

type MachineWorkloadProof struct {
	MachineID, GroupID, Audience string
	// permission selection is server-derived for attachment, never client input.
	PermissionID string
	Proof        MachineProof
}

// group policy lookup exposes no descriptor. unknown and unauthorized groups
// use the same denial, including when the caller supplies a valid human token.
func (d *Database) PublisherGroupWorkloadPolicy(ctx context.Context, group, workload string) (r ProjectWorkload, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer rollback(ctx, tx, "read group workload policy", &retErr)()
	_, _, c, err := d.lockGroupWorkload(ctx, tx, group)
	if err != nil {
		return r, err
	}
	r, found := c.Workloads[workload]
	if !found {
		return r, ErrWorkloadDenied
	}
	return r, nil
}

func (d *Database) lockGroupWorkload(ctx context.Context, tx pgx.Tx, id string) (group controlstatedb.ControlProjectPublisherGroup, project controlstatedb.ControlAppliedProject, c ProjectConfiguration, err error) {
	var team string
	if err = tx.QueryRow(ctx, `SELECT team_id FROM control.project_publisher_groups WHERE id=$1`, id).Scan(&team); err != nil {
		err = publisherLookupError(err, ErrWorkloadDenied)
		return
	}
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, team); err != nil {
		err = publisherLookupError(err, ErrWorkloadDenied)
		return
	}
	if err = tx.QueryRow(ctx, `SELECT id,team_id,project_key,name,template_name FROM control.project_publisher_groups WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, id).Scan(&group.ID, &group.TeamID, &group.ProjectKey, &group.Name, &group.TemplateName); err != nil {
		err = publisherLookupError(err, ErrWorkloadDenied)
		return
	}
	project, err = q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: group.TeamID, ProjectKey: group.ProjectKey})
	if err != nil {
		err = publisherLookupError(err, ErrWorkloadDenied)
		return
	}
	c, err = d.openAppliedProject(project)
	return
}

type PublisherGroupWorkloadResolution = authorityv1.PublisherGroupWorkloadResolution

func (d *Database) ResolvePublisherGroupWorkload(ctx context.Context, groupID, workload, server string, execution oidc.WorkloadExecution, machine *MachineWorkloadProof, now time.Time) (r PublisherGroupWorkloadResolution, retErr error) {
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer rollback(ctx, tx, "resolve workload publisher group", &retErr)()
	group, project, c, err := d.lockGroupWorkload(ctx, tx, groupID)
	if err != nil {
		return r, err
	}
	p, found := c.Workloads[workload]
	if !found {
		return r, ErrWorkloadDenied
	}
	if machine != nil {
		var authority machineWorkloadAuthority
		execution, authority, err = d.verifyGroupMachine(ctx, tx, group, p, workload, *machine, "resolve", "", "", nil, clock.current())
		if err != nil {
			return r, err
		}
		if authority.Signed {
			if err = consumeMachineProof(ctx, tx, machine.MachineID, authority.Digest, authority.ProofUntil); err != nil {
				return r, err
			}
		}
	} else if id, found, e := registeredOIDCMachine(ctx, tx, group.TeamID, execution); e != nil {
		return r, e
	} else if found {
		execution, _, err = d.authorizeRegisteredOIDCGroup(ctx, tx, group, p, workload, id, execution, clock.current())
		if err != nil {
			return r, err
		}
	}
	if execution.Validate(clock.current()) != nil || !p.matches(execution) {
		return r, ErrWorkloadDenied
	}
	definition := group.TemplateName
	if definition == "" {
		definition = group.Name
	}
	services := map[string]controlv1.ServiceProtocol{}
	selected := []string{}
	for _, key := range p.Services {
		if s, ok := c.Services[key]; ok && s.PublisherGroup == definition {
			services[key] = controlv1.ServiceProtocol(s.Protocol)
			selected = append(selected, key)
		}
	}
	if len(selected) == 0 {
		return r, ErrWorkloadDenied
	}
	label := project.ProjectLabel
	if label == "" {
		label = project.ProjectKey
	}
	r = PublisherGroupWorkloadResolution{PublisherGroup: definition, Connection: controlv1.PublisherGroupConnection{Schema: 1, Server: server, TeamId: group.TeamID, ProjectKey: group.ProjectKey, SourceFingerprint: project.SourceFingerprint, ProjectLabel: label, GroupId: group.ID, GroupName: group.Name, Services: services, Workloads: map[string]controlv1.PublisherGroupConnectionWorkload{workload: {Provider: controlv1.WorkloadProvider(p.Provider), MaxDurationSeconds: p.MaxDurationSeconds, Services: selected}}}}
	return r, tx.Commit(ctx)
}

type machineWorkloadAuthority struct {
	MachineID, PermissionID string
	GroupID                 string
	Revision                int64
	Until                   time.Time
	ProofUntil              time.Time
	Digest                  []byte
	Signed                  bool
}

func (d *Database) verifyGroupMachine(ctx context.Context, tx pgx.Tx, group controlstatedb.ControlProjectPublisherGroup, p ProjectWorkload, workload string, request MachineWorkloadProof, operation, public, nonce string, services []string, now time.Time) (c oidc.WorkloadExecution, a machineWorkloadAuthority, err error) {
	if request.GroupID != group.ID {
		return c, a, ErrMachineDenied
	}
	m, a, err := machineGroupPermission(ctx, tx, group, workload, request.MachineID, request.PermissionID, now)
	if err != nil {
		return c, a, err
	}
	until, digest, err := verifyMachineProof(ctx, tx, m, request.Proof, machineproof.Workload(group.ID, workload, operation, public, nonce, services), request.Audience, now)
	if err != nil {
		return c, a, err
	}
	a.MachineID = m.ID
	a.Revision = m.Revision
	a.Until = minTime(a.Until, until)
	a.ProofUntil = until
	a.Digest = digest
	a.Signed = m.ProofKind == "signing_key"
	c = request.Proof.Execution
	if a.Signed {
		if p.Provider != "oidc" {
			return c, a, ErrMachineDenied
		}
		key, _ := publisherproof.KeyID(request.Proof.Assertion)
		origin := strings.Split(request.Audience, "/v1/")[0]
		c = oidc.WorkloadExecution{Provider: "oidc", Issuer: origin, Subject: m.ID, Audience: origin, TrustDigest: p.Trust.Digest(), IssuedAt: until.Add(-publisherproof.AssertionLifetime).Unix(), NotBefore: until.Add(-publisherproof.AssertionLifetime).Unix(), ExpiresAt: a.Until.Unix(), AssertionDigest: sha256.Sum256([]byte(request.Proof.Assertion)), RegisteredMachine: &oidc.RegisteredMachineExecution{ID: m.ID, KeyID: key, PermissionID: a.PermissionID, Revision: m.Revision}}
	} else if !p.matches(c) {
		return c, a, ErrMachineDenied
	}
	if c.ExpiresAt > a.Until.Unix() {
		c.ExpiresAt = a.Until.Unix()
	}
	if c.Validate(now) != nil {
		return c, a, ErrMachineDenied
	}
	return c, a, nil
}

func machineGroupPermission(ctx context.Context, tx pgx.Tx, group controlstatedb.ControlProjectPublisherGroup, workload, machine, permission string, now time.Time) (m MachineIdentity, a machineWorkloadAuthority, err error) {
	var environment bool
	if err = tx.QueryRow(ctx, `SELECT environment_id IS NOT NULL OR EXISTS(SELECT 1 FROM control.environments reverse_owner WHERE reverse_owner.group_id=publisher_group.id) FROM control.project_publisher_groups publisher_group WHERE id=$1`, group.ID).Scan(&environment); err != nil {
		return m, a, err
	}
	if environment {
		return m, a, ErrMachineDenied
	}
	m, err = machineIdentity(ctx, tx, machine)
	if err != nil {
		return m, a, err
	}
	if m.TeamID != group.TeamID || group.TemplateName == "" {
		return m, a, ErrMachineDenied
	}
	err = tx.QueryRow(ctx, `SELECT id,expires_at FROM control.machine_workload_permissions WHERE machine_id=$1 AND team_id=$2 AND project_key=$3 AND workload=$4 AND $5=ANY(templates) AND revoked_at IS NULL AND expires_at>$6 AND ($7='' OR id=$7) ORDER BY id LIMIT 1 FOR UPDATE`, m.ID, group.TeamID, group.ProjectKey, workload, group.TemplateName, now, permission).Scan(&a.PermissionID, &a.Until)
	if err != nil {
		return m, a, publisherLookupError(err, ErrMachineDenied)
	}
	a.MachineID = m.ID
	a.GroupID = group.ID
	a.Revision = m.Revision
	return m, a, nil
}

// look up registrations including revoked ones: omitting machine_id at a
// legacy workload endpoint must not turn a revoked machine back into a visitor.
func registeredOIDCMachine(ctx context.Context, tx pgx.Tx, team string, c oidc.WorkloadExecution) (id string, found bool, err error) {
	if c.Provider != "oidc" || c.RegisteredMachine != nil {
		return "", false, nil
	}
	err = tx.QueryRow(ctx, `SELECT id FROM control.machine_identities WHERE team_id=$1 AND proof_kind='oidc' AND trust->>'issuer'=$2 AND trust->>'audience'=$3 AND trust->'claims'->>'sub'=$4`, team, c.Issuer, c.Audience, c.Subject).Scan(&id)
	if err == pgx.ErrNoRows {
		return "", false, nil
	}
	return id, err == nil, err
}

func (d *Database) authorizeRegisteredOIDCGroup(ctx context.Context, tx pgx.Tx, group controlstatedb.ControlProjectPublisherGroup, p ProjectWorkload, workload, machine string, c oidc.WorkloadExecution, now time.Time) (oidc.WorkloadExecution, machineWorkloadAuthority, error) {
	m, a, err := machineGroupPermission(ctx, tx, group, workload, machine, "", now)
	if err != nil {
		return c, a, err
	}
	if c.Validate(now) != nil || !c.Matches(m.Trust) || !p.matches(c) {
		return c, a, ErrMachineDenied
	}
	a.Until = minTime(a.Until, time.Unix(c.ExpiresAt, 0))
	c.ExpiresAt = a.Until.Unix()
	return c, a, nil
}

func (d *Database) registeredMachineExchange(ctx context.Context, tx pgx.Tx, r ExchangeWorkloadRequest, p ProjectWorkload, c oidc.WorkloadExecution, now time.Time) (oidc.WorkloadExecution, machineWorkloadAuthority, error) {
	id, found, err := registeredOIDCMachine(ctx, tx, r.TeamID, c)
	if err != nil || !found {
		return c, machineWorkloadAuthority{}, err
	}
	if len(r.Services) == 0 {
		return c, machineWorkloadAuthority{}, ErrMachineDenied
	}
	groupID, _, qualified := strings.Cut(r.Services[0], "/")
	if !qualified {
		return c, machineWorkloadAuthority{}, ErrMachineDenied
	}
	for _, s := range r.Services {
		if !strings.HasPrefix(s, groupID+"/") {
			return c, machineWorkloadAuthority{}, ErrMachineDenied
		}
	}
	var group controlstatedb.ControlProjectPublisherGroup
	err = tx.QueryRow(ctx, `SELECT id,team_id,project_key,name,template_name FROM control.project_publisher_groups WHERE id=$1 AND team_id=$2 AND project_key=$3 AND deleted_at IS NULL FOR UPDATE`, groupID, r.TeamID, r.ProjectKey).Scan(&group.ID, &group.TeamID, &group.ProjectKey, &group.Name, &group.TemplateName)
	if err != nil {
		return c, machineWorkloadAuthority{}, publisherLookupError(err, ErrMachineDenied)
	}
	return d.authorizeRegisteredOIDCGroup(ctx, tx, group, p, r.Workload, id, c, now)
}

func (d *Database) ExchangeMachineWorkload(ctx context.Context, r ExchangeWorkloadRequest, machine MachineWorkloadProof, now time.Time) (WorkloadSession, error) {
	r.Machine = &machine
	return d.ExchangeWorkload(ctx, r, now)
}

func verifyMachineSession(ctx context.Context, tx pgx.Tx, id string, now time.Time) error {
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM control.workload_session_machines x WHERE x.session_id=$1) OR EXISTS(SELECT 1 FROM control.workload_session_machines x JOIN control.workload_sessions w ON w.id=x.session_id JOIN control.machine_identities m ON m.id=x.machine_id AND m.team_id=w.team_id AND m.revision=x.identity_revision AND m.revoked_at IS NULL JOIN control.machine_workload_permissions p ON p.id=x.permission_id AND p.machine_id=m.id AND p.team_id=w.team_id AND p.project_key=w.project_key AND p.workload=w.workload_name AND p.revoked_at IS NULL AND p.expires_at>$2 JOIN control.project_publisher_groups g ON g.id=x.group_id AND g.team_id=w.team_id AND g.project_key=w.project_key AND g.environment_id IS NULL AND g.template_name=ANY(p.templates) AND g.deleted_at IS NULL WHERE x.session_id=$1)`, id, now).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrWorkloadDenied
	}
	return nil
}

func machineExchangePublicKey(r ExchangeWorkloadRequest) string {
	return base64.RawURLEncoding.EncodeToString(r.PublicKey)
}
