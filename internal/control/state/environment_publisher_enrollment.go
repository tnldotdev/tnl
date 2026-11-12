package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

type EnvironmentPublisherSelection struct {
	TeamID, ProjectKey, EnvironmentID string
	Manager                           EnvironmentPublisherManager
}

func (r EnvironmentPublisherSelection) valid() bool {
	return opaqueid.Valid(r.TeamID, opaqueid.TeamPrefix) && naming.ValidProjectKey(r.ProjectKey) && opaqueid.Valid(r.EnvironmentID, opaqueid.EnvironmentPrefix)
}

type IssueEnvironmentPublisherEnrollmentRequest struct {
	EnvironmentPublisherSelection
	ExpectedRevision          int64
	ExpectedConfigurationHash string
	Services                  []string
	MaxMembers                int
	Lifetime                  time.Duration
	Now                       time.Time
	IdempotencyKey            string
}

type EnvironmentPublisherEnrollment struct {
	TeamID, ProjectKey, EnvironmentID string
	Key                               string
	ExpiresAt                         time.Time
	MaxMembers                        int
}

// management starts with a captured session credential, never an actor ID or an
// internal assignment selector. exact machine scope is checked by the operation.
func lockEnvironmentPublisherManagement(ctx context.Context, tx pgx.Tx, r EnvironmentPublisherSelection) (row controlstatedb.ControlEnvironment, err error) {
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, r.TeamID); err != nil {
		return row, err
	}
	if err = r.Manager.start(ctx, tx, r.TeamID); err != nil {
		return row, err
	}
	if _, err = q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey}); err != nil {
		return row, err
	}
	row, err = q.LockEnvironment(ctx, controlstatedb.LockEnvironmentParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ID: r.EnvironmentID})
	if err != nil {
		return row, err
	}
	if row.RetiredAt.Valid {
		return row, ErrEnvironmentRetired
	}
	_, err = q.LockEnvironmentPublisherAssignment(ctx, controlstatedb.LockEnvironmentPublisherAssignmentParams{GroupID: row.GroupID, EnvironmentID: text(row.ID), TeamID: row.TeamID, ProjectKey: row.ProjectKey})
	return row, err
}

func (d *Database) IssueEnvironmentPublisherEnrollment(ctx context.Context, r IssueEnvironmentPublisherEnrollmentRequest) (result EnvironmentPublisherEnrollment, retErr error) {
	defer func() { retErr = environmentOperationError(retErr) }()
	clock := newAuthorizationClock(r.Now)
	if !r.EnvironmentPublisherSelection.valid() || r.ExpectedRevision < 1 || !fingerprintPattern.MatchString(r.ExpectedConfigurationHash) || len(r.Services) < 1 || len(r.Services) > 128 || r.MaxMembers < 1 || r.MaxMembers > 256 || r.Lifetime < time.Minute || r.Lifetime > 24*time.Hour || r.IdempotencyKey != "" && (len(r.IdempotencyKey) > 128 || !validEnvironmentKey(r.IdempotencyKey)) {
		return result, ErrEnvironmentInvalid
	}
	names := slices.Clone(r.Services)
	slices.Sort(names)
	for i, name := range names {
		if !serviceName.MatchString(name) || i > 0 && name == names[i-1] {
			return result, ErrEnvironmentInvalid
		}
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "issue environment publisher enrollment", &retErr)()
	row, err := lockEnvironmentPublisherManagement(ctx, tx, r.EnvironmentPublisherSelection)
	if err != nil {
		return result, err
	}
	if row.MutationRevision != r.ExpectedRevision || row.ConfigurationHash != r.ExpectedConfigurationHash {
		return result, ErrEnvironmentStale
	}
	_, _, projection, err := d.environmentProjection(ctx, tx, row)
	if err != nil {
		return result, err
	}
	type capturedService struct{ name, id string }
	captured := make([]capturedService, 0, len(names))
	for _, name := range names {
		configuration, found := projection[name]
		if !found {
			return result, ErrEnvironmentNotFound
		}
		var s capturedService
		if err = tx.QueryRow(ctx, `SELECT binding.service,service.id FROM control.applied_project_services binding JOIN control.services service ON service.id=binding.service_id WHERE binding.team_id=$1 AND binding.project_key=$2 AND binding.group_id=$3 AND binding.service=$4 AND binding.public_url_id IS NULL AND service.team_id=$1 AND service.protocol=$5 AND service.enabled AND service.deleted_at IS NULL FOR UPDATE OF binding,service`, row.TeamID, row.ProjectKey, row.GroupID, publisherGroupServiceKey(row.GroupID, name), configuration.Protocol).Scan(&s.name, &s.id); err != nil {
			return result, err
		}
		captured = append(captured, s)
	}
	scope := ProvisioningScope{Operation: ProvisioningEnroll, TeamID: r.TeamID, ProjectKey: r.ProjectKey, EnvironmentID: row.ID, Services: names, EnrollmentMembers: r.MaxMembers, EnrollmentLifetime: r.Lifetime}
	if err = r.Manager.authorize(ctx, tx, scope, false); err != nil {
		return result, err
	}
	if r.Manager.provisioningCredential != "" {
		previous, found, e := d.environmentProvisioningEnrollmentRetry(ctx, tx, r, names, clock)
		if e != nil {
			return result, e
		}
		if found {
			if e = r.Manager.finish(ctx, tx, r.TeamID); e != nil {
				return result, e
			}
			return previous, tx.Commit(ctx)
		}
	}
	if err = r.Manager.authorize(ctx, tx, scope, true); err != nil {
		return result, err
	}
	id, err := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
	if err != nil {
		return result, err
	}
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		return result, err
	}
	key := id + "." + base64.RawURLEncoding.EncodeToString(secret[:])
	digest := sha256.Sum256([]byte(key))
	until := r.Now.Add(r.Lifetime)
	if _, err = tx.Exec(ctx, `INSERT INTO control.publisher_group_enrollments(id,group_id,secret_digest,max_members,created_by_identity_id,expires_at,created_by_machine_id,provisioning_grant_id) VALUES($1,$2,$3,$4,NULLIF($5,''),$6,NULLIF($7,''),NULLIF($8,''))`, id, row.GroupID, digest[:], r.MaxMembers, r.Manager.identityID, until, r.Manager.machineID, r.Manager.provisioningGrantID); err != nil {
		return result, err
	}
	for _, s := range captured {
		if _, err = tx.Exec(ctx, `INSERT INTO control.environment_publisher_enrollment_services(enrollment_id,service,service_id) VALUES($1,$2,$3)`, id, s.name, s.id); err != nil {
			return result, err
		}
	}
	if r.Manager.provisioningCredential != "" {
		if err = d.recordEnvironmentProvisioningEnrollment(ctx, tx, r, names, id, key); err != nil {
			return result, err
		}
	}
	if err = recordPublisherGroupUpdate(ctx, tx, row.GroupID, r.Manager.issuer(), "", "enrollment/"+id, r.Now); err != nil {
		return result, err
	}
	if err = r.Manager.finish(ctx, tx, r.TeamID); err != nil {
		return result, err
	}
	if !until.After(clock.current()) {
		return result, ErrEnvironmentPublisher
	}
	result = EnvironmentPublisherEnrollment{TeamID: row.TeamID, ProjectKey: row.ProjectKey, EnvironmentID: row.ID, Key: key, ExpiresAt: until, MaxMembers: r.MaxMembers}
	return result, tx.Commit(ctx)
}

func (d *Database) RedeemEnvironmentPublisherEnrollment(ctx context.Context, secret string, public ed25519.PublicKey, now time.Time) (result EnvironmentPublisher, retErr error) {
	clock := newAuthorizationClock(now)
	parts := strings.Split(secret, ".")
	if len(secret) > 256 || len(parts) != 2 || !opaqueid.Valid(parts[0], opaqueid.PublisherEnrollmentPrefix) || len(public) != ed25519.PublicKeySize {
		return result, ErrEnvironmentPublisher
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "redeem environment publisher enrollment", &retErr)()
	var group string
	if err = tx.QueryRow(ctx, `SELECT owner.team_id,owner.project_key,owner.id,owner.group_id FROM control.publisher_group_enrollments enrollment JOIN control.project_publisher_groups assignment ON assignment.id=enrollment.group_id JOIN control.environments owner ON owner.id=assignment.environment_id AND owner.group_id=assignment.id AND owner.team_id=assignment.team_id AND owner.project_key=assignment.project_key WHERE enrollment.id=$1`, parts[0]).Scan(&result.TeamID, &result.ProjectKey, &result.EnvironmentID, &group); err != nil {
		return result, publisherLookupError(err, ErrEnvironmentPublisher)
	}
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, result.TeamID); err != nil {
		return result, publisherLookupError(err, ErrEnvironmentPublisher)
	}
	if _, err = q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: result.TeamID, ProjectKey: result.ProjectKey}); err != nil {
		return result, err
	}
	row, err := q.LockEnvironment(ctx, controlstatedb.LockEnvironmentParams{TeamID: result.TeamID, ProjectKey: result.ProjectKey, ID: result.EnvironmentID})
	if err != nil {
		return result, publisherLookupError(err, ErrEnvironmentPublisher)
	}
	if row.RetiredAt.Valid || row.GroupID != group {
		return result, ErrEnvironmentPublisher
	}
	if _, err = q.LockEnvironmentPublisherAssignment(ctx, controlstatedb.LockEnvironmentPublisherAssignmentParams{GroupID: group, EnvironmentID: text(row.ID), TeamID: row.TeamID, ProjectKey: row.ProjectKey}); err != nil {
		return result, publisherLookupError(err, ErrEnvironmentPublisher)
	}
	var issuer string
	var machine, provisioningGrant string
	var digest []byte
	var until time.Time
	var maxMembers int
	var live bool
	err = tx.QueryRow(ctx, `SELECT COALESCE(created_by_identity_id,''),COALESCE(created_by_machine_id,''),COALESCE(provisioning_grant_id,''),secret_digest,expires_at,max_members,revoked_at IS NULL FROM control.publisher_group_enrollments WHERE id=$1 AND group_id=$2 FOR UPDATE`, parts[0], group).Scan(&issuer, &machine, &provisioningGrant, &digest, &until, &maxMembers, &live)
	if err != nil {
		return result, publisherLookupError(err, ErrEnvironmentPublisher)
	}
	actual := sha256.Sum256([]byte(secret))
	actor := publisherIssuer{IdentityID: issuer, MachineID: machine, ProvisioningGrantID: provisioningGrant}
	if !live || !actor.valid() || !until.After(clock.current()) || subtle.ConstantTimeCompare(actual[:], digest) != 1 {
		return result, ErrEnvironmentPublisher
	}
	if err = checkEnvironmentEnrollmentAuthority(ctx, tx, row, actor, parts[0], maxMembers, until, clock); err != nil {
		return result, err
	}
	var existingGroup string
	var current bool
	err = tx.QueryRow(ctx, `SELECT member.publisher_identity_id,member.key_id,member.group_id,control.active_publisher(publisher.id,$2) AND signing_key.retired_at IS NULL AND publisher.team_id=$3 AND publisher.kind='installed' AND publisher.ownership='team' FROM control.publisher_group_members member JOIN control.publisher_identities publisher ON publisher.id=member.publisher_identity_id JOIN control.publisher_identity_keys signing_key ON signing_key.id=member.key_id AND signing_key.publisher_identity_id=publisher.id AND signing_key.public_key=member.public_key WHERE member.public_key=$1 FOR UPDATE OF member,publisher,signing_key`, []byte(public), clock.current(), result.TeamID).Scan(&result.PublisherIdentityID, &result.KeyID, &existingGroup, &current)
	if err == nil {
		// replay is identity recovery only. it must not recreate a revoked grant,
		// restore a removed mapping or capture a newly added service.
		if !current || existingGroup != group || !until.After(clock.current()) {
			return EnvironmentPublisher{}, ErrEnvironmentPublisher
		}
		if err = checkEnvironmentEnrollmentAuthority(ctx, tx, row, actor, parts[0], maxMembers, until, clock); err != nil {
			return EnvironmentPublisher{}, err
		}
		return result, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	var reused bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.publisher_identity_keys WHERE public_key=$1)`, []byte(public)).Scan(&reused); err != nil {
		return result, err
	}
	if reused {
		return result, ErrEnvironmentPublisher
	}
	var count, total int
	if err = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.publisher_group_members WHERE enrollment_id=$1),count(*) FROM control.publisher_group_members member JOIN control.project_publisher_groups assignment ON assignment.id=member.group_id JOIN control.publisher_identities publisher ON publisher.id=member.publisher_identity_id WHERE assignment.team_id=$2 AND assignment.project_key=$3 AND assignment.deleted_at IS NULL AND publisher.revoked_at IS NULL`, parts[0], result.TeamID, result.ProjectKey).Scan(&count, &total); err != nil {
		return result, err
	}
	if count >= maxMembers || total >= 256 {
		return result, ErrEnvironmentPublisher
	}
	_, _, projection, err := d.environmentProjection(ctx, tx, row)
	if err != nil {
		return result, err
	}
	rows, err := tx.Query(ctx, `SELECT service,service_id FROM control.environment_publisher_enrollment_services WHERE enrollment_id=$1 ORDER BY service`, parts[0])
	if err != nil {
		return result, err
	}
	type capturedService struct{ name, id string }
	captured, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (s capturedService, err error) {
		err = row.Scan(&s.name, &s.id)
		return s, err
	})
	if err != nil {
		return result, err
	}
	if len(captured) < 1 || len(captured) > 128 {
		return result, ErrEnvironmentPublisher
	}
	bindings := make([]controlstatedb.ControlAppliedProjectService, 0, len(captured))
	for _, s := range captured {
		configuration, found := projection[appliedServiceName(s.name)]
		if !found {
			return result, ErrEnvironmentPublisher
		}
		binding, e := q.LockEnvironmentPublisherService(ctx, controlstatedb.LockEnvironmentPublisherServiceParams{TeamID: row.TeamID, ProjectKey: row.ProjectKey, GroupID: text(group), ServiceID: text(s.id)})
		if e != nil {
			return result, publisherLookupError(e, ErrEnvironmentPublisher)
		}
		service, e := q.LockService(ctx, s.id)
		if e != nil {
			return result, e
		}
		if binding.Service != s.name || binding.PublicURLID.Valid || !service.Enabled || service.DeletedAt.Valid || service.TeamID != row.TeamID || service.Protocol != configuration.Protocol {
			return result, ErrEnvironmentPublisher
		}
		bindings = append(bindings, binding)
	}
	id, err := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	if err != nil {
		return result, err
	}
	kid, err := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	if err != nil {
		return result, err
	}
	if _, err = q.InsertPublisherIdentity(ctx, controlstatedb.InsertPublisherIdentityParams{ID: id, TeamID: row.TeamID, Name: row.Name, Kind: "installed", CreatedByIdentityID: nullableText(issuer), CreatedByMachineID: nullableText(machine), ProvisioningGrantID: nullableText(provisioningGrant), CreatedAt: timestamptz(now), Ownership: "team"}); err != nil {
		return result, err
	}
	if err = q.InsertPublisherKey(ctx, controlstatedb.InsertPublisherKeyParams{ID: kid, PublisherIdentityID: id, PublicKey: public, Revision: 1, CreatedAt: timestamptz(now)}); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO control.publisher_group_members(publisher_identity_id,group_id,enrollment_id,public_key,key_id) VALUES($1,$2,$3,$4,$5)`, id, group, parts[0], []byte(public), kid); err != nil {
		return result, err
	}
	for _, binding := range bindings {
		grant, e := insertPublisherGrantForIssuer(ctx, q, id, actor, servicePublisherScope{teamID: row.TeamID, serviceID: binding.ServiceID.String}, nil, now)
		if e != nil {
			return result, e
		}
		if _, err = tx.Exec(ctx, `INSERT INTO control.publisher_group_service_grants(publisher_identity_id,team_id,project_key,service,grant_id) VALUES($1,$2,$3,$4,$5)`, id, row.TeamID, row.ProjectKey, binding.Service, grant.ID); err != nil {
			return result, err
		}
	}
	if err = recordPublisherGroupUpdate(ctx, tx, group, actor, id, "enroll-member/"+id, now); err != nil {
		return result, err
	}
	if err = checkEnvironmentEnrollmentAuthority(ctx, tx, row, actor, parts[0], maxMembers, until, clock); err != nil {
		return EnvironmentPublisher{}, err
	}
	result.PublisherIdentityID, result.KeyID = id, kid
	return result, tx.Commit(ctx)
}

func checkEnvironmentEnrollmentIssuer(ctx context.Context, tx pgx.Tx, group, issuer string, until time.Time, clock authorizationClock) error {
	var current bool
	if err := tx.QueryRow(ctx, `SELECT control.environment_group_manager($1,$2,$3)`, group, issuer, clock.current()).Scan(&current); err != nil {
		return err
	}
	if !current || !until.After(clock.current()) {
		return ErrEnvironmentPublisher
	}
	return nil
}
