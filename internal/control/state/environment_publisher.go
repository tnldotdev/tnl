package state

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

var ErrEnvironmentPublisher = errors.New("environment publisher lease or enrollment is unavailable")

const EnvironmentPublisherLeaseLifetime = 2 * time.Minute

type EnvironmentPublisher struct {
	TeamID              string `json:"team_id"`
	ProjectKey          string `json:"project_key"`
	EnvironmentID       string `json:"environment_id"`
	PublisherIdentityID string `json:"publisher_identity_id"`
	KeyID               string `json:"key_id"`
}

type environmentPublisherMember struct {
	EnvironmentPublisher
	groupID string
}

type EnvironmentPublisherStatus struct {
	EnvironmentPublisher
	Runtime          *PublisherRuntimeStatus `json:"runtime,omitempty"`
	ObservedRevision int64                   `json:"observed_revision"`
	CurrentRevision  int64                   `json:"current_revision"`
	SnapshotAt       time.Time               `json:"snapshot_at"`
	AcknowledgedAt   *time.Time              `json:"acknowledged_at,omitempty"`
	Healthy          bool                    `json:"healthy"`
	LeaseExpiresAt   *time.Time              `json:"lease_expires_at,omitempty"`
}

type EnvironmentPublisherLease struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type EnvironmentPublisherAssignment struct {
	Service       string                        `json:"service"`
	ServiceID     string                        `json:"service_id"`
	GrantID       string                        `json:"grant_id"`
	TrustRevision int64                         `json:"trust_revision"`
	Configuration EnvironmentServicePublication `json:"configuration"`
}

type EnvironmentPublisherAssignments struct {
	Publisher             EnvironmentPublisher             `json:"publisher"`
	Environment           EnvironmentPublication           `json:"environment"`
	Services              []EnvironmentPublisherAssignment `json:"services"`
	CertificateStatePlans []CertificatePlan                `json:"certificate_state_plans"`
}

// verification consumes a one-use environment proof without replacing a lease.
func (d *Database) VerifyEnvironmentPublisher(ctx context.Context, id, environment, assertion, audience string, now time.Time) (result EnvironmentPublisher, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "verify environment publisher", &retErr)()
	member, _, err := authorizeEnvironmentPublisherAssertion(ctx, tx, id, environment, assertion, audience, now)
	if err != nil {
		return result, err
	}
	return member.EnvironmentPublisher, tx.Commit(ctx)
}

func authorizeEnvironmentPublisherAssertion(ctx context.Context, tx pgx.Tx, id, environment, assertion, audience string, now time.Time) (result environmentPublisherMember, proofUntil time.Time, err error) {
	clock := newAuthorizationClock(now)
	kid, err := publisherproof.KeyID(assertion)
	if err != nil || !opaqueid.Valid(environment, opaqueid.EnvironmentPrefix) {
		return result, proofUntil, ErrEnvironmentPublisher
	}
	if err = tx.QueryRow(ctx, `SELECT team_id FROM control.environments WHERE id=$1`, environment).Scan(&result.TeamID); err != nil {
		return result, proofUntil, publisherLookupError(err, ErrEnvironmentPublisher)
	}
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, result.TeamID); err != nil {
		return result, proofUntil, publisherLookupError(err, ErrEnvironmentPublisher)
	}
	var public []byte
	err = tx.QueryRow(ctx, `SELECT signing_key.public_key,owner.project_key,assignment.id FROM control.environments owner JOIN control.project_publisher_groups assignment ON assignment.id=owner.group_id AND assignment.environment_id=owner.id AND assignment.team_id=owner.team_id AND assignment.project_key=owner.project_key JOIN control.publisher_group_members member ON member.group_id=assignment.id JOIN control.publisher_identities publisher ON publisher.id=member.publisher_identity_id AND publisher.team_id=owner.team_id JOIN control.publisher_identity_keys signing_key ON signing_key.id=member.key_id AND signing_key.publisher_identity_id=publisher.id AND signing_key.public_key=member.public_key WHERE publisher.id=$1 AND owner.id=$2 AND signing_key.id=$3 AND owner.retired_at IS NULL AND assignment.deleted_at IS NULL AND control.active_publisher(publisher.id,$4) AND signing_key.retired_at IS NULL AND publisher.kind='installed' AND publisher.ownership='team' FOR UPDATE OF member,publisher,signing_key`, id, environment, kid, clock.current()).Scan(&public, &result.ProjectKey, &result.groupID)
	if err != nil {
		return result, proofUntil, publisherLookupError(err, ErrEnvironmentPublisher)
	}
	a, err := publisherproof.Verify(assertion, id, kid, environment, audience, public, clock.current())
	if err != nil {
		return result, proofUntil, ErrEnvironmentPublisher
	}
	if err = q.PrunePublisherAssertions(ctx, controlstatedb.PrunePublisherAssertionsParams{PublisherIdentityID: id, Now: timestamptz(clock.current())}); err != nil {
		return result, proofUntil, err
	}
	n, err := q.ClaimPublisherAssertion(ctx, controlstatedb.ClaimPublisherAssertionParams{PublisherIdentityID: id, AssertionID: a.ID, ExpiresAt: timestamptz(a.Until)})
	if err != nil {
		return result, proofUntil, err
	}
	if n != 1 || !a.Until.After(clock.current()) {
		return result, proofUntil, ErrEnvironmentPublisher
	}
	result.EnvironmentID, result.PublisherIdentityID, result.KeyID = environment, id, kid
	return result, a.Until, nil
}

func (d *Database) AcquireEnvironmentPublisherLease(ctx context.Context, id, environment, assertion, audience string, now time.Time) (result EnvironmentPublisherLease, retErr error) {
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "acquire environment publisher lease", &retErr)()
	member, proofUntil, err := authorizeEnvironmentPublisherAssertion(ctx, tx, id, environment, assertion, audience, now)
	if err != nil {
		return result, err
	}
	result, err = issueEnvironmentPublisherLease(ctx, tx, id, member.KeyID, now.Add(EnvironmentPublisherLeaseLifetime))
	if err != nil {
		return result, err
	}
	if !proofUntil.After(clock.current()) || !result.ExpiresAt.After(clock.current()) {
		return EnvironmentPublisherLease{}, ErrEnvironmentPublisher
	}
	return result, tx.Commit(ctx)
}

func issueEnvironmentPublisherLease(ctx context.Context, tx pgx.Tx, id, key string, until time.Time) (result EnvironmentPublisherLease, err error) {
	secret, digest, err := privateSecret()
	if err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM control.publisher_group_leases WHERE publisher_identity_id=$1`, id); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO control.publisher_group_leases(token_digest,publisher_identity_id,key_id,expires_at) VALUES($1,$2,$3,$4)`, digest, id, key, until); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.publisher_group_members SET lease_expires_at=$2 WHERE publisher_identity_id=$1`, id, until); err != nil {
		return result, err
	}
	return EnvironmentPublisherLease{AccessToken: "epl_" + secret, ExpiresAt: until}, nil
}

func lockEnvironmentPublisherLease(ctx context.Context, tx pgx.Tx, token string, now time.Time) (result environmentPublisherMember, until time.Time, err error) {
	clock := newAuthorizationClock(now)
	if !strings.HasPrefix(token, "epl_") {
		return result, until, ErrEnvironmentPublisher
	}
	digest, err := serviceSecretDigest(strings.TrimPrefix(token, "epl_"))
	if err != nil {
		return result, until, ErrEnvironmentPublisher
	}
	if err = tx.QueryRow(ctx, `SELECT assignment.team_id FROM control.publisher_group_leases lease JOIN control.publisher_group_members member ON member.publisher_identity_id=lease.publisher_identity_id JOIN control.project_publisher_groups assignment ON assignment.id=member.group_id WHERE lease.token_digest=$1`, digest).Scan(&result.TeamID); err != nil {
		return result, until, publisherLookupError(err, ErrEnvironmentPublisher)
	}
	if _, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, result.TeamID); err != nil {
		return result, until, publisherLookupError(err, ErrEnvironmentPublisher)
	}
	err = tx.QueryRow(ctx, `SELECT owner.project_key,owner.id,assignment.id,member.publisher_identity_id,member.key_id,lease.expires_at FROM control.publisher_group_leases lease JOIN control.publisher_group_members member ON member.publisher_identity_id=lease.publisher_identity_id AND member.key_id=lease.key_id JOIN control.project_publisher_groups assignment ON assignment.id=member.group_id JOIN control.environments owner ON owner.id=assignment.environment_id AND owner.group_id=assignment.id AND owner.team_id=assignment.team_id AND owner.project_key=assignment.project_key JOIN control.publisher_identities publisher ON publisher.id=member.publisher_identity_id AND publisher.team_id=owner.team_id JOIN control.publisher_identity_keys signing_key ON signing_key.id=lease.key_id AND signing_key.publisher_identity_id=publisher.id AND signing_key.public_key=member.public_key WHERE lease.token_digest=$1 AND lease.expires_at>$2 AND owner.retired_at IS NULL AND assignment.deleted_at IS NULL AND control.active_publisher(publisher.id,$2) AND signing_key.retired_at IS NULL AND publisher.kind='installed' AND publisher.ownership='team'`, digest, clock.current()).Scan(&result.ProjectKey, &result.EnvironmentID, &result.groupID, &result.PublisherIdentityID, &result.KeyID, &until)
	return result, until, publisherLookupError(err, ErrEnvironmentPublisher)
}

func (d *Database) GetEnvironmentPublisherAssignments(ctx context.Context, token string, now time.Time) (result EnvironmentPublisherAssignments, retErr error) {
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get environment publisher assignments", &retErr)()
	m, until, err := lockEnvironmentPublisherLease(ctx, tx, token, now)
	if err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	configuration, environment, err := d.environmentPublisherConfiguration(ctx, tx, m)
	if err != nil {
		return result, err
	}
	result = EnvironmentPublisherAssignments{Publisher: m.EnvironmentPublisher, Environment: environment, Services: []EnvironmentPublisherAssignment{}, CertificateStatePlans: []CertificatePlan{}}
	checkpoints, err := q.ListPublisherCertificateCheckpoints(ctx, m.PublisherIdentityID)
	if err != nil {
		return result, err
	}
	if len(checkpoints) > 1024 {
		return result, ErrEnvironmentPublisher
	}
	for _, checkpoint := range checkpoints {
		var plan CertificatePlan
		if json.Unmarshal(checkpoint, &plan) != nil {
			return result, ErrEnvironmentPublisher
		}
		result.CertificateStatePlans = append(result.CertificateStatePlans, plan)
	}
	services, err := q.ListAppliedProjectServices(ctx, controlstatedb.ListAppliedProjectServicesParams{TeamID: m.TeamID, ProjectKey: m.ProjectKey})
	if err != nil {
		return result, err
	}
	for _, binding := range services {
		if binding.GroupID.String != m.groupID {
			continue
		}
		if !binding.ServiceID.Valid || binding.PublicURLID.Valid {
			return result, ErrEnvironmentInvalid
		}
		var assignment EnvironmentPublisherAssignment
		err = tx.QueryRow(ctx, `SELECT grant_record.id,service.trust_revision FROM control.publisher_group_service_grants mapping JOIN control.publisher_grants grant_record ON grant_record.id=mapping.grant_id AND grant_record.publisher_identity_id=mapping.publisher_identity_id JOIN control.services service ON service.id=grant_record.service_id AND service.team_id=$2 AND service.enabled AND service.deleted_at IS NULL WHERE mapping.publisher_identity_id=$1 AND mapping.team_id=$2 AND mapping.project_key=$3 AND mapping.service=$4 AND grant_record.kind='service' AND grant_record.service_id=$5 AND grant_record.revoked_at IS NULL AND (grant_record.expires_at IS NULL OR grant_record.expires_at>$6)`, m.PublisherIdentityID, m.TeamID, m.ProjectKey, binding.Service, binding.ServiceID, clock.current()).Scan(&assignment.GrantID, &assignment.TrustRevision)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return result, err
		}
		assignment.Service = appliedServiceName(binding.Service)
		assignment.ServiceID = binding.ServiceID.String
		var found bool
		assignment.Configuration, found = configuration[assignment.Service]
		if !found {
			return result, ErrEnvironmentStale
		}
		result.Services = append(result.Services, assignment)
	}
	if !until.After(clock.current()) {
		return EnvironmentPublisherAssignments{}, ErrEnvironmentPublisher
	}
	return result, tx.Commit(ctx)
}

func (d *Database) AcknowledgeEnvironmentPublisher(ctx context.Context, token string, requested EnvironmentPublication, healthy bool, now time.Time) (retErr error) {
	clock := newAuthorizationClock(now)
	if !requested.valid() {
		return ErrEnvironmentStale
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "acknowledge environment publisher", &retErr)()
	m, until, err := lockEnvironmentPublisherLease(ctx, tx, token, now)
	if err != nil {
		return err
	}
	_, current, err := d.environmentPublisherConfiguration(ctx, tx, m)
	if err != nil {
		return err
	}
	if current != requested {
		return ErrEnvironmentStale
	}
	if err = controlstatedb.New(tx).AcknowledgePublisherGroupConfiguration(ctx, controlstatedb.AcknowledgePublisherGroupConfigurationParams{PublisherIdentityID: m.PublisherIdentityID, Revision: current.MutationRevision, Healthy: healthy, AcknowledgedAt: timestamptz(now)}); err != nil {
		return err
	}
	if !until.After(clock.current()) {
		return ErrEnvironmentPublisher
	}
	return tx.Commit(ctx)
}

func listEnvironmentPublisherStatus(ctx context.Context, tx pgx.Tx, team, project string) ([]EnvironmentPublisherStatus, error) {
	now := time.Now().UTC()
	rows, err := controlstatedb.New(tx).ListEnvironmentPublisherStatus(ctx, controlstatedb.ListEnvironmentPublisherStatusParams{TeamID: team, ProjectKey: project, Now: timestamptz(now)})
	if err != nil {
		return nil, err
	}
	result := []EnvironmentPublisherStatus{}
	for _, row := range rows {
		s := EnvironmentPublisherStatus{EnvironmentPublisher: EnvironmentPublisher{TeamID: team, ProjectKey: project, EnvironmentID: row.EnvironmentID, PublisherIdentityID: row.PublisherIdentityID, KeyID: row.KeyID}, ObservedRevision: row.ObservedRevision, CurrentRevision: row.CurrentRevision, Healthy: row.Healthy, SnapshotAt: now}
		if row.LeaseExpiresAt.Valid {
			s.LeaseExpiresAt = &row.LeaseExpiresAt.Time
		}
		if row.AcknowledgedAt.Valid {
			s.AcknowledgedAt = &row.AcknowledgedAt.Time
		}
		s.Runtime, err = publisherRuntimeStatus(ctx, controlstatedb.New(tx), s.PublisherIdentityID, now)
		if err != nil {
			return nil, err
		}
		if s.Runtime != nil {
			s.Healthy = s.Healthy && s.Runtime.Active
		}
		result = append(result, s)
	}
	return result, nil
}

func (d *Database) ListEnvironmentPublishers(ctx context.Context, r EnvironmentPublisherSelection) (result []EnvironmentPublisherStatus, retErr error) {
	defer func() { retErr = environmentOperationError(retErr) }()
	if !r.valid() {
		return nil, ErrEnvironmentInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "list environment publishers", &retErr)()
	row, err := lockEnvironmentPublisherManagement(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	if err = d.authorizeEnvironmentProjection(ctx, tx, r.Manager, row, ProvisioningRead); err != nil {
		return nil, err
	}
	members, err := listEnvironmentPublisherStatus(ctx, tx, r.TeamID, r.ProjectKey)
	if err != nil {
		return nil, err
	}
	result = []EnvironmentPublisherStatus{}
	for _, member := range members {
		if member.EnvironmentID == r.EnvironmentID {
			result = append(result, member)
		}
	}
	if err = r.Manager.finish(ctx, tx, r.TeamID); err != nil {
		return nil, err
	}
	return result, tx.Commit(ctx)
}

func (d *Database) RevokeEnvironmentPublisher(ctx context.Context, r EnvironmentPublisherSelection, publisher string, now time.Time) (retErr error) {
	defer func() { retErr = environmentOperationError(retErr) }()
	if !r.valid() || !opaqueid.Valid(publisher, opaqueid.PublisherIdentityPrefix) {
		return ErrEnvironmentInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke environment publisher", &retErr)()
	row, err := lockEnvironmentPublisherManagement(ctx, tx, r)
	if err != nil {
		return err
	}
	if err = d.authorizeEnvironmentProjection(ctx, tx, r.Manager, row, ProvisioningRevokeMember); err != nil {
		return err
	}
	if err = setServiceAuditIssuer(ctx, tx, r.Manager.issuer()); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	services, err := q.ListAppliedProjectServices(ctx, controlstatedb.ListAppliedProjectServicesParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err != nil {
		return err
	}
	for _, service := range services {
		if service.GroupID.String == row.GroupID && service.ServiceID.Valid {
			if _, err = q.LockService(ctx, service.ServiceID.String); err != nil {
				return err
			}
		}
	}
	var selected string
	if err = tx.QueryRow(ctx, `SELECT member.publisher_identity_id FROM control.publisher_group_members member JOIN control.publisher_identities publisher ON publisher.id=member.publisher_identity_id AND publisher.team_id=$3 WHERE member.publisher_identity_id=$1 AND member.group_id=$2 FOR UPDATE OF member,publisher`, publisher, row.GroupID, row.TeamID).Scan(&selected); err != nil {
		return err
	}
	for _, service := range services {
		if service.GroupID.String == row.GroupID && service.ServiceID.Valid {
			if err = closeRevokedPrivatePublication(ctx, tx, q, service.ServiceID.String, publisher, "", now); err != nil {
				return err
			}
		}
	}
	if _, err = q.RevokePublisherIdentity(ctx, controlstatedb.RevokePublisherIdentityParams{ID: publisher, TeamID: r.TeamID, Now: timestamptz(now)}); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.publisher_grants SET revoked_at=COALESCE(revoked_at,$2) WHERE publisher_identity_id=$1`, publisher, now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM control.publisher_group_leases WHERE publisher_identity_id=$1`, publisher); err != nil {
		return err
	}
	if err = recordPublisherGroupUpdate(ctx, tx, row.GroupID, r.Manager.issuer(), publisher, "revoke-member/"+publisher, now); err != nil {
		return err
	}
	if err = r.Manager.finish(ctx, tx, r.TeamID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *Database) removePublisherGroup(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, group string, now time.Time) error {
	if err := retireServiceNamespace(ctx, tx, group, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE control.publisher_grants SET revoked_at=COALESCE(revoked_at,$2) WHERE publisher_identity_id IN(SELECT publisher_identity_id FROM control.publisher_group_members WHERE group_id=$1)`, group, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE control.publisher_identities SET revoked_at=COALESCE(revoked_at,$2) WHERE id IN(SELECT publisher_identity_id FROM control.publisher_group_members WHERE group_id=$1)`, group, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE control.publisher_group_enrollments SET revoked_at=COALESCE(revoked_at,$2) WHERE group_id=$1`, group, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE control.project_publisher_groups SET deleted_at=$2 WHERE id=$1`, group, now)
	return err
}
