package controlstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
)

var ErrPublisherGroup = errors.New("publisher group lease or enrollment is unavailable")

const PublisherGroupLeaseLifetime = 2 * time.Minute

type PublisherGroupEnrollment struct {
	Key        string    `json:"enrollment_key"`
	GroupID    string    `json:"group_id"`
	ExpiresAt  time.Time `json:"expires_at"`
	MaxMembers int       `json:"max_members"`
}
type PublisherGroupMember struct {
	TeamID              string `json:"team_id"`
	ProjectKey          string `json:"project_key"`
	GroupID             string `json:"group_id"`
	GroupName           string `json:"group_name"`
	PublisherIdentityID string `json:"publisher_identity_id"`
	KeyID               string `json:"key_id"`
}
type PublisherGroupMemberStatus struct {
	PublisherGroupMember
	Runtime          *PublisherRuntimeStatus `json:"runtime,omitempty"`
	ObservedRevision int64                   `json:"observed_revision"`
	Healthy          bool                    `json:"healthy"`
	LeaseExpiresAt   *time.Time              `json:"lease_expires_at,omitempty"`
}
type PublisherGroupLease struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}
type PublisherGroupVerification struct {
	Member     PublisherGroupMember `json:"member"`
	GroupNames []string             `json:"group_names"`
}
type PublisherGroupServiceAssignment struct {
	Service       string                      `json:"service"`
	ServiceID     string                      `json:"service_id"`
	Kind          string                      `json:"service_kind"`
	GrantID       string                      `json:"grant_id"`
	Hostname      string                      `json:"hostname,omitempty"`
	TrustRevision int64                       `json:"trust_revision"`
	Configuration ProjectServiceConfiguration `json:"configuration"`
}
type PublisherGroupAssignments struct {
	Member                   PublisherGroupMember              `json:"member"`
	Revision                 int64                             `json:"revision"`
	ConfigurationHash        string                            `json:"configuration_hash"`
	Services                 []PublisherGroupServiceAssignment `json:"services"`
	CertificateStateRequired bool                              `json:"certificate_state_required"`
}

func (d *Database) IssuePublisherGroupEnrollment(ctx context.Context, team, project, group, actor string, maxMembers int, lifetime time.Duration, now time.Time) (result PublisherGroupEnrollment, retErr error) {
	if maxMembers < 1 || maxMembers > 256 || lifetime < time.Minute || lifetime > 24*time.Hour {
		return result, ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "issue publisher group enrollment", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, team); err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	if err = privateServiceManager(ctx, tx, team, actor); err != nil {
		return result, err
	}
	if err = SetServiceAuditActor(ctx, tx, actor); err != nil {
		return result, err
	}
	var gid string
	if err = tx.QueryRow(ctx, `SELECT g.id FROM control.project_publisher_groups g JOIN control.publisher_group_names alias ON alias.group_id=g.id WHERE alias.team_id=$1 AND alias.project_key=$2 AND alias.name=$3 AND g.deleted_at IS NULL FOR UPDATE OF g`, team, project, group).Scan(&gid); err != nil {
		return result, publisherLookupError(err, ErrPublisherGroup)
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
	until := now.Add(lifetime)
	_, err = tx.Exec(ctx, `INSERT INTO control.publisher_group_enrollments(id,group_id,secret_digest,max_members,created_by_identity_id,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, id, gid, digest[:], maxMembers, actor, until)
	if err != nil {
		return result, err
	}
	if err = recordPublisherGroupUpdate(ctx, tx, gid, actor, "", "enrollment/"+id, now); err != nil {
		return result, err
	}
	return PublisherGroupEnrollment{Key: key, GroupID: gid, ExpiresAt: until, MaxMembers: maxMembers}, tx.Commit(ctx)
}

func (d *Database) RedeemPublisherGroupEnrollment(ctx context.Context, secret string, public ed25519.PublicKey, now time.Time) (result PublisherGroupMember, retErr error) {
	parts := strings.Split(secret, ".")
	if len(secret) > 256 || len(parts) != 2 || !opaqueid.Valid(parts[0], opaqueid.PublisherEnrollmentPrefix) || len(public) != ed25519.PublicKeySize {
		return result, ErrPublisherGroup
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "redeem publisher group enrollment", &retErr)()
	// team -> project -> group -> enrollment -> identity is the management order.
	var team, project, gid string
	if err = tx.QueryRow(ctx, `SELECT g.team_id,g.project_key,g.id FROM control.publisher_group_enrollments e JOIN control.project_publisher_groups g ON g.id=e.group_id WHERE e.id=$1`, parts[0]).Scan(&team, &project, &gid); err != nil {
		return result, publisherLookupError(err, ErrPublisherGroup)
	}
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, team); err != nil {
		return result, publisherLookupError(err, ErrPublisherGroup)
	}
	var name, actor string
	var digest []byte
	var until time.Time
	var maxMembers int
	var live bool
	err = tx.QueryRow(ctx, `SELECT g.name,e.created_by_identity_id,e.secret_digest,e.expires_at,e.max_members,g.deleted_at IS NULL AND e.revoked_at IS NULL FROM control.publisher_group_enrollments e JOIN control.project_publisher_groups g ON g.id=e.group_id WHERE e.id=$1 FOR UPDATE OF e,g`, parts[0]).Scan(&name, &actor, &digest, &until, &maxMembers, &live)
	if err != nil {
		return result, publisherLookupError(err, ErrPublisherGroup)
	}
	actual := sha256.Sum256([]byte(secret))
	if !live || !until.After(now) || subtle.ConstantTimeCompare(actual[:], digest) != 1 {
		return result, ErrPublisherGroup
	}
	result = PublisherGroupMember{TeamID: team, ProjectKey: project, GroupID: gid, GroupName: name}
	var existingGroup string
	var revoked bool
	err = tx.QueryRow(ctx, `SELECT m.publisher_identity_id,m.key_id,m.group_id,p.revoked_at IS NOT NULL FROM control.publisher_group_members m JOIN control.publisher_identities p ON p.id=m.publisher_identity_id WHERE m.public_key=$1`, []byte(public)).Scan(&result.PublisherIdentityID, &result.KeyID, &existingGroup, &revoked)
	if err == nil {
		if revoked || existingGroup != gid {
			return PublisherGroupMember{}, ErrPublisherGroup
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
		return result, ErrPublisherGroup
	}
	var count, total int
	if err = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.publisher_group_members WHERE enrollment_id=$1),count(*) FROM control.publisher_group_members member JOIN control.project_publisher_groups publisher_group ON publisher_group.id=member.group_id JOIN control.publisher_identities publisher ON publisher.id=member.publisher_identity_id WHERE publisher_group.team_id=$2 AND publisher_group.project_key=$3 AND publisher_group.deleted_at IS NULL AND publisher.revoked_at IS NULL`, parts[0], team, project).Scan(&count, &total); err != nil {
		return result, err
	}
	if count >= maxMembers || total >= 256 {
		return result, ErrPublisherGroup
	}
	id, err := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	if err != nil {
		return result, err
	}
	kid, err := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	if err != nil {
		return result, err
	}
	if _, err = q.InsertPublisherIdentity(ctx, controlstatedb.InsertPublisherIdentityParams{ID: id, TeamID: team, Name: name, Kind: "installed", CreatedByIdentityID: actor, CreatedAt: timestamptz(now), Ownership: "team"}); err != nil {
		return result, err
	}
	if err = q.InsertPublisherKey(ctx, controlstatedb.InsertPublisherKeyParams{ID: kid, PublisherIdentityID: id, PublicKey: public, Revision: 1, CreatedAt: timestamptz(now)}); err != nil {
		return result, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO control.publisher_group_members(publisher_identity_id,group_id,enrollment_id,public_key,key_id) VALUES($1,$2,$3,$4,$5)`, id, gid, parts[0], []byte(public), kid)
	if err != nil {
		return result, err
	}
	services, err := q.ListAppliedProjectServices(ctx, controlstatedb.ListAppliedProjectServicesParams{TeamID: team, ProjectKey: project})
	if err != nil {
		return result, err
	}
	for _, s := range services {
		if s.GroupID.String == gid {
			if err = d.ensureGroupServiceGrant(ctx, tx, q, id, s, actor, now); err != nil {
				return result, err
			}
		}
	}
	result.PublisherIdentityID, result.KeyID = id, kid
	if err = recordPublisherGroupUpdate(ctx, tx, gid, "", id, "enroll-member/"+id, now); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func (d *Database) RevokePublisherGroupMember(ctx context.Context, team, project, group, publisher, actor string, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke publisher group member", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, team); err != nil {
		return publisherLookupError(err, ErrPrivateServiceAccess)
	}
	if err = privateServiceManager(ctx, tx, team, actor); err != nil {
		return err
	}
	if err = SetServiceAuditActor(ctx, tx, actor); err != nil {
		return err
	}
	var gid string
	err = tx.QueryRow(ctx, `SELECT g.id FROM control.project_publisher_groups g JOIN control.publisher_group_names alias ON alias.group_id=g.id JOIN control.publisher_group_members m ON m.group_id=g.id WHERE alias.team_id=$1 AND alias.project_key=$2 AND alias.name=$3 AND m.publisher_identity_id=$4 AND g.deleted_at IS NULL FOR UPDATE OF g,m`, team, project, group, publisher).Scan(&gid)
	if err != nil {
		return err
	}
	services, err := q.ListAppliedProjectServices(ctx, controlstatedb.ListAppliedProjectServicesParams{TeamID: team, ProjectKey: project})
	if err != nil {
		return err
	}
	for _, s := range services {
		if s.GroupID.String == gid && s.PrivateServiceID.Valid {
			if err = closeRevokedPrivatePublication(ctx, tx, q, s.PrivateServiceID.String, publisher, "", now); err != nil {
				return err
			}
		}
	}
	if err = closeRevokedPublicPublications(ctx, tx, q, publisher, "", now); err != nil {
		return err
	}
	if _, err = q.RevokePublisherIdentity(ctx, controlstatedb.RevokePublisherIdentityParams{ID: publisher, TeamID: team, Now: timestamptz(now)}); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.publisher_grants SET revoked_at=COALESCE(revoked_at,$2) WHERE publisher_identity_id=$1`, publisher, now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM control.publisher_group_leases WHERE publisher_identity_id=$1`, publisher); err != nil {
		return err
	}
	if err = recordPublisherGroupMemberRevocation(ctx, tx, publisher, actor, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// verification consumes a one-use proof but never rotates the active lease.
func (d *Database) VerifyPublisherGroupIdentity(ctx context.Context, id, group, assertion, audience string, now time.Time) (result PublisherGroupVerification, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "verify publisher group identity", &retErr)()
	result.Member, err = authorizePublisherGroupAssertion(ctx, tx, id, group, assertion, audience, now)
	if err != nil {
		return result, err
	}
	rows, err := tx.Query(ctx, `SELECT name FROM control.publisher_group_names WHERE group_id=$1 ORDER BY name`, group)
	if err != nil {
		return result, err
	}
	result.GroupNames, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func authorizePublisherGroupAssertion(ctx context.Context, tx pgx.Tx, id, group, assertion, audience string, now time.Time) (result PublisherGroupMember, err error) {
	kid, err := publisheridentity.KeyID(assertion)
	if err != nil {
		return result, ErrPublisherGroup
	}
	if err = tx.QueryRow(ctx, `SELECT team_id FROM control.project_publisher_groups WHERE id=$1`, group).Scan(&result.TeamID); err != nil {
		return result, publisherLookupError(err, ErrPublisherGroup)
	}
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, result.TeamID); err != nil {
		return result, publisherLookupError(err, ErrPublisherGroup)
	}
	var public []byte
	err = tx.QueryRow(ctx, `SELECT k.public_key,g.project_key,g.name FROM control.publisher_group_members m JOIN control.project_publisher_groups g ON g.id=m.group_id JOIN control.publisher_identities p ON p.id=m.publisher_identity_id JOIN control.publisher_identity_keys k ON k.id=m.key_id AND k.publisher_identity_id=p.id WHERE p.id=$1 AND g.id=$2 AND k.id=$3 AND g.deleted_at IS NULL AND p.revoked_at IS NULL AND k.retired_at IS NULL FOR UPDATE OF m,p`, id, group, kid).Scan(&public, &result.ProjectKey, &result.GroupName)
	if err != nil {
		return result, publisherLookupError(err, ErrPublisherGroup)
	}
	a, err := publisheridentity.Verify(assertion, id, kid, group, audience, public, now)
	if err != nil {
		return result, ErrPublisherGroup
	}
	if err = q.PrunePublisherAssertions(ctx, controlstatedb.PrunePublisherAssertionsParams{PublisherIdentityID: id, Now: timestamptz(now)}); err != nil {
		return result, err
	}
	n, err := q.ClaimPublisherAssertion(ctx, controlstatedb.ClaimPublisherAssertionParams{PublisherIdentityID: id, AssertionID: a.ID, ExpiresAt: timestamptz(a.Until)})
	if err != nil {
		return result, err
	}
	if n != 1 {
		return result, ErrPublisherGroup
	}
	result.GroupID, result.PublisherIdentityID, result.KeyID = group, id, kid
	return result, nil
}

func (d *Database) AcquirePublisherGroupLease(ctx context.Context, id, group, assertion, audience string, now time.Time) (result PublisherGroupLease, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "acquire publisher group lease", &retErr)()
	member, err := authorizePublisherGroupAssertion(ctx, tx, id, group, assertion, audience, now)
	if err != nil {
		return result, err
	}
	result, err = issuePublisherGroupLease(ctx, tx, id, member.KeyID, now.Add(PublisherGroupLeaseLifetime))
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func issuePublisherGroupLease(ctx context.Context, tx pgx.Tx, id, key string, until time.Time) (result PublisherGroupLease, err error) {
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
	return PublisherGroupLease{AccessToken: "pgl_" + secret, ExpiresAt: until}, nil
}

func lockPublisherGroupLease(ctx context.Context, tx pgx.Tx, token string, now time.Time) (result PublisherGroupMember, err error) {
	if !strings.HasPrefix(token, "pgl_") {
		return result, ErrPublisherGroup
	}
	digest, err := privateSecretDigest(strings.TrimPrefix(token, "pgl_"))
	if err != nil {
		return result, ErrPublisherGroup
	}
	// locate the team first, then recheck all live state after locking it.
	if err = tx.QueryRow(ctx, `SELECT g.team_id FROM control.publisher_group_leases l JOIN control.publisher_group_members m ON m.publisher_identity_id=l.publisher_identity_id JOIN control.project_publisher_groups g ON g.id=m.group_id WHERE l.token_digest=$1`, digest).Scan(&result.TeamID); err != nil {
		return result, publisherLookupError(err, ErrPublisherGroup)
	}
	if _, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, result.TeamID); err != nil {
		return result, publisherLookupError(err, ErrPublisherGroup)
	}
	err = tx.QueryRow(ctx, `SELECT g.project_key,g.id,g.name,m.publisher_identity_id,m.key_id FROM control.publisher_group_leases l JOIN control.publisher_group_members m ON m.publisher_identity_id=l.publisher_identity_id JOIN control.project_publisher_groups g ON g.id=m.group_id JOIN control.publisher_identities p ON p.id=m.publisher_identity_id JOIN control.publisher_identity_keys k ON k.id=l.key_id AND k.publisher_identity_id=p.id WHERE l.token_digest=$1 AND l.expires_at>$2 AND g.deleted_at IS NULL AND p.revoked_at IS NULL AND k.retired_at IS NULL`, digest, now).Scan(&result.ProjectKey, &result.GroupID, &result.GroupName, &result.PublisherIdentityID, &result.KeyID)
	return result, publisherLookupError(err, ErrPublisherGroup)
}

func (d *Database) GetPublisherGroupAssignments(ctx context.Context, token string, now time.Time) (result PublisherGroupAssignments, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get publisher group assignments", &retErr)()
	m, err := lockPublisherGroupLease(ctx, tx, token, now)
	if err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	row, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: m.TeamID, ProjectKey: m.ProjectKey})
	if err != nil {
		return result, err
	}
	c, err := d.openAppliedProject(row)
	if err != nil {
		return result, err
	}
	result = PublisherGroupAssignments{Member: m, Revision: row.Revision, ConfigurationHash: row.ConfigurationHash, Services: []PublisherGroupServiceAssignment{}}
	if err = tx.QueryRow(ctx, `SELECT certificate_state_required FROM control.publisher_identities WHERE id=$1`, m.PublisherIdentityID).Scan(&result.CertificateStateRequired); err != nil {
		return result, err
	}
	services, err := q.ListAppliedProjectServices(ctx, controlstatedb.ListAppliedProjectServicesParams{TeamID: m.TeamID, ProjectKey: m.ProjectKey})
	if err != nil {
		return result, err
	}
	for _, s := range services {
		if s.GroupID.String != m.GroupID {
			continue
		}
		var grant string
		if err = tx.QueryRow(ctx, `SELECT assignment.grant_id FROM control.publisher_group_service_grants assignment JOIN control.publisher_grants g ON g.id=assignment.grant_id WHERE assignment.publisher_identity_id=$1 AND assignment.team_id=$2 AND assignment.project_key=$3 AND assignment.service=$4 AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>$5)`, m.PublisherIdentityID, m.TeamID, m.ProjectKey, s.Service, now).Scan(&grant); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return result, publisherLookupError(err, ErrPublisherGroup)
		}
		a := PublisherGroupServiceAssignment{Service: s.Service, ServiceID: s.PublicURLID.String, Kind: "public_url", GrantID: grant, Configuration: c.Services[s.Service]}
		if s.PrivateServiceID.Valid {
			a.ServiceID, a.Kind = s.PrivateServiceID.String, "private_service"
			if err = tx.QueryRow(ctx, `SELECT trust_revision FROM control.private_services WHERE id=$1 AND enabled AND deleted_at IS NULL`, a.ServiceID).Scan(&a.TrustRevision); err != nil {
				return result, err
			}
		} else {
			a.Hostname = a.Configuration.PublicURL.Hostname
		}
		result.Services = append(result.Services, a)
	}
	return result, tx.Commit(ctx)
}

func (d *Database) AcknowledgePublisherGroupConfiguration(ctx context.Context, token string, revision int64, hash string, healthy bool, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "acknowledge publisher group configuration", &retErr)()
	m, err := lockPublisherGroupLease(ctx, tx, token, now)
	if err != nil {
		return err
	}
	row, err := controlstatedb.New(tx).LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: m.TeamID, ProjectKey: m.ProjectKey})
	if err != nil {
		return err
	}
	if revision < 1 || row.Revision != revision || !bytes.Equal([]byte(row.ConfigurationHash), []byte(hash)) {
		return ErrProjectConfigurationStale
	}
	_, err = tx.Exec(ctx, `UPDATE control.publisher_group_members SET observed_revision=$2,healthy=$3 WHERE publisher_identity_id=$1`, m.PublisherIdentityID, revision, healthy)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func listPublisherGroupMemberStatus(ctx context.Context, tx pgx.Tx, team, project string) ([]PublisherGroupMemberStatus, error) {
	rows, err := tx.Query(ctx, `SELECT g.id,g.name,m.publisher_identity_id,m.key_id,m.observed_revision,m.healthy AND m.lease_expires_at>now(),m.lease_expires_at FROM control.project_publisher_groups g JOIN control.publisher_group_members m ON m.group_id=g.id JOIN control.publisher_identities p ON p.id=m.publisher_identity_id WHERE g.team_id=$1 AND g.project_key=$2 AND g.deleted_at IS NULL AND p.revoked_at IS NULL ORDER BY g.name,m.publisher_identity_id`, team, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []PublisherGroupMemberStatus{}
	for rows.Next() {
		s := PublisherGroupMemberStatus{PublisherGroupMember: PublisherGroupMember{TeamID: team, ProjectKey: project}}
		if err = rows.Scan(&s.GroupID, &s.GroupName, &s.PublisherIdentityID, &s.KeyID, &s.ObservedRevision, &s.Healthy, &s.LeaseExpiresAt); err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	for i := range result {
		result[i].Runtime, err = publisherRuntimeStatus(ctx, controlstatedb.New(tx), result[i].PublisherIdentityID, time.Now())
		if err != nil {
			return nil, err
		}
		if result[i].Runtime != nil {
			result[i].Healthy = result[i].Healthy && result[i].Runtime.Active
		}
	}
	return result, nil
}

func (d *Database) removePublisherGroup(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, group string, now time.Time) error {
	if err := retireManagedNamespace(ctx, tx, group, now); err != nil {
		return err
	}
	// all its service assignments were reconciled first. revoking identities also
	// invalidates any access tokens previously exchanged for exact-service grants.
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
