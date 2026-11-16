package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

var ErrDeploymentPublisher = errors.New("deployment lease or enrollment is unavailable")

const DeploymentPublisherLeaseLifetime = 2 * time.Minute

type DeploymentPublisherIdentity struct {
	TeamID              string `json:"team_id"`
	ProjectKey          string `json:"project_key"`
	DeploymentID        string `json:"deployment_id"`
	DeploymentName      string `json:"deployment_name"`
	PublisherIdentityID string `json:"publisher_identity_id"`
	KeyID               string `json:"key_id"`
}
type DeploymentPublisherStatus struct {
	DeploymentPublisherIdentity
	Runtime          *PublisherRuntimeStatus `json:"runtime,omitempty"`
	ObservedRevision int64                   `json:"observed_revision,string"`
	CurrentRevision  int64                   `json:"current_revision,string"`
	SnapshotAt       time.Time               `json:"snapshot_at"`
	AcknowledgedAt   *time.Time              `json:"acknowledged_at,omitempty"`
	Healthy          bool                    `json:"healthy"`
	LeaseExpiresAt   *time.Time              `json:"lease_expires_at,omitempty"`
}
type DeploymentPublisherLease struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}
type DeploymentPublisherVerification struct {
	Member          DeploymentPublisherIdentity `json:"member"`
	DeploymentNames []string                    `json:"deployment_names"`
}
type DeploymentPublisherServiceAssignment struct {
	Service       string                      `json:"service"`
	ServiceID     string                      `json:"service_id"`
	Kind          string                      `json:"service_kind"`
	GrantID       string                      `json:"grant_id"`
	Hostname      string                      `json:"hostname,omitempty"`
	TrustRevision int64                       `json:"trust_revision,string"`
	Configuration ProjectServiceConfiguration `json:"configuration"`
}
type DeploymentPublisherAssignments struct {
	Member                DeploymentPublisherIdentity            `json:"member"`
	Revision              int64                                  `json:"revision,string"`
	ConfigurationHash     string                                 `json:"configuration_hash"`
	Services              []DeploymentPublisherServiceAssignment `json:"services"`
	CertificateStatePlans []CertificatePlan                      `json:"certificate_state_plans"`
}

func (d *Database) RedeemDeploymentPublisherEnrollment(ctx context.Context, secret string, public ed25519.PublicKey, now time.Time) (result DeploymentPublisherIdentity, retErr error) {
	clock := newAuthorizationClock(now)
	parts := strings.Split(secret, ".")
	if len(secret) > 256 || len(parts) != 2 || !opaqueid.Valid(parts[0], opaqueid.PublisherEnrollmentPrefix) || len(public) != ed25519.PublicKeySize {
		return result, ErrDeploymentPublisher
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "redeem deployment enrollment", &retErr)()
	// team -> project -> deployment -> enrollment -> identity is the management order.
	var team, project, gid string
	if err = tx.QueryRow(ctx, `SELECT g.team_id,g.project_key,g.id FROM control.deployment_publisher_enrollments e JOIN control.deployments g ON g.id=e.deployment_id WHERE e.id=$1`, parts[0]).Scan(&team, &project, &gid); err != nil {
		return result, publisherLookupError(err, ErrDeploymentPublisher)
	}
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, team); err != nil {
		return result, publisherLookupError(err, ErrDeploymentPublisher)
	}
	deployment, err := q.LockDeploymentByID(ctx, gid)
	if err != nil {
		return result, publisherLookupError(err, ErrDeploymentPublisher)
	}
	enrollment, err := q.LockDeploymentPublisherEnrollment(ctx, parts[0])
	if err != nil {
		return result, publisherLookupError(err, ErrDeploymentPublisher)
	}
	name, actor, until, maxMembers := deployment.Name, enrollment.CreatedByIdentityID, enrollment.ExpiresAt.Time, int(enrollment.MaxMembers)
	actual := sha256.Sum256([]byte(secret))
	if enrollment.DeploymentID != gid || enrollment.RevokedAt.Valid || !until.After(clock.current()) || subtle.ConstantTimeCompare(actual[:], enrollment.SecretDigest) != 1 {
		return result, ErrDeploymentPublisher
	}
	if _, err = d.currentPublisherEnrollmentServices(ctx, q, enrollment, deployment); err != nil {
		if errors.Is(err, ErrPublisherEnrollment) {
			return result, ErrDeploymentPublisher
		}
		return result, err
	}
	result = DeploymentPublisherIdentity{TeamID: team, ProjectKey: project, DeploymentID: gid, DeploymentName: name}
	var existingDeployment, existingEnrollment string
	var revoked bool
	err = tx.QueryRow(ctx, `SELECT m.publisher_identity_id,m.key_id,m.deployment_id,m.enrollment_id,p.revoked_at IS NOT NULL FROM control.deployment_publisher_members m JOIN control.publisher_identities p ON p.id=m.publisher_identity_id WHERE m.public_key=$1`, []byte(public)).Scan(&result.PublisherIdentityID, &result.KeyID, &existingDeployment, &existingEnrollment, &revoked)
	if err == nil {
		if revoked || existingDeployment != gid || existingEnrollment != parts[0] || !until.After(clock.current()) {
			return DeploymentPublisherIdentity{}, ErrDeploymentPublisher
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
		return result, ErrDeploymentPublisher
	}
	var count, total int
	if err = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.deployment_publisher_members WHERE enrollment_id=$1),count(*) FROM control.deployment_publisher_members member JOIN control.deployments deployment ON deployment.id=member.deployment_id JOIN control.publisher_identities publisher ON publisher.id=member.publisher_identity_id WHERE deployment.team_id=$2 AND deployment.project_key=$3 AND deployment.deleted_at IS NULL AND publisher.revoked_at IS NULL`, parts[0], team, project).Scan(&count, &total); err != nil {
		return result, err
	}
	if count >= maxMembers || total >= 256 {
		return result, ErrDeploymentPublisher
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
	_, err = tx.Exec(ctx, `INSERT INTO control.deployment_publisher_members(publisher_identity_id,deployment_id,enrollment_id,public_key,key_id) VALUES($1,$2,$3,$4,$5)`, id, gid, parts[0], []byte(public), kid)
	if err != nil {
		return result, err
	}
	services, err := q.ListDeploymentPublisherServices(ctx, gid)
	if err != nil {
		return result, err
	}
	for _, s := range services {
		if err = d.ensureDeploymentServiceGrant(ctx, tx, q, id, s, actor, now); err != nil {
			return result, err
		}
	}
	result.PublisherIdentityID, result.KeyID = id, kid
	if err = recordDeploymentPublisherUpdate(ctx, tx, gid, "", id, "enroll-member/"+id, now); err != nil {
		return result, err
	}
	if !until.After(clock.current()) {
		return DeploymentPublisherIdentity{}, ErrDeploymentPublisher
	}
	return result, tx.Commit(ctx)
}

// verification consumes a one-use proof but never rotates the active lease.
func (d *Database) VerifyDeploymentIdentity(ctx context.Context, id, deployment, assertion, audience string, now time.Time) (result DeploymentPublisherVerification, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "verify deployment identity", &retErr)()
	result.Member, err = authorizeDeploymentPublisherAssertion(ctx, tx, id, deployment, assertion, audience, now)
	if err != nil {
		return result, err
	}
	rows, err := tx.Query(ctx, `SELECT name FROM control.deployment_names WHERE deployment_id=$1 ORDER BY name`, deployment)
	if err != nil {
		return result, err
	}
	result.DeploymentNames, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func authorizeDeploymentPublisherAssertion(ctx context.Context, tx pgx.Tx, id, deployment, assertion, audience string, now time.Time) (result DeploymentPublisherIdentity, err error) {
	kid, err := publisherproof.KeyID(assertion)
	if err != nil {
		return result, ErrDeploymentPublisher
	}
	if err = tx.QueryRow(ctx, `SELECT team_id FROM control.deployments WHERE id=$1`, deployment).Scan(&result.TeamID); err != nil {
		return result, publisherLookupError(err, ErrDeploymentPublisher)
	}
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, result.TeamID); err != nil {
		return result, publisherLookupError(err, ErrDeploymentPublisher)
	}
	var public []byte
	err = tx.QueryRow(ctx, `SELECT k.public_key,g.project_key,g.name FROM control.deployment_publisher_members m JOIN control.deployments g ON g.id=m.deployment_id JOIN control.publisher_identities p ON p.id=m.publisher_identity_id JOIN control.publisher_identity_keys k ON k.id=m.key_id AND k.publisher_identity_id=p.id WHERE p.id=$1 AND g.id=$2 AND k.id=$3 AND g.deleted_at IS NULL AND p.revoked_at IS NULL AND k.retired_at IS NULL FOR UPDATE OF m,p`, id, deployment, kid).Scan(&public, &result.ProjectKey, &result.DeploymentName)
	if err != nil {
		return result, publisherLookupError(err, ErrDeploymentPublisher)
	}
	a, err := publisherproof.Verify(assertion, id, kid, deployment, audience, public, now)
	if err != nil {
		return result, ErrDeploymentPublisher
	}
	if err = q.PrunePublisherAssertions(ctx, controlstatedb.PrunePublisherAssertionsParams{PublisherIdentityID: id, Now: timestamptz(now)}); err != nil {
		return result, err
	}
	n, err := q.ClaimPublisherAssertion(ctx, controlstatedb.ClaimPublisherAssertionParams{PublisherIdentityID: id, AssertionID: a.ID, ExpiresAt: timestamptz(a.Until)})
	if err != nil {
		return result, err
	}
	if n != 1 {
		return result, ErrDeploymentPublisher
	}
	result.DeploymentID, result.PublisherIdentityID, result.KeyID = deployment, id, kid
	return result, nil
}

func (d *Database) AcquireDeploymentPublisherLease(ctx context.Context, id, deployment, assertion, audience string, now time.Time) (result DeploymentPublisherLease, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "acquire deployment lease", &retErr)()
	member, err := authorizeDeploymentPublisherAssertion(ctx, tx, id, deployment, assertion, audience, now)
	if err != nil {
		return result, err
	}
	result, err = issueDeploymentPublisherLease(ctx, tx, id, member.KeyID, now.Add(DeploymentPublisherLeaseLifetime))
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func issueDeploymentPublisherLease(ctx context.Context, tx pgx.Tx, id, key string, until time.Time) (result DeploymentPublisherLease, err error) {
	secret, digest, err := privateSecret()
	if err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM control.deployment_publisher_leases WHERE publisher_identity_id=$1`, id); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO control.deployment_publisher_leases(token_digest,publisher_identity_id,key_id,expires_at) VALUES($1,$2,$3,$4)`, digest, id, key, until); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.deployment_publisher_members SET lease_expires_at=$2 WHERE publisher_identity_id=$1`, id, until); err != nil {
		return result, err
	}
	return DeploymentPublisherLease{AccessToken: "dpl_lease_" + secret, ExpiresAt: until}, nil
}

func lockDeploymentPublisherLease(ctx context.Context, tx pgx.Tx, token string, now time.Time) (result DeploymentPublisherIdentity, err error) {
	if !strings.HasPrefix(token, "dpl_lease_") {
		return result, ErrDeploymentPublisher
	}
	digest, err := serviceSecretDigest(strings.TrimPrefix(token, "dpl_lease_"))
	if err != nil {
		return result, ErrDeploymentPublisher
	}
	// locate the team first, then recheck all live state after locking it.
	if err = tx.QueryRow(ctx, `SELECT g.team_id FROM control.deployment_publisher_leases l JOIN control.deployment_publisher_members m ON m.publisher_identity_id=l.publisher_identity_id JOIN control.deployments g ON g.id=m.deployment_id WHERE l.token_digest=$1`, digest).Scan(&result.TeamID); err != nil {
		return result, publisherLookupError(err, ErrDeploymentPublisher)
	}
	if _, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, result.TeamID); err != nil {
		return result, publisherLookupError(err, ErrDeploymentPublisher)
	}
	err = tx.QueryRow(ctx, `SELECT g.project_key,g.id,g.name,m.publisher_identity_id,m.key_id FROM control.deployment_publisher_leases l JOIN control.deployment_publisher_members m ON m.publisher_identity_id=l.publisher_identity_id JOIN control.deployments g ON g.id=m.deployment_id JOIN control.publisher_identities p ON p.id=m.publisher_identity_id JOIN control.publisher_identity_keys k ON k.id=l.key_id AND k.publisher_identity_id=p.id WHERE l.token_digest=$1 AND l.expires_at>$2 AND g.deleted_at IS NULL AND p.revoked_at IS NULL AND k.retired_at IS NULL`, digest, now).Scan(&result.ProjectKey, &result.DeploymentID, &result.DeploymentName, &result.PublisherIdentityID, &result.KeyID)
	return result, publisherLookupError(err, ErrDeploymentPublisher)
}

func (d *Database) GetDeploymentPublisherAssignments(ctx context.Context, token string, now time.Time) (result DeploymentPublisherAssignments, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get deployment assignments", &retErr)()
	m, err := lockDeploymentPublisherLease(ctx, tx, token, now)
	if err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	row, err := q.LockDeploymentByID(ctx, m.DeploymentID)
	if err != nil {
		return result, err
	}
	c, err := d.openDeploymentConfiguration(row)
	if err != nil {
		return result, err
	}
	result = DeploymentPublisherAssignments{Member: m, Revision: row.Revision, ConfigurationHash: row.ConfigurationHash, Services: []DeploymentPublisherServiceAssignment{}}
	result.CertificateStatePlans = []CertificatePlan{}
	checkpoints, err := q.ListPublisherCertificateCheckpoints(ctx, m.PublisherIdentityID)
	if err != nil {
		return result, err
	}
	if len(checkpoints) > 1024 {
		return result, ErrDeploymentPublisher
	}
	for _, checkpoint := range checkpoints {
		var plan CertificatePlan
		if json.Unmarshal(checkpoint, &plan) != nil {
			return result, ErrDeploymentPublisher
		}
		result.CertificateStatePlans = append(result.CertificateStatePlans, plan)
	}
	services, err := q.ListDeploymentPublisherServices(ctx, m.DeploymentID)
	if err != nil {
		return result, err
	}
	for _, s := range services {
		allowed, err := q.DeploymentPublisherServiceAllowed(ctx, controlstatedb.DeploymentPublisherServiceAllowedParams{PublisherID: m.PublisherIdentityID, DeploymentID: m.DeploymentID, Service: s.Service, ServiceID: s.ServiceID, PublicURLID: s.PublicURLID})
		if err != nil {
			return result, err
		}
		if !allowed {
			continue
		}
		var grant string
		if err = tx.QueryRow(ctx, `SELECT assignment.grant_id FROM control.deployment_publisher_service_grants assignment JOIN control.publisher_grants g ON g.id=assignment.grant_id WHERE assignment.publisher_identity_id=$1 AND assignment.team_id=$2 AND assignment.project_key=$3 AND assignment.service=$4 AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>$5)`, m.PublisherIdentityID, m.TeamID, m.ProjectKey, s.Service, now).Scan(&grant); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return result, publisherLookupError(err, ErrDeploymentPublisher)
		}
		configuration, ok := c.Services[s.Service]
		if !ok {
			return result, ErrDeploymentPublisher
		}
		a := DeploymentPublisherServiceAssignment{Service: s.Service, ServiceID: s.PublicURLID.String, Kind: "public_url", GrantID: grant, Configuration: configuration}
		if s.ServiceID.Valid {
			a.ServiceID, a.Kind = s.ServiceID.String, "service"
			if err = tx.QueryRow(ctx, `SELECT trust_revision FROM control.services WHERE id=$1 AND enabled AND deleted_at IS NULL`, a.ServiceID).Scan(&a.TrustRevision); err != nil {
				return result, err
			}
		} else {
			a.Hostname = a.Configuration.PublicURL.Hostname
		}
		result.Services = append(result.Services, a)
	}
	return result, tx.Commit(ctx)
}

func (d *Database) AcknowledgeDeploymentPublisherConfiguration(ctx context.Context, token string, revision int64, hash string, healthy bool, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "acknowledge deployment configuration", &retErr)()
	m, err := lockDeploymentPublisherLease(ctx, tx, token, now)
	if err != nil {
		return err
	}
	row, err := controlstatedb.New(tx).LockDeploymentByID(ctx, m.DeploymentID)
	if err != nil {
		return err
	}
	if revision < 1 || row.Revision != revision || !bytes.Equal([]byte(row.ConfigurationHash), []byte(hash)) {
		return ErrProjectConfigurationStale
	}
	err = controlstatedb.New(tx).AcknowledgeDeploymentPublisherConfiguration(ctx, controlstatedb.AcknowledgeDeploymentPublisherConfigurationParams{PublisherIdentityID: m.PublisherIdentityID, Revision: revision, Healthy: healthy, AcknowledgedAt: timestamptz(now)})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func listDeploymentPublisherStatus(ctx context.Context, tx pgx.Tx, team, project string) ([]DeploymentPublisherStatus, error) {
	now := time.Now().UTC()
	rows, err := controlstatedb.New(tx).ListDeploymentPublisherStatus(ctx, controlstatedb.ListDeploymentPublisherStatusParams{TeamID: team, ProjectKey: project, Now: timestamptz(now)})
	if err != nil {
		return nil, err
	}
	result := []DeploymentPublisherStatus{}
	for _, row := range rows {
		s := DeploymentPublisherStatus{DeploymentPublisherIdentity: DeploymentPublisherIdentity{TeamID: team, ProjectKey: project, DeploymentID: row.DeploymentID, DeploymentName: row.DeploymentName, PublisherIdentityID: row.PublisherIdentityID, KeyID: row.KeyID}, ObservedRevision: row.ObservedRevision, CurrentRevision: row.CurrentRevision, Healthy: row.Healthy, SnapshotAt: now}
		if row.LeaseExpiresAt.Valid {
			s.LeaseExpiresAt = &row.LeaseExpiresAt.Time
		}
		if row.AcknowledgedAt.Valid {
			s.AcknowledgedAt = &row.AcknowledgedAt.Time
		}
		result = append(result, s)
	}
	for i := range result {
		result[i].Runtime, err = publisherRuntimeStatus(ctx, controlstatedb.New(tx), result[i].PublisherIdentityID, now)
		if err != nil {
			return nil, err
		}
		if result[i].Runtime != nil {
			result[i].Healthy = result[i].Healthy && result[i].Runtime.Active
		}
	}
	return result, nil
}

func (d *Database) removeDeploymentPublisher(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, deployment string, now time.Time) error {
	if err := retireServiceNamespace(ctx, tx, deployment, now); err != nil {
		return err
	}
	// all its service assignments were reconciled first. revoking identities also
	// invalidates any access tokens previously exchanged for exact-service grants.
	if _, err := tx.Exec(ctx, `UPDATE control.publisher_grants SET revoked_at=COALESCE(revoked_at,$2) WHERE publisher_identity_id IN(SELECT publisher_identity_id FROM control.deployment_publisher_members WHERE deployment_id=$1)`, deployment, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE control.publisher_identities SET revoked_at=COALESCE(revoked_at,$2) WHERE id IN(SELECT publisher_identity_id FROM control.deployment_publisher_members WHERE deployment_id=$1)`, deployment, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE control.deployment_publisher_enrollments SET revoked_at=COALESCE(revoked_at,$2) WHERE deployment_id=$1`, deployment, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE control.deployments SET deleted_at=$2 WHERE id=$1`, deployment, now)
	return err
}
