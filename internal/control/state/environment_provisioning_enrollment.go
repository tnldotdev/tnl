package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func provisioningEnrollmentContext(id string) string {
	return "environment-provisioning-enrollment/" + id
}

func provisioningEnrollmentDigest(r IssueEnvironmentPublisherEnrollmentRequest, names []string) [32]byte {
	data, _ := json.Marshal([]any{r.TeamID, r.ProjectKey, r.EnvironmentID, r.ExpectedRevision, r.ExpectedConfigurationHash, names, r.MaxMembers, int64(r.Lifetime)})
	return sha256.Sum256(data)
}

func (d *Database) environmentProvisioningEnrollmentRetry(ctx context.Context, tx pgx.Tx, r IssueEnvironmentPublisherEnrollmentRequest, names []string, clock authorizationClock) (result EnvironmentPublisherEnrollment, found bool, err error) {
	if len(r.IdempotencyKey) == 0 || len(r.IdempotencyKey) > 128 || !validEnvironmentKey(r.IdempotencyKey) {
		return result, false, ErrEnvironmentInvalid
	}
	var id, environment, keyID string
	var digest, ciphertext []byte
	var live bool
	err = tx.QueryRow(ctx, `SELECT receipt.enrollment_id,receipt.environment_id,receipt.request_digest,receipt.storage_key_id,receipt.key_ciphertext,enrollment.expires_at,enrollment.max_members,enrollment.revoked_at IS NULL FROM control.environment_provisioning_enrollments receipt JOIN control.publisher_group_enrollments enrollment ON enrollment.id=receipt.enrollment_id WHERE receipt.grant_id=$1 AND receipt.idempotency_key=$2 FOR UPDATE OF receipt,enrollment`, r.Manager.provisioningGrantID, r.IdempotencyKey).Scan(&id, &environment, &digest, &keyID, &ciphertext, &result.ExpiresAt, &result.MaxMembers, &live)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, false, nil
	}
	if err != nil {
		return result, false, err
	}
	actual := provisioningEnrollmentDigest(r, names)
	if environment != r.EnvironmentID || !bytes.Equal(digest, actual[:]) || !live || !result.ExpiresAt.After(clock.current()) {
		return result, true, ErrServiceConflict
	}
	key, _, err := d.openSecret(keyID, provisioningEnrollmentContext(id), ciphertext)
	if err != nil {
		return result, true, err
	}
	defer clear(key)
	result.TeamID, result.ProjectKey, result.EnvironmentID, result.Key = r.TeamID, r.ProjectKey, r.EnvironmentID, string(key)
	return result, true, nil
}

func (d *Database) recordEnvironmentProvisioningEnrollment(ctx context.Context, tx pgx.Tx, r IssueEnvironmentPublisherEnrollmentRequest, names []string, id, key string) error {
	ciphertext, err := d.sealSecret(provisioningEnrollmentContext(id), []byte(key))
	if err != nil {
		return err
	}
	digest := provisioningEnrollmentDigest(r, names)
	_, err = tx.Exec(ctx, `INSERT INTO control.environment_provisioning_enrollments(grant_id,idempotency_key,environment_id,enrollment_id,request_digest,storage_key_id,key_ciphertext) VALUES($1,$2,$3,$4,$5,$6,$7)`, r.Manager.provisioningGrantID, r.IdempotencyKey, r.EnvironmentID, id, digest[:], d.storageKey.CurrentID(), ciphertext)
	return err
}

// pending enrollments still require their actual issuer's current authority.
// already enrolled publishers never call this check during lease renewal.
func checkEnvironmentEnrollmentAuthority(ctx context.Context, tx pgx.Tx, row controlstatedb.ControlEnvironment, issuer publisherIssuer, enrollment string, maxMembers int, until time.Time, clock authorizationClock) error {
	if issuer.MachineID == "" {
		return checkEnvironmentEnrollmentIssuer(ctx, tx, row.GroupID, issuer.IdentityID, until, clock)
	}
	var collection string
	var future bool
	var captured, allowed []string
	var expires time.Time
	var cap int
	err := tx.QueryRow(ctx, `SELECT COALESCE(g.collection_id,''),g.include_future_environments,g.environment_ids,g.services,g.expires_at,g.max_enrollment_members FROM control.machine_provisioning_grants g JOIN control.machine_identities m ON m.id=g.machine_id AND m.team_id=g.team_id WHERE g.id=$1 AND m.id=$2 AND g.team_id=$3 AND g.project_key=$4 AND g.revoked_at IS NULL AND m.revoked_at IS NULL AND 'enroll'=ANY(g.operations) FOR UPDATE OF g,m`, issuer.ProvisioningGrantID, issuer.MachineID, row.TeamID, row.ProjectKey).Scan(&collection, &future, &captured, &allowed, &expires, &cap)
	if err != nil {
		return publisherLookupError(err, ErrEnvironmentPublisher)
	}
	if !expires.After(clock.current()) || !until.After(clock.current()) || maxMembers > cap {
		return ErrEnvironmentPublisher
	}
	if err = checkEnvironmentPermissionScope(ctx, tx, row.TeamID, row.ProjectKey, row.ID, "", collection, future, captured); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT service FROM control.environment_publisher_enrollment_services WHERE enrollment_id=$1 ORDER BY service`, enrollment)
	if err != nil {
		return err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for i := range names {
		names[i] = appliedServiceName(names[i])
	}
	if !environmentPermissionServicesContain(allowed, names) || !expires.After(clock.current()) || !until.After(clock.current()) {
		return ErrEnvironmentPublisher
	}
	return nil
}
