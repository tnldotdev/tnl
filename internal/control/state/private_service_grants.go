package controlstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func (d *Database) CreatePrivateServiceGrant(ctx context.Context, serviceID, actorID, key, kind, identityID string, expires *time.Time, now time.Time) (result PrivateServiceGrant, retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.PrivateServicePrefix) || len(key) == 0 || len(key) > 128 ||
		(kind != "team" && kind != "identity") || (kind == "team") != (identityID == "") ||
		expires != nil && !expires.After(now) {
		return result, ErrPrivateServiceAccess
	}
	id, err := opaqueid.New(opaqueid.PrivateServiceGrantPrefix)
	if err != nil {
		return result, err
	}
	expiry := ""
	if expires != nil {
		expiry = expires.UTC().Format(time.RFC3339Nano)
	}
	digest := sha256.Sum256([]byte(serviceID + "\x00" + kind + "\x00" + identityID + "\x00" + expiry))
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create private service grant", &retErr)()
	service, err := lockManagedPrivateService(ctx, tx, serviceID, actorID)
	if err != nil {
		return result, err
	}
	if identityID != "" {
		var active bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.identities WHERE id=$1 AND disabled_at IS NULL)`, identityID).Scan(&active); err != nil {
			return result, err
		}
		if !active {
			return result, ErrPrivateServiceAccess
		}
	}
	var existing controlstatedb.ControlPrivateServiceGrant
	// sqlc's create source has an exact active grant constraint; query the retry key before inserting.
	var oldID string
	err = tx.QueryRow(ctx, `SELECT id FROM control.private_service_grants WHERE created_by_identity_id=$1 AND kind=$2 AND idempotency_key=$3`, actorID, kind, key).Scan(&oldID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if oldID != "" {
		err = tx.QueryRow(ctx, `SELECT id, private_service_id, team_id, kind, identity_id, invitation_id,
			created_by_identity_id, idempotency_key, request_digest, created_at, expires_at, revoked_at
			FROM control.private_service_grants WHERE id=$1 FOR UPDATE`, oldID).Scan(&existing.ID, &existing.PrivateServiceID,
			&existing.TeamID, &existing.Kind, &existing.IdentityID, &existing.InvitationID, &existing.CreatedByIdentityID,
			&existing.IdempotencyKey, &existing.RequestDigest, &existing.CreatedAt, &existing.ExpiresAt, &existing.RevokedAt)
		if err != nil {
			return result, err
		}
		if existing.PrivateServiceID != serviceID || existing.RevokedAt.Valid || !bytes.Equal(existing.RequestDigest, digest[:]) {
			return result, ErrPrivateServiceConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return result, err
		}
		return privateGrantRecord(existing), nil
	}
	row, err := controlstatedb.New(tx).InsertPrivateServiceGrant(ctx, controlstatedb.InsertPrivateServiceGrantParams{
		ID: id, PrivateServiceID: serviceID, TeamID: service.TeamID, Kind: kind, IdentityID: nullableText(identityID),
		CreatedByIdentityID: actorID, IdempotencyKey: key, RequestDigest: digest[:], Now: timestamptz(now), ExpiresAt: nullableTime(expires),
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return result, ErrPrivateServiceConflict
	}
	if err != nil {
		return result, err
	}
	if err = auditPrivateMutation(ctx, tx, serviceID, actorID, "grant.create", row.ID, now); err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return privateGrantRecord(row), nil
}

func (d *Database) ListPrivateServiceGrants(ctx context.Context, serviceID, actorID, after string) (result []PrivateServiceGrant, next string, retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.PrivateServicePrefix) || after != "" && !opaqueid.Valid(after, opaqueid.PrivateServiceGrantPrefix) {
		return nil, "", ErrPrivateServiceAccess
	}
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, "", err
	}
	defer rollback(ctx, tx, "list private service grants", &retErr)()
	if _, err = lockManagedPrivateService(ctx, tx, serviceID, actorID); err != nil {
		return nil, "", err
	}
	rows, err := controlstatedb.New(tx).ListPrivateServiceGrants(ctx, controlstatedb.ListPrivateServiceGrantsParams{PrivateServiceID: serviceID, AfterID: after})
	if err != nil {
		return nil, "", err
	}
	if len(rows) > 100 {
		next, rows = rows[99].ID, rows[:100]
	}
	result = make([]PrivateServiceGrant, 0, len(rows))
	for _, row := range rows {
		result = append(result, privateGrantRecord(row))
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return result, next, nil
}

func (d *Database) RevokePrivateServiceGrant(ctx context.Context, serviceID, actorID, grantID string, now time.Time) (retErr error) {
	if !opaqueid.Valid(grantID, opaqueid.PrivateServiceGrantPrefix) {
		return ErrPrivateServiceAccess
	}
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke private service grant", &retErr)()
	if _, err = lockManagedPrivateService(ctx, tx, serviceID, actorID); err != nil {
		return err
	}
	if err = rejectProjectManagedGrant(ctx, tx, grantID); err != nil {
		return err
	}
	count, err := controlstatedb.New(tx).RevokePrivateServiceGrant(ctx, controlstatedb.RevokePrivateServiceGrantParams{ID: grantID, PrivateServiceID: serviceID, Now: timestamptz(now)})
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrPrivateServiceAccess
	}
	if err = auditPrivateMutation(ctx, tx, serviceID, actorID, "grant.revoke", grantID, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
