package state

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

func (d *Database) CreateServiceGrant(ctx context.Context, serviceID, actorID, key, kind, identityID string, expires *time.Time, now time.Time) (result ServiceGrant, retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) || len(key) == 0 || len(key) > 128 ||
		(kind != "team" && kind != "identity") || (kind == "team") != (identityID == "") ||
		expires != nil && !expires.After(now) {
		return result, ErrServiceAccess
	}
	id, err := opaqueid.New(opaqueid.ServiceGrantPrefix)
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
	defer rollback(ctx, tx, "create service grant", &retErr)()
	service, err := lockService(ctx, tx, serviceID, actorID)
	if err != nil {
		return result, err
	}
	if identityID != "" {
		var active bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.identities WHERE id=$1 AND disabled_at IS NULL)`, identityID).Scan(&active); err != nil {
			return result, err
		}
		if !active {
			return result, ErrServiceAccess
		}
	}
	var existing controlstatedb.ControlVisitorGrant
	// sqlc's create source has an exact active grant constraint; query the retry key before inserting.
	var oldID string
	err = tx.QueryRow(ctx, `SELECT id FROM control.visitor_grants WHERE resource_kind='service' AND created_by_identity_id=$1 AND kind=$2 AND idempotency_key=$3`, actorID, kind, key).Scan(&oldID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if oldID != "" {
		err = tx.QueryRow(ctx, `SELECT id, service_id, team_id, kind, identity_id, invitation_id,
			created_by_identity_id, idempotency_key, request_digest, created_at, expires_at, revoked_at
			FROM control.visitor_grants WHERE id=$1 FOR UPDATE`, oldID).Scan(&existing.ID, &existing.ServiceID,
			&existing.TeamID, &existing.Kind, &existing.IdentityID, &existing.InvitationID, &existing.CreatedByIdentityID,
			&existing.IdempotencyKey, &existing.RequestDigest, &existing.CreatedAt, &existing.ExpiresAt, &existing.RevokedAt)
		if err != nil {
			return result, err
		}
		if existing.ServiceID.String != serviceID || existing.RevokedAt.Valid || !bytes.Equal(existing.RequestDigest, digest[:]) {
			return result, ErrServiceConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return result, err
		}
		return privateGrantRecord(existing), nil
	}
	row, err := controlstatedb.New(tx).InsertServiceGrant(ctx, controlstatedb.InsertServiceGrantParams{
		ID: id, ServiceID: text(serviceID), TeamID: service.TeamID, Kind: kind, IdentityID: nullableText(identityID),
		CreatedByIdentityID: actorID, IdempotencyKey: key, RequestDigest: digest[:], Now: timestamptz(now), ExpiresAt: nullableTime(expires),
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return result, ErrServiceConflict
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

func (d *Database) ListServiceGrants(ctx context.Context, serviceID, actorID, after string) (result []ServiceGrant, next string, retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) || after != "" && !opaqueid.Valid(after, opaqueid.ServiceGrantPrefix) {
		return nil, "", ErrServiceAccess
	}
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, "", err
	}
	defer rollback(ctx, tx, "list service grants", &retErr)()
	if _, err = lockService(ctx, tx, serviceID, actorID); err != nil {
		return nil, "", err
	}
	rows, err := controlstatedb.New(tx).ListServiceGrants(ctx, controlstatedb.ListServiceGrantsParams{ServiceID: text(serviceID), AfterID: after})
	if err != nil {
		return nil, "", err
	}
	if len(rows) > 100 {
		next, rows = rows[99].ID, rows[:100]
	}
	result = make([]ServiceGrant, 0, len(rows))
	for _, row := range rows {
		result = append(result, privateGrantRecord(row))
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return result, next, nil
}

func (d *Database) RevokeServiceGrant(ctx context.Context, serviceID, actorID, grantID string, now time.Time) (retErr error) {
	if !opaqueid.Valid(grantID, opaqueid.ServiceGrantPrefix) {
		return ErrServiceAccess
	}
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke service grant", &retErr)()
	if _, err = lockService(ctx, tx, serviceID, actorID); err != nil {
		return err
	}
	if err = rejectProjectManagedGrant(ctx, tx, grantID); err != nil {
		return err
	}
	count, err := controlstatedb.New(tx).RevokeServiceGrant(ctx, controlstatedb.RevokeServiceGrantParams{ID: grantID, ServiceID: text(serviceID), Now: timestamptz(now)})
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrServiceAccess
	}
	if err = auditPrivateMutation(ctx, tx, serviceID, actorID, "grant.revoke", grantID, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
