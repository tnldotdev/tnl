package state

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

type VisitorDevice struct {
	ID         string     `json:"id"`
	IdentityID string     `json:"identity_id"`
	PublicKey  string     `json:"public_key"`
	CreatedAt  time.Time  `json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// enrolling an existing key is retry-stable. revocation is permanent: signing
// in again cannot resurrect a stolen device key.
func (d *Database) EnrollVisitorDevice(ctx context.Context, identityID string, key ed25519.PublicKey, now time.Time) (result VisitorDevice, err error) {
	if len(key) != ed25519.PublicKeySize {
		return result, ErrServiceAccess
	}
	id, err := opaqueid.New("vdev_")
	if err != nil {
		return result, err
	}
	var public []byte
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "enroll visitor device", &err)()
	err = tx.QueryRow(ctx, `INSERT INTO control.visitor_devices(id,identity_id,public_key,created_at)
	    SELECT $1,id,$3,$4 FROM control.identities WHERE id=$2 AND disabled_at IS NULL
	    ON CONFLICT(identity_id,public_key) DO UPDATE SET public_key=EXCLUDED.public_key
	    WHERE control.visitor_devices.revoked_at IS NULL RETURNING id,identity_id,public_key,created_at`, id, identityID, []byte(key), now).
		Scan(&result.ID, &result.IdentityID, &public, &result.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	if err = auditDeviceMutation(ctx, tx, identityID, result.ID, "device.enroll", result.CreatedAt); err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	result.PublicKey = hex.EncodeToString(public)
	return result, nil
}

func (d *Database) RevokeVisitorDevice(ctx context.Context, identityID, deviceID string, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke visitor device", &retErr)()
	tag, err := tx.Exec(ctx, `UPDATE control.visitor_devices SET revoked_at=COALESCE(revoked_at,$3) WHERE id=$1 AND identity_id=$2`, deviceID, identityID, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrServiceAccess
	}
	if err = auditDeviceMutation(ctx, tx, identityID, deviceID, "device.revoke", now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
