package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

var ErrVisitorSigningKey = errors.New("visitor signing key is unavailable")

const maximumVisitorVerificationKeys = 64

func visitorSigningKeyContext(id string) string { return "visitor-token-signing-key:" + id }

// the issuer row is the replica-wide serialization point for issuance, rotation,
// and retirement. resource authorization locks are acquired before this row.
func ensureVisitorIssuer(ctx context.Context, q *controlstatedb.Queries, issuer string) error {
	canonical, err := naming.CanonicalControlURL(issuer)
	if err != nil || canonical != issuer || len(issuer) > 256 {
		return ErrVisitorSigningKey
	}
	stored, err := q.EnsureVisitorTokenIssuer(ctx, issuer)
	if err != nil {
		return fmt.Errorf("read visitor issuer: %w", err)
	}
	if stored != issuer {
		return ErrVisitorSigningKey
	}
	return nil
}

func (d *Database) createVisitorSigningKey(ctx context.Context, q *controlstatedb.Queries, now time.Time) (controlstatedb.ControlVisitorTokenKey, error) {
	var zero controlstatedb.ControlVisitorTokenKey
	keys, err := q.VisitorTokenVerificationKeys(ctx, timestamptz(now))
	if err != nil {
		return zero, err
	}
	if len(keys) >= maximumVisitorVerificationKeys {
		return zero, ErrVisitorSigningKey
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return zero, err
	}
	defer clear(private)
	id, err := opaqueid.New("vtk_")
	if err != nil {
		return zero, err
	}
	sealed, err := d.storageKey.Seal(visitorSigningKeyContext(id), private.Seed())
	if err != nil {
		return zero, err
	}
	return q.CreateVisitorTokenSigningKey(ctx, controlstatedb.CreateVisitorTokenSigningKeyParams{ID: id, PublicKey: public, SeedCiphertext: sealed, StorageKeyID: d.storageKey.CurrentID(), Now: timestamptz(now)})
}

// signVisitorPermission is called only after the new permission model has
// authorized the exact scope and capped its deadline in this same transaction.
// retaining the key and committing the permission are one durable decision.
func (d *Database) signVisitorPermission(ctx context.Context, tx pgx.Tx, issuer string, permission visitortoken.Permission, now time.Time) (visitortoken.Token, error) {
	if d.storageKey == nil {
		return "", ErrVisitorSigningKey
	}
	q := controlstatedb.New(tx)
	if err := ensureVisitorIssuer(ctx, q, issuer); err != nil {
		return "", err
	}
	row, err := q.LockVisitorTokenSigningKey(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		row, err = d.createVisitorSigningKey(ctx, q, now)
	}
	if err != nil {
		return "", err
	}
	if row.CreatedAt.Time.After(now) {
		return "", ErrVisitorSigningKey
	}
	seed, _, err := d.storageKey.Open(row.StorageKeyID, visitorSigningKeyContext(row.ID), row.SeedCiphertext)
	if err != nil {
		return "", fmt.Errorf("open visitor signing key: %w", err)
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return "", ErrVisitorSigningKey
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	if !bytes.Equal(private.Public().(ed25519.PublicKey), row.PublicKey) {
		return "", ErrVisitorSigningKey
	}
	token, err := visitortoken.Sign(issuer, row.ID, private, permission, now)
	if err != nil {
		return "", err
	}
	changed, err := q.RetainVisitorTokenSigningKey(ctx, controlstatedb.RetainVisitorTokenSigningKeyParams{ID: row.ID, ExpiresAt: timestamptz(permission.ExpiresAt)})
	if err != nil {
		return "", err
	}
	if changed != 1 {
		return "", ErrVisitorSigningKey
	}
	return token, nil
}

// RotateVisitorSigningKey is a control-owned operation. emergency rotation drops
// every previous verification key; ordinary rotation retains unexpired tokens.
func (d *Database) RotateVisitorSigningKey(ctx context.Context, issuer string, emergency bool, now time.Time) (retErr error) {
	if d.storageKey == nil {
		return ErrVisitorSigningKey
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "rotate visitor signing key", &retErr)()
	q := controlstatedb.New(tx)
	if err := ensureVisitorIssuer(ctx, q, issuer); err != nil {
		return err
	}
	if emergency {
		if err := q.RevokeVisitorTokenSigningKeys(ctx, timestamptz(now)); err != nil {
			return err
		}
	} else if err := q.RetireVisitorTokenSigningKeys(ctx, timestamptz(now)); err != nil {
		return err
	}
	if err := q.DeleteExpiredVisitorTokenSigningKeys(ctx, timestamptz(now)); err != nil {
		return err
	}
	if _, err := d.createVisitorSigningKey(ctx, q, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// visitorVerificationKeys returns public material only. authenticated policy
// snapshots call it within their snapshot transaction, after locking the issuer.
func visitorVerificationKeys(ctx context.Context, q *controlstatedb.Queries, issuer string, now time.Time) (map[string]ed25519.PublicKey, error) {
	if err := ensureVisitorIssuer(ctx, q, issuer); err != nil {
		return nil, err
	}
	rows, err := q.VisitorTokenVerificationKeys(ctx, timestamptz(now))
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 || len(rows) > maximumVisitorVerificationKeys {
		return nil, ErrVisitorSigningKey
	}
	keys := make(map[string]ed25519.PublicKey, len(rows))
	for _, row := range rows {
		if !opaqueid.Valid(row.ID, "vtk_") || len(row.PublicKey) != ed25519.PublicKeySize {
			return nil, ErrVisitorSigningKey
		}
		keys[row.ID] = bytes.Clone(row.PublicKey)
	}
	return keys, nil
}
