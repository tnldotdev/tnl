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

func visitorSigningKeyContext(id string) string { return "visitor-token-signing-key:" + id }

// PrepareVisitorSigningKeys runs during control startup, before serving owners
// prepare policy views. anonymous traffic must not wait for a first token issue.
func (d *Database) PrepareVisitorSigningKeys(ctx context.Context, issuer string, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "prepare visitor signing keys", &retErr)()
	q := controlstatedb.New(tx)
	if err := ensureVisitorIssuer(ctx, q, issuer); err != nil {
		return err
	}
	if _, err := q.LockVisitorTokenIssuer(ctx); err != nil {
		return err
	}
	if err := q.LockVisitorVerificationAuthority(ctx); err != nil {
		return err
	}
	if _, err := q.LockVisitorTokenSigningKey(ctx); errors.Is(err, pgx.ErrNoRows) {
		if _, err := d.createVisitorSigningKey(ctx, q, now); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// the issuer is immutable after bootstrap. ordinary issuance reads it without
// joining the exclusive key-creation and rotation queue.
func ensureVisitorIssuer(ctx context.Context, q *controlstatedb.Queries, issuer string) error {
	canonical, err := naming.CanonicalControlURL(issuer)
	if err != nil || canonical != issuer || len(issuer) > 256 {
		return ErrVisitorSigningKey
	}
	stored, err := q.ReadVisitorTokenIssuer(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		// concurrent bootstrap either becomes visible at read committed or
		// fails serialization at repeatable read. the caller retries its whole
		// authorization transaction; it must never sign from a stale snapshot.
		if err := q.EnsureVisitorTokenIssuer(ctx, issuer); err != nil {
			return fmt.Errorf("read visitor issuer: %w", err)
		}
		stored, err = q.ReadVisitorTokenIssuer(ctx)
	}
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
	return d.signVisitorCredential(ctx, tx, issuer, permission.ExpiresAt, now, func(id string, private ed25519.PrivateKey) (visitortoken.Token, error) {
		return visitortoken.Sign(issuer, id, private, permission, now)
	})
}

func (d *Database) signWorkloadIdentity(ctx context.Context, tx pgx.Tx, issuer string, identity visitortoken.WorkloadIdentity, now time.Time) (visitortoken.Token, error) {
	return d.signVisitorCredential(ctx, tx, issuer, identity.ExpiresAt, now, func(id string, private ed25519.PrivateKey) (visitortoken.Token, error) {
		return visitortoken.SignWorkloadIdentity(issuer, id, private, identity, now)
	})
}

// signing profiles share key validation and retention.
// callers authorize their distinct facts and absolute expiry in this transaction.
func (d *Database) signVisitorCredential(ctx context.Context, tx pgx.Tx, issuer string, expires time.Time, now time.Time, sign func(string, ed25519.PrivateKey) (visitortoken.Token, error)) (visitortoken.Token, error) {
	if d.storageKey == nil {
		return "", ErrVisitorSigningKey
	}
	q := controlstatedb.New(tx)
	if err := ensureVisitorIssuer(ctx, q, issuer); err != nil {
		return "", err
	}
	// signers share the issuer before key authority. previous binaries rotate
	// under the exclusive issuer guard before touching keys or their revision.
	_, err := q.ObserveVisitorTokenIssuer(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err = q.LockVisitorTokenIssuer(ctx); err != nil {
			return "", err
		}
		if err = q.LockVisitorVerificationAuthority(ctx); err != nil {
			return "", err
		}
	}
	if err != nil {
		return "", err
	}
	row, err := q.LockVisitorTokenSigningAuthority(ctx)
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
	token, err := sign(row.ID, private)
	if err != nil {
		return "", err
	}
	// key authority is held through commit. sufficient retention needs no write;
	// an extension must still update exactly that current, unrevoked key.
	if row.RetainUntil.Time.Before(expires) {
		// round retention upward to amortize writes across issuances. this is
		// a cleanup horizon, not a token lifetime or an inventory ceiling.
		retain := expires.Truncate(time.Hour).Add(time.Hour)
		changed, err := q.RetainVisitorTokenSigningKey(ctx, controlstatedb.RetainVisitorTokenSigningKeyParams{ID: row.ID, ExpiresAt: timestamptz(retain)})
		if err != nil {
			return "", err
		}
		if changed != 1 {
			current, err := q.LockVisitorTokenSigningAuthority(ctx)
			if err != nil {
				return "", err
			}
			if current.ID != row.ID || current.RetainUntil.Time.Before(expires) {
				return "", ErrVisitorSigningKey
			}
		}
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
	if _, err := q.LockVisitorTokenIssuer(ctx); err != nil {
		return err
	}
	if err := q.LockVisitorVerificationAuthority(ctx); err != nil {
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
