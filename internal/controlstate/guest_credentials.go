package controlstate

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
)

func (d *Database) EnsureGuestPrincipal(ctx context.Context, guestID string, now time.Time) (result [32]byte, retErr error) {
	if err := d.requireOpen(); err != nil {
		return result, err
	}
	candidate := make([]byte, 32)
	if _, err := rand.Read(candidate); err != nil {
		return result, err
	}
	ciphertext, err := d.sealSecret(guestRetryMasterKeyContext(), candidate)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "ensure guest principal", &retErr)()
	queries := controlstatedb.New(tx)
	if _, err := queries.EnsureGuestPrincipal(ctx, controlstatedb.EnsureGuestPrincipalParams{IdentityID: guestID, CreatedAt: timestamp(now)}); errors.Is(err, pgx.ErrNoRows) {
		return result, ErrGuestUnknown
	} else if err != nil {
		return result, err
	}
	stored, err := queries.EnsureGuestRetryMasterKey(ctx, controlstatedb.EnsureGuestRetryMasterKeyParams{Ciphertext: ciphertext, KeyID: d.storageKey.CurrentID(), CreatedAt: timestamp(now)})
	if err != nil {
		return result, err
	}
	key, _, err := d.openSecret(stored.GuestRetryMasterKeyStorageKeyID, guestRetryMasterKeyContext(), stored.GuestRetryMasterKeyCiphertext)
	if err != nil {
		return result, failure.Wrap("open guest retry key", failure.ServerStoredStateInvalid, err)
	}
	if len(key) != 32 {
		return result, failure.Wrap("read guest retry key", failure.ServerStoredStateInvalid,
			errors.New("controlstate: invalid guest retry key"))
	}
	copy(result[:], key)
	return result, tx.Commit(ctx)
}
