package controlstate

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

var ErrExternalAuthorityPrincipal = errors.New("controlstate: external authority principal is invalid")

// EnsureExternalAuthorityPrincipal records only the server-local principal ID
// needed by durable route and audit state and returns the shared retry secret.
func (d *Database) EnsureExternalAuthorityPrincipal(
	ctx context.Context,
	identityID string,
	now time.Time,
) (result [32]byte, retErr error) {
	if !opaqueid.Valid(identityID, "identity_") {
		return result, ErrExternalAuthorityPrincipal
	}
	if err := d.requireOpen(); err != nil {
		return result, err
	}
	candidate := make([]byte, len(result))
	if _, err := rand.Read(candidate); err != nil {
		return result, fmt.Errorf("controlstate: create external retry master key: %w", err)
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return result, fmt.Errorf("controlstate: ensure external authority principal: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "ensure external authority principal", &retErr)()
	queries := controlstatedb.New(tx)
	if _, err := queries.EnsureExternalAuthorityPrincipal(ctx, controlstatedb.EnsureExternalAuthorityPrincipalParams{
		IdentityID: identityID, CreatedAt: timestamptz(now),
	}); errors.Is(err, pgx.ErrNoRows) {
		return result, ErrExternalAuthorityPrincipal
	} else if err != nil {
		return result, fmt.Errorf("controlstate: ensure external authority principal: %w", err)
	}
	key, err := queries.EnsureExternalRetryMasterKey(ctx, controlstatedb.EnsureExternalRetryMasterKeyParams{
		ExternalRetryMasterKey: candidate, CreatedAt: timestamptz(now),
	})
	if err != nil || len(key) != len(result) {
		return result, fmt.Errorf("controlstate: ensure external retry master key: %w", err)
	}
	copy(result[:], key)
	if err := tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("controlstate: ensure external authority principal: commit: %w", err)
	}
	return result, nil
}
