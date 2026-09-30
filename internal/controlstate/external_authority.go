package controlstate

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

var ErrExternalAuthorityPrincipal = errors.New("controlstate: external authority principal is invalid")

// EnsureExternalAuthorityPrincipal records only the server-local principal ID
// needed by stored route and audit state and returns the shared retry secret.
func (d *Database) EnsureExternalAuthorityPrincipal(
	ctx context.Context,
	identityID string,
	now time.Time,
) (result [32]byte, retErr error) {
	if !validStateText(identityID) {
		return result, ErrExternalAuthorityPrincipal
	}
	if err := d.requireOpen(); err != nil {
		return result, err
	}
	candidate := make([]byte, len(result))
	if _, err := rand.Read(candidate); err != nil {
		return result, fmt.Errorf("controlstate: create external retry master key: %w", err)
	}
	candidateCiphertext, err := d.sealSecret(externalRetryMasterKeyContext(), candidate)
	if err != nil {
		return result, fmt.Errorf("controlstate: encrypt external retry master key: %w", err)
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
	stored, err := queries.EnsureExternalRetryMasterKey(ctx, controlstatedb.EnsureExternalRetryMasterKeyParams{
		ExternalRetryMasterKeyCiphertext: candidateCiphertext, CreatedAt: timestamptz(now),
		ExternalRetryMasterKeyStorageKeyID: d.storageKey.CurrentID(),
	})
	if err != nil {
		return result, fmt.Errorf("controlstate: ensure external retry master key: %w", err)
	}
	key, previous, err := d.openSecret(stored.ExternalRetryMasterKeyStorageKeyID, externalRetryMasterKeyContext(), stored.ExternalRetryMasterKeyCiphertext)
	if err != nil || len(key) != len(result) {
		return result, errors.New("controlstate: external retry master key is invalid")
	}
	if previous {
		rotated, err := d.sealSecret(externalRetryMasterKeyContext(), key)
		if err != nil {
			return result, fmt.Errorf("controlstate: re-encrypt external retry master key: %w", err)
		}
		if err := queries.RotateExternalRetryMasterKey(ctx, controlstatedb.RotateExternalRetryMasterKeyParams{
			ExternalRetryMasterKeyCiphertext: rotated, ExternalRetryMasterKeyStorageKeyID: d.storageKey.CurrentID(),
			PreviousKeyID: stored.ExternalRetryMasterKeyStorageKeyID, PreviousCiphertext: stored.ExternalRetryMasterKeyCiphertext,
		}); err != nil {
			return result, fmt.Errorf("controlstate: store re-encrypted external retry master key: %w", err)
		}
	}
	copy(result[:], key)
	if err := tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("controlstate: ensure external authority principal: commit: %w", err)
	}
	return result, nil
}

// GetPublicURLForAuthorization returns stored public URL data for an authority request.
// Callers must not expose the result before the authority approves it.
func (d *Database) GetPublicURLForAuthorization(ctx context.Context, publicURLID string) (PublicURL, error) {
	return d.getPublicURLForAuthorization(ctx, publicURLID, "")
}

// GetPublicURLForPublishRunAuthorization returns the publish run number from an earlier
// matching publish run request, or the next number for a new request.
func (d *Database) GetPublicURLForPublishRunAuthorization(
	ctx context.Context,
	publicURLID, idempotencyKey string,
) (PublicURL, error) {
	if !validStateText(idempotencyKey) || len(idempotencyKey) > 128 {
		return PublicURL{}, ErrPublicURLInvalid
	}
	return d.getPublicURLForAuthorization(ctx, publicURLID, idempotencyKey)
}

func (d *Database) getPublicURLForAuthorization(ctx context.Context, publicURLID, publishRunIdempotencyKey string) (PublicURL, error) {
	if !validStateText(publicURLID) {
		return PublicURL{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return PublicURL{}, err
	}
	row, err := controlstatedb.New(d.pool).GetExternalAuthorityPublicURL(ctx, controlstatedb.GetExternalAuthorityPublicURLParams{
		PublicURLID: publicURLID, PublishRunIdempotencyKey: publishRunIdempotencyKey,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURL{}, ErrPublicURLNotFound
	}
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: get public URL for authorization: %w", err)
	}
	result := publicURLFromValues(
		row.ID, row.TeamID, row.DomainID, row.MembershipID, row.CanonicalHostname, row.Target,
		row.PublicURLScope, row.PolicyRevision, row.LifecycleState, row.DnsAuthorityReference, row.DnsState, row.AllowedIpPrefixes,
		row.NextPublishRunNumber, row.MutationRevision, row.Ephemeral, row.ExpiresAt, row.OpenPublishRunID, row.CreatedAt, row.UpdatedAt,
	)
	result.AuthorizationPublishRunNumber = uint64(row.AuthorizationPublishRunNumber)
	return result, nil
}
