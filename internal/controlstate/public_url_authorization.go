package controlstate

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

// GetPublicURLForAuthorization returns saved state before the caller authorizes
// access. callers must not expose it before checking current membership.
func (d *Database) GetPublicURLForAuthorization(ctx context.Context, publicURLID string) (PublicURL, error) {
	return d.getPublicURLForAuthorization(ctx, publicURLID, "")
}

func (d *Database) GetPublicURLForPublishRunAuthorization(ctx context.Context, publicURLID, key string) (PublicURL, error) {
	if !validStateText(key) || len(key) > 128 {
		return PublicURL{}, ErrPublicURLInvalid
	}
	return d.getPublicURLForAuthorization(ctx, publicURLID, key)
}

func (d *Database) getPublicURLForAuthorization(ctx context.Context, id, key string) (PublicURL, error) {
	if !validStateText(id) {
		return PublicURL{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return PublicURL{}, err
	}
	row, err := controlstatedb.New(d.pool).GetPublicURLForAuthorizationData(ctx, controlstatedb.GetPublicURLForAuthorizationDataParams{PublicURLID: id, PublishRunIdempotencyKey: key})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURL{}, ErrPublicURLNotFound
	}
	if err != nil {
		return PublicURL{}, err
	}
	result := publicURLFromValues(row.ID, row.TeamID, row.DomainID, row.MembershipID, row.CanonicalHostname, row.Target, row.PublicURLScope, row.Purpose, row.PolicyRevision, row.LifecycleState, row.DnsAuthorityReference, row.DnsState, row.NextPublishRunNumber, row.MutationRevision, row.Ephemeral, row.ExpiresAt, row.OpenPublishRunID, row.CreatedAt, row.UpdatedAt)
	if err := d.restorePublicURLPolicy(&result, row.AllowedIpPolicyStorageKeyID, row.AllowedIpPolicyCiphertext, row.AllowedIpHashes); err != nil {
		return PublicURL{}, err
	}
	result.AuthorizationPublishRunNumber = uint64(row.AuthorizationPublishRunNumber)
	return result, nil
}
