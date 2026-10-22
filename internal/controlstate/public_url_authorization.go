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
	result := publicURLFromAuthorizationRow(row)
	if err := d.restorePublicURLPolicy(&result, row.AllowedIpPolicyStorageKeyID, row.AllowedIpPolicyCiphertext, row.AllowedIpHashes); err != nil {
		return PublicURL{}, err
	}
	return result, nil
}

func publicURLFromAuthorizationRow(row controlstatedb.GetPublicURLForAuthorizationDataRow) PublicURL {
	return publicURLFromProjection(publicURLProjection{
		ID: row.ID, TeamID: row.TeamID, DomainID: row.DomainID, MembershipID: row.MembershipID,
		CanonicalHostname: row.CanonicalHostname, Target: row.Target, Namespace: row.Namespace,
		PublicURLScope: row.PublicURLScope, Purpose: row.Purpose, AccessMode: row.AccessMode,
		PolicyRevision: row.PolicyRevision, LifecycleState: row.LifecycleState,
		DNSAuthorityReference: row.DnsAuthorityReference, DNSState: row.DnsState,
		NextPublishRunNumber: row.NextPublishRunNumber, MutationRevision: row.MutationRevision,
		Ephemeral: row.Ephemeral, ExpiresAt: row.ExpiresAt, OpenPublishRunID: row.OpenPublishRunID,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, ServiceProtocol: row.ServiceProtocol, PublisherPool: row.PublisherPool,
		AuthorizationPublishRunNumber: &row.AuthorizationPublishRunNumber,
	})
}
