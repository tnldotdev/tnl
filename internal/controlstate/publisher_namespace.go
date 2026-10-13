package controlstate

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

func newEphemeralHostname(namespace string) (string, error) {
	canonical, err := naming.CanonicalizeHostname(namespace)
	if err != nil || canonical != namespace {
		return "", ErrPublicURLInvalid
	}
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	label := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(entropy[:]))
	hostname := "eph-" + label + "." + namespace
	if len(hostname) > naming.MaxHostnameBytes {
		return "", ErrPublicURLInvalid
	}
	return hostname, nil
}

// PublisherMayStartRun checks the grant's captured URL IDs before control
// reads route state, so an out-of-scope token cannot probe other teams' IDs.
func (d *Database) PublisherMayStartRun(ctx context.Context, identity PublisherIdentity, publicURLID string) (bool, error) {
	if !validStateText(publicURLID) {
		return false, ErrPublicURLInvalid
	}
	if identity.Scope.Kind == "saved_url" {
		return identity.Scope.PublicURLID == publicURLID, nil
	}
	if identity.GuestID != "" {
		return d.GuestOwnsPublicURL(ctx, identity.GuestID, publicURLID)
	}
	if identity.Scope.Kind != "namespace" {
		return false, nil
	}
	allocation, err := controlstatedb.New(d.pool).GetPublisherNamespaceAllocation(ctx, publicURLID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return allocation.PublisherIdentityID == identity.ID && allocation.PublisherGrantID == identity.GrantID, nil
}

func (d *Database) PublisherRunLinked(ctx context.Context, authenticated PublishRunAuthentication) (bool, error) {
	if err := validatePublishRunAuthentication(authenticated); err != nil {
		return false, err
	}
	_, err := controlstatedb.New(d.pool).GetPublishRunPublisherIdentity(ctx, authenticated.PublishRunID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func validatePublisherNamespaceDeletion(ctx context.Context, queries *controlstatedb.Queries,
	request AuthorizedPublicURLDeleteRequest, route controlstatedb.ControlPublicUrl, now time.Time,
) error {
	if !route.Ephemeral || route.TeamID != request.TeamID || route.CreatedByIdentityID != request.ActingIdentityID {
		return ErrPublicURLAccess
	}
	allocation, err := queries.GetPublisherNamespaceAllocation(ctx, route.ID)
	if err != nil || allocation.PublisherIdentityID != request.PublisherIdentityID ||
		allocation.PublisherGrantID != request.PublisherGrantID {
		return ErrPublicURLAccess
	}
	identity, err := queries.LockPublisherIdentity(ctx, request.PublisherIdentityID)
	if err != nil || identity.RevokedAt.Valid || identity.TeamID != route.TeamID {
		return ErrPublicURLAccess
	}
	grant, err := queries.GetPublisherIdentityGrant(ctx, controlstatedb.GetPublisherIdentityGrantParams{
		GrantID: request.PublisherGrantID, PublisherIdentityID: request.PublisherIdentityID,
	})
	if err != nil || grant.Kind != "namespace" || grant.DomainID.String != route.DomainID ||
		grant.Namespace.String != route.Namespace || grant.RevokedAt.Valid ||
		grant.ExpiresAt.Valid && !grant.ExpiresAt.Time.After(now) {
		return ErrPublicURLAccess
	}
	return nil
}
