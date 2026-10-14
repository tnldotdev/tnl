package controlstate

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

// RegisterGuestPublisherIdentity registers one signing key inside the trial's
// existing namespace and lifetime.
func (d *Database) RegisterGuestPublisherIdentity(ctx context.Context, guestID string, public ed25519.PublicKey, now time.Time) (result PublisherIdentity, retErr error) {
	if !opaqueid.Valid(guestID, opaqueid.GuestPrefix) || len(public) != ed25519.PublicKeySize {
		return PublisherIdentity{}, ErrPublisherIdentity
	}
	if err := d.requireOpen(); err != nil {
		return PublisherIdentity{}, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return PublisherIdentity{}, err
	}
	defer rollback(ctx, tx, "register guest publisher", &retErr)()
	queries := controlstatedb.New(tx)
	guest, err := queries.LockGuestTrialByID(ctx, guestID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (!guest.ExpiresAt.Time.After(now) || guest.UsedReadyNs >= int64(GuestReadyAllowance) || guest.UsedBytes >= GuestByteAllowance) {
		return PublisherIdentity{}, ErrGuestTrialSpent
	}
	if err != nil {
		return PublisherIdentity{}, err
	}
	domain, err := queries.FindManagedDomain(ctx)
	if err != nil || domain.ID != guest.DomainID || domain.State != "ready" {
		return PublisherIdentity{}, ErrPublisherIdentity
	}
	if _, err := queries.EnsureGuestPrincipal(ctx, controlstatedb.EnsureGuestPrincipalParams{
		IdentityID: guestID, CreatedAt: timestamptz(now),
	}); err != nil {
		return PublisherIdentity{}, err
	}
	id, err := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	if err != nil {
		return PublisherIdentity{}, err
	}
	keyID, err := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	if err != nil {
		return PublisherIdentity{}, err
	}
	grantID, err := opaqueid.New(opaqueid.PublisherGrantPrefix)
	if err != nil {
		return PublisherIdentity{}, err
	}
	scope := PublisherScope{TeamID: guest.TeamID, DomainID: guest.DomainID,
		Namespace: guest.NamespaceLabel + "." + domain.CanonicalDomain, Kind: "namespace"}
	if _, err := queries.InsertPublisherIdentity(ctx, controlstatedb.InsertPublisherIdentityParams{
		ID: id, TeamID: guest.TeamID, Name: "guest-demo", Kind: "guest",
		CreatedByIdentityID: text(guestID), CreatedAt: timestamptz(now),
	}); err != nil {
		return PublisherIdentity{}, err
	}
	if _, err := queries.InsertPublisherIdentityKey(ctx, controlstatedb.InsertPublisherIdentityKeyParams{
		ID: keyID, PublisherIdentityID: id, Revision: 1, PublicKey: public, CreatedAt: timestamptz(now),
	}); err != nil {
		return PublisherIdentity{}, err
	}
	if _, err := queries.InsertPublisherIdentityGrant(ctx, controlstatedb.InsertPublisherIdentityGrantParams{
		ID: grantID, PublisherIdentityID: id, Kind: "namespace", DomainID: text(guest.DomainID),
		Namespace: text(scope.Namespace), CreatedAt: timestamptz(now), ExpiresAt: timestamptz(guest.ExpiresAt.Time),
	}); err != nil {
		return PublisherIdentity{}, err
	}
	if err := queries.InsertGuestPublisherIdentity(ctx, controlstatedb.InsertGuestPublisherIdentityParams{
		PublisherIdentityID: id, GuestID: guestID, CreatedAt: timestamptz(now),
	}); err != nil {
		return PublisherIdentity{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PublisherIdentity{}, err
	}
	return PublisherIdentity{ID: id, KeyID: keyID, GrantID: grantID, GuestID: guestID, CreatorID: guestID, Scope: scope}, nil
}

func guestPublisherScope(scope PublisherScope, guest controlstatedb.GuestForPublisherIdentityRow, now time.Time) bool {
	return scope.Kind == "namespace" && scope.TeamID == guest.TeamID && scope.DomainID == guest.DomainID &&
		scope.Namespace == guest.NamespaceLabel+"."+guest.CanonicalDomain && guest.ExpiresAt.Time.After(now) &&
		guest.UsedReadyNs < int64(GuestReadyAllowance) && guest.UsedBytes < GuestByteAllowance
}

func (d *Database) GuestPublisherSourceMatches(ctx context.Context, guestID string, address netip.Addr) (bool, error) {
	if !opaqueid.Valid(guestID, opaqueid.GuestPrefix) || !address.IsValid() || address.Zone() != "" {
		return false, ErrGuestUnknown
	}
	row, err := controlstatedb.New(d.pool).GetGuestTrialByID(ctx, guestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrGuestUnknown
	}
	if err != nil {
		return false, err
	}
	address = address.Unmap()
	return d.GuestSourceMatches(GuestTrial{ID: guestID,
		SourceIPDigest: row.SourceIpDigest.String, SourceIPKeyID: row.SourceIpKeyID.String},
		netip.PrefixFrom(address, address.BitLen()).String())
}
