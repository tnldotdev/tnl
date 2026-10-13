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

// RegisterGuestPublisherIdentity gives one trial a signing key and its exact
// managed namespace. guest team IDs never become organization team rows.
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
	if err != nil || !guest.ExpiresAt.Time.After(now) || guest.UsedReadyNs >= int64(GuestReadyAllowance) || guest.UsedBytes >= GuestByteAllowance {
		return PublisherIdentity{}, ErrGuestTrialSpent
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
	expiry := guest.ExpiresAt.Time
	scope := PublisherScope{TeamID: guest.TeamID, DomainID: guest.DomainID,
		Namespace: guest.NamespaceLabel + "." + domain.CanonicalDomain, Kind: "namespace"}
	identity, err := insertPublisherIdentity(ctx, queries, scope, "guest-demo", "guest", guestID, public, &expiry, now)
	if err != nil {
		return PublisherIdentity{}, err
	}
	if err := queries.InsertGuestPublisherIdentity(ctx, controlstatedb.InsertGuestPublisherIdentityParams{
		PublisherIdentityID: identity.ID, GuestID: guestID, CreatedAt: timestamptz(now),
	}); err != nil {
		return PublisherIdentity{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PublisherIdentity{}, err
	}
	identity.GuestID = guestID
	return identity, nil
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
	prefix := netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen()).String()
	return d.GuestSourceMatches(GuestTrial{ID: guestID,
		SourceIPDigest: row.SourceIpDigest.String, SourceIPKeyID: row.SourceIpKeyID.String}, prefix)
}

// EnsureGuestIdentity supplies the foreign-key actor for the guest trial's
// temporary demo URL; publisher retry credentials come from signed run proofs.
func (d *Database) EnsureGuestIdentity(ctx context.Context, guestID string, now time.Time) error {
	if !opaqueid.Valid(guestID, opaqueid.GuestPrefix) {
		return ErrGuestUnknown
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	_, err := controlstatedb.New(d.pool).EnsureGuestPrincipal(ctx, controlstatedb.EnsureGuestPrincipalParams{
		IdentityID: guestID, CreatedAt: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrGuestUnknown
	}
	return err
}
