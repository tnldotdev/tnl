package controlstate

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
)

// EnsureServiceIdentity resolves identity facts supplied by the configured OIDC
// provider's website. it never issues a control session or changes team roles.
func (d *Database) EnsureServiceIdentity(ctx context.Context, managedDomain string, identity OIDCIdentity, now time.Time) (result IdentityContext, retErr error) {
	if !validStateText(managedDomain) || !validStateText(identity.Issuer) || len(identity.Issuer) > 2048 ||
		!validStateText(identity.Subject) || len(identity.Subject) > 256 || !validStateText(identity.DisplayName) || len(identity.DisplayName) > 256 || now.IsZero() {
		return result, ErrAuthorityInvalid
	}
	email, err := normalizeEmailRestriction(identity.NormalizedEmail)
	if err != nil || email != identity.NormalizedEmail || (email != "") != identity.EmailVerified {
		return result, ErrAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "resolve service identity", &retErr)()
	queries := controlstatedb.New(tx)
	if err := queries.LockIdentityBootstrap(ctx); err != nil {
		return result, err
	}
	stored, err := ensureOIDCIdentity(ctx, queries, managedDomain, d.managedURLMode, identity, now)
	if err != nil {
		return result, err
	}
	result, err = loadIdentityContext(ctx, queries, stored.ID)
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func ensureOIDCIdentity(ctx context.Context, queries *controlstatedb.Queries, managedDomain string, mode naming.ManagedURLMode, identity OIDCIdentity, now time.Time) (controlstatedb.ControlIdentity, error) {
	domain, err := ensureManagedDomain(ctx, queries, managedDomain, now)
	if err != nil {
		return controlstatedb.ControlIdentity{}, err
	}
	stored, err := queries.FindOIDCIdentity(ctx, controlstatedb.FindOIDCIdentityParams{Issuer: text(identity.Issuer), Subject: text(identity.Subject)})
	if errors.Is(err, pgx.ErrNoRows) {
		return createOIDCIdentity(ctx, queries, domain.ID, mode, identity, now)
	}
	if err != nil {
		return stored, err
	}
	if stored.DisabledAt.Valid {
		return stored, ErrAuthorityAccess
	}
	return queries.UpdateOIDCIdentity(ctx, controlstatedb.UpdateOIDCIdentityParams{
		DisplayName: identity.DisplayName, NormalizedEmail: nullableText(identity.NormalizedEmail),
		EmailVerified: identity.EmailVerified, UpdatedAt: timestamp(now), ID: stored.ID,
	})
}

type InvitationPreview struct {
	TeamDisplayName string
	InitialRole     TeamRole
	ExpiresAt       time.Time
}

func (d *Database) PreviewInvitation(ctx context.Context, identityID string, secret string, now time.Time) (InvitationPreview, error) {
	digest, err := credentials.ParseInvitationToken(credentials.InvitationToken(secret))
	if err != nil {
		return InvitationPreview{}, ErrInvitationNotFound
	}
	row, err := controlstatedb.New(d.pool).PreviewInvitation(ctx, controlstatedb.PreviewInvitationParams{IdentityID: identityID, TokenDigest: digest[:]})
	if errors.Is(err, pgx.ErrNoRows) {
		return InvitationPreview{}, ErrInvitationNotFound
	}
	if err != nil {
		return InvitationPreview{}, err
	}
	if row.State != string(InvitationPending) || !row.ExpiresAt.Time.After(now) {
		return InvitationPreview{}, ErrAuthorityConflict
	}
	if row.NormalizedEmailRestriction.Valid && (!row.EmailVerified || row.NormalizedEmail.String != row.NormalizedEmailRestriction.String) {
		return InvitationPreview{}, ErrAuthorityAccess
	}
	return InvitationPreview{TeamDisplayName: row.DisplayName, InitialRole: TeamRole(row.InitialRole), ExpiresAt: row.ExpiresAt.Time}, nil
}
