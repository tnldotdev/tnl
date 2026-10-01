package controlstate

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const loginAuthenticationMethod = "login_token"

const oidcAuthenticationMethod = "oidc"

var (
	ErrControlAuthentication = errors.New("controlstate: invalid control credential")
	ErrControlIdentity       = errors.New("controlstate: identity is unavailable")
	ErrManagedDomainMismatch = errors.New("controlstate: configured managed deployment domain changed")
	ErrOIDCAssertionReplay   = errors.New("controlstate: OIDC assertion was already exchanged")
)

type IdentityContext struct {
	Identity       Identity
	PersonalTeamID string
	Memberships    []Membership
}

type Identity struct {
	ID              string
	DisplayName     string
	NormalizedEmail string
	EmailVerified   bool
	Administrator   bool
	CreatedAt       time.Time
}

type Membership struct {
	ID              string
	TeamID          string
	IdentityID      string
	TeamDisplayName string
	TeamKind        TeamKind
	Role            TeamRole
	MemberSlug      string
	ManagedLabel    string
	PolicyRevision  int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type ControlPrincipal struct {
	SessionID        string
	IdentityID       string
	Administrator    bool
	RetrySecret      [32]byte
	RefreshExpiresAt time.Time
}

type ControlSession struct {
	SessionID        string
	AccessToken      credentials.AccessToken
	AccessExpiresAt  time.Time
	RefreshToken     credentials.RefreshToken
	RefreshExpiresAt time.Time
	Identity         IdentityContext
}

// OIDCIdentity contains the limited identity and assertion fields verified from
// an ID token.
type OIDCIdentity struct {
	Issuer          string
	Subject         string
	DisplayName     string
	NormalizedEmail string
	EmailVerified   bool
	AssertionDigest [32]byte
	AssertionExpiry time.Time
}

func (d *Database) CreateBuiltinControlSession(
	ctx context.Context,
	managedDomain string,
	authenticationSourceRevision int64,
	accessLifetime time.Duration,
	refreshLifetime time.Duration,
	now time.Time,
) (result ControlSession, retErr error) {
	if managedDomain == "" || authenticationSourceRevision < 1 || accessLifetime <= 0 || refreshLifetime < accessLifetime {
		return ControlSession{}, ErrControlAuthentication
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ControlSession{}, fmt.Errorf("controlstate: begin builtin authentication: %w", err)
	}
	defer rollback(ctx, tx, "builtin authentication", &retErr)()
	queries := controlstatedb.New(tx)
	if err := queries.LockIdentityBootstrap(ctx); err != nil {
		return ControlSession{}, fmt.Errorf("controlstate: lock identity bootstrap: %w", err)
	}

	identity, err := queries.FindBuiltinIdentity(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		identity, err = bootstrapBuiltinIdentity(ctx, queries, managedDomain, now)
	}
	if err != nil {
		return ControlSession{}, err
	}
	domain, err := queries.FindManagedDomain(ctx)
	if err != nil {
		return ControlSession{}, fmt.Errorf("controlstate: read managed deployment domain: %w", err)
	}
	if domain.CanonicalDomain != managedDomain {
		return ControlSession{}, ErrManagedDomainMismatch
	}

	result, err = d.createControlSession(
		ctx, queries, identity.ID, identity.Administrator, loginAuthenticationMethod,
		authenticationSourceRevision, accessLifetime, refreshLifetime, now,
	)
	if err != nil {
		return ControlSession{}, err
	}
	result.Identity, err = loadIdentityContext(ctx, queries, identity.ID)
	if err != nil {
		return ControlSession{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ControlSession{}, fmt.Errorf("controlstate: commit builtin authentication: %w", err)
	}
	return result, nil
}

// CreateOIDCControlSession consumes one verified assertion and creates or updates
// its non-administrator local identity before issuing a local control session.
func (d *Database) CreateOIDCControlSession(
	ctx context.Context,
	managedDomain string,
	identity OIDCIdentity,
	accessLifetime time.Duration,
	refreshLifetime time.Duration,
	now time.Time,
) (result ControlSession, retErr error) {
	if !validStateText(managedDomain) || !validStateText(identity.Issuer) || !validStateText(identity.Subject) ||
		!validStateText(identity.DisplayName) || len(identity.Issuer) > 2048 || len(identity.Subject) > 256 ||
		len(identity.DisplayName) > 256 || accessLifetime <= 0 || refreshLifetime < accessLifetime ||
		!identity.AssertionExpiry.After(now) || identity.AssertionDigest == ([32]byte{}) ||
		(identity.NormalizedEmail == "") != !identity.EmailVerified || len(identity.NormalizedEmail) > 320 {
		return ControlSession{}, ErrControlAuthentication
	}
	if err := d.requireOpen(); err != nil {
		return ControlSession{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ControlSession{}, fmt.Errorf("controlstate: begin OIDC authentication: %w", err)
	}
	defer rollback(ctx, tx, "OIDC authentication", &retErr)()
	queries := controlstatedb.New(tx)
	if err := queries.LockIdentityBootstrap(ctx); err != nil {
		return ControlSession{}, fmt.Errorf("controlstate: lock OIDC identity provisioning: %w", err)
	}
	if err := queries.DeleteExpiredOIDCAssertionExchanges(ctx, timestamptz(now)); err != nil {
		return ControlSession{}, fmt.Errorf("controlstate: expire OIDC assertion exchanges: %w", err)
	}
	inserted, err := queries.ConsumeOIDCAssertion(ctx, controlstatedb.ConsumeOIDCAssertionParams{
		AssertionDigest: identity.AssertionDigest[:], ConsumedAt: timestamptz(now),
		ExpiresAt: timestamptz(identity.AssertionExpiry),
	})
	if err != nil {
		return ControlSession{}, fmt.Errorf("controlstate: consume OIDC assertion: %w", err)
	}
	if inserted != 1 {
		return ControlSession{}, ErrOIDCAssertionReplay
	}
	domain, err := ensureManagedDomain(ctx, queries, managedDomain, now)
	if err != nil {
		return ControlSession{}, err
	}
	stored, err := queries.FindOIDCIdentity(ctx, controlstatedb.FindOIDCIdentityParams{
		Issuer: text(identity.Issuer), Subject: text(identity.Subject),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		stored, err = createOIDCIdentity(ctx, queries, domain.ID, identity, now)
	} else if err == nil && stored.DisabledAt.Valid {
		return ControlSession{}, ErrControlAuthentication
	} else if err == nil {
		stored, err = queries.UpdateOIDCIdentity(ctx, controlstatedb.UpdateOIDCIdentityParams{
			DisplayName: identity.DisplayName, NormalizedEmail: nullableText(identity.NormalizedEmail),
			EmailVerified: identity.EmailVerified, UpdatedAt: timestamp(now), ID: stored.ID,
		})
	}
	if err != nil {
		return ControlSession{}, fmt.Errorf("controlstate: ensure OIDC identity: %w", err)
	}
	result, err = d.createControlSession(
		ctx, queries, stored.ID, stored.Administrator, oidcAuthenticationMethod, 1,
		accessLifetime, refreshLifetime, now,
	)
	if err != nil {
		return ControlSession{}, err
	}
	result.Identity, err = loadIdentityContext(ctx, queries, stored.ID)
	if err != nil {
		return ControlSession{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ControlSession{}, fmt.Errorf("controlstate: commit OIDC authentication: %w", err)
	}
	return result, nil
}

func bootstrapBuiltinIdentity(
	ctx context.Context,
	queries *controlstatedb.Queries,
	managedDomain string,
	now time.Time,
) (controlstatedb.ControlIdentity, error) {
	identityID, err := opaqueid.New(opaqueid.IdentityPrefix)
	if err != nil {
		return controlstatedb.ControlIdentity{}, err
	}
	teamID, err := opaqueid.New(opaqueid.TeamPrefix)
	if err != nil {
		return controlstatedb.ControlIdentity{}, err
	}
	membershipID, err := opaqueid.New(opaqueid.MembershipPrefix)
	if err != nil {
		return controlstatedb.ControlIdentity{}, err
	}
	reservationID, err := opaqueid.New(opaqueid.SlugReservationPrefix)
	if err != nil {
		return controlstatedb.ControlIdentity{}, err
	}
	domain, err := ensureManagedDomain(ctx, queries, managedDomain, now)
	if err != nil {
		return controlstatedb.ControlIdentity{}, err
	}

	label, err := availableManagedLabel(ctx, queries, now)
	if err != nil {
		return controlstatedb.ControlIdentity{}, err
	}
	createdAt := timestamp(now)
	if err := queries.CreateIdentity(ctx, controlstatedb.CreateIdentityParams{
		ID: identityID, Kind: "builtin", DisplayName: "Local administrator",
		Administrator: true, CreatedAt: createdAt, UpdatedAt: createdAt,
	}); err != nil {
		return controlstatedb.ControlIdentity{}, fmt.Errorf("controlstate: create builtin identity: %w", err)
	}
	if err := queries.CreatePersonalTeam(ctx, controlstatedb.CreatePersonalTeamParams{
		ID: teamID, DisplayName: "Local administrator", ManagedLabel: label,
		CreatedByIdentityID: identityID, CreatedAt: createdAt,
	}); err != nil {
		return controlstatedb.ControlIdentity{}, fmt.Errorf("controlstate: create builtin personal team: %w", err)
	}
	if err := queries.CreateActiveSlugReservation(ctx, controlstatedb.CreateActiveSlugReservationParams{
		ID: reservationID, TeamID: teamID, MemberSlug: label,
		IdentityID: text(identityID), CreatedAt: createdAt,
	}); err != nil {
		return controlstatedb.ControlIdentity{}, fmt.Errorf("controlstate: reserve builtin member slug: %w", err)
	}
	if err := queries.CreateOwnerMembership(ctx, controlstatedb.CreateOwnerMembershipParams{
		ID: membershipID, TeamID: teamID, IdentityID: identityID,
		SlugReservationID: reservationID, ManagedLabel: label, CreatedAt: createdAt,
	}); err != nil {
		return controlstatedb.ControlIdentity{}, fmt.Errorf("controlstate: create builtin membership: %w", err)
	}
	if err := queries.SetPersonalTeamDefaultDomain(ctx, controlstatedb.SetPersonalTeamDefaultDomainParams{
		DomainID: text(domain.ID), UpdatedAt: createdAt, TeamID: teamID,
	}); err != nil {
		return controlstatedb.ControlIdentity{}, fmt.Errorf("controlstate: set builtin default domain: %w", err)
	}
	return queries.FindBuiltinIdentity(ctx)
}

func createOIDCIdentity(
	ctx context.Context,
	queries *controlstatedb.Queries,
	domainID string,
	identity OIDCIdentity,
	now time.Time,
) (controlstatedb.ControlIdentity, error) {
	identityID, err := opaqueid.New(opaqueid.IdentityPrefix)
	if err != nil {
		return controlstatedb.ControlIdentity{}, err
	}
	teamID, err := opaqueid.New(opaqueid.TeamPrefix)
	if err != nil {
		return controlstatedb.ControlIdentity{}, err
	}
	membershipID, err := opaqueid.New(opaqueid.MembershipPrefix)
	if err != nil {
		return controlstatedb.ControlIdentity{}, err
	}
	reservationID, err := opaqueid.New(opaqueid.SlugReservationPrefix)
	if err != nil {
		return controlstatedb.ControlIdentity{}, err
	}
	label, err := availableManagedLabel(ctx, queries, now)
	if err != nil {
		return controlstatedb.ControlIdentity{}, err
	}
	createdAt := timestamp(now)
	stored, err := queries.CreateOIDCIdentity(ctx, controlstatedb.CreateOIDCIdentityParams{
		ID: identityID, Issuer: text(identity.Issuer), Subject: text(identity.Subject),
		DisplayName: identity.DisplayName, NormalizedEmail: nullableText(identity.NormalizedEmail),
		EmailVerified: identity.EmailVerified, CreatedAt: createdAt,
	})
	if err != nil {
		return controlstatedb.ControlIdentity{}, fmt.Errorf("controlstate: create OIDC identity: %w", err)
	}
	if err := queries.CreatePersonalTeam(ctx, controlstatedb.CreatePersonalTeamParams{
		ID: teamID, DisplayName: identity.DisplayName, ManagedLabel: label,
		CreatedByIdentityID: identityID, CreatedAt: createdAt,
	}); err != nil {
		return controlstatedb.ControlIdentity{}, fmt.Errorf("controlstate: create OIDC personal team: %w", err)
	}
	if err := queries.CreateActiveSlugReservation(ctx, controlstatedb.CreateActiveSlugReservationParams{
		ID: reservationID, TeamID: teamID, MemberSlug: label,
		IdentityID: text(identityID), CreatedAt: createdAt,
	}); err != nil {
		return controlstatedb.ControlIdentity{}, fmt.Errorf("controlstate: reserve OIDC member slug: %w", err)
	}
	if err := queries.CreateOwnerMembership(ctx, controlstatedb.CreateOwnerMembershipParams{
		ID: membershipID, TeamID: teamID, IdentityID: identityID,
		SlugReservationID: reservationID, ManagedLabel: label, CreatedAt: createdAt,
	}); err != nil {
		return controlstatedb.ControlIdentity{}, fmt.Errorf("controlstate: create OIDC membership: %w", err)
	}
	if err := queries.SetPersonalTeamDefaultDomain(ctx, controlstatedb.SetPersonalTeamDefaultDomainParams{
		DomainID: text(domainID), UpdatedAt: createdAt, TeamID: teamID,
	}); err != nil {
		return controlstatedb.ControlIdentity{}, fmt.Errorf("controlstate: set OIDC default domain: %w", err)
	}
	return stored, nil
}

func ensureManagedDomain(
	ctx context.Context,
	queries *controlstatedb.Queries,
	managedDomain string,
	now time.Time,
) (controlstatedb.ControlDomain, error) {
	domain, err := queries.FindManagedDomain(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		domainID, idErr := opaqueid.New(opaqueid.DomainPrefix)
		if idErr != nil {
			return controlstatedb.ControlDomain{}, idErr
		}
		if err := queries.CreateManagedDomain(ctx, controlstatedb.CreateManagedDomainParams{
			ID: domainID, CanonicalDomain: managedDomain, CreatedAt: timestamp(now),
		}); err != nil {
			return controlstatedb.ControlDomain{}, fmt.Errorf("controlstate: create managed deployment domain: %w", err)
		}
		domain.ID, domain.CanonicalDomain = domainID, managedDomain
	} else if err != nil {
		return controlstatedb.ControlDomain{}, fmt.Errorf("controlstate: read managed deployment domain: %w", err)
	} else if domain.CanonicalDomain != managedDomain {
		return controlstatedb.ControlDomain{}, ErrManagedDomainMismatch
	}
	return domain, nil
}

func availableManagedLabel(ctx context.Context, queries *controlstatedb.Queries, now time.Time) (string, error) {
	for range 32 {
		label, err := naming.GeneratedHostnameLabel()
		if err != nil {
			return "", err
		}
		if _, err := queries.ReserveManagedLabel(ctx, controlstatedb.ReserveManagedLabelParams{
			Label: label, CreatedAt: timestamp(now),
		}); err == nil {
			return label, nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("controlstate: reserve managed label: %w", err)
		}
	}
	return "", errors.New("controlstate: managed label selection exhausted")
}

func (d *Database) createControlSession(
	ctx context.Context,
	queries *controlstatedb.Queries,
	identityID string,
	administrator bool,
	authenticationMethod string,
	authenticationSourceRevision int64,
	accessLifetime time.Duration,
	refreshLifetime time.Duration,
	now time.Time,
) (ControlSession, error) {
	sessionID, err := opaqueid.New(opaqueid.ControlSessionPrefix)
	if err != nil {
		return ControlSession{}, err
	}
	accessToken, accessTokenID, accessTokenDigest, err := credentials.NewAccessToken()
	if err != nil {
		return ControlSession{}, err
	}
	refreshToken, refreshTokenID, refreshTokenDigest, err := credentials.NewRefreshToken()
	if err != nil {
		return ControlSession{}, err
	}
	var retrySecret [32]byte
	if _, err := rand.Read(retrySecret[:]); err != nil {
		return ControlSession{}, fmt.Errorf("controlstate: generate retry secret: %w", err)
	}
	retrySecretCiphertext, err := d.sealSecret(controlSessionRetrySecretContext(sessionID), retrySecret[:])
	if err != nil {
		return ControlSession{}, fmt.Errorf("controlstate: encrypt retry secret: %w", err)
	}
	accessExpiresAt := now.Add(accessLifetime).UTC().Truncate(time.Microsecond)
	refreshExpiresAt := now.Add(refreshLifetime).UTC().Truncate(time.Microsecond)
	if err := queries.CreateControlSession(ctx, controlstatedb.CreateControlSessionParams{
		ID: sessionID, IdentityID: identityID, AuthenticationMethod: authenticationMethod,
		AuthenticationSourceRevision: authenticationSourceRevision, Administrator: administrator,
		AccessTokenID: accessTokenID.String(), AccessTokenDigest: accessTokenDigest[:],
		AccessExpiresAt: timestamp(accessExpiresAt), RefreshTokenID: refreshTokenID.String(),
		RefreshTokenDigest: refreshTokenDigest[:], RetrySecretCiphertext: retrySecretCiphertext,
		RetrySecretStorageKeyID: d.storageKey.CurrentID(),
		RefreshExpiresAt:        timestamp(refreshExpiresAt), CreatedAt: timestamp(now),
	}); err != nil {
		return ControlSession{}, fmt.Errorf("controlstate: create control session: %w", err)
	}
	return ControlSession{
		SessionID: sessionID, AccessToken: accessToken, AccessExpiresAt: accessExpiresAt,
		RefreshToken: refreshToken, RefreshExpiresAt: refreshExpiresAt,
	}, nil
}

func (d *Database) AuthenticateAccessToken(
	ctx context.Context,
	token credentials.AccessToken,
	loginSourceRevision int64,
	now time.Time,
) (ControlPrincipal, error) {
	tokenID, digest, err := credentials.ParseAccessToken(token)
	if err != nil {
		return ControlPrincipal{}, ErrControlAuthentication
	}
	row, err := controlstatedb.New(d.pool).GetControlSessionByAccessID(ctx, tokenID.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return ControlPrincipal{}, ErrControlAuthentication
	}
	if err != nil {
		return ControlPrincipal{}, fmt.Errorf("controlstate: authenticate access token: %w", err)
	}
	if !credentials.SecretHashMatches(row.AccessTokenDigest, digest) || !row.AccessExpiresAt.Time.After(now) ||
		row.AuthenticationMethod == loginAuthenticationMethod && row.AuthenticationSourceRevision != loginSourceRevision {
		return ControlPrincipal{}, ErrControlAuthentication
	}
	retrySecret, previous, err := d.openSecret(row.RetrySecretStorageKeyID, controlSessionRetrySecretContext(row.ID), row.RetrySecretCiphertext)
	if err != nil || len(retrySecret) != len((ControlPrincipal{}).RetrySecret) {
		return ControlPrincipal{}, errors.New("controlstate: control session has invalid retry secret")
	}
	if previous {
		rotated, err := d.sealSecret(controlSessionRetrySecretContext(row.ID), retrySecret)
		if err != nil {
			return ControlPrincipal{}, fmt.Errorf("controlstate: re-encrypt control-session retry secret: %w", err)
		}
		if err := controlstatedb.New(d.pool).RotateControlSessionRetrySecret(ctx, controlstatedb.RotateControlSessionRetrySecretParams{
			RetrySecretCiphertext: rotated, RetrySecretStorageKeyID: d.storageKey.CurrentID(), ID: row.ID,
			PreviousKeyID: row.RetrySecretStorageKeyID, PreviousCiphertext: row.RetrySecretCiphertext,
		}); err != nil {
			return ControlPrincipal{}, fmt.Errorf("controlstate: store re-encrypted control-session retry secret: %w", err)
		}
	}
	principal := ControlPrincipal{
		SessionID: row.ID, IdentityID: row.IdentityID, Administrator: row.Administrator,
		RefreshExpiresAt: row.RefreshExpiresAt.Time,
	}
	copy(principal.RetrySecret[:], retrySecret)
	return principal, nil
}

func (d *Database) RefreshControlSession(
	ctx context.Context,
	token credentials.RefreshToken,
	loginSourceRevision int64,
	accessLifetime time.Duration,
	now time.Time,
) (result ControlSession, retErr error) {
	tokenID, digest, err := credentials.ParseRefreshToken(token)
	if err != nil {
		return ControlSession{}, ErrControlAuthentication
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ControlSession{}, fmt.Errorf("controlstate: begin control-session refresh: %w", err)
	}
	defer rollback(ctx, tx, "control-session refresh", &retErr)()
	queries := controlstatedb.New(tx)
	row, err := queries.LockControlSessionByRefreshID(ctx, tokenID.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return ControlSession{}, ErrControlAuthentication
	}
	if err != nil {
		return ControlSession{}, fmt.Errorf("controlstate: lock control session: %w", err)
	}
	if !credentials.SecretHashMatches(row.RefreshTokenDigest, digest) || !row.RefreshExpiresAt.Time.After(now) ||
		row.AuthenticationMethod == loginAuthenticationMethod && row.AuthenticationSourceRevision != loginSourceRevision {
		return ControlSession{}, ErrControlAuthentication
	}
	accessToken, accessTokenID, accessTokenDigest, err := credentials.NewAccessToken()
	if err != nil {
		return ControlSession{}, err
	}
	refreshToken, refreshTokenID, refreshTokenDigest, err := credentials.NewRefreshToken()
	if err != nil {
		return ControlSession{}, err
	}
	accessExpiresAt := now.Add(accessLifetime).UTC().Truncate(time.Microsecond)
	if row.RefreshExpiresAt.Time.Before(accessExpiresAt) {
		accessExpiresAt = row.RefreshExpiresAt.Time
	}
	updated, err := queries.RotateControlSessionCredentials(ctx, controlstatedb.RotateControlSessionCredentialsParams{
		AccessTokenID: accessTokenID.String(), AccessTokenDigest: accessTokenDigest[:],
		AccessExpiresAt: timestamp(accessExpiresAt), RefreshTokenID: refreshTokenID.String(),
		RefreshTokenDigest: refreshTokenDigest[:], RefreshedAt: timestamp(now), ID: row.ID,
	})
	if err != nil {
		return ControlSession{}, fmt.Errorf("controlstate: rotate control session: %w", err)
	}
	if updated != 1 {
		return ControlSession{}, ErrControlAuthentication
	}
	identity, err := loadIdentityContext(ctx, queries, row.IdentityID)
	if err != nil {
		return ControlSession{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ControlSession{}, fmt.Errorf("controlstate: commit control-session refresh: %w", err)
	}
	return ControlSession{
		SessionID: row.ID, AccessToken: accessToken, AccessExpiresAt: accessExpiresAt,
		RefreshToken: refreshToken, RefreshExpiresAt: row.RefreshExpiresAt.Time, Identity: identity,
	}, nil
}

func (d *Database) RevokeControlSession(ctx context.Context, principal ControlPrincipal, now time.Time) error {
	updated, err := controlstatedb.New(d.pool).RevokeControlSession(ctx, controlstatedb.RevokeControlSessionParams{
		RevokedAt: timestamp(now), RevokedBy: text(principal.IdentityID), ID: principal.SessionID,
	})
	if err != nil {
		return fmt.Errorf("controlstate: revoke control session: %w", err)
	}
	if updated != 1 {
		return ErrControlAuthentication
	}
	return nil
}

func (d *Database) IdentityContext(ctx context.Context, identityID string) (IdentityContext, error) {
	return loadIdentityContext(ctx, controlstatedb.New(d.pool), identityID)
}

func loadIdentityContext(ctx context.Context, queries *controlstatedb.Queries, identityID string) (IdentityContext, error) {
	identity, err := queries.GetIdentityContextIdentity(ctx, identityID)
	if errors.Is(err, pgx.ErrNoRows) {
		return IdentityContext{}, ErrControlIdentity
	}
	if err != nil {
		return IdentityContext{}, fmt.Errorf("controlstate: read identity context: %w", err)
	}
	rows, err := queries.ListIdentityMembershipContexts(ctx, identityID)
	if err != nil {
		return IdentityContext{}, fmt.Errorf("controlstate: list identity memberships: %w", err)
	}
	memberships := make([]Membership, len(rows))
	for index, row := range rows {
		memberships[index] = Membership{
			ID: row.ID, TeamID: row.TeamID, IdentityID: row.IdentityID,
			TeamDisplayName: row.TeamDisplayName, TeamKind: TeamKind(row.TeamKind), Role: TeamRole(row.Role),
			MemberSlug: row.MemberSlug, ManagedLabel: row.ManagedLabel, PolicyRevision: row.PolicyRevision,
			CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time,
		}
	}
	return IdentityContext{
		Identity: Identity{
			ID: identity.ID, DisplayName: identity.DisplayName, NormalizedEmail: identity.NormalizedEmail.String,
			EmailVerified: identity.EmailVerified, Administrator: identity.Administrator, CreatedAt: identity.CreatedAt.Time,
		},
		PersonalTeamID: identity.PersonalTeamID,
		Memberships:    memberships,
	}, nil
}

func timestamp(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value.UTC(), Valid: true}
}
