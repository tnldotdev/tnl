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

var (
	ErrControlAuthentication = errors.New("controlstate: invalid control credential")
	ErrControlIdentity       = errors.New("controlstate: identity is unavailable")
	ErrManagedDomainMismatch = errors.New("controlstate: configured managed deployment domain changed")
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
	TeamKind        string
	Role            string
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
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			retErr = errors.Join(retErr, fmt.Errorf("controlstate: roll back builtin authentication: %w", err))
		}
	}()
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

	result, err = createControlSession(
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

func bootstrapBuiltinIdentity(
	ctx context.Context,
	queries *controlstatedb.Queries,
	managedDomain string,
	now time.Time,
) (controlstatedb.ControlIdentity, error) {
	identityID, err := opaqueid.New("identity_")
	if err != nil {
		return controlstatedb.ControlIdentity{}, err
	}
	teamID, err := opaqueid.New("team_")
	if err != nil {
		return controlstatedb.ControlIdentity{}, err
	}
	membershipID, err := opaqueid.New("membership_")
	if err != nil {
		return controlstatedb.ControlIdentity{}, err
	}
	reservationID, err := opaqueid.New("slug_reservation_")
	if err != nil {
		return controlstatedb.ControlIdentity{}, err
	}
	domain, err := queries.FindManagedDomain(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		domainID, idErr := opaqueid.New("domain_")
		if idErr != nil {
			return controlstatedb.ControlIdentity{}, idErr
		}
		if err := queries.CreateManagedDomain(ctx, controlstatedb.CreateManagedDomainParams{
			ID: domainID, CanonicalDomain: managedDomain, CreatedAt: timestamp(now),
		}); err != nil {
			return controlstatedb.ControlIdentity{}, fmt.Errorf("controlstate: create managed deployment domain: %w", err)
		}
		domain.ID, domain.CanonicalDomain = domainID, managedDomain
	} else if err != nil {
		return controlstatedb.ControlIdentity{}, fmt.Errorf("controlstate: read managed deployment domain: %w", err)
	} else if domain.CanonicalDomain != managedDomain {
		return controlstatedb.ControlIdentity{}, ErrManagedDomainMismatch
	}

	label, err := availableManagedLabel(ctx, queries)
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

func availableManagedLabel(ctx context.Context, queries *controlstatedb.Queries) (string, error) {
	for range 32 {
		label, err := naming.GeneratedHostnameLabel()
		if err != nil {
			return "", err
		}
		exists, err := queries.ManagedLabelExists(ctx, label)
		if err != nil {
			return "", fmt.Errorf("controlstate: check managed label: %w", err)
		}
		if !exists {
			return label, nil
		}
	}
	return "", errors.New("controlstate: managed label selection exhausted")
}

func createControlSession(
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
	sessionID, err := opaqueid.New("control_session_")
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
	accessExpiresAt := now.Add(accessLifetime)
	refreshExpiresAt := now.Add(refreshLifetime)
	if err := queries.CreateControlSession(ctx, controlstatedb.CreateControlSessionParams{
		ID: sessionID, IdentityID: identityID, AuthenticationMethod: authenticationMethod,
		AuthenticationSourceRevision: authenticationSourceRevision, Administrator: administrator,
		AccessTokenID: accessTokenID.String(), AccessTokenDigest: accessTokenDigest[:],
		AccessExpiresAt: timestamp(accessExpiresAt), RefreshTokenID: refreshTokenID.String(),
		RefreshTokenDigest: refreshTokenDigest[:], RetrySecret: retrySecret[:],
		RefreshExpiresAt: timestamp(refreshExpiresAt), CreatedAt: timestamp(now),
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
	if len(row.RetrySecret) != len((ControlPrincipal{}).RetrySecret) {
		return ControlPrincipal{}, errors.New("controlstate: control session has invalid retry secret")
	}
	principal := ControlPrincipal{
		SessionID: row.ID, IdentityID: row.IdentityID, Administrator: row.Administrator,
		RefreshExpiresAt: row.RefreshExpiresAt.Time,
	}
	copy(principal.RetrySecret[:], row.RetrySecret)
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
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			retErr = errors.Join(retErr, fmt.Errorf("controlstate: roll back control-session refresh: %w", err))
		}
	}()
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
	accessExpiresAt := now.Add(accessLifetime)
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
			TeamDisplayName: row.TeamDisplayName, TeamKind: row.TeamKind, Role: row.Role,
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
