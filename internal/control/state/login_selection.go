package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func (d *Database) ResolveLoginTeam(ctx context.Context, name string) (string, error) {
	if name == "" {
		return "", nil
	}
	if !validStateText(name) || len(name) > 128 {
		return "", ErrAuthorityInvalid
	}
	id, err := controlstatedb.New(d.pool).ResolveLoginTeam(ctx, name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrTeamNotFound
	}
	return id, err
}

func (d *Database) PrepareCompanyBrowser(ctx context.Context, team, issuer, client, redirect string, now time.Time) (*CompanyLoginIntent, error) {
	if team == "" {
		return nil, nil
	}
	q := controlstatedb.New(d.pool)
	required, err := q.LoginTeamRequiresCompany(ctx, team)
	if err != nil {
		return nil, err
	}
	if !required {
		return nil, nil
	}
	intent, err := d.CreateCompanyLoginIntent(ctx, team, issuer, client, redirect, now)
	return &intent, err
}

// reauthentication proves possession of an unexpired control refresh credential,
// without rotating it or extending any company source's authentication time.
func (q loginReauthentication) check(ctx context.Context, token string, now time.Time) (string, string, error) {
	id, digest, err := credentials.ParseRefreshToken(credentials.RefreshToken(token))
	if err != nil {
		return "", "", ErrControlAuthentication
	}
	s, err := q.queries.LockControlSessionByRefreshID(ctx, id.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrControlAuthentication
	}
	if err != nil {
		return "", "", err
	}
	if !credentials.SecretHashMatches(s.RefreshTokenDigest, digest) || !s.RefreshExpiresAt.Time.After(now) {
		return "", "", ErrControlAuthentication
	}
	return s.ID, s.IdentityID, nil
}

type loginReauthentication struct{ queries *controlstatedb.Queries }
