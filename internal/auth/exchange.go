// Package auth implements standalone core authentication flows.
package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/state"
)

const AccessTokenLifetime = 30 * 24 * time.Hour

var (
	// ErrUnauthenticated hides why a bootstrap credential was rejected.
	ErrUnauthenticated = errors.New("auth: unauthenticated")
	localPrincipal     = state.Principal{ID: "principal_local", DisplayName: "Local operator"}
)

// IssuedAccessToken is the successful result of a bootstrap exchange.
type IssuedAccessToken struct {
	Token        credentials.AccessToken
	CredentialID credentials.CredentialID
	ExpiresAt    time.Time
}

// TokenExchange exchanges one configured deployment credential for access credentials.
type TokenExchange struct {
	db        *sql.DB
	bootstrap credentials.BootstrapVerifier
	now       func() time.Time
}

// NewTokenExchange parses bootstrap once so the service does not retain the raw token.
func NewTokenExchange(db *sql.DB, bootstrap credentials.BootstrapToken) (*TokenExchange, error) {
	if db == nil {
		return nil, errors.New("auth: nil state database")
	}
	verifier, err := credentials.ParseBootstrapToken(bootstrap)
	if err != nil {
		return nil, fmt.Errorf("auth: configure bootstrap token: %w", err)
	}
	return &TokenExchange{db: db, bootstrap: verifier, now: time.Now}, nil
}

// Exchange issues a new access credential for the stable local principal.
func (e *TokenExchange) Exchange(
	ctx context.Context,
	bootstrap credentials.BootstrapToken,
) (IssuedAccessToken, error) {
	if !e.bootstrap.Matches(bootstrap) {
		return IssuedAccessToken{}, ErrUnauthenticated
	}
	token, credentialID, hash, err := credentials.NewAccessToken()
	if err != nil {
		return IssuedAccessToken{}, err
	}
	issuedAt := time.Unix(e.now().Unix(), 0).UTC()
	expiresAt := issuedAt.Add(AccessTokenLifetime)
	if err := state.CreateAccessCredential(
		ctx, e.db, localPrincipal, credentialID, hash, issuedAt, expiresAt,
	); err != nil {
		return IssuedAccessToken{}, fmt.Errorf("auth: store access credential: %w", err)
	}
	return IssuedAccessToken{Token: token, CredentialID: credentialID, ExpiresAt: expiresAt}, nil
}
