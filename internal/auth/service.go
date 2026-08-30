package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/state"
)

const AccessTokenLifetime = 30 * 24 * time.Hour

var (
	// ErrUnauthenticated hides why a credential was rejected.
	ErrUnauthenticated = errors.New("auth: unauthenticated")
	// ErrCredentialNotFound hides whether a credential exists or belongs to another principal.
	ErrCredentialNotFound = errors.New("auth: credential not found")
	localPrincipal        = state.Principal{ID: "principal_local", DisplayName: "Local operator"}
)

// IssuedAccessToken is the successful result of a login exchange.
type IssuedAccessToken struct {
	Token        credentials.AccessToken
	CredentialID credentials.CredentialID
	ExpiresAt    time.Time
}

// Service implements standalone login and access credential flows.
type Service struct {
	db    *sql.DB
	login *credentials.LoginVerifier
	oidc  OIDCVerifier
	now   func() time.Time
}

// NewService parses login once so the service does not retain the raw token.
func NewService(db *sql.DB, login credentials.LoginToken) (*Service, error) {
	return NewServiceWithOIDC(db, login, nil)
}

func NewServiceWithOIDC(
	db *sql.DB,
	login credentials.LoginToken,
	oidc OIDCVerifier,
) (*Service, error) {
	if db == nil {
		return nil, errors.New("auth: nil state database")
	}
	var verifier *credentials.LoginVerifier
	if login != "" {
		parsed, err := credentials.ParseLoginToken(login)
		if err != nil {
			return nil, fmt.Errorf("auth: configure login token: %w", err)
		}
		verifier = &parsed
	}
	if verifier == nil && oidc == nil {
		return nil, errors.New("auth: no authentication method configured")
	}
	return &Service{db: db, login: verifier, oidc: oidc, now: time.Now}, nil
}

// Exchange issues a new access credential for the stable local principal.
func (s *Service) Exchange(
	ctx context.Context,
	login credentials.LoginToken,
) (IssuedAccessToken, error) {
	if s.login == nil || !s.login.Matches(login) {
		return IssuedAccessToken{}, ErrUnauthenticated
	}
	return s.issue(ctx, localPrincipal, s.now().Add(AccessTokenLifetime), nil)
}

func (s *Service) ExchangeOIDC(ctx context.Context, token string) (IssuedAccessToken, error) {
	if s.oidc == nil {
		return IssuedAccessToken{}, ErrUnauthenticated
	}
	identity, err := s.oidc.Verify(ctx, token)
	if err != nil {
		return IssuedAccessToken{}, err
	}
	digest := sha256.Sum256([]byte(identity.Issuer + "\x00" + identity.Subject))
	principal := state.Principal{
		ID: "principal_oidc_" + hex.EncodeToString(digest[:]),
	}
	tokenHash := sha256.Sum256([]byte(token))
	issued, err := s.issueOIDC(ctx, principal, s.now().Add(AccessTokenLifetime), tokenHash[:], identity.ExpiresAt)
	if errors.Is(err, state.ErrOIDCAssertionAlreadyExchanged) {
		return IssuedAccessToken{}, ErrUnauthenticated
	}
	return issued, err
}

func (s *Service) issue(
	ctx context.Context,
	principal state.Principal,
	expiresAt time.Time,
	assertionHash []byte,
) (IssuedAccessToken, error) {
	return s.issueOIDC(ctx, principal, expiresAt, assertionHash, time.Time{})
}

func (s *Service) issueOIDC(
	ctx context.Context,
	principal state.Principal,
	expiresAt time.Time,
	assertionHash []byte,
	assertionExpiresAt time.Time,
) (IssuedAccessToken, error) {
	token, credentialID, hash, err := credentials.NewAccessToken()
	if err != nil {
		return IssuedAccessToken{}, err
	}
	issuedAt := time.Unix(s.now().Unix(), 0).UTC()
	expiresAt = time.Unix(expiresAt.Unix(), 0).UTC()
	if !expiresAt.After(issuedAt) {
		return IssuedAccessToken{}, ErrUnauthenticated
	}
	var storeErr error
	if assertionHash == nil {
		storeErr = state.CreateAccessCredential(ctx, s.db, principal, credentialID, hash, issuedAt, expiresAt)
	} else {
		storeErr = state.CreateOIDCAccessCredential(
			ctx, s.db, principal, credentialID, hash, issuedAt, expiresAt, assertionHash, assertionExpiresAt,
		)
	}
	if storeErr != nil {
		return IssuedAccessToken{}, fmt.Errorf("auth: store access credential: %w", storeErr)
	}
	return IssuedAccessToken{Token: token, CredentialID: credentialID, ExpiresAt: expiresAt}, nil
}

// Authenticate resolves a valid access token to its principal.
func (s *Service) Authenticate(
	ctx context.Context,
	token credentials.AccessToken,
) (state.Principal, error) {
	credentialID, hash, err := credentials.ParseAccessToken(token)
	if err != nil {
		return state.Principal{}, ErrUnauthenticated
	}
	principal, err := state.AuthenticateAccessCredential(ctx, s.db, credentialID, hash, s.now())
	if errors.Is(err, credentials.ErrInvalidAccessToken) {
		return state.Principal{}, ErrUnauthenticated
	}
	if err != nil {
		return state.Principal{}, fmt.Errorf("auth: authenticate access credential: %w", err)
	}
	return principal, nil
}

// Revoke revokes an access credential owned by principal.
func (s *Service) Revoke(
	ctx context.Context,
	principal state.Principal,
	credentialID credentials.CredentialID,
) error {
	err := state.RevokeAccessCredential(ctx, s.db, principal.ID, credentialID, s.now())
	if errors.Is(err, state.ErrAccessCredentialNotFound) {
		return ErrCredentialNotFound
	}
	if err != nil {
		return fmt.Errorf("auth: revoke access credential: %w", err)
	}
	return nil
}
