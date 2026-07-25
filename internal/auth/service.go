package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/state"
)

const AccessTokenLifetime = 30 * 24 * time.Hour

var (
	// ErrUnauthenticated hides why a credential was rejected.
	ErrUnauthenticated = errors.New("auth: unauthenticated")
	// ErrCredentialNotFound hides whether a credential exists or belongs to another principal.
	ErrCredentialNotFound = errors.New("auth: credential not found")
	localPrincipal        = state.Principal{ID: "principal_local", DisplayName: "Local operator"}
)

// IssuedAccessToken is the successful result of a bootstrap exchange.
type IssuedAccessToken struct {
	Token        credentials.AccessToken
	CredentialID credentials.CredentialID
	ExpiresAt    time.Time
}

// Service implements standalone bootstrap and access credential flows.
type Service struct {
	db        *sql.DB
	bootstrap *credentials.BootstrapVerifier
	external  ExternalVerifier
	now       func() time.Time
}

// NewService parses bootstrap once so the service does not retain the raw token.
func NewService(db *sql.DB, bootstrap credentials.BootstrapToken) (*Service, error) {
	return NewServiceWithExternal(db, bootstrap, nil)
}

func NewServiceWithExternal(
	db *sql.DB,
	bootstrap credentials.BootstrapToken,
	external ExternalVerifier,
) (*Service, error) {
	if db == nil {
		return nil, errors.New("auth: nil state database")
	}
	var verifier *credentials.BootstrapVerifier
	if bootstrap != "" {
		parsed, err := credentials.ParseBootstrapToken(bootstrap)
		if err != nil {
			return nil, fmt.Errorf("auth: configure bootstrap token: %w", err)
		}
		verifier = &parsed
	}
	if verifier == nil && external == nil {
		return nil, errors.New("auth: no authentication method configured")
	}
	return &Service{db: db, bootstrap: verifier, external: external, now: time.Now}, nil
}

// Exchange issues a new access credential for the stable local principal.
func (s *Service) Exchange(
	ctx context.Context,
	bootstrap credentials.BootstrapToken,
) (IssuedAccessToken, error) {
	if s.bootstrap == nil || !s.bootstrap.Matches(bootstrap) {
		return IssuedAccessToken{}, ErrUnauthenticated
	}
	return s.issue(ctx, localPrincipal, s.now().Add(AccessTokenLifetime), nil)
}

func (s *Service) ExchangeExternal(ctx context.Context, token string) (IssuedAccessToken, error) {
	if s.external == nil {
		return IssuedAccessToken{}, ErrUnauthenticated
	}
	identity, err := s.external.Verify(ctx, token)
	if err != nil {
		return IssuedAccessToken{}, err
	}
	digest := sha256.Sum256([]byte(identity.Issuer + "\x00" + identity.Subject))
	principal := state.Principal{
		ID: "principal_external_" + hex.EncodeToString(digest[:]),
	}
	expiresAt := identity.ExpiresAt
	if limit := s.now().Add(AccessTokenLifetime); limit.Before(expiresAt) {
		expiresAt = limit
	}
	tokenHash := sha256.Sum256([]byte(token))
	issued, err := s.issue(ctx, principal, expiresAt, tokenHash[:])
	if errors.Is(err, state.ErrExternalTokenAlreadyExchanged) {
		return IssuedAccessToken{}, ErrUnauthenticated
	}
	return issued, err
}

func (s *Service) issue(
	ctx context.Context,
	principal state.Principal,
	expiresAt time.Time,
	externalTokenHash []byte,
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
	if externalTokenHash == nil {
		storeErr = state.CreateAccessCredential(ctx, s.db, principal, credentialID, hash, issuedAt, expiresAt)
	} else {
		storeErr = state.CreateExternalAccessCredential(
			ctx, s.db, principal, credentialID, hash, issuedAt, expiresAt, externalTokenHash,
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
