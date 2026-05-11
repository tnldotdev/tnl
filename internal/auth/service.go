package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/state"
)

const (
	DefaultAccessTokenLifetime  = time.Hour
	DefaultRefreshTokenLifetime = 30 * 24 * time.Hour
)

type Grant string

const (
	GrantPublish Grant = "publish"
	GrantAdmin   Grant = "admin"
)

var (
	// ErrUnauthenticated hides why a credential was rejected.
	ErrUnauthenticated = errors.New("auth: unauthenticated")
	localIdentity      = state.Identity{ID: "identity_local", DisplayName: "Local operator"}
)

// IssuedControlSession is returned after login and refresh exchanges.
type IssuedControlSession struct {
	SessionID        string
	AccessToken      credentials.AccessToken
	AccessExpiresAt  time.Time
	RefreshToken     credentials.RefreshToken
	RefreshExpiresAt time.Time
	Grants           []Grant
}

// Principal is the identity, session, and effective grants resolved from an access token.
type Principal struct {
	SessionID string
	Identity  state.Identity
	Grants    []Grant
}

func (p Principal) HasGrant(grant Grant) bool {
	for _, candidate := range p.Grants {
		if candidate == grant {
			return true
		}
	}
	return false
}

type ServiceConfig struct {
	LoginToken         credentials.LoginToken
	LoginTokenRevision int64
	OIDC               OIDCVerifier
	AccessLifetime     time.Duration
	RefreshLifetime    time.Duration
}

// Service implements control-session login, refresh, authentication, and logout.
type Service struct {
	db              *sql.DB
	login           *credentials.LoginVerifier
	loginRevision   int64
	oidc            OIDCVerifier
	now             func() time.Time
	accessLifetime  time.Duration
	refreshLifetime time.Duration
}

// NewService validates authentication configuration and retains only a verifier for the login token.
func NewService(db *sql.DB, config ServiceConfig) (*Service, error) {
	if db == nil {
		return nil, errors.New("auth: nil state database")
	}
	if config.AccessLifetime <= 0 || config.RefreshLifetime <= 0 || config.RefreshLifetime < config.AccessLifetime {
		return nil, errors.New("auth: control session lifetimes are invalid")
	}
	var verifier *credentials.LoginVerifier
	if config.LoginToken != "" {
		parsed, err := credentials.ParseLoginToken(config.LoginToken)
		if err != nil {
			return nil, fmt.Errorf("auth: configure login token: %w", err)
		}
		if config.LoginTokenRevision < 1 {
			return nil, errors.New("auth: login token revision is invalid")
		}
		verifier = &parsed
	}
	if verifier == nil && config.OIDC == nil {
		return nil, errors.New("auth: no authentication method configured")
	}
	return &Service{
		db: db, login: verifier, loginRevision: config.LoginTokenRevision, oidc: config.OIDC, now: time.Now,
		accessLifetime: config.AccessLifetime, refreshLifetime: config.RefreshLifetime,
	}, nil
}

// Exchange starts a control session for the stable local identity.
func (s *Service) Exchange(ctx context.Context, login credentials.LoginToken) (IssuedControlSession, error) {
	if s.login == nil || !s.login.Matches(login) {
		return IssuedControlSession{}, ErrUnauthenticated
	}
	return s.issue(ctx, localIdentity, state.AuthenticationMethodLoginToken, s.loginRevision,
		[]Grant{GrantPublish, GrantAdmin}, nil, time.Time{})
}

// ExchangeOIDC starts a publish-only control session for a verified OIDC identity.
func (s *Service) ExchangeOIDC(ctx context.Context, token string) (IssuedControlSession, error) {
	if s.oidc == nil {
		return IssuedControlSession{}, ErrUnauthenticated
	}
	oidcIdentity, err := s.oidc.Verify(ctx, token)
	if err != nil {
		return IssuedControlSession{}, err
	}
	digest := sha256.Sum256([]byte(oidcIdentity.Issuer + "\x00" + oidcIdentity.Subject))
	identity := state.Identity{ID: "identity_oidc_" + hex.EncodeToString(digest[:])}
	assertionHash := sha256.Sum256([]byte(token))
	issued, err := s.issue(ctx, identity, state.AuthenticationMethodOIDC, 1, []Grant{GrantPublish}, assertionHash[:], oidcIdentity.ExpiresAt)
	if errors.Is(err, state.ErrOIDCAssertionAlreadyExchanged) {
		return IssuedControlSession{}, ErrUnauthenticated
	}
	return issued, err
}

func (s *Service) issue(
	ctx context.Context,
	identity state.Identity,
	method state.AuthenticationMethod,
	sourceRevision int64,
	grants []Grant,
	assertionHash []byte,
	assertionExpiresAt time.Time,
) (IssuedControlSession, error) {
	access, accessID, accessHash, err := credentials.NewAccessToken()
	if err != nil {
		return IssuedControlSession{}, err
	}
	refresh, refreshID, refreshHash, err := credentials.NewRefreshToken()
	if err != nil {
		return IssuedControlSession{}, err
	}
	sessionID, err := newControlSessionID()
	if err != nil {
		return IssuedControlSession{}, err
	}
	issuedAt := s.now().UTC()
	accessExpiresAt := issuedAt.Add(s.accessLifetime)
	refreshExpiresAt := issuedAt.Add(s.refreshLifetime)
	storedGrants := grantStrings(grants)
	err = state.CreateControlSession(ctx, s.db, state.ControlSession{
		ID: sessionID, Identity: identity, AuthenticationMethod: method,
		AuthenticationSourceRevision: sourceRevision, Grants: storedGrants, CreatedAt: issuedAt,
		RefreshExpiresAt: refreshExpiresAt, AccessTokenID: accessID, AccessTokenHash: accessHash,
		AccessExpiresAt: accessExpiresAt, RefreshTokenID: refreshID, RefreshTokenHash: refreshHash,
	}, assertionHash, assertionExpiresAt)
	if err != nil {
		return IssuedControlSession{}, fmt.Errorf("auth: store control session: %w", err)
	}
	return IssuedControlSession{
		SessionID: sessionID, AccessToken: access, AccessExpiresAt: accessExpiresAt,
		RefreshToken: refresh, RefreshExpiresAt: refreshExpiresAt, Grants: append([]Grant(nil), grants...),
	}, nil
}

// Refresh rotates both credentials without changing the session's grants or absolute expiry.
func (s *Service) Refresh(ctx context.Context, previous credentials.RefreshToken) (IssuedControlSession, error) {
	previousID, previousHash, err := credentials.ParseRefreshToken(previous)
	if err != nil {
		return IssuedControlSession{}, ErrUnauthenticated
	}
	access, accessID, accessHash, err := credentials.NewAccessToken()
	if err != nil {
		return IssuedControlSession{}, err
	}
	refresh, refreshID, refreshHash, err := credentials.NewRefreshToken()
	if err != nil {
		return IssuedControlSession{}, err
	}
	now := s.now().UTC()
	rotation, err := state.RotateControlSession(
		ctx, s.db, previousID, previousHash, accessID, accessHash, now.Add(s.accessLifetime),
		refreshID, refreshHash, now,
	)
	if errors.Is(err, credentials.ErrInvalidRefreshToken) {
		return IssuedControlSession{}, ErrUnauthenticated
	}
	if err != nil {
		return IssuedControlSession{}, fmt.Errorf("auth: refresh control session: %w", err)
	}
	return IssuedControlSession{
		SessionID: rotation.SessionID, AccessToken: access, AccessExpiresAt: rotation.AccessExpiresAt,
		RefreshToken: refresh, RefreshExpiresAt: rotation.RefreshExpiresAt, Grants: grantsFromStrings(rotation.Grants),
	}, nil
}

// Authenticate resolves a current access token to its identity, session, and effective grants.
func (s *Service) Authenticate(ctx context.Context, token credentials.AccessToken) (Principal, error) {
	credentialID, hash, err := credentials.ParseAccessToken(token)
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	authenticated, err := state.AuthenticateControlSession(ctx, s.db, credentialID, hash, s.now())
	if errors.Is(err, credentials.ErrInvalidAccessToken) {
		return Principal{}, ErrUnauthenticated
	}
	if err != nil {
		return Principal{}, fmt.Errorf("auth: authenticate control session: %w", err)
	}
	return Principal{
		SessionID: authenticated.SessionID, Identity: authenticated.Identity,
		Grants: grantsFromStrings(authenticated.Grants),
	}, nil
}

// Logout revokes the authenticated control session.
func (s *Service) Logout(ctx context.Context, principal Principal) error {
	err := state.RevokeControlSession(ctx, s.db, principal.Identity.ID, principal.SessionID, s.now())
	if errors.Is(err, state.ErrControlSessionNotFound) {
		return ErrUnauthenticated
	}
	if err != nil {
		return fmt.Errorf("auth: logout control session: %w", err)
	}
	return nil
}

func grantStrings(grants []Grant) []string {
	result := make([]string, len(grants))
	for index, grant := range grants {
		result[index] = string(grant)
	}
	return result
}

func grantsFromStrings(grants []string) []Grant {
	result := make([]Grant, len(grants))
	for index, grant := range grants {
		result[index] = Grant(grant)
	}
	return result
}

func newControlSessionID() (string, error) {
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", fmt.Errorf("auth: generate control session ID: %w", err)
	}
	return "control_session_" + hex.EncodeToString(material[:]), nil
}
