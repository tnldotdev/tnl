package state

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

const MaxActiveControlSessions = 10

type AuthenticationMethod string

const (
	AuthenticationMethodLoginToken AuthenticationMethod = "login_token"
	AuthenticationMethodOIDC       AuthenticationMethod = "oidc"
)

var (
	ErrControlSessionNotFound        = errors.New("state: control session not found")
	ErrOIDCAssertionAlreadyExchanged = errors.New("state: OIDC assertion already exchanged")
)

// Identity is a tnl server identity.
type Identity struct {
	ID          string
	DisplayName string
	Email       string
}

// ControlSession contains the durable, non-secret and hashed state for a control session.
type ControlSession struct {
	ID                           string
	Identity                     Identity
	AuthenticationMethod         AuthenticationMethod
	AuthenticationSourceRevision int64
	Grants                       []string
	CreatedAt                    time.Time
	RefreshExpiresAt             time.Time
	AccessTokenID                credentials.CredentialID
	AccessTokenHash              credentials.SecretHash
	AccessExpiresAt              time.Time
	RefreshTokenID               credentials.CredentialID
	RefreshTokenHash             credentials.SecretHash
}

// AuthenticatedControlSession is the identity and authorization resolved from an access token.
type AuthenticatedControlSession struct {
	SessionID string
	Identity  Identity
	Grants    []string
}

// ControlSessionRotation is the durable state retained across credential rotation.
type ControlSessionRotation struct {
	SessionID        string
	IdentityID       string
	Grants           []string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}

// CreateControlSession ensures the identity and stores a new session atomically.
func CreateControlSession(
	ctx context.Context,
	db *sql.DB,
	session ControlSession,
	assertionHash []byte,
	assertionExpiresAt time.Time,
) error {
	grants, err := encodeGrants(session.Grants)
	if err != nil || strings.TrimSpace(session.Identity.ID) == "" || !validControlSessionID(session.ID) ||
		session.AuthenticationSourceRevision < 1 || !validAuthenticationMethod(session.AuthenticationMethod) ||
		session.AccessTokenID == "" || session.RefreshTokenID == "" ||
		!session.AccessExpiresAt.After(session.CreatedAt) || session.AccessExpiresAt.After(session.RefreshExpiresAt) {
		return errors.New("state: control session is invalid")
	}
	if assertionHash != nil && (len(assertionHash) != 32 || !assertionExpiresAt.After(session.CreatedAt)) {
		return errors.New("state: OIDC assertion metadata is invalid")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: begin control session transaction: %w", err)
	}
	defer tx.Rollback()
	queries := statedb.New(tx)
	if err := queries.UpsertIdentity(ctx, statedb.UpsertIdentityParams{
		IdentityID: session.Identity.ID, DisplayName: session.Identity.DisplayName,
		Email: session.Identity.Email, CreatedAt: session.CreatedAt.UnixNano(),
	}); err != nil {
		return fmt.Errorf("state: ensure identity: %w", err)
	}
	if assertionHash != nil {
		if err := queries.DeleteExpiredOIDCAssertions(ctx, session.CreatedAt.UnixNano()); err != nil {
			return fmt.Errorf("state: expire OIDC assertion exchanges: %w", err)
		}
		inserted, err := queries.ConsumeOIDCAssertion(ctx, statedb.ConsumeOIDCAssertionParams{
			AssertionHash: assertionHash, ConsumedAt: session.CreatedAt.UnixNano(),
			ExpiresAt: assertionExpiresAt.UnixNano(),
		})
		if err != nil {
			return fmt.Errorf("state: consume OIDC assertion: %w", err)
		}
		if inserted == 0 {
			return ErrOIDCAssertionAlreadyExchanged
		}
	}
	if err := queries.InsertControlSession(ctx, statedb.InsertControlSessionParams{
		SessionID: session.ID, IdentityID: session.Identity.ID,
		AuthenticationMethod:         string(session.AuthenticationMethod),
		AuthenticationSourceRevision: session.AuthenticationSourceRevision,
		Grants:                       grants, CreatedAt: session.CreatedAt.UnixNano(),
		RefreshExpiresAt: session.RefreshExpiresAt.UnixNano(),
		AccessTokenID:    session.AccessTokenID.String(), AccessTokenHash: session.AccessTokenHash[:],
		AccessExpiresAt: session.AccessExpiresAt.UnixNano(),
		RefreshTokenID:  session.RefreshTokenID.String(), RefreshTokenHash: session.RefreshTokenHash[:],
	}); err != nil {
		return fmt.Errorf("state: create control session: %w", err)
	}
	if _, err := queries.RevokeExpiredControlSessions(ctx, session.CreatedAt.UnixNano()); err != nil {
		return fmt.Errorf("state: revoke expired control sessions: %w", err)
	}
	if _, err := queries.RevokeExcessControlSessions(ctx, statedb.RevokeExcessControlSessionsParams{
		RevokedAt: session.CreatedAt.UnixNano(), IdentityID: session.Identity.ID,
		MaxActiveSessions: MaxActiveControlSessions,
	}); err != nil {
		return fmt.Errorf("state: cap active control sessions: %w", err)
	}
	if err := queries.DeleteInactiveControlSessionRefreshTokens(ctx, session.CreatedAt.UnixNano()); err != nil {
		return fmt.Errorf("state: prune inactive control session refresh credentials: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: commit control session transaction: %w", err)
	}
	return nil
}

// AuthenticateControlSession resolves a current access token to its session, identity, and grants.
func AuthenticateControlSession(
	ctx context.Context,
	db *sql.DB,
	credentialID credentials.CredentialID,
	candidate credentials.SecretHash,
	now time.Time,
) (AuthenticatedControlSession, error) {
	stored, err := statedb.New(db).GetControlSessionByAccessToken(ctx, credentialID.String())
	if errors.Is(err, sql.ErrNoRows) {
		return AuthenticatedControlSession{}, credentials.ErrInvalidAccessToken
	}
	if err != nil {
		return AuthenticatedControlSession{}, fmt.Errorf("state: read control session: %w", err)
	}
	if !credentials.SecretHashMatches(stored.AccessTokenHash, candidate) || stored.AccessTokenRevokedAt.Valid ||
		stored.RevokedAt.Valid || now.UnixNano() >= stored.AccessExpiresAt {
		return AuthenticatedControlSession{}, credentials.ErrInvalidAccessToken
	}
	grants, err := decodeGrants(stored.Grants)
	if err != nil {
		return AuthenticatedControlSession{}, err
	}
	return AuthenticatedControlSession{
		SessionID: stored.SessionID,
		Identity:  Identity{ID: stored.IdentityID, DisplayName: stored.DisplayName, Email: stored.Email},
		Grants:    grants,
	}, nil
}

// RotateControlSession replaces both credentials while preserving the absolute refresh expiry and grants.
func RotateControlSession(
	ctx context.Context,
	db *sql.DB,
	previousRefreshID credentials.CredentialID,
	candidate credentials.SecretHash,
	accessID credentials.CredentialID,
	accessHash credentials.SecretHash,
	accessExpiresAt time.Time,
	refreshID credentials.CredentialID,
	refreshHash credentials.SecretHash,
	now time.Time,
) (ControlSessionRotation, error) {
	if previousRefreshID == "" || accessID == "" || refreshID == "" || !accessExpiresAt.After(now) {
		return ControlSessionRotation{}, credentials.ErrInvalidRefreshToken
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ControlSessionRotation{}, fmt.Errorf("state: begin refresh transaction: %w", err)
	}
	defer tx.Rollback()
	queries := statedb.New(tx)
	stored, err := queries.GetControlSessionByRefreshToken(ctx, previousRefreshID.String())
	if errors.Is(err, sql.ErrNoRows) {
		return detectRefreshReuse(ctx, tx, queries, previousRefreshID, candidate, now)
	}
	if err != nil {
		return ControlSessionRotation{}, fmt.Errorf("state: read refresh credential: %w", err)
	}
	if !credentials.SecretHashMatches(stored.RefreshTokenHash, candidate) {
		return ControlSessionRotation{}, credentials.ErrInvalidRefreshToken
	}
	if stored.RefreshTokenRevokedAt.Valid || stored.RevokedAt.Valid || now.UnixNano() >= stored.RefreshExpiresAt {
		if !stored.RevokedAt.Valid {
			if _, err := queries.RevokeControlSession(ctx, statedb.RevokeControlSessionParams{
				RevokedAt: now.UnixNano(), SessionID: stored.SessionID,
			}); err != nil {
				return ControlSessionRotation{}, fmt.Errorf("state: revoke inactive control session: %w", err)
			}
		}
		if err := queries.DeleteInactiveControlSessionRefreshTokens(ctx, now.UnixNano()); err != nil {
			return ControlSessionRotation{}, fmt.Errorf("state: prune inactive control session refresh credentials: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return ControlSessionRotation{}, fmt.Errorf("state: commit inactive control session cleanup: %w", err)
		}
		return ControlSessionRotation{}, credentials.ErrInvalidRefreshToken
	}
	if accessExpiresAt.UnixNano() > stored.RefreshExpiresAt {
		accessExpiresAt = time.Unix(0, stored.RefreshExpiresAt).UTC()
	}
	if err := queries.InsertReplacedControlSessionRefreshToken(ctx, statedb.InsertReplacedControlSessionRefreshTokenParams{
		RefreshTokenID: previousRefreshID.String(), SessionID: stored.SessionID,
		TokenHash: stored.RefreshTokenHash, ReplacedAt: now.UnixNano(),
	}); err != nil {
		return ControlSessionRotation{}, fmt.Errorf("state: retain replaced refresh credential: %w", err)
	}
	updated, err := queries.RotateControlSessionTokens(ctx, statedb.RotateControlSessionTokensParams{
		AccessTokenID: accessID.String(), AccessTokenHash: accessHash[:], AccessExpiresAt: accessExpiresAt.UnixNano(),
		RefreshTokenID: refreshID.String(), RefreshTokenHash: refreshHash[:], SessionID: stored.SessionID,
		PreviousRefreshTokenID: previousRefreshID.String(),
	})
	if err != nil {
		return ControlSessionRotation{}, fmt.Errorf("state: rotate control session credentials: %w", err)
	}
	if updated != 1 {
		return ControlSessionRotation{}, credentials.ErrInvalidRefreshToken
	}
	if err := queries.DeleteInactiveControlSessionRefreshTokens(ctx, now.UnixNano()); err != nil {
		return ControlSessionRotation{}, fmt.Errorf("state: prune inactive control session refresh credentials: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ControlSessionRotation{}, fmt.Errorf("state: commit refresh transaction: %w", err)
	}
	grants, err := decodeGrants(stored.Grants)
	if err != nil {
		return ControlSessionRotation{}, err
	}
	return ControlSessionRotation{
		SessionID: stored.SessionID, IdentityID: stored.IdentityID, Grants: grants,
		AccessExpiresAt:  accessExpiresAt.UTC(),
		RefreshExpiresAt: time.Unix(0, stored.RefreshExpiresAt).UTC(),
	}, nil
}

func detectRefreshReuse(
	ctx context.Context,
	tx *sql.Tx,
	queries *statedb.Queries,
	credentialID credentials.CredentialID,
	candidate credentials.SecretHash,
	now time.Time,
) (ControlSessionRotation, error) {
	replaced, err := queries.GetReplacedControlSessionRefreshToken(ctx, credentialID.String())
	if errors.Is(err, sql.ErrNoRows) || err == nil && subtle.ConstantTimeCompare(replaced.TokenHash, candidate[:]) != 1 {
		return ControlSessionRotation{}, credentials.ErrInvalidRefreshToken
	}
	if err != nil {
		return ControlSessionRotation{}, fmt.Errorf("state: read replaced refresh credential: %w", err)
	}
	if !replaced.RevokedAt.Valid {
		if _, err := queries.RevokeControlSession(ctx, statedb.RevokeControlSessionParams{
			RevokedAt: now.UnixNano(), SessionID: replaced.SessionID,
		}); err != nil {
			return ControlSessionRotation{}, fmt.Errorf("state: revoke replayed control session: %w", err)
		}
	}
	if err := queries.DeleteInactiveControlSessionRefreshTokens(ctx, now.UnixNano()); err != nil {
		return ControlSessionRotation{}, fmt.Errorf("state: prune replayed control session refresh credentials: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ControlSessionRotation{}, fmt.Errorf("state: commit replay revocation: %w", err)
	}
	return ControlSessionRotation{}, credentials.ErrInvalidRefreshToken
}

// RevokeControlSession revokes a session owned by identityID.
func RevokeControlSession(ctx context.Context, db *sql.DB, identityID, sessionID string, revokedAt time.Time) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: begin control session revocation transaction: %w", err)
	}
	defer tx.Rollback()
	queries := statedb.New(tx)
	updated, err := queries.RevokeOwnedControlSession(ctx, statedb.RevokeOwnedControlSessionParams{
		RevokedAt: revokedAt.UnixNano(), SessionID: sessionID, IdentityID: identityID,
	})
	if err != nil {
		return fmt.Errorf("state: revoke control session: %w", err)
	}
	if updated == 0 {
		return ErrControlSessionNotFound
	}
	if err := queries.DeleteInactiveControlSessionRefreshTokens(ctx, revokedAt.UnixNano()); err != nil {
		return fmt.Errorf("state: prune revoked control session refresh credentials: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: commit control session revocation: %w", err)
	}
	return nil
}

func encodeGrants(grants []string) (string, error) {
	publish, admin := false, false
	for _, grant := range grants {
		switch grant {
		case "publish":
			if publish {
				return "", errors.New("state: control session grants are invalid")
			}
			publish = true
		case "admin":
			if admin {
				return "", errors.New("state: control session grants are invalid")
			}
			admin = true
		default:
			return "", errors.New("state: control session grants are invalid")
		}
	}
	if publish && admin {
		return "publish,admin", nil
	}
	if publish {
		return "publish", nil
	}
	return "", errors.New("state: control session grants are invalid")
}

func decodeGrants(grants string) ([]string, error) {
	switch grants {
	case "publish":
		return []string{"publish"}, nil
	case "publish,admin":
		return []string{"publish", "admin"}, nil
	default:
		return nil, errors.New("state: persisted control session grants are invalid")
	}
}

func validAuthenticationMethod(method AuthenticationMethod) bool {
	return method == AuthenticationMethodLoginToken || method == AuthenticationMethodOIDC
}

func validControlSessionID(value string) bool {
	return opaqueid.Valid(value, "control_session_")
}
