package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

var (
	// ErrAccessCredentialNotFound indicates that no credential matched the requested owner and ID.
	ErrAccessCredentialNotFound = errors.New("state: access credential not found")
	// ErrOIDCAssertionAlreadyExchanged indicates that an ID token was already consumed.
	ErrOIDCAssertionAlreadyExchanged = errors.New("state: OIDC assertion already exchanged")
)

// Identity is a tnl server identity.
type Identity struct {
	ID          string
	DisplayName string
	Email       string
}

// CreateAccessCredential ensures the identity and stores its credential atomically.
func CreateAccessCredential(
	ctx context.Context,
	db *sql.DB,
	identity Identity,
	credentialID credentials.CredentialID,
	secretHash credentials.SecretHash,
	issuedAt, expiresAt time.Time,
) error {
	return createAccessCredential(ctx, db, identity, credentialID, secretHash, issuedAt, expiresAt, nil, time.Time{})
}

// CreateOIDCAccessCredential consumes one ID token and stores its access credential atomically.
func CreateOIDCAccessCredential(
	ctx context.Context,
	db *sql.DB,
	identity Identity,
	credentialID credentials.CredentialID,
	secretHash credentials.SecretHash,
	issuedAt, expiresAt time.Time,
	assertionHash []byte,
	assertionExpiresAt time.Time,
) error {
	if len(assertionHash) != 32 || !assertionExpiresAt.After(issuedAt) {
		return errors.New("state: OIDC assertion metadata is invalid")
	}
	return createAccessCredential(
		ctx, db, identity, credentialID, secretHash, issuedAt, expiresAt, assertionHash, assertionExpiresAt,
	)
}

func createAccessCredential(
	ctx context.Context,
	db *sql.DB,
	identity Identity,
	credentialID credentials.CredentialID,
	secretHash credentials.SecretHash,
	issuedAt, expiresAt time.Time,
	assertionHash []byte,
	assertionExpiresAt time.Time,
) error {
	if strings.TrimSpace(identity.ID) == "" || strings.TrimSpace(credentialID.String()) == "" {
		return errors.New("state: identity and credential IDs are required")
	}
	if !expiresAt.After(issuedAt) {
		return errors.New("state: credential expiry must follow issuance")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: begin credential transaction: %w", err)
	}
	defer tx.Rollback()
	queries := statedb.New(tx)

	if err := queries.UpsertIdentity(ctx, statedb.UpsertIdentityParams{
		IdentityID:  identity.ID,
		DisplayName: identity.DisplayName,
		Email:       identity.Email,
		CreatedAt:   issuedAt.UnixNano(),
	}); err != nil {
		return fmt.Errorf("state: ensure identity: %w", err)
	}
	if assertionHash != nil {
		if err := queries.DeleteExpiredOIDCAssertions(ctx, issuedAt.UnixNano()); err != nil {
			return fmt.Errorf("state: expire OIDC assertion exchanges: %w", err)
		}
		inserted, err := queries.ConsumeOIDCAssertion(ctx, statedb.ConsumeOIDCAssertionParams{
			AssertionHash: assertionHash,
			ConsumedAt:    issuedAt.UnixNano(),
			ExpiresAt:     assertionExpiresAt.UnixNano(),
		})
		if err != nil {
			return fmt.Errorf("state: consume OIDC assertion: %w", err)
		}
		if inserted == 0 {
			return ErrOIDCAssertionAlreadyExchanged
		}
	}
	if err := queries.InsertAccessCredential(ctx, statedb.InsertAccessCredentialParams{
		CredentialID: credentialID.String(),
		IdentityID:   identity.ID,
		SecretHash:   secretHash[:],
		CreatedAt:    issuedAt.UnixNano(),
		ExpiresAt:    expiresAt.UnixNano(),
	}); err != nil {
		return fmt.Errorf("state: create access credential: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: commit credential transaction: %w", err)
	}
	return nil
}

// AuthenticateAccessCredential resolves a valid credential to its identity.
func AuthenticateAccessCredential(
	ctx context.Context,
	db *sql.DB,
	credentialID credentials.CredentialID,
	candidate credentials.SecretHash,
	now time.Time,
) (Identity, error) {
	credential, err := statedb.New(db).GetAccessCredential(ctx, credentialID.String())
	if errors.Is(err, sql.ErrNoRows) {
		return Identity{}, credentials.ErrInvalidAccessToken
	}
	if err != nil {
		return Identity{}, fmt.Errorf("state: read access credential: %w", err)
	}
	if !credentials.SecretHashMatches(credential.SecretHash, candidate) || credential.RevokedAt.Valid || now.UnixNano() >= credential.ExpiresAt {
		return Identity{}, credentials.ErrInvalidAccessToken
	}
	return Identity{
		ID:          credential.IdentityID,
		DisplayName: credential.DisplayName,
		Email:       credential.Email,
	}, nil
}

// RevokeAccessCredential revokes a credential owned by identityID.
func RevokeAccessCredential(
	ctx context.Context,
	db *sql.DB,
	identityID string,
	credentialID credentials.CredentialID,
	revokedAt time.Time,
) error {
	updated, err := statedb.New(db).RevokeAccessCredential(ctx, statedb.RevokeAccessCredentialParams{
		RevokedAt:    revokedAt.UnixNano(),
		CredentialID: credentialID.String(),
		IdentityID:   identityID,
	})
	if err != nil {
		return fmt.Errorf("state: revoke access credential: %w", err)
	}
	if updated == 0 {
		return ErrAccessCredentialNotFound
	}
	return nil
}
