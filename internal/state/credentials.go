package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/state/statedb"
)

var (
	// ErrAccessCredentialNotFound indicates that no credential matched the requested owner and ID.
	ErrAccessCredentialNotFound = errors.New("state: access credential not found")
	// ErrOIDCAssertionAlreadyExchanged indicates that an ID token was already consumed.
	ErrOIDCAssertionAlreadyExchanged = errors.New("state: OIDC assertion already exchanged")
)

// Principal is a tnl server identity.
type Principal struct {
	ID          string
	DisplayName string
	Email       string
}

// CreateAccessCredential ensures the principal and stores its credential atomically.
func CreateAccessCredential(
	ctx context.Context,
	db *sql.DB,
	principal Principal,
	credentialID credentials.CredentialID,
	secretHash credentials.SecretHash,
	issuedAt, expiresAt time.Time,
) error {
	return createAccessCredential(ctx, db, principal, credentialID, secretHash, issuedAt, expiresAt, nil, time.Time{})
}

// CreateOIDCAccessCredential consumes one ID token and stores its access credential atomically.
func CreateOIDCAccessCredential(
	ctx context.Context,
	db *sql.DB,
	principal Principal,
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
		ctx, db, principal, credentialID, secretHash, issuedAt, expiresAt, assertionHash, assertionExpiresAt,
	)
}

func createAccessCredential(
	ctx context.Context,
	db *sql.DB,
	principal Principal,
	credentialID credentials.CredentialID,
	secretHash credentials.SecretHash,
	issuedAt, expiresAt time.Time,
	assertionHash []byte,
	assertionExpiresAt time.Time,
) error {
	if strings.TrimSpace(principal.ID) == "" || strings.TrimSpace(credentialID.String()) == "" {
		return errors.New("state: principal and credential IDs are required")
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

	if err := queries.UpsertPrincipal(ctx, statedb.UpsertPrincipalParams{
		PrincipalID: principal.ID,
		DisplayName: principal.DisplayName,
		Email:       principal.Email,
		CreatedAt:   issuedAt.Unix(),
	}); err != nil {
		return fmt.Errorf("state: ensure principal: %w", err)
	}
	if assertionHash != nil {
		if err := queries.DeleteExpiredOIDCAssertions(ctx, issuedAt.Unix()); err != nil {
			return fmt.Errorf("state: expire OIDC assertion exchanges: %w", err)
		}
		inserted, err := queries.ConsumeOIDCAssertion(ctx, statedb.ConsumeOIDCAssertionParams{
			AssertionHash: assertionHash,
			ConsumedAt:    issuedAt.Unix(),
			ExpiresAt:     assertionExpiresAt.Unix(),
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
		PrincipalID:  principal.ID,
		SecretHash:   secretHash[:],
		CreatedAt:    issuedAt.Unix(),
		ExpiresAt:    expiresAt.Unix(),
	}); err != nil {
		return fmt.Errorf("state: create access credential: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: commit credential transaction: %w", err)
	}
	return nil
}

// AuthenticateAccessCredential resolves a valid credential to its principal.
func AuthenticateAccessCredential(
	ctx context.Context,
	db *sql.DB,
	credentialID credentials.CredentialID,
	candidate credentials.SecretHash,
	now time.Time,
) (Principal, error) {
	credential, err := statedb.New(db).GetAccessCredential(ctx, credentialID.String())
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, credentials.ErrInvalidAccessToken
	}
	if err != nil {
		return Principal{}, fmt.Errorf("state: read access credential: %w", err)
	}
	if !credentials.SecretHashMatches(credential.SecretHash, candidate) || credential.RevokedAt.Valid || now.Unix() >= credential.ExpiresAt {
		return Principal{}, credentials.ErrInvalidAccessToken
	}
	return Principal{
		ID:          credential.PrincipalID,
		DisplayName: credential.DisplayName,
		Email:       credential.Email,
	}, nil
}

// RevokeAccessCredential revokes a credential owned by principalID.
func RevokeAccessCredential(
	ctx context.Context,
	db *sql.DB,
	principalID string,
	credentialID credentials.CredentialID,
	revokedAt time.Time,
) error {
	updated, err := statedb.New(db).RevokeAccessCredential(ctx, statedb.RevokeAccessCredentialParams{
		RevokedAt:    revokedAt.Unix(),
		CredentialID: credentialID.String(),
		PrincipalID:  principalID,
	})
	if err != nil {
		return fmt.Errorf("state: revoke access credential: %w", err)
	}
	if updated == 0 {
		return ErrAccessCredentialNotFound
	}
	return nil
}
