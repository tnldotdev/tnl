package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0xcadams/tnl/internal/credentials"
)

var (
	// ErrAccessCredentialNotFound indicates that no credential matched the requested owner and ID.
	ErrAccessCredentialNotFound = errors.New("state: access credential not found")
	// ErrExternalTokenAlreadyExchanged indicates that an upstream bearer was already consumed.
	ErrExternalTokenAlreadyExchanged = errors.New("state: external token already exchanged")
)

// Principal is a standalone core identity.
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
	return createAccessCredential(ctx, db, principal, credentialID, secretHash, issuedAt, expiresAt, nil)
}

// CreateExternalAccessCredential consumes one upstream bearer and stores its access credential atomically.
func CreateExternalAccessCredential(
	ctx context.Context,
	db *sql.DB,
	principal Principal,
	credentialID credentials.CredentialID,
	secretHash credentials.SecretHash,
	issuedAt, expiresAt time.Time,
	externalTokenHash []byte,
) error {
	if len(externalTokenHash) != 32 {
		return errors.New("state: external token hash is invalid")
	}
	return createAccessCredential(
		ctx, db, principal, credentialID, secretHash, issuedAt, expiresAt, externalTokenHash,
	)
}

func createAccessCredential(
	ctx context.Context,
	db *sql.DB,
	principal Principal,
	credentialID credentials.CredentialID,
	secretHash credentials.SecretHash,
	issuedAt, expiresAt time.Time,
	externalTokenHash []byte,
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

	if _, err := tx.ExecContext(ctx, `INSERT INTO principals
		(id, display_name, email, created_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET display_name = excluded.display_name, email = excluded.email`,
		principal.ID, principal.DisplayName, principal.Email, issuedAt.Unix()); err != nil {
		return fmt.Errorf("state: ensure principal: %w", err)
	}
	if externalTokenHash != nil {
		if _, err := tx.ExecContext(ctx,
			"DELETE FROM external_token_exchanges WHERE expires_at <= ?", issuedAt.Unix(),
		); err != nil {
			return fmt.Errorf("state: expire external token exchanges: %w", err)
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO external_token_exchanges
			(token_hash, consumed_at, expires_at) VALUES (?, ?, ?)
			ON CONFLICT (token_hash) DO NOTHING`, externalTokenHash, issuedAt.Unix(), expiresAt.Unix())
		if err != nil {
			return fmt.Errorf("state: consume external token: %w", err)
		}
		inserted, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("state: count consumed external tokens: %w", err)
		}
		if inserted == 0 {
			return ErrExternalTokenAlreadyExchanged
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO access_credentials
		(id, principal_id, secret_hash, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)`,
		credentialID.String(), principal.ID, secretHash[:], issuedAt.Unix(), expiresAt.Unix()); err != nil {
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
	var principal Principal
	var storedHash []byte
	var expiresAt int64
	var revokedAt sql.NullInt64
	err := db.QueryRowContext(ctx, `SELECT
		p.id, p.display_name, p.email, c.secret_hash, c.expires_at, c.revoked_at
		FROM access_credentials c
		JOIN principals p ON p.id = c.principal_id
		WHERE c.id = ?`, credentialID.String()).Scan(
		&principal.ID,
		&principal.DisplayName,
		&principal.Email,
		&storedHash,
		&expiresAt,
		&revokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, credentials.ErrInvalidAccessToken
	}
	if err != nil {
		return Principal{}, fmt.Errorf("state: read access credential: %w", err)
	}
	if !credentials.SecretHashMatches(storedHash, candidate) || revokedAt.Valid || now.Unix() >= expiresAt {
		return Principal{}, credentials.ErrInvalidAccessToken
	}
	return principal, nil
}

// RevokeAccessCredential revokes a credential owned by principalID.
func RevokeAccessCredential(
	ctx context.Context,
	db *sql.DB,
	principalID string,
	credentialID credentials.CredentialID,
	revokedAt time.Time,
) error {
	result, err := db.ExecContext(ctx, `UPDATE access_credentials
		SET revoked_at = COALESCE(revoked_at, ?)
		WHERE id = ? AND principal_id = ?`, revokedAt.Unix(), credentialID.String(), principalID)
	if err != nil {
		return fmt.Errorf("state: revoke access credential: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("state: count revoked credentials: %w", err)
	}
	if updated == 0 {
		return ErrAccessCredentialNotFound
	}
	return nil
}
