package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

const (
	loginTokenKey         = "login-token"
	loginTokenRevisionKey = "login-token-revision"
)

// EnsureLoginToken loads or creates the database's login token.
func EnsureLoginToken(ctx context.Context, db *sql.DB) (credentials.LoginToken, bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback()
	queries := statedb.New(tx)
	data, err := queries.GetServerValue(ctx, loginTokenKey)
	generated := errors.Is(err, sql.ErrNoRows)
	if err != nil && !generated {
		return "", false, err
	}
	if generated {
		token, err := credentials.NewLoginToken()
		if err != nil {
			return "", false, err
		}
		data = []byte(token)
		if err := queries.PutServerValue(ctx, statedb.PutServerValueParams{Key: loginTokenKey, Value: data}); err != nil {
			return "", false, err
		}
		if err := queries.PutServerValue(ctx, statedb.PutServerValueParams{
			Key: loginTokenRevisionKey, Value: []byte("1"),
		}); err != nil {
			return "", false, err
		}
	}
	token := credentials.LoginToken(data)
	if _, err := credentials.ParseLoginToken(token); err != nil {
		return "", false, errors.New("state: persisted login token is invalid")
	}
	if _, err := readLoginTokenRevision(ctx, queries); err != nil {
		return "", false, err
	}
	if err := tx.Commit(); err != nil {
		return "", false, err
	}
	return token, generated, nil
}

// ReadLoginTokenRevision returns the current login-token authentication source revision.
func ReadLoginTokenRevision(ctx context.Context, db *sql.DB) (int64, error) {
	return readLoginTokenRevision(ctx, statedb.New(db))
}

// ReadLoginToken reads the persisted login token.
func ReadLoginToken(ctx context.Context, db *sql.DB) (credentials.LoginToken, error) {
	data, err := statedb.New(db).GetServerValue(ctx, loginTokenKey)
	if err != nil {
		return "", err
	}
	token := credentials.LoginToken(data)
	if _, err := credentials.ParseLoginToken(token); err != nil {
		return "", errors.New("state: persisted login token is invalid")
	}
	return token, nil
}

// RotateLoginToken replaces the persisted login token.
func RotateLoginToken(ctx context.Context, db *sql.DB) (credentials.LoginToken, error) {
	token, err := credentials.NewLoginToken()
	if err != nil {
		return "", err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	queries := statedb.New(tx)
	revision, err := readLoginTokenRevision(ctx, queries)
	if err != nil {
		return "", err
	}
	revision++
	if err := queries.PutServerValue(ctx, statedb.PutServerValueParams{
		Key:   loginTokenKey,
		Value: []byte(token),
	}); err != nil {
		return "", err
	}
	if err := queries.PutServerValue(ctx, statedb.PutServerValueParams{
		Key: loginTokenRevisionKey, Value: []byte(strconv.FormatInt(revision, 10)),
	}); err != nil {
		return "", err
	}
	now := time.Now().UTC().UnixNano()
	if _, err := queries.RevokeControlSessionsByAuthenticationSource(ctx, statedb.RevokeControlSessionsByAuthenticationSourceParams{
		RevokedAt: now, AuthenticationMethod: string(AuthenticationMethodLoginToken),
		AuthenticationSourceRevision: revision,
	}); err != nil {
		return "", fmt.Errorf("state: revoke old login-token sessions: %w", err)
	}
	if err := queries.DeleteInactiveControlSessionRefreshTokens(ctx, now); err != nil {
		return "", fmt.Errorf("state: prune old login-token session refresh credentials: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

type serverValueReader interface {
	GetServerValue(context.Context, string) ([]byte, error)
}

func readLoginTokenRevision(ctx context.Context, queries serverValueReader) (int64, error) {
	data, err := queries.GetServerValue(ctx, loginTokenRevisionKey)
	if err != nil {
		return 0, err
	}
	revision, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil || revision < 1 {
		return 0, errors.New("state: persisted login token revision is invalid")
	}
	return revision, nil
}
