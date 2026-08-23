package state

import (
	"context"
	"database/sql"
	"errors"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

const loginTokenKey = "login-token"

// EnsureLoginToken loads or creates the database's login token.
func EnsureLoginToken(ctx context.Context, db *sql.DB) (credentials.LoginToken, bool, error) {
	if token, err := ReadLoginToken(ctx, db); err == nil {
		return token, false, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", false, err
	}
	token, err := credentials.NewLoginToken()
	if err != nil {
		return "", false, err
	}
	inserted, err := statedb.New(db).InsertServerState(ctx, statedb.InsertServerStateParams{
		StateKey: loginTokenKey,
		Value:    []byte(token),
	})
	if err != nil {
		return "", false, err
	}
	stored, err := ReadLoginToken(ctx, db)
	return stored, inserted == 1, err
}

// ReadLoginToken reads the persisted login token.
func ReadLoginToken(ctx context.Context, db *sql.DB) (credentials.LoginToken, error) {
	data, err := statedb.New(db).GetServerState(ctx, loginTokenKey)
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
	if err := statedb.New(db).PutServerState(ctx, statedb.PutServerStateParams{
		StateKey: loginTokenKey,
		Value:    []byte(token),
	}); err != nil {
		return "", err
	}
	return token, nil
}
