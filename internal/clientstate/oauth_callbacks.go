package clientstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
)

// OAuthCallback identifies the exact local publish run that started a login.
type OAuthCallback struct {
	TunnelID string
	Path     string
}

type OAuthCallbackScope struct {
	Server, Hostname, IntegrationGroup string
}

// OAuthRedirectOrigin is the exact public URL and run that started login. an
// alias origin is independent of the local app tunnel receiving the callback.
type OAuthRedirectOrigin struct {
	Hostname         string
	PublicURLID      string
	PublishRunNumber uint64
}

type OAuthCallbackDestination struct {
	TunnelID, Path, Query string
}

type SaveOAuthCallbackInput struct {
	Scope       OAuthCallbackScope
	Origin      OAuthRedirectOrigin
	Destination OAuthCallbackDestination
	State       string
}

// SaveOAuthCallback stores an opaque OAuth state digest, never the state value.
// duplicate states fail closed rather than replacing another worktree's login.
func (d *Database) SaveOAuthCallback(ctx context.Context, input SaveOAuthCallbackInput) error {
	scope, origin, destination := input.Scope, input.Origin, input.Destination
	if scope.Server == "" || scope.Hostname == "" || scope.IntegrationGroup == "" || input.State == "" || len(input.State) > 8192 || destination.TunnelID == "" || destination.Path == "" || origin.PublicURLID == "" || origin.PublishRunNumber == 0 || origin.PublishRunNumber > 1<<63-1 {
		return errors.New("incomplete OAuth callback")
	}
	digest := sha256.Sum256([]byte(input.State))
	now := d.now().UTC()
	if err := d.queries.ExpireOAuthCallbacks(ctx, now.UnixNano()); err != nil {
		return fmt.Errorf("expire OAuth callbacks: %w", err)
	}
	if err := d.queries.ExpireOAuthAliasReturns(ctx, now.UnixNano()); err != nil {
		return err
	}
	count, err := d.queries.SaveOAuthCallback(ctx, clientstatedb.SaveOAuthCallbackParams{
		ServerOrigin: scope.Server, Hostname: scope.Hostname, IntegrationGroup: scope.IntegrationGroup, StateDigest: digest[:], TunnelID: destination.TunnelID,
		CallbackPath: destination.Path, CallbackQuery: destination.Query, ExpiresAt: now.Add(10 * time.Minute).UnixNano(),
		PublicURLID: origin.PublicURLID, PublishRunNumber: int64(origin.PublishRunNumber), Now: now.UnixNano(),
		OriginHostname: origin.Hostname,
	})
	if err != nil {
		return fmt.Errorf("save OAuth callback: %w", err)
	}
	if count != 1 {
		return errors.New("OAuth callback already exists or tunnel stopped")
	}
	return nil
}

// ConsumeOAuthCallback atomically removes one mapping and checks its tunnel is
// still ready. a callback for a stopped or replaced publish run cannot be sent
// to a different app merely because the hostname was reused.
func (d *Database) ConsumeOAuthCallback(ctx context.Context, server, hostname, state, path string) (OAuthCallback, OAuthRedirectOrigin, error) {
	if server == "" || hostname == "" || state == "" || len(state) > 8192 || path == "" {
		return OAuthCallback{}, OAuthRedirectOrigin{}, errors.New("invalid OAuth callback")
	}
	digest := sha256.Sum256([]byte(state))
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return OAuthCallback{}, OAuthRedirectOrigin{}, err
	}
	defer tx.Rollback()
	queries := clientstatedb.New(tx)
	row, err := queries.GetCurrentOAuthCallback(ctx, clientstatedb.GetCurrentOAuthCallbackParams{
		ServerOrigin: server, Hostname: hostname, StateDigest: digest[:], CallbackPath: path, Now: d.now().UTC().UnixNano(),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return OAuthCallback{}, OAuthRedirectOrigin{}, sql.ErrNoRows
	}
	if err != nil {
		return OAuthCallback{}, OAuthRedirectOrigin{}, err
	}
	count, err := queries.DeleteOAuthCallback(ctx, clientstatedb.DeleteOAuthCallbackParams{
		ServerOrigin: server, Hostname: hostname, StateDigest: digest[:],
	})
	if err != nil {
		return OAuthCallback{}, OAuthRedirectOrigin{}, err
	}
	if count != 1 {
		return OAuthCallback{}, OAuthRedirectOrigin{}, sql.ErrNoRows
	}
	if row.OriginHostname != "" && row.OriginHostname != row.Hostname.String {
		count, err := queries.SaveOAuthAliasReturn(ctx, clientstatedb.SaveOAuthAliasReturnParams{
			ServerOrigin: server, Hostname: row.OriginHostname, StateDigest: digest[:], CallbackPath: row.CallbackPath,
			PublicURLID: row.PublicURLID, PublishRunNumber: row.PublishRunNumber, ExpiresAt: row.ExpiresAt,
			Now: d.now().UTC().UnixNano(),
		})
		if err != nil {
			return OAuthCallback{}, OAuthRedirectOrigin{}, err
		}
		if count != 1 {
			return OAuthCallback{}, OAuthRedirectOrigin{}, errors.New("alias callback return state is full")
		}
	}
	if err := tx.Commit(); err != nil {
		return OAuthCallback{}, OAuthRedirectOrigin{}, err
	}
	origin := row.OriginHostname
	if origin == "" {
		origin = row.Hostname.String
	}
	return OAuthCallback{TunnelID: row.TunnelID, Path: row.CallbackPath}, OAuthRedirectOrigin{
		Hostname:    origin,
		PublicURLID: row.PublicURLID, PublishRunNumber: uint64(row.PublishRunNumber),
	}, nil
}

// AdmitAliasOAuthReturn binds the browser's final callback hop to the alias run
// that started login. unknown states are ordinary app requests; a known return
// never falls through to a replacement run, including after it was consumed.
func (d *Database) AdmitAliasOAuthReturn(ctx context.Context, server, hostname, state, path, publicURLID string, number uint64) error {
	if state == "" || len(state) > 8192 {
		return nil
	}
	digest := sha256.Sum256([]byte(state))
	row, err := d.queries.GetOAuthAliasReturn(ctx, clientstatedb.GetOAuthAliasReturnParams{ServerOrigin: server, Hostname: hostname, StateDigest: digest[:]})
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if row.CallbackPath != path {
		return nil
	}
	count, err := d.queries.ConsumeOAuthAliasReturn(ctx, clientstatedb.ConsumeOAuthAliasReturnParams{
		ServerOrigin: server, Hostname: hostname, StateDigest: digest[:], CallbackPath: path,
		PublicURLID: publicURLID, PublishRunNumber: int64(number), Now: sql.NullInt64{Int64: d.now().UTC().UnixNano(), Valid: true},
	})
	if err != nil {
		return err
	}
	if count != 1 {
		return sql.ErrNoRows
	}
	return nil
}
