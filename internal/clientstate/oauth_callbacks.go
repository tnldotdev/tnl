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

// SaveOAuthCallback stores an opaque OAuth state digest, never the state value.
// duplicate states fail closed rather than replacing another worktree's login.
func (d *Database) SaveOAuthCallback(ctx context.Context, server, hostname, group, state, tunnelID, path, query, publicURLID string, runNumber uint64) error {
	if server == "" || hostname == "" || group == "" || state == "" || len(state) > 8192 || tunnelID == "" || path == "" || publicURLID == "" || runNumber == 0 || runNumber > 1<<63-1 {
		return errors.New("incomplete OAuth callback")
	}
	digest := sha256.Sum256([]byte(state))
	now := d.now().UTC()
	if err := d.queries.ExpireOAuthCallbacks(ctx, now.UnixNano()); err != nil {
		return fmt.Errorf("expire OAuth callbacks: %w", err)
	}
	count, err := d.queries.SaveOAuthCallback(ctx, clientstatedb.SaveOAuthCallbackParams{
		ServerOrigin: server, Hostname: hostname, IntegrationGroup: group, StateDigest: digest[:], TunnelID: tunnelID,
		CallbackPath: path, CallbackQuery: query, ExpiresAt: now.Add(10 * time.Minute).UnixNano(),
		PublicURLID: publicURLID, PublishRunNumber: int64(runNumber), Now: now.UnixNano(),
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
func (d *Database) ConsumeOAuthCallback(ctx context.Context, server, hostname, state, path string) (OAuthCallback, TunnelInfo, error) {
	if server == "" || hostname == "" || state == "" || len(state) > 8192 || path == "" {
		return OAuthCallback{}, TunnelInfo{}, errors.New("invalid OAuth callback")
	}
	digest := sha256.Sum256([]byte(state))
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return OAuthCallback{}, TunnelInfo{}, err
	}
	defer tx.Rollback()
	queries := clientstatedb.New(tx)
	row, err := queries.GetCurrentOAuthCallback(ctx, clientstatedb.GetCurrentOAuthCallbackParams{
		ServerOrigin: server, Hostname: hostname, StateDigest: digest[:], CallbackPath: path, Now: d.now().UTC().UnixNano(),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return OAuthCallback{}, TunnelInfo{}, sql.ErrNoRows
	}
	if err != nil {
		return OAuthCallback{}, TunnelInfo{}, err
	}
	count, err := queries.DeleteOAuthCallback(ctx, clientstatedb.DeleteOAuthCallbackParams{
		ServerOrigin: server, Hostname: hostname, StateDigest: digest[:],
	})
	if err != nil {
		return OAuthCallback{}, TunnelInfo{}, err
	}
	if count != 1 {
		return OAuthCallback{}, TunnelInfo{}, sql.ErrNoRows
	}
	if err := tx.Commit(); err != nil {
		return OAuthCallback{}, TunnelInfo{}, err
	}
	return OAuthCallback{TunnelID: row.TunnelID, Path: row.CallbackPath}, TunnelInfo{
		ID: row.TunnelID, Hostname: row.Hostname, PublicURL: "https://" + row.Hostname,
		PublicURLID: row.PublicURLID, PublishRunNumber: uint64(row.PublishRunNumber),
	}, nil
}
