package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/tnldotdev/tnl/internal/state/statedb"
	"golang.org/x/crypto/acme/autocert"
)

const relayMapKey = "relay-map/tailcat"

// ReadRelayMap returns the pinned Tailcat relay map.
func ReadRelayMap(ctx context.Context, db *sql.DB) ([]byte, error) {
	return statedb.New(db).GetServerState(ctx, relayMapKey)
}

// WriteRelayMap replaces the pinned Tailcat relay map.
func WriteRelayMap(ctx context.Context, db *sql.DB, data []byte) error {
	return statedb.New(db).PutServerState(ctx, statedb.PutServerStateParams{StateKey: relayMapKey, Value: data})
}

// ControlTLSCache returns an autocert cache scoped to one ACME directory.
func ControlTLSCache(db *sql.DB, directoryURL string) autocert.Cache {
	digest := sha256.Sum256([]byte(directoryURL))
	return &controlTLSCache{db: db, prefix: "control-acme/" + hex.EncodeToString(digest[:]) + "/"}
}

type controlTLSCache struct {
	db     *sql.DB
	prefix string
}

func (c *controlTLSCache) Get(ctx context.Context, key string) ([]byte, error) {
	data, err := statedb.New(c.db).GetServerState(ctx, c.prefix+key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, fmt.Errorf("state: read control TLS cache: %w", err)
	}
	return data, nil
}

func (c *controlTLSCache) Put(ctx context.Context, key string, data []byte) error {
	if err := statedb.New(c.db).PutServerState(ctx, statedb.PutServerStateParams{StateKey: c.prefix + key, Value: data}); err != nil {
		return fmt.Errorf("state: write control TLS cache: %w", err)
	}
	return nil
}

func (c *controlTLSCache) Delete(ctx context.Context, key string) error {
	if err := statedb.New(c.db).DeleteServerState(ctx, c.prefix+key); err != nil {
		return fmt.Errorf("state: delete control TLS cache: %w", err)
	}
	return nil
}
