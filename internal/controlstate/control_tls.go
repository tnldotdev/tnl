package controlstate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"golang.org/x/crypto/acme/autocert"
)

const (
	controlTLSLeadershipKey           int64 = 0x746e6c63746c7301
	controlTLSLeadershipCheckInterval       = time.Second
	maximumControlTLSCacheKey               = 512
	maximumControlTLSCacheData              = 2 << 20
)

type ControlTLSCache struct {
	database     *Database
	directoryURL string
}

func (d *Database) ControlTLSCache(directoryURL string) (*ControlTLSCache, error) {
	if err := d.requireOpen(); err != nil {
		return nil, err
	}
	if !validStateText(directoryURL) {
		return nil, errors.New("controlstate: invalid control TLS cache directory")
	}
	return &ControlTLSCache{database: d, directoryURL: directoryURL}, nil
}

func (c *ControlTLSCache) Get(ctx context.Context, key string) ([]byte, error) {
	if c == nil || c.database == nil || !validControlTLSCacheKey(key) {
		return nil, autocert.ErrCacheMiss
	}
	stored, err := controlstatedb.New(c.database.pool).GetControlTLSCacheEntry(ctx, controlstatedb.GetControlTLSCacheEntryParams{
		DirectoryUrl: c.directoryURL, CacheKey: key,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, fmt.Errorf("controlstate: get control TLS cache entry: %w", err)
	}
	data, previous, err := c.database.openSecret(stored.CacheStorageKeyID, controlTLSCacheContext(c.directoryURL, key), stored.CacheCiphertext)
	if err != nil {
		return nil, fmt.Errorf("controlstate: decrypt control TLS cache entry: %w", err)
	}
	if previous {
		rotated, err := c.database.sealSecret(controlTLSCacheContext(c.directoryURL, key), data)
		if err != nil {
			return nil, fmt.Errorf("controlstate: re-encrypt control TLS cache entry: %w", err)
		}
		if err := controlstatedb.New(c.database.pool).RotateControlTLSCacheEntry(ctx, controlstatedb.RotateControlTLSCacheEntryParams{
			CacheCiphertext: rotated, UpdatedAt: timestamptz(time.Now()), DirectoryUrl: c.directoryURL,
			CacheStorageKeyID: c.database.storageKey.CurrentID(), CacheKey: key,
			PreviousKeyID: stored.CacheStorageKeyID, PreviousCiphertext: stored.CacheCiphertext,
		}); err != nil {
			return nil, fmt.Errorf("controlstate: store re-encrypted control TLS cache entry: %w", err)
		}
	}
	return data, nil
}

func (c *ControlTLSCache) Put(ctx context.Context, key string, data []byte) error {
	if c == nil || c.database == nil || !validControlTLSCacheKey(key) || len(data) == 0 || len(data) > maximumControlTLSCacheData {
		return errors.New("controlstate: invalid control TLS cache entry")
	}
	ciphertext, err := c.database.sealSecret(controlTLSCacheContext(c.directoryURL, key), data)
	if err != nil {
		return fmt.Errorf("controlstate: encrypt control TLS cache entry: %w", err)
	}
	if err := controlstatedb.New(c.database.pool).PutControlTLSCacheEntry(ctx, controlstatedb.PutControlTLSCacheEntryParams{
		DirectoryUrl: c.directoryURL, CacheKey: key, CacheCiphertext: ciphertext,
		CacheStorageKeyID: c.database.storageKey.CurrentID(), UpdatedAt: timestamptz(time.Now()),
	}); err != nil {
		return fmt.Errorf("controlstate: put control TLS cache entry: %w", err)
	}
	return nil
}

func (c *ControlTLSCache) Delete(ctx context.Context, key string) error {
	if c == nil || c.database == nil || !validControlTLSCacheKey(key) {
		return nil
	}
	if err := controlstatedb.New(c.database.pool).DeleteControlTLSCacheEntry(ctx, controlstatedb.DeleteControlTLSCacheEntryParams{
		DirectoryUrl: c.directoryURL, CacheKey: key,
	}); err != nil {
		return fmt.Errorf("controlstate: delete control TLS cache entry: %w", err)
	}
	return nil
}

func (d *Database) RunControlTLSLeader(ctx context.Context, run func(context.Context) error) error {
	if run == nil {
		return errors.New("controlstate: control TLS leader function is required")
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	retry := time.NewTicker(time.Second)
	defer retry.Stop()
	for {
		connection, err := d.pool.Acquire(ctx)
		if err != nil {
			return fmt.Errorf("controlstate: acquire control TLS leadership connection: %w", err)
		}
		var acquired bool
		err = connection.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, controlTLSLeadershipKey).Scan(&acquired)
		if err != nil {
			connection.Release()
			return fmt.Errorf("controlstate: acquire control TLS leadership: %w", err)
		}
		if acquired {
			connectionLost := false
			defer connection.Release()
			defer func() {
				if connectionLost {
					return
				}
				unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, _ = connection.Exec(unlockCtx, `SELECT pg_advisory_unlock($1)`, controlTLSLeadershipKey)
			}()
			leaderCtx, cancelLeader := context.WithCancel(ctx)
			defer cancelLeader()
			result := make(chan error, 1)
			go func() { result <- run(leaderCtx) }()
			check := time.NewTicker(controlTLSLeadershipCheckInterval)
			defer check.Stop()
			for {
				select {
				case err := <-result:
					return err
				case <-ctx.Done():
					return nil
				case <-check.C:
					pingCtx, cancel := context.WithTimeout(context.Background(), controlTLSLeadershipCheckInterval)
					err := connection.Ping(pingCtx)
					cancel()
					if err != nil {
						connectionLost = true
						cancelLeader()
						return fmt.Errorf("controlstate: control TLS leadership connection lost: %w", err)
					}
				}
			}
		}
		connection.Release()
		select {
		case <-ctx.Done():
			return nil
		case <-retry.C:
		}
	}
}

func validControlTLSCacheKey(key string) bool {
	return key != "" && len(key) <= maximumControlTLSCacheKey
}
