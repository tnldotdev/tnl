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
	config := d.dedicatedConnectionConfig(tlsLeadershipConnection)
	for {
		connection, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !waitControlTLSLeadershipRetry(ctx, retry.C) {
				return nil
			}
			continue
		}
		transaction, err := connection.Begin(ctx)
		if err != nil {
			closeControlTLSLeadershipConnection(connection)
			if ctx.Err() != nil {
				return nil
			}
			if !waitControlTLSLeadershipRetry(ctx, retry.C) {
				return nil
			}
			continue
		}
		release := func() {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), controlTLSLeadershipCheckInterval)
			_ = transaction.Rollback(rollbackCtx)
			cancel()
			closeControlTLSLeadershipConnection(connection)
		}
		var acquired bool
		err = transaction.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, controlTLSLeadershipKey).Scan(&acquired)
		if err != nil {
			release()
			if ctx.Err() != nil {
				return nil
			}
			if !waitControlTLSLeadershipRetry(ctx, retry.C) {
				return nil
			}
			continue
		}
		if acquired {
			leaderCtx, cancelLeader := context.WithCancel(ctx)
			result := make(chan error, 1)
			go func() { result <- run(leaderCtx) }()
			check := time.NewTicker(controlTLSLeadershipCheckInterval)
		leadership:
			for {
				select {
				case err := <-result:
					check.Stop()
					cancelLeader()
					release()
					return err
				case <-ctx.Done():
					check.Stop()
					cancelLeader()
					err := waitControlTLSLeader(result)
					release()
					return err
				case <-check.C:
					pingCtx, cancel := context.WithTimeout(context.Background(), controlTLSLeadershipCheckInterval)
					_, err := transaction.Exec(pingCtx, `SELECT 1`)
					cancel()
					if err != nil {
						check.Stop()
						cancelLeader()
						callbackErr := waitControlTLSLeader(result)
						release()
						if callbackErr != nil {
							return fmt.Errorf("controlstate: stop control TLS leader after connection loss: %w", errors.Join(err, callbackErr))
						}
						if !waitControlTLSLeadershipRetry(ctx, retry.C) {
							return nil
						}
						break leadership
					}
				}
			}
			continue
		}
		release()
		if !waitControlTLSLeadershipRetry(ctx, retry.C) {
			return nil
		}
	}
}

func waitControlTLSLeader(result <-chan error) error {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case err := <-result:
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	case <-timer.C:
		return errors.New("controlstate: timed out stopping control TLS leader")
	}
}

func closeControlTLSLeadershipConnection(connection *pgx.Conn) {
	closeCtx, cancel := context.WithTimeout(context.Background(), controlTLSLeadershipCheckInterval)
	defer cancel()
	_ = connection.Close(closeCtx)
}

func waitControlTLSLeadershipRetry(ctx context.Context, retry <-chan time.Time) bool {
	select {
	case <-ctx.Done():
		return false
	case <-retry:
		return true
	}
}

func validControlTLSCacheKey(key string) bool {
	return key != "" && len(key) <= maximumControlTLSCacheKey
}
