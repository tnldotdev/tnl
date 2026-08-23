// Package backup manages optional Litestream replication for the state database.
package backup

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/benbjohnson/litestream"
	_ "github.com/benbjohnson/litestream/s3"
)

type Manager struct {
	databasePath string
	client       litestream.ReplicaClient
	store        *litestream.Store
}

// ValidateURL validates the supported backup URL shape.
func ValidateURL(value string) error {
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || strings.TrimSpace(value) != value || parsed.Scheme != "s3" || parsed.Host == "" ||
		strings.Trim(parsed.Path, "/") == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("backup URL must be s3://bucket/path")
	}
	return nil
}

// New returns a backup manager for databasePath.
func New(databasePath, remoteURL string) (*Manager, error) {
	if err := ValidateURL(remoteURL); err != nil {
		return nil, err
	}
	client, err := litestream.NewReplicaClientFromURL(remoteURL)
	if err != nil {
		return nil, fmt.Errorf("backup: configure replica: %w", err)
	}
	return &Manager{databasePath: databasePath, client: client}, nil
}

// Restore restores the newest backup when the local database is absent.
func (m *Manager) Restore(ctx context.Context) (bool, error) {
	if _, err := os.Stat(m.databasePath); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("backup: inspect database: %w", err)
	}
	if err := m.client.Init(ctx); err != nil {
		return false, fmt.Errorf("backup: initialize replica: %w", err)
	}
	options := litestream.NewRestoreOptions()
	options.OutputPath = m.databasePath
	options.IntegrityCheck = litestream.IntegrityCheckQuick
	err := litestream.NewReplicaWithClient(nil, m.client).Restore(ctx, options)
	if errors.Is(err, litestream.ErrTxNotAvailable) || errors.Is(err, litestream.ErrNoSnapshots) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("backup: restore database: %w", err)
	}
	return true, nil
}

// Start begins continuous replication.
func (m *Manager) Start(ctx context.Context) error {
	database := litestream.NewDB(m.databasePath)
	database.Replica = litestream.NewReplicaWithClient(database, m.client)
	store := litestream.NewStore([]*litestream.DB{database}, litestream.DefaultCompactionLevels)
	if err := store.Open(ctx); err != nil {
		return fmt.Errorf("backup: start replication: %w", err)
	}
	if err := database.SyncAndWait(ctx); err != nil {
		_ = store.Close(ctx)
		return fmt.Errorf("backup: initial sync: %w", err)
	}
	m.store = store
	return nil
}

// Close stops replication after a final sync.
func (m *Manager) Close(ctx context.Context) error {
	if m == nil || m.store == nil {
		return nil
	}
	store := m.store
	m.store = nil
	if err := store.Close(ctx); err != nil {
		return fmt.Errorf("backup: stop replication: %w", err)
	}
	return nil
}
