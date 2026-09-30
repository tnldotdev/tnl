package clientstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	tnlsqlite "github.com/tnldotdev/tnl/internal/sqlite"
)

const databaseName = "client.db"

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Database owns the shared local client database.
type Database struct {
	root              string
	locksDir          string
	db                *sql.DB
	queries           *clientstatedb.Queries
	now               func() time.Time
	heartbeatInterval time.Duration
}

// Store scopes credentials, certificates, and locks to one server profile.
type Store struct {
	database        *Database
	controlEndpoint string
	locksDir        string
	secrets         secretProtector
}

// SelectedTeam returns the stable team selection for this server origin.
func (s *Store) SelectedTeam(ctx context.Context) (string, bool, error) {
	teamID, err := s.database.queries.GetSelectedTeam(ctx, s.controlEndpoint)
	if err != nil {
		return "", false, fmt.Errorf("clientstate: read selected team: %w", err)
	}
	return teamID, teamID != "", nil
}

// SaveSelectedTeam records the selected team for this server origin.
func (s *Store) SaveSelectedTeam(ctx context.Context, teamID string) error {
	if strings.TrimSpace(teamID) != teamID || teamID == "" {
		return errors.New("clientstate: invalid selected team")
	}
	if err := s.database.queries.SetSelectedTeam(ctx, clientstatedb.SetSelectedTeamParams{
		TeamID: teamID, Now: s.database.now().UTC().UnixNano(), Origin: s.controlEndpoint,
	}); err != nil {
		return fmt.Errorf("clientstate: save selected team: %w", err)
	}
	return nil
}

// DatabasePath returns the shared client database path within root.
func DatabasePath(root string) string { return filepath.Join(root, databaseName) }

func DefaultDir() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("clientstate: resolve user config directory: %w", err)
	}
	return filepath.Join(root, "tnl"), nil
}

// Open creates and migrates the shared local client database.
func Open(ctx context.Context, root string) (*Database, error) {
	root, err := prepareRoot(root)
	if err != nil {
		return nil, err
	}
	locksDir, err := privateSubdir(root, "locks")
	if err != nil {
		return nil, err
	}
	path := DatabasePath(root)
	migrationLock, err := openLockContext(ctx, filepath.Join(locksDir, "migrations.lock"), "migration")
	if err != nil {
		return nil, err
	}
	defer migrationLock.Close()
	if info, statErr := os.Lstat(path); statErr == nil {
		if err := validatePrivateFile(info, false); err != nil {
			return nil, fmt.Errorf("clientstate: database: %w", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("clientstate: inspect database: %w", statErr)
	}
	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("clientstate: load migrations: %w", err)
	}
	db, err := tnlsqlite.Open(ctx, path, migrations)
	if err != nil {
		return nil, fmt.Errorf("clientstate: %w", err)
	}
	return &Database{
		root: root, locksDir: locksDir, db: db, queries: clientstatedb.New(db), now: time.Now,
		heartbeatInterval: tunnelHeartbeatInterval,
	}, nil
}

func (d *Database) Close() error {
	if d == nil || d.db == nil {
		return nil
	}
	return d.db.Close()
}

// Server returns state scoped to a canonical server origin.
func (d *Database) Server(ctx context.Context, serverOrigin string) (*Store, error) {
	serverOrigin, err := CanonicalServer(serverOrigin)
	if err != nil {
		return nil, err
	}
	now := d.now().UTC().UnixNano()
	if err := d.queries.UpsertServerProfile(ctx, clientstatedb.UpsertServerProfileParams{
		Origin: serverOrigin, Now: now,
	}); err != nil {
		return nil, fmt.Errorf("clientstate: save server profile: %w", err)
	}
	digest := sha256.Sum256([]byte(serverOrigin))
	locksDir, err := privateSubdir(d.locksDir, hex.EncodeToString(digest[:]))
	if err != nil {
		return nil, err
	}
	profileDigest := sha256.Sum256([]byte(d.root + "\x00" + serverOrigin))
	return &Store{
		database: d, controlEndpoint: serverOrigin, locksDir: locksDir,
		secrets: newSecretProtector(
			hex.EncodeToString(profileDigest[:]), filepath.Join(locksDir, "keychain-initialization.lock"),
		),
	}, nil
}

// SavedServer returns the server selected by the last successful login.
func (d *Database) SavedServer(ctx context.Context) (string, bool, error) {
	selected, err := d.queries.GetSelectedServer(ctx)
	if err != nil {
		return "", false, fmt.Errorf("clientstate: read selected server: %w", err)
	}
	if !selected.Valid {
		return "", false, nil
	}
	server, err := CanonicalServer(selected.String)
	if err != nil || server != selected.String {
		return "", true, errors.New("clientstate: selected server is invalid")
	}
	return server, true, nil
}

// SaveServer records the server selected by a successful login.
func (d *Database) SaveServer(ctx context.Context, serverOrigin string) error {
	serverOrigin, err := CanonicalServer(serverOrigin)
	if err != nil {
		return err
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("clientstate: begin selected server update: %w", err)
	}
	defer tx.Rollback()
	queries := d.queries.WithTx(tx)
	if err := queries.UpsertServerProfile(ctx, clientstatedb.UpsertServerProfileParams{
		Origin: serverOrigin, Now: d.now().UTC().UnixNano(),
	}); err != nil {
		return fmt.Errorf("clientstate: save server profile: %w", err)
	}
	if err := queries.SetSelectedServer(ctx, sql.NullString{String: serverOrigin, Valid: true}); err != nil {
		return fmt.Errorf("clientstate: select server: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("clientstate: commit selected server update: %w", err)
	}
	return nil
}

// CanonicalServer validates and normalizes a tnl server origin.
func CanonicalServer(value string) (string, error) {
	server, err := naming.CanonicalControlURL(value)
	if errors.Is(err, naming.ErrInvalidControlPort) {
		return "", errors.New("clientstate: server port must be between 1 and 65535")
	}
	if err != nil {
		return "", errors.New("clientstate: server must be an HTTPS origin")
	}
	return server, nil
}
