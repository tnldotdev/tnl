package clientstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
)

// databaseFilename identifies the fresh client-state baseline independently of
// the SQLite migration and local event schema versions.
const databaseFilename = "v1.db"

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
	secrets           secretProtector
}

// Root returns the canonical, validated directory used by this client state.
func (d *Database) Root() string { return d.root }

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
		TeamID: sql.NullString{String: teamID, Valid: true}, Now: s.database.now().UTC().UnixNano(), Origin: s.controlEndpoint,
	}); err != nil {
		return fmt.Errorf("clientstate: save selected team: %w", err)
	}
	return nil
}

// DatabasePath returns the shared client database path within root.
func DatabasePath(root string) string {
	return filepath.Join(root, databaseFilename)
}

func DefaultDir() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", failure.Wrap("find client state directory", failure.ClientStateUnavailable, err)
	}
	return filepath.Join(root, "tnl"), nil
}

type ProtectionMode string

const (
	ProtectionFile     ProtectionMode = "file"
	ProtectionKeychain ProtectionMode = "keychain"
)

type OpenOptions struct {
	// protection defaults to Keychain on macOS and a private file elsewhere.
	// reopening must use the same mode; the database verifies the wrapping key.
	Protection ProtectionMode
}

// Open initializes fresh v1 state without reading any earlier database.
func Open(ctx context.Context, root string) (result *Database, retErr error) {
	return OpenWithOptions(ctx, root, OpenOptions{})
}

func OpenWithOptions(ctx context.Context, root string, options OpenOptions) (result *Database, retErr error) {
	defer func() {
		if retErr != nil {
			if _, typed := failure.Of(retErr); !typed {
				retErr = failure.Wrap("open client state", failure.ClientStateUnavailable, retErr)
			}
		}
	}()
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
	exists := false
	if info, statErr := os.Lstat(path); statErr == nil {
		exists = true
		if err := validatePrivateFile(info, false); err != nil {
			return nil, fmt.Errorf("clientstate: database: %w", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("clientstate: inspect database: %w", statErr)
	}
	mode := options.Protection
	if mode == "" {
		mode = defaultProtection()
	}
	digest := sha256.Sum256([]byte(root))
	account := hex.EncodeToString(digest[:])
	var key []byte
	switch mode {
	case ProtectionFile:
		key, err = fileWrappingKey(root, !exists)
	case ProtectionKeychain:
		key, err = platformWrappingKey(ctx, account, !exists)
	default:
		return nil, errors.New("clientstate: invalid protection mode")
	}
	if err != nil {
		return nil, err
	}
	protector := &encryptedProtector{key: key, account: account}
	var db *sql.DB
	if exists {
		db, err = openClientSQLite(ctx, path, false)
	} else {
		db, err = initializeClientSQLite(ctx, path, mode, protector)
	}
	if err != nil {
		return nil, fmt.Errorf("clientstate: %w", err)
	}
	if exists {
		var storedMode string
		var check []byte
		if err := db.QueryRowContext(ctx, "SELECT protection_mode, key_check_ciphertext FROM state_protection WHERE id = 1").Scan(&storedMode, &check); err != nil {
			db.Close()
			return nil, fmt.Errorf("clientstate: read state protection: %w", err)
		}
		if storedMode != string(mode) {
			db.Close()
			return nil, errors.New("clientstate: state protection mode does not match")
		}
		value, err := protector.Open(ctx, "wrapping-key-check", check)
		if err != nil || string(value) != "tnl client state v1" {
			db.Close()
			return nil, errors.New("clientstate: wrapping key does not match database")
		}
	}
	return &Database{
		root: root, locksDir: locksDir, db: db, queries: clientstatedb.New(db), now: time.Now,
		heartbeatInterval: tunnelHeartbeatInterval,
		secrets:           protector,
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
	return &Store{
		database: d, controlEndpoint: serverOrigin, locksDir: locksDir,
		secrets: scopedProtector{protector: d.secrets, scope: serverOrigin},
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
		return "", failure.Wrap("validate control URL port", failure.InvalidControlPort, err)
	}
	if err != nil {
		return "", failure.Wrap("validate control URL", failure.InvalidControlURL, err)
	}
	return server, nil
}
