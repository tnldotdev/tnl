package clientstate

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	tnlsqlite "github.com/tnldotdev/tnl/internal/sqlite"
)

// TelemetryEnabled returns the saved preference for this client state.
func (d *Database) TelemetryEnabled(ctx context.Context) (bool, error) {
	enabled, err := d.queries.GetTelemetryEnabled(ctx)
	if err != nil {
		return false, fmt.Errorf("clientstate: read telemetry preference: %w", err)
	}
	return enabled == 1, nil
}

// SetTelemetryEnabled saves the preference across commands and projects.
func (d *Database) SetTelemetryEnabled(ctx context.Context, enabled bool) error {
	value := int64(0)
	if enabled {
		value = 1
	}
	if err := d.queries.SetTelemetryEnabled(ctx, value); err != nil {
		return fmt.Errorf("clientstate: save telemetry preference: %w", err)
	}
	return nil
}

// TelemetryEnabledAt checks an existing database without creating client state
// or migrating it. an absent database defaults to enabled.
func TelemetryEnabledAt(ctx context.Context, root string) (bool, error) {
	path := DatabasePath(root)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("clientstate: inspect telemetry preference: %w", err)
	}
	if err := validatePrivateFile(info, false); err != nil {
		return false, fmt.Errorf("clientstate: database: %w", err)
	}
	return readTelemetryPreference(ctx, path)
}

func readTelemetryPreference(ctx context.Context, path string) (bool, error) {
	// read both existing and preview-enabled state without migrating client state.
	db, err := tnlsqlite.OpenReadOnly(ctx, path)
	if err != nil {
		return false, fmt.Errorf("clientstate: open telemetry preference: %w", err)
	}
	defer db.Close()
	var version int64
	if err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version WHERE is_applied = 1").Scan(&version); err != nil {
		return false, fmt.Errorf("clientstate: read telemetry schema version: %w", err)
	}
	if version != 2 && version != 3 {
		return false, fmt.Errorf("clientstate: unsupported telemetry schema version %d", version)
	}
	enabled, err := clientstatedb.New(db).GetTelemetryEnabled(ctx)
	if err != nil {
		return false, fmt.Errorf("clientstate: read telemetry preference: %w", err)
	}
	return enabled == 1, nil
}
