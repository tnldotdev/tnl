package state

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/tnldotdev/tnl/internal/client/state/clientstatedb"
	tnlsqlite "github.com/tnldotdev/tnl/internal/client/state/sqlite"
)

// TelemetryPreference fences reports collected across persistent preference changes.
type TelemetryPreference struct {
	Enabled bool
	Epoch   int64
}

func (d *Database) TelemetryPreference(ctx context.Context) (TelemetryPreference, error) {
	row, err := d.queries.GetTelemetryPreference(ctx)
	if err != nil {
		return TelemetryPreference{}, fmt.Errorf("read telemetry preference: %w", err)
	}
	return TelemetryPreference{Enabled: row.TelemetryEnabled == 1, Epoch: row.TelemetryEpoch}, nil
}

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
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("clientstate: begin telemetry preference: %w", err)
	}
	defer tx.Rollback()
	queries := d.queries.WithTx(tx)
	if err := queries.SetTelemetryEnabled(ctx, value); err != nil {
		return fmt.Errorf("clientstate: save telemetry preference: %w", err)
	}
	if !enabled {
		if err := queries.ClearTelemetryEvents(ctx); err != nil {
			return fmt.Errorf("clientstate: clear telemetry queue: %w", err)
		}
	}
	return tx.Commit()
}

// TelemetryEnabledAt checks an existing database without creating client state
// or migrating it. an absent database defaults to enabled.
func TelemetryEnabledAt(ctx context.Context, root string) (bool, error) {
	preference, err := telemetryPreferenceAt(ctx, root, false)
	return preference.Enabled, err
}

// TelemetryPreferenceAt reads the saved epoch without creating writable state
// or waiting for a sqlite writer. optional queued observations use it to fence
// an off/on change during startup.
func TelemetryPreferenceAt(ctx context.Context, root string) (TelemetryPreference, error) {
	return telemetryPreferenceAt(ctx, root, true)
}

func telemetryPreferenceAt(ctx context.Context, root string, noWait bool) (TelemetryPreference, error) {
	path := DatabasePath(root)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return TelemetryPreference{Enabled: true}, nil
	}
	if err != nil {
		return TelemetryPreference{}, fmt.Errorf("clientstate: inspect telemetry preference: %w", err)
	}
	if err := validatePrivateFile(info, false); err != nil {
		return TelemetryPreference{}, fmt.Errorf("clientstate: database: %w", err)
	}
	return readTelemetryPreference(ctx, path, noWait)
}

func readTelemetryPreference(ctx context.Context, path string, noWait bool) (TelemetryPreference, error) {
	// read the telemetry value without opening writable state or migrating it.
	open := tnlsqlite.OpenReadOnly
	if noWait {
		open = tnlsqlite.OpenReadOnlyNowait
	}
	db, err := open(ctx, path)
	if err != nil {
		return TelemetryPreference{}, fmt.Errorf("clientstate: open telemetry preference: %w", err)
	}
	defer db.Close()
	row, err := clientstatedb.New(db).GetTelemetryPreference(ctx)
	if err != nil {
		return TelemetryPreference{}, fmt.Errorf("clientstate: read telemetry preference: %w", err)
	}
	return TelemetryPreference{Enabled: row.TelemetryEnabled == 1, Epoch: row.TelemetryEpoch}, nil
}
