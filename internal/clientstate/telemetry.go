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

// DemoTelemetryEnabled returns the explicit choice for demo CLI telemetry.
func (d *Database) DemoTelemetryEnabled(ctx context.Context) (bool, error) {
	enabled, err := d.queries.GetDemoTelemetryEnabled(ctx)
	if err != nil {
		return false, fmt.Errorf("clientstate: read demo telemetry preference: %w", err)
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

// DemoTelemetryEnabledAt never opens new client state to send telemetry.
func DemoTelemetryEnabledAt(ctx context.Context, root string) (bool, error) {
	path := DatabasePath(root)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("clientstate: inspect demo telemetry preference: %w", err)
	}
	if err := validatePrivateFile(info, false); err != nil {
		return false, fmt.Errorf("clientstate: database: %w", err)
	}
	db, err := tnlsqlite.OpenReadOnly(ctx, path, 2)
	if err != nil {
		return false, fmt.Errorf("clientstate: open demo telemetry preference: %w", err)
	}
	defer db.Close()
	enabled, err := clientstatedb.New(db).GetDemoTelemetryEnabled(ctx)
	if err != nil {
		return false, fmt.Errorf("clientstate: read demo telemetry preference: %w", err)
	}
	return enabled == 1, nil
}

func readTelemetryPreference(ctx context.Context, path string) (bool, error) {
	db, err := tnlsqlite.OpenReadOnly(ctx, path, 2)
	if err != nil {
		return false, fmt.Errorf("clientstate: open telemetry preference: %w", err)
	}
	defer db.Close()
	enabled, err := clientstatedb.New(db).GetTelemetryEnabled(ctx)
	if err != nil {
		return false, fmt.Errorf("clientstate: read telemetry preference: %w", err)
	}
	return enabled == 1, nil
}
