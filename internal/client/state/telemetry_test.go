package state

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTelemetryPreferenceIsPersistentAndDoesNotCreateStateOnRead(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	read := func(want bool) {
		t.Helper()
		enabled, err := TelemetryEnabledAt(t.Context(), root)
		if err != nil || enabled != want {
			t.Fatalf("telemetry enabled = %t, error = %v; want %t", enabled, err, want)
		}
	}
	readPreference := func(want TelemetryPreference) {
		t.Helper()
		preference, err := TelemetryPreferenceAt(t.Context(), root)
		if err != nil || preference != want {
			t.Fatalf("read-only preference = %+v, error = %v; want %+v", preference, err, want)
		}
	}
	read(true)
	readPreference(TelemetryPreference{Enabled: true})
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("read of absent client state created files: %v", err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	// an old client.db must not be opened or imported when v1.db is absent.
	if err := os.WriteFile(filepath.Join(root, "client.db"), []byte("old database"), 0o600); err != nil {
		t.Fatal(err)
	}
	read(true)
	if _, err := os.Stat(DatabasePath(root)); !os.IsNotExist(err) {
		t.Fatalf("telemetry read created versioned state: %v", err)
	}
	state, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SetTelemetryEnabled(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	read(false)
	readPreference(TelemetryPreference{Epoch: 1})
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	enabled, err := state.TelemetryEnabled(t.Context())
	if err != nil || enabled {
		t.Fatalf("reopened telemetry preference = %t, error = %v", enabled, err)
	}
	if err := state.SetTelemetryEnabled(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	read(true)
	readPreference(TelemetryPreference{Enabled: true, Epoch: 2})
	if err := state.SetTelemetryEnabled(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	readPreference(TelemetryPreference{Enabled: true, Epoch: 2})
}

func native70TelemetryState(t *testing.T, enabled bool) *Database {
	t.Helper()
	database, err := OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), OpenOptions{Protection: ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	// only these telemetry columns/trigger differ from native70's v1.db.
	for _, statement := range []string{
		"DROP TRIGGER telemetry_preference_changed",
		"ALTER TABLE installation_settings DROP COLUMN telemetry_epoch",
		"ALTER TABLE telemetry_outbox DROP COLUMN client_json",
	} {
		if _, err := database.db.ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.db.ExecContext(t.Context(), "UPDATE installation_settings SET telemetry_enabled = ? WHERE id = 1", enabled); err != nil {
		t.Fatal(err)
	}
	return database
}

func TestTelemetryAmendsNative70StateWithoutReset(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "saved off", true: "saved on"}[enabled], func(t *testing.T) {
			legacy := native70TelemetryState(t, enabled)
			root := legacy.Root()
			id, err := legacy.InstallationID(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := legacy.SaveServer(t.Context(), "https://saved.example"); err != nil {
				t.Fatal(err)
			}
			if _, err := legacy.db.ExecContext(t.Context(), `INSERT INTO telemetry_outbox (event_id, created_at, event_json)
				VALUES ('tev_0123456789abcdefghijkl', 1, '{"invocation_id":"private","occurred_at":"private"}')`); err != nil {
				t.Fatal(err)
			}
			preference, err := TelemetryPreferenceAt(t.Context(), root)
			if err != nil || preference != (TelemetryPreference{Enabled: enabled, Epoch: -1}) {
				t.Fatalf("read lost native70 choice: %+v %v", preference, err)
			}
			var columns int
			if err := legacy.db.QueryRowContext(t.Context(), `SELECT count(*) FROM pragma_table_info('installation_settings') WHERE name = 'telemetry_epoch'`).Scan(&columns); err != nil || columns != 0 {
				t.Fatalf("optional preference read amended state: columns=%d err=%v", columns, err)
			}
			before, err := os.Stat(DatabasePath(root))
			if err != nil {
				t.Fatal(err)
			}
			database, err := OpenWithOptions(t.Context(), root, OpenOptions{Protection: ProtectionFile})
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			after, err := os.Stat(DatabasePath(root))
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("amendment replaced v1.db: %v", err)
			}
			if got, err := database.TelemetryPreference(t.Context()); err != nil || got != (TelemetryPreference{Enabled: enabled}) {
				t.Fatalf("amendment lost saved choice or failed to establish epoch: %+v %v", got, err)
			} else {
				preference = got
			}
			if got, err := database.InstallationID(t.Context()); err != nil || got != id {
				t.Fatalf("amendment reset installation ID: %q %v", got, err)
			}
			if got, found, err := database.SavedServer(t.Context()); err != nil || !found || got != "https://saved.example" {
				t.Fatalf("amendment lost other client state: %q %t %v", got, found, err)
			}
			if pending, err := database.PendingTelemetryEvents(t.Context(), 25); err != nil || len(pending) != 0 {
				t.Fatalf("amendment retained private legacy outbox: %+v %v", pending, err)
			}
			if _, err := legacy.db.ExecContext(t.Context(), `INSERT INTO telemetry_outbox (event_id, created_at, event_json)
				VALUES ('tev_abcdefghijklmnopqrstuv', 2, '{"invocation_id":"private"}')`); err == nil {
				t.Fatal("already-open native70 writer repopulated the outbox")
			}
			// native70's preference UPDATE does not name the new epoch. it must
			// still fence old observations across an off/on cycle.
			for _, next := range []bool{true, false, true} {
				if _, err := legacy.db.ExecContext(t.Context(), "UPDATE installation_settings SET telemetry_enabled = ? WHERE id = 1", next); err != nil {
					t.Fatal(err)
				}
			}
			current, err := database.TelemetryPreference(t.Context())
			if err != nil || !current.Enabled || current.Epoch <= preference.Epoch {
				t.Fatalf("legacy toggle did not fence the epoch: %+v %v", current, err)
			}
			for _, event := range []struct {
				id    string
				epoch int64
			}{{"tev_0123456789abcdefghijkl", preference.Epoch}, {"tev_ABCDEFGHIJKLMNOPQRSTUV", current.Epoch}} {
				payload := json.RawMessage(`{"event_id":"` + event.id + `","event_version":1,"name":"command.outcome","payload":{"command":"publish","outcome":"completed"}}`)
				metadata := json.RawMessage(`{"version":"test","os":"linux","arch":"arm64","ci":false}`)
				if err := database.QueueTelemetryEvent(t.Context(), event.id, payload, metadata, event.epoch); err != nil {
					t.Fatal(err)
				}
			}
			// reopening is idempotent: do not clear current strict outbox rows or
			// reset the epoch when another native owner opens the same state.
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenWithOptions(t.Context(), root, OpenOptions{Protection: ProtectionFile})
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if got, err := reopened.TelemetryPreference(t.Context()); err != nil || got != current {
				t.Fatalf("reopen reset the epoch: %+v %v", got, err)
			}
			if pending, err := reopened.PendingTelemetryEvents(t.Context(), 25); err != nil || len(pending) != 1 || pending[0].ID != "tev_ABCDEFGHIJKLMNOPQRSTUV" {
				t.Fatalf("reopen lost current or revived old epoch rows: %+v %v", pending, err)
			}
		})
	}
}

func TestTelemetryAmendmentRollsBackOnOutboxFailure(t *testing.T) {
	legacy := native70TelemetryState(t, false)
	if _, err := legacy.db.ExecContext(t.Context(), `INSERT INTO telemetry_outbox (event_id, created_at, event_json) VALUES ('tev_0123456789abcdefghijkl', 1, '{}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.db.ExecContext(t.Context(), `CREATE TRIGGER fail_amendment BEFORE DELETE ON telemetry_outbox BEGIN SELECT RAISE(ABORT, 'cannot clear'); END`); err != nil {
		t.Fatal(err)
	}
	opened, err := OpenWithOptions(t.Context(), legacy.Root(), OpenOptions{Protection: ProtectionFile})
	if opened != nil {
		_ = opened.Close()
	}
	if err == nil {
		t.Fatal("amendment succeeded despite failing outbox deletion")
	}
	var columns int
	if err := legacy.db.QueryRowContext(t.Context(), `SELECT count(*) FROM pragma_table_info('installation_settings') WHERE name = 'telemetry_epoch'`).Scan(&columns); err != nil || columns != 0 {
		t.Fatalf("failed amendment retained a partial epoch column: %d %v", columns, err)
	}
	if preference, err := TelemetryPreferenceAt(context.Background(), legacy.Root()); err != nil || preference.Enabled {
		t.Fatalf("failed amendment lost saved off choice: %+v %v", preference, err)
	}
}
