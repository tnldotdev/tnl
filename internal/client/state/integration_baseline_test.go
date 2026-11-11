package state

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestStateRejectsEncodedIntegrationBaselineWithoutMigratingIt(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	options := OpenOptions{Protection: ProtectionFile}
	database, err := OpenWithOptions(t.Context(), root, options)
	if err != nil {
		t.Fatal(err)
	}
	// retain the predecessor's identity and generated columns as a migration fence.
	for _, statement := range []string{
		`DROP TABLE baseline_identity`,
		`CREATE TABLE baseline_identity (id INTEGER PRIMARY KEY CHECK (id = 1), identity TEXT NOT NULL CHECK (identity = 'tnl-client-fresh-v1-services')) STRICT`,
		`INSERT INTO baseline_identity VALUES (1, 'tnl-client-fresh-v1-services')`,
		`ALTER TABLE local_tunnels ADD COLUMN integration_group TEXT GENERATED ALWAYS AS (CASE WHEN primary_project_root IS NULL THEN '' ELSE primary_project_root || char(0) || integration_namespace END) VIRTUAL NOT NULL`,
		`ALTER TABLE webhook_owners ADD COLUMN integration_group TEXT GENERATED ALWAYS AS (primary_project_root || char(0) || integration_namespace) VIRTUAL NOT NULL`,
	} {
		if _, err := database.db.ExecContext(t.Context(), statement); err != nil {
			_ = database.Close()
			t.Fatal(err)
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	path := DatabasePath(root)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenWithOptions(t.Context(), root, options); err == nil {
		_ = reopened.Close()
		t.Fatal("accepted the encoded integration baseline")
	} else if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ClientStateUnavailable || !strings.Contains(err.Error(), "select a fresh state directory") {
		t.Fatalf("predecessor rejection = %v", err)
	}
	if reopened, err := openReadOnlySQLite(t.Context(), path); err == nil {
		_ = reopened.Close()
		t.Fatal("read-only state accepted the encoded integration baseline")
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || filepath.Base(path) != "v1.db" {
		t.Fatalf("rejection replaced the v1 database: %v", err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var baseline string
	var version, projections int
	if err := raw.QueryRowContext(t.Context(), `SELECT identity FROM baseline_identity WHERE id = 1`).Scan(&baseline); err != nil || baseline != "tnl-client-fresh-v1-services" {
		t.Fatalf("rejection rewrote baseline %q: %v", baseline, err)
	}
	if err := raw.QueryRowContext(t.Context(), `SELECT max(version_id) FROM goose_db_version WHERE is_applied = 1`).Scan(&version); err != nil || version != 1 {
		t.Fatalf("rejection migrated version %d: %v", version, err)
	}
	for _, table := range []string{"local_tunnels", "webhook_owners"} {
		if err := raw.QueryRowContext(t.Context(), `SELECT count(*) FROM pragma_table_xinfo(?) WHERE name = 'integration_group' AND hidden = 2`, table).Scan(&projections); err != nil || projections != 1 {
			t.Fatalf("rejection changed %s's generated column: %v", table, err)
		}
	}
}
