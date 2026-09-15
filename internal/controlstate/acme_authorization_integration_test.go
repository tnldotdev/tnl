package controlstate_test

import (
	"database/sql"
	"os"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationControlStateMigrationUpgrade(t *testing.T) {
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "controlstate_acme_authorization_upgrade")
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(t.Context(), "CREATE SCHEMA control"); err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, os.DirFS("migrations"),
		goose.WithTableName("control.goose_db_version"), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if old, err := controlstate.Open(t.Context(), databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ""); err == nil {
		old.Close()
		t.Fatal("Open accepted the old schema without a migration")
	}
	for range 2 {
		if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
			t.Fatal(err)
		}
	}
	database, err := controlstate.Open(t.Context(), databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	if err := database.Readiness(t.Context()); err != nil {
		t.Fatal(err)
	}
	var version int64
	if err := db.QueryRowContext(t.Context(), "SELECT max(version_id) FROM control.goose_db_version WHERE is_applied").Scan(&version); err != nil || version != 3 {
		t.Fatalf("upgraded schema version = %d, %v", version, err)
	}
}
