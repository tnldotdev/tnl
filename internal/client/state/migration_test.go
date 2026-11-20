package state

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestMigrationOneIsImmutable(t *testing.T) {
	data, err := migrationFiles.ReadFile("migrations/00001_schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	// pinned schema after the explicitly approved prerelease reset in #791.
	const want = "4d829fce7ff5cabed747c9b05333eb7508c5d9fd09dded6a4327961c1b55afbc"
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
		t.Fatalf("migration 1 changed: SHA-256 = %s, want %s; add a numbered migration unless a schema reset is explicitly approved", got, want)
	}
}

func TestClientMigrationsPreserveProtectedState(t *testing.T) {
	for _, skipRelease := range []bool{false, true} {
		t.Run(fmt.Sprintf("skip_release=%t", skipRelease), func(t *testing.T) {
			ctx := t.Context()
			database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
			document := []byte("saved publisher jobs")
			if err := database.SavePublisherJobRegistry(ctx, document); err != nil {
				t.Fatal(err)
			}
			var ciphertext []byte
			if err := database.db.QueryRowContext(ctx, `SELECT jobs_ciphertext FROM publisher_job_registry`).Scan(&ciphertext); err != nil {
				t.Fatal(err)
			}
			key, err := os.ReadFile(WrappingKeyPath(database.Root()))
			if err != nil {
				t.Fatal(err)
			}
			statements := []string{
				`ALTER TABLE publisher_job_registry ADD COLUMN label TEXT NOT NULL DEFAULT '';`,
				`UPDATE publisher_job_registry SET label='migrated';`,
			}
			if !skipRelease {
				if err := migrateClientSQLite(ctx, database.db, clientMigrationFixture(t, statements[:1]...), schemaVersion+1); err != nil {
					t.Fatal(err)
				}
			}
			migrations := clientMigrationFixture(t, statements...)
			for range 2 {
				if err := migrateClientSQLite(ctx, database.db, migrations, schemaVersion+2); err != nil {
					t.Fatal(err)
				}
				got, found, err := database.PublisherJobRegistry(ctx)
				if err != nil || !found || !bytes.Equal(got, document) {
					t.Fatalf("migration lost saved publisher jobs: found=%t, %v", found, err)
				}
				var preserved []byte
				var label string
				if err := database.db.QueryRowContext(ctx, `SELECT jobs_ciphertext, label FROM publisher_job_registry`).Scan(&preserved, &label); err != nil || !bytes.Equal(ciphertext, preserved) || label != "migrated" {
					t.Fatal("migration did not preserve protected state and apply the backfill", err)
				}
				if got, err := os.ReadFile(WrappingKeyPath(database.Root())); err != nil || !bytes.Equal(got, key) {
					t.Fatal("migration changed the wrapping key", err)
				}
			}
			if err := database.SavePublisherJobRegistry(ctx, []byte("updated publisher jobs")); err != nil {
				t.Fatal("migrated state no longer accepts writes", err)
			}
		})
	}
}

func TestClientMigrationFailureRollsBack(t *testing.T) {
	ctx := t.Context()
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	migrations := clientMigrationFixture(t, `
		ALTER TABLE publisher_job_registry ADD COLUMN label TEXT;
		UPDATE missing_table SET label='failed';
	`)
	if err := migrateClientSQLite(ctx, database.db, migrations, schemaVersion+1); err == nil {
		t.Fatal("invalid migration succeeded")
	}
	if err := checkClientSchemaVersion(ctx, database.db, schemaVersion); err != nil {
		t.Fatal("failed migration advanced the schema version", err)
	}
	var columns int
	if err := database.db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('publisher_job_registry') WHERE name='label'`).Scan(&columns); err != nil || columns != 0 {
		t.Fatal("failed migration left a partial schema change", columns, err)
	}
}

func TestClientStateRejectsNewerSchemaWithoutReplacingIt(t *testing.T) {
	ctx := t.Context()
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	root := database.Root()
	if _, err := database.db.ExecContext(ctx, `INSERT INTO goose_db_version (version_id, is_applied) VALUES (?, 1)`, schemaVersion+1); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(DatabasePath(root))
	if err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenWithOptions(ctx, root, OpenOptions{Protection: ProtectionFile}); err == nil {
		reopened.Close()
		t.Fatal("newer schema accepted")
	} else if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ClientStateUnavailable {
		t.Fatalf("schema failure lost its classification: %v", err)
	}
	if reader, err := openReadOnlySQLite(ctx, DatabasePath(root)); err == nil {
		reader.Close()
		t.Fatal("read-only state accepted a newer schema")
	}
	after, err := os.Stat(DatabasePath(root))
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("schema rejection replaced the database", err)
	}
	if err := checkClientSchemaVersion(ctx, database.db, schemaVersion+1); err != nil {
		t.Fatal("schema rejection changed the migration history", err)
	}
}

func TestReadOnlyClientStateDoesNotMigrate(t *testing.T) {
	ctx := t.Context()
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	if _, err := database.db.ExecContext(ctx, `DELETE FROM goose_db_version WHERE version_id > 0`); err != nil {
		t.Fatal(err)
	}
	if reader, err := openReadOnlySQLite(ctx, DatabasePath(database.Root())); err == nil {
		reader.Close()
		t.Fatal("read-only state accepted an older schema")
	}
	if err := checkClientSchemaVersion(ctx, database.db, 0); err != nil {
		t.Fatal("read-only open changed the migration history", err)
	}
}

func clientMigrationFixture(t *testing.T, statements ...string) fstest.MapFS {
	t.Helper()
	files, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	migrations := fstest.MapFS{}
	for _, file := range files {
		data, err := migrationFiles.ReadFile("migrations/" + file.Name())
		if err != nil {
			t.Fatal(err)
		}
		migrations[file.Name()] = &fstest.MapFile{Data: data}
	}
	for i, statement := range statements {
		name := fmt.Sprintf("%05d_test.sql", schemaVersion+int64(i)+1)
		migrations[name] = &fstest.MapFile{Data: []byte("-- +goose Up\n" + statement + "\n")}
	}
	return migrations
}
