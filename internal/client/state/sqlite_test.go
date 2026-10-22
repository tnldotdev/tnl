package state

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"modernc.org/sqlite"
)

type failedProtector struct{}

func (failedProtector) Seal(context.Context, string, []byte) ([]byte, error) {
	return nil, errors.New("sealing failed")
}
func (failedProtector) Open(context.Context, string, []byte) ([]byte, error) {
	return nil, errors.New("opening failed")
}

func TestFreshInitializationDoesNotPublishPartialDatabase(t *testing.T) {
	root, err := PrepareRoot(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	if database, err := initializeClientSQLite(t.Context(), DatabasePath(root), ProtectionFile, failedProtector{}); err == nil {
		database.Close()
		t.Fatal("failed secret initialization succeeded")
	}
	if _, err := os.Lstat(DatabasePath(root)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial canonical database was published: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed initialization left temporary files: %#v, %v", entries, err)
	}
	database := openFileDatabase(t, root)
	if _, err := database.ReadRuntimeSnapshot(t.Context(), t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteSettingsSurviveConnectionReplacement(t *testing.T) {
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	// discard idle connections so every subsequent operation uses a new one.
	database.db.SetMaxIdleConns(0)
	for _, test := range []struct {
		pragma string
		want   int
	}{{"foreign_keys", 1}, {"busy_timeout", 5000}} {
		var value int
		if err := database.db.QueryRowContext(t.Context(), "PRAGMA "+test.pragma).Scan(&value); err != nil || value != test.want {
			t.Fatalf("%s after replacement: %d, %v", test.pragma, value, err)
		}
	}
	var mode string
	if err := database.db.QueryRowContext(t.Context(), "PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal mode: %q, %v", mode, err)
	}
}

var sqliteWriterRoot = flag.String("tnl-sqlite-writer-root", "", "client state root for the SQLite writer subprocess")
var sqliteWriterBlocked = flag.Bool("tnl-sqlite-writer-blocked", false, "require the SQLite writer subprocess to encounter a live write lock")
var sqliteWriterWorker = flag.String("tnl-sqlite-writer-worker", "", "worker name for concurrent SQLite writes")
var sqliteWriterRounds = flag.Int("tnl-sqlite-writer-rounds", 0, "number of concurrent SQLite open/write/close rounds")

func TestSQLiteWriterProcess(t *testing.T) {
	if *sqliteWriterRoot == "" {
		t.Skip("requires a client state root from the parent test")
	}
	if *sqliteWriterRounds != 0 {
		if err := sqliteConcurrentWrites(t.Context(), *sqliteWriterRoot, *sqliteWriterWorker, *sqliteWriterRounds); err != nil {
			t.Fatal(err)
		}
		return
	}
	database := openFileDatabase(t, *sqliteWriterRoot)
	if _, err := database.db.ExecContext(t.Context(), "PRAGMA busy_timeout=0"); err != nil {
		t.Fatal(err)
	}
	tx, err := database.db.BeginTx(t.Context(), nil)
	if *sqliteWriterBlocked {
		if err == nil {
			tx.Rollback()
			t.Fatal("another process acquired the SQLite write lock while the parent transaction was live")
		}
		var sqliteErr *sqlite.Error
		if !errors.As(err, &sqliteErr) || sqliteErr.Code()&0xff != 5 {
			t.Fatalf("contending writer: %v; want SQLITE_BUSY", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(t.Context(), "INSERT INTO write_lock_probe (value) VALUES ('child')"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func sqliteWriterProbe(t *testing.T, root string, blocked bool) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-test.run=^TestSQLiteWriterProcess$", "-test.timeout=30s", "-tnl-sqlite-writer-root=" + root}
	if blocked {
		args = append(args, "-tnl-sqlite-writer-blocked")
	}
	if output, err := exec.CommandContext(t.Context(), executable, args...).CombinedOutput(); err != nil {
		t.Fatalf("SQLite writer subprocess: %v\n%s", err, output)
	}
}

func TestSQLiteOpenPreservesLiveWriteLock(t *testing.T) {
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	if _, err := database.db.ExecContext(t.Context(), "CREATE TABLE write_lock_probe (value TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	tx, err := database.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(t.Context(), "INSERT INTO write_lock_probe (value) VALUES ('parent')"); err != nil {
		t.Fatal(err)
	}
	// a separate process is essential: sqlite also tracks locks in process-local
	// memory, which can hide a lost posix lock from another same-process handle.
	sqliteWriterProbe(t, database.Root(), true)
	second := openFileDatabase(t, database.Root())
	sqliteWriterProbe(t, database.Root(), true)
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	sqliteWriterProbe(t, database.Root(), true)
	// a rejected open must also leave the first handle's locks intact.
	shm := DatabasePath(database.Root()) + "-shm"
	if err := os.Chmod(shm, 0o644); err != nil {
		t.Fatal(err)
	}
	rejected, openErr := OpenWithOptions(t.Context(), database.Root(), OpenOptions{Protection: ProtectionFile})
	if err := os.Chmod(shm, 0o600); err != nil {
		t.Fatal(err)
	}
	if openErr == nil {
		rejected.Close()
		t.Fatal("publicly readable shared memory accepted")
	}
	sqliteWriterProbe(t, database.Root(), true)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	sqliteWriterProbe(t, database.Root(), false)
	var count int
	if err := database.db.QueryRowContext(t.Context(), "SELECT count(*) FROM write_lock_probe").Scan(&count); err != nil || count != 2 {
		t.Fatalf("committed writes: %d, %v", count, err)
	}
}

func TestSQLiteRejectsUnsafeDatabaseFiles(t *testing.T) {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		for _, mutation := range []string{"public", "symlink", "directory", "owner"} {
			t.Run("db"+suffix+"/"+mutation, func(t *testing.T) {
				if mutation == "owner" && os.Geteuid() != 0 {
					t.Skip("changing file ownership requires root")
				}
				database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
				root := database.Root()
				if err := database.Close(); err != nil {
					t.Fatal(err)
				}
				path := DatabasePath(root) + suffix
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				switch mutation {
				case "public", "owner":
					if err := os.WriteFile(path, nil, 0o600); err != nil {
						t.Fatal(err)
					}
					if mutation == "public" {
						if err := os.Chmod(path, 0o644); err != nil {
							t.Fatal(err)
						}
					} else if err := os.Chown(path, 1, -1); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					target := filepath.Join(t.TempDir(), "target")
					if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, path); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						data, err := os.ReadFile(target)
						if err != nil || string(data) != "untouched" {
							t.Errorf("symlink target changed: %v", err)
						}
					})
				case "directory":
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				before, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				reopened, openErr := OpenWithOptions(t.Context(), root, OpenOptions{Protection: ProtectionFile})
				if openErr == nil {
					reopened.Close()
					t.Fatal("unsafe database file accepted")
				}
				want := "not a real private file"
				if mutation == "public" {
					want = "permissions are 0644, want 0600"
				} else if mutation == "owner" {
					want = "not owned by the current user"
				}
				if !strings.Contains(openErr.Error(), want) {
					t.Fatalf("unsafe database file error = %v; want %q", openErr, want)
				}
				after, err := os.Lstat(path)
				if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
					t.Fatalf("unsafe database file replaced or permissions changed: %v", err)
				}
			})
		}
	}
}

func sqliteConcurrentWrites(ctx context.Context, root, worker string, rounds int) error {
	for sequence := range rounds {
		err := func() error {
			database, err := OpenWithOptions(ctx, root, OpenOptions{Protection: ProtectionFile})
			if err != nil {
				return err
			}
			defer database.Close()
			tx, err := database.db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			if _, err := tx.ExecContext(ctx, "UPDATE write_lock_count SET value = value + 1"); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO write_lock_probe (worker, sequence, payload) VALUES (?, ?, ?)", worker, sequence, strings.Repeat("x", 4096)); err != nil {
				return err
			}
			return tx.Commit()
		}()
		if err != nil {
			return fmt.Errorf("worker %s round %d: %w", worker, sequence, err)
		}
	}
	return nil
}

func TestSQLiteConcurrentOpenWriteCloseProcesses(t *testing.T) {
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	for _, query := range []string{
		"CREATE TABLE write_lock_probe (worker TEXT NOT NULL, sequence INTEGER NOT NULL, payload TEXT NOT NULL, PRIMARY KEY (worker, sequence))",
		"CREATE TABLE write_lock_count (value INTEGER NOT NULL)",
		"INSERT INTO write_lock_count (value) VALUES (0)",
	} {
		if _, err := database.db.ExecContext(t.Context(), query); err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const goroutines, processes, rounds = 8, 3, 20
	results := make(chan error, goroutines+processes)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for worker := range goroutines + processes {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			name := fmt.Sprintf("worker-%d", worker)
			if worker < goroutines {
				results <- sqliteConcurrentWrites(t.Context(), database.Root(), name, rounds)
				return
			}
			args := []string{"-test.run=^TestSQLiteWriterProcess$", "-test.timeout=2m", "-tnl-sqlite-writer-root=" + database.Root(), "-tnl-sqlite-writer-worker=" + name, fmt.Sprintf("-tnl-sqlite-writer-rounds=%d", rounds)}
			output, err := exec.CommandContext(t.Context(), executable, args...).CombinedOutput()
			if err != nil {
				err = fmt.Errorf("SQLite writer subprocess: %w\n%s", err, output)
			}
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Error(err)
		}
	}
	var count, updates int
	if err := database.db.QueryRowContext(t.Context(), "SELECT count(*) FROM write_lock_probe WHERE sequence >= 0 AND sequence < ? AND length(payload) = 4096", rounds).Scan(&count); err != nil || count != (goroutines+processes)*rounds {
		t.Errorf("committed rows: %d, %v", count, err)
	}
	if err := database.db.QueryRowContext(t.Context(), "SELECT value FROM write_lock_count").Scan(&updates); err != nil || updates != count {
		t.Errorf("atomic counter: %d; committed rows: %d, %v", updates, count, err)
	}
	var integrity string
	if err := database.db.QueryRowContext(t.Context(), "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		t.Errorf("database integrity: %q, %v", integrity, err)
	}
}
