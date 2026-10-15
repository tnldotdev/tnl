package clientstate

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var wrappingKeyCrashRoot = flag.String("tnl-wrapping-key-crash-root", "", "private state root for the wrapping-key crash helper")
var wrappingKeyCrashStage = flag.String("tnl-wrapping-key-crash-stage", "", "wrapping-key publication boundary for the crash helper")

const wrappingKeyCrashExit = 47

func lockKeyInitialization(t *testing.T, root string) *Lock {
	t.Helper()
	locks, err := privateSubdir(root, "locks")
	if err != nil {
		t.Fatal(err)
	}
	lock, err := openLockContext(t.Context(), filepath.Join(locks, "migrations.lock"), "initialization")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lock.Close() })
	return lock
}

func TestWrappingKeyPublicationCrashHelper(t *testing.T) {
	if *wrappingKeyCrashStage == "" {
		return
	}
	root, err := PrepareRoot(*wrappingKeyCrashRoot)
	if err != nil {
		t.Fatal(err)
	}
	lockKeyInitialization(t, root)
	key := bytes.Repeat([]byte{0x49}, wrappingKeySize)
	err = publishWrappingKey(root, key, func(stage wrappingKeyPublicationStage, file *os.File) error {
		if *wrappingKeyCrashStage == "partial" && stage == wrappingKeyCreated {
			if _, err := file.Write(key[:7]); err != nil {
				t.Fatal(err)
			}
			os.Exit(wrappingKeyCrashExit)
		}
		if string(stage) == *wrappingKeyCrashStage {
			os.Exit(wrappingKeyCrashExit)
		}
		return nil
	})
	t.Fatalf("crash boundary was not reached: %v", err)
}

func TestWrappingKeyPublicationSurvivesProcessExitBeforeDatabasePublish(t *testing.T) {
	for _, stage := range []string{"created", "partial", "written", "synced", "published", "durable"} {
		t.Run(stage, func(t *testing.T) {
			root, err := PrepareRoot(filepath.Join(t.TempDir(), "state"))
			if err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(t.Context(), executable,
				"-test.run=^TestWrappingKeyPublicationCrashHelper$",
				"-tnl-wrapping-key-crash-root="+root, "-tnl-wrapping-key-crash-stage="+stage)
			output, err := command.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != wrappingKeyCrashExit {
				t.Fatalf("crash helper: %v\n%s", err, output)
			}
			var expectedKey []byte
			if stage == "published" || stage == "durable" {
				expectedKey = bytes.Repeat([]byte{0x49}, wrappingKeySize)
			}
			assertUnpublishedDatabaseAndKey(t, root, expectedKey)
			assertFreshInitializationRecovers(t, root, expectedKey)
		})
	}
}

func TestWrappingKeyPublicationFailuresRemainRecoverable(t *testing.T) {
	for _, stage := range []string{"created", "partial", "write-error", "written", "sync-error", "synced", "close-error", "published", "durable"} {
		t.Run(stage, func(t *testing.T) {
			root, err := PrepareRoot(filepath.Join(t.TempDir(), "state"))
			if err != nil {
				t.Fatal(err)
			}
			lock := lockKeyInitialization(t, root)
			key := bytes.Repeat([]byte{0x37}, wrappingKeySize)
			injected := errors.New("publication interrupted")
			err = publishWrappingKey(root, key, func(observed wrappingKeyPublicationStage, file *os.File) error {
				if stage == "partial" && observed == wrappingKeyCreated {
					if _, err := file.Write(key[:7]); err != nil {
						return err
					}
					return injected
				}
				if stage == "write-error" && observed == wrappingKeyCreated || stage == "sync-error" && observed == wrappingKeyWritten || stage == "close-error" && observed == wrappingKeySynced {
					// closing at this boundary makes the next real write, sync,
					// or close fail instead of substituting a successful operation.
					return file.Close()
				}
				if string(observed) == stage {
					return injected
				}
				return nil
			})
			if err == nil {
				t.Fatal("injected publication failure succeeded")
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
			var expectedKey []byte
			if stage == "published" || stage == "durable" {
				expectedKey = key
			}
			assertUnpublishedDatabaseAndKey(t, root, expectedKey)
			assertFreshInitializationRecovers(t, root, expectedKey)
		})
	}
}

func TestWrappingKeyPublicationNeverReplacesCanonicalKey(t *testing.T) {
	root, err := PrepareRoot(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	lock := lockKeyInitialization(t, root)
	key := bytes.Repeat([]byte{0x12}, wrappingKeySize)
	if err := publishWrappingKey(root, key, nil); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(WrappingKeyPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if err := publishWrappingKey(root, bytes.Repeat([]byte{0x34}, wrappingKeySize), nil); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing canonical key was not refused: %v", err)
	}
	after, err := os.Lstat(WrappingKeyPath(root))
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("canonical key inode was replaced: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	assertUnpublishedDatabaseAndKey(t, root, key)
	assertFreshInitializationRecovers(t, root, key)
}

func TestPublishedWrappingKeySurvivesFailedDatabaseInitialization(t *testing.T) {
	root, err := PrepareRoot(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	lock := lockKeyInitialization(t, root)
	key, err := fileWrappingKey(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if database, err := initializeClientSQLite(t.Context(), DatabasePath(root), ProtectionFile, failedProtector{}); err == nil {
		database.Close()
		t.Fatal("failed database initialization succeeded")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	assertUnpublishedDatabaseAndKey(t, root, key)
	assertFreshInitializationRecovers(t, root, key)
}

func assertUnpublishedDatabaseAndKey(t *testing.T, root string, expectedKey []byte) {
	t.Helper()
	if _, err := os.Lstat(DatabasePath(root)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canonical database published before key initialization completed: %v", err)
	}
	key, err := os.ReadFile(WrappingKeyPath(root))
	if expectedKey == nil {
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("canonical key published before the synced key was complete: %v", err)
		}
		return
	}
	if err != nil || !bytes.Equal(key, expectedKey) {
		t.Fatalf("published wrapping key is incomplete or changed: %v", err)
	}
}

func assertFreshInitializationRecovers(t *testing.T, root string, expectedKey []byte) {
	t.Helper()
	database := openFileDatabase(t, root)
	key, err := os.ReadFile(WrappingKeyPath(root))
	if err != nil || len(key) != wrappingKeySize || expectedKey != nil && !bytes.Equal(key, expectedKey) {
		t.Fatalf("fresh initialization did not recover with a complete, stable key: %v", err)
	}
	if err := database.SavePublisherJobRegistry(t.Context(), []byte("private recovery value")); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openFileDatabase(t, root)
	value, found, err := reopened.PublisherJobRegistry(t.Context())
	if err != nil || !found || string(value) != "private recovery value" {
		t.Fatalf("recovered database could not reopen its encrypted state: %v, %v", found, err)
	}
}
