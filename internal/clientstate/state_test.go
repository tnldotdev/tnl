package clientstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
)

const testRouteID = "route_0123456789abcdef0123456789abcdef"

func TestStateRejectsSymlinksAndPublicFiles(t *testing.T) {
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "state")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), link); err == nil {
		t.Fatal("symlink state root accepted")
	}

	root := filepath.Join(parent, "private")
	database, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(DatabasePath(root))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode = %o", info.Mode().Perm())
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(DatabasePath(root), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), root); err == nil {
		t.Fatal("publicly readable database accepted")
	}
}

func TestStateLocksHostnameBeforeRouteTakeover(t *testing.T) {
	store := testStore(t, filepath.Join(t.TempDir(), "state"), "https://server.example")
	lock, err := store.LockHostname("route.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LockHostname("route.example"); !errors.Is(err, ErrLocked) {
		t.Fatalf("second hostname lock error = %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	lock, err = store.LockHostname("route.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStateDoesNotChmodAnExistingPublicRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), root); err == nil {
		t.Fatal("public state root accepted")
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("state root mode changed to %04o", info.Mode().Perm())
	}
}

func TestStateRejectsWritableAncestor(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), filepath.Join(parent, "state")); err == nil {
		t.Fatal("state root beneath writable ancestor accepted")
	}
}

func TestStateAllowsStickyWritableAncestor(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	database, err := Open(t.Context(), filepath.Join(parent, "state"))
	if err != nil {
		t.Fatal(err)
	}
	database.Close()
}

func TestControlSessionPersistsPrivatelyAndCanBeRemoved(t *testing.T) {
	store := testStore(t, filepath.Join(t.TempDir(), "state"), "https://server.example")
	token, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	want := ControlSession{
		AuthorityEndpoint: "https://accounts.example",
		SessionID:         "control_session_0123456789abcdef0123456789abcdef",
		AccessToken:       token.String(), AccessExpiresAt: time.Now().Add(time.Hour).UTC(),
		RefreshToken: refresh.String(), RefreshExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
	}
	if err := store.SaveControlSession(t.Context(), want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(DatabasePath(store.database.root))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("client database mode = %o", info.Mode().Perm())
	}
	got, found, err := store.ControlSession(t.Context())
	if err != nil || !found || got.AuthorityEndpoint != want.AuthorityEndpoint || got.SessionID != want.SessionID ||
		got.AccessToken != want.AccessToken || !got.AccessExpiresAt.Equal(want.AccessExpiresAt) ||
		got.RefreshToken != want.RefreshToken || !got.RefreshExpiresAt.Equal(want.RefreshExpiresAt) {
		t.Fatalf("control session = %#v, found = %v, error = %v", got, found, err)
	}
	if err := store.RemoveControlSession(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.ControlSession(t.Context()); err != nil || found {
		t.Fatalf("control session found after removal = %v, error = %v", found, err)
	}
}

func TestControlSessionLockSerializesUpdates(t *testing.T) {
	store := testStore(t, filepath.Join(t.TempDir(), "state"), "https://server.example")
	lock, err := store.LockControlSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LockControlSession(); !errors.Is(err, ErrLocked) {
		t.Fatalf("second control session lock error = %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	lock, err = store.LockControlSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentStoreInitialization(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	var wait sync.WaitGroup
	errorsFound := make(chan error, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			database, err := Open(t.Context(), root)
			if err == nil {
				_, err = database.Server(t.Context(), "https://server.example")
				err = errors.Join(err, database.Close())
			}
			errorsFound <- err
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestMigrationLockWaitCanBeCanceled(t *testing.T) {
	root, err := prepareRoot(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	locksDir, err := privateSubdir(root, "locks")
	if err != nil {
		t.Fatal(err)
	}
	lock, err := openLock(filepath.Join(locksDir, "migrations.lock"), "migration")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	if database, err := Open(ctx, root); database != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contending open = %v, %v", database, err)
	}
}

func testStore(t *testing.T, root, server string) *Store {
	t.Helper()
	database, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	store, err := database.Server(t.Context(), server)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
