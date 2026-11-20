package state

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestMain(m *testing.M) {
	UseMemoryKeychainForTesting()
	os.Exit(m.Run())
}

func TestKeychainMissingKeyNeverRegeneratedForExistingDatabase(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	database, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	root = database.Root()
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(root))
	account := hex.EncodeToString(digest[:])
	mock := memoryKeychain.Load()
	mock.mu.Lock()
	delete(mock.values, keychainService+"\x00"+account)
	mock.mu.Unlock()
	if database, err := Open(t.Context(), root); err == nil {
		database.Close()
		t.Fatal("missing Keychain key accepted")
	}
	if _, err := mock.get(keychainService, account); err != keyring.ErrNotFound {
		t.Fatalf("missing key was regenerated: %v", err)
	}
}

func TestSelectedKeychainRejectsUnsafeOrMissingPathsWithoutDefaultFallback(t *testing.T) {
	for name, selected := range map[string]string{
		"empty":     "",
		"relative":  "relative.keychain",
		"newline":   "/private/test\nkeychain",
		"carriage":  "/private/test\rkeychain",
		"missing":   filepath.Join(t.TempDir(), "missing.keychain"),
		"directory": t.TempDir(),
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("TNL_STATE_KEYCHAIN", selected)
			root := filepath.Join(t.TempDir(), "state")
			if database, err := Open(t.Context(), root); err == nil {
				database.Close()
				t.Fatal("invalid selected Keychain fell back to default protection")
			}
			if _, err := os.Stat(DatabasePath(root)); !os.IsNotExist(err) {
				t.Fatal("failed Keychain selection initialized client state", err)
			}
		})
	}
}
