package clientstate

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestMain(m *testing.M) {
	keyring.MockInit()
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
	if err := keyring.Delete(keychainService, account); err != nil {
		t.Fatal(err)
	}
	if database, err := Open(t.Context(), root); err == nil {
		database.Close()
		t.Fatal("missing Keychain key accepted")
	}
	if _, err := keyring.Get(keychainService, account); err != keyring.ErrNotFound {
		t.Fatalf("missing key was regenerated: %v", err)
	}
}
