package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/zalando/go-keyring"
)

var keychainStateRoot = flag.String("tnl-keychain-state", "", "private state directory for the Keychain reopen subprocess")

func TestIntegrationKeychainStateAcrossProcesses(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if *keychainStateRoot != "" {
		assertKeychainReopen(t, *keychainStateRoot)
		return
	}
	keychain := testutil.UseClientKeychain(t)
	root := filepath.Join(t.TempDir(), "state")
	database, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Error("close Keychain test state", err)
		}
	})
	root = database.Root()
	if err := database.SavePublisherJobRegistry(t.Context(), []byte("test credential")); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(WrappingKeyPath(root)); !os.IsNotExist(err) {
		t.Fatal("Keychain state wrote a file wrapping key", err)
	}
	// use the same test executable, but a new process with its own library mock.
	// only the explicitly selected real keychain can reopen the encrypted state.
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestIntegrationKeychainStateAcrossProcesses$", "-test.v", "-tnl-test-tier=integration", "-tnl-keychain-state="+root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("reopen Keychain state in subprocess: %v\n%s", err, output)
	}
	t.Run("different-keychain", func(t *testing.T) {
		testutil.UseClientKeychain(t)
		if reopened, err := Open(t.Context(), root); !errors.Is(err, keyring.ErrNotFound) {
			if reopened != nil {
				reopened.Close()
			}
			t.Fatal("another Keychain did not fail with its missing wrapping key", err)
		}
	})
	digest := sha256.Sum256([]byte(root))
	account := hex.EncodeToString(digest[:])
	securityFixtureDelete := exec.CommandContext(t.Context(), "/usr/bin/security", "delete-generic-password", "-s", keychainService, "-a", account, keychain)
	if err := securityFixtureDelete.Run(); err != nil {
		t.Fatal("delete test wrapping key", err)
	}
	if reopened, err := Open(t.Context(), root); !errors.Is(err, keyring.ErrNotFound) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatal("deleted Keychain wrapping key did not fail as missing", err)
	}
	if _, err := namedKeychainGet(t.Context(), keychain, keychainService, account); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatal("missing wrapping key was recreated or its lookup failed", err)
	}
}

func assertKeychainReopen(t *testing.T, root string) {
	t.Helper()
	if _, selected := os.LookupEnv("TNL_STATE_KEYCHAIN"); !selected {
		t.Fatal("Keychain subprocess requires an explicitly selected disposable Keychain")
	}
	database, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Error("close subprocess Keychain state", err)
		}
	})
	value, found, err := database.PublisherJobRegistry(t.Context())
	if err != nil || !found || !bytes.Equal(value, []byte("test credential")) {
		t.Fatal("subprocess did not decrypt the saved credential", err)
	}
}
