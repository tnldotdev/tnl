package testutil

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// UseClientKeychain selects a disposable real keychain for native subprocess
// tests. register it before starting workers so their cleanup runs first.
func UseClientKeychain(t testing.TB) string {
	t.Helper()
	RequireTestTier(t, TestTierIntegration)
	preferences := keychainPreferences(t)
	// a private keychain outside Library/Keychains is not added to the search
	// list. never set the user's default keychain or replace their search list.
	path := filepath.Join(t.TempDir(), `tnl test's "private".keychain`)
	password := make([]byte, 32)
	if _, err := rand.Read(password); err != nil {
		t.Fatal("generate disposable Keychain password", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := os.Stat(path); err == nil {
			if err := exec.CommandContext(ctx, "/usr/bin/security", "delete-keychain", path).Run(); err != nil {
				t.Error("delete disposable Keychain", err)
			}
		} else if !os.IsNotExist(err) {
			t.Error("inspect disposable Keychain during cleanup", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Error("disposable Keychain still exists after cleanup", err)
		}
		if !bytes.Equal(preferences, keychainPreferences(t)) {
			t.Error("Keychain preferences changed during the test")
		}
	})
	securityFixtureCommand(t, "create-keychain", "-p", hex.EncodeToString(password), path)
	securityFixtureCommand(t, "set-keychain-settings", path)
	securityFixtureCommand(t, "unlock-keychain", "-p", hex.EncodeToString(password), path)
	if !bytes.Equal(preferences, keychainPreferences(t)) {
		t.Fatal("disposable Keychain setup changed Keychain preferences")
	}
	t.Setenv("TNL_STATE_KEYCHAIN", path)
	return path
}

func securityFixtureCommand(t testing.TB, arguments ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	operation := arguments[0]
	for i, argument := range arguments {
		if strings.ContainsAny(argument, "\x00\r\n") {
			t.Fatal("invalid disposable Keychain argument")
		}
		arguments[i] = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(argument) + `"`
	}
	command := exec.CommandContext(ctx, "/usr/bin/security", "-i")
	command.Stdin = strings.NewReader(strings.Join(arguments, " ") + "\n")
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		// security can echo failed commands. do not expose passwords from stdin.
		t.Fatalf("disposable Keychain %s failed: %v", operation, err)
	}
}

func keychainPreferences(t testing.TB) []byte {
	t.Helper()
	var snapshot []byte
	for _, operation := range []string{"default-keychain", "list-keychains"} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		output, err := exec.CommandContext(ctx, "/usr/bin/security", operation, "-d", "user").Output()
		cancel()
		if err != nil {
			t.Fatalf("read Keychain %s: %v", operation, err)
		}
		snapshot = append(snapshot, output...)
		snapshot = append(snapshot, 0)
	}
	return snapshot
}
