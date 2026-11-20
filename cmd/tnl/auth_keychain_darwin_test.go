package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestAuthKeychainFailurePrecedesBrowserChallenge(t *testing.T) {
	t.Setenv("TNL_STATE_KEYCHAIN", filepath.Join(t.TempDir(), "missing.keychain"))
	for _, command := range [][]string{{"auth", "login"}, {"auth", "login", "start"}} {
		root := filepath.Join(t.TempDir(), "state")
		args := append([]string{"--no-config"}, command...)
		args = append(args, "--server=https://must-not-contact.invalid", "--state-dir="+root, "--output=json")
		var stdout, stderr bytes.Buffer
		err := run(t.Context(), args, &stdout, &stderr)
		if failure.KnownCase(err) != "keychain-unavailable" {
			t.Fatalf("login reached authentication instead of failing on Keychain selection: %v", err)
		}
		if stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatal("login emitted a browser challenge before client-state preflight")
		}
		if _, err := os.Stat(clientstate.DatabasePath(root)); !os.IsNotExist(err) {
			t.Fatal("failed preflight initialized client state", err)
		}
	}
}
