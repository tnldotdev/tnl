package main

import (
	"os"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestMain(m *testing.M) {
	// routine tests must not read or create credentials in the user's Keychain.
	keyring.MockInit()
	// CLI tests opt into each setting explicitly.
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "TNL_") || strings.HasPrefix(name, "TNLD_") {
			if err := os.Unsetenv(name); err != nil {
				panic(err)
			}
		}
	}
	os.Exit(m.Run())
}
