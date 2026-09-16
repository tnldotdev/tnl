package main

import (
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	// CLI tests opt into each setting explicitly. Preserve only the subprocess
	// helper marker used by the process-group tests.
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if (strings.HasPrefix(name, "TNL_") || strings.HasPrefix(name, "TNLD_")) && name != "TNL_TEST_DEV_PROCESS_HELPER" {
			if err := os.Unsetenv(name); err != nil {
				panic(err)
			}
		}
	}
	os.Exit(m.Run())
}
