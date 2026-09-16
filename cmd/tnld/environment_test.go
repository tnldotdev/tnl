package main

import (
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "TNLD_") || strings.HasPrefix(name, "TNL_") {
			if err := os.Unsetenv(name); err != nil {
				panic(err)
			}
		}
	}
	os.Exit(m.Run())
}
