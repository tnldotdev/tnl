package main

import "testing"

// the production command must supply the authority without test-only injection.
func TestNativePublicationProductionAuthorityComposition(t *testing.T) {
	settings := (runtimeOptions{Directory: t.TempDir(), StateDir: t.TempDir()}).settings()
	if settings.ApplicationAuthority == nil {
		t.Fatal("runtime serve production settings omit ApplicationAuthority; /v1/publications cannot reach machine-publication exchange")
	}
}
