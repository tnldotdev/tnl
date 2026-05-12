package clientstate

import (
	"path/filepath"
	"testing"
)

func TestSavedServer(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	database, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, found, err := database.SavedServer(t.Context()); err != nil || found {
		t.Fatalf("empty saved server = %t, %v", found, err)
	}
	if err := database.SaveServer(t.Context(), "https://TNL.EXAMPLE:443/"); err != nil {
		t.Fatal(err)
	}
	server, found, err := database.SavedServer(t.Context())
	if err != nil || !found || server != "https://tnl.example" {
		t.Fatalf("saved server = %q, %t, %v", server, found, err)
	}
}

func TestCanonicalServerRejectsNonOrigins(t *testing.T) {
	for _, value := range []string{
		"http://tnl.example",
		"https://user@tnl.example",
		"https://tnl.example/path",
		"https://tnl.example?query=true",
	} {
		if _, err := CanonicalServer(value); err == nil {
			t.Fatalf("CanonicalServer(%q) succeeded", value)
		}
	}
}
