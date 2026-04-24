package clientstate

import (
	"path/filepath"
	"testing"
)

func TestSavedServer(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if _, found, err := SavedServer(root); err != nil || found {
		t.Fatalf("empty saved server = %t, %v", found, err)
	}
	if err := SaveServer(root, "https://TNL.EXAMPLE:443/"); err != nil {
		t.Fatal(err)
	}
	server, found, err := SavedServer(root)
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
