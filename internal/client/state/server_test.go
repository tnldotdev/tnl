package state

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
