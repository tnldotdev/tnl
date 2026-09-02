package clientstate

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallationIDIsStable(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	database, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	first, err := database.InstallationID(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	second, err := database.InstallationID(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(first) != len("installation_")+32 ||
		!strings.HasPrefix(first, "installation_") || first != strings.ToLower(first) {
		t.Fatalf("installation IDs = %q, %q", first, second)
	}
}
