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

func TestInstallationIDIsStableAcrossConcurrentDatabases(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	firstDatabase, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer firstDatabase.Close()
	secondDatabase, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer secondDatabase.Close()

	type result struct {
		id  string
		err error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, database := range []*Database{firstDatabase, secondDatabase} {
		go func() {
			<-start
			id, err := database.InstallationID(t.Context())
			results <- result{id: id, err: err}
		}()
	}
	close(start)
	first := <-results
	second := <-results
	if first.err != nil {
		t.Fatal(first.err)
	}
	if second.err != nil {
		t.Fatal(second.err)
	}
	if first.id == "" || first.id != second.id {
		t.Fatalf("installation IDs = %q, %q", first.id, second.id)
	}
}
