package clientstate

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/opaqueid"
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
	if first != second || !opaqueid.Valid(first, opaqueid.InstallationPrefix) {
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

func TestWorktreeHashSaltIsStableAndPrivateToState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	database, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	first, err := database.WorktreeHashSalt(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	second, err := reopened.WorktreeHashSalt(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	other, err := Open(t.Context(), filepath.Join(t.TempDir(), "other-state"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	third, err := other.WorktreeHashSalt(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first == third || bytes.Equal(first[:], make([]byte, len(first))) {
		t.Fatalf("worktree hash salts are not stable and state-specific")
	}
}

func TestWorktreeHashSaltIsStableAcrossConcurrentDatabases(t *testing.T) {
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
		salt [worktreeHashSaltLength]byte
		err  error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, database := range []*Database{firstDatabase, secondDatabase} {
		go func() {
			<-start
			salt, err := database.WorktreeHashSalt(t.Context())
			results <- result{salt: salt, err: err}
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
	if first.salt != second.salt || bytes.Equal(first.salt[:], make([]byte, len(first.salt))) {
		t.Fatalf("concurrent worktree hash salts differ or are empty")
	}
}
