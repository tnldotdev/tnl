package init

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitGitignoreWithoutRepositoryAndWithNegations(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	path := filepath.Join(root, ".gitignore")
	if err := os.WriteFile(path, []byte(".tnl/*\n!.tnl/*\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureTnlGitignore(root); err != nil {
		t.Fatal(err)
	}
	if actions := projectGitignoreActions(t.Context(), root); len(actions) != 0 {
		t.Fatalf("trackable files diagnosed as ignored: %v", actions)
	}
	if _, err := os.Stat(filepath.Join(root, ".git")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created project Git state: %v", err)
	}
	if err := os.WriteFile(path, []byte("/.tnl/local/\n!/.tnl/local/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if actions := projectGitignoreActions(t.Context(), root); len(actions) == 0 || !strings.Contains(actions[0], "not ignored") {
		t.Fatalf("local negation not diagnosed: %v", actions)
	}
}
