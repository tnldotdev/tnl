package project

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
)

func TestLocalPublicationIdentityIgnoresGitOrigin(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "app")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "tnl.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"tnl":{"services":{"web":{}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(t.Context(), "git", "init", "--quiet", parent).CombinedOutput(); err != nil {
		t.Fatalf("git: %v %s", err, out)
	}
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	resolve := func() Project {
		p, err := Resolve(t.Context(), Selection{Path: path}, root, [32]byte{})
		if err != nil {
			t.Fatal(err)
		}
		p, err = p.BindLocalIdentity(t.Context(), state)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	before := resolve()
	check := func(after Project) {
		t.Helper()
		encoded, _, err := after.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		transferred, err := ReadSnapshot(bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		for _, selected := range []Project{after, transferred} {
			if selected.LocalPublicationIdentity() != before.LocalPublicationIdentity() || selected.LocalWorktreeKey() != before.LocalWorktreeKey() {
				t.Fatal("Git boundary or snapshot transfer changed local publication identity")
			}
		}
		if transferred.Worktree.Label != after.Worktree.Label {
			t.Fatal("snapshot transfer changed the selected hostname label")
		}
	}
	check(before)
	for _, args := range [][]string{
		{"-C", parent, "remote", "add", "origin", "https://example.test/one.git"},
		{"-C", parent, "remote", "set-url", "origin", "https://example.test/two.git"},
	} {
		if out, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git: %v %s", err, out)
		}
		after := resolve()
		check(after)
	}
	other, err := (Project{Root: parent}).BindLocalIdentity(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	if other.LocalPublicationIdentity() == before.LocalPublicationIdentity() {
		t.Fatal("different project directories shared local identity")
	}
}

func TestLocalCheckoutIdentitySurvivesMoveButNotRecreation(t *testing.T) {
	parent := t.TempDir()
	main, perf, moved := filepath.Join(parent, "zelda"), filepath.Join(parent, "perf"), filepath.Join(parent, "faster")
	git := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	git("init", "-q", main)
	git("-C", main, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-qm", "initial")
	git("-C", main, "worktree", "add", "-q", "--detach", perf)
	store, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(parent, "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key := func(root string) string {
		t.Helper()
		tree, err := ResolveWorktree(t.Context(), root)
		if err != nil {
			t.Fatal(err)
		}
		p, err := (Project{Root: root, Worktree: tree}).BindLocalIdentity(t.Context(), store)
		if err != nil {
			t.Fatal(err)
		}
		return p.LocalWorktreeKey()
	}
	first := key(perf)
	git("-C", main, "worktree", "move", perf, moved)
	if got := key(moved); got != first {
		t.Fatal("moving the same checkout changed its identity")
	}
	git("-C", main, "worktree", "remove", moved)
	git("-C", main, "worktree", "add", "-q", "--detach", perf)
	if got := key(perf); got == first {
		t.Fatal("a fresh worktree inherited the old checkout identity")
	}
}
