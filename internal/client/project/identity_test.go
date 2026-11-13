package project

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLocalPublicationIdentityIsIndependentOfGitBoundary(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "app")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "tnl.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"tnl":{"services":{"web":{}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	resolve := func() Project {
		p, err := Resolve(t.Context(), Selection{Path: path}, root, [32]byte{})
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
	for step, args := range [][]string{
		{"init", "--quiet", parent},
		{"-C", parent, "remote", "add", "origin", "https://example.test/one.git"},
		{"-C", parent, "remote", "set-url", "origin", "https://example.test/two.git"},
	} {
		if out, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git: %v %s", err, out)
		}
		after := resolve()
		check(after)
		if step == 0 {
			if _, err := after.SourceIdentity(t.Context()); err == nil {
				t.Fatal("portable identity accepted missing origin")
			}
		}
	}
	other := Project{Root: parent}
	if other.LocalPublicationIdentity() == before.LocalPublicationIdentity() {
		t.Fatal("different project directories shared local identity")
	}
}
