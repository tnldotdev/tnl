package projectconfig

import (
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
	for step, args := range [][]string{
		{"init", "--quiet", parent},
		{"-C", parent, "remote", "add", "origin", "https://example.test/one.git"},
		{"-C", parent, "remote", "set-url", "origin", "https://example.test/two.git"},
	} {
		if out, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git: %v %s", err, out)
		}
		after := resolve()
		if after.LocalPublicationIdentity() != before.LocalPublicationIdentity() || after.LocalWorktreeKey() != before.LocalWorktreeKey() {
			t.Fatal("Git boundary changed local publication identity")
		}
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

func TestRemoteIdentityIgnoresTransportAndCredentials(t *testing.T) {
	for _, remote := range []string{"git@github.com:tnldotdev/tnl.git", "ssh://git@github.com/tnldotdev/tnl.git", "https://user:secret@GitHub.com/tnldotdev/tnl/"} {
		got, err := NormalizeGitRemote(remote)
		if err != nil || got != "github.com/tnldotdev/tnl" {
			t.Fatalf("remote = %q: %v", got, err)
		}
	}
	for _, remote := range []string{"/Users/user/repo", "../repo", "file:///tmp/repo", "https://github.com/org/repo?token=secret", "https://github.com/org/../repo"} {
		if _, err := NormalizeGitRemote(remote); err == nil {
			t.Fatalf("accepted nonportable remote %q", remote)
		}
	}
}
