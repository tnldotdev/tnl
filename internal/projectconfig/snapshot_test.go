package projectconfig

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestSnapshotPreservesEvaluatedConfigurationAndPrimaryCheckout(t *testing.T) {
	root := t.TempDir()
	address := config.Target("3000")
	project := Project{Root: root, Selection: Selection{Path: filepath.Join(root, "selected.config.ts")}, Worktree: Worktree{Root: root, primaryRoot: filepath.Dir(root)}, Config: config.TNL{Services: config.Services{
		"web": {Tunnel: &config.Tunnel{Access: &config.Access{Mode: "anonymous"}}, Target: &config.ServiceTarget{Type: "address", Address: &address}, HTTP: &config.HTTPService{Readiness: &config.Readiness{Path: "/health"}}},
	}}}
	project.Worktree = ApplyWorktreeHashSalt(project.Worktree, root, [32]byte{})
	encoded, digest, err := project.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := ReadSnapshot(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	again, restoredDigest, err := restored.Snapshot()
	if err != nil || !bytes.Equal(encoded, again) || digest != restoredDigest || restored.Worktree.PrimaryCheckoutRoot() != project.Worktree.PrimaryCheckoutRoot() {
		t.Fatalf("selected snapshot changed in transit: %v", err)
	}
	if got, want := ServiceWorktreeLabel("web", restored.Worktree), ServiceWorktreeLabel("web", project.Worktree); got != want {
		t.Fatalf("owner selected another hostname: %q, want %q", got, want)
	}
}
