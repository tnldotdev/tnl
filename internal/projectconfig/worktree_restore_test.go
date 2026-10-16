package projectconfig

import "testing"

func TestRestoreHostWorktreePreservesUntruncatedServiceLabels(t *testing.T) {
	host := Worktree{Root: "/host/checkout", Name: "checkout", IsGit: true, primaryRoot: "/host/primary"}
	host = ApplyWorktreeHashSalt(host, "/host/checkout/apps/web", [32]byte{1})
	// simulate the JSON boundary: the unexported label parts and primary root
	// do not travel into the owner container.
	serialized := Worktree{Root: host.Root, Name: host.Name, IsGit: host.IsGit, Label: host.Label}
	restored, err := RestoreHostWorktree(serialized, "/host/checkout/apps/web", "/host/primary")
	if err != nil {
		t.Fatal(err)
	}
	if restored.PrimaryCheckoutRoot() != host.PrimaryCheckoutRoot() || ServiceWorktreeLabel("service", restored) != ServiceWorktreeLabel("service", host) {
		t.Fatal("owner changed host service hostname identity")
	}
	serialized.Label.FullLabel = "different"
	if _, err := RestoreHostWorktree(serialized, "/host/checkout/apps/web", "/host/primary"); err == nil {
		t.Fatal("owner accepted mismatched host label")
	}
}
