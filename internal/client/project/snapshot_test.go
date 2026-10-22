package projectconfig

import (
	"bytes"
	"os"
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

func TestSnapshotPreservesEvaluatedInspection(t *testing.T) {
	for _, file := range []struct{ name, source string }{
		{"tnl.json", `{"version":1,"tnl":{"inspection":{"retention":"24h","max_bytes":"64MiB"},"services":{"web":{"inspection":{"max_bytes":"1025KiB"}}}}}`},
		{"tnl.config.ts", `export default () => ({inspection: {retention: "24h", maxBytes: "64MiB"}, services: {web: {inspection: {maxBytes: "1025KiB"}}}});`},
	} {
		t.Run(file.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, file.name)
			if err := os.WriteFile(path, []byte(file.source), 0600); err != nil {
				t.Fatal(err)
			}
			project, err := Resolve(t.Context(), Selection{Path: path}, root, [32]byte{})
			if err != nil {
				t.Fatal(err)
			}
			encoded, digest, err := project.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			restored, err := ReadSnapshot(bytes.NewReader(encoded))
			if err != nil {
				t.Fatal(err)
			}
			again, restoredDigest, err := restored.Snapshot()
			if err != nil || !bytes.Equal(encoded, again) || digest != restoredDigest {
				t.Fatalf("evaluated snapshot changed: %v", err)
			}
			static, err := restored.StaticMap()
			if err != nil {
				t.Fatal(err)
			}
			if got := static["inspection"].(map[string]any)["max_bytes"]; got != "64MiB" {
				t.Fatalf("static byte-size contract changed: %v", got)
			}
		})
	}
}

func TestSnapshotUsesCanonicalSelectedProjectDirectory(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "project")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tnl.json"), []byte(`{"version":1,"tnl":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	selection, err := SelectProjectConfig(t.Context(), alias, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	project, err := Resolve(t.Context(), selection, alias, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _, err := project.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := ReadSnapshot(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if restored.Root != root || filepath.Dir(restored.Selection.Path) != root {
		t.Fatalf("owner receives noncanonical project directory: root=%q selection=%q", restored.Root, restored.Selection.Path)
	}
}
