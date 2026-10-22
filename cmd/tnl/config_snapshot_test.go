package main

import (
	"os"
	"path/filepath"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
)

func TestRuntimeProjectReadsEvaluatedSnapshotThroughSymlink(t *testing.T) {
	for _, inspection := range []string{"", `inspection: {maxBytes: "64MiB"},`} {
		t.Run(inspection, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(t.TempDir(), "project")
			if err := os.Symlink(root, alias); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(alias, "tnl.config.ts")
			if err := os.WriteFile(path, []byte(`export default () => ({`+inspection+`services: {web: {}}});`), 0600); err != nil {
				t.Fatal(err)
			}
			project, err := clientproject.Resolve(t.Context(), clientproject.Selection{Path: path}, alias, [32]byte{})
			if err != nil {
				t.Fatal(err)
			}
			encoded, _, err := project.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			// the owner must use the evaluated value, never import the config again.
			if err := os.WriteFile(path, []byte(`throw new Error("must not reevaluate");`), 0600); err != nil {
				t.Fatal(err)
			}
			input, err := os.CreateTemp(t.TempDir(), "snapshot")
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			if _, err := input.Write(encoded); err != nil {
				t.Fatal(err)
			}
			if _, err := input.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			stdin := os.Stdin
			os.Stdin = input
			defer func() { os.Stdin = stdin }()
			restored, _, err := runtimeProject(t.Context(), runtimeOptions{Directory: alias, StateDir: filepath.Join(t.TempDir(), "state"), SnapshotStdin: true})
			if err != nil {
				t.Fatal(err)
			}
			if restored.Root != root || restored.Config.Services["web"].Protocol != nil {
				t.Fatalf("owner changed selected project: %+v", restored.Project)
			}
			if inspection != "" && (restored.Config.Inspection == nil || restored.Config.Inspection.MaxBytes.Value() != 64<<20) {
				t.Fatal("owner lost evaluated byte size")
			}
		})
	}
}
