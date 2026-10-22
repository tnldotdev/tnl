package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestInitStaticGenerationNeedsNoExternalTooling(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("PATH", t.TempDir())
	if err := runInit(t.Context(), initCommand{}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".tnl/generated/project.d.ts")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"package.json", "tsconfig.json", "node_modules"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatal("non-JavaScript init created tooling state", name, err)
		}
	}
}
