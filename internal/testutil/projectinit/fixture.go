// package projectinittest supplies project fixtures for init operation and
// command presentation tests. product code must not import it.
package projectinittest

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func CopyFixture(t testing.TB, directory string) string {
	t.Helper()
	root := t.TempDir()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, entry.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func GenericFixture(t testing.TB, script, manager string) string {
	t.Helper()
	root := t.TempDir()
	scripts := ""
	if script != "" {
		scripts = fmt.Sprintf(`"scripts":{"dev":%q},`, script)
	}
	data := fmt.Sprintf(`{"packageManager":%q,%s"devDependencies":{"@tnldotdev/tnl":"1.0.0"}}`, manager+"@1", scripts)
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tsconfig.json"), []byte(`{"include":[".tnl/generated/project.d.ts"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func APIFixture(t testing.TB, dependency, script, moduleType, source string) string {
	t.Helper()
	root := t.TempDir()
	entry := filepath.Join(root, "src", "index.ts")
	if err := os.MkdirAll(filepath.Dir(entry), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	packageJSON := fmt.Sprintf(`{"packageManager":"pnpm@11.25.0","type":%q,"scripts":{"dev":%q},"dependencies":{%q:"1.0.0","@tnldotdev/tnl":"1.0.0"}}`, moduleType, script, dependency)
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(packageJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}
