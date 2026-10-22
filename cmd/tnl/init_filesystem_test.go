package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitPreservesExistingStaticConfiguration(t *testing.T) {
	root := copyInitFixture(t, "next")
	path := filepath.Join(root, "tnl.yml")
	static := []byte("version: 1\ntnl:\n  team: Existing Team\n")
	if err := os.WriteFile(path, static, 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ConfigurationPath != path || plan.NewConfiguration != nil {
		t.Fatalf("plan = %#v", plan)
	}
	t.Chdir(root)
	if err := runInit(t.Context(), initCommand{NoInstall: true}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, static) {
		t.Fatalf("existing config changed: %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(root, "tnl.config.ts")); !os.IsNotExist(err) {
		t.Fatalf("created conflicting TypeScript config: %v", err)
	}
}

func TestInitStaticProjectNeedsNoPackageManifestOrOrigin(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	for range 2 {
		if err := runInit(t.Context(), initCommand{NoInstall: true}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"tnl.yml", ".tnl/generated/project.d.ts", ".tnl/generated/manifest.json"} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "package.json")); !os.IsNotExist(err) {
		t.Fatal("non-JavaScript init created package.json")
	}
}

func TestInitWiresTypeIncludeForExistingProjectConfig(t *testing.T) {
	root := copyInitFixture(t, "next")
	if err := os.WriteFile(filepath.Join(root, "tnl.yml"), []byte("version: 1\ntnl: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "tsconfig.json")
	source := []byte("{\n  \"include\": [\"app/**/*.tsx\"]\n}\n")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	var output bytes.Buffer
	if err := runInitWithInput(t.Context(), initCommand{NoInstall: true}, strings.NewReader(""), false, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(got, []byte("app/**/*.tsx")) || !bytes.Contains(got, []byte(".tnl/generated/project.d.ts")) || !strings.Contains(output.String(), `.tnl/generated/project.d.ts`) || !strings.Contains(output.String(), "ignore") {
		t.Fatalf("tsconfig = %s, output = %s, err = %v", got, output.String(), err)
	}
}
