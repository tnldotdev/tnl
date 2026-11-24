package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitDryRunPrintsPlanWithoutEdits(t *testing.T) {
	root := t.TempDir()
	const manifest = `{"packageManager":"pnpm@11.0.0","devDependencies":{"vite":"*"}}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	t.Setenv("TNL_STATE_DIR", filepath.Join(root, "state"))
	var out, diag bytes.Buffer
	if err := run(t.Context(), []string{"init", "--dry-run"}, &out, &diag); err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"tnl.config.ts", "vite.config.ts", "pnpm add --save-dev @tnldotdev/tnl", "no changes made"} {
		if !strings.Contains(out.String(), step) {
			t.Fatalf("missing plan step %q:\n%s", step, &out)
		}
	}
	files, err := os.ReadDir(root)
	if err != nil || len(files) != 1 {
		t.Fatalf("dry run changed project: %v (%v)", files, err)
	}
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil || string(data) != manifest {
		t.Fatal("dry run changed package.json", err)
	}
}

func TestInitWritesHonoBunEntrypointWithoutAConfiguredPort(t *testing.T) {
	root := apiInitFixture(t, "hono", "bun --hot src/index.ts", "module", "import { Hono } from 'hono'\nconst app = new Hono()\nexport default app\n")
	t.Chdir(root)
	var output, diagnostics bytes.Buffer
	if err := runInitWithInput(t.Context(), initCommand{NoInstall: true}, strings.NewReader(""), false, &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	entry, err := os.ReadFile(filepath.Join(root, "src", "index.ts"))
	if err != nil || !bytes.Contains(entry, []byte("await publication?.register(server)")) {
		t.Fatalf("Hono Bun entrypoint = %s, %v", entry, err)
	}
	config, err := os.ReadFile(filepath.Join(root, "tnl.config.ts"))
	if err != nil || bytes.Contains(config, []byte("command:")) || bytes.Contains(config, []byte("port:")) {
		t.Fatalf("generated config = %s, %v", config, err)
	}
	if !strings.Contains(output.String(), "src/index.ts") {
		t.Fatalf("updated server was not reported: %s", output.String())
	}
	if err := runInitWithInput(t.Context(), initCommand{NoInstall: true}, strings.NewReader(""), false, &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(root, "src", "index.ts"))
	if err != nil || !bytes.Equal(second, entry) {
		t.Fatalf("repeat init modified server: %s, %v", second, err)
	}
}
