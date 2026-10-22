package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
