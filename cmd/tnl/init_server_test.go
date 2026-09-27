package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitConnectsRecognizedAPIServerEntrypoints(t *testing.T) {
	for _, test := range []struct {
		name, dependency, script, moduleType, source, result string
	}{
		{"hono_node", "hono", "tsx watch src/index.ts", "module", "import { serve } from '@hono/node-server'\nimport { Hono } from 'hono'\nconst app = new Hono()\napp.get('/', (c) => c.text('ok'))\nserve(app)\n", "const server = serve({ fetch: app.fetch, port: tnl.port })"},
		{"hono_bun", "hono", "bun --hot src/index.ts", "", "import { Hono } from 'hono'\nconst app = new Hono()\napp.get('/', (c) => c.text('ok'))\nexport default app\n", "const server = Bun.serve({ fetch: app.fetch, port: tnl.port })"},
		{"express", "express", "tsx watch src/index.ts", "module", "import express from 'express'\nconst app = express()\napp.get('/', (_req, res) => res.send('ok'))\napp.listen(3000)\n", "const server = app.listen(tnl.port)"},
		{"fastify", "fastify", "tsx watch src/index.ts", "module", "import fastify from 'fastify'\nconst app = fastify()\napp.get('/', () => 'ok')\napp.listen({ port: 3000 })\n", "await app.listen({ port: tnl.port })"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := apiInitFixture(t, test.dependency, test.script, test.moduleType, test.source)
			plan, err := planInit(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			if plan.framework != "" || plan.genericDev || plan.devPort != 0 || plan.serverPath != filepath.Join(root, "src", "index.ts") || !bytes.Equal(plan.serverBefore, []byte(test.source)) ||
				!strings.Contains(string(plan.serverAfter), test.result) || !strings.Contains(string(plan.serverAfter), "await tnl.register(") || !strings.Contains(string(plan.serverAfter), "import { tnl } from '@tnldotdev/tnl'") {
				t.Fatalf("init plan: %#v", plan)
			}
			if err := replaceRecognizedInitFile(plan.serverPath, plan.serverBefore, plan.serverAfter); err != nil {
				t.Fatal(err)
			}
			second, err := planInit(t.Context(), root)
			if err != nil || len(second.serverAfter) != 0 || second.genericDev || second.devPort != 0 {
				t.Fatalf("second plan = %#v, %v", second, err)
			}
		})
	}
}

func TestInitPreservesCustomAPIServerSource(t *testing.T) {
	source := "import { Hono } from 'hono'\nconst app = new Hono()\napp.get('/', (c) => c.text('custom'))\nexport default { fetch: app.fetch }\n"
	root := apiInitFixture(t, "hono", "bun --hot src/index.ts", "module", source)
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.serverAfter) != 0 || len(plan.actions) != 1 || !strings.Contains(plan.actions[0], "tnl.register") {
		t.Fatalf("custom server plan = %#v", plan)
	}
	contents, err := os.ReadFile(filepath.Join(root, "src", "index.ts"))
	if err != nil || string(contents) != source {
		t.Fatalf("custom server was modified: %s, %v", contents, err)
	}
}

func TestInitDoesNotTurnANodeHonoExportIntoABunListener(t *testing.T) {
	source := "import { Hono } from 'hono'\nconst app = new Hono()\nexport default app\n"
	root := apiInitFixture(t, "hono", "tsx watch src/index.ts", "module", source)
	plan, err := planInit(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.serverAfter) != 0 || len(plan.actions) != 1 || !strings.Contains(plan.actions[0], "tnl.register") {
		t.Fatalf("Node Hono export plan = %#v", plan)
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
	if err != nil || !bytes.Contains(entry, []byte("await tnl.register(server)")) {
		t.Fatalf("Hono Bun entrypoint = %s, %v", entry, err)
	}
	config, err := os.ReadFile(filepath.Join(root, "tnl.config.ts"))
	if err != nil || !bytes.Contains(config, []byte(`command: ["pnpm","dev"]`)) || bytes.Contains(config, []byte("port:")) {
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

func TestInitRemovesRecognizedFixedPortFromAPIServerConfig(t *testing.T) {
	root := apiInitFixture(t, "hono", "bun --hot src/index.ts", "module", "import { Hono } from 'hono'\nconst app = new Hono()\nexport default app\n")
	path := filepath.Join(root, "tnl.config.ts")
	if err := os.WriteFile(path, initConfigSourceWithPort("app", []string{"pnpm", "dev"}, 3000), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	var output, diagnostics bytes.Buffer
	if err := runInitWithInput(t.Context(), initCommand{NoInstall: true}, strings.NewReader(""), false, &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, initConfigSource("app", []string{"pnpm", "dev"})) {
		t.Fatalf("fixed-port project config = %s, %v", got, err)
	}
}

func TestInitViteOwnsHonoViteListener(t *testing.T) {
	root := apiInitFixture(t, "hono", "vite --host", "module", "export default {}\n")
	path := filepath.Join(root, "package.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"hono":"1.0.0"`), []byte(`"hono":"1.0.0","vite":"8.0.0"`), 1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := planInit(t.Context(), root)
	if err != nil || plan.framework != "vite" || len(plan.serverAfter) != 0 {
		t.Fatalf("vite-owned Hono server = %#v, %v", plan, err)
	}
}

func apiInitFixture(t *testing.T, dependency, script, moduleType, source string) string {
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
