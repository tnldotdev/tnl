package projectinit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitConnectsRecognizedAPIServerEntrypoints(t *testing.T) {
	for _, test := range []struct {
		name, dependency, script, moduleType, source, result string
	}{
		{"hono_node", "hono", "tsx watch src/index.ts", "module", "import { serve } from '@hono/node-server'\nimport { Hono } from 'hono'\nconst app = new Hono()\napp.get('/', (c) => c.text('ok'))\nserve(app)\n", "const server = serve({ fetch: app.fetch, port: 3000 })"},
		{"hono_bun", "hono", "bun --hot src/index.ts", "", "import { Hono } from 'hono'\nconst app = new Hono()\napp.get('/', (c) => c.text('ok'))\nexport default app\n", "const server = Bun.serve({ fetch: app.fetch, port: 3000 })"},
		{"express", "express", "tsx watch src/index.ts", "module", "import express from 'express'\nconst app = express()\napp.get('/', (_req, res) => res.send('ok'))\napp.listen(3000)\n", "const server = app.listen(3000)"},
		{"fastify", "fastify", "tsx watch src/index.ts", "module", "import fastify from 'fastify'\nconst app = fastify()\napp.get('/', () => 'ok')\napp.listen({ port: 3000 })\n", "await app.listen({ port: 3000 })"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := apiInitFixture(t, test.dependency, test.script, test.moduleType, test.source)
			plan, err := planInit(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Framework != "" || plan.NeedsAppRegistration || plan.ServerPath != filepath.Join(root, "src", "index.ts") || !bytes.Equal(plan.ServerSource, []byte(test.source)) ||
				!strings.Contains(string(plan.ServerReplacement), test.result) || !strings.Contains(string(plan.ServerReplacement), "await publication?.register(") || !strings.Contains(string(plan.ServerReplacement), "tnl.prepare(") || !strings.Contains(string(plan.ServerReplacement), "import { tnl } from '@tnldotdev/tnl'") {
				t.Fatalf("init plan: %#v", plan)
			}
			if err := replaceRecognizedInitFile(plan.ServerPath, plan.ServerSource, plan.ServerReplacement); err != nil {
				t.Fatal(err)
			}
			second, err := planInit(t.Context(), root)
			if err != nil || len(second.ServerReplacement) != 0 || second.NeedsAppRegistration {
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
	if len(plan.ServerReplacement) != 0 || len(plan.Actions) != 1 || !strings.Contains(plan.Actions[0], "tnl.prepare") {
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
	if len(plan.ServerReplacement) != 0 || len(plan.Actions) != 1 || !strings.Contains(plan.Actions[0], "tnl.prepare") {
		t.Fatalf("Node Hono export plan = %#v", plan)
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
	if err != nil || plan.Framework != "vite" || len(plan.ServerReplacement) != 0 {
		t.Fatalf("vite-owned Hono server = %#v, %v", plan, err)
	}
}
