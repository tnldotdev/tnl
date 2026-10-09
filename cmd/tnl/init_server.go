package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var apiEntryInScript = regexp.MustCompile(`(?:^|[[:space:]"'])(src/(?:index|server|app)|(?:index|server))\.(?:ts|mts|js|mjs)(?:$|[[:space:]"'])`)

// an API framework does not imply a particular development runtime. only
// recognized listener calls, not the dependency alone, are edited by init.
func detectAPIServer(config packageDocument) string {
	kind := ""
	for _, name := range []string{"hono", "fastify", "express"} {
		if hasPackageDependency(config, name) {
			if kind != "" {
				return "ambiguous"
			}
			kind = name
		}
	}
	return kind
}

func startsAPIServer(script string) bool {
	return strings.HasPrefix(script, "tsx ") || strings.HasPrefix(script, "node ") ||
		strings.HasPrefix(script, "bun ") || strings.HasPrefix(script, "nodemon ")
}

func planAPIServer(plan *initPlan, root, kind string, config packageDocument) error {
	if kind == "ambiguous" {
		plan.actions = append(plan.actions, "multiple API servers were detected; prepare the selected service with tnl.prepare and register its bound HTTP listener.")
		return nil
	}
	entry, err := apiServerEntry(root, config.Scripts["dev"])
	if err != nil {
		return err
	}
	if entry == "" {
		plan.actions = append(plan.actions, fmt.Sprintf("find your %s server entrypoint: await tnl.prepare({ service: \"app\" }) before startup and register the bound listener with that handle.", kind))
		return nil
	}
	plan.serverPath = entry
	source, err := readInitFile(entry)
	if err != nil {
		return err
	}
	if bytes.Contains(source, []byte("tnl.prepare(")) {
		return nil
	}
	if isModuleEntrypoint(entry, config.Type, config.Scripts["dev"]) {
		if updated, ok := recognizedAPIServerSource(source, kind, config.Scripts["dev"]); ok {
			plan.serverBefore, plan.serverAfter = source, updated
			return nil
		}
	}
	plan.actions = append(plan.actions, fmt.Sprintf("update %s: await tnl.prepare({ service: \"app\" }) before startup and register the bound listener with that handle.", entry))
	return nil
}

func apiServerEntry(root, script string) (string, error) {
	if match := apiEntryInScript.FindStringSubmatch(script); len(match) != 0 {
		// the pattern permits only a fixed path shape beneath the project root.
		part := strings.TrimSpace(match[0])
		part = strings.Trim(part, `"'`)
		path := filepath.Join(root, part)
		info, err := os.Lstat(path)
		if err == nil && info.Mode().IsRegular() {
			return path, nil
		}
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		return "", nil
	}
	var entries []string
	for _, name := range []string{"src/index.ts", "src/server.ts", "server.ts", "index.ts"} {
		path := filepath.Join(root, name)
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
			entries = append(entries, path)
		} else if err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	if len(entries) == 1 {
		return entries[0], nil
	}
	return "", nil
}

func isModuleEntrypoint(path, packageType, script string) bool {
	return filepath.Ext(path) == ".mts" || packageType == "module" || strings.HasPrefix(script, "bun ")
}

func recognizedAPIServerSource(source []byte, kind, script string) ([]byte, bool) {
	if !bytes.Equal(bytes.ToValidUTF8(source, nil), source) || bytes.Contains(source, []byte("\r")) || bytes.HasPrefix(source, []byte("#!")) || bytes.Contains(source, []byte("@tnldotdev/tnl")) {
		return nil, false
	}
	text := string(source)
	quote := `"`
	if strings.Contains(text, "from '"+kind+"'") {
		quote = "'"
	}
	importLine := "import { tnl } from " + quote + "@tnldotdev/tnl" + quote
	semicolon := ";"
	trimmed := strings.TrimSuffix(text, "\n")
	if !strings.HasSuffix(trimmed, ";") {
		semicolon = ""
	}
	var before, after string
	switch kind {
	case "hono":
		if !strings.Contains(text, "from "+quote+"hono"+quote) || !strings.Contains(text, "const app = new Hono(") {
			return nil, false
		}
		if strings.Contains(text, "from "+quote+"@hono/node-server"+quote) {
			before = "serve(app)" + semicolon
			after = "const server = serve({ fetch: app.fetch, port: 3000 })" + semicolon + "\nawait publication?.register(server)" + semicolon
		} else {
			if !strings.HasPrefix(script, "bun ") {
				return nil, false
			}
			before = "export default app" + semicolon
			after = "const server = Bun.serve({ fetch: app.fetch, port: 3000 })" + semicolon + "\nawait publication?.register(server)" + semicolon
		}
	case "express":
		if !strings.Contains(text, "from "+quote+"express"+quote) || !strings.Contains(text, "const app = express(") {
			return nil, false
		}
		before = "app.listen(3000)" + semicolon
		after = "const server = app.listen(3000)" + semicolon + "\nawait publication?.register(server)" + semicolon
	case "fastify":
		if !strings.Contains(text, "from "+quote+"fastify"+quote) || !strings.Contains(text, "const app = fastify(") {
			return nil, false
		}
		before = "app.listen({ port: 3000 })" + semicolon
		after = "await app.listen({ port: 3000 })" + semicolon + "\nawait publication?.register(app.server)" + semicolon
	default:
		return nil, false
	}
	if strings.Count(text, before) != 1 || !strings.HasSuffix(trimmed, before) {
		return nil, false
	}
	updated := importLine + semicolon + "\nconst publication = process.env.NODE_ENV === \"production\" ? null : await tnl.prepare({ service: \"app\" })" + semicolon + "\n" + strings.TrimSuffix(trimmed, before) + after
	if strings.HasSuffix(text, "\n") {
		updated += "\n"
	}
	return []byte(updated), true
}
