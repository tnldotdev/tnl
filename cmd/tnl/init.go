package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/clioutput"
	projectconfig "github.com/tnldotdev/tnl/internal/config"
)

const initReadLimit = 1 << 20

type initCommand struct {
	NoInstall bool `name:"no-install" help:"Print the dependency command instead of running it."`
}

type initPlan struct {
	root             string
	manager          string
	packages         []string
	configPath       string
	configData       []byte
	framework        string
	frameworkPath    string
	frameworkBefore  []byte
	frameworkAfter   []byte
	actions          []string
	installBlocked   bool
	generatedService bool
}

type packageDocument struct {
	PackageManager       string            `json:"packageManager"`
	Type                 string            `json:"type"`
	Workspaces           json.RawMessage   `json:"workspaces"`
	Scripts              map[string]string `json:"scripts"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func runInit(ctx context.Context, flags initCommand, stdout, stderr io.Writer) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("read working directory: %w", err)
	}
	plan, err := planInit(ctx, cwd)
	if err != nil {
		return err
	}
	installed := false
	if len(plan.packages) != 0 && !plan.installBlocked {
		command := packageInstallCommand(plan.manager, plan.packages)
		if flags.NoInstall || command == nil {
			plan.actions = append(plan.actions, "Run: "+shellCommand(commandForRecommendation(plan.manager, plan.packages)))
		} else {
			if err := runInitInstall(ctx, plan.root, command); err != nil {
				return err
			}
			installed = true
		}
	}
	created := false
	if len(plan.configData) != 0 {
		if err := createInitFile(plan.configPath, plan.configData); err != nil {
			return err
		}
		created = true
	}
	frameworkUpdated := false
	if len(plan.frameworkAfter) != 0 {
		if err := replaceRecognizedInitFile(plan.frameworkPath, plan.frameworkBefore, plan.frameworkAfter); err != nil {
			return err
		}
		frameworkUpdated = true
	}
	gitignoreUpdated, err := ensureTnlGitignore(plan.root)
	if err != nil {
		return err
	}
	var typeUpdates []string
	if plan.generatedService {
		typeActions, updated, err := ensureProjectTypeIncludes(projectConfiguration{
			root:                plan.root,
			directories:         map[string]string{"app": plan.root},
			relativeDirectories: map[string]string{"app": "."},
		})
		if err != nil {
			return err
		}
		plan.actions = append(plan.actions, typeActions...)
		typeUpdates = updated
	}
	state := "already configured"
	if created || installed || frameworkUpdated || gitignoreUpdated || len(typeUpdates) != 0 {
		state = "configured"
	}
	if len(plan.actions) != 0 {
		state = "needs action"
	}
	fields := []clioutput.Field{{Label: "project", Value: plan.root}}
	if created {
		fields = append(fields, clioutput.Field{Label: "created", Value: plan.configPath})
	} else {
		fields = append(fields, clioutput.Field{Label: "config", Value: plan.configPath})
	}
	if installed {
		fields = append(fields, clioutput.Field{Label: "installed", Value: strings.Join(plan.packages, ", ")})
	}
	if frameworkUpdated {
		fields = append(fields, clioutput.Field{Label: "updated", Value: plan.frameworkPath})
	}
	if gitignoreUpdated {
		fields = append(fields, clioutput.Field{Label: "updated", Value: filepath.Join(plan.root, ".gitignore")})
	}
	for _, path := range typeUpdates {
		fields = append(fields, clioutput.Field{Label: "updated", Value: path})
	}
	blocks := []clioutput.Block{clioutput.Fields(fields...)}
	for _, action := range plan.actions {
		blocks = append(blocks, clioutput.Section("action", clioutput.Text(action)))
	}
	footer := "run tnl dev"
	if len(plan.actions) != 0 {
		footer = "complete the actions above, then run tnl dev"
	}
	return writeHumanFrame(stdout, "tnl init", state, footer, blocks...)
}

func planInit(ctx context.Context, cwd string) (initPlan, error) {
	root, err := initProjectRoot(ctx, cwd)
	if err != nil {
		return initPlan{}, err
	}
	plan := initPlan{root: root, configPath: filepath.Join(root, "tnl.config.ts")}
	packagePath := filepath.Join(root, "package.json")
	var packageConfig packageDocument
	packageFound := false
	if data, readErr := readInitFile(packagePath); readErr == nil {
		packageFound = true
		if err := json.Unmarshal(data, &packageConfig); err != nil {
			return initPlan{}, fmt.Errorf("read package.json: %w", err)
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return initPlan{}, readErr
	}
	plan.manager, err = detectPackageManager(ctx, root, packageConfig.PackageManager)
	if err != nil {
		plan.installBlocked = true
		plan.actions = append(plan.actions, err.Error())
	}
	plan.framework, err = detectFramework(root, packageConfig)
	if err != nil {
		plan.actions = append(plan.actions, err.Error())
	}

	existingConfigs := existingInitConfigs(root)
	if len(existingConfigs) > 1 {
		return initPlan{}, fmt.Errorf("multiple project configuration files found: %s", strings.Join(existingConfigs, ", "))
	}
	command := initDevCommand(plan.framework, plan.manager, packageConfig.Scripts)
	if len(existingConfigs) == 1 {
		plan.configPath = existingConfigs[0]
		if filepath.Base(plan.configPath) == "tnl.config.ts" {
			data, readErr := readInitFile(plan.configPath)
			if readErr != nil {
				return initPlan{}, readErr
			}
			plan.generatedService = isGeneratedInitConfig(data)
		}
	} else {
		plan.configData = initConfigSource("app", command)
		plan.generatedService = true
	}

	if packageFound {
		for _, dependency := range initDependencies() {
			if !hasPackageDependency(packageConfig, dependency) {
				plan.packages = append(plan.packages, dependency)
			}
		}
	} else {
		plan.actions = append(plan.actions, "Create package.json, then install @tnldotdev/tnl as a development dependency.")
	}
	if plan.framework != "" {
		if err := planFrameworkConfig(&plan, root, packageConfig.Type); err != nil {
			return initPlan{}, err
		}
	}
	return plan, nil
}

func initProjectRoot(ctx context.Context, cwd string) (string, error) {
	absolute, err := filepath.Abs(cwd)
	if err != nil {
		return "", err
	}
	worktree, err := projectconfig.ResolveWorktree(ctx, absolute)
	if err != nil {
		return "", err
	}
	boundary := absolute
	if worktree.IsGit {
		boundary = worktree.Root
	}
	for directory := absolute; ; directory = filepath.Dir(directory) {
		if info, statErr := os.Stat(filepath.Join(directory, "package.json")); statErr == nil && !info.IsDir() {
			return directory, nil
		}
		if directory == boundary {
			break
		}
		parent := filepath.Dir(directory)
		if parent == directory || !pathInside(parent, boundary) {
			break
		}
	}
	return absolute, nil
}

func pathInside(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func existingInitConfigs(root string) []string {
	var paths []string
	for _, name := range projectconfig.ProjectConfigNames {
		path := filepath.Join(root, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	return paths
}

func detectPackageManager(ctx context.Context, root, declared string) (string, error) {
	locks := []struct{ file, manager string }{
		{"pnpm-lock.yaml", "pnpm"}, {"yarn.lock", "yarn"}, {"package-lock.json", "npm"},
		{"npm-shrinkwrap.json", "npm"}, {"bun.lock", "bun"}, {"bun.lockb", "bun"},
	}
	worktree, err := projectconfig.ResolveWorktree(ctx, root)
	if err != nil {
		return "", err
	}
	boundary := root
	if worktree.IsGit {
		boundary = worktree.Root
	} else {
		boundary = packageWorkspaceBoundary(root)
	}
	var managers []string
	for directory := root; ; directory = filepath.Dir(directory) {
		packageManager := ""
		if directory == root {
			packageManager = declared
		} else if data, readErr := readInitFile(filepath.Join(directory, "package.json")); readErr == nil {
			var document packageDocument
			if json.Unmarshal(data, &document) == nil {
				packageManager = document.PackageManager
			}
		}
		if packageManager != "" {
			name, _, _ := strings.Cut(packageManager, "@")
			if !slices.Contains([]string{"pnpm", "npm", "yarn", "bun"}, name) {
				return "", fmt.Errorf("set packageManager to pnpm, npm, yarn, or bun instead of %q, then run tnl init again", packageManager)
			}
			if !slices.Contains(managers, name) {
				managers = append(managers, name)
			}
		}
		for _, lock := range locks {
			if info, statErr := os.Stat(filepath.Join(directory, lock.file)); statErr == nil && !info.IsDir() && !slices.Contains(managers, lock.manager) {
				managers = append(managers, lock.manager)
			}
		}
		if directory == boundary {
			break
		}
		parent := filepath.Dir(directory)
		if parent == directory || !pathInside(parent, boundary) {
			break
		}
	}
	if len(managers) == 1 {
		return managers[0], nil
	}
	if len(managers) > 1 {
		return "", errors.New("remove ambiguous package-manager lockfiles, then run tnl init again")
	}
	return "", nil
}

func packageWorkspaceBoundary(root string) string {
	boundary := root
	for directory := filepath.Dir(root); ; directory = filepath.Dir(directory) {
		workspace := false
		if info, err := os.Stat(filepath.Join(directory, "pnpm-workspace.yaml")); err == nil && !info.IsDir() {
			workspace = true
		}
		if data, err := readInitFile(filepath.Join(directory, "package.json")); err == nil {
			var document packageDocument
			if json.Unmarshal(data, &document) == nil && len(document.Workspaces) != 0 && string(document.Workspaces) != "null" {
				workspace = true
			}
		}
		if workspace {
			boundary = directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
	}
	return boundary
}

func detectFramework(root string, config packageDocument) (string, error) {
	next := hasPackageDependency(config, "next")
	vite := hasPackageDependency(config, "vite")
	if next && vite {
		nextConfigs := frameworkConfigPaths(root, "next")
		viteConfigs := frameworkConfigPaths(root, "vite")
		if len(nextConfigs) != 0 && len(viteConfigs) == 0 {
			return "next", nil
		}
		if len(viteConfigs) != 0 && len(nextConfigs) == 0 {
			return "vite", nil
		}
		return "", errors.New("both Next.js and Vite were detected; configure the intended framework integration manually")
	}
	if next {
		return "next", nil
	}
	if vite {
		return "vite", nil
	}
	return "", nil
}

func hasPackageDependency(config packageDocument, name string) bool {
	for _, dependencies := range []map[string]string{config.Dependencies, config.DevDependencies, config.OptionalDependencies} {
		if _, found := dependencies[name]; found {
			return true
		}
	}
	return false
}

func initDependencies() []string {
	return []string{"@tnldotdev/tnl"}
}

func initDevCommand(framework, manager string, scripts map[string]string) []string {
	if scripts["dev"] != "" {
		switch manager {
		case "pnpm", "yarn":
			return []string{manager, "dev"}
		case "bun":
			return []string{"bun", "run", "dev"}
		default:
			return []string{"npm", "run", "dev"}
		}
	}
	switch framework {
	case "next":
		return []string{"next", "dev"}
	case "vite":
		return []string{"vite"}
	}
	return nil
}

func initConfigSource(service string, command []string) []byte {
	commandField := ""
	if len(command) != 0 {
		encoded, _ := json.Marshal(command)
		commandField = "      dev: { command: " + string(encoded) + " },\n"
	}
	return []byte(fmt.Sprintf(`import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  services: {
    %s: {
      directory: ".",
%s    },
  },
});
`, service, commandField))
}

func isGeneratedInitConfig(data []byte) bool {
	commands := [][]string{
		nil,
		{"next", "dev"},
		{"vite"},
		{"pnpm", "dev"},
		{"yarn", "dev"},
		{"bun", "run", "dev"},
		{"npm", "run", "dev"},
	}
	for _, command := range commands {
		if bytes.Equal(data, initConfigSource("app", command)) {
			return true
		}
	}
	return false
}

func frameworkConfigPaths(root, framework string) []string {
	extensions := []string{".ts", ".mts", ".cts", ".tsx", ".js", ".mjs", ".cjs", ".jsx"}
	var paths []string
	for _, extension := range extensions {
		path := filepath.Join(root, framework+".config"+extension)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			paths = append(paths, path)
		}
	}
	return paths
}

func planFrameworkConfig(plan *initPlan, root, packageType string) error {
	paths := frameworkConfigPaths(root, plan.framework)
	if len(paths) > 1 {
		plan.actions = append(plan.actions, fmt.Sprintf("Configure @tnldotdev/tnl/%s in the intended framework config; multiple files were found.", plan.framework))
		return nil
	}
	if len(paths) == 0 {
		plan.frameworkPath = filepath.Join(root, plan.framework+".config.ts")
		if plan.framework == "next" {
			plan.frameworkAfter = []byte("import { withTnl } from \"@tnldotdev/tnl/next\";\n\nexport default withTnl({});\n")
		} else {
			plan.frameworkAfter = []byte("import { defineConfig } from \"vite\";\nimport tnl from \"@tnldotdev/tnl/vite\";\n\nexport default defineConfig({\n  plugins: [tnl()],\n});\n")
		}
		return nil
	}
	path := paths[0]
	data, err := readInitFile(path)
	if err != nil {
		return err
	}
	plan.frameworkPath = path
	if !recognizedESMConfigPath(path, packageType) {
		plan.actions = append(plan.actions, frameworkConfigAction(plan.framework, path))
		return nil
	}
	var updated []byte
	if plan.framework == "next" {
		updated = updateNextConfig(data)
	} else {
		updated = updateViteConfig(data)
	}
	if updated != nil {
		if !bytes.Equal(updated, data) {
			plan.frameworkBefore = data
			plan.frameworkAfter = updated
		}
		return nil
	}
	plan.actions = append(plan.actions, frameworkConfigAction(plan.framework, path))
	return nil
}

func recognizedESMConfigPath(path, packageType string) bool {
	switch filepath.Ext(path) {
	case ".ts", ".mts", ".mjs":
		return true
	case ".js":
		return packageType == "module"
	default:
		return false
	}
}

func frameworkConfigAction(framework, path string) string {
	if framework == "next" {
		return fmt.Sprintf("Update %s: import { withTnl } from \"@tnldotdev/tnl/next\" and wrap the default export with withTnl(...).", path)
	}
	return fmt.Sprintf("Update %s: import tnl from \"@tnldotdev/tnl/vite\" and add tnl() to plugins.", path)
}

type initJSToken struct {
	text       string
	value      string
	start, end int
	kind       byte
}

const (
	initJSIdentifier = 'i'
	initJSString     = 's'
)

type initJSImport struct {
	source         string
	defaultBinding string
	named          map[string]string
	typeOnly       bool
}

func updateNextConfig(data []byte) []byte {
	tokens, pairs, ok := lexInitJS(data)
	if !ok || hasInitJSCJS(tokens) {
		return nil
	}
	imports, ok := parseInitJSImports(tokens)
	if !ok {
		return nil
	}
	export, ok := initJSDefaultExport(tokens)
	if !ok {
		return nil
	}
	for _, imported := range imports {
		if imported.source != "@tnldotdev/tnl/next" || imported.typeOnly {
			continue
		}
		for local, name := range imported.named {
			if name == "withTnl" && initJSDefaultCall(tokens, pairs, export, local) {
				return data
			}
		}
	}
	for _, imported := range imports {
		if imported.source == "@tnldotdev/tnl/next" || imported.source == "@tnldotdev/next" {
			return nil
		}
	}
	start, end, ok := initJSDefaultExpression(tokens, export)
	if !ok || end-start != 1 || tokens[start].kind != initJSIdentifier || initJSHasIdentifier(tokens, "withTnl") {
		return nil
	}
	identifier := tokens[start]
	source := string(data)
	return []byte("import { withTnl } from \"@tnldotdev/tnl/next\";" + initJSLineEnding(source) +
		source[:identifier.start] + "withTnl(" + identifier.text + ")" + source[identifier.end:])
}

func updateViteConfig(data []byte) []byte {
	tokens, pairs, ok := lexInitJS(data)
	if !ok || hasInitJSCJS(tokens) || initJSHasToken(tokens, "...") || hasInitJSComputedProperty(tokens, pairs) {
		return nil
	}
	imports, ok := parseInitJSImports(tokens)
	if !ok {
		return nil
	}
	export, ok := initJSDefaultExport(tokens)
	if !ok {
		return nil
	}
	object, ok := initJSViteObject(tokens, pairs, imports, export)
	if !ok {
		return nil
	}
	plugins, property, ok := initJSPluginsArray(tokens, pairs, object)
	if !ok {
		return nil
	}
	for _, imported := range imports {
		if imported.source == "@tnldotdev/tnl/vite" && !imported.typeOnly && imported.defaultBinding != "" &&
			initJSArrayHasCall(tokens, pairs, plugins, imported.defaultBinding) {
			return data
		}
	}
	for _, imported := range imports {
		if imported.source == "@tnldotdev/tnl/vite" || imported.source == "@tnldotdev/vite" {
			return nil
		}
	}
	if initJSHasIdentifier(tokens, "tnl") {
		return nil
	}

	source := string(data)
	open := tokens[plugins]
	first := plugins + 1
	gap := source[open.end:tokens[first].start]
	insertion := "tnl()"
	if first != pairs[plugins] {
		insertion += ","
	}
	if strings.ContainsAny(gap, "\r\n") {
		indent := initJSLineIndent(source, tokens[first].start)
		if first == pairs[plugins] {
			indent = initJSLineIndent(source, tokens[property].start)
			if strings.Contains(indent, "\t") {
				indent += "\t"
			} else {
				indent += "  "
			}
		}
		insertion = initJSLineEnding(source) + indent + "tnl(),"
	} else if first != pairs[plugins] && (gap == "" || gap[0] != ' ' && gap[0] != '\t') {
		insertion += " "
	}
	updated := source[:open.end] + insertion + source[open.end:]
	return []byte("import tnl from \"@tnldotdev/tnl/vite\";" + initJSLineEnding(source) + updated)
}

func lexInitJS(data []byte) ([]initJSToken, []int, bool) {
	if bytes.HasPrefix(data, []byte("#!")) {
		return nil, nil, false
	}
	var tokens []initJSToken
	for i := 0; i < len(data); {
		if strings.ContainsRune(" \t\r\n\f\v", rune(data[i])) {
			i++
			continue
		}
		if data[i] >= 0x80 || data[i] == '`' {
			return nil, nil, false
		}
		if data[i] == '/' {
			if i+1 < len(data) && data[i+1] == '/' {
				i += 2
				for i < len(data) && data[i] != '\n' {
					i++
				}
				continue
			}
			if i+1 < len(data) && data[i+1] == '*' {
				i += 2
				for i+1 < len(data) && (data[i] != '*' || data[i+1] != '/') {
					i++
				}
				if i+1 >= len(data) {
					return nil, nil, false
				}
				i += 2
				continue
			}
			return nil, nil, false
		}
		if data[i] == '\'' || data[i] == '"' {
			start, quote, plain := i, data[i], true
			i++
			for i < len(data) && data[i] != quote {
				if data[i] == '\r' || data[i] == '\n' {
					return nil, nil, false
				}
				if data[i] == '\\' {
					plain = false
					i += 2
				} else {
					i++
				}
			}
			if i >= len(data) {
				return nil, nil, false
			}
			i++
			value := ""
			if plain {
				value = string(data[start+1 : i-1])
			}
			tokens = append(tokens, initJSToken{text: string(data[start:i]), value: value, start: start, end: i, kind: initJSString})
			continue
		}
		if initJSIdentifierStart(data[i]) {
			start := i
			for i++; i < len(data) && initJSIdentifierPart(data[i]); i++ {
			}
			tokens = append(tokens, initJSToken{text: string(data[start:i]), start: start, end: i, kind: initJSIdentifier})
			continue
		}
		start := i
		switch {
		case i+2 < len(data) && string(data[i:i+3]) == "...":
			i += 3
		case i+1 < len(data) && string(data[i:i+2]) == "=>":
			i += 2
		default:
			i++
		}
		tokens = append(tokens, initJSToken{text: string(data[start:i]), start: start, end: i})
	}

	pairs := make([]int, len(tokens))
	for i := range pairs {
		pairs[i] = -1
	}
	var stack []int
	for i, token := range tokens {
		switch token.text {
		case "(", "[", "{":
			stack = append(stack, i)
		case ")", "]", "}":
			if len(stack) == 0 || !initJSMatchingPair(tokens[stack[len(stack)-1]].text, token.text) {
				return nil, nil, false
			}
			open := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			pairs[open], pairs[i] = i, open
		}
	}
	return tokens, pairs, len(stack) == 0
}

func initJSIdentifierStart(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value == '_' || value == '$'
}

func initJSIdentifierPart(value byte) bool {
	return initJSIdentifierStart(value) || value >= '0' && value <= '9'
}

func initJSMatchingPair(open, close string) bool {
	return open == "(" && close == ")" || open == "[" && close == "]" || open == "{" && close == "}"
}

func parseInitJSImports(tokens []initJSToken) ([]initJSImport, bool) {
	var imports []initJSImport
	for i := 0; i < len(tokens); i++ {
		if tokens[i].text != "import" || i+1 == len(tokens) || tokens[i+1].text == "(" || tokens[i+1].text == "." {
			continue
		}
		imported := initJSImport{named: map[string]string{}}
		j := i + 1
		if tokens[j].text == "type" {
			imported.typeOnly = true
			j++
		}
		if j >= len(tokens) {
			return nil, false
		}
		if tokens[j].kind == initJSString {
			imported.source = tokens[j].value
			imports = append(imports, imported)
			i = j
			continue
		}
		if tokens[j].kind == initJSIdentifier {
			imported.defaultBinding = tokens[j].text
			j++
			if j < len(tokens) && tokens[j].text == "," {
				j++
			}
		}
		if j < len(tokens) && tokens[j].text == "{" {
			j++
			for j < len(tokens) && tokens[j].text != "}" {
				if tokens[j].kind != initJSIdentifier {
					return nil, false
				}
				name, local := tokens[j].text, tokens[j].text
				j++
				if j < len(tokens) && tokens[j].text == "as" {
					j++
					if j >= len(tokens) || tokens[j].kind != initJSIdentifier {
						return nil, false
					}
					local = tokens[j].text
					j++
				}
				imported.named[local] = name
				if j < len(tokens) && tokens[j].text == "," {
					j++
				}
			}
			if j >= len(tokens) {
				return nil, false
			}
			j++
		} else if j < len(tokens) && tokens[j].text == "*" {
			j += 3
		}
		if j+1 >= len(tokens) || tokens[j].text != "from" || tokens[j+1].kind != initJSString {
			return nil, false
		}
		imported.source = tokens[j+1].value
		imports = append(imports, imported)
		i = j + 1
	}
	return imports, true
}

func initJSDefaultExport(tokens []initJSToken) (int, bool) {
	found := -1
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i].text == "export" && tokens[i+1].text == "default" {
			if found != -1 {
				return -1, false
			}
			found = i
		}
	}
	return found, found != -1
}

func initJSDefaultExpression(tokens []initJSToken, export int) (int, int, bool) {
	start, end := export+2, len(tokens)
	if end > start && tokens[end-1].text == ";" {
		end--
	}
	return start, end, start < end
}

func initJSDefaultCall(tokens []initJSToken, pairs []int, export int, binding string) bool {
	start, end, ok := initJSDefaultExpression(tokens, export)
	return ok && end-start >= 3 && tokens[start].text == binding && tokens[start+1].text == "(" && pairs[start+1] == end-1
}

func initJSViteObject(tokens []initJSToken, pairs []int, imports []initJSImport, export int) (int, bool) {
	start, end, ok := initJSDefaultExpression(tokens, export)
	if !ok {
		return -1, false
	}
	if tokens[start].text == "{" && pairs[start] == end-1 {
		return start, true
	}
	if end-start < 4 || tokens[start].kind != initJSIdentifier || tokens[start+1].text != "(" || pairs[start+1] != end-1 {
		return -1, false
	}
	defineConfig := false
	for _, imported := range imports {
		if imported.source == "vite" && !imported.typeOnly && imported.named[tokens[start].text] == "defineConfig" {
			defineConfig = true
		}
	}
	if !defineConfig {
		return -1, false
	}
	argumentStart, argumentEnd := start+2, end-1
	if argumentStart >= argumentEnd {
		return -1, false
	}
	if tokens[argumentStart].text == "{" && pairs[argumentStart] == argumentEnd-1 {
		return argumentStart, true
	}
	return initJSFactoryObject(tokens, pairs, argumentStart, argumentEnd)
}

func initJSFactoryObject(tokens []initJSToken, pairs []int, start, end int) (int, bool) {
	arrow := -1
	for i := start; i < end; i++ {
		if tokens[i].text == "=>" {
			if arrow != -1 {
				return -1, false
			}
			arrow = i
		}
	}
	if arrow != -1 {
		parameters := start
		if tokens[parameters].text == "async" {
			parameters++
		}
		if parameters >= arrow || !(arrow-parameters == 1 && tokens[parameters].kind == initJSIdentifier ||
			tokens[parameters].text == "(" && pairs[parameters] == arrow-1) {
			return -1, false
		}
		return initJSReturnedObject(tokens, pairs, arrow+1, end)
	}

	function := start
	if tokens[function].text == "async" {
		function++
	}
	if function >= end || tokens[function].text != "function" {
		return -1, false
	}
	function++
	if function < end && tokens[function].kind == initJSIdentifier {
		function++
	}
	if function >= end || tokens[function].text != "(" {
		return -1, false
	}
	body := pairs[function] + 1
	if body >= end || tokens[body].text != "{" || pairs[body] != end-1 {
		return -1, false
	}
	return initJSReturnStatementObject(tokens, pairs, body+1, end-1)
}

func initJSReturnedObject(tokens []initJSToken, pairs []int, start, end int) (int, bool) {
	if start >= end {
		return -1, false
	}
	if tokens[start].text == "(" && pairs[start] == end-1 && start+1 < end && tokens[start+1].text == "{" && pairs[start+1] == end-2 {
		return start + 1, true
	}
	if tokens[start].text == "{" && pairs[start] == end-1 {
		return initJSReturnStatementObject(tokens, pairs, start+1, end-1)
	}
	return -1, false
}

func initJSReturnStatementObject(tokens []initJSToken, pairs []int, start, end int) (int, bool) {
	if start+1 >= end || tokens[start].text != "return" || tokens[start+1].text != "{" {
		return -1, false
	}
	object, after := start+1, pairs[start+1]+1
	if after < end && tokens[after].text == ";" {
		after++
	}
	return object, after == end
}

func initJSPluginsArray(tokens []initJSToken, pairs []int, object int) (int, int, bool) {
	propertyCount, propertyToken := 0, -1
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i].kind == initJSIdentifier && tokens[i].text == "plugins" && tokens[i+1].text == ":" {
			propertyCount++
			propertyToken = i
		}
		if tokens[i].kind == initJSString && tokens[i].value == "plugins" && tokens[i+1].text == ":" {
			return -1, -1, false
		}
	}
	if propertyCount != 1 {
		return -1, -1, false
	}

	for i, close := object+1, pairs[object]; i < close; {
		if tokens[i].text == "," {
			i++
			continue
		}
		start := i
		for i < close && tokens[i].text != "," {
			if pairs[i] > i {
				i = pairs[i] + 1
			} else {
				i++
			}
		}
		end := i
		if start >= end || tokens[start].text == "..." || tokens[start].text == "[" {
			return -1, -1, false
		}
		if start == propertyToken {
			if start+2 >= end || tokens[start+1].text != ":" || tokens[start+2].text != "[" || pairs[start+2] != end-1 {
				return -1, -1, false
			}
			return start + 2, start, true
		}
	}
	return -1, -1, false
}

func initJSArrayHasCall(tokens []initJSToken, pairs []int, array int, binding string) bool {
	for i, close := array+1, pairs[array]; i < close; {
		if tokens[i].text == "," {
			i++
			continue
		}
		start := i
		for i < close && tokens[i].text != "," {
			if pairs[i] > i {
				i = pairs[i] + 1
			} else {
				i++
			}
		}
		if i-start == 3 && tokens[start].text == binding && tokens[start+1].text == "(" && tokens[start+2].text == ")" {
			return true
		}
	}
	return false
}

func hasInitJSCJS(tokens []initJSToken) bool {
	for i := range tokens {
		if i+2 < len(tokens) && tokens[i].text == "module" && tokens[i+1].text == "." && tokens[i+2].text == "exports" ||
			i+1 < len(tokens) && tokens[i].text == "exports" && tokens[i+1].text == "." ||
			i+1 < len(tokens) && tokens[i].text == "require" && tokens[i+1].text == "(" {
			return true
		}
	}
	return false
}

func hasInitJSComputedProperty(tokens []initJSToken, pairs []int) bool {
	for i, token := range tokens {
		if token.text == "[" && pairs[i] > i && pairs[i]+1 < len(tokens) &&
			(tokens[pairs[i]+1].text == ":" || tokens[pairs[i]+1].text == "(") {
			return true
		}
	}
	return false
}

func initJSHasIdentifier(tokens []initJSToken, identifier string) bool {
	for _, token := range tokens {
		if token.kind == initJSIdentifier && token.text == identifier {
			return true
		}
	}
	return false
}

func initJSHasToken(tokens []initJSToken, text string) bool {
	for _, token := range tokens {
		if token.text == text {
			return true
		}
	}
	return false
}

func initJSLineEnding(source string) string {
	if strings.Contains(source, "\r\n") {
		return "\r\n"
	}
	return "\n"
}

func initJSLineIndent(source string, offset int) string {
	start := strings.LastIndexAny(source[:offset], "\r\n") + 1
	indent := source[start:offset]
	if strings.Trim(indent, " \t") != "" {
		return ""
	}
	return indent
}

func packageInstallCommand(manager string, packages []string) []string {
	switch manager {
	case "pnpm":
		return append([]string{"pnpm", "add", "--save-dev", "--reporter=silent"}, packages...)
	case "yarn":
		return append([]string{"yarn", "add", "--dev", "--silent"}, packages...)
	case "npm":
		return append([]string{"npm", "install", "--save-dev", "--no-audit", "--no-fund", "--loglevel=error"}, packages...)
	case "bun":
		return append([]string{"bun", "add", "--dev"}, packages...)
	default:
		return nil
	}
}

func commandForRecommendation(manager string, packages []string) []string {
	switch manager {
	case "pnpm":
		return append([]string{"pnpm", "add", "--save-dev"}, packages...)
	case "yarn":
		return append([]string{"yarn", "add", "--dev"}, packages...)
	case "bun":
		return append([]string{"bun", "add", "--dev"}, packages...)
	case "npm":
		return append([]string{"npm", "install", "--save-dev"}, packages...)
	}
	return append([]string{"npm", "install", "--save-dev"}, packages...)
}

func shellCommand(arguments []string) string {
	return strings.Join(arguments, " ")
}

func runInitInstall(ctx context.Context, root string, arguments []string) error {
	command := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
	command.Dir = root
	command.Env = append(os.Environ(), "NO_COLOR=1")
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Run(); err != nil {
		return fmt.Errorf("install tnl project dependencies; run %s: %w", shellCommand(arguments), err)
	}
	return nil
}

func readInitFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, initReadLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > initReadLimit {
		return nil, fmt.Errorf("refusing to edit %s: file exceeds %d bytes", path, initReadLimit)
	}
	return data, nil
}

func createInitFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".tnl-init-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0o644); err != nil {
		file.Close()
		return fmt.Errorf("set temporary file permissions for %s: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	return nil
}

func replaceRecognizedInitFile(path string, expected, replacement []byte) error {
	if expected == nil {
		return createInitFile(path, replacement)
	}
	current, err := readInitFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, expected) {
		return fmt.Errorf("refusing to overwrite %s because it changed during initialization", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to overwrite %s because it is not a regular file", path)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".tnl-init-*")
	if err != nil {
		return fmt.Errorf("create temporary replacement for %s: %w", path, err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		temporary.Close()
		return fmt.Errorf("set temporary replacement permissions for %s: %w", path, err)
	}
	if _, err := temporary.Write(replacement); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary replacement for %s: %w", path, err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary replacement for %s: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary replacement for %s: %w", path, err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("update %s: %w", path, err)
	}
	return nil
}

func ensureTnlGitignore(root string) (bool, error) {
	path := filepath.Join(root, ".gitignore")
	data, err := readInitFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := createInitFile(path, []byte(".tnl/\n")); err != nil {
			return false, err
		}
		return true, nil
	}
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == ".tnl" || strings.TrimSpace(line) == ".tnl/" {
			return false, nil
		}
	}
	replacement := slices.Clone(data)
	if len(replacement) != 0 && replacement[len(replacement)-1] != '\n' {
		replacement = append(replacement, '\n')
	}
	replacement = append(replacement, []byte(".tnl/\n")...)
	if err := replaceRecognizedInitFile(path, data, replacement); err != nil {
		return false, err
	}
	return true, nil
}
