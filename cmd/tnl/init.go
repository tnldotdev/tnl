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
	"github.com/tnldotdev/tnl/internal/projectconfig"
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
	frameworkAfter   []byte
	actions          []string
	installBlocked   bool
	generatedService bool
}

type packageDocument struct {
	PackageManager       string            `json:"packageManager"`
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
		if err := createInitFile(plan.frameworkPath, plan.frameworkAfter); err != nil {
			return err
		}
		frameworkUpdated = true
	}
	gitignoreUpdated, err := ensureTnlGitignore(plan.root)
	if err != nil {
		return err
	}
	if plan.generatedService {
		typeActions, err := projectTypeIncludeActions(projectConfiguration{
			Project: projectconfig.Project{
				Root:                       plan.root,
				ServiceDirectories:         map[string]string{"app": plan.root},
				RelativeServiceDirectories: map[string]string{"app": "."},
			},
		})
		if err != nil {
			return err
		}
		plan.actions = append(plan.actions, typeActions...)
	}
	state := "already configured"
	if created || installed || frameworkUpdated || gitignoreUpdated {
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
		if err := planFrameworkConfig(&plan, root); err != nil {
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
	for _, name := range projectconfig.ConfigNames() {
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

func planFrameworkConfig(plan *initPlan, root string) error {
	paths := frameworkConfigPaths(root, plan.framework)
	if len(paths) > 1 {
		plan.actions = append(plan.actions, fmt.Sprintf("Configure @tnldotdev/tnl/%s in the intended framework config; multiple files were found.", plan.framework))
		return nil
	}
	if len(paths) == 0 {
		plan.frameworkPath = filepath.Join(root, plan.framework+".config.ts")
		plan.frameworkAfter = frameworkConfigSource(plan.framework)
		return nil
	}
	path := paths[0]
	data, err := readInitFile(path)
	if err != nil {
		return err
	}
	plan.frameworkPath = path
	if bytes.Equal(data, frameworkConfigSource(plan.framework)) {
		return nil
	}
	plan.actions = append(plan.actions, frameworkConfigAction(plan.framework, path))
	return nil
}

func frameworkConfigSource(framework string) []byte {
	if framework == "next" {
		return []byte("import { withTnl } from \"@tnldotdev/tnl/next\";\n\nexport default withTnl({});\n")
	}
	return []byte("import { defineConfig } from \"vite\";\nimport tnl from \"@tnldotdev/tnl/vite\";\n\nexport default defineConfig({\n  plugins: [tnl()],\n});\n")
}

func frameworkConfigAction(framework, path string) string {
	if framework == "next" {
		return fmt.Sprintf("Update %s: import { withTnl } from \"@tnldotdev/tnl/next\" and wrap the default export with withTnl(...).", path)
	}
	return fmt.Sprintf("Update %s: import tnl from \"@tnldotdev/tnl/vite\" and add tnl() to plugins.", path)
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
		if cause := context.Cause(ctx); cause != nil {
			return fmt.Errorf("install tnl project dependencies: %w", cause)
		}
		return fmt.Errorf(
			"install tnl project dependencies; run %s: %w",
			shellCommand(arguments), err,
		)
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
