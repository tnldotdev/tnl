package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/projectconfig"
)

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
	script := scripts["dev"]
	parsed, simple := simpleInitScript(script)
	switch framework {
	case "next":
		if simple && len(parsed) >= 2 && parsed[0] == "next" && parsed[1] == "dev" {
			return parsed
		}
		return []string{"next", "dev"}
	case "vite":
		if simple && len(parsed) != 0 && parsed[0] == "vite" {
			return parsed
		}
		return []string{"vite"}
	}
	if script != "" {
		if simple && (scriptStartsTnlDev(script) || packageDevCommandLabel(parsed) != "") {
			return nil
		}
		if simple {
			return parsed
		}
		return initDevScriptCommand(manager)
	}
	return nil
}

func simpleInitScript(script string) ([]string, bool) {
	// shell operators and assignments need the original script runner or a manual command.
	if script == "" || strings.ContainsAny(script, "$`|&;<>\n") {
		return nil, false
	}
	command, err := parseInitCommand(script)
	return command, err == nil && !strings.Contains(command[0], "=")
}

func scriptStartsTnlDev(script string) bool {
	command, ok := simpleInitScript(script)
	if !ok || len(command) < 2 {
		return false
	}
	if command[0] == "tnl" && command[1] == "dev" {
		return true
	}
	return len(command) >= 3 && (command[0] == "npx" || command[0] == "bunx") && command[1] == "tnl" && command[2] == "dev" ||
		len(command) >= 4 && (command[0] == "pnpm" || command[0] == "npm" || command[0] == "yarn" || command[0] == "bun") &&
			(command[1] == "exec" || command[1] == "run") && command[2] == "tnl" && command[3] == "dev"
}

func initDevScriptCommand(manager string) []string {
	switch manager {
	case "pnpm", "yarn":
		return []string{manager, "dev"}
	case "bun":
		return []string{"bun", "run", "dev"}
	default:
		return []string{"npm", "run", "dev"}
	}
}

func packageTypeConfigExists(root string) bool {
	info, err := os.Stat(filepath.Join(root, "tsconfig.json"))
	return err == nil && !info.IsDir()
}
