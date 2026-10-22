package projectinit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tnldotdev/tnl/internal/failure"
)

// Plan records the detected project and the edits init can safely make.
// planning reads files but does not install dependencies or write project state.
type Plan struct {
	Root                 string
	PackageManager       string
	MissingPackages      []string
	ConfigurationPath    string
	NewConfiguration     []byte
	Framework            string
	FrameworkPath        string
	NewFrameworkConfig   []byte
	ServerPath           string
	ServerSource         []byte
	ServerReplacement    []byte
	Actions              []string
	InstallBlocked       bool
	GeneratedAppService  bool
	NeedsAppRegistration bool
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

// NewPlan uses actionForFailure only for recoverable detection diagnostics.
// the caller supplies their presentation; fatal errors retain their causes.
func NewPlan(ctx context.Context, cwd string, actionForFailure func(error) string) (Plan, error) {
	root, err := initProjectRoot(ctx, cwd)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{Root: root, ConfigurationPath: filepath.Join(root, "tnl.config.ts")}
	packagePath := filepath.Join(root, "package.json")
	var packageConfig packageDocument
	packageFound := false
	if data, readErr := readInitFile(packagePath); readErr == nil {
		packageFound = true
		if err := json.Unmarshal(data, &packageConfig); err != nil {
			return Plan{}, fmt.Errorf("read package.json: %w", err)
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return Plan{}, readErr
	}
	plan.PackageManager, err = detectPackageManager(ctx, root, packageConfig.PackageManager)
	if err != nil {
		plan.InstallBlocked = true
		plan.Actions = append(plan.Actions, actionForFailure(failure.Wrap("select package manager", failure.InitPackageManager, err)))
	}
	plan.Framework, err = detectFramework(root, packageConfig)
	frameworkUnclear := err != nil
	if frameworkUnclear {
		plan.Actions = append(plan.Actions, actionForFailure(failure.Wrap("detect framework", failure.InitFramework, err)))
	}
	apiKind := detectAPIServer(packageConfig)
	if apiKind != "" && plan.Framework == "vite" && startsAPIServer(packageConfig.Scripts["dev"]) {
		plan.Framework = ""
	}

	existingConfigs := existingInitConfigs(root)
	if len(existingConfigs) > 1 {
		return Plan{}, fmt.Errorf("multiple project configuration files found: %s", strings.Join(existingConfigs, ", "))
	}
	if len(existingConfigs) == 1 {
		plan.ConfigurationPath = existingConfigs[0]
		if filepath.Base(plan.ConfigurationPath) == "tnl.config.ts" {
			data, readErr := readInitFile(plan.ConfigurationPath)
			if readErr != nil {
				return Plan{}, readErr
			}
			plan.GeneratedAppService = bytes.Equal(data, initConfigSource("app"))
		}
	} else {
		if packageFound {
			plan.NewConfiguration = initConfigSource("app")
			plan.GeneratedAppService = true
		} else {
			plan.ConfigurationPath = filepath.Join(root, "tnl.yml")
			plan.NewConfiguration = []byte("version: 1\ntnl:\n  services: {}\n")
			plan.Actions = append(plan.Actions, "declare services in tnl.yml, then run tnl generate")
		}
	}
	plan.NeedsAppRegistration = packageFound && !frameworkUnclear && plan.Framework == "" && apiKind == "" && plan.GeneratedAppService
	if plan.NeedsAppRegistration {
		plan.Actions = append(plan.Actions, "prepare the app before startup with await tnl.prepare({ service: \"app\" }), then await the returned handle's register(server) after the HTTP listener binds.")
	}

	if packageFound {
		for _, dependency := range initDependencies() {
			if !hasPackageDependency(packageConfig, dependency) {
				plan.MissingPackages = append(plan.MissingPackages, dependency)
			}
		}
	}
	if plan.Framework != "" {
		if err := planFrameworkConfig(&plan, root); err != nil {
			return Plan{}, err
		}
	} else if apiKind != "" && !frameworkUnclear {
		if err := planAPIServer(&plan, root, apiKind, packageConfig); err != nil {
			return Plan{}, err
		}
	}
	return plan, nil
}

func initConfigSource(service string) []byte {
	return []byte(fmt.Sprintf(`import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  feedback: true,
  services: {
    %s: {
      publicURL: {},
      target: { type: "app" },
    },
  },
});
`, service))
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

func planFrameworkConfig(plan *Plan, root string) error {
	paths := frameworkConfigPaths(root, plan.Framework)
	if len(paths) > 1 {
		plan.Actions = append(plan.Actions, fmt.Sprintf("Configure @tnldotdev/tnl/%s in the intended framework config; multiple files were found.", plan.Framework))
		return nil
	}
	if len(paths) == 0 {
		plan.FrameworkPath = filepath.Join(root, plan.Framework+".config.ts")
		plan.NewFrameworkConfig = frameworkConfigSource(plan.Framework)
		return nil
	}
	path := paths[0]
	data, err := readInitFile(path)
	if err != nil {
		return err
	}
	plan.FrameworkPath = path
	if bytes.Equal(data, frameworkConfigSource(plan.Framework)) {
		return nil
	}
	plan.Actions = append(plan.Actions, frameworkConfigAction(plan.Framework, path))
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
