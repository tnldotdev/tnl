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
	"strings"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"golang.org/x/term"
)

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
	serverPath       string
	serverBefore     []byte
	serverAfter      []byte
	actions          []string
	installBlocked   bool
	generatedService bool
	genericDev       bool
	scriptHint       string
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
	return runInitWithInput(ctx, flags, os.Stdin, term.IsTerminal(int(os.Stdin.Fd())), stdout, stderr)
}

func runInitWithInput(ctx context.Context, flags initCommand, input io.Reader, interactive bool, stdout, stderr io.Writer) error {
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
	serverUpdated := false
	if len(plan.serverAfter) != 0 {
		if err := replaceRecognizedInitFile(plan.serverPath, plan.serverBefore, plan.serverAfter); err != nil {
			return err
		}
		serverUpdated = true
	}
	gitignoreUpdated, err := ensureTnlGitignore(plan.root)
	if err != nil {
		return err
	}
	if plan.generatedService || packageTypeConfigExists(plan.root) {
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
	if created || installed || frameworkUpdated || serverUpdated || gitignoreUpdated {
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
	if serverUpdated {
		fields = append(fields, clioutput.Field{Label: "updated", Value: plan.serverPath})
	}
	if gitignoreUpdated {
		fields = append(fields, clioutput.Field{Label: "updated", Value: filepath.Join(plan.root, ".gitignore")})
	}
	fields = append(fields, clioutput.Field{Label: "ignored", Value: ".tnl/"})
	blocks := []clioutput.Block{clioutput.Fields(fields...)}
	for _, action := range plan.actions {
		blocks = append(blocks, clioutput.Section("action", clioutput.Text(action)))
	}
	if plan.scriptHint != "" {
		blocks = append(blocks, clioutput.Section("hint", clioutput.Text(plan.scriptHint)))
	}
	footer := "start your app normally, then run tnl wait"
	if len(plan.actions) != 0 {
		footer = "complete the actions above, then start your app normally"
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
		plan.actions = append(plan.actions, presentFailure(failure.Wrap("select package manager", failure.InitPackageManager, err)).action)
	}
	plan.framework, err = detectFramework(root, packageConfig)
	frameworkUnclear := err != nil
	if frameworkUnclear {
		plan.actions = append(plan.actions, presentFailure(failure.Wrap("detect framework", failure.InitFramework, err)).action)
	}
	apiKind := detectAPIServer(packageConfig)
	if apiKind != "" && plan.framework == "vite" && startsAPIServer(packageConfig.Scripts["dev"]) {
		plan.framework = ""
	}

	existingConfigs := existingInitConfigs(root)
	if len(existingConfigs) > 1 {
		return initPlan{}, fmt.Errorf("multiple project configuration files found: %s", strings.Join(existingConfigs, ", "))
	}
	if len(existingConfigs) == 1 {
		plan.configPath = existingConfigs[0]
		if filepath.Base(plan.configPath) == "tnl.config.ts" {
			data, readErr := readInitFile(plan.configPath)
			if readErr != nil {
				return initPlan{}, readErr
			}
			plan.generatedService = bytes.Equal(data, initConfigSource("app"))
		}
	} else {
		plan.configData = initConfigSource("app")
		plan.generatedService = true
	}
	plan.genericDev = packageFound && !frameworkUnclear && plan.framework == "" && apiKind == "" && plan.generatedService
	if plan.genericDev {
		plan.actions = append(plan.actions, "prepare the app before startup with await tnl.prepare({ service: \"app\" }), then await the returned handle's register(server) after the HTTP listener binds.")
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
	} else if apiKind != "" && !frameworkUnclear {
		if err := planAPIServer(&plan, root, apiKind, packageConfig); err != nil {
			return initPlan{}, err
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
      directory: ".",
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
