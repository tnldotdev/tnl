// package projectinit owns project initialization planning, safe edits, and
// project-local dependency installation. callers provide artifact generation
// and diagnostic presentation without exposing command or publisher state.
package init

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"

	"github.com/tnldotdev/tnl/internal/client/project/meta"
)

type Options struct {
	NoInstall bool
	// Generate writes portable artifacts for the selected configuration. init
	// calls it after safe source edits and before wiring Python and TypeScript.
	Generate func(ctx context.Context, root, configurationPath string) ([]meta.ArtifactOutcome, error)
}

// Result contains operation facts in their existing presentation order.
type Result struct {
	Root                 string
	ConfigurationPath    string
	ConfigurationCreated bool
	InstalledPackages    []string
	UpdatedPaths         []string
	DeclarationsPath     string
	PythonPackagePath    string
	PythonInstalled      bool
	Actions              []string
	Changed              bool
	Report               Report
}

func (plan Plan) Apply(ctx context.Context, options Options) (Result, error) {
	return plan.run(ctx, options, false)
}

// Preview uses the same edit decisions as Apply without running installers,
// evaluating the project configuration or writing files.
func (plan Plan) Preview(ctx context.Context, noInstall bool) (Report, error) {
	result, err := plan.run(ctx, Options{NoInstall: noInstall}, true)
	return result.Report, err
}

func (plan Plan) run(ctx context.Context, options Options, preview bool) (Result, error) {
	result := Result{
		Root:              plan.Root,
		ConfigurationPath: plan.ConfigurationPath,
		DeclarationsPath:  filepath.Join(plan.Root, meta.GeneratedDirectoryName, meta.DeclarationsName),
		Actions:           slices.Clone(plan.Actions),
		Report:            Report{Files: []FileChange{}, Steps: []Step{}},
	}
	record := func(edit fileEdit) error {
		if !preview {
			if err := edit.apply(); err != nil {
				return err
			}
		}
		result.Report.Files = append(result.Report.Files, FileChange{
			Path: RelativePath(plan.Root, edit.path), Status: fileStatus(edit, preview),
		})
		return nil
	}
	result.Report.outstanding(plan.Actions)
	if install := plan.PackageInstall(options.NoInstall); install.Command != "" {
		if err := result.Report.install(ctx, plan.Root, "install_node", install, preview); err != nil {
			return Result{}, err
		}
		if install.Manual {
			result.Actions = append(result.Actions, install.Command)
		} else {
			result.InstalledPackages = slices.Clone(plan.MissingPackages)
			result.Changed = true
		}
	}
	if err := record(fileEdit{path: plan.ConfigurationPath, replacement: plan.NewConfiguration}); err != nil {
		return Result{}, err
	}
	if len(plan.NewConfiguration) != 0 {
		result.ConfigurationCreated = true
		result.Changed = true
	}
	if plan.FrameworkPath != "" {
		if err := record(fileEdit{path: plan.FrameworkPath, replacement: plan.NewFrameworkConfig}); err != nil {
			return Result{}, err
		}
		if len(plan.NewFrameworkConfig) != 0 {
			result.UpdatedPaths = append(result.UpdatedPaths, plan.FrameworkPath)
		}
	}
	if plan.ServerPath != "" {
		if err := record(fileEdit{path: plan.ServerPath, before: plan.ServerSource, replacement: plan.ServerReplacement}); err != nil {
			return Result{}, err
		}
		if len(plan.ServerReplacement) != 0 {
			result.UpdatedPaths = append(result.UpdatedPaths, plan.ServerPath)
		}
	}
	ignore, err := planTnlGitignore(plan.Root)
	if err != nil {
		return Result{}, err
	}
	if err := record(ignore); err != nil {
		return Result{}, err
	}
	if ignore.replacement != nil {
		result.UpdatedPaths = append(result.UpdatedPaths, ignore.path)
	}
	if preview {
		result.Report.Steps = append(result.Report.Steps,
			Step{Kind: "check_gitignore", Status: "conditional", Message: "Check effective Git ignore rules after source edits."},
			Step{Kind: "generate", Status: "conditional", Path: meta.GeneratedDirectoryName, Message: "Generated files and local completion depend on the evaluated configuration."},
		)
	} else {
		actions := projectGitignoreActions(ctx, plan.Root)
		result.Actions = append(result.Actions, actions...)
		result.Report.outstanding(actions)
		artifacts, err := options.Generate(ctx, plan.Root, plan.ConfigurationPath)
		if err != nil {
			return Result{}, err
		}
		for _, outcome := range artifacts {
			result.Report.Files = append(result.Report.Files, FileChange{Path: outcome.Path, Status: outcome.Status})
		}
		result.Report.Steps = append(result.Report.Steps, Step{Kind: "generate", Status: "executed", Path: meta.GeneratedDirectoryName})
	}
	python, err := plan.PythonInstall(options.NoInstall)
	if err != nil {
		return Result{}, err
	}
	if python.Command != "" {
		if err := result.Report.install(ctx, plan.Root, "install_python", python, preview); err != nil {
			return Result{}, err
		}
		result.PythonPackagePath = filepath.Join(plan.Root, meta.GeneratedDirectoryName, meta.PythonDirectoryName)
		result.PythonInstalled = !python.Manual
		if python.Manual {
			result.Actions = append(result.Actions, python.Command)
		}
	}
	if plan.GeneratedAppService || packageTypeConfigExists(plan.Root) {
		types, err := visitProjectTypeIncludes(plan.Root, record)
		if err != nil {
			return Result{}, err
		}
		result.Actions = append(result.Actions, types.actions...)
		result.Report.outstanding(types.actions)
		result.UpdatedPaths = append(result.UpdatedPaths, types.updated...)
	}
	result.Changed = result.Changed || result.PythonInstalled || len(result.UpdatedPaths) != 0
	return result, nil
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
