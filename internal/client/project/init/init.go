// package projectinit owns project initialization planning, safe edits, and
// project-local dependency installation. callers provide artifact generation
// and diagnostic presentation without exposing command or publisher state.
package projectinit

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"

	projectmeta "github.com/tnldotdev/tnl/internal/client/project/meta"
)

type Options struct {
	NoInstall bool
	// Generate writes portable artifacts for the selected configuration. init
	// calls it after safe source edits and before wiring Python and TypeScript.
	Generate func(ctx context.Context, root, configurationPath string) error
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
	Actions              []string
	Changed              bool
}

func (plan Plan) Apply(ctx context.Context, options Options) (Result, error) {
	result := Result{
		Root:              plan.Root,
		ConfigurationPath: plan.ConfigurationPath,
		DeclarationsPath:  filepath.Join(plan.Root, projectmeta.GeneratedDirectoryName, projectmeta.DeclarationsName),
		Actions:           slices.Clone(plan.Actions),
	}
	if len(plan.MissingPackages) != 0 && !plan.InstallBlocked {
		command := packageInstallCommand(plan.PackageManager, plan.MissingPackages)
		if options.NoInstall || command == nil {
			result.Actions = append(result.Actions, "Run: "+shellCommand(commandForRecommendation(plan.PackageManager, plan.MissingPackages)))
		} else {
			if err := runInitInstall(ctx, plan.Root, command); err != nil {
				return Result{}, err
			}
			result.InstalledPackages = slices.Clone(plan.MissingPackages)
			result.Changed = true
		}
	}
	if len(plan.NewConfiguration) != 0 {
		if err := createInitFile(plan.ConfigurationPath, plan.NewConfiguration); err != nil {
			return Result{}, err
		}
		result.ConfigurationCreated = true
		result.Changed = true
	}
	if len(plan.NewFrameworkConfig) != 0 {
		if err := createInitFile(plan.FrameworkPath, plan.NewFrameworkConfig); err != nil {
			return Result{}, err
		}
		result.UpdatedPaths = append(result.UpdatedPaths, plan.FrameworkPath)
	}
	if len(plan.ServerReplacement) != 0 {
		if err := replaceRecognizedInitFile(plan.ServerPath, plan.ServerSource, plan.ServerReplacement); err != nil {
			return Result{}, err
		}
		result.UpdatedPaths = append(result.UpdatedPaths, plan.ServerPath)
	}
	gitignoreUpdated, err := ensureTnlGitignore(plan.Root)
	if err != nil {
		return Result{}, err
	}
	if gitignoreUpdated {
		result.UpdatedPaths = append(result.UpdatedPaths, filepath.Join(plan.Root, ".gitignore"))
	}
	result.Actions = append(result.Actions, projectGitignoreActions(ctx, plan.Root)...)
	if err := options.Generate(ctx, plan.Root, plan.ConfigurationPath); err != nil {
		return Result{}, err
	}
	pythonUpdated, pythonActions, err := wirePythonProject(ctx, plan.Root, options.NoInstall)
	if err != nil {
		return Result{}, err
	}
	result.Actions = append(result.Actions, pythonActions...)
	if pythonUpdated || len(pythonActions) != 0 {
		result.PythonPackagePath = filepath.Join(plan.Root, projectmeta.GeneratedDirectoryName, projectmeta.PythonDirectoryName)
	}
	if plan.GeneratedAppService || packageTypeConfigExists(plan.Root) {
		types, err := wireProjectTypeIncludes(plan.Root)
		if err != nil {
			return Result{}, err
		}
		result.Actions = append(result.Actions, types.actions...)
		result.UpdatedPaths = append(result.UpdatedPaths, types.updated...)
	}
	result.Changed = result.Changed || pythonUpdated || len(result.UpdatedPaths) != 0
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
