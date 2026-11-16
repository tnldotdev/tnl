package meta

import (
	"context"
	"errors"
	"path/filepath"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	"github.com/tnldotdev/tnl/internal/failure"
)

// Generate writes portable artifacts, or compares them without writing when
// check is true. the caller evaluates the project with a zero installation salt.
func Generate(ctx context.Context, project clientproject.Project, directory string, check bool) error {
	if !project.Found() {
		return failure.Wrap("generate project", failure.ProjectConfigMissing, errors.New("project configuration is required"))
	}
	// macOS /var is itself a symlink; generated output components must remain real.
	canonicalRoot, err := filepath.EvalSymlinks(project.Root)
	if err != nil {
		return err
	}
	project.Root = canonicalRoot
	project.Selection.Path = filepath.Join(canonicalRoot, filepath.Base(project.Selection.Path))
	if project.Declared == nil {
		return failure.Wrap("generate project", failure.ProjectConfigInvalid, errors.New("project declarations have not been loaded"))
	}
	declaration := *project.Declared
	if !filepath.IsAbs(directory) {
		directory = filepath.Join(project.Root, directory)
	}
	declarations, err := Declarations(declaration, project.Selection.Path, directory)
	if err != nil {
		return failure.Wrap("declare project types", failure.ProjectConfigInvalid, err)
	}
	files, err := PythonFacade(declaration, project.Selection.Path)
	if err != nil {
		return failure.Wrap("declare Python project types", failure.ProjectConfigInvalid, err)
	}
	files["project.d.ts"] = declarations
	files["services.ts"] = serviceFacts(declaration)
	if len(declaration.Workloads) > 0 {
		source, err := project.SourceIdentity(ctx)
		if err != nil {
			return failure.Wrap("identify workload project", failure.ProjectConfigInvalid, err)
		}
		files[workloadmanifest.Filename], err = workloadmanifest.Generate(declaration, source)
		if err != nil {
			return failure.Wrap("render workload metadata", failure.ProjectConfigInvalid, err)
		}
	}
	if err := writeArtifacts(directory, files, check); err != nil {
		reason := failure.ProjectArtifactsWriteFailed
		if check {
			reason = failure.ProjectArtifactsInvalid
		}
		return failure.Wrap("generate project artifacts", reason, err)
	}
	return nil
}
