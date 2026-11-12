package meta

import (
	"context"
	"errors"
	"path/filepath"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/failure"
)

// Generate writes portable artifacts, or compares them without writing when
// check is true. the caller evaluates the project with a zero installation salt.
func Generate(ctx context.Context, project clientproject.Project, directory string, check bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
	if !filepath.IsAbs(directory) {
		directory = filepath.Join(project.Root, directory)
	}
	facts, err := snapshotServices(project.Config)
	if err != nil {
		return failure.Wrap("snapshot project services", failure.ProjectConfigInvalid, err)
	}
	files := pythonServices(facts)
	files[ProjectName] = typescriptServices(facts)
	if err := ctx.Err(); err != nil {
		return err
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
