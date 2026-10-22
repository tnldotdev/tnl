package meta

import (
	"context"
	"errors"
	"path/filepath"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher/deployment"
)

// Generate writes portable artifacts, or compares them without writing when
// check is true. the caller evaluates the project with a zero installation salt.
func Generate(ctx context.Context, project clientproject.Project, directory string, check bool) (deployment.Manifest, error) {
	if !project.Found() {
		return deployment.Manifest{}, failure.Wrap("generate project", failure.ProjectConfigMissing, errors.New("project configuration is required"))
	}
	// macOS /var is itself a symlink; generated output components must remain real.
	canonicalRoot, err := filepath.EvalSymlinks(project.Root)
	if err != nil {
		return deployment.Manifest{}, err
	}
	project.Root = canonicalRoot
	project.Selection.Path = filepath.Join(canonicalRoot, filepath.Base(project.Selection.Path))
	var source clientproject.SourceIdentity
	if len(project.Config.Workloads) > 0 {
		source, err = project.SourceIdentity(ctx)
		if err != nil {
			return deployment.Manifest{}, failure.Wrap("identify workload project", failure.ProjectConfigInvalid, err)
		}
	}
	for _, publisher := range project.Config.PublisherGroups {
		if publisher.AWS == nil {
			continue
		}
		source, err = project.SourceIdentity(ctx)
		if err != nil {
			return deployment.Manifest{}, failure.Wrap("identify generated project", failure.ProjectConfigInvalid, err)
		}
		break
	}
	if !filepath.IsAbs(directory) {
		directory = filepath.Join(project.Root, directory)
	}
	declarations, err := Declarations(project.Config, project.Selection.Path, directory)
	if err != nil {
		return deployment.Manifest{}, failure.Wrap("declare project types", failure.ProjectConfigInvalid, err)
	}
	python, err := PythonFacade(project.Config, project.Selection.Path)
	if err != nil {
		return deployment.Manifest{}, failure.Wrap("declare Python project types", failure.ProjectConfigInvalid, err)
	}
	bundle, err := deployment.Generate(project.Config, source, declarations)
	if err != nil {
		return deployment.Manifest{}, failure.Wrap("render project artifacts", failure.ProjectConfigInvalid, err)
	}
	if check {
		err = bundle.Check(directory)
	} else {
		err = bundle.Write(directory)
	}
	if err == nil {
		err = WritePythonFacade(directory, python, check)
	}
	if err != nil {
		reason := failure.PublisherDeploymentWriteFailed
		if check {
			reason = failure.PublisherDeploymentInvalid
		}
		return deployment.Manifest{}, failure.Wrap("generate publisher deployment", reason, err)
	}
	return bundle.Manifest, nil
}
