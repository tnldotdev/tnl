package main

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strconv"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/internal/publisherdeployment"
)

type generateCommand struct {
	Check     bool   `name:"check" help:"Read-only comparison of every generated artifact against the evaluated configuration."`
	OutputDir string `name:"output-dir" default:".tnl/generated" help:"Artifact directory, relative to the selected project root unless absolute."`
}

func runGenerate(ctx context.Context, flags cli, output io.Writer) error {
	// generation deliberately bypasses client state, installation salt and telemetry.
	project, err := loadProjectConfigurationWithSalt(ctx, flags, [32]byte{})
	if err != nil {
		return err
	}
	if !project.Found() {
		return failure.Wrap("generate project", failure.ProjectConfigMissing, errors.New("project configuration is required"))
	}
	// normalize the selected root before output safety checks; macOS /var is
	// itself a symlink, while generated output components must remain real.
	canonicalRoot, err := filepath.EvalSymlinks(project.Root)
	if err != nil {
		return err
	}
	project.Root = canonicalRoot
	project.Selection.Path = filepath.Join(canonicalRoot, filepath.Base(project.Selection.Path))
	var source projectconfig.SourceIdentity
	if len(project.Config.Workloads) > 0 {
		source, err = project.SourceIdentity(ctx)
		if err != nil {
			return failure.Wrap("identify workload project", failure.ProjectConfigInvalid, err)
		}
	}
	for _, publisher := range project.Config.Publishers {
		if publisher.AWS == nil {
			continue
		}
		source, err = project.SourceIdentity(ctx)
		if err != nil {
			return failure.Wrap("identify generated project", failure.ProjectConfigInvalid, err)
		}
		break
	}
	directory := flags.Generate.OutputDir
	if !filepath.IsAbs(directory) {
		directory = filepath.Join(project.Root, directory)
	}
	declarations, err := projectmeta.Declarations(project.Config, project.Selection.Path, directory)
	if err != nil {
		return failure.Wrap("declare project types", failure.ProjectConfigInvalid, err)
	}
	python, err := projectmeta.PythonFacade(project.Config, project.Selection.Path)
	if err != nil {
		return failure.Wrap("declare Python project types", failure.ProjectConfigInvalid, err)
	}
	bundle, err := publisherdeployment.Generate(project.Config, source, declarations)
	if err != nil {
		return failure.Wrap("render project artifacts", failure.ProjectConfigInvalid, err)
	}
	state := "generated"
	if flags.Generate.Check {
		state, err = "current", bundle.Check(directory)
	} else {
		err = bundle.Write(directory)
	}
	if err == nil {
		err = projectmeta.WritePythonFacade(directory, python, flags.Generate.Check)
	}
	if err != nil {
		reason := failure.PublisherDeploymentWriteFailed
		if flags.Generate.Check {
			reason = failure.PublisherDeploymentInvalid
		}
		return failure.Wrap("generate publisher deployment", reason, err)
	}
	return writeHumanFrame(output, "tnl generate", state, "commit generated artifacts with project configuration", clioutput.Fields(clioutput.Field{Label: "publishers", Value: strconv.Itoa(len(bundle.Manifest.Publishers))}, clioutput.Field{Label: "output", Value: flags.Generate.OutputDir}))
}
