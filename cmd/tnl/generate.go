package main

import (
	"context"
	"io"
	"path/filepath"
	"strconv"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
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
	source, err := project.SourceIdentity(ctx)
	if err != nil {
		return failure.Wrap("identify generated project", failure.ProjectConfigInvalid, err)
	}
	bundle, err := publisherdeployment.Generate(project.Config, source)
	if err != nil {
		return failure.Wrap("render publisher deployment", failure.ProjectConfigInvalid, err)
	}
	directory := flags.Generate.OutputDir
	if !filepath.IsAbs(directory) {
		directory = filepath.Join(project.Root, directory)
	}
	state := "generated"
	if flags.Generate.Check {
		state, err = "current", bundle.Check(directory)
	} else {
		err = bundle.Write(directory)
	}
	if err != nil {
		reason := failure.PublisherDeploymentWriteFailed
		if flags.Generate.Check {
			reason = failure.PublisherDeploymentInvalid
		}
		return failure.Wrap("generate publisher deployment", reason, err)
	}
	return writeHumanFrame(output, "tnl generate", state, "commit generated artifacts with project configuration", clioutput.Fields(clioutput.Field{Label: "project key", Value: source.Key}, clioutput.Field{Label: "publishers", Value: strconv.Itoa(len(bundle.Manifest.Publishers))}, clioutput.Field{Label: "output", Value: flags.Generate.OutputDir}))
}
