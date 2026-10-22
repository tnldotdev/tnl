package main

import (
	"context"
	"io"
	"strconv"

	projectmeta "github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	"github.com/tnldotdev/tnl/internal/clioutput"
)

type generateCommand struct {
	Check     bool   `name:"check" help:"Read-only comparison of every generated artifact against the evaluated configuration."`
	OutputDir string `name:"output-dir" default:".tnl/generated" help:"Artifact directory, relative to the selected project root unless absolute."`
}

func runGenerate(ctx context.Context, flags cli, output io.Writer) error {
	// generation deliberately bypasses client state, installation salt and telemetry.
	project, err := resolve.LoadWithSalt(ctx, projectOptions(flags), [32]byte{})
	if err != nil {
		return err
	}
	manifest, err := projectmeta.Generate(ctx, project, flags.Generate.OutputDir, flags.Generate.Check)
	if err != nil {
		return err
	}
	state := "generated"
	if flags.Generate.Check {
		state = "current"
	}
	return writeHumanFrame(output, "tnl generate", state, "commit generated artifacts with project configuration", clioutput.Fields(clioutput.Field{Label: "publishers", Value: strconv.Itoa(len(manifest.Publishers))}, clioutput.Field{Label: "output", Value: flags.Generate.OutputDir}))
}
