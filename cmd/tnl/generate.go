package main

import (
	"context"
	"io"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/tnldotdev/tnl/internal/client/project/meta"
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
	if err := meta.Generate(ctx, project, flags.Generate.OutputDir, flags.Generate.Check); err != nil {
		return err
	}
	state := "generated"
	if flags.Generate.Check {
		state = "current"
	} else if err := meta.WriteCompletion(ctx, project); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl generate", state, "commit generated artifacts with project configuration", clioutput.Fields(clioutput.Field{Label: "services", Value: strconv.Itoa(len(project.Config.Services))}, clioutput.Field{Label: "output", Value: flags.Generate.OutputDir}))
}

func (a *commandApp) newGenerateCommand() *cobra.Command {
	f := a.flags
	cGenerate := &cobra.Command{Use: "generate", Short: "Generate portable project types and declared publisher infrastructure offline.", GroupID: "manage"}
	a.leaf(cGenerate, &f.Generate, func(call commandCall) error {
		return runGenerate(call.ctx, *f, a.out)
	})
	return cGenerate
}
