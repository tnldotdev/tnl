package main

import (
	"context"
	"io"

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
	message := "Generated project files in " + flags.Generate.OutputDir
	if flags.Generate.Check {
		message = "Generated files are current."
	} else if err := meta.WriteCompletion(ctx, project); err != nil {
		return err
	}
	return writeResult(output, clioutput.Line(message))
}

func (a *commandApp) newGenerateCommand() *cobra.Command {
	f := a.flags
	cGenerate := &cobra.Command{
		Use: "generate", Short: "Generate project types and publisher infrastructure.", GroupID: "project",
		Long: "Generate files from your project configuration without contacting the server. Use --check in CI to detect missing or outdated files.",
	}
	a.leaf(cGenerate, &f.Generate, func(call commandCall) error {
		return runGenerate(call.ctx, *f, a.out)
	})
	return cGenerate
}
