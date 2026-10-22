package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	projectinit "github.com/tnldotdev/tnl/internal/client/project/init"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"golang.org/x/term"
)

type initCommand struct {
	NoInstall bool `name:"no-install" help:"Print the dependency command instead of running it."`
}

func runInit(ctx context.Context, flags initCommand, stdout, stderr io.Writer) error {
	return runInitWithInput(ctx, flags, os.Stdin, term.IsTerminal(int(os.Stdin.Fd())), stdout, stderr)
}

func runInitWithInput(ctx context.Context, flags initCommand, input io.Reader, interactive bool, stdout, stderr io.Writer) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("read working directory: %w", err)
	}
	plan, err := projectinit.NewPlan(ctx, cwd, func(err error) string { return presentFailure(err).action })
	if err != nil {
		return err
	}
	result, err := plan.Apply(ctx, projectinit.Options{
		NoInstall: flags.NoInstall,
		Generate: func(ctx context.Context, root, configurationPath string) error {
			return runGenerate(ctx, cli{ConfigPath: configurationPath, Generate: generateCommand{OutputDir: ".tnl/generated"}}, io.Discard)
		},
	})
	if err != nil {
		return err
	}
	state := "already configured"
	if result.Changed {
		state = "configured"
	}
	if len(result.Actions) != 0 {
		state = "needs action"
	}
	fields := []clioutput.Field{{Label: "project", Value: result.Root}}
	if result.ConfigurationCreated {
		fields = append(fields, clioutput.Field{Label: "created", Value: result.ConfigurationPath})
	} else {
		fields = append(fields, clioutput.Field{Label: "config", Value: result.ConfigurationPath})
	}
	if len(result.InstalledPackages) != 0 {
		fields = append(fields, clioutput.Field{Label: "installed", Value: strings.Join(result.InstalledPackages, ", ")})
	}
	for _, path := range result.UpdatedPaths {
		fields = append(fields, clioutput.Field{Label: "updated", Value: path})
	}
	fields = append(fields, clioutput.Field{Label: "types", Value: result.DeclarationsPath})
	if result.PythonPackagePath != "" {
		fields = append(fields, clioutput.Field{Label: "python", Value: result.PythonPackagePath})
	}
	fields = append(fields, clioutput.Field{Label: "ignore", Value: projectinit.LocalIgnoreRule})
	blocks := []clioutput.Block{clioutput.Fields(fields...)}
	for _, action := range result.Actions {
		blocks = append(blocks, clioutput.Section("action", clioutput.Text(action)))
	}
	footer := "start your app normally, then run tnl wait"
	if len(result.Actions) != 0 {
		footer = "complete the actions above, then start your app normally"
	}
	return writeHumanFrame(stdout, "tnl init", state, footer, blocks...)
}
