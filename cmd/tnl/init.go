package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	projectinit "github.com/tnldotdev/tnl/internal/client/project/init"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"golang.org/x/term"
)

type initCommand struct {
	DryRun    bool `name:"dry-run" help:"Preview setup without writing files or installing packages."`
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
	plan, err := projectinit.NewPlan(ctx, cwd, initRecoveryAction)
	if err != nil {
		return err
	}
	if flags.DryRun {
		return writeInitPlan(stdout, plan, flags.NoInstall)
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
	var blocks []clioutput.Block
	if result.ConfigurationCreated {
		blocks = append(blocks, clioutput.Line("Created "+filepath.Base(result.ConfigurationPath)))
	}
	if len(result.InstalledPackages) != 0 {
		blocks = append(blocks, clioutput.Line("Installed "+strings.Join(result.InstalledPackages, ", ")))
	}
	for _, path := range result.UpdatedPaths {
		verb := "Updated "
		if path == plan.FrameworkPath && len(plan.NewFrameworkConfig) != 0 {
			verb = "Created "
		}
		blocks = append(blocks, clioutput.Line(verb+projectinit.RelativePath(result.Root, path)))
	}
	if result.PythonInstalled {
		blocks = append(blocks, clioutput.Line("Installed the editable Python package "+projectinit.RelativePath(result.Root, result.PythonPackagePath)))
	}
	if len(result.Actions) != 0 {
		blocks = append(blocks, clioutput.Section("Finish setup", initManualSteps(result.Actions)...))
	} else if result.Changed {
		blocks = append(blocks, clioutput.Text("Start your app normally, then run:"), clioutput.Literal("tnl wait"))
	} else {
		blocks = append(blocks, clioutput.Text("Project is already configured."))
	}
	return writeResult(stdout, blocks...)
}

func writeInitPlan(output io.Writer, plan projectinit.Plan, noInstall bool) error {
	var planned, manual []clioutput.Block
	showPath := func(verb, path string) {
		planned = append(planned, clioutput.Line(verb+" "+projectinit.RelativePath(plan.Root, path)))
	}
	showInstall := func(install projectinit.Install) {
		if install.Command == "" {
			return
		}
		if install.Manual {
			manual = append(manual, clioutput.Literal(install.Command))
		} else {
			planned = append(planned, clioutput.Literal(install.Command))
		}
	}
	configVerb := "Use"
	if len(plan.NewConfiguration) != 0 {
		configVerb = "Create"
	}
	showPath(configVerb, plan.ConfigurationPath)
	if len(plan.NewFrameworkConfig) != 0 {
		showPath("Create", plan.FrameworkPath)
	}
	if len(plan.ServerReplacement) != 0 {
		showPath("Update", plan.ServerPath)
	}
	showInstall(plan.PackageInstall(noInstall))
	planned = append(planned, clioutput.Text("Generate files in .tnl/generated."), clioutput.Text("Check Git ignore rules and project type bindings."))
	python, err := plan.PythonInstall(noInstall)
	if err != nil {
		return err
	}
	showInstall(python)
	blocks := []clioutput.Block{clioutput.Section("Planned changes", planned...)}
	manual = append(manual, initManualSteps(plan.Actions)...)
	if len(manual) != 0 {
		blocks = append(blocks, clioutput.Section("Manual steps", manual...))
	}
	return writeResult(output, append(blocks, clioutput.Text("No changes made."))...)
}

func initRecoveryAction(err error) string {
	switch reason, _ := failure.ReasonOf(err); reason {
	case failure.InitPackageManager:
		return "Set packageManager in package.json to pnpm, npm, yarn, or bun."
	case failure.InitFramework:
		return "Choose the framework integration for this project."
	default:
		return presentFailure(err).action
	}
}

func initManualSteps(actions []string) []clioutput.Block {
	var steps []clioutput.Block
	for _, action := range actions {
		steps = append(steps, clioutput.Line(action))
	}
	return steps
}

func (a *commandApp) newInitCommand() *cobra.Command {
	f := a.flags
	cInit := &cobra.Command{
		Use: "init", Short: "Set up tnl in this project.", GroupID: "start",
		Long: "Set up project configuration and the framework integration for your app. Start the app with its usual development command. Sign in with tnl auth login for a shareable HTTPS URL.",
	}
	a.leaf(cInit, &f.Init, func(call commandCall) error {
		return runInit(call.ctx, f.Init, a.out, a.errOut)
	})
	return cInit
}
