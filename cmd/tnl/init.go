package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	projectinit "github.com/tnldotdev/tnl/internal/client/project/init"
	"github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"golang.org/x/term"
)

type initCommand struct {
	DryRun    bool             `name:"dry-run" help:"Preview setup without writing files or installing packages."`
	NoInstall bool             `name:"no-install" help:"Write project files but leave dependency installation outstanding."`
	Output    statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

func runInit(ctx context.Context, flags initCommand, stdout, stderr io.Writer) error {
	return runInitWithInput(ctx, flags, os.Stdin, term.IsTerminal(int(os.Stdin.Fd())), stdout, stderr)
}

func runInitWithInput(ctx context.Context, flags initCommand, input io.Reader, interactive bool, stdout, stderr io.Writer) error {
	cwd, err := invocationDirectory(ctx)
	if err != nil {
		return err
	}
	plan, err := projectinit.NewPlan(ctx, cwd, initRecoveryAction)
	if err != nil {
		return err
	}
	if flags.DryRun {
		if flags.Output == statusOutputJSON {
			report, err := plan.Preview(ctx, flags.NoInstall)
			if err != nil {
				return err
			}
			return writeInitJSON(stdout, flags, plan.Root, report)
		}
		return writeInitPlan(stdout, plan, flags.NoInstall)
	}
	result, err := plan.Apply(ctx, projectinit.Options{
		NoInstall: flags.NoInstall,
		Generate: func(ctx context.Context, _, configurationPath string) ([]meta.ArtifactOutcome, error) {
			project, err := resolve.LoadWithSalt(ctx, resolve.Options{Directory: cwd, ConfigPath: configurationPath}, [32]byte{})
			if err != nil {
				return nil, err
			}
			return meta.GenerateWithOutcomes(ctx, project)
		},
	})
	if err != nil {
		return err
	}
	if flags.Output == statusOutputJSON {
		return writeInitJSON(stdout, flags, result.Root, result.Report)
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
		blocks = append(blocks, clioutput.Text("Start your app normally, then run:"), clioutput.Literal(checkoutCommand(ctx, "wait")))
	} else {
		blocks = append(blocks, clioutput.Text("Project is already configured."))
	}
	return writeResult(stdout, blocks...)
}

func writeInitJSON(output io.Writer, flags initCommand, root string, report projectinit.Report) error {
	err := json.NewEncoder(output).Encode(struct {
		SchemaVersion int    `json:"schema_version"`
		Project       string `json:"project"`
		DryRun        bool   `json:"dry_run"`
		NoInstall     bool   `json:"no_install"`
		projectinit.Report
	}{1, root, flags.DryRun, flags.NoInstall, report})
	return failure.Wrap("write init result", failure.OutputUnavailable, err)
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
		Long: "Set up project configuration and the framework integration for your app. Use --dry-run --output json to see the plan without evaluating configuration, or --no-install --output json to see the file changes and remaining steps. Start the app with its usual development command. Sign in with tnl auth login for a shareable HTTPS URL.",
	}
	a.leaf(cInit, &f.Init, func(call commandCall) error {
		return runInit(call.ctx, f.Init, a.out, a.errOut)
	})
	return cInit
}
