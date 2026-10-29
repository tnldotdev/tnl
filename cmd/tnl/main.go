package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	"golang.org/x/term"
)

type cli struct {
	ConfigPath  string           `name:"config" help:"Use a project configuration file; put this flag before the command." type:"path"`
	NoConfig    bool             `name:"no-config" help:"Skip project configuration; put this flag before the command."`
	NoTelemetry bool             `name:"no-telemetry" env:"TNL_NO_TELEMETRY" help:"Disable pseudonymous usage telemetry."`
	Init        initCommand      `cmd:"" help:"Set up tnl for the current project." group:"start"`
	Apply       applyCommand     `cmd:"" help:"Reconcile this project's declared services and publisher groups with control." group:"manage"`
	Generate    generateCommand  `cmd:"" help:"Generate portable project types and declared publisher infrastructure offline." group:"manage"`
	Check       struct{}         `cmd:"" help:"Validate project configuration and show its selected path." group:"manage"`
	Bootstrap   bootstrapCommand `cmd:"" help:"Prepare durable publisher identity secrets and parameter bindings for a customer deployment." group:"manage"`
	Audit       auditCommand     `cmd:"" help:"Read team service audit history." group:"manage"`
	Runtime     runtimeCommand   `cmd:"" hidden:""`
	Wait        waitCommand      `cmd:"" help:"Wait for fresh public readiness checks of configured services." group:"start"`
	Watch       watchCommand     `cmd:"" help:"Follow local app and TCP publication events." group:"start"`
	Publish     publishCommand   `cmd:"" help:"Publish a local service or try the built-in demo." group:"start"`
	Connect     connectCommand   `cmd:"" help:"Make an approved service available locally using the current identity." group:"start"`
	Publisher   publisherCommand `cmd:"" help:"Enroll publishers and manage their scoped grants." group:"manage"`
	Service     serviceCommand   `cmd:"" help:"Manage installed publications." group:"operate"`
	Detached    detachedCommand  `cmd:"" help:"Inspect and stop detached publications." group:"operate"`
	Status      statusCommand    `cmd:"" help:"Show local snapshots and fresh signed-in server facts; --all includes other projects." group:"start"`
	Ping        pingCommand      `cmd:"" help:"Check a public URL from this machine as an unauthenticated visitor." group:"start"`
	Inspect     inspectCommand   `cmd:"" help:"Inspect recent local HTTP and supported TCP activity." group:"manage"`
	Telemetry   telemetryCommand `cmd:"" help:"Manage the saved usage telemetry choice." group:"manage"`
	Auth        authCommand      `cmd:"" help:"Inspect credentials and explicitly log in or out." group:"manage"`
	Team        teamCommand      `cmd:"" help:"Manage teams and memberships." group:"manage"`
	Domain      domainCommand    `cmd:"" help:"Manage team domains." group:"manage"`
	URL         publicURLCommand `cmd:"" name:"url" help:"Manage public URLs." group:"manage"`
	Share       shareCommand     `cmd:"" help:"Manage public URL shares and exact-service access." group:"manage"`
	Feedback    feedbackCommand  `cmd:"" help:"Read and follow up on preview feedback." group:"manage"`
	Webhook     webhookCommand   `cmd:"" help:"Choose a receiver for a selected webhook." group:"manage"`
	Alias       aliasCommand     `cmd:"" help:"Choose which worktree serves a project alias." group:"manage"`
	Admin       adminCommand     `cmd:"" help:"Administer a self-hosted tnl server." group:"operate"`
	Version     struct{}         `cmd:"" help:"Print release version information." group:"operate"`
}

type openOptions struct {
	Open        bool `name:"open" help:"Open the public URL in the default browser once ready."`
	openFromCLI bool
}

type tunnelFlags struct {
	teamSelectionFlags `embed:""`
	Domain             string                `name:"domain" env:"TNL_DOMAIN" help:"Ready team domain for the public URL. Defaults to the team's default domain."`
	Name               string                `name:"name" env:"TNL_NAME" help:"One label beneath the selected domain or member namespace. Defaults to a service-and-worktree name."`
	PublicURL          string                `name:"public-url" env:"TNL_PUBLIC_URL" help:"Exact public URL hostname or HTTPS origin to publish."`
	Anonymous          bool                  `name:"anonymous" help:"Do not require a tnl visitor credential; the local service still owns its own authentication."`
	IP                 []string              `name:"ip" help:"Restrict visitor source addresses; repeat for each address, CIDR or 'current'."`
	Ephemeral          bool                  `name:"ephemeral" env:"TNL_EPHEMERAL" help:"Remove the public URL when this tunnel stops."`
	Requests           *int                  `name:"requests" env:"TNL_REQUESTS" help:"Total application requests admitted before the tunnel drains."`
	RateRequests       *int                  `name:"rate-requests" env:"TNL_RATE_REQUESTS" help:"Number of requests admitted per rate period. Requires --rate-per."`
	RatePer            string                `name:"rate-per" env:"TNL_RATE_PER" help:"Rate period, such as 1m. Requires --rate-requests."`
	RateBurst          *int                  `name:"rate-burst" help:"Maximum burst of application work admitted by the rate limit."`
	Concurrency        *int                  `name:"concurrency" env:"TNL_CONCURRENCY" help:"Maximum simultaneous HTTP work or TCP connections. Defaults to 64 for HTTP and 24 for TCP."`
	TargetCAFile       string                `name:"target-ca-file" env:"TNL_TARGET_CA_FILE" type:"path" help:"Additional PEM certificate authorities for an HTTPS target."`
	InspectionMode     config.InspectionMode `name:"inspection-mode" enum:"none,summary" default:"summary" help:"Local HTTP and TCP inspection: summary (default) or none."`

	ephemeralFromCLI         bool
	domainFromCLI            bool
	inspectionModeFromCLI    bool
	inspectionModeFromConfig bool
	workLimits               *config.Limits
	inspection               *config.Inspection
	access                   *config.Access
}

type remoteFlags struct {
	ServerURL    string `name:"server" env:"TNL_SERVER" help:"Control URL. Defaults to the project or selected server."`
	AccessToken  string `name:"access-token" env:"TNL_ACCESS_TOKEN" help:"Access token. Defaults to the saved session."`
	StateDir     string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	ProjectTeam  string `kong:"-"`
	SelectedTeam string `kong:"-"`
}

type teamSelectionFlags struct {
	Team string `name:"team" env:"TNL_TEAM" help:"Team name or ID; overrides the project team for this command."`
}

type scopedTeamFlags struct {
	remoteFlags        `embed:""`
	teamSelectionFlags `embed:""`
}

func (flags scopedTeamFlags) selection() remoteFlags {
	selected := flags.remoteFlags
	selected.SelectedTeam = flags.Team
	return selected
}

type webhookCommand struct {
	Use     webhookUseCommand    `cmd:"" help:"Send this webhook to the ready service in this worktree."`
	Release webhookChoiceCommand `cmd:"" help:"Stop sending this webhook to this worktree."`
}

type webhookUseCommand struct {
	webhookChoiceCommand `embed:""`
	Force                bool `help:"Replace the selected receiver even if its tunnel is running."`
}

type webhookChoiceCommand struct {
	remoteFlags `embed:""`
	Endpoint    string `arg:"" name:"endpoint" help:"Configured webhook endpoint name."`
}

type aliasCommand struct {
	Use     aliasUseCommand    `cmd:"" help:"Use this worktree for an alias."`
	Release aliasChoiceCommand `cmd:"" help:"Return the alias to the primary checkout."`
}

type aliasUseCommand struct {
	aliasChoiceCommand `embed:""`
	Force              bool `help:"Deliberately replace another live worktree's selection."`
}

type aliasChoiceCommand struct {
	scopedTeamFlags `embed:""`
	Name            string `arg:"" name:"name" help:"Configured project alias name."`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop() // restore default handling so a second signal terminates immediately.
	}()
	launchCtx := observability.ExtractLaunch(ctx, os.Getenv(observability.LaunchTraceparent))
	_ = os.Unsetenv(observability.LaunchTraceparent)
	err := runNativeProcess(launchCtx, os.Args[1:], os.Stdout, os.Stderr, newTelemetryReporter)
	if err != nil {
		code, render := terminalResult(err)
		if render != nil {
			writeCommandError(os.Stderr, render)
		}
		if code != 0 {
			os.Exit(code)
		}
	}
}

func terminalResult(err error) (int, error) {
	failures, unowned := 0, 0
	var visit func(error, bool)
	visit = func(err error, owned bool) {
		if err == nil {
			return
		}
		if reported, ok := err.(*reportedError); ok {
			visit(reported.err, true)
			return
		}
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			unwrapped := false
			for _, inner := range joined.Unwrap() {
				if inner != nil {
					visit(inner, owned)
					unwrapped = true
				}
			}
			if unwrapped {
				return
			}
		}
		if wrapped, ok := err.(interface{ Unwrap() error }); ok && wrapped.Unwrap() != nil {
			visit(wrapped.Unwrap(), owned)
			return
		}
		if errors.Is(err, context.Canceled) {
			return
		}
		failures++
		if !owned {
			unowned++
		}
	}
	visit(err, false)
	if failures != 0 {
		if unowned != 0 {
			return 1, err
		}
		return 1, nil
	}
	return 0, nil
}

func writeCommandError(output io.Writer, err error) {
	var machine *machineCommandError
	if errors.As(err, &machine) {
		writeMachineCommandError(output, machine.error)
		return
	}
	err = classifyCommandError(err)
	command := "tnl"
	if contextual, ok := clioutput.CommandOf(err); ok {
		command = contextual
	}
	if text, ok := diagnostic.TextForCommandError(command, err); ok {
		_, _ = io.WriteString(output, text+"\n")
		return
	}
	presented := presentFailure(err)
	blocks := []clioutput.Block{clioutput.Text(presented.message)}
	if typed, ok := failure.Of(err); ok && typed.Reason() == failure.ObservabilityConfigInvalid && typed.Setting() != "" {
		blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "setting", Value: string(typed.Setting())}))
	}
	caseID := failure.KnownCase(err)
	if variant := failure.CaseFor(presented.reason, caseID); variant != nil {
		blocks = append(blocks, clioutput.Text(variant.Description), clioutput.Text(variant.Action))
	} else if presented.action != "" {
		blocks = append(blocks, clioutput.Text(presented.action))
	}
	footer := ""
	if helpURL := failure.HelpURL(presented.reason, caseID); helpURL != "" {
		blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "help", Value: helpURL}))
		footer = string(presented.reason)
	}
	_ = clioutput.Write(output, clioutput.Frame{
		Command: command,
		State:   "command failed",
		Blocks:  blocks,
		Footer:  footer,
	})
}

func classifyCommandError(err error) error {
	if err == nil {
		return nil
	}
	if _, classified := diagnostic.CodeOf(err); classified {
		return err
	}
	if reason, _, owned := failure.Describe(err); owned {
		switch reason {
		case failure.Authentication, failure.ServerUnavailable, failure.ServerRateLimited, failure.DNSPending:
			// common API sentinels have matching CLI diagnostics below.
		default:
			// an operation's more specific meaning takes precedence over its cause.
			return err
		}
	}
	if errors.Is(err, auth.ErrAuthenticationTimeout) {
		return diagnostic.Wrap(diagnostic.AuthenticationTimeout, err)
	}
	if errors.Is(err, clientcontrol.ErrUnauthenticated) || errors.Is(err, clientauthority.ErrUnauthenticated) {
		return diagnostic.Wrap(diagnostic.AuthenticationRequired, err)
	}
	if errors.Is(err, clientcontrol.ErrDNSProofPending) || errors.Is(err, clientauthority.ErrDNSProofPending) {
		return diagnostic.Wrap(diagnostic.DNSSetupPending, err)
	}
	if errors.Is(err, clientcontrol.ErrRateLimited) || errors.Is(err, clientauthority.ErrRateLimited) {
		return diagnostic.Wrap(diagnostic.RateLimited, err)
	}
	if errors.Is(err, clientcontrol.ErrUnavailable) || errors.Is(err, clientauthority.ErrUnavailable) {
		return diagnostic.Wrap(diagnostic.ServerUnavailable, err)
	}
	return err
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, reporterFactories ...telemetryReporterFactory) (result error) {
	command := ""
	machineIntent := false
	defer func() {
		result = classifyCommandError(result)
		if result != nil {
			if _, typed := failure.Of(result); !typed {
				if _, classified := diagnostic.CodeOf(result); !classified {
					result = failure.Wrap(failure.Operation(commandFailureOperation(command)), commandFailureReason(command), result)
				}
			}
		}
		if result != nil && command != "" {
			result = clioutput.WrapCommand(command, result)
		}
		var reported *reportedError
		if result != nil && (machineIntent || machineOutputRequested(args)) && !errors.As(result, &reported) {
			result = &machineCommandError{result}
		}
	}()
	var flags cli
	parser, err := kong.New(
		&flags,
		kong.Name("tnl"),
		kong.Description("take a shortcut through the internet.\n\nPublish local services at stable public URLs. Start your app normally with its tnl integration, try tnl publish --demo, or run tnl publish 3000 for an already-running service. By default, visitors need a current sign-in, link, or token."),
		kong.ExplicitGroups([]kong.Group{
			{Key: "start", Title: "Start here:"},
			{Key: "manage", Title: "Manage:"},
			{Key: "operate", Title: "Operate:"},
		}),
		kong.HelpOptions{Compact: true, FlagsLast: true, WrapUpperBound: 72},
	)
	if err != nil {
		return err
	}
	parsed, err := parser.Parse(args)
	if err != nil {
		var parseError *kong.ParseError
		if errors.As(err, &parseError) && parseError.Context != nil && parseError.Context.Command() != "" {
			command = clioutput.CommandTitle("tnl", canonicalParsedCommand(parseError.Context.Command()))
		}
		return err
	}
	parsedCommand := canonicalParsedCommand(parsed.Command())
	machineIntent = strings.HasPrefix(parsedCommand, "runtime connections ")
	applyTunnelCLIUnits(parsed, &flags)
	command = clioutput.CommandTitle("tnl", parsedCommand)
	if parsedCommand == "generate" {
		return runGenerate(ctx, flags, stdout)
	}
	if parsedCommand == "check" {
		project, err := loadProjectConfigurationWithSalt(ctx, flags, [32]byte{})
		if err != nil {
			return err
		}
		return runCheck(project, stdout)
	}
	if native, _ := ctx.Value(nativeProcessKey{}).(bool); native && parsedCommand != "version" {
		var metrics *observability.Metrics
		ctx, metrics, err = observability.StartProcess(ctx, commandObservabilityRole(parsedCommand, flags).String())
		if err != nil {
			return err
		}
		defer func() {
			budget := observability.CLIShutdownTimeout
			if persistentObservabilityOwner(parsedCommand, flags) {
				budget = observability.ShutdownTimeout
			}
			shutdown, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			_ = metrics.Shutdown(shutdown)
		}()
	}
	ctx, finishCommand := observability.ClientCommand(ctx, parsedCommand)
	defer func() { finishCommand(result) }()
	if flags.Publish.Install || flags.Publisher.Serve.Install || flags.Connect.Start.Install {
		var finishInstall func(error)
		ctx, finishInstall = observability.ClientOperation(ctx, "client.install")
		defer func() { finishInstall(result) }()
	}
	if strings.HasPrefix(parsedCommand, "runtime connections ") {
		return runConnections(ctx, parsedCommand, flags.Runtime.Connections, stdout)
	}
	if parsedCommand == "connect kube-credential" {
		return runKubeCredential(ctx, flags.Connect.KubeCredential, stdout)
	}
	if parsedCommand == "publisher serve" {
		serve := &flags.Publisher.Serve
		if serve.fixedList() {
			return runFixedPublisherGroups(ctx, *serve, stderr)
		}
		if err := validatePublisherServe(*serve); err != nil {
			return err
		}
		if serve.Install {
			options, err := (systemStateFlags{SystemStateDir: serve.SystemStateDir}).options()
			if err != nil {
				return err
			}
			if err := requireInstalledService(ctx, options, nil); err != nil {
				return err
			}
		}
		if serve.Detach {
			if serve.EnrollmentKey == "-" {
				return publisherCLIError("--detach cannot read an enrollment key from stdin; enroll this instance in the foreground first")
			}
			// the owning child consumes the injected secret before loading project
			// configuration; clear the launching process's copy after handoff too.
			defer os.Unsetenv("TNL_GROUP_IDENTITY")
			return detachPublish(ctx, args, serve.StateDir, stdout, "tnl publisher serve")
		}
		if err := preparePublisherGroupIdentity(serve); err != nil {
			return err
		}
		if serve.DetachedChild != "" {
			root, err := clientStateRoot(serve.StateDir)
			if err != nil {
				return err
			}
			var cleanup func()
			ctx, cleanup, err = serveDetached(ctx, root, serve.DetachedChild)
			if err != nil {
				return err
			}
			defer cleanup()
		}
	}
	if parsedCommand == "connect start <name>" {
		connect := &flags.Connect.Start
		if err := validateConnectMode(*connect); err != nil {
			return err
		}
		if connect.Install {
			options, err := (systemStateFlags{SystemStateDir: connect.SystemStateDir}).options()
			if err != nil {
				return err
			}
			if err := requireInstalledService(ctx, options, nil); err != nil {
				return err
			}
		}
		if connect.Detach {
			// resolve and validate the service mode before creating a child.
			connect.detach = func() error { return detachPublish(ctx, args, connect.StateDir, stdout, "tnl connect") }
		}
		root, err := clientStateRoot(connect.StateDir)
		if err != nil {
			return err
		}
		if connect.DetachedChild != "" {
			var cleanup func()
			ctx, cleanup, err = serveDetached(ctx, root, connect.DetachedChild)
			if err != nil {
				return err
			}
			defer cleanup()
		}
		project, err := loadProjectConfiguration(ctx, flags, root)
		if err != nil {
			return err
		}
		if err := project.applyConnect(connect); err != nil {
			return err
		}
	}
	if parsedCommand == "publish <service-or-target>" {
		if flags.Publish.Foreground && (flags.Publish.Install || flags.Publish.Detach) {
			return publisherCLIError("select only one of --foreground, --detach, or --install")
		}
		if flags.Publish.Detach && flags.Publish.Install {
			return publisherCLIError("--install and --detach cannot be combined")
		}
		if flags.Publish.Detach {
			if flags.Publish.EnrollmentKey == "-" {
				return publisherCLIError("--detach cannot read an enrollment key from stdin; use --publisher-identity or --publisher-credential-file")
			}
			if flags.Publish.Output != "human" {
				return publisherCLIError("--detach requires --output=human")
			}
			if flags.Publish.System || flags.Publish.ServiceName != "" || flags.Publish.SystemStateDir != "" || flags.Publish.ServerCAFile != "" {
				return publisherCLIError("--system, --service-name, --system-state-dir, and --server-ca-file require --install")
			}
			return detachPublish(ctx, args, flags.Publish.StateDir, stdout)
		}
		if flags.Publish.DetachedChild != "" {
			root, err := clientStateRoot(flags.Publish.StateDir)
			if err != nil {
				return err
			}
			var cleanup func()
			ctx, cleanup, err = serveDetached(ctx, root, flags.Publish.DetachedChild)
			if err != nil {
				return err
			}
			defer cleanup()
		}
	}
	if parsedCommand == "publish <service-or-target>" && flags.Publish.Demo {
		if err := prepareDemoPublish(&flags.Publish, flags.ConfigPath, term.IsTerminal(int(os.Stdin.Fd()))); err != nil {
			return err
		}
	}
	telemetryCommand, telemetryAction, collectTelemetry := selectedTelemetryCommand(parsed)
	if flags.Publish.Install || flags.Publish.Detach {
		collectTelemetry = false
	}
	var telemetry *telemetryInvocation
	if !flags.NoTelemetry && collectTelemetry &&
		len(reporterFactories) != 0 && reporterFactories[0] != nil {
		if root, stateErr := commandStateRoot(parsed); stateErr == nil {
			if reporter := reporterFactories[0](root); reporter != nil {
				telemetry = newTelemetryInvocation(reporter)
				if telemetryCommand == telemetryPublish {
					mode := telemetryPublishApp
					if flags.Publish.Demo {
						mode = telemetryPublishDemo
					}
					telemetry.SetPublishMode(mode)
				}
			}
		}
	}
	failureStage := telemetrySetupStage
	if telemetry != nil {
		defer func() {
			outcome := telemetryCommandOutcome(ctx, result)
			if outcome == clienttelemetry.CommandFailed {
				telemetry.failed(telemetryCommand, telemetryAction, failureStage, classifyCommandError(result))
			} else {
				telemetry.Report(clienttelemetry.Observation{Event: outcome, Command: telemetryCommand, Action: telemetryAction})
			}
		}()
	}
	var project projectConfiguration
	projectStateRoot := ""
	switch parsedCommand {
	case "runtime endpoint":
		return runRuntimeEndpoint(ctx, flags.Runtime.Endpoint, stdout)
	case "runtime owner-endpoint":
		return runRuntimeOwnerEndpoint(ctx, flags.Runtime.OwnerEndpoint, stdout)
	case "runtime serve":
		return runRuntimeServe(ctx, flags.Runtime.Serve)
	case "wait", "watch":
		return runAppObservation(ctx, flags, parsedCommand, stdout)
	case "publish <service-or-target>":
		if parsedCommand == "publish <service-or-target>" && flags.Publish.Install {
			selection, _, selectErr := selectProjectConfiguration(ctx, flags)
			if selectErr != nil {
				return selectErr
			}
			if selection.Path == "" {
				break
			}
			projectStateRoot, err = commandStateRoot(parsed)
			if err != nil {
				return err
			}
			project, err = loadProjectConfiguration(ctx, flags, projectStateRoot)
			if err != nil {
				return err
			}
			if err := project.applyInstalledService(&flags.Publish); err != nil {
				return err
			}
			break
		}
		if parsedCommand == "publish <service-or-target>" && flags.Publish.Demo {
			break
		}
		if parsedCommand == "publish <service-or-target>" && flags.Publish.PublisherCredentialFile != "" {
			flags.Publish.ServerURL, err = invocation.PublisherCredentialFileServer(flags.Publish.ServerURL, flags.Publish.PublisherCredentialFile)
			if err != nil {
				return err
			}
		}
		projectStateRoot, err = commandStateRoot(parsed)
		if err != nil {
			return err
		}
		project, err = loadProjectConfiguration(ctx, flags, projectStateRoot)
		if err != nil {
			return err
		}
		if parsedCommand == "publish <service-or-target>" {
			err = project.applyPublish(&flags.Publish)
		}
		if err != nil {
			return err
		}
	default:
		if projectSensitiveCommand(parsedCommand) {
			if strings.HasPrefix(parsedCommand, "alias ") {
				selection, _, selectErr := selectProjectConfiguration(ctx, flags)
				if selectErr != nil {
					return selectErr
				}
				if selection.Path == "" {
					return failure.Wrap("select alias", failure.ProjectConfigMissing, errors.New("project configuration with an alias is required"))
				}
			}
			projectStateRoot, err = commandStateRoot(parsed)
			if err != nil {
				return err
			}
			project, err = loadProjectConfiguration(ctx, flags, projectStateRoot)
			if err != nil {
				return err
			}
			if err := applyProjectCommandContext(parsedCommand, project, &flags); err != nil {
				return err
			}
		}
	}
	failureStage = telemetryCommandStage
	switch parsedCommand {
	case "init":
		return runInit(ctx, flags.Init, stdout, stderr)
	case "apply":
		return runApply(ctx, flags.Apply, project, stdout, stderr)
	case "bootstrap <publisher-group>":
		return runBootstrap(ctx, flags.Bootstrap, project, stdout, stderr)
	case "audit list":
		return runAuditList(ctx, flags.Audit.List, stdout, stderr)
	case "telemetry on":
		return runTelemetryPreference(ctx, flags.Telemetry.On, "on", stdout)
	case "telemetry off":
		return runTelemetryPreference(ctx, flags.Telemetry.Off, "off", stdout)
	case "telemetry status":
		return runTelemetryPreference(ctx, flags.Telemetry.Status, "status", stdout)
	case "auth status":
		return runAuthStatus(ctx, flags.Auth.Status, stdout, stderr)
	case "auth login", "auth login run":
		return runLogin(ctx, flags.Auth.Login.loginCommand, os.Stdin, stdout, stderr)
	case "auth login start":
		return runAuthLoginStart(ctx, flags.Auth.Login.loginCommand, os.Stdin, stdout, stderr)
	case "auth login wait <operation-id>":
		return runAuthLoginOperation(ctx, flags.Auth.Login.loginCommand, flags.Auth.Login.Wait.ID, "wait", stdout, stderr)
	case "auth login inspect <operation-id>":
		return runAuthLoginOperation(ctx, flags.Auth.Login.loginCommand, flags.Auth.Login.Inspect.ID, "inspect", stdout, stderr)
	case "auth login cancel <operation-id>":
		return runAuthLoginOperation(ctx, flags.Auth.Login.loginCommand, flags.Auth.Login.Cancel.ID, "cancel", stdout, stderr)
	case "auth logout":
		return runLogout(ctx, flags.Auth.Logout, stdout, stderr)
	case "auth browser <url>":
		return runAuthBrowser(ctx, flags.Auth.Browser, stdout, stderr)
	case "version":
		_, err := fmt.Fprintln(stdout, buildinfo.Line("tnl"))
		return err
	case "publish <service-or-target>":
		flags.Publish.telemetryDisabled = flags.NoTelemetry
		return runPublish(ctx, flags.Publish, stdout, stderr, telemetry)
	case "connect available":
		return runConnectAvailable(ctx, flags.Connect.Available, stdout, stderr)
	case "connect start <name>":
		flags.Connect.Start.telemetryDisabled = flags.NoTelemetry
		return runConnectStart(ctx, flags.Connect.Start, stdout, stderr)
	case "connect list":
		return runConnectJobs(ctx, flags.Connect.List, "", "list", stdout)
	case "connect stop <name>":
		return runConnectJobs(ctx, flags.Connect.Stop.connectListCommand, flags.Connect.Stop.Name, "stop", stdout)
	case "connect remove <name>":
		return runConnectJobs(ctx, flags.Connect.Remove.connectListCommand, flags.Connect.Remove.Name, "remove", stdout)
	case "publisher enroll <public-url-id>", "publisher enroll":
		if flags.Publisher.Enroll.Group != "" {
			return runPublisherGroupEnrollment(ctx, flags.Publisher.Enroll, project, stdout, stderr)
		}
		if flags.Publisher.Enroll.ProjectKey != "" || flags.Publisher.Enroll.Members != 1 || flags.Publisher.Enroll.ExpiresIn != 10*time.Minute {
			return publisherCLIError("--project-key, --members, and --expires-in require --group")
		}
		return runPublisherEnroll(ctx, flags.Publisher.Enroll, stdout, stderr)
	case "publisher current":
		return runPublisherCurrent(ctx, flags.Publisher.Current, stdout)
	case "publisher setup":
		return runPublisherSetup(ctx, flags.Publisher.Setup, stdout, stderr)
	case "publisher serve":
		return runPublisherServe(ctx, flags.Publisher.Serve, project, stdout, stderr)
	case "publisher rename <group> <name>":
		return runPublisherGroupRename(ctx, flags.Publisher.Rename, project, stdout, stderr)
	case "publisher namespace rename <group> <label>":
		return runPublisherNamespaceRename(ctx, flags.Publisher.Namespace.Rename, project, stdout, stderr)
	case "publisher provision":
		return runPublisherProvision(ctx, flags.Publisher.Provision, project, stdout, stderr)
	case "publisher list":
		return runPublisherList(ctx, flags.Publisher.List, stdout, stderr)
	case "publisher revoke <publisher-identity-id>":
		return runPublisherRevoke(ctx, flags.Publisher.Revoke, stdout, stderr)
	case "publisher grant add <publisher-identity-id>":
		return runPublisherGrantAdd(ctx, flags.Publisher.Grant.Add, stdout, stderr)
	case "publisher grant revoke <publisher-identity-id> <grant-id>":
		return runPublisherGrantRevoke(ctx, flags.Publisher.Grant.Revoke, stdout, stderr)
	case "service install":
		return runServiceInstall(ctx, flags.Service.Install, stdout, nil)
	case "service register":
		return runPublicationRegister(ctx, flags.Service.Register, os.Stdin, stdout, nil)
	case "service start <job>":
		return runServiceStart(ctx, flags.Service.Start, stdout, nil)
	case "service stop <job>":
		return runServiceStop(ctx, flags.Service.Stop, stdout)
	case "service remove <job>":
		return runServiceRemove(ctx, flags.Service.Remove, stdout)
	case "service list":
		return runServiceList(ctx, flags.Service.List, stdout)
	case "service status <job>":
		return runServiceStatus(ctx, flags.Service.Status, stdout)
	case "service serve":
		return runServiceServe(ctx, flags.Service.Serve)
	case "detached list":
		return runDetachedList(flags.Detached.List, stdout)
	case "detached stop <id>":
		return runDetachedStop(flags.Detached.Stop, stdout)
	case "status":
		if !flags.Status.All {
			flags.Status.Project, err = projectRoot(ctx, flags)
			if err != nil {
				return err
			}
			stateRoot, err := clientStateRoot(flags.Status.StateDir)
			if err != nil {
				return err
			}
			flags.Status.Configuration, err = loadProjectConfiguration(ctx, flags, stateRoot)
			if err != nil {
				return err
			}
		}
		return runStatus(ctx, flags.Status, stdout)
	case "ping <url>":
		return runPing(ctx, flags.Ping, stdout)
	case "inspect list", "inspect show <inspection-number>":
		root, err := projectRoot(ctx, flags)
		if err != nil {
			return err
		}
		if parsedCommand == "inspect list" {
			return runInspectList(ctx, flags.Inspect.List, root, stdout)
		}
		return runInspectShow(ctx, flags.Inspect.Show, root, stdout)
	case "webhook use <endpoint>":
		return runWebhookChoice(ctx, flags.Webhook.Use.webhookChoiceCommand, project, true, flags.Webhook.Use.Force, stdout)
	case "webhook release <endpoint>":
		return runWebhookChoice(ctx, flags.Webhook.Release, project, false, false, stdout)
	case "alias use <name>":
		return runAliasChoice(ctx, flags.Alias.Use.aliasChoiceCommand, project, true, flags.Alias.Use.Force, stdout, stderr)
	case "alias release <name>":
		return runAliasChoice(ctx, flags.Alias.Release, project, false, false, stdout, stderr)
	case "team current":
		return runTeamCurrent(ctx, flags.Team.Current, stdout, stderr)
	case "team list":
		return runTeamList(ctx, flags.Team.List, stdout, stderr)
	case "team use <team>":
		return runTeamUse(ctx, flags.Team.Use, stdout, stderr)
	case "team create <name>":
		return runTeamCreate(ctx, flags.Team.Create, stdout, stderr)
	case "team members":
		return runTeamMembers(ctx, flags.Team.Members, stdout, stderr)
	case "team invite create":
		return runTeamInviteCreate(ctx, flags.Team.Invite.Create, stdout, stderr)
	case "team invite list":
		return runTeamInviteList(ctx, flags.Team.Invite.List, stdout, stderr)
	case "team invite revoke <invitation-id>":
		return runTeamInviteRevoke(ctx, flags.Team.Invite.Revoke, stdout, stderr)
	case "team join <secret>":
		return runTeamJoin(ctx, flags.Team.Join, stdout, stderr)
	case "team member set-role <membership-id>":
		return runTeamMemberSetRole(ctx, flags.Team.Member.SetRole, stdout, stderr)
	case "team member remove <membership-id>":
		return runTeamMemberRemove(ctx, flags.Team.Member.Remove, stdout, stderr)
	case "team feedback get":
		return runTeamFeedbackGet(ctx, flags.Team.Feedback.Get, stdout, stderr)
	case "team feedback set <authors>":
		return runTeamFeedbackSet(ctx, flags.Team.Feedback.Set, stdout, stderr)
	case "domain claim <domain>":
		return runDomainClaim(ctx, flags.Domain.Claim, stdout, stderr)
	case "domain default <domain>":
		return runDomainDefault(ctx, flags.Domain.Default, stdout, stderr)
	case "domain list":
		return runDomainList(ctx, flags.Domain.List, stdout, stderr)
	case "domain status <domain>":
		return runDomainStatus(ctx, flags.Domain.Status, stdout, stderr)
	case "domain release <domain>":
		return runDomainRelease(ctx, flags.Domain.Release, stdout, stderr)
	case "url list":
		return runURLList(ctx, flags.URL.List, stdout, stderr)
	case "url inventory":
		return runURLInventory(ctx, flags.URL.Inventory, stdout, stderr)
	case "url available":
		return runURLAvailable(ctx, flags.URL.Available, stdout, stderr)
	case "url access show <url>":
		return runURLAccessShow(ctx, flags.URL.Access.Show, stdout, stderr)
	case "url access set <url> <mode>":
		return runURLAccessSet(ctx, flags.URL.Access.Set, stdout, stderr)
	case "url update <public-url-id>":
		return runURLUpdate(ctx, flags.URL.Update, stdout, stderr)
	case "url delete <public-url-id>":
		return runURLDelete(ctx, flags.URL.Delete, stdout, stderr)
	case "share link create <url>":
		return runShareCreate(ctx, flags.Share.Link.Create, project, stdout, stderr)
	case "share token create <url>":
		return runShareTokenCreate(ctx, flags.Share.Token.Create, project, stdout, stderr)
	case "share list <url>":
		return runShareList(ctx, flags.Share.List, project, stdout, stderr)
	case "share revoke <share-id>":
		return runShareRevoke(ctx, flags.Share.Revoke, stdout, stderr)
	case "share team create <url>":
		return runShareTeamCreate(ctx, flags.Share.Team.Create, project, stdout, stderr)
	case "share team revoke", "share team revoke <url>":
		return runShareTeamRevoke(ctx, flags.Share.Team.Revoke, project, stdout, stderr)
	case "share invite create <url>":
		return runShareInviteCreate(ctx, flags.Share.Invite.Create, stdout, stderr)
	case "share invite accept <secret>":
		return runShareInviteAccept(ctx, flags.Share.Invite.Accept, stdout, stderr)
	case "share invite list <url>":
		return runShareInviteList(ctx, flags.Share.Invite.List, stdout, stderr)
	case "share invite revoke <url> <invitation-id>":
		return runShareInviteRevoke(ctx, flags.Share.Invite.Revoke, stdout, stderr)
	case "share service invite create <name>":
		return runServiceShareInviteCreate(ctx, flags.Share.Service.Invite.Create, project, stdout, stderr)
	case "share service invite accept <secret>":
		return runServiceShareInviteAccept(ctx, flags.Share.Service.Invite.Accept, stdout, stderr)
	case "share service list <name>":
		return runServiceShareList(ctx, flags.Share.Service.List, project, stdout, stderr)
	case "share service revoke <name> <access-id>":
		return runServiceShareRevoke(ctx, flags.Share.Service.Revoke, project, stdout, stderr)
	case "share service link create <name>":
		return runServiceShareHTTPCreate(ctx, flags.Share.Service.Link.Create, project, "share", stdout, stderr)
	case "share service token create <name>":
		return runServiceShareHTTPCreate(ctx, flags.Share.Service.Token.Create, project, "token", stdout, stderr)
	case "feedback list":
		return runFeedbackList(ctx, flags.Feedback.List, project, stdout, stderr)
	case "feedback inspect <feedback-id>":
		return runFeedbackInspect(ctx, flags.Feedback.Inspect, project, stdout, stderr)
	case "feedback watch":
		return runFeedbackWatch(ctx, flags.Feedback.Watch, project, stdout, stderr)
	case "feedback reply <feedback-id>":
		return runFeedbackMutation(ctx, flags.Feedback.Reply.feedbackMutationCommand, project, "reply", stdout, stderr)
	case "feedback update <feedback-id>":
		return runFeedbackMutation(ctx, flags.Feedback.Update.feedbackMutationCommand, project, "update", stdout, stderr)
	case "feedback resolve <feedback-id>":
		return runFeedbackMutation(ctx, flags.Feedback.Resolve.feedbackMutationCommand, project, "thread.resolved", stdout, stderr)
	case "feedback reopen <feedback-id>":
		return runFeedbackMutation(ctx, flags.Feedback.Reopen.feedbackMutationCommand, project, "thread.reopened", stdout, stderr)
	case "admin server status":
		return runAdminServerStatus(ctx, flags.Admin.Server.Status, stdout, stderr)
	case "admin relays list":
		return runAdminRelaysList(ctx, flags.Admin.Relays.List, stdout, stderr)
	case "admin relays drain <relay-id>":
		return runAdminRelayDrain(ctx, flags.Admin.Relays.Drain, stdout, stderr)
	case "admin maintenance list":
		return runAdminMaintenanceList(ctx, flags.Admin.Maintenance.List, stdout, stderr)
	case "admin maintenance allow <name>":
		return runAdminMaintenanceSet(ctx, flags.Admin.Maintenance.Allow, true, stdout, stderr)
	case "admin maintenance block <name>":
		return runAdminMaintenanceSet(ctx, flags.Admin.Maintenance.Block, false, stdout, stderr)
	default:
		return errors.New("command is required")
	}
}

type nativeProcessKey struct{}

func persistentObservabilityOwner(command string, flags cli) bool {
	return commandObservabilityRole(command, flags) == observability.RolePublisher || command == "runtime connections serve" || command == "connect start <name>" && !flags.Connect.Start.Detach && !flags.Connect.Start.Install
}

func commandObservabilityRole(command string, flags cli) observability.Role {
	switch command {
	case "publish <service-or-target>":
		if !flags.Publish.Install && !flags.Publish.Detach {
			return observability.RolePublisher
		}
	case "publisher serve":
		if !flags.Publisher.Serve.Detach && !flags.Publisher.Serve.Install {
			return observability.RolePublisher
		}
	case "runtime serve", "service serve":
		return observability.RolePublisher
	}
	return observability.RoleClient
}

func commandFailureOperation(command string) string {
	if command == "" {
		return "parse command"
	}
	return command
}

func commandFailureReason(command string) failure.Reason {
	switch {
	case command == "tnl init":
		return failure.InitFailed
	case command == "tnl check", command == "tnl generate":
		return failure.ProjectConfigInvalid
	case strings.HasPrefix(command, "tnl telemetry "), command == "tnl status":
		return failure.ClientStateUnavailable
	case strings.HasPrefix(command, "tnl auth "):
		return failure.Authentication
	case strings.HasPrefix(command, "tnl publish"):
		return failure.TunnelUnavailable
	case strings.HasPrefix(command, "tnl connect"):
		return failure.TunnelUnavailable
	case strings.HasPrefix(command, "tnl team "):
		return failure.TeamUnavailable
	case strings.HasPrefix(command, "tnl domain "):
		return failure.DomainUnavailable
	case strings.HasPrefix(command, "tnl url "):
		return failure.ServerConflict
	case strings.HasPrefix(command, "tnl share "), strings.HasPrefix(command, "tnl feedback "):
		return failure.ServerConflict
	case strings.HasPrefix(command, "tnl webhook "):
		return failure.ServerConflict
	case strings.HasPrefix(command, "tnl admin "):
		return failure.AdminUnavailable
	case command == "tnl version":
		return failure.OutputUnavailable
	default:
		return failure.InvalidCommand
	}
}

func canonicalParsedCommand(command string) string {
	switch command {
	case "auth login run":
		return "auth login"
	case "publish":
		return "publish <service-or-target>"
	case "publisher enroll":
		return "publisher enroll <public-url-id>"
	case "url ip set <url>":
		return "url ip set <url> <prefixes>"
	case "share link create":
		return "share link create <url>"
	case "share team create":
		return "share team create <url>"
	case "share list":
		return "share list <url>"
	default:
		return command
	}
}

func applyTunnelCLIUnits(parsed *kong.Context, flags *cli) {
	publicURL, name, domain, ephemeral, open := false, false, false, false, false
	inspectionMode := false
	for _, path := range parsed.Path {
		if path.Flag == nil {
			continue
		}
		switch path.Flag.Name {
		case "public-url":
			publicURL = true
		case "name":
			name = true
		case "domain":
			domain = true
		case "open":
			open = true
		case "ephemeral":
			ephemeral = true
		case "inspection-mode":
			inspectionMode = true
		}
	}
	apply := func(tunnel *tunnelFlags) {
		tunnel.ephemeralFromCLI = ephemeral
		tunnel.domainFromCLI = domain
		tunnel.inspectionModeFromCLI = inspectionMode
		if publicURL && !name {
			tunnel.Name = ""
		}
		if name && !publicURL {
			tunnel.PublicURL = ""
		}
	}
	switch canonicalParsedCommand(parsed.Command()) {
	case "publish <service-or-target>":
		apply(&flags.Publish.tunnelFlags)
		flags.Publish.openFromCLI = open
		flags.Publish.demoNameFromCLI = name
	}
}
