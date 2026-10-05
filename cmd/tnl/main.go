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

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/failure"
	"golang.org/x/term"
)

type cli struct {
	ConfigPath  string           `name:"config" help:"Use a project configuration file; put this flag before the command." type:"path"`
	NoConfig    bool             `name:"no-config" help:"Skip project configuration; put this flag before the command."`
	NoTelemetry bool             `name:"no-telemetry" env:"TNL_NO_TELEMETRY" help:"Disable pseudonymous usage telemetry."`
	Init        initCommand      `cmd:"" help:"Set up tnl for the current project." group:"start"`
	Dev         devCommand       `cmd:"" help:"Start and publish a development service; override its child command after --." group:"start"`
	Publish     publishCommand   `cmd:"" help:"Publish a local HTTP service or try the built-in demo." group:"start"`
	Status      statusCommand    `cmd:"" help:"Show locally recorded tunnels for this project; --all includes other projects." group:"start"`
	Telemetry   telemetryCommand `cmd:"" help:"Manage the saved usage telemetry choice." group:"manage"`
	Login       loginCommand     `cmd:"" help:"Authenticate to a tnl server." group:"start"`
	Config      configCommand    `cmd:"" help:"Inspect project configuration." group:"manage"`
	Team        teamCommand      `cmd:"" help:"Manage teams and memberships." group:"manage"`
	Domain      domainCommand    `cmd:"" help:"Manage team domains." group:"manage"`
	URL         publicURLCommand `cmd:"" name:"url" help:"Manage public URLs." group:"manage"`
	Share       shareCommand     `cmd:"" help:"Manage preview shares." group:"manage"`
	Feedback    feedbackCommand  `cmd:"" help:"Read and follow up on preview feedback." group:"manage"`
	Logout      logoutCommand    `cmd:"" help:"Revoke and remove the saved control session." group:"manage"`
	Admin       adminCommand     `cmd:"" help:"Administer a self-hosted tnl server." group:"operate"`
	Version     struct{}         `cmd:"" help:"Print release version information." group:"operate"`
}

type openOptions struct {
	Open        bool `name:"open" help:"Open the public URL in the default browser once ready."`
	openFromCLI bool
}

type tunnelFlags struct {
	teamSelectionFlags `embed:""`
	Domain             string   `name:"domain" env:"TNL_DOMAIN" help:"Ready team domain for the public URL. Defaults to the team's default domain."`
	Name               string   `name:"name" env:"TNL_NAME" help:"One label beneath your member namespace. Defaults to a service-and-worktree name."`
	PublicURL          string   `name:"public-url" help:"Exact HTTPS public URL to publish."`
	AllowIP            []string `name:"allow-ip" help:"Add a visitor IP address or prefix; your current IP is also allowed. Repeat for each value."`
	AllowProvider      []string `name:"allow-provider" help:"Add stripe or github webhook IPs; your current IP is also allowed. Repeat for each provider."`
	AllowAllIPs        bool     `name:"allow-all-ips" env:"TNL_ALLOW_ALL_IPS" help:"Allow visitors from every IP instead of a restricted IP policy."`
	Ephemeral          bool     `name:"ephemeral" env:"TNL_EPHEMERAL" help:"Remove the public URL when this tunnel stops."`
	RequestLimit       *int     `name:"request-limit" env:"TNL_REQUEST_LIMIT" help:"Maximum concurrent requests forwarded to the local service, including streams and upgrades. Defaults to 500."`

	allowAllIPsFromCLI bool
	ephemeralFromCLI   bool
	domainFromCLI      bool
}

type remoteFlags struct {
	ServerURL    string `name:"server" env:"TNL_SERVER" help:"Control URL. Defaults to the project server, selected server, or https://control.tnl.dev."`
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

type configCommand struct {
	Path     struct{}              `cmd:"" help:"Show the selected project configuration path."`
	Check    configCheckCommand    `cmd:"" help:"Validate the selected project configuration."`
	Generate configGenerateCommand `cmd:"" help:"Generate project metadata and TypeScript declarations."`
}

type configCheckCommand struct {
	StateDir string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
}

type configGenerateCommand struct {
	StateDir string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
}

type loginCommand struct {
	Server     string `arg:"" name:"server" optional:"" help:"Control URL. Defaults to the project server, selected server, or https://control.tnl.dev."`
	ServerURL  string `name:"server" env:"TNL_SERVER" help:"Control URL. Defaults to the project server, selected server, or https://control.tnl.dev."`
	StateDir   string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	Token      bool   `name:"token" help:"Use a login token even when OIDC is available."`
	LoginToken string `name:"login-token" env:"TNL_LOGIN_TOKEN" hidden:""`
}

type logoutCommand struct {
	ServerURL string `name:"server" env:"TNL_SERVER" help:"Control URL. Defaults to the project server, selected server, or https://control.tnl.dev."`
	StateDir  string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop() // restore default handling so a second signal terminates immediately.
	}()
	var telemetry *asyncTelemetryReporter
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr, func(root string) telemetryReporter {
		telemetry = newTelemetryReporter(root)
		return telemetry
	})
	if telemetry != nil {
		waitCtx, cancel := context.WithTimeout(context.Background(), telemetryRequestTimeout)
		telemetry.Wait(waitCtx)
		cancel()
	}
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
	var child *childExitError
	children, failures, unowned := 0, 0, 0
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
		if exit, ok := err.(*childExitError); ok {
			children++
			child = exit
			if !owned {
				unowned++
			}
			return
		}
		failures++
		if !owned {
			unowned++
		}
	}
	visit(err, false)
	if failures != 0 || children > 1 {
		if unowned != 0 {
			return 1, err
		}
		return 1, nil
	}
	if children == 1 {
		return child.code, nil
	}
	return 0, nil
}

func writeCommandError(output io.Writer, err error) {
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
	if presented.action != "" {
		blocks = append(blocks, clioutput.Text(presented.action))
	}
	_ = clioutput.Write(output, clioutput.Frame{
		Command: command,
		State:   "command failed",
		Blocks:  blocks,
	})
}

func classifyCommandError(err error) error {
	if err == nil {
		return nil
	}
	if _, classified := diagnostic.CodeOf(err); classified {
		return err
	}
	if errors.Is(err, clientauth.ErrAuthenticationTimeout) {
		return diagnostic.Wrap(diagnostic.AuthenticationTimeout, err)
	}
	if errors.Is(err, controlclient.ErrUnauthenticated) || errors.Is(err, authorityclient.ErrUnauthenticated) {
		return diagnostic.Wrap(diagnostic.AuthenticationRequired, err)
	}
	if errors.Is(err, controlclient.ErrDNSProofPending) || errors.Is(err, authorityclient.ErrDNSProofPending) {
		return diagnostic.Wrap(diagnostic.DNSSetupPending, err)
	}
	if errors.Is(err, controlclient.ErrRateLimited) || errors.Is(err, authorityclient.ErrRateLimited) {
		return diagnostic.Wrap(diagnostic.RateLimited, err)
	}
	if errors.Is(err, controlclient.ErrUnavailable) || errors.Is(err, authorityclient.ErrUnavailable) {
		return diagnostic.Wrap(diagnostic.ServerUnavailable, err)
	}
	return err
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, reporterFactories ...telemetryReporterFactory) (result error) {
	command := ""
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
	}()
	parseArgs, devCommand, err := splitDevPassthrough(args)
	if err != nil {
		return err
	}
	var flags cli
	parser, err := kong.New(
		&flags,
		kong.Name("tnl"),
		kong.Description("Publish local services at stable public URLs. Try tnl publish --demo, run tnl dev to start an app, or tnl publish 3000 for an already-running service. By default, only your current IP is allowed to visit."),
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
	parsed, err := parser.Parse(parseArgs)
	if err != nil {
		var parseError *kong.ParseError
		if errors.As(err, &parseError) && parseError.Context != nil && parseError.Context.Command() != "" {
			command = clioutput.CommandTitle("tnl", canonicalParsedCommand(parseError.Context.Command()))
		}
		return err
	}
	parsedCommand := canonicalParsedCommand(parsed.Command())
	flags.Dev.Command = devCommand
	applyTunnelCLIUnits(parsed, &flags)
	command = clioutput.CommandTitle("tnl", parsedCommand)
	if parsedCommand == "publish <service-or-target>" && flags.Publish.Demo {
		if err := prepareDemoPublish(&flags.Publish, flags.ConfigPath, term.IsTerminal(int(os.Stdin.Fd()))); err != nil {
			return err
		}
	}
	telemetryCommand, collectTelemetry := selectedTelemetryCommand(parsed)
	var telemetry *telemetryInvocation
	if !flags.NoTelemetry && collectTelemetry &&
		len(reporterFactories) != 0 && reporterFactories[0] != nil {
		if root, stateErr := commandStateRoot(parsed); stateErr == nil {
			if enabled, preferenceErr := clientstate.TelemetryEnabledAt(ctx, root); preferenceErr == nil && enabled {
				if reporter := reporterFactories[0](root); reporter != nil {
					if invocation, idErr := newTelemetryInvocation(reporter); idErr == nil {
						telemetry = invocation
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
		}
	}
	failureStage := telemetrySetupStage
	if telemetry != nil {
		telemetry.Report(newTelemetryStarted(telemetryCommand))
		defer func() {
			if result != nil {
				telemetry.failed(telemetryCommand, failureStage, classifyCommandError(result))
			} else if telemetryCommand == telemetryInit || telemetryCommand == telemetryLogin {
				telemetry.Report(newTelemetryCompleted(telemetryCommand))
			}
		}()
	}
	var project projectConfiguration
	projectStateRoot := ""
	switch parsedCommand {
	case "publish <service-or-target>", "dev <service>", "config check", "config generate":
		if parsedCommand == "publish <service-or-target>" && flags.Publish.Demo {
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
		if parsedCommand == "publish <service-or-target>" {
			err = project.applyPublish(&flags.Publish)
		} else if parsedCommand == "dev <service>" && (flags.Dev.Service != "" || len(project.Config.Services) == 0) {
			err = project.applyDev(&flags.Dev)
		}
		if err != nil {
			return err
		}
	default:
		if projectSensitiveCommand(parsedCommand) {
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
	case "config path":
		return runConfigPath(ctx, flags, stdout)
	case "config check":
		return runConfigCheck(project, stdout)
	case "config generate":
		return runConfigGenerate(ctx, projectStateRoot, project, stdout, stderr)
	case "telemetry on":
		return runTelemetryPreference(ctx, flags.Telemetry.On, "on", stdout)
	case "telemetry off":
		return runTelemetryPreference(ctx, flags.Telemetry.Off, "off", stdout)
	case "telemetry status":
		return runTelemetryPreference(ctx, flags.Telemetry.Status, "status", stdout)
	case "login":
		return runLogin(ctx, flags.Login, os.Stdin, stdout, stderr)
	case "logout":
		return runLogout(ctx, flags.Logout, stdout, stderr)
	case "version":
		_, err := fmt.Fprintln(stdout, buildinfo.Line("tnl"))
		return err
	case "publish <service-or-target>":
		return runPublish(ctx, flags.Publish, stdout, stderr, telemetry)
	case "dev <service>":
		if flags.Dev.Service == "" && len(project.Config.Services) > 0 {
			return runCoordinatedDev(ctx, project, flags.Dev, os.Stdin, stdout, stderr, telemetry)
		}
		return runDev(ctx, flags.Dev, os.Stdin, stdout, stderr, telemetry)
	case "status":
		if !flags.Status.All {
			flags.Status.Project, err = projectRoot(ctx, flags)
			if err != nil {
				return err
			}
		}
		return runStatus(ctx, flags.Status, stdout)
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
	case "url delete <public-url-id>":
		return runURLDelete(ctx, flags.URL.Delete, stdout, stderr)
	case "share create <url>":
		return runShareCreate(ctx, flags.Share.Create, project, stdout, stderr)
	case "share list <url>":
		return runShareList(ctx, flags.Share.List, stdout, stderr)
	case "share revoke <share-id>":
		return runShareRevoke(ctx, flags.Share.Revoke, stdout, stderr)
	case "feedback list":
		return runFeedbackList(ctx, flags.Feedback.List, project, stdout, stderr)
	case "feedback inspect <feedback-id>":
		return runFeedbackInspect(ctx, flags.Feedback.Inspect, project, stdout, stderr)
	case "feedback watch":
		return runFeedbackWatch(ctx, flags.Feedback.Watch, project, stdout, stderr)
	case "feedback reply <feedback-id>":
		return runFeedbackMutation(ctx, flags.Feedback.Reply.feedbackMutationCommand, project, "reply", stdout, stderr)
	case "feedback ready <feedback-id>":
		return runFeedbackMutation(ctx, flags.Feedback.Ready.feedbackMutationCommand, project, "fix.ready_for_recheck", stdout, stderr)
	case "feedback resolve <feedback-id>":
		return runFeedbackMutation(ctx, flags.Feedback.Resolve.feedbackMutationCommand, project, "thread.resolved", stdout, stderr)
	case "feedback open <service>":
		return runFeedbackOpen(ctx, flags.Feedback.Open, project, stdout)
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
	case strings.HasPrefix(command, "tnl config "):
		return failure.ProjectConfigInvalid
	case strings.HasPrefix(command, "tnl telemetry "), command == "tnl status":
		return failure.ClientStateUnavailable
	case command == "tnl login", command == "tnl logout":
		return failure.Authentication
	case strings.HasPrefix(command, "tnl publish"), strings.HasPrefix(command, "tnl dev"):
		return failure.TunnelUnavailable
	case strings.HasPrefix(command, "tnl team "):
		return failure.TeamUnavailable
	case strings.HasPrefix(command, "tnl domain "):
		return failure.DomainUnavailable
	case strings.HasPrefix(command, "tnl url "):
		return failure.ServerConflict
	case strings.HasPrefix(command, "tnl share "), strings.HasPrefix(command, "tnl feedback "):
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
	case "dev":
		return "dev <service>"
	case "publish":
		return "publish <service-or-target>"
	case "share create":
		return "share create <url>"
	case "share list":
		return "share list <url>"
	case "feedback open":
		return "feedback open <service>"
	default:
		return command
	}
}

func applyTunnelCLIUnits(parsed *kong.Context, flags *cli) {
	publicURL, name, domain, allowIP, allowProvider, allowAllIPs, ephemeral, open := false, false, false, false, false, false, false, false
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
		case "allow-ip":
			allowIP = true
		case "allow-provider":
			allowProvider = true
		case "allow-all-ips":
			allowAllIPs = true
		case "ephemeral":
			ephemeral = true
		case "port":
			flags.Dev.portFromCLI = true
		case "startup-timeout":
			flags.Dev.startupTimeoutFromCLI = true
		}
	}
	apply := func(tunnel *tunnelFlags) {
		tunnel.allowAllIPsFromCLI = allowAllIPs
		tunnel.ephemeralFromCLI = ephemeral
		tunnel.domainFromCLI = domain
		if publicURL && !name {
			tunnel.Name = ""
		}
		if name && !publicURL {
			tunnel.PublicURL = ""
		}
		if (allowIP || allowProvider) && !allowAllIPs {
			tunnel.AllowAllIPs = false
		}
	}
	switch canonicalParsedCommand(parsed.Command()) {
	case "publish <service-or-target>":
		apply(&flags.Publish.tunnelFlags)
		flags.Publish.openFromCLI = open
		flags.Publish.demoNameFromCLI = name
	case "dev <service>":
		apply(&flags.Dev.tunnelFlags)
		flags.Dev.openFromCLI = open
	}
}

func splitDevPassthrough(args []string) ([]string, []string, error) {
	commandIndex := rootCommandIndex(args)
	if commandIndex < 0 || args[commandIndex] != "dev" {
		return args, nil, nil
	}
	for index := commandIndex + 1; index < len(args); index++ {
		if args[index] != "--" {
			continue
		}
		if index == len(args)-1 {
			return nil, nil, errors.New("development command after -- must not be empty")
		}
		parsed := append([]string(nil), args[:index]...)
		return parsed, append([]string(nil), args[index+1:]...), nil
	}
	return args, nil, nil
}

func rootCommandIndex(args []string) int {
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--config":
			index++
		case strings.HasPrefix(argument, "--config="), argument == "--no-config", argument == "--no-telemetry",
			strings.HasPrefix(argument, "--no-config="), strings.HasPrefix(argument, "--no-telemetry="):
		case strings.HasPrefix(argument, "-"):
			return -1
		default:
			return index
		}
	}
	return -1
}
