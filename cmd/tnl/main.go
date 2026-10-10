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
	"github.com/tnldotdev/tnl/internal/config"
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
	Runtime     runtimeCommand   `cmd:"" hidden:""`
	Wait        waitCommand      `cmd:"" help:"Wait for fresh public readiness checks of configured services." group:"start"`
	Watch       watchCommand     `cmd:"" help:"Follow ordered local app lifecycle events." group:"start"`
	Publish     publishCommand   `cmd:"" help:"Publish an HTTP or HTTPS service or try the built-in demo." group:"start"`
	Status      statusCommand    `cmd:"" help:"Show configured services and local publications; --all includes other projects." group:"start"`
	Requests    requestsCommand  `cmd:"" help:"Inspect recent local HTTP requests." group:"manage"`
	Telemetry   telemetryCommand `cmd:"" help:"Manage the saved usage telemetry choice." group:"manage"`
	Auth        authCommand      `cmd:"" help:"Inspect credentials and explicitly log in or out." group:"manage"`
	Config      configCommand    `cmd:"" help:"Inspect project configuration." group:"manage"`
	Team        teamCommand      `cmd:"" help:"Manage teams and memberships." group:"manage"`
	Domain      domainCommand    `cmd:"" help:"Manage team domains." group:"manage"`
	URL         publicURLCommand `cmd:"" name:"url" help:"Manage public URLs." group:"manage"`
	Share       shareCommand     `cmd:"" help:"Manage preview shares." group:"manage"`
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
	Domain             string                       `name:"domain" env:"TNL_DOMAIN" help:"Ready team domain for the public URL. Defaults to the team's default domain."`
	Name               string                       `name:"name" env:"TNL_NAME" help:"One label beneath the selected domain or member namespace. Defaults to a service-and-worktree name."`
	PublicURL          string                       `name:"public-url" env:"TNL_PUBLIC_URL" help:"Exact public URL hostname or HTTPS origin to publish."`
	AllowIP            []string                     `name:"allow-ip" help:"Add a visitor IP address or prefix; your current IP is also allowed. Repeat for each value."`
	AllowAllIPs        bool                         `name:"allow-all-ips" env:"TNL_ALLOW_ALL_IPS" help:"Allow visitors from every IP instead of a restricted IP policy."`
	Ephemeral          bool                         `name:"ephemeral" env:"TNL_EPHEMERAL" help:"Remove the public URL when this tunnel stops."`
	RequestLimit       *int                         `name:"request-limit" env:"TNL_REQUEST_LIMIT" help:"Maximum concurrent requests forwarded to the local service, including streams and upgrades. Defaults to 500."`
	TargetCAFile       string                       `name:"target-ca-file" env:"TNL_TARGET_CA_FILE" type:"path" help:"Additional PEM certificate authorities for an HTTPS target."`
	RequestInspection  config.RequestInspectionMode `name:"request-inspection" enum:"summary,detailed" default:"summary" help:"Local request capture: summary (default) or detailed, including credentials and bounded bodies."`

	allowAllIPsFromCLI       bool
	ephemeralFromCLI         bool
	domainFromCLI            bool
	requestInspectionFromCLI bool
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
	var telemetry *asyncTelemetryReporter
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr, func(root string) telemetryReporter {
		telemetry = newTelemetryReporter(root)
		return telemetry
	})
	if telemetry != nil {
		waitCtx, cancel := context.WithTimeout(context.Background(), telemetryRequestTimeout)
		telemetry.Wait(waitCtx)
		telemetry.flush(waitCtx)
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
		var reported *reportedError
		if result != nil && machineOutputRequested(args) && !errors.As(result, &reported) {
			result = &machineCommandError{result}
		}
	}()
	var flags cli
	parser, err := kong.New(
		&flags,
		kong.Name("tnl"),
		kong.Description("Publish local services at stable public URLs. Start your app normally with its tnl integration, try tnl publish --demo, or run tnl publish 3000 for an already-running service. By default, only your current IP is allowed to visit."),
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
	applyTunnelCLIUnits(parsed, &flags)
	command = clioutput.CommandTitle("tnl", parsedCommand)
	if parsedCommand == "publish <service-or-target>" && flags.Publish.Demo {
		if err := prepareDemoPublish(&flags.Publish, flags.ConfigPath, term.IsTerminal(int(os.Stdin.Fd()))); err != nil {
			return err
		}
	}
	telemetryCommand, telemetryAction, collectTelemetry := selectedTelemetryCommand(parsed)
	var telemetry *telemetryInvocation
	if !flags.NoTelemetry && collectTelemetry &&
		len(reporterFactories) != 0 && reporterFactories[0] != nil {
		if root, stateErr := commandStateRoot(parsed); stateErr == nil {
			if enabled, preferenceErr := clientstate.TelemetryEnabledAt(ctx, root); preferenceErr == nil && enabled {
				if reporter := reporterFactories[0](root); reporter != nil {
					if invocation, idErr := newTelemetryInvocation(reporter); idErr == nil {
						telemetry = invocation
						telemetry.action = telemetryAction
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
			} else if telemetryCommand != telemetryPublish && !(telemetryCommand == "feedback" && telemetryAction == "watch") {
				telemetry.Report(newTelemetryCompleted(telemetryCommand))
			}
		}()
	}
	var project projectConfiguration
	projectStateRoot := ""
	switch parsedCommand {
	case "runtime address":
		return runRuntimeAddress(ctx, flags.Runtime.Address, stdout)
	case "runtime serve":
		return runRuntimeServe(ctx, flags.Runtime.Serve)
	case "wait", "watch":
		return runAppObservation(ctx, flags, parsedCommand, stdout)
	case "publish <service-or-target>", "config check", "config generate":
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
	case "version":
		_, err := fmt.Fprintln(stdout, buildinfo.Line("tnl"))
		return err
	case "publish <service-or-target>":
		return runPublish(ctx, flags.Publish, stdout, stderr, telemetry)
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
	case "requests list", "requests show <request-id>":
		root, err := projectRoot(ctx, flags)
		if err != nil {
			return err
		}
		if parsedCommand == "requests list" {
			return runRequestsList(ctx, flags.Requests.List, root, stdout)
		}
		return runRequestsShow(ctx, flags.Requests.Show, root, stdout)
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
	case "url update <public-url-id>":
		return runURLUpdate(ctx, flags.URL.Update, stdout, stderr)
	case "url delete <public-url-id>":
		return runURLDelete(ctx, flags.URL.Delete, stdout, stderr)
	case "url credential create <service-or-public-url-id>":
		return runURLCredentialCreate(ctx, flags.URL.Credential.Create, project, stdout, stderr)
	case "url credential list <public-url-id>":
		return runURLCredentialList(ctx, flags.URL.Credential.List, stdout, stderr)
	case "url credential revoke <credential-id>":
		return runURLCredentialRevoke(ctx, flags.URL.Credential.Revoke, stdout, stderr)
	case "share link create <url>":
		return runShareCreate(ctx, flags.Share.Link.Create, project, stdout, stderr)
	case "share list <url>":
		return runShareList(ctx, flags.Share.List, project, stdout, stderr)
	case "share link revoke <share-id>":
		return runShareRevoke(ctx, flags.Share.Link.Revoke, stdout, stderr)
	case "share team create <url>":
		return runShareTeamCreate(ctx, flags.Share.Team.Create, project, stdout, stderr)
	case "share team revoke":
		return runShareTeamRevoke(ctx, flags.Share.Team.Revoke, project, stdout, stderr)
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
	case strings.HasPrefix(command, "tnl auth "):
		return failure.Authentication
	case strings.HasPrefix(command, "tnl publish"):
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
	case "url credential create":
		return "url credential create <service-or-public-url-id>"
	case "url credential list":
		return "url credential list <public-url-id>"
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
	publicURL, name, domain, allowIP, allowAllIPs, ephemeral, open, inspection := false, false, false, false, false, false, false, false
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
		case "allow-all-ips":
			allowAllIPs = true
		case "ephemeral":
			ephemeral = true
		case "request-inspection":
			inspection = true
		}
	}
	apply := func(tunnel *tunnelFlags) {
		tunnel.allowAllIPsFromCLI = allowAllIPs
		tunnel.ephemeralFromCLI = ephemeral
		tunnel.domainFromCLI = domain
		tunnel.requestInspectionFromCLI = inspection
		if publicURL && !name {
			tunnel.Name = ""
		}
		if name && !publicURL {
			tunnel.PublicURL = ""
		}
		if allowIP && !allowAllIPs {
			tunnel.AllowAllIPs = false
		}
	}
	switch canonicalParsedCommand(parsed.Command()) {
	case "publish <service-or-target>":
		apply(&flags.Publish.tunnelFlags)
		flags.Publish.openFromCLI = open
		flags.Publish.demoNameFromCLI = name
	}
}
