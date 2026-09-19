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
	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/diagnostic"
)

type cli struct {
	ConfigPath  string         `name:"config" help:"Use an explicit project configuration file." type:"path"`
	NoConfig    bool           `name:"no-config" help:"Do not search for project configuration."`
	NoTelemetry bool           `name:"no-telemetry" env:"TNL_NO_TELEMETRY" help:"Disable pseudonymous usage telemetry."`
	Init        initCommand    `cmd:"" help:"Set up tnl for the current project." group:"start"`
	Dev         devCommand     `cmd:"" help:"Run and publish one development service. Pass its command after --." group:"start"`
	Publish     publishCommand `cmd:"" help:"Publish one local HTTP service." group:"start"`
	Status      statusCommand  `cmd:"" help:"Show local tunnels for this project." group:"start"`
	Login       loginCommand   `cmd:"" help:"Authenticate to a tnl server." group:"start"`
	Config      configCommand  `cmd:"" help:"Inspect project configuration." group:"manage"`
	Team        teamCommand    `cmd:"" help:"Manage teams and memberships." group:"manage"`
	Domain      domainCommand  `cmd:"" help:"Manage team domains." group:"manage"`
	Route       routeCommand   `cmd:"" help:"Manage routes." group:"manage"`
	Logout      logoutCommand  `cmd:"" help:"Revoke and remove the saved control session." group:"manage"`
	Admin       adminCommand   `cmd:"" help:"Administer a self-hosted tnl server." group:"operate"`
	Version     struct{}       `cmd:"" help:"Print release version information." group:"operate"`
}

type openOptions struct {
	Open bool `name:"open" help:"Open the public URL in the default browser once ready."`
}

type tunnelFlags struct {
	Team         string   `name:"team" env:"TNL_TEAM" help:"Team ID or unambiguous display name."`
	Host         string   `name:"host" env:"TNL_HOST" help:"Hostname to publish. Defaults to the worktree label in the current member namespace."`
	Subdomain    string   `name:"subdomain" env:"TNL_SUBDOMAIN" help:"One label beneath the current member namespace."`
	AllowIP      []string `name:"allow-ip" help:"Allow a visitor IP address or prefix. Repeat for each value."`
	AllowAllIPs  bool     `name:"allow-all-ips" env:"TNL_ALLOW_ALL_IPS" help:"Allow visitors from every IP address."`
	Ephemeral    bool     `name:"ephemeral" env:"TNL_EPHEMERAL" help:"Remove the route when this tunnel stops."`
	RequestLimit *int     `name:"request-limit" env:"TNL_REQUEST_LIMIT" help:"Maximum concurrent requests forwarded to the local service, including streams and upgrades. Defaults to 500."`

	allowAllIPsFromCLI bool
	ephemeralFromCLI   bool
}

type remoteFlags struct {
	ServerURL   string `name:"server" env:"TNL_SERVER" help:"Control URL. Defaults to the selected server or https://control.tnl.dev."`
	AccessToken string `name:"access-token" env:"TNL_ACCESS_TOKEN" help:"Access token. Defaults to the saved session."`
	StateDir    string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	ProjectTeam string `kong:"-"`
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
	Server     string `arg:"" name:"server" optional:"" help:"Control URL. Defaults to the selected server or https://control.tnl.dev."`
	ServerURL  string `name:"server" env:"TNL_SERVER" help:"Control URL. Defaults to the selected server or https://control.tnl.dev."`
	StateDir   string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	Token      bool   `name:"token" help:"Use a login token even when OIDC is available."`
	LoginToken string `name:"login-token" env:"TNL_LOGIN_TOKEN" hidden:""`
}

type logoutCommand struct {
	ServerURL string `name:"server" env:"TNL_SERVER" help:"Control URL. Defaults to the selected server or https://control.tnl.dev."`
	StateDir  string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop() // Restore default handling so a second signal terminates immediately.
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
	if err != nil && !errors.Is(err, context.Canceled) {
		var commandErr *childExitError
		if errors.As(err, &commandErr) {
			os.Exit(commandErr.code)
		}
		writeCommandError(os.Stderr, err)
		os.Exit(1)
	}
}

func writeCommandError(output io.Writer, err error) {
	err = classifyCommandError(err)
	command := "tnl"
	if contextual, ok := clioutput.CommandOf(err); ok {
		command = contextual
	}
	if text, ok := diagnostic.TextForCommandError(command, err); ok {
		_, _ = io.WriteString(output, text)
		return
	}
	_ = clioutput.Write(output, clioutput.Frame{
		Command: command,
		State:   "command failed",
		Blocks:  []clioutput.Block{clioutput.Text(err.Error())},
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
	return err
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, reporterFactories ...telemetryReporterFactory) (result error) {
	command := ""
	defer func() {
		result = classifyCommandError(result)
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
		kong.Description("Publish local services at stable public URLs."),
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
		return err
	}
	parsedCommand := canonicalParsedCommand(parsed.Command())
	flags.Dev.Command = devCommand
	applyTunnelCLIUnits(parseArgs, parsedCommand, &flags)
	command = clioutput.CommandTitle("tnl", parsedCommand)
	var project projectConfiguration
	projectStateRoot := ""
	switch parsedCommand {
	case "publish <service-or-target>", "dev <service>", "config check", "config generate":
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
		} else if parsedCommand == "dev <service>" {
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
	var telemetry telemetryReporter
	if !flags.NoTelemetry && len(reporterFactories) != 0 && reporterFactories[0] != nil {
		root, stateErr := commandStateRoot(parsed)
		if stateErr == nil {
			telemetry = reporterFactories[0](root)
			command := canonicalTelemetryCommand(parsed)
			if telemetry != nil && command != "" {
				telemetry.Report(newTelemetryPayload("command", command, "", ""))
			}
		}
	}
	switch parsedCommand {
	case "init":
		return runInit(ctx, flags.Init, stdout, stderr)
	case "config path":
		return runConfigPath(flags, stdout)
	case "config check":
		return runConfigCheck(project, stdout)
	case "config generate":
		return runConfigGenerate(ctx, projectStateRoot, project, stdout, stderr)
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
	case "team create <display-name>":
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
	case "domain release <domain>":
		return runDomainRelease(ctx, flags.Domain.Release, stdout, stderr)
	case "route list":
		return runRouteList(ctx, flags.Route.List, stdout, stderr)
	case "route delete <route-id>":
		return runRouteDelete(ctx, flags.Route.Delete, stdout, stderr)
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

func canonicalParsedCommand(command string) string {
	switch command {
	case "dev":
		return "dev <service>"
	case "publish":
		return "publish <service-or-target>"
	default:
		return command
	}
}

func applyTunnelCLIUnits(args []string, command string, flags *cli) {
	host, subdomain, allowIP, allowAllIPs, ephemeral := false, false, false, false, false
	commandIndex := rootCommandIndex(args)
	for index, argument := range args {
		if index <= commandIndex {
			continue
		}
		switch {
		case argument == "--host" || strings.HasPrefix(argument, "--host="):
			host = true
		case argument == "--subdomain" || strings.HasPrefix(argument, "--subdomain="):
			subdomain = true
		case argument == "--allow-ip" || strings.HasPrefix(argument, "--allow-ip="):
			allowIP = true
		case argument == "--allow-all-ips" || argument == "--no-allow-all-ips" || strings.HasPrefix(argument, "--allow-all-ips="):
			allowAllIPs = true
		case argument == "--ephemeral" || argument == "--no-ephemeral" || strings.HasPrefix(argument, "--ephemeral="):
			ephemeral = true
		}
	}
	apply := func(tunnel *tunnelFlags) {
		tunnel.allowAllIPsFromCLI = allowAllIPs
		tunnel.ephemeralFromCLI = ephemeral
		if host && !subdomain {
			tunnel.Subdomain = ""
		}
		if subdomain && !host {
			tunnel.Host = ""
		}
		if allowIP && !allowAllIPs {
			tunnel.AllowAllIPs = false
		}
	}
	switch command {
	case "publish <service-or-target>":
		apply(&flags.Publish.tunnelFlags)
	case "dev <service>":
		apply(&flags.Dev.tunnelFlags)
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
		case strings.HasPrefix(argument, "--config="), argument == "--no-config", argument == "--no-telemetry":
		case strings.HasPrefix(argument, "-"):
			return -1
		default:
			return index
		}
	}
	return -1
}
