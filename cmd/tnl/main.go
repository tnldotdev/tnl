package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/publisher"
)

type cli struct {
	ConfigPath  string         `name:"config" help:"Use an explicit project configuration file." type:"path"`
	NoConfig    bool           `name:"no-config" help:"Disable project configuration discovery."`
	NoTelemetry bool           `name:"no-telemetry" env:"TNL_NO_TELEMETRY" help:"Disable pseudonymous usage telemetry."`
	Publish     publishCommand `cmd:"" help:"Publish one local HTTP service."`
	Dev         devCommand     `cmd:"" help:"Run and publish a development server."`
	Config      configCommand  `cmd:"" help:"Inspect project configuration."`
	Status      statusCommand  `cmd:"" help:"Show local tunnel status."`
	Team        teamCommand    `cmd:"" help:"Manage teams and memberships."`
	Domain      domainCommand  `cmd:"" help:"Manage team domains."`
	Route       routeCommand   `cmd:"" help:"Manage durable routes."`
	Login       loginCommand   `cmd:"" help:"Authenticate to a tnl server."`
	Logout      logoutCommand  `cmd:"" help:"Revoke and remove the saved control session."`
	Admin       adminCommand   `cmd:"" help:"Administer a self-hosted tnl server."`
	Version     struct{}       `cmd:"" help:"Print release version information."`
}

type openOptions struct {
	Open bool `name:"open" help:"Open the public URL in the default browser once ready."`
}

type tunnelFlags struct {
	Host      string   `name:"host" env:"TNL_HOST" help:"Exact hostname to publish; defaults to the current member namespace."`
	Subdomain string   `name:"subdomain" env:"TNL_SUBDOMAIN" help:"One label beneath the current member namespace."`
	AllowIP   []string `name:"allow-ip" help:"Allow a visitor IP address or prefix; repeat for each value."`
	Public    bool     `name:"public" help:"Allow visitors from every IP address."`
}

type remoteFlags struct {
	ServerURL   string `name:"server" env:"TNL_SERVER" help:"tnl server HTTPS origin; defaults to the selected server or https://control.tnl.dev."`
	AccessToken string `name:"access-token" env:"TNL_ACCESS_TOKEN" help:"Server access token; defaults to the saved login."`
	StateDir    string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent client state."`
}

type publishCommand struct {
	openOptions `embed:""`
	remoteFlags `embed:""`
	tunnelFlags `embed:""`
	Target      string `arg:"" name:"target" optional:"" help:"Local port or loopback-only HTTP URL."`
	Output      string `name:"output" enum:"human,ndjson" default:"human" help:"Output format: ${enum}."`

	serverFromConfig bool
}

type configCommand struct {
	Path  struct{} `cmd:"" help:"Show the selected project configuration path."`
	Check struct{} `cmd:"" help:"Validate the selected project configuration."`
}

type loginCommand struct {
	Server     string `arg:"" name:"server" optional:"" help:"tnl server HTTPS origin; defaults to the selected server or https://control.tnl.dev."`
	ServerURL  string `name:"server" env:"TNL_SERVER" help:"tnl server HTTPS origin; defaults to the selected server or https://control.tnl.dev."`
	StateDir   string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent client state."`
	Token      bool   `name:"token" help:"Use login-token authentication even when OIDC is available."`
	LoginToken string `name:"login-token" env:"TNL_LOGIN_TOKEN" hidden:""`
}

type logoutCommand struct {
	ServerURL string `name:"server" env:"TNL_SERVER" help:"tnl server HTTPS origin; defaults to the selected server or https://control.tnl.dev."`
	StateDir  string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent client state."`
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

func run(ctx context.Context, args []string, stdout, stderr io.Writer, reporterFactories ...telemetryReporterFactory) (result error) {
	command := ""
	defer func() {
		if result != nil && command != "" {
			result = clioutput.WrapCommand(command, result)
		}
	}()
	var flags cli
	parser, err := kong.New(&flags, kong.Name("tnl"), kong.Description("public urls for localhost."))
	if err != nil {
		return err
	}
	parsed, err := parser.Parse(args)
	if err != nil {
		return err
	}
	command = clioutput.CommandTitle("tnl", parsed.Command())
	var project projectConfiguration
	switch parsed.Command() {
	case "publish <target>", "dev <command>":
		project, err = loadProjectConfiguration(ctx, flags)
		if err != nil {
			return err
		}
		if parsed.Command() == "publish <target>" {
			err = project.applyPublish(&flags.Publish)
		} else {
			err = project.applyDev(&flags.Dev)
		}
		if err != nil {
			return err
		}
	}
	var telemetry telemetryReporter
	if !flags.NoTelemetry && len(reporterFactories) != 0 && reporterFactories[0] != nil {
		root, stateErr := telemetryStateRoot(parsed)
		if stateErr == nil {
			telemetry = reporterFactories[0](root)
			command := canonicalTelemetryCommand(parsed)
			if telemetry != nil && command != "" {
				telemetry.Report(newTelemetryPayload("command", command, "", ""))
			}
		}
	}
	switch parsed.Command() {
	case "config path":
		return runConfigPath(flags, stdout)
	case "config check":
		return runConfigCheck(ctx, flags, stdout)
	case "login":
		return runLogin(ctx, flags.Login, os.Stdin, stdout, stderr)
	case "logout":
		return runLogout(ctx, flags.Logout, stdout, stderr)
	case "version":
		_, err := fmt.Fprintln(stdout, buildinfo.Line("tnl"))
		return err
	case "publish <target>":
		return runPublish(ctx, flags.Publish, stdout, stderr, telemetry)
	case "dev <command>":
		return runDev(ctx, flags.Dev, os.Stdin, stdout, stderr, telemetry)
	case "status":
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
	case "admin maintenance enable <name>":
		return runAdminMaintenanceSet(ctx, flags.Admin.Maintenance.Enable, true, stdout, stderr)
	case "admin maintenance disable <name>":
		return runAdminMaintenanceSet(ctx, flags.Admin.Maintenance.Disable, false, stdout, stderr)
	default:
		return errors.New("command is required")
	}
}

func runPublish(ctx context.Context, flags publishCommand, stdout, stderr io.Writer, reporters ...telemetryReporter) (result error) {
	telemetry := optionalTelemetryReporter(reporters)
	output, err := newPublishOutput(flags.Output, "tnl publish", stdout, stderr, browserOpener(flags.Open))
	if err != nil {
		return err
	}
	fail := func(err error) error {
		if cause := context.Cause(ctx); cause != nil {
			if errors.Is(cause, context.Canceled) {
				return errors.Join(cause, output.stopped())
			}
			_ = output.failed(cause)
			return cause
		}
		_ = output.failed(err)
		return err
	}
	target, err := localproxy.NormalizeTarget(flags.Target)
	if err != nil {
		return fail(err)
	}
	serverURL, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return fail(err)
	}
	defer state.Close()
	tunnel, err := state.BeginTunnel(ctx, clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: serverURL, Target: target,
	})
	if err != nil {
		return fail(err)
	}
	ctx = tunnel.Context()
	defer func() {
		finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result = errors.Join(result, tunnel.Finish(finishCtx, result))
	}()
	if err := output.starting(tunnel.ID(), target); err != nil {
		return err
	}
	if err := localproxy.Preflight(ctx, target); err != nil {
		return fail(err)
	}
	authenticated, err := authenticatePublisher(ctx, state, serverURL, flags.AccessToken, "tnl publish", os.Stdin, stderr)
	if err != nil {
		return fail(err)
	}
	allowedIPPrefixes, currentIP, err := resolveIPPolicy(ctx, authenticated.Control, flags.AllowIP, flags.Public)
	if err != nil {
		return fail(err)
	}
	if currentIP != "" {
		if err := output.currentIP(currentIP); err != nil {
			return err
		}
	}
	services, err := preparePublisherServices(ctx, state, serverURL, flags.Host, flags.Subdomain, authenticated)
	if err != nil {
		return fail(err)
	}
	publisherConfig := services.config(target, allowedIPPrefixes)
	publisherConfig.Logf = output.logf
	publisherConfig.Observe = withTelemetryObserver(telemetry, "publish", serverURL, "", func(event publisher.Event) error {
		switch event.Type {
		case publisher.EventRouteAssigned:
			return tunnel.SetRoute(ctx, event.RouteID, event.Hostname)
		case publisher.EventProvisioning:
			return tunnel.SetProvisioning(ctx, event.RouteVersion)
		case publisher.EventReady:
			if err := tunnel.SetReady(ctx, event.PublicURL, event.RouteVersion); err != nil {
				return err
			}
			return output.ready(event.PublicURL, event.RouteVersion)
		case publisher.EventDraining:
			return tunnel.SetDraining(context.WithoutCancel(ctx))
		}
		return nil
	})
	err = publisher.Run(ctx, publisherConfig)
	if cause := context.Cause(ctx); cause != nil {
		return fail(cause)
	}
	if err != nil && !(ctx.Err() != nil && errors.Is(err, context.Canceled)) {
		return fail(err)
	}
	return output.stopped()
}
