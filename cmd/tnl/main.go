package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/publisher"
)

type cli struct {
	NoTelemetry bool           `name:"no-telemetry" env:"TNL_NO_TELEMETRY" help:"Disable pseudonymous usage telemetry."`
	Publish     publishCommand `cmd:"" help:"Publish one local HTTP service."`
	Dev         devCommand     `cmd:"" help:"Run and publish a development server."`
	Status      statusCommand  `cmd:"" help:"Show local tunnel status."`
	Host        hostCommand    `cmd:"" help:"Manage persistent public hostnames."`
	Login       loginCommand   `cmd:"" help:"Authenticate to a tnl server."`
	Logout      logoutCommand  `cmd:"" help:"Revoke and remove the saved control session."`
	Admin       adminCommand   `cmd:"" help:"Administer a self-hosted tnl server."`
	Version     struct{}       `cmd:"" help:"Print release version information."`
}

type openOptions struct {
	Open bool `name:"open" help:"Open the public URL in the default browser once ready."`
}

type remoteFlags struct {
	ServerURL   string `name:"server" env:"TNL_SERVER" help:"tnl server HTTPS origin; defaults to the selected server or https://control.tnl.dev."`
	AccessToken string `name:"access-token" env:"TNL_ACCESS_TOKEN" help:"Server access token; defaults to the saved login."`
	StateDir    string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent client state."`
}

type publishCommand struct {
	openOptions    `embed:""`
	remoteFlags    `embed:""`
	Target         string   `arg:"" name:"target" required:"" help:"Local port or loopback-only HTTP URL."`
	Host           string   `name:"host" env:"TNL_HOST" help:"Requested public hostname; omit to generate a temporary hostname for this invocation."`
	AllowIP        []string `name:"allow-ip" help:"Allow a visitor IP address or prefix; repeat for each value."`
	AllowCurrentIP bool     `name:"allow-current-ip" help:"Allow the public IP reported by the tnl server."`
	Output         string   `name:"output" enum:"human,ndjson" default:"human" help:"Output format: ${enum}."`
}

type hostCommand struct {
	Claim   hostClaimCommand   `cmd:"" help:"Claim a persistent managed hostname or custom domain."`
	List    hostListCommand    `cmd:"" help:"List claimed hostnames."`
	Release hostReleaseCommand `cmd:"" help:"Release a persistent managed hostname or custom domain."`
}

type hostClaimCommand struct {
	remoteFlags `embed:""`
	Hostname    string `arg:"" name:"hostname" optional:"" help:"Managed hostname or absolute custom domain; omit to generate a managed hostname."`
}

type hostListCommand struct {
	remoteFlags `embed:""`
}

type hostReleaseCommand struct {
	remoteFlags `embed:""`
	Hostname    string `arg:"" name:"hostname" required:"" help:"Exact hostname to release."`
}

type loginCommand struct {
	Server    string `arg:"" name:"server" optional:"" help:"tnl server HTTPS origin; defaults to the selected server or https://control.tnl.dev."`
	ServerURL string `name:"server" env:"TNL_SERVER" help:"tnl server HTTPS origin; defaults to the selected server or https://control.tnl.dev."`
	StateDir  string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent client state."`
	Token     bool   `name:"token" help:"Use login-token authentication even when OIDC is available."`
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
	if text, ok := diagnostic.TextForError(err); ok {
		_, _ = io.WriteString(output, text)
		return
	}
	_, _ = fmt.Fprintf(output, "tnl: %v\n", err)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, reporterFactories ...telemetryReporterFactory) error {
	var flags cli
	parser, err := kong.New(&flags, kong.Name("tnl"), kong.Description("public urls for localhost."))
	if err != nil {
		return err
	}
	parsed, err := parser.Parse(args)
	if err != nil {
		return err
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
	case "host claim", "host claim [<hostname>]", "host claim <hostname>":
		return runHostClaim(ctx, flags.Host.Claim, stdout, stderr)
	case "host list":
		return runHostList(ctx, flags.Host.List, stdout, stderr)
	case "host release <hostname>":
		return runHostRelease(ctx, flags.Host.Release, stdout, stderr)
	case "admin server status":
		return runAdminServerStatus(ctx, flags.Admin.Server.Status, stdout, stderr)
	case "admin server login-token":
		return runAdminLoginToken(ctx, flags.Admin.Server.LoginToken, stdout)
	case "admin server token worker":
		return runAdminTokenWorker(stdout)
	case "admin server token service":
		return runAdminTokenService(stdout)
	case "admin server relay refresh":
		return runAdminRelayRefresh(ctx, flags.Admin.Server.Relay.Refresh, stdout)
	case "admin routes list":
		return runAdminRoutesList(ctx, flags.Admin.Routes.List, stdout, stderr)
	case "admin routes show <route-id>":
		return runAdminRouteShow(ctx, flags.Admin.Routes.Show, stdout, stderr)
	case "admin routes suspend <route-id>":
		return runAdminRouteSuspend(ctx, flags.Admin.Routes.Suspend, stdout, stderr)
	case "admin routes resume <route-id>":
		return runAdminRouteResume(ctx, flags.Admin.Routes.Resume, stdout, stderr)
	case "admin hostnames list":
		return runAdminHostnamesList(ctx, flags.Admin.Hostnames.List, stdout, stderr)
	case "admin hostnames show <hostname-id>":
		return runAdminHostnameShow(ctx, flags.Admin.Hostnames.Show, stdout, stderr)
	case "admin hostnames remove <hostname-id>":
		return runAdminHostnameRemove(ctx, flags.Admin.Hostnames.Remove, stdout, stderr)
	case "admin hostnames quarantine <hostname-id>":
		return runAdminHostnameQuarantine(ctx, flags.Admin.Hostnames.Quarantine, stdout, stderr)
	case "admin credentials list":
		return runAdminCredentialsList(ctx, flags.Admin.Credentials.List, stdout, stderr)
	case "admin credentials revoke <credential-id>":
		return runAdminCredentialRevoke(ctx, flags.Admin.Credentials.Revoke, stdout, stderr)
	case "admin control-sessions list":
		return runAdminControlSessionsList(ctx, flags.Admin.ControlSessions.List, stdout, stderr)
	case "admin control-sessions revoke <control-session-id>":
		return runAdminControlSessionRevoke(ctx, flags.Admin.ControlSessions.Revoke, stdout, stderr)
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
	output, err := newPublishOutput(flags.Output, stdout, stderr, browserOpener(flags.Open))
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
	allowedIPPrefixes, err := authorization.CanonicalizeIPPrefixes(flags.AllowIP)
	if err != nil {
		return fail(fmt.Errorf("invalid --allow-ip: %w", err))
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
	authenticated, err := authenticatePublisher(ctx, state, serverURL, flags.AccessToken, os.Stdin, stderr)
	if err != nil {
		return fail(err)
	}
	allowedIPPrefixes, currentIP, err := allowCurrentIP(ctx, authenticated, allowedIPPrefixes, flags.AllowCurrentIP)
	if err != nil {
		return fail(err)
	}
	if currentIP != "" {
		if err := output.currentIP(currentIP); err != nil {
			return err
		}
	}
	services, err := preparePublisherServices(ctx, state, serverURL, flags.Host, authenticated)
	if err != nil {
		return fail(err)
	}
	logger := log.New(stderr, "tnl: ", 0)
	publisherConfig := services.config(target, allowedIPPrefixes)
	publisherConfig.Logf = logger.Printf
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
