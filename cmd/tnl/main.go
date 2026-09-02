package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/routeclient"
	"github.com/tnldotdev/tnl/internal/serverclient"
	"github.com/tnldotdev/tnl/pkg/protocol/authorityv1"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
	"golang.org/x/term"
	"tailscale.com/tailcfg"
)

const defaultServerURL = "https://control.tnl.dev"

type cli struct {
	NoTelemetry bool           `name:"no-telemetry" env:"TNL_NO_TELEMETRY" help:"Disable pseudonymous usage telemetry."`
	Publish     publishCommand `cmd:"" help:"Publish one local HTTP service."`
	Dev         devCommand     `cmd:"" help:"Run and publish a development server."`
	Status      statusCommand  `cmd:"" help:"Show local tunnel status."`
	Host        hostCommand    `cmd:"" help:"Manage persistent public names."`
	Login       loginCommand   `cmd:"" help:"Authenticate to a tnl server."`
	Logout      logoutCommand  `cmd:"" help:"Revoke and remove the saved control session."`
	Admin       adminCommand   `cmd:"" help:"Administer a self-hosted tnl server."`
	Version     struct{}       `cmd:"" help:"Print release version information."`
}

type openOptions struct {
	Open bool `name:"open" help:"Open the public URL in the default browser once ready."`
}

type publishCommand struct {
	openOptions    `embed:""`
	Target         string   `arg:"" name:"target" required:"" help:"Local port, localhost port, or literal-loopback HTTP origin."`
	ServerURL      string   `name:"server" env:"TNL_SERVER" help:"tnl server HTTPS origin; defaults to the selected server or https://control.tnl.dev."`
	AccessToken    string   `name:"access-token" env:"TNL_ACCESS_TOKEN" help:"Server access token; defaults to the saved login."`
	Name           string   `name:"name" env:"TNL_NAME" help:"Requested single-label public name; omit for a random name."`
	AllowIP        []string `name:"allow-ip" help:"Allow a visitor IP address or prefix; repeat for each value."`
	AllowCurrentIP bool     `name:"allow-current-ip" help:"Allow the public IP reported by the tnl server."`
	Output         string   `name:"output" enum:"human,ndjson" default:"human" help:"Output format: ${enum}."`
	StateDir       string   `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent route state."`
}

type hostCommand struct {
	Add    hostAddCommand    `cmd:"" help:"Add a persistent managed base or custom domain."`
	List   hostListCommand   `cmd:"" help:"List hostnames."`
	Remove hostRemoveCommand `cmd:"" help:"Remove a persistent managed base or custom domain."`
}

type hostAddCommand struct {
	Name        string `arg:"" name:"name" optional:"" help:"Managed base name or absolute custom domain; omit to generate a base."`
	ServerURL   string `name:"server" env:"TNL_SERVER" help:"tnl server HTTPS origin; defaults to the selected server or https://control.tnl.dev."`
	AccessToken string `name:"access-token" env:"TNL_ACCESS_TOKEN" help:"Server access token; defaults to the saved login."`
	StateDir    string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent client state."`
}

type hostListCommand struct {
	ServerURL   string `name:"server" env:"TNL_SERVER" help:"tnl server HTTPS origin; defaults to the selected server or https://control.tnl.dev."`
	AccessToken string `name:"access-token" env:"TNL_ACCESS_TOKEN" help:"Server access token; defaults to the saved login."`
	StateDir    string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent client state."`
}

type hostRemoveCommand struct {
	Hostname    string `arg:"" name:"hostname" required:"" help:"Exact hostname to remove."`
	ServerURL   string `name:"server" env:"TNL_SERVER" help:"tnl server HTTPS origin; defaults to the selected server or https://control.tnl.dev."`
	AccessToken string `name:"access-token" env:"TNL_ACCESS_TOKEN" help:"Server access token; defaults to the saved login."`
	StateDir    string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent route state."`
}

type loginCommand struct {
	Server    string `arg:"" name:"server" optional:"" help:"tnl server HTTPS origin; defaults to the selected server or https://control.tnl.dev."`
	ServerURL string `name:"server" env:"TNL_SERVER" help:"tnl server HTTPS origin; defaults to the selected server or https://control.tnl.dev."`
	StateDir  string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent client state."`
	Token     bool   `name:"token" help:"Use the local login token even when OIDC is available."`
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
		fmt.Fprintf(os.Stderr, "tnl: %v\n", err)
		os.Exit(1)
	}
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
	case "host add", "host add [<name>]", "host add <name>":
		return runHostAdd(ctx, flags.Host.Add, stdout, stderr)
	case "host list":
		return runHostList(ctx, flags.Host.List, stdout, stderr)
	case "host remove <hostname>":
		return runHostRemove(ctx, flags.Host.Remove, stdout, stderr)
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
	case "admin switches list":
		return runAdminSwitchesList(ctx, flags.Admin.Switches.List, stdout, stderr)
	case "admin switches enable <name>":
		return runAdminSwitchSet(ctx, flags.Admin.Switches.Enable, true, stdout, stderr)
	case "admin switches disable <name>":
		return runAdminSwitchSet(ctx, flags.Admin.Switches.Disable, false, stdout, stderr)
	default:
		return errors.New("command is required")
	}
}

func runLogin(ctx context.Context, flags loginCommand, input io.Reader, output, errorOutput io.Writer) error {
	serverValue := flags.Server
	if serverValue == "" {
		serverValue = flags.ServerURL
	}
	serverURL, state, err := resolveServer(ctx, flags.StateDir, serverValue)
	if err != nil {
		return err
	}
	defer state.Close()
	_, err = clientauth.Authenticate(ctx, clientauth.Config{
		CoreEndpoint: serverURL, State: state, Diagnostics: errorOutput,
		LoginToken: loginTokenPrompt(input, errorOutput), ForceLogin: true, ForceLoginToken: flags.Token,
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(errorOutput, "Authenticated")
	return err
}

func readLoginToken(input io.Reader, output io.Writer) (credentials.LoginToken, error) {
	file, ok := input.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return "", errors.New("login-token authentication requires an interactive terminal")
	}
	if _, err := fmt.Fprint(output, "Login token: "); err != nil {
		return "", err
	}
	data, err := term.ReadPassword(int(file.Fd()))
	_, _ = fmt.Fprintln(output)
	if err != nil {
		return "", fmt.Errorf("read login token: %w", err)
	}
	return parseLoginInput(data)
}

func loginTokenPrompt(input io.Reader, output io.Writer) func() (credentials.LoginToken, error) {
	file, ok := input.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return nil
	}
	return func() (credentials.LoginToken, error) { return readLoginToken(input, output) }
}

func parseLoginInput(data []byte) (credentials.LoginToken, error) {
	token := credentials.LoginToken(strings.TrimSpace(string(data)))
	if _, err := credentials.ParseLoginToken(token); err != nil {
		return "", errors.New("invalid login token")
	}
	return token, nil
}

func runLogout(ctx context.Context, flags logoutCommand, output io.Writer, diagnostics ...io.Writer) error {
	serverURL, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	diagnostic := io.Discard
	if len(diagnostics) != 0 && diagnostics[0] != nil {
		diagnostic = diagnostics[0]
	}
	if err := clientauth.Logout(ctx, clientauth.Config{
		CoreEndpoint: serverURL, State: state, Diagnostics: diagnostic,
	}); err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, "Logged out")
	return err
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
	authenticated, err := clientauth.Authenticate(ctx, clientauth.Config{
		CoreEndpoint: serverURL, State: state, AccessToken: flags.AccessToken,
		Diagnostics: stderr, LoginToken: loginTokenPrompt(os.Stdin, stderr),
	})
	if err != nil {
		return fail(err)
	}
	if flags.AllowCurrentIP {
		current, err := authenticated.Core.ClientIP(ctx)
		if err != nil {
			return fail(fmt.Errorf("read current IP: %w", err))
		}
		address, err := netip.ParseAddr(current.Ip)
		if err != nil || address.Zone() != "" {
			return fail(errors.New("server returned an invalid current IP"))
		}
		effectiveIP := address.Unmap().String()
		if err := output.currentIP(effectiveIP); err != nil {
			return err
		}
		allowedIPPrefixes, err = authorization.CanonicalizeIPPrefixes(append(allowedIPPrefixes, effectiveIP))
		if err != nil {
			return fail(fmt.Errorf("combine allowed IP prefixes: %w", err))
		}
	}
	capabilities := authenticated.CoreCapabilities
	publisherState, err := state.Server(ctx, serverURL)
	if err != nil {
		return fail(err)
	}
	if capabilities.Transport.Type != serverv1.Tailcat || capabilities.Transport.Version != serverv1.TransportCapabilitiesVersionN1 {
		return fail(errors.New("server does not support tailcat transport version 1"))
	}
	if capabilities.HostnameSuffix == "" || capabilities.MaximumSubdomainDepth != 8 {
		return fail(errors.New("server does not support the required naming contract"))
	}
	profile := capabilities.Transport.RelayRegion
	if capabilities.Acme == nil || capabilities.Acme.AcmeProfile == "" {
		return fail(errors.New("server does not support automatic certificates"))
	}
	names, namingCapabilities, err := namingAPI(authenticated)
	if err != nil {
		return fail(err)
	}
	hostname, err := addPublishHostname(ctx, names, flags.Name, namingCapabilities)
	if err != nil {
		return fail(err)
	}
	routes, err := routeAPI(authenticated)
	if err != nil {
		return fail(err)
	}
	logger := log.New(stderr, "tnl: ", 0)
	err = publisher.Run(ctx, publisher.Config{
		Server: routes, Hostname: hostname, Target: target,
		AllowedIPPrefixes: allowedIPPrefixes,
		State:             publisherState, ACMEProfile: capabilities.Acme.AcmeProfile,
		RelayRegion: profile, Logf: logger.Printf,
		LoadRegions: func(ctx context.Context) (map[string]*tailcfg.DERPRegion, error) {
			relayMap, err := authenticated.Core.RelayMap(ctx)
			if err != nil {
				return nil, fmt.Errorf("read server relay map: %w", err)
			}
			return config.DecodeRelayRegions(relayMap)
		},
		Observe: withTelemetryObserver(telemetry, "publish", serverURL, "", func(event publisher.Event) error {
			switch event.Type {
			case publisher.EventRoute:
				return tunnel.SetRoute(ctx, event.RouteID, event.Hostname)
			case publisher.EventProvisioning:
				return tunnel.SetProvisioning(ctx, event.Version)
			case publisher.EventReady:
				if err := tunnel.SetReady(ctx, event.PublicURL, event.Version); err != nil {
					return err
				}
				return output.ready(event.PublicURL, event.Version)
			case publisher.EventDraining:
				return tunnel.SetDraining(context.WithoutCancel(ctx))
			}
			return nil
		}),
	})
	if cause := context.Cause(ctx); cause != nil {
		return fail(cause)
	}
	if err != nil && !(ctx.Err() != nil && errors.Is(err, context.Canceled)) {
		return fail(err)
	}
	return output.stopped()
}

func runHostAdd(ctx context.Context, flags hostAddCommand, output io.Writer, diagnostics ...io.Writer) error {
	client, capabilities, state, err := namingClient(ctx, flags.StateDir, flags.ServerURL, flags.AccessToken, diagnosticOutput(diagnostics))
	if err != nil {
		return err
	}
	defer state.Close()
	kind, name, err := classifyAddHostname(flags.Name, capabilities.HostnameSuffix)
	if err != nil {
		return err
	}
	requestKey, err := randomRequestKey()
	if err != nil {
		return err
	}
	if kind == serverv1.AddHostnameRequestKindManaged {
		hostname, err := client.AddHostname(ctx, kind, name, requestKey)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(output, hostname.Hostname)
		return err
	}
	if !capabilities.CustomDomainSupport {
		return errors.New("server does not support custom domains")
	}
	verification, err := client.CreateDomainVerification(ctx, name, requestKey)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "Add these DNS records:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output); err != nil {
		return err
	}
	for _, record := range verification.Records {
		if _, err := fmt.Fprintf(output, "%-32s %-5s %s\n", record.Name, record.Type, record.Value); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(output); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "Waiting for DNS..."); err != nil {
		return err
	}
	for {
		hostname, err := client.CompleteDomainVerification(ctx, verification.Id)
		if err == nil {
			_, err = fmt.Fprintf(output, "Added %s\n", hostname.Hostname)
			return err
		}
		if !errors.Is(err, serverclient.ErrDNSProofPending) && !errors.Is(err, authorityclient.ErrDNSProofPending) {
			return err
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func runHostList(ctx context.Context, flags hostListCommand, output io.Writer, diagnostics ...io.Writer) error {
	client, _, state, err := namingClient(ctx, flags.StateDir, flags.ServerURL, flags.AccessToken, diagnosticOutput(diagnostics))
	if err != nil {
		return err
	}
	defer state.Close()
	if _, err := fmt.Fprintln(output, "NAME\tTYPE\tSTATE"); err != nil {
		return err
	}
	cursor := ""
	for {
		hostnames, next, err := client.ListHostnamesPage(ctx, cursor)
		if err != nil {
			return err
		}
		for _, hostname := range hostnames {
			typeName := "managed"
			switch hostname.Kind {
			case serverv1.HostnameKindCustomDomain:
				typeName = "custom"
			case serverv1.HostnameKindTemporary:
				typeName = "temporary"
			}
			if _, err := fmt.Fprintf(output, "%s\t%s\t%s\n", hostname.Hostname, typeName, hostname.Status); err != nil {
				return err
			}
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}

func runHostRemove(ctx context.Context, flags hostRemoveCommand, output io.Writer, diagnostics ...io.Writer) error {
	client, capabilities, state, err := namingClient(ctx, flags.StateDir, flags.ServerURL, flags.AccessToken, diagnosticOutput(diagnostics))
	if err != nil {
		return err
	}
	defer state.Close()
	hostnames, err := client.ListHostnames(ctx)
	if err != nil {
		return err
	}
	hostname, hostnameID, err := resolveReleaseName(flags.Hostname, capabilities.HostnameSuffix, hostnames)
	if err != nil {
		return err
	}
	if err := client.RemoveHostname(ctx, hostnameID); err != nil &&
		!errors.Is(err, serverclient.ErrNotFound) && !errors.Is(err, authorityclient.ErrNotFound) {
		return err
	}
	_, err = fmt.Fprintln(output, hostname)
	return err
}

func addPublishHostname(
	ctx context.Context,
	client hostnameAPI,
	name string,
	capabilities serverv1.Capabilities,
) (string, error) {
	if name == "" {
		requestKey, err := randomRequestKey()
		if err != nil {
			return "", err
		}
		hostname, err := client.AddHostname(ctx, serverv1.AddHostnameRequestKindTemporary, "", requestKey)
		if err != nil {
			return "", err
		}
		if hostname.Kind != serverv1.HostnameKindTemporary || hostname.Status != serverv1.HostnameStatusPendingRoute {
			return "", errors.New("server returned an invalid temporary name")
		}
		return validateAddManagedHostname(hostname, capabilities.HostnameSuffix)
	}
	hostnames, err := client.ListHostnames(ctx)
	if err != nil {
		return "", err
	}
	resolvedHostname, base, managed, implicit, err := resolvePublishName(name, capabilities.HostnameSuffix, capabilities.MaximumSubdomainDepth, hostnames)
	if err != nil {
		return "", err
	}
	if implicit {
		requestKey, err := randomRequestKey()
		if err != nil {
			return "", err
		}
		added, err := client.AddHostname(ctx, serverv1.AddHostnameRequestKindManaged, base, requestKey)
		if err != nil {
			return "", err
		}
		if added.Hostname != resolvedHostname || added.Status != serverv1.HostnameStatusActive {
			return "", errors.New("server returned an invalid managed base")
		}
	} else if !managed && !capabilities.CustomDomainSupport {
		return "", errors.New("server does not support custom domains")
	}
	return resolvedHostname, nil
}

func validateAddManagedHostname(value serverv1.Hostname, suffix string) (string, error) {
	canonicalSuffix, suffixErr := naming.CanonicalizeHostname(suffix)
	hostname, err := naming.CanonicalizeHostname(value.Hostname)
	label, found := strings.CutSuffix(hostname, "."+suffix)
	if suffixErr != nil || canonicalSuffix != suffix || err != nil || hostname != value.Hostname ||
		!found || label == "" || strings.Contains(label, ".") || value.Id == "" {
		return "", errors.New("server returned an invalid hostname")
	}
	return hostname, nil
}

func namingClient(
	ctx context.Context,
	stateDir, serverValue, accessToken string,
	diagnostics io.Writer,
) (hostnameAPI, serverv1.Capabilities, *clientstate.Database, error) {
	serverURL, state, err := resolveServer(ctx, stateDir, serverValue)
	if err != nil {
		return nil, serverv1.Capabilities{}, nil, err
	}
	authenticated, err := clientauth.Authenticate(ctx, clientauth.Config{
		CoreEndpoint: serverURL, State: state, AccessToken: accessToken,
		Diagnostics: diagnostics, LoginToken: loginTokenPrompt(os.Stdin, diagnostics),
	})
	if err != nil {
		state.Close()
		return nil, serverv1.Capabilities{}, nil, err
	}
	client, capabilities, err := namingAPI(authenticated)
	if err != nil {
		state.Close()
		return nil, serverv1.Capabilities{}, nil, err
	}
	if capabilities.HostnameSuffix == "" || capabilities.MaximumSubdomainDepth != 8 {
		state.Close()
		return nil, serverv1.Capabilities{}, nil, errors.New("server does not support the required naming contract")
	}
	return client, capabilities, state, nil
}

func classifyAddHostname(input, hostnameSuffix string) (serverv1.AddHostnameRequestKind, string, error) {
	if input == "" {
		return serverv1.AddHostnameRequestKindManaged, "", nil
	}
	absolute := strings.HasSuffix(input, ".")
	canonical, err := naming.CanonicalizeHostname(input)
	if err != nil {
		return "", "", err
	}
	if !absolute && !strings.Contains(canonical, ".") {
		return serverv1.AddHostnameRequestKindManaged, canonical, nil
	}
	if naming.IsWithin(canonical, hostnameSuffix) {
		depth, _ := naming.ChildDepth(canonical, hostnameSuffix)
		if depth != 1 {
			return "", "", errors.New("managed base must be exactly one label beneath the hostname suffix")
		}
		return serverv1.AddHostnameRequestKindManaged, canonical, nil
	}
	domain, _, err := naming.CustomDomain(canonical, hostnameSuffix)
	if err != nil {
		return "", "", err
	}
	return "", domain, nil
}

func resolvePublishName(
	input, hostnameSuffix string,
	maximumDepth int,
	hostnames []serverv1.Hostname,
) (hostname, base string, managed, implicit bool, err error) {
	absolute := strings.HasSuffix(input, ".")
	canonical, err := naming.CanonicalizeHostname(input)
	if err != nil {
		return "", "", false, false, err
	}
	active := func(kind serverv1.HostnameKind, candidate string) bool {
		for _, hostname := range hostnames {
			if hostname.Kind == kind && hostname.Status == serverv1.HostnameStatusActive && hostname.Hostname == candidate {
				return true
			}
		}
		return false
	}
	if !absolute && !naming.IsWithin(canonical, hostnameSuffix) {
		for _, hostname := range hostnames {
			if hostname.Kind != serverv1.HostnameKindCustomDomain || hostname.Status != serverv1.HostnameStatusActive {
				continue
			}
			if depth, ok := naming.ChildDepth(canonical, hostname.Hostname); ok {
				if depth > maximumDepth {
					return "", "", false, false, errors.New("custom-domain child exceeds maximum depth")
				}
				return canonical, hostname.Hostname, false, false, nil
			}
		}
	}
	if absolute && !naming.IsWithin(canonical, hostnameSuffix) {
		for _, hostname := range hostnames {
			if hostname.Kind == serverv1.HostnameKindCustomDomain && hostname.Status == serverv1.HostnameStatusActive {
				if depth, ok := naming.ChildDepth(canonical, hostname.Hostname); ok && depth <= maximumDepth {
					return canonical, hostname.Hostname, false, false, nil
				}
			}
		}
		return "", "", false, false, errors.New("absolute name is not within an owned custom domain")
	}
	if !naming.IsWithin(canonical, hostnameSuffix) {
		canonical += "." + hostnameSuffix
		canonical, err = naming.CanonicalizeHostname(canonical)
		if err != nil {
			return "", "", false, false, err
		}
	}
	if canonical == hostnameSuffix {
		return "", "", false, false, errors.New("hostname suffix cannot be published")
	}
	relative, _ := strings.CutSuffix(canonical, "."+hostnameSuffix)
	labels := strings.Split(relative, ".")
	if len(labels) == 0 || len(labels)-1 > maximumDepth {
		return "", "", false, false, errors.New("managed child exceeds maximum depth")
	}
	base = labels[len(labels)-1] + "." + hostnameSuffix
	if len(labels) == 1 && !active(serverv1.HostnameKindManaged, base) {
		return canonical, labels[0], true, true, nil
	}
	if !active(serverv1.HostnameKindManaged, base) {
		return "", "", false, false, fmt.Errorf("base %s is not owned", base)
	}
	return canonical, base, true, false, nil
}

func resolveReleaseName(
	input, hostnameSuffix string,
	hostnames []serverv1.Hostname,
) (string, string, error) {
	canonical, err := naming.CanonicalizeHostname(input)
	if err != nil {
		return "", "", err
	}
	if !strings.HasSuffix(input, ".") && !strings.Contains(canonical, ".") {
		canonical += "." + hostnameSuffix
	}
	for _, hostname := range hostnames {
		if hostname.Hostname == canonical {
			if hostname.Kind == serverv1.HostnameKindTemporary {
				return "", "", errors.New("temporary hostnames are retired with their route and cannot be removed")
			}
			return canonical, hostname.Id, nil
		}
	}
	return "", "", errors.New("hostname not found")
}

type hostnameAPI interface {
	AddHostname(context.Context, serverv1.AddHostnameRequestKind, string, string) (serverv1.Hostname, error)
	ListHostnames(context.Context) ([]serverv1.Hostname, error)
	ListHostnamesPage(context.Context, string) ([]serverv1.Hostname, string, error)
	RemoveHostname(context.Context, string) error
	CreateDomainVerification(context.Context, string, string) (serverv1.DomainVerification, error)
	CompleteDomainVerification(context.Context, string) (serverv1.Hostname, error)
}

type authorityHostnameAPI struct{ client *authorityclient.Client }

func (a authorityHostnameAPI) AddHostname(
	ctx context.Context,
	kind serverv1.AddHostnameRequestKind,
	name, requestKey string,
) (serverv1.Hostname, error) {
	hostname, err := a.client.AddHostname(ctx, authorityv1.AddHostnameRequestKind(kind), name, requestKey)
	return authorityHostname(hostname), err
}

func (a authorityHostnameAPI) ListHostnames(ctx context.Context) ([]serverv1.Hostname, error) {
	hostnames, err := a.client.ListHostnames(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]serverv1.Hostname, len(hostnames))
	for index, hostname := range hostnames {
		result[index] = authorityHostname(hostname)
	}
	return result, nil
}

func (a authorityHostnameAPI) ListHostnamesPage(
	ctx context.Context,
	cursor string,
) ([]serverv1.Hostname, string, error) {
	hostnames, next, err := a.client.ListHostnamesPage(ctx, cursor)
	if err != nil {
		return nil, "", err
	}
	result := make([]serverv1.Hostname, len(hostnames))
	for index, hostname := range hostnames {
		result[index] = authorityHostname(hostname)
	}
	return result, next, nil
}

func (a authorityHostnameAPI) RemoveHostname(ctx context.Context, hostnameID string) error {
	return a.client.RemoveHostname(ctx, hostnameID)
}

func (a authorityHostnameAPI) CreateDomainVerification(
	ctx context.Context,
	domain, requestKey string,
) (serverv1.DomainVerification, error) {
	verification, err := a.client.CreateDomainVerification(ctx, domain, requestKey)
	return authorityDomainVerification(verification), err
}

func (a authorityHostnameAPI) CompleteDomainVerification(
	ctx context.Context,
	verificationID string,
) (serverv1.Hostname, error) {
	hostname, err := a.client.CompleteDomainVerification(ctx, verificationID)
	return authorityHostname(hostname), err
}

func namingAPI(authenticated *clientauth.Client) (hostnameAPI, serverv1.Capabilities, error) {
	if authenticated == nil || authenticated.Core == nil {
		return nil, serverv1.Capabilities{}, errors.New("authentication did not return a Core client")
	}
	capabilities := authenticated.CoreCapabilities
	if authenticated.Kind == clientstate.ControlSessionKindCore {
		return authenticated.Core, capabilities, nil
	}
	if authenticated.Authority == nil || authenticated.AuthorityCapabilities == nil {
		return nil, serverv1.Capabilities{}, errors.New("authentication did not return an authorization authority client")
	}
	authority := authenticated.AuthorityCapabilities
	capabilities.HostnameSuffix = authority.HostnameSuffix
	capabilities.MaximumSubdomainDepth = int(authority.HostnamePolicy.MaximumSubdomainDepth)
	capabilities.CustomDomainSupport = bool(authority.HostnamePolicy.CustomDomainSupport)
	capabilities.PersistentBaseSupport = bool(authority.HostnamePolicy.PersistentBaseSupport)
	capabilities.TemporaryNameSupport = bool(authority.HostnamePolicy.TemporaryNameSupport)
	return authorityHostnameAPI{client: authenticated.Authority}, capabilities, nil
}

func routeAPI(authenticated *clientauth.Client) (*routeclient.Client, error) {
	if authenticated.Kind == clientstate.ControlSessionKindCore {
		return routeclient.NewLocal(authenticated.Core)
	}
	if authenticated.Authority == nil || authenticated.AuthorityCapabilities == nil {
		return nil, errors.New("authentication did not return an authorization authority client")
	}
	return routeclient.NewSigned(
		authenticated.CoreEndpoint, authenticated.Core, authenticated.Authority, *authenticated.AuthorityCapabilities,
	)
}

func authorityHostname(hostname authorityv1.Hostname) serverv1.Hostname {
	return serverv1.Hostname{
		Id: hostname.Id, Hostname: hostname.Hostname,
		Kind: serverv1.HostnameKind(hostname.Kind), Status: serverv1.HostnameStatus(hostname.Status),
		Source: serverv1.HostnameSource(hostname.Source), CreatedAt: hostname.CreatedAt,
		ActivatedAt: hostname.ActivatedAt, DeactivatedAt: hostname.DeactivatedAt,
	}
}

func authorityDomainVerification(verification authorityv1.DomainVerification) serverv1.DomainVerification {
	records := make([]serverv1.DNSRecord, len(verification.Records))
	for index, record := range verification.Records {
		records[index] = serverv1.DNSRecord{Name: record.Name, Type: serverv1.DNSRecordType(record.Type), Value: record.Value}
	}
	return serverv1.DomainVerification{
		Id: verification.Id, Domain: verification.Domain, VerificationTarget: verification.VerificationTarget,
		Apex: verification.Apex, Status: serverv1.DomainVerificationStatus(verification.Status), Records: records,
		HostnameId: verification.HostnameId, CreatedAt: verification.CreatedAt,
		VerifiedAt: verification.VerifiedAt, InvalidatedAt: verification.InvalidatedAt,
	}
}

func diagnosticOutput(outputs []io.Writer) io.Writer {
	if len(outputs) != 0 && outputs[0] != nil {
		return outputs[0]
	}
	return io.Discard
}

func resolveServer(ctx context.Context, root, value string) (string, *clientstate.Database, error) {
	root, err := clientStateRoot(root)
	if err != nil {
		return "", nil, err
	}
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return "", nil, err
	}
	if value != "" {
		server, err := clientstate.CanonicalServer(value)
		if err != nil {
			state.Close()
			return "", nil, err
		}
		return server, state, nil
	}
	server, found, err := state.SavedServer(ctx)
	if err != nil {
		state.Close()
		return "", nil, err
	}
	if !found {
		return defaultServerURL, state, nil
	}
	return server, state, nil
}

func clientStateRoot(root string) (string, error) {
	if root != "" {
		return root, nil
	}
	return clientstate.DefaultDir()
}

func randomRequestKey() (string, error) {
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", err
	}
	return "random_" + hex.EncodeToString(material[:]), nil
}
