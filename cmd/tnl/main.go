package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/oidclogin"
	"github.com/tnldotdev/tnl/internal/publication"
	"github.com/tnldotdev/tnl/internal/serverclient"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
	"golang.org/x/term"
	"tailscale.com/tailcfg"
)

const defaultServerURL = "https://control.tnl.dev"

type cli struct {
	Public  publicCommand `cmd:"" help:"Publish one local HTTP service."`
	Dev     devCommand    `cmd:"" help:"Run and publish a development server."`
	Host    hostCommand   `cmd:"" help:"Manage persistent public names."`
	Login   loginCommand  `cmd:"" help:"Authenticate to a tnl server."`
	Logout  logoutCommand `cmd:"" help:"Revoke and remove the saved access token."`
	Version struct{}      `cmd:"" help:"Print release version information."`
}

type publicCommand struct {
	Target      string `arg:"" name:"target" required:"" help:"Local port, localhost port, or literal-loopback HTTP origin."`
	ServerURL   string `name:"server" env:"TNL_SERVER" help:"tnl server HTTPS origin; defaults to the selected server or https://control.tnl.dev."`
	AccessToken string `name:"access-token" env:"TNL_ACCESS_TOKEN" help:"Server access token; defaults to the saved login."`
	Name        string `name:"name" env:"TNL_NAME" help:"Requested single-label public name; omit for a random name."`
	Output      string `name:"output" enum:"human,ndjson" default:"human" help:"Output format: ${enum}."`
	StateDir    string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent route state."`
}

type hostCommand struct {
	Claim   hostClaimCommand   `cmd:"" help:"Claim a persistent managed base or custom domain."`
	List    hostListCommand    `cmd:"" help:"List active hostname claims."`
	Release hostReleaseCommand `cmd:"" help:"Release a persistent managed base or custom domain."`
}

type hostClaimCommand struct {
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

type hostReleaseCommand struct {
	Hostname    string `arg:"" name:"hostname" required:"" help:"Exact hostname to release."`
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
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil && !errors.Is(err, context.Canceled) {
		var commandErr *childExitError
		if errors.As(err, &commandErr) {
			os.Exit(commandErr.code)
		}
		fmt.Fprintf(os.Stderr, "tnl: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	var flags cli
	parser, err := kong.New(&flags, kong.Name("tnl"), kong.Description("public urls for localhost."))
	if err != nil {
		return err
	}
	parsed, err := parser.Parse(args)
	if err != nil {
		return err
	}
	switch parsed.Command() {
	case "login":
		return runLogin(ctx, flags.Login, os.Stdin, stdout, stderr)
	case "logout":
		return runLogout(ctx, flags.Logout, stdout)
	case "version":
		_, err := fmt.Fprintln(stdout, buildinfo.Line("tnl"))
		return err
	case "public <target>":
		return runPublic(ctx, flags.Public, stdout, stderr)
	case "dev <command>":
		return runDev(ctx, flags.Dev, os.Stdin, stdout, stderr)
	case "host claim", "host claim [<name>]", "host claim <name>":
		return runHostClaim(ctx, flags.Host.Claim, stdout)
	case "host list":
		return runHostList(ctx, flags.Host.List, stdout)
	case "host release <hostname>":
		return runHostRelease(ctx, flags.Host.Release, stdout)
	default:
		return errors.New("command is required")
	}
}

func runLogin(ctx context.Context, flags loginCommand, input io.Reader, output, errorOutput io.Writer) error {
	serverValue := flags.Server
	if serverValue == "" {
		serverValue = flags.ServerURL
	}
	serverURL, stateRoot, err := resolveServer(flags.StateDir, serverValue)
	if err != nil {
		return err
	}
	server, err := serverclient.New(serverURL, nil, "")
	if err != nil {
		return err
	}
	capabilities, err := server.Capabilities(ctx)
	if err != nil {
		return fmt.Errorf("read server capabilities: %w", err)
	}
	oidcCapabilities := capabilities.Oidc
	useOIDC := oidcCapabilities != nil && !flags.Token
	var idToken string
	var login credentials.LoginToken
	if useOIDC {
		idToken, err = oidclogin.Login(ctx, oidclogin.Config{
			Issuer: oidcCapabilities.Issuer, ClientID: oidcCapabilities.ClientId,
		}, output)
		if err != nil {
			return err
		}
	} else {
		login, err = readLoginToken(input, errorOutput)
		if err != nil {
			return err
		}
	}
	state, err := clientstate.New(stateRoot, serverURL)
	if err != nil {
		return err
	}
	credentialLock, err := state.LockCredentials()
	if err != nil {
		return err
	}
	defer credentialLock.Close()
	previous, hadPrevious, err := state.AccessCredential()
	if err != nil {
		return err
	}
	var issued serverv1.TokenExchangeResponse
	if useOIDC {
		issued, err = server.ExchangeOIDC(ctx, idToken)
		if err != nil {
			return fmt.Errorf("exchange OIDC login: %w", err)
		}
	} else {
		issued, err = server.Exchange(ctx, login)
		if err != nil {
			return fmt.Errorf("exchange login token: %w", err)
		}
	}
	access := credentials.AccessToken(issued.AccessToken)
	credentialID, _, err := credentials.ParseAccessToken(access)
	if err != nil {
		return errors.New("server returned invalid access credential")
	}
	cleanup := func() {
		if client, cleanupErr := serverclient.New(serverURL, nil, access); cleanupErr == nil {
			_ = client.RevokeAccessCredential(ctx, credentialID.String())
		}
	}
	if credentialID.String() != issued.CredentialId || !issued.ExpiresAt.After(time.Now()) {
		cleanup()
		return errors.New("server returned invalid access credential")
	}
	if hadPrevious && previous.CredentialID != credentialID {
		previousClient, previousErr := serverclient.New(serverURL, nil, previous.Token)
		if previousErr == nil {
			previousErr = previousClient.RevokeAccessCredential(ctx, previous.CredentialID.String())
		}
		if previousErr != nil && !errors.Is(previousErr, serverclient.ErrUnauthenticated) &&
			!errors.Is(previousErr, serverclient.ErrNotFound) {
			cleanup()
			return fmt.Errorf("revoke previous access credential: %w", previousErr)
		}
	}
	if err := state.SaveAccessCredential(clientstate.AccessCredential{
		Token: access, CredentialID: credentialID, ExpiresAt: issued.ExpiresAt,
	}); err != nil {
		cleanup()
		return errors.Join(err, state.RemoveAccessCredential())
	}
	if err := clientstate.SaveServer(stateRoot, serverURL); err != nil {
		cleanup()
		return errors.Join(err, state.RemoveAccessCredential())
	}
	_, err = fmt.Fprintf(output, "Authenticated until %s\n", issued.ExpiresAt.UTC().Format(time.RFC3339))
	return err
}

func readLoginToken(input io.Reader, output io.Writer) (credentials.LoginToken, error) {
	if file, ok := input.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
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
	data, err := io.ReadAll(io.LimitReader(input, 257))
	if err != nil {
		return "", fmt.Errorf("read login token: %w", err)
	}
	if len(data) > 256 {
		return "", errors.New("login token input is too large")
	}
	return parseLoginInput(data)
}

func parseLoginInput(data []byte) (credentials.LoginToken, error) {
	token := credentials.LoginToken(strings.TrimSpace(string(data)))
	if _, err := credentials.ParseLoginToken(token); err != nil {
		return "", errors.New("invalid login token")
	}
	return token, nil
}

func runLogout(ctx context.Context, flags logoutCommand, output io.Writer) error {
	serverURL, _, err := resolveServer(flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	state, err := openClientState(flags.StateDir, serverURL)
	if err != nil {
		return err
	}
	credentialLock, err := state.LockCredentials()
	if err != nil {
		return err
	}
	defer credentialLock.Close()
	stored, found, err := state.AccessCredential()
	if err != nil {
		return err
	}
	if !found {
		return errors.New("no saved login")
	}
	server, err := serverclient.New(serverURL, nil, stored.Token)
	if err != nil {
		return err
	}
	revokeErr := server.RevokeAccessCredential(ctx, stored.CredentialID.String())
	if revokeErr != nil && !errors.Is(revokeErr, serverclient.ErrUnauthenticated) &&
		!errors.Is(revokeErr, serverclient.ErrNotFound) {
		return revokeErr
	}
	if err := state.RemoveAccessCredential(); err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, "Logged out")
	return err
}

func runPublic(ctx context.Context, flags publicCommand, stdout, stderr io.Writer) error {
	output, err := newPublicOutput(flags.Output, stdout, stderr)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		if ctx.Err() != nil {
			return errors.Join(ctx.Err(), output.stopped())
		}
		_ = output.failed(err)
		return err
	}
	target, err := localproxy.NormalizeTarget(flags.Target)
	if err != nil {
		return fail(err)
	}
	if err := output.starting(target); err != nil {
		return err
	}
	if err := localproxy.Preflight(ctx, target); err != nil {
		return fail(err)
	}
	serverURL, _, err := resolveServer(flags.StateDir, flags.ServerURL)
	if err != nil {
		return fail(err)
	}
	state, err := openClientState(flags.StateDir, serverURL)
	if err != nil {
		return fail(err)
	}
	client, err := authenticatedClient(serverURL, flags.AccessToken, state)
	if err != nil {
		return fail(err)
	}
	capabilities, err := client.Capabilities(ctx)
	if err != nil {
		return fail(fmt.Errorf("read server capabilities: %w", err))
	}
	if capabilities.Transport.Type != serverv1.Tailcat || capabilities.Transport.Version != serverv1.TransportCapabilitiesVersionN1 {
		return fail(errors.New("server does not support tailcat transport version 1"))
	}
	if capabilities.RouteSuffix == "" || capabilities.MaximumChildDepth != 8 {
		return fail(errors.New("server does not support the required naming contract"))
	}
	profile := capabilities.Transport.RelayProfile
	var publicationState *clientstate.Store
	acmeProfile := ""
	if capabilities.Acme == nil || capabilities.Acme.Profile == "" {
		return fail(errors.New("server does not support automatic certificates"))
	}
	publicationState = state
	acmeProfile = capabilities.Acme.Profile
	hostname, err := claimPublicHostname(ctx, client, flags.Name, capabilities)
	if err != nil {
		return fail(err)
	}
	logger := log.New(stderr, "tnl: ", 0)
	err = publication.RunPublic(ctx, publication.PublicConfig{
		Server: client, Hostname: hostname, Target: target,
		State: publicationState, ACMEProfile: acmeProfile,
		RelayProfile: profile, Logf: logger.Printf,
		LoadProfiles: func(ctx context.Context) (map[string]*tailcfg.DERPRegion, error) {
			relayMap, err := client.RelayMap(ctx)
			if err != nil {
				return nil, fmt.Errorf("read server relay map: %w", err)
			}
			return config.DecodeRelayProfiles(relayMap)
		},
		OnLeaseReady: output.ready,
	})
	if err != nil && !(ctx.Err() != nil && errors.Is(err, context.Canceled)) {
		return fail(err)
	}
	return output.stopped()
}

func runHostClaim(ctx context.Context, flags hostClaimCommand, output io.Writer) error {
	client, capabilities, err := namingClient(ctx, flags.StateDir, flags.ServerURL, flags.AccessToken)
	if err != nil {
		return err
	}
	kind, name, err := classifyClaimName(flags.Name, capabilities.RouteSuffix)
	if err != nil {
		return err
	}
	requestKey, err := randomRequestKey()
	if err != nil {
		return err
	}
	if kind == serverv1.CreateHostnameClaimRequestKindPersistentManaged {
		claim, err := client.ClaimName(ctx, kind, name, requestKey)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(output, claim.Hostname)
		return err
	}
	if !capabilities.CustomDomainSupport {
		return errors.New("server does not support custom domains")
	}
	challenge, err := client.CreateDomainChallenge(ctx, name, requestKey)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "Add these DNS records:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output); err != nil {
		return err
	}
	for _, record := range challenge.Records {
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
		claim, err := client.VerifyDomainChallenge(ctx, challenge.Id)
		if err == nil {
			_, err = fmt.Fprintf(output, "Claimed %s\n", claim.Hostname)
			return err
		}
		if !errors.Is(err, serverclient.ErrDNSProofPending) {
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

func runHostList(ctx context.Context, flags hostListCommand, output io.Writer) error {
	client, _, err := namingClient(ctx, flags.StateDir, flags.ServerURL, flags.AccessToken)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "NAME\tTYPE\tSTATE"); err != nil {
		return err
	}
	cursor := ""
	for {
		claims, next, err := client.ListHostnameClaimsPage(ctx, cursor)
		if err != nil {
			return err
		}
		for _, claim := range claims {
			typeName := "managed"
			if claim.Kind == serverv1.HostnameClaimKindPersistentCustomDomain {
				typeName = "custom"
			}
			if _, err := fmt.Fprintf(output, "%s\t%s\t%s\n", claim.Hostname, typeName, claim.State); err != nil {
				return err
			}
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}

func runHostRelease(ctx context.Context, flags hostReleaseCommand, output io.Writer) error {
	client, capabilities, err := namingClient(ctx, flags.StateDir, flags.ServerURL, flags.AccessToken)
	if err != nil {
		return err
	}
	claims, err := client.ListHostnameClaims(ctx)
	if err != nil {
		return err
	}
	hostname, claimID, err := resolveReleaseName(flags.Hostname, capabilities.RouteSuffix, claims)
	if err != nil {
		return err
	}
	if err := client.ReleaseHostnameClaim(ctx, claimID); err != nil && !errors.Is(err, serverclient.ErrNotFound) {
		return err
	}
	_, err = fmt.Fprintln(output, hostname)
	return err
}

func claimPublicHostname(
	ctx context.Context,
	client *serverclient.Client,
	name string,
	capabilities serverv1.Capabilities,
) (string, error) {
	if name == "" {
		requestKey, err := randomRequestKey()
		if err != nil {
			return "", err
		}
		claim, err := client.ClaimName(ctx, serverv1.CreateHostnameClaimRequestKindEphemeral, "", requestKey)
		if err != nil {
			return "", err
		}
		if claim.Kind != serverv1.HostnameClaimKindEphemeral || claim.State != serverv1.HostnameClaimStateHeld {
			return "", errors.New("server returned an invalid ephemeral name")
		}
		return validateClaimHostname(claim, capabilities.RouteSuffix)
	}
	claims, err := client.ListHostnameClaims(ctx)
	if err != nil {
		return "", err
	}
	hostname, base, managed, implicit, err := resolvePublicationName(name, capabilities.RouteSuffix, capabilities.MaximumChildDepth, claims)
	if err != nil {
		return "", err
	}
	if implicit {
		requestKey, err := randomRequestKey()
		if err != nil {
			return "", err
		}
		claim, err := client.ClaimName(ctx, serverv1.CreateHostnameClaimRequestKindPersistentManaged, base, requestKey)
		if err != nil {
			return "", err
		}
		if claim.Hostname != hostname || claim.State != serverv1.HostnameClaimStateActive {
			return "", errors.New("server returned an invalid managed base")
		}
	} else if !managed && !capabilities.CustomDomainSupport {
		return "", errors.New("server does not support custom domains")
	}
	return hostname, nil
}

func validateClaimHostname(claim serverv1.HostnameClaim, suffix string) (string, error) {
	canonicalSuffix, suffixErr := naming.CanonicalizeHostname(suffix)
	hostname, err := naming.CanonicalizeHostname(claim.Hostname)
	label, found := strings.CutSuffix(hostname, "."+suffix)
	if suffixErr != nil || canonicalSuffix != suffix || err != nil || hostname != claim.Hostname ||
		!found || label == "" || strings.Contains(label, ".") || claim.Id == "" {
		return "", errors.New("server returned an invalid hostname claim")
	}
	return hostname, nil
}

func namingClient(
	ctx context.Context,
	stateDir, serverValue, accessToken string,
) (*serverclient.Client, serverv1.Capabilities, error) {
	serverURL, _, err := resolveServer(stateDir, serverValue)
	if err != nil {
		return nil, serverv1.Capabilities{}, err
	}
	var state *clientstate.Store
	if accessToken == "" {
		state, err = openClientState(stateDir, serverURL)
		if err != nil {
			return nil, serverv1.Capabilities{}, err
		}
	}
	client, err := authenticatedClient(serverURL, accessToken, state)
	if err != nil {
		return nil, serverv1.Capabilities{}, err
	}
	capabilities, err := client.Capabilities(ctx)
	if err != nil {
		return nil, serverv1.Capabilities{}, fmt.Errorf("read server capabilities: %w", err)
	}
	if capabilities.RouteSuffix == "" || capabilities.MaximumChildDepth != 8 {
		return nil, serverv1.Capabilities{}, errors.New("server does not support the required naming contract")
	}
	return client, capabilities, nil
}

func classifyClaimName(input, routeSuffix string) (serverv1.CreateHostnameClaimRequestKind, string, error) {
	if input == "" {
		return serverv1.CreateHostnameClaimRequestKindPersistentManaged, "", nil
	}
	absolute := strings.HasSuffix(input, ".")
	canonical, err := naming.CanonicalizeHostname(input)
	if err != nil {
		return "", "", err
	}
	if !absolute && !strings.Contains(canonical, ".") {
		return serverv1.CreateHostnameClaimRequestKindPersistentManaged, canonical, nil
	}
	if naming.IsWithin(canonical, routeSuffix) {
		depth, _ := naming.ChildDepth(canonical, routeSuffix)
		if depth != 1 {
			return "", "", errors.New("managed base must be exactly one label beneath the route suffix")
		}
		return serverv1.CreateHostnameClaimRequestKindPersistentManaged, canonical, nil
	}
	domain, _, err := naming.CustomDomain(canonical, routeSuffix)
	if err != nil {
		return "", "", err
	}
	return "", domain, nil
}

func resolvePublicationName(
	input, routeSuffix string,
	maximumDepth int,
	claims []serverv1.HostnameClaim,
) (hostname, base string, managed, implicit bool, err error) {
	absolute := strings.HasSuffix(input, ".")
	canonical, err := naming.CanonicalizeHostname(input)
	if err != nil {
		return "", "", false, false, err
	}
	active := func(kind serverv1.HostnameClaimKind, candidate string) bool {
		for _, claim := range claims {
			if claim.Kind == kind && claim.State == serverv1.HostnameClaimStateActive && claim.Hostname == candidate {
				return true
			}
		}
		return false
	}
	if !absolute && !naming.IsWithin(canonical, routeSuffix) {
		for _, claim := range claims {
			if claim.Kind != serverv1.HostnameClaimKindPersistentCustomDomain || claim.State != serverv1.HostnameClaimStateActive {
				continue
			}
			if depth, ok := naming.ChildDepth(canonical, claim.Hostname); ok {
				if depth > maximumDepth {
					return "", "", false, false, errors.New("custom-domain child exceeds maximum depth")
				}
				return canonical, claim.Hostname, false, false, nil
			}
		}
	}
	if absolute && !naming.IsWithin(canonical, routeSuffix) {
		for _, claim := range claims {
			if claim.Kind == serverv1.HostnameClaimKindPersistentCustomDomain && claim.State == serverv1.HostnameClaimStateActive {
				if depth, ok := naming.ChildDepth(canonical, claim.Hostname); ok && depth <= maximumDepth {
					return canonical, claim.Hostname, false, false, nil
				}
			}
		}
		return "", "", false, false, errors.New("absolute name is not within an owned custom domain")
	}
	if !naming.IsWithin(canonical, routeSuffix) {
		canonical += "." + routeSuffix
		canonical, err = naming.CanonicalizeHostname(canonical)
		if err != nil {
			return "", "", false, false, err
		}
	}
	if canonical == routeSuffix {
		return "", "", false, false, errors.New("route suffix cannot be published")
	}
	relative, _ := strings.CutSuffix(canonical, "."+routeSuffix)
	labels := strings.Split(relative, ".")
	if len(labels) == 0 || len(labels)-1 > maximumDepth {
		return "", "", false, false, errors.New("managed child exceeds maximum depth")
	}
	base = labels[len(labels)-1] + "." + routeSuffix
	if len(labels) == 1 && !active(serverv1.HostnameClaimKindPersistentManaged, base) {
		return canonical, labels[0], true, true, nil
	}
	if !active(serverv1.HostnameClaimKindPersistentManaged, base) {
		return "", "", false, false, fmt.Errorf("base %s is not owned", base)
	}
	return canonical, base, true, false, nil
}

func resolveReleaseName(
	input, routeSuffix string,
	claims []serverv1.HostnameClaim,
) (string, string, error) {
	canonical, err := naming.CanonicalizeHostname(input)
	if err != nil {
		return "", "", err
	}
	if !strings.HasSuffix(input, ".") && !strings.Contains(canonical, ".") {
		canonical += "." + routeSuffix
	}
	for _, claim := range claims {
		if claim.Hostname == canonical {
			return canonical, claim.Id, nil
		}
	}
	return "", "", errors.New("hostname claim not found")
}

func authenticatedClient(
	serverURL, tokenValue string,
	state *clientstate.Store,
) (*serverclient.Client, error) {
	if tokenValue == "" {
		if state == nil {
			return nil, errors.New("not authenticated; run tnl login")
		}
		stored, found, err := state.AccessCredential()
		if err != nil {
			return nil, err
		}
		if !found || !stored.ExpiresAt.After(time.Now()) {
			return nil, errors.New("not authenticated; run tnl login")
		}
		tokenValue = stored.Token.String()
	}
	token := credentials.AccessToken(tokenValue)
	if _, _, err := credentials.ParseAccessToken(token); err != nil {
		return nil, errors.New("invalid access token")
	}
	return serverclient.New(serverURL, nil, token)
}

func resolveServer(root, value string) (string, string, error) {
	root, err := clientStateRoot(root)
	if err != nil {
		return "", "", err
	}
	if value != "" {
		server, err := clientstate.CanonicalServer(value)
		return server, root, err
	}
	server, found, err := clientstate.SavedServer(root)
	if err != nil {
		return "", "", err
	}
	if !found {
		return defaultServerURL, root, nil
	}
	return server, root, nil
}

func openClientState(root, serverURL string) (*clientstate.Store, error) {
	root, err := clientStateRoot(root)
	if err != nil {
		return nil, err
	}
	return clientstate.New(root, serverURL)
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
