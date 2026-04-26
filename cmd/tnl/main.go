package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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

	"github.com/0xcadams/tnl/internal/buildinfo"
	"github.com/0xcadams/tnl/internal/clientstate"
	"github.com/0xcadams/tnl/internal/config"
	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/localproxy"
	"github.com/0xcadams/tnl/internal/naming"
	"github.com/0xcadams/tnl/internal/oidclogin"
	"github.com/0xcadams/tnl/internal/publication"
	"github.com/0xcadams/tnl/internal/serverclient"
	"github.com/0xcadams/tnl/pkg/protocol/serverv1"
	"github.com/alecthomas/kong"
	"golang.org/x/term"
	"tailscale.com/tailcfg"
)

type cli struct {
	Public  publicCommand `cmd:"" help:"Publish one local HTTP service."`
	Host    hostCommand   `cmd:"" help:"Manage self-hosted public names."`
	Login   loginCommand  `cmd:"" help:"Authenticate to a tnl server."`
	Logout  logoutCommand `cmd:"" help:"Revoke and remove the saved access token."`
	Version struct{}      `cmd:"" help:"Print release version information."`
}

type publicCommand struct {
	Target      string `arg:"" name:"target" required:"" help:"Local port or literal-loopback HTTP origin."`
	ServerURL   string `name:"server" env:"TNL_SERVER" help:"tnl server HTTPS origin; defaults to the saved server."`
	AccessToken string `name:"access-token" env:"TNL_ACCESS_TOKEN" help:"Server access token; defaults to the saved login."`
	Host        string `name:"host" env:"TNL_HOST" help:"Requested single-label public name; omit for a random name."`
	Output      string `name:"output" enum:"human,ndjson" default:"human" help:"Output format: ${enum}."`
	StateDir    string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent route state."`
}

type hostCommand struct {
	List    hostListCommand    `cmd:"" help:"List active hostname claims."`
	Release hostReleaseCommand `cmd:"" help:"Permanently release a hostname claim."`
}

type hostListCommand struct {
	ServerURL   string `name:"server" env:"TNL_SERVER" help:"tnl server HTTPS origin; defaults to the saved server."`
	AccessToken string `name:"access-token" env:"TNL_ACCESS_TOKEN" help:"Server access token; defaults to the saved login."`
	StateDir    string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent client state."`
}

type hostReleaseCommand struct {
	Hostname    string `arg:"" name:"hostname" required:"" help:"Exact hostname to release."`
	ServerURL   string `name:"server" env:"TNL_SERVER" help:"tnl server HTTPS origin; defaults to the saved server."`
	AccessToken string `name:"access-token" env:"TNL_ACCESS_TOKEN" help:"Server access token; defaults to the saved login."`
	StateDir    string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent route state."`
}

type loginCommand struct {
	Server    string `arg:"" name:"server" optional:"" help:"tnl server HTTPS origin."`
	ServerURL string `name:"server" env:"TNL_SERVER" help:"tnl server HTTPS origin; defaults to the saved server."`
	StateDir  string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent client state."`
	Token     bool   `name:"token" help:"Use the local login token even when OIDC is available."`
}

type logoutCommand struct {
	ServerURL string `name:"server" env:"TNL_SERVER" help:"tnl server HTTPS origin; defaults to the saved server."`
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
	case "host list":
		return runHostList(ctx, flags.Host.List, stderr)
	case "host release <hostname>":
		return runHostRelease(ctx, flags.Host.Release, stderr)
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
	if capabilities.LocalClaim == nil || capabilities.LocalClaim.Suffix == "" {
		return fail(errors.New("server does not support self-hosted hostname claims"))
	}
	profile := capabilities.Transport.RelayProfile
	var publicationState *clientstate.Store
	acmeProfile := ""
	if capabilities.Acme == nil || capabilities.Acme.Profile == "" {
		return fail(errors.New("server does not support automatic certificates"))
	}
	publicationState = state
	acmeProfile = capabilities.Acme.Profile
	hostname, err := claimPublicHostname(ctx, client, state, target, flags.Host, capabilities.LocalClaim.Suffix)
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

func runHostList(ctx context.Context, flags hostListCommand, output io.Writer) error {
	serverURL, _, err := resolveServer(flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	var state *clientstate.Store
	if flags.AccessToken == "" {
		state, err = openClientState(flags.StateDir, serverURL)
		if err != nil {
			return err
		}
	}
	client, err := authenticatedClient(serverURL, flags.AccessToken, state)
	if err != nil {
		return err
	}
	cursor := ""
	for {
		claims, next, err := client.ListHostnameClaimsPage(ctx, cursor)
		if err != nil {
			return err
		}
		for _, claim := range claims {
			if _, err := fmt.Fprintln(output, claim.Hostname); err != nil {
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
	hostname, err := naming.CanonicalizeHostname(flags.Hostname)
	if err != nil {
		return err
	}
	serverURL, _, err := resolveServer(flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	state, err := openClientState(flags.StateDir, serverURL)
	if err != nil {
		return err
	}
	lock, err := clientstate.LockHostnameContext(ctx, state, "hostname-selections")
	if err != nil {
		return err
	}
	defer lock.Close()
	client, err := authenticatedClient(serverURL, flags.AccessToken, state)
	if err != nil {
		return err
	}
	// Persist release intent before deletion so retries keep the claim ID.
	pendingID, pending, err := state.PendingHostnameRelease(hostname)
	if err != nil {
		return err
	}
	claimID := pendingID
	if !pending {
		cursor := ""
		for claimID == "" {
			claims, next, err := client.ListHostnameClaimsPage(ctx, cursor)
			if err != nil {
				return err
			}
			for _, claim := range claims {
				if claim.Hostname == hostname {
					claimID = claim.Id
					break
				}
			}
			if next == "" {
				break
			}
			cursor = next
		}
		if claimID == "" {
			return errors.New("hostname claim not found")
		}
		if err := state.SaveHostnameRelease(hostname, claimID); err != nil {
			return err
		}
	}
	if err := client.ReleaseHostnameClaim(ctx, claimID); err != nil && !errors.Is(err, serverclient.ErrNotFound) {
		return err
	}
	if err := state.RemoveHostnameSelection(hostname); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, hostname); err != nil {
		return err
	}
	if err := state.ClearHostnameRelease(hostname); err != nil {
		return err
	}
	return nil
}

func claimPublicHostname(
	ctx context.Context,
	client *serverclient.Client,
	state *clientstate.Store,
	target, label, suffix string,
) (string, error) {
	if label != "" {
		canonical, err := naming.CanonicalizeHostname(label)
		if err != nil || strings.Contains(canonical, ".") {
			return "", errors.New("host must be one DNS label")
		}
		digest := sha256.Sum256([]byte(canonical))
		claim, err := client.ClaimHostname(ctx, canonical, "label_"+hex.EncodeToString(digest[:]))
		if err != nil {
			return "", err
		}
		return validateClaimHostname(claim, suffix)
	}
	// Serialize the whole selection flow across processes.
	lock, err := clientstate.LockHostnameContext(ctx, state, "hostname-selections")
	if err != nil {
		return "", err
	}
	defer lock.Close()
	selection, found, err := state.HostnameSelection(target)
	if err != nil {
		return "", err
	}
	if !found {
		selection.RequestKey, err = randomRequestKey()
		if err != nil {
			return "", err
		}
		// Save before allocation so retries replay the same request.
		if err := state.SaveHostnameSelection(target, selection); err != nil {
			return "", err
		}
	}
	claim, err := client.ClaimHostname(ctx, "", selection.RequestKey)
	if err != nil {
		return "", err
	}
	hostname, err := validateClaimHostname(claim, suffix)
	if err != nil {
		return "", err
	}
	selection.ClaimID = claim.Id
	selection.Hostname = hostname
	if err := state.SaveHostnameSelection(target, selection); err != nil {
		return "", err
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
		return "", "", errors.New("server is required; run tnl login SERVER or use --server")
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
