package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/0xcadams/tnl/internal/buildinfo"
	"github.com/0xcadams/tnl/internal/clientstate"
	"github.com/0xcadams/tnl/internal/config"
	"github.com/0xcadams/tnl/internal/coreclient"
	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/localproxy"
	"github.com/0xcadams/tnl/internal/naming"
	"github.com/0xcadams/tnl/internal/publication"
	"github.com/0xcadams/tnl/pkg/protocol/corev1"
	"github.com/alecthomas/kong"
)

type cli struct {
	Public  publicCommand `cmd:"" help:"Publish one local HTTP service."`
	Host    hostCommand   `cmd:"" help:"Manage self-hosted public names."`
	Token   tokenCommand  `cmd:"" help:"Generate a deployment credential."`
	Auth    authCommand   `cmd:"" help:"Authenticate to a core API."`
	Version struct{}      `cmd:"" help:"Print release version information."`
}

type publicCommand struct {
	Target       string `arg:"" name:"target" required:"" help:"Local port or literal-loopback HTTP origin."`
	CoreURL      string `name:"core-url" env:"TNL_CORE_URL" required:"" help:"tnl core HTTPS origin."`
	AccessToken  string `name:"access-token" env:"TNL_ACCESS_TOKEN" required:"" help:"Core API access token."`
	Host         string `name:"host" env:"TNL_HOST" help:"Requested single-label public name; omit for a random name."`
	Output       string `name:"output" enum:"human,ndjson" default:"human" help:"Output format: ${enum}."`
	CertFile     string `name:"cert-file" env:"TNL_CERT_FILE" type:"path" help:"Application TLS certificate file; overrides automatic certificates."`
	KeyFile      string `name:"key-file" env:"TNL_KEY_FILE" type:"path" help:"Application TLS private key file; overrides automatic certificates."`
	StateDir     string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent route state."`
	RelayMapFile string `name:"relay-map-file" env:"TNL_RELAY_MAP_FILE" type:"path" required:"" help:"Approved DERP map JSON file."`
}

type hostCommand struct {
	List    hostListCommand    `cmd:"" help:"List active hostname claims."`
	Release hostReleaseCommand `cmd:"" help:"Permanently release a hostname claim."`
}

type hostListCommand struct {
	CoreURL     string `name:"core-url" env:"TNL_CORE_URL" required:"" help:"tnl core HTTPS origin."`
	AccessToken string `name:"access-token" env:"TNL_ACCESS_TOKEN" required:"" help:"Core API access token."`
}

type hostReleaseCommand struct {
	Hostname    string `arg:"" name:"hostname" required:"" help:"Exact hostname to release."`
	CoreURL     string `name:"core-url" env:"TNL_CORE_URL" required:"" help:"tnl core HTTPS origin."`
	AccessToken string `name:"access-token" env:"TNL_ACCESS_TOKEN" required:"" help:"Core API access token."`
	StateDir    string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent route state."`
}

type tokenCommand struct {
	Bootstrap struct{} `cmd:"" help:"Generate a bootstrap token."`
	Worker    struct{} `cmd:"" help:"Generate an edge-to-worker token."`
}

type authCommand struct {
	Exchange exchangeCommand `cmd:"" help:"Exchange a bootstrap token for an access token."`
}

type exchangeCommand struct {
	CoreURL        string `name:"core-url" env:"TNL_CORE_URL" required:"" help:"tnl core HTTPS origin."`
	BootstrapToken string `name:"bootstrap-token" env:"TNL_BOOTSTRAP_TOKEN" required:"" help:"Deployment bootstrap token."`
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
	parser, err := kong.New(&flags, kong.Name("tnl"), kong.Description("A public URL for localhost."))
	if err != nil {
		return err
	}
	parsed, err := parser.Parse(args)
	if err != nil {
		return err
	}
	switch parsed.Command() {
	case "token bootstrap":
		token, err := credentials.NewBootstrapToken()
		if err == nil {
			_, err = fmt.Fprintln(stdout, token.String())
		}
		return err
	case "token worker":
		token, _, err := credentials.NewWorkerToken()
		if err == nil {
			_, err = fmt.Fprintln(stdout, token.String())
		}
		return err
	case "auth exchange":
		return runExchange(ctx, flags.Auth.Exchange, stdout)
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

func runExchange(ctx context.Context, flags exchangeCommand, output io.Writer) error {
	bootstrap := credentials.BootstrapToken(flags.BootstrapToken)
	if _, err := credentials.ParseBootstrapToken(bootstrap); err != nil {
		return errors.New("invalid bootstrap token")
	}
	client, err := coreclient.New(flags.CoreURL, nil, "")
	if err != nil {
		return err
	}
	issued, err := client.Exchange(ctx, bootstrap)
	if err != nil {
		return err
	}
	access := credentials.AccessToken(issued.AccessToken)
	if _, _, err := credentials.ParseAccessToken(access); err != nil {
		return errors.New("core returned invalid access token")
	}
	_, err = fmt.Fprintln(output, access.String())
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
	client, err := authenticatedClient(flags.CoreURL, flags.AccessToken)
	if err != nil {
		return fail(err)
	}
	capabilities, err := client.Capabilities(ctx)
	if err != nil {
		return fail(fmt.Errorf("read core capabilities: %w", err))
	}
	if capabilities.Transport.Type != corev1.Tailcat || capabilities.Transport.Version != corev1.TransportCapabilitiesVersionN1 {
		return fail(errors.New("core does not support tailcat transport version 1"))
	}
	if capabilities.LocalClaim == nil || capabilities.LocalClaim.Suffix == "" {
		return fail(errors.New("core does not support self-hosted hostname claims"))
	}
	profiles, err := config.LoadRelayProfiles(flags.RelayMapFile)
	if err != nil {
		return fail(err)
	}
	profile := capabilities.Transport.RelayProfile
	if profiles[profile] == nil {
		return fail(fmt.Errorf("core requires relay profile %q, which is absent from the relay map", profile))
	}
	state, err := openClientState(flags.StateDir, flags.CoreURL)
	if err != nil {
		return fail(err)
	}
	var certificate tls.Certificate
	var publicationState *clientstate.Store
	acmeProfile := ""
	if flags.CertFile == "" != (flags.KeyFile == "") {
		return fail(errors.New("certificate and key files must be configured together"))
	}
	if flags.CertFile != "" {
		certificate, err = tls.LoadX509KeyPair(flags.CertFile, flags.KeyFile)
		if err != nil {
			return fail(fmt.Errorf("load application certificate: %w", err))
		}
	} else {
		if capabilities.Acme == nil || capabilities.Acme.Profile == "" {
			return fail(errors.New("core does not support automatic certificates; certificate and key files are required"))
		}
		publicationState = state
		acmeProfile = capabilities.Acme.Profile
	}
	hostname, err := claimPublicHostname(ctx, client, state, target, flags.Host, capabilities.LocalClaim.Suffix)
	if err != nil {
		return fail(err)
	}
	logger := log.New(stderr, "tnl: ", 0)
	err = publication.RunPublic(ctx, publication.PublicConfig{
		Core: client, Hostname: hostname, Target: target, Certificate: certificate,
		State: publicationState, ACMEProfile: acmeProfile,
		RelayProfile: profile, Profiles: profiles, Logf: logger.Printf,
		OnLeaseReady: output.ready,
	})
	if err != nil && !(ctx.Err() != nil && errors.Is(err, context.Canceled)) {
		return fail(err)
	}
	return output.stopped()
}

func runHostList(ctx context.Context, flags hostListCommand, output io.Writer) error {
	client, err := authenticatedClient(flags.CoreURL, flags.AccessToken)
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
	state, err := openClientState(flags.StateDir, flags.CoreURL)
	if err != nil {
		return err
	}
	lock, err := clientstate.LockHostnameContext(ctx, state, "hostname-selections")
	if err != nil {
		return err
	}
	defer lock.Close()
	client, err := authenticatedClient(flags.CoreURL, flags.AccessToken)
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
	if err := client.ReleaseHostnameClaim(ctx, claimID); err != nil && !errors.Is(err, coreclient.ErrNotFound) {
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
	client *coreclient.Client,
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

func validateClaimHostname(claim corev1.HostnameClaim, suffix string) (string, error) {
	canonicalSuffix, suffixErr := naming.CanonicalizeHostname(suffix)
	hostname, err := naming.CanonicalizeHostname(claim.Hostname)
	label, found := strings.CutSuffix(hostname, "."+suffix)
	if suffixErr != nil || canonicalSuffix != suffix || err != nil || hostname != claim.Hostname ||
		!found || label == "" || strings.Contains(label, ".") || claim.Id == "" {
		return "", errors.New("core returned an invalid hostname claim")
	}
	return hostname, nil
}

func authenticatedClient(coreURL, tokenValue string) (*coreclient.Client, error) {
	token := credentials.AccessToken(tokenValue)
	if _, _, err := credentials.ParseAccessToken(token); err != nil {
		return nil, errors.New("invalid access token")
	}
	return coreclient.New(coreURL, nil, token)
}

func openClientState(root, coreURL string) (*clientstate.Store, error) {
	if root == "" {
		var err error
		root, err = clientstate.DefaultDir()
		if err != nil {
			return nil, err
		}
	}
	return clientstate.New(root, coreURL)
}

func randomRequestKey() (string, error) {
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", err
	}
	return "random_" + hex.EncodeToString(material[:]), nil
}
