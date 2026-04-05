package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/0xcadams/tnl/internal/clientstate"
	"github.com/0xcadams/tnl/internal/config"
	"github.com/0xcadams/tnl/internal/coreclient"
	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/publication"
	"github.com/0xcadams/tnl/pkg/protocol/corev1"
	"github.com/alecthomas/kong"
)

type cli struct {
	Publish publishCommand `cmd:"" help:"Publish one local HTTP service."`
	Token   tokenCommand   `cmd:"" help:"Generate a deployment credential."`
	Auth    authCommand    `cmd:"" help:"Authenticate to a core API."`
}

type publishCommand struct {
	CoreURL      string `name:"core-url" env:"TNL_CORE_URL" required:"" help:"TNL core HTTPS origin."`
	AccessToken  string `name:"access-token" env:"TNL_ACCESS_TOKEN" required:"" help:"Core API access token."`
	Hostname     string `name:"hostname" env:"TNL_HOSTNAME" required:"" help:"Public route hostname."`
	Target       string `name:"target" env:"TNL_TARGET" required:"" help:"Literal-loopback HTTP target."`
	CertFile     string `name:"cert-file" env:"TNL_CERT_FILE" type:"path" help:"Application TLS certificate file; overrides automatic certificates."`
	KeyFile      string `name:"key-file" env:"TNL_KEY_FILE" type:"path" help:"Application TLS private key file; overrides automatic certificates."`
	StateDir     string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Directory for persistent route keys and certificates."`
	RelayMapFile string `name:"relay-map-file" env:"TNL_RELAY_MAP_FILE" type:"path" required:"" help:"Approved DERP map JSON file."`
}

type tokenCommand struct {
	Bootstrap struct{} `cmd:"" help:"Generate a bootstrap token."`
	Worker    struct{} `cmd:"" help:"Generate an edge-to-worker token."`
}

type authCommand struct {
	Exchange exchangeCommand `cmd:"" help:"Exchange a bootstrap token for an access token."`
}

type exchangeCommand struct {
	CoreURL        string `name:"core-url" env:"TNL_CORE_URL" required:"" help:"TNL core HTTPS origin."`
	BootstrapToken string `name:"bootstrap-token" env:"TNL_BOOTSTRAP_TOKEN" required:"" help:"Deployment bootstrap token."`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, args []string, output io.Writer) error {
	var flags cli
	parser, err := kong.New(&flags, kong.Name("tnl"), kong.Description("TNL client."))
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
			_, err = fmt.Fprintln(output, token.String())
		}
		return err
	case "token worker":
		token, _, err := credentials.NewWorkerToken()
		if err == nil {
			_, err = fmt.Fprintln(output, token.String())
		}
		return err
	case "auth exchange":
		bootstrap := credentials.BootstrapToken(flags.Auth.Exchange.BootstrapToken)
		if _, err := credentials.ParseBootstrapToken(bootstrap); err != nil {
			return errors.New("invalid bootstrap token")
		}
		client, err := coreclient.New(flags.Auth.Exchange.CoreURL, nil, "")
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
	case "publish":
		return runPublish(ctx, flags.Publish, output)
	default:
		return errors.New("command is required")
	}
}

func runPublish(ctx context.Context, flags publishCommand, output io.Writer) error {
	accessToken := credentials.AccessToken(flags.AccessToken)
	if _, _, err := credentials.ParseAccessToken(accessToken); err != nil {
		return errors.New("invalid access token")
	}
	if flags.CertFile == "" != (flags.KeyFile == "") {
		return errors.New("certificate and key files must be configured together")
	}
	profiles, err := config.LoadRelayProfiles(flags.RelayMapFile)
	if err != nil {
		return err
	}
	client, err := coreclient.New(flags.CoreURL, nil, accessToken)
	if err != nil {
		return err
	}
	capabilities, err := client.Capabilities(ctx)
	if err != nil {
		return fmt.Errorf("read core capabilities: %w", err)
	}
	if capabilities.Transport.Type != corev1.Tailcat || capabilities.Transport.Version != corev1.TransportCapabilitiesVersionN1 {
		return errors.New("core does not support tailcat transport version 1")
	}
	profile := capabilities.Transport.RelayProfile
	if profiles[profile] == nil {
		return fmt.Errorf("core requires relay profile %q, which is absent from the relay map", profile)
	}
	var certificate tls.Certificate
	var clientState *clientstate.Store
	acmeProfile := ""
	if flags.CertFile != "" {
		certificate, err = tls.LoadX509KeyPair(flags.CertFile, flags.KeyFile)
		if err != nil {
			return fmt.Errorf("load application certificate: %w", err)
		}
	} else {
		if capabilities.Acme == nil || capabilities.Acme.Profile == "" {
			return errors.New("core does not support automatic certificates; certificate and key files are required")
		}
		stateDir := flags.StateDir
		if stateDir == "" {
			stateDir, err = clientstate.DefaultDir()
			if err != nil {
				return err
			}
		}
		clientState, err = clientstate.New(stateDir, flags.CoreURL)
		if err != nil {
			return err
		}
		acmeProfile = capabilities.Acme.Profile
	}
	return publication.RunPublic(ctx, publication.PublicConfig{
		Core: client, Hostname: flags.Hostname, Target: flags.Target, Certificate: certificate,
		State: clientState, ACMEProfile: acmeProfile,
		RelayProfile: profile, Profiles: profiles, Logf: log.Printf,
		OnReady: func(publicURL string) { fmt.Fprintln(output, publicURL) },
	})
}
