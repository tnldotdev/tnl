package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/tnldruntime"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "tnld: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	var flags tnldCLI
	parser, err := newTNLDParser(&flags, stdout)
	if err != nil {
		return err
	}
	parsed, err := parser.Parse(args)
	if err != nil {
		return err
	}
	switch parsed.Command() {
	case "migrate":
		directURL := os.Getenv("TNLD_DATABASE_DIRECT_URL")
		if directURL == "" {
			return errors.New("TNLD_DATABASE_DIRECT_URL is required")
		}
		return controlstate.Migrate(ctx, directURL)
	case "login-token":
		token, err := credentials.NewLoginToken()
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, token)
		return err
	case "serve":
		cfg, err := resolveTNLDCommand(flags.Serve.ConfigPath, config.TNLD(flags.Serve.Values), parsed)
		if err != nil {
			return err
		}
		return tnldruntime.Serve(ctx, cfg)
	case "config check":
		if flags.Config.Check.ConfigPath == "" {
			return errors.New("--config or TNLD_CONFIG is required")
		}
		base, err := parseTNLDDefaultsAndEnvironment()
		if err != nil {
			return err
		}
		_, err = resolveTNLDFile(flags.Config.Check.ConfigPath, base, nil)
		return err
	case "version":
		_, err := fmt.Fprintln(stdout, buildinfo.Line("tnld"))
		return err
	default:
		return errors.New("command is required")
	}
}

func newTNLDParser(flags *tnldCLI, output io.Writer) (*kong.Kong, error) {
	return kong.New(flags, kong.Name("tnld"), kong.Description("tnl server."), kong.Writers(output, output))
}

type tnldServeCommand struct {
	ConfigPath string     `name:"config" env:"TNLD_CONFIG" type:"path" help:"Load YAML or JSON server configuration."`
	Values     tnldValues `embed:""`
}

type tnldValues config.TNLD

type tnldConfigCheckCommand struct {
	ConfigPath string `name:"config" env:"TNLD_CONFIG" type:"path" help:"Validate YAML or JSON server configuration."`
}

type tnldConfigCommand struct {
	Check tnldConfigCheckCommand `cmd:"" help:"Validate server configuration without starting services."`
}

type tnldCLI struct {
	LoginToken struct{}          `cmd:"" name:"login-token" help:"Generate a bootstrap login token."`
	Migrate    struct{}          `cmd:"" help:"Apply control-state database migrations."`
	Serve      tnldServeCommand  `cmd:"" default:"withargs" help:"Run the tnl server."`
	Config     tnldConfigCommand `cmd:"" help:"Inspect server configuration."`
	Version    struct{}          `cmd:"" help:"Print release version information."`
}

func resolveTNLDCommand(path string, base config.TNLD, parsed *kong.Context) (config.TNLD, error) {
	if path == "" {
		return config.ResolveTNLD(base)
	}
	commandLine := make(map[string]bool)
	for _, element := range parsed.Path {
		if element.Flag != nil && !element.Resolved {
			commandLine[strings.ReplaceAll(element.Flag.Name, "-", "_")] = true
		}
	}
	return resolveTNLDFile(path, base, commandLine)
}

func resolveTNLDFile(path string, base config.TNLD, commandLine map[string]bool) (config.TNLD, error) {
	if strings.EqualFold(filepath.Ext(path), ".ts") {
		return config.TNLD{}, errors.New("tnld configuration must use .yml, .yaml, or .json")
	}
	document, err := config.LoadDocument(path)
	if err != nil {
		return config.TNLD{}, err
	}
	if document.TNLD == nil {
		return config.TNLD{}, errors.New("tnld configuration section is required")
	}
	applied := document.TNLD.ApplyLowerPrecedence(&base, commandLine)
	directory := filepath.Dir(path)
	for name, target := range map[string]*string{
		"control_tls_certificate_file": &base.ControlTLSCertificateFile,
		"control_tls_private_key_file": &base.ControlTLSPrivateKeyFile,
	} {
		if applied[name] && *target != "" && !filepath.IsAbs(*target) {
			*target = filepath.Join(directory, *target)
		}
	}
	return config.ResolveTNLD(base)
}

func parseTNLDDefaultsAndEnvironment() (config.TNLD, error) {
	var value tnldValues
	parser, err := kong.New(&value, kong.Name("tnld"))
	if err != nil {
		return config.TNLD{}, err
	}
	if _, err := parser.Parse(nil); err != nil {
		return config.TNLD{}, err
	}
	return config.TNLD(value), nil
}
