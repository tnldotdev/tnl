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
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/daemon"
	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/failure"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		writeTerminalError(os.Stderr, err)
		os.Exit(1)
	}
}

func writeTerminalError(output io.Writer, err error) {
	typed, ok := failure.Of(err)
	if !ok {
		err = failure.Wrap("run tnld", failure.Unexpected, err)
		typed, _ = failure.Of(err)
	}
	_, definition, _ := failure.Describe(err)
	operation := string(typed.Operation())
	if setting := typed.Setting(); setting != "" {
		operation += " " + string(setting)
	}
	var text strings.Builder
	lineBreak := false
	for _, character := range fmt.Sprintf("%s: %s; %s", operation, definition.Message, definition.Action) {
		if character == '\r' || character == '\n' {
			lineBreak = true
			continue
		}
		if lineBreak && text.Len() != 0 {
			text.WriteString("; ")
		}
		lineBreak = false
		if character < 0x20 || character == 0x7f {
			fmt.Fprintf(&text, `\x%02x`, character)
			continue
		}
		text.WriteRune(character)
	}
	_, _ = fmt.Fprintf(output, "tnld: %s\n", text.String())
}

func run(ctx context.Context, args []string, stdout io.Writer) (result error) {
	operation := failure.Operation("parse command")
	reason := failure.ServerCommandInvalid
	defer func() {
		if result != nil {
			if _, typed := failure.Of(result); !typed {
				result = failure.Wrap(operation, reason, result)
			}
		}
	}()
	var flags tnldCLI
	parser, err := newTNLDParser(&flags, stdout)
	if err != nil {
		return err
	}
	parsed, err := parser.Parse(args)
	if err != nil {
		return err
	}
	if parsed.Command() != "" {
		operation = failure.Operation(parsed.Command())
	}
	switch parsed.Command() {
	case "migrate":
		reason = failure.ServerMigrationFailed
		directURL := os.Getenv("TNLD_DATABASE_DIRECT_URL")
		if directURL == "" {
			return failure.WrapSetting(operation, failure.DirectDatabaseURLMissing, failure.SettingDatabaseDirectURL,
				errors.New("TNLD_DATABASE_DIRECT_URL is required"))
		}
		return controlstate.Migrate(ctx, directURL)
	case "serve":
		reason = failure.ServerStartupFailed
		cfg, err := resolveServeCommand(flags.Serve.ConfigPath, daemonconfig.Config(flags.Serve.Values), parsed)
		if err != nil {
			return err
		}
		return daemon.Serve(ctx, cfg)
	case "config check":
		reason = failure.ServerConfigInvalid
		if flags.Config.Check.ConfigPath == "" {
			return failure.Wrap(operation, failure.ServerConfigFileInvalid, errors.New("--config or TNLD_CONFIG is required"))
		}
		base, err := parseDefaultsAndEnvironment()
		if err != nil {
			return err
		}
		_, err = resolveConfigFile(flags.Config.Check.ConfigPath, base, nil)
		return err
	case "version":
		reason = failure.ServerOutputUnavailable
		_, err := fmt.Fprintln(stdout, buildinfo.Line("tnld"))
		return err
	default:
		return errors.New("command is required")
	}
}

func newTNLDParser(flags *tnldCLI, output io.Writer) (*kong.Kong, error) {
	return kong.New(flags, kong.Name("tnld"), kong.Description("tnld process."), kong.Writers(output, output))
}

type tnldServeCommand struct {
	ConfigPath string     `name:"config" env:"TNLD_CONFIG" type:"path" help:"Load YAML or JSON process configuration."`
	Values     tnldValues `embed:""`
}

type tnldValues daemonconfig.Config

type tnldConfigCheckCommand struct {
	ConfigPath string `name:"config" env:"TNLD_CONFIG" type:"path" help:"Validate YAML or JSON process configuration."`
}

type tnldConfigCommand struct {
	Check tnldConfigCheckCommand `cmd:"" help:"Validate process configuration without starting services."`
}

type tnldCLI struct {
	Migrate struct{}          `cmd:"" help:"Apply control-state database migrations."`
	Serve   tnldServeCommand  `cmd:"" default:"withargs" help:"Run the configured tnld process."`
	Config  tnldConfigCommand `cmd:"" help:"Inspect process configuration."`
	Version struct{}          `cmd:"" help:"Print release version information."`
}

func resolveServeCommand(path string, base daemonconfig.Config, parsed *kong.Context) (daemonconfig.Config, error) {
	if path == "" {
		return daemonconfig.Resolve(base)
	}
	commandLine := make(map[string]bool)
	for _, element := range parsed.Path {
		if element.Flag != nil && !element.Resolved {
			commandLine[strings.ReplaceAll(element.Flag.Name, "-", "_")] = true
		}
	}
	return resolveConfigFile(path, base, commandLine)
}

func resolveConfigFile(path string, base daemonconfig.Config, commandLine map[string]bool) (daemonconfig.Config, error) {
	if strings.EqualFold(filepath.Ext(path), ".ts") {
		return daemonconfig.Config{}, failure.Wrap("load configuration", failure.ServerConfigFileInvalid,
			errors.New("tnld configuration must use .yml, .yaml, or .json"))
	}
	document, err := config.LoadDocument(path)
	if err != nil {
		return daemonconfig.Config{}, failure.Wrap("load configuration", failure.ServerConfigFileInvalid, err)
	}
	if document.TNLD == nil {
		return daemonconfig.Config{}, failure.Wrap("load configuration", failure.ServerConfigFileInvalid,
			errors.New("tnld configuration section is required"))
	}
	applied := document.TNLD.ApplyLowerPrecedence(&base, commandLine)
	directory := filepath.Dir(path)
	for name, target := range map[string]*string{
		"oidc_admission_file":                  &base.OIDCAdmissionFile,
		"private_control_tls_certificate_file": &base.ControlTLSCertificateFile,
		"private_control_tls_private_key_file": &base.ControlTLSPrivateKeyFile,
		"relay_tls_certificate_file":           &base.RelayTLSCertificateFile,
		"relay_tls_private_key_file":           &base.RelayTLSPrivateKeyFile,
	} {
		if applied[name] && *target != "" && !filepath.IsAbs(*target) {
			*target = filepath.Join(directory, *target)
		}
	}
	return daemonconfig.Resolve(base)
}

func parseDefaultsAndEnvironment() (daemonconfig.Config, error) {
	var value tnldValues
	parser, err := kong.New(&value, kong.Name("tnld"))
	if err != nil {
		return daemonconfig.Config{}, err
	}
	if _, err := parser.Parse(nil); err != nil {
		return daemonconfig.Config{}, err
	}
	return daemonconfig.Config(value), nil
}
