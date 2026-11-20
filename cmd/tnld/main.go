package main

import (
	"context"
	"encoding/json"
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
	case "config show":
		reason = failure.ServerConfigInvalid
		base := daemonconfig.Config(flags.Config.Show.Values)
		sources := explicitSources(parsed)
		var cfg daemonconfig.Config
		if flags.Config.Show.ConfigPath != "" {
			cfg, err = resolveConfigWithSources(flags.Config.Show.ConfigPath, base, sources)
		} else {
			cfg, err = daemonconfig.ResolveExplicit(base, suppliedSettings(sources))
		}
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(daemonconfig.Inspect(cfg, sources))
	case "ingress-pool apply":
		reason = failure.ServerConfigInvalid
		cfg, err := resolveServeCommand(flags.IngressPool.Apply.ConfigPath, daemonconfig.Config(flags.IngressPool.Apply.Values), parsed)
		if err != nil {
			return err
		}
		return daemon.ApplyIngressPool(ctx, cfg)
	case "version":
		reason = failure.ServerOutputUnavailable
		_, err := fmt.Fprintln(stdout, buildinfo.Line("tnld"))
		return err
	default:
		return errors.New("command is required")
	}
}

func newTNLDParser(flags *tnldCLI, output io.Writer) (*kong.Kong, error) {
	return kong.New(flags, kong.Name("tnld"), kong.Description("tnld process."), kong.Writers(output, output), kong.Help(func(options kong.HelpOptions, ctx *kong.Context) error {
		role := daemonconfig.Role(flags.Serve.Values.Role)
		if role == "" {
			role = daemonconfig.Role(os.Getenv("TNLD_ROLE"))
		}
		if role == "" {
			role = daemonconfig.RoleStandalone
		}
		for _, element := range ctx.Path {
			if element.Flag != nil && element.Flag.Name == "role" {
				if value, ok := ctx.FlagValue(element.Flag).(daemonconfig.Role); ok {
					role = value
				}
			}
		}
		var visit func(*kong.Node)
		visit = func(node *kong.Node) {
			for _, flag := range node.Flags {
				name := strings.ReplaceAll(flag.Name, "-", "_")
				if flag.Name != "help" && flag.Name != "config" && !daemonconfig.SettingApplies(name, role) {
					flag.Hidden = true
				}
			}
			for _, child := range node.Children {
				visit(child)
			}
		}
		visit(ctx.Model.Node)
		return kong.DefaultHelpPrinter(options, ctx)
	}))
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
	Show  tnldServeCommand       `cmd:"" help:"Print resolved settings and sources as JSON, with credentials redacted."`
}

type tnldIngressPoolCommand struct {
	Apply tnldServeCommand `cmd:"" help:"Explicitly apply the primary pool allocation inventory without starting services."`
}

type tnldCLI struct {
	Migrate     struct{}               `cmd:"" help:"Apply control-state database migrations."`
	Serve       tnldServeCommand       `cmd:"" default:"withargs" help:"Run the configured tnld process."`
	Config      tnldConfigCommand      `cmd:"" help:"Inspect process configuration."`
	IngressPool tnldIngressPoolCommand `cmd:"" help:"Manage durable ingress pool allocation policy."`
	Version     struct{}               `cmd:"" help:"Print release version information."`
}

func resolveServeCommand(path string, base daemonconfig.Config, parsed *kong.Context) (daemonconfig.Config, error) {
	sources := explicitSources(parsed)
	if path == "" {
		return daemonconfig.ResolveExplicit(base, suppliedSettings(sources))
	}
	return resolveConfigWithSources(path, base, sources)
}

func explicitSources(parsed *kong.Context) map[string]string {
	result := map[string]string{}
	for _, element := range parsed.Path {
		if element.Flag != nil && !element.Resolved {
			result[strings.ReplaceAll(element.Flag.Name, "-", "_")] = "flag"
		}
	}
	return result
}

func suppliedSettings(sources map[string]string) map[string]bool {
	result := map[string]bool{}
	for name := range sources {
		result[name] = true
	}
	return result
}

func resolveConfigFile(path string, base daemonconfig.Config, commandLine map[string]bool) (daemonconfig.Config, error) {
	sources := map[string]string{}
	for name := range commandLine {
		sources[name] = "flag"
	}
	return resolveConfigWithSources(path, base, sources)
}

func resolveConfigWithSources(path string, base daemonconfig.Config, sources map[string]string) (daemonconfig.Config, error) {
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
	applied := document.TNLD.ApplyLowerPrecedence(&base, suppliedSettings(sources))
	for name := range applied {
		sources[name] = "file"
	}
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
	return daemonconfig.ResolveExplicit(base, suppliedSettings(sources))
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
