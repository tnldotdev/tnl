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

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/cliflags"
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
	var flags tnldCLI
	root := newServerCommand(&flags, stdout)
	root.SetArgs(args)
	_, err := root.ExecuteContextC(ctx)
	if err != nil {
		if _, typed := failure.Of(err); !typed {
			return failure.Wrap("parse command", failure.ServerCommandInvalid, err)
		}
	}
	return err
}

type serveOptions struct {
	ConfigPath string              `name:"config" env:"TNLD_CONFIG" type:"path" help:"Load YAML or JSON process configuration."`
	Values     daemonconfig.Config `embed:""`
}
type tnldCLI struct {
	Serve, Show, Apply serveOptions
	Check              struct {
		ConfigPath string `name:"config" env:"TNLD_CONFIG" type:"path" help:"Validate YAML or JSON process configuration."`
	}
}

func newServerCommand(flags *tnldCLI, stdout io.Writer) *cobra.Command {
	root := &cobra.Command{Use: "tnld", Short: "tnl server.", SilenceErrors: true, SilenceUsage: true}
	root.SetOut(stdout)
	root.SetErr(stdout)
	add := func(parent *cobra.Command, name, help string, options any, reason failure.Reason, run func(*cobra.Command) error) *cobra.Command {
		cmd := &cobra.Command{Use: name, Short: help, Args: cobra.NoArgs}
		cliflags.Bind(cmd, options, false)
		cmd.RunE = func(cmd *cobra.Command, _ []string) error {
			err := run(cmd)
			if err != nil {
				if _, typed := failure.Of(err); !typed {
					return failure.Wrap(failure.Operation(strings.TrimPrefix(cmd.CommandPath(), "tnld ")), reason, err)
				}
			}
			return err
		}
		parent.AddCommand(cmd)
		return cmd
	}
	group := func(name, help string) *cobra.Command {
		cmd := &cobra.Command{Use: name, Short: help, Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return errors.New("subcommand required") }}
		root.AddCommand(cmd)
		return cmd
	}
	configGroup := group("config", "Inspect process configuration.")
	pool := group("ingress-pool", "Manage durable ingress pool allocation policy.")
	add(root, "migrate", "Apply control-state database migrations.", nil, failure.ServerMigrationFailed, func(cmd *cobra.Command) error {
		directURL := os.Getenv("TNLD_DATABASE_DIRECT_URL")
		if directURL == "" {
			return failure.WrapSetting(failure.Operation("migrate"), failure.DirectDatabaseURLMissing, failure.SettingDatabaseDirectURL,
				errors.New("TNLD_DATABASE_DIRECT_URL is required"))
		}
		return controlstate.Migrate(cmd.Context(), directURL)
	})
	serve := add(root, "serve", "Run the configured tnld process.", &flags.Serve, failure.ServerStartupFailed, func(cmd *cobra.Command) error {
		cfg, err := resolveServeCommand(flags.Serve.ConfigPath, daemonconfig.Config(flags.Serve.Values), cmd)
		if err != nil {
			return err
		}
		return daemon.Serve(cmd.Context(), cfg)
	})
	add(configGroup, "check", "Validate process configuration without starting services.", &flags.Check, failure.ServerConfigInvalid, func(cmd *cobra.Command) error {
		if flags.Check.ConfigPath == "" {
			return failure.Wrap(failure.Operation("config check"), failure.ServerConfigFileInvalid, errors.New("--config or TNLD_CONFIG is required"))
		}
		base, err := parseDefaultsAndEnvironment()
		if err != nil {
			return err
		}
		_, err = resolveConfigFile(flags.Check.ConfigPath, base, nil)
		return err
	})
	add(configGroup, "show", "Print resolved settings and sources as JSON, with credentials redacted.", &flags.Show, failure.ServerConfigInvalid, func(cmd *cobra.Command) error {
		base := daemonconfig.Config(flags.Show.Values)
		sources := explicitSources(cmd)
		var err error
		var cfg daemonconfig.Config
		if flags.Show.ConfigPath != "" {
			cfg, err = resolveConfigWithSources(flags.Show.ConfigPath, base, sources)
		} else {
			cfg, err = daemonconfig.ResolveExplicit(base, suppliedSettings(sources))
		}
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(daemonconfig.Inspect(cfg, sources))
	})
	add(pool, "apply", "Apply the primary pool allocation inventory.", &flags.Apply, failure.ServerConfigInvalid, func(cmd *cobra.Command) error {
		cfg, err := resolveServeCommand(flags.Apply.ConfigPath, daemonconfig.Config(flags.Apply.Values), cmd)
		if err != nil {
			return err
		}
		return daemon.ApplyIngressPool(cmd.Context(), cfg)
	})
	add(root, "version", "Print release version information.", nil, failure.ServerOutputUnavailable, func(cmd *cobra.Command) error {
		_, err := fmt.Fprintln(stdout, buildinfo.Line("tnld"))
		return err
	})
	root.RunE = func(cmd *cobra.Command, args []string) error { return serve.RunE(cmd, args) }
	root.Args = serve.Args
	root.Flags().AddFlagSet(serve.Flags())
	normalHelp := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if flag := cmd.Flags().Lookup("role"); flag != nil {
			role := daemonconfig.Role(flag.Value.String())
			if env := os.Getenv("TNLD_ROLE"); !flag.Changed && env != "" {
				role = daemonconfig.Role(env)
			}
			cmd.Flags().VisitAll(func(f *pflag.Flag) {
				if f.Name != "help" && f.Name != "config" && !daemonconfig.SettingApplies(strings.ReplaceAll(f.Name, "-", "_"), role) {
					f.Hidden = true
				}
			})
		}
		normalHelp(cmd, args)
	})
	return root
}

func resolveServeCommand(path string, base daemonconfig.Config, cmd *cobra.Command) (daemonconfig.Config, error) {
	sources := explicitSources(cmd)
	if path == "" {
		return daemonconfig.ResolveExplicit(base, suppliedSettings(sources))
	}
	return resolveConfigWithSources(path, base, sources)
}
func explicitSources(cmd *cobra.Command) map[string]string {
	result := map[string]string{}
	cmd.Flags().Visit(func(f *pflag.Flag) { result[strings.ReplaceAll(f.Name, "-", "_")] = "flag" })
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
	var value daemonconfig.Config
	cmd := &cobra.Command{Use: "tnld"}
	cliflags.Bind(cmd, &value, false)
	err := cmd.ValidateArgs(nil)
	return value, err
}
