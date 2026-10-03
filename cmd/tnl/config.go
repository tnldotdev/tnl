package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/webhookips"
)

type projectConfiguration struct {
	projectconfig.Project
}

func selectProjectConfiguration(ctx context.Context, flags cli) (projectconfig.Selection, string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return projectconfig.Selection{}, "", fmt.Errorf("read working directory: %w", err)
	}
	selection, err := projectconfig.SelectProjectConfig(ctx, cwd, flags.ConfigPath, os.Getenv("TNL_CONFIG"), flags.NoConfig)
	return selection, cwd, err
}

func loadProjectConfiguration(ctx context.Context, flags cli, stateRoot string) (projectConfiguration, error) {
	state, err := clientstate.Open(ctx, stateRoot)
	if err != nil {
		return projectConfiguration{}, err
	}
	salt, err := state.WorktreeHashSalt(ctx)
	closeErr := state.Close()
	if err != nil {
		return projectConfiguration{}, err
	}
	if closeErr != nil {
		return projectConfiguration{}, closeErr
	}
	return loadProjectConfigurationWithSalt(ctx, flags, salt)
}

func loadProjectConfigurationWithSalt(ctx context.Context, flags cli, salt [32]byte) (projectConfiguration, error) {
	selection, cwd, err := selectProjectConfiguration(ctx, flags)
	if err != nil {
		return projectConfiguration{}, err
	}
	project, err := projectconfig.Resolve(ctx, selection, cwd, salt)
	if err != nil {
		return projectConfiguration{}, err
	}
	return projectConfiguration{Project: project}, nil
}

func projectRoot(ctx context.Context, flags cli) (string, error) {
	selection, cwd, err := selectProjectConfiguration(ctx, flags)
	if err != nil {
		return "", err
	}
	if selection.Path != "" {
		return filepath.Dir(selection.Path), nil
	}
	worktree, err := projectconfig.ResolveWorktree(ctx, cwd)
	if err != nil {
		return "", fmt.Errorf("resolve project worktree: %w", err)
	}
	return worktree.Root, nil
}

func (c projectConfiguration) applyPublish(flags *publishCommand) error {
	service := ""
	if _, found := c.Config.Services[flags.Target]; found && flags.Target != "" {
		service, flags.Target = flags.Target, ""
	} else if flags.Target == "" {
		var err error
		service, err = c.defaultService()
		if err != nil {
			return err
		}
	}
	effective, err := c.EffectiveService(service)
	if err != nil {
		return err
	}
	flags.Service = service
	flags.projectRoot = c.Root
	flags.ServerURL, flags.serverFromConfig, err = resolveProjectServer(flags.ServerURL, effective.Server, flags.AccessToken)
	if err != nil {
		return err
	}
	configuredTeam, err := c.configuredTeamForService(service, effective)
	if err != nil {
		return err
	}
	if flags.Team != "" {
		flags.selectedTeam = flags.Team
	} else {
		flags.selectedTeam, err = projectTeamForServer(flags.ServerURL, effective.Server, configuredTeam)
		if err != nil {
			return err
		}
	}
	if flags.Target == "" && effective.Publish != nil && effective.Publish.Target != nil {
		flags.Target = string(*effective.Publish.Target)
	}
	applyTunnelConfiguration(&flags.tunnelFlags, effective.Tunnel)
	applyOpenConfiguration(&flags.openOptions, effective.Tunnel)
	applyBuiltInHostname(&flags.tunnelFlags, service, c.Worktree)
	if flags.Target == "" {
		if service != "" {
			return fmt.Errorf("local target is required for service %q through publish.target", service)
		}
		return errors.New("local target is required as an argument or publish.target in project configuration")
	}
	return validateTunnelFlags(flags.tunnelFlags)
}

func (c projectConfiguration) applyDev(flags *devCommand) error {
	service := flags.Service
	if service == "" {
		var err error
		service, err = c.defaultService()
		if err != nil {
			return err
		}
	} else if _, found := c.Config.Services[service]; !found {
		return fmt.Errorf("service %q is not configured", service)
	}
	effective, err := c.EffectiveService(service)
	if err != nil {
		return err
	}
	flags.Service = service
	flags.projectRoot = c.Root
	flags.project = c
	flags.ServerURL, flags.serverFromConfig, err = resolveProjectServer(flags.ServerURL, effective.Server, flags.AccessToken)
	if err != nil {
		return err
	}
	configuredTeam, err := c.configuredTeamForService(service, effective)
	if err != nil {
		return err
	}
	if flags.Team != "" {
		flags.selectedTeam = flags.Team
	} else {
		flags.selectedTeam, err = projectTeamForServer(flags.ServerURL, effective.Server, configuredTeam)
		if err != nil {
			return err
		}
	}
	if service == "" {
		flags.commandDir = c.Root
	} else {
		flags.commandDir = c.ServiceDirectories[service]
		if flags.commandDir == "" {
			flags.commandDir = c.Root
		}
	}
	if flags.commandDir == "" && c.Selection.Path != "" {
		flags.commandDir = c.Root
	}
	if flags.portFromCLI && flags.Port == 0 {
		return diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("port must be between 1 and 65535"))
	}
	if flags.startupTimeoutFromCLI && flags.StartupTimeout == 0 {
		return errors.New("startup timeout must be greater than zero and at most 10 minutes")
	}
	if len(flags.Command) == 0 && effective.Dev != nil && effective.Dev.Command != nil {
		flags.Command = slices.Clone(effective.Dev.Command)
	}
	if flags.Port == 0 && effective.Dev != nil && effective.Dev.Port != nil {
		flags.Port = *effective.Dev.Port
	}
	if flags.StartupTimeout == 0 && effective.Dev != nil && effective.Dev.StartupTimeout != nil {
		flags.StartupTimeout = effective.Dev.StartupTimeout.Value()
	}
	applyTunnelConfiguration(&flags.tunnelFlags, effective.Tunnel)
	applyOpenConfiguration(&flags.openOptions, effective.Tunnel)
	_, ephemeralFromEnvironment := os.LookupEnv("TNL_EPHEMERAL")
	_, domainFromEnvironment := os.LookupEnv("TNL_DOMAIN")
	runtimeServerOverride := flags.ServerURL != "" && !flags.serverFromConfig
	flags.useMetadataHostname = flags.PublicURL == "" && flags.Name == "" && flags.Team == "" &&
		flags.Ephemeral && !runtimeServerOverride && !ephemeralFromEnvironment &&
		!flags.domainFromCLI && !domainFromEnvironment &&
		effective.Tunnel != nil && effective.Tunnel.Ephemeral != nil && *effective.Tunnel.Ephemeral
	applyBuiltInHostname(&flags.tunnelFlags, service, c.Worktree)
	if flags.StartupTimeout == 0 {
		flags.StartupTimeout = defaultDevStartupTimeout
	}
	return validateTunnelFlags(flags.tunnelFlags)
}

func (c projectConfiguration) defaultService() (string, error) {
	if len(c.Config.Services) == 0 {
		return "", nil
	}
	names := make([]string, 0, len(c.Config.Services))
	for name := range c.Config.Services {
		names = append(names, name)
	}
	slices.Sort(names)
	if len(names) == 1 {
		return names[0], nil
	}
	message := fmt.Sprintf("service is required; configured services: %s", strings.Join(names, ", "))
	return "", diagnostic.WrapMessage(diagnostic.ServiceAmbiguous, message, errors.New(message))
}

func applyBuiltInHostname(flags *tunnelFlags, service string, worktree projectconfig.Worktree) {
	if flags.PublicURL == "" && flags.Name == "" && !flags.Ephemeral {
		flags.Name = projectconfig.ServiceWorktreeLabel(service, worktree)
	}
}

func applyOpenConfiguration(flags *openOptions, tunnel *config.Tunnel) {
	if !flags.openFromCLI && tunnel != nil && tunnel.Open != nil {
		flags.Open = *tunnel.Open
	}
}

func applyTunnelConfiguration(flags *tunnelFlags, tunnel *config.Tunnel) {
	if tunnel == nil {
		return
	}
	if flags.RequestLimit == nil {
		flags.RequestLimit = tunnel.RequestLimit
	}
	if flags.Domain == "" && tunnel.Domain != nil {
		flags.Domain = *tunnel.Domain
	}
	if flags.PublicURL == "" && flags.Name == "" {
		if tunnel.PublicURL != nil {
			flags.PublicURL = *tunnel.PublicURL
		}
		if tunnel.Name != nil {
			flags.Name = *tunnel.Name
		}
	}
	_, ephemeralFromEnvironment := os.LookupEnv("TNL_EPHEMERAL")
	if tunnel.Ephemeral != nil && !flags.ephemeralFromCLI && !ephemeralFromEnvironment {
		flags.Ephemeral = *tunnel.Ephemeral
	}
	_, allowAllIPsFromEnvironment := os.LookupEnv("TNL_ALLOW_ALL_IPS")
	if !flags.allowAllIPsFromCLI && !allowAllIPsFromEnvironment {
		if flags.AllowIP == nil {
			flags.AllowIP = slices.Clone(tunnel.AllowIP)
		}
		if flags.AllowProvider == nil {
			flags.AllowProvider = slices.Clone(tunnel.AllowProviders)
		}
		if tunnel.AllowAllIPs != nil && flags.AllowIP == nil && flags.AllowProvider == nil {
			flags.AllowAllIPs = *tunnel.AllowAllIPs
		}
	}
}

func validateTunnelFlags(flags tunnelFlags) error {
	if flags.RequestLimit != nil && *flags.RequestLimit <= 0 {
		return errors.New("--request-limit must be greater than zero")
	}
	if flags.PublicURL != "" && flags.Name != "" {
		return errors.New("--public-url and --name are mutually exclusive")
	}
	if flags.AllowAllIPs && (flags.AllowIP != nil || flags.AllowProvider != nil) {
		return errors.New("--allow-all-ips cannot be combined with --allow-ip or --allow-provider")
	}
	seen := make(map[string]bool, len(flags.AllowProvider))
	for _, provider := range flags.AllowProvider {
		if !webhookips.Valid(provider) {
			return fmt.Errorf("unknown webhook IP provider %q (choose %s)", provider, strings.Join(webhookips.Names(), " or "))
		}
		if seen[provider] {
			return fmt.Errorf("--allow-provider %q was repeated", provider)
		}
		seen[provider] = true
	}
	return nil
}

func runConfigPath(ctx context.Context, flags cli, stdout io.Writer) error {
	selection, _, err := selectProjectConfiguration(ctx, flags)
	if err != nil {
		return err
	}
	state := "not found"
	text := "No project configuration file is selected."
	if selection.Path != "" {
		state = "selected"
		text = selection.Path
	}
	return clioutput.Write(stdout, clioutput.Frame{
		Command: "tnl config path", State: state, Blocks: []clioutput.Block{clioutput.Text(text)},
	})
}

func runConfigCheck(loaded projectConfiguration, stdout io.Writer) error {
	if !loaded.Found() {
		return errors.New("no project configuration file found")
	}
	return clioutput.Write(stdout, clioutput.Frame{
		Command: "tnl config check", State: "valid",
		Blocks: []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "path", Value: loaded.Selection.Path})},
	})
}

func projectSensitiveCommand(command string) bool {
	return command == "login" || command == "logout" || strings.HasPrefix(command, "admin ") ||
		strings.HasPrefix(command, "team ") || strings.HasPrefix(command, "domain ") || strings.HasPrefix(command, "url ")
}

// resolveProjectServer preserves invocation selection and its provenance. A
// project must not choose the destination for an explicitly supplied credential.
func resolveProjectServer(selected string, project *string, token string) (server string, fromProject bool, err error) {
	if selected != "" || project == nil {
		return selected, false, nil
	}
	if token != "" {
		return "", false, errors.New("an explicit access token with a project-provided server requires --server or TNL_SERVER")
	}
	return *project, true, nil
}

func projectTeamForServer(server string, configuredServer, configuredTeam *string) (string, error) {
	if configuredTeam == nil {
		return "", nil
	}
	if server != "" && configuredServer != nil {
		selected, err := clientstate.CanonicalServer(server)
		if err != nil {
			return "", err
		}
		project, err := clientstate.CanonicalServer(*configuredServer)
		if err != nil {
			return "", err
		}
		if selected != project {
			return "", nil
		}
	}
	return *configuredTeam, nil
}

func (c projectConfiguration) configuredTeamForService(service string, effective config.TNL) (*string, error) {
	if service == "" || effective.Team == nil || c.Config.Server == nil {
		return effective.Team, nil
	}
	settings := c.Config.Services[service]
	if settings.Team != nil || settings.Server == nil {
		return effective.Team, nil
	}
	projectServer, err := clientstate.CanonicalServer(*c.Config.Server)
	if err != nil {
		return nil, err
	}
	serviceServer, err := clientstate.CanonicalServer(*settings.Server)
	if err != nil {
		return nil, err
	}
	if projectServer != serviceServer {
		return nil, nil
	}
	return effective.Team, nil
}

func applyProjectCommandContext(command string, project projectConfiguration, flags *cli) error {
	var contextErr error
	apply := func(remote *remoteFlags, useTeam bool) {
		if contextErr != nil {
			return
		}
		remote.ServerURL, _, contextErr = resolveProjectServer(remote.ServerURL, project.Config.Server, remote.AccessToken)
		if contextErr == nil && useTeam {
			remote.ProjectTeam, contextErr = projectTeamForServer(remote.ServerURL, project.Config.Server, project.Config.Team)
		}
	}
	switch command {
	case "login":
		if flags.Login.Server == "" {
			flags.Login.ServerURL, _, contextErr = resolveProjectServer(flags.Login.ServerURL, project.Config.Server, "")
		}
	case "logout":
		flags.Logout.ServerURL, _, contextErr = resolveProjectServer(flags.Logout.ServerURL, project.Config.Server, "")
	case "team current":
		apply(&flags.Team.Current.remoteFlags, true)
	case "team list":
		apply(&flags.Team.List.remoteFlags, true)
	case "team use <team>":
		apply(&flags.Team.Use.remoteFlags, true)
	case "team create <name>":
		apply(&flags.Team.Create.remoteFlags, true)
	case "team members":
		apply(&flags.Team.Members.remoteFlags, true)
	case "team invite create":
		apply(&flags.Team.Invite.Create.remoteFlags, true)
	case "team invite list":
		apply(&flags.Team.Invite.List.remoteFlags, true)
	case "team invite revoke <invitation-id>":
		apply(&flags.Team.Invite.Revoke.remoteFlags, true)
	case "team join <secret>":
		apply(&flags.Team.Join.remoteFlags, true)
	case "team member set-role <membership-id>":
		apply(&flags.Team.Member.SetRole.remoteFlags, true)
	case "team member remove <membership-id>":
		apply(&flags.Team.Member.Remove.remoteFlags, true)
	case "domain claim <domain>":
		apply(&flags.Domain.Claim.remoteFlags, true)
	case "domain default <domain>":
		apply(&flags.Domain.Default.remoteFlags, true)
	case "domain list":
		apply(&flags.Domain.List.remoteFlags, true)
	case "domain status <domain>":
		apply(&flags.Domain.Status.remoteFlags, true)
	case "domain release <domain>":
		apply(&flags.Domain.Release.remoteFlags, true)
	case "url list":
		apply(&flags.URL.List.remoteFlags, true)
	case "url delete <public-url-id>":
		apply(&flags.URL.Delete.remoteFlags, true)
	case "admin server status":
		apply(&flags.Admin.Server.Status.remoteFlags, false)
	case "admin relays list":
		apply(&flags.Admin.Relays.List.remoteFlags, false)
	case "admin relays drain <relay-id>":
		apply(&flags.Admin.Relays.Drain.remoteFlags, false)
	case "admin maintenance list":
		apply(&flags.Admin.Maintenance.List.remoteFlags, false)
	case "admin maintenance allow <name>":
		apply(&flags.Admin.Maintenance.Allow.remoteFlags, false)
	case "admin maintenance block <name>":
		apply(&flags.Admin.Maintenance.Block.remoteFlags, false)
	}
	return contextErr
}
