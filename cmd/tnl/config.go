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
	projectconfig "github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/tnlts"
)

type projectConfiguration struct {
	selection           projectconfig.Selection
	tnl                 projectconfig.TNL
	worktree            projectconfig.Worktree
	root                string
	directories         map[string]string
	relativeDirectories map[string]string
	found               bool
}

func selectProjectConfiguration(flags cli) (projectconfig.Selection, string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return projectconfig.Selection{}, "", fmt.Errorf("read working directory: %w", err)
	}
	selection, err := projectconfig.SelectProjectConfig(cwd, flags.ConfigPath, os.Getenv("TNL_CONFIG"), flags.NoConfig)
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
	selection, cwd, err := selectProjectConfiguration(flags)
	if err != nil {
		return projectConfiguration{}, err
	}
	worktree, err := projectconfig.ResolveWorktree(ctx, cwd)
	if err != nil {
		return projectConfiguration{}, fmt.Errorf("resolve project worktree: %w", err)
	}
	worktree = projectconfig.ApplyWorktreeHashSalt(worktree, salt)
	result := projectConfiguration{selection: selection, worktree: worktree, root: worktree.Root}
	if selection.Path == "" {
		return result, nil
	}
	result.found = true
	result.root = filepath.Dir(selection.Path)
	result.worktree, err = projectconfig.ResolveWorktree(ctx, result.root)
	if err != nil {
		return projectConfiguration{}, fmt.Errorf("resolve project worktree: %w", err)
	}
	result.worktree = projectconfig.ApplyWorktreeHashSalt(result.worktree, salt)
	if strings.EqualFold(filepath.Ext(selection.Path), ".ts") {
		result.tnl, err = tnlts.Load(ctx, selection.Path, cwd, result.worktree)
		if err != nil {
			return projectConfiguration{}, err
		}
	} else {
		document, loadErr := projectconfig.LoadDocument(selection.Path)
		if loadErr != nil {
			return projectConfiguration{}, loadErr
		}
		if document.TNL != nil {
			result.tnl = *document.TNL
		}
	}
	if err := result.resolveServiceDirectories(); err != nil {
		return projectConfiguration{}, err
	}
	return result, nil
}

func (c *projectConfiguration) resolveServiceDirectories() error {
	c.directories = make(map[string]string, len(c.tnl.Services))
	c.relativeDirectories = make(map[string]string, len(c.tnl.Services))
	names := make([]string, 0, len(c.tnl.Services))
	for name := range c.tnl.Services {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		directory, relative, err := c.tnl.ServiceDirectory(c.root, name)
		if err != nil {
			return fmt.Errorf("service %q: %w", name, err)
		}
		c.directories[name] = directory
		c.relativeDirectories[name] = relative
	}
	return nil
}

func projectRoot(ctx context.Context, flags cli) (string, error) {
	selection, cwd, err := selectProjectConfiguration(flags)
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
	if _, found := c.tnl.Services[flags.Target]; found && flags.Target != "" {
		service, flags.Target = flags.Target, ""
	} else if flags.Target == "" {
		var err error
		service, err = c.defaultService()
		if err != nil {
			return err
		}
	}
	effective, err := c.tnl.EffectiveService(service)
	if err != nil {
		return err
	}
	flags.Service = service
	flags.projectRoot = c.root
	if flags.ServerURL == "" && effective.Server != nil {
		flags.ServerURL = *effective.Server
		flags.serverFromConfig = true
	}
	if flags.AccessToken != "" && flags.serverFromConfig {
		return errors.New("an explicit access token with a project-provided server requires --server or TNL_SERVER")
	}
	if flags.Team != "" {
		flags.selectedTeam = flags.Team
	} else if effective.Team != nil {
		flags.selectedTeam = *effective.Team
	}
	if flags.Target == "" && effective.Publish != nil && effective.Publish.Target != nil {
		flags.Target = string(*effective.Publish.Target)
	}
	applyTunnelConfiguration(&flags.tunnelFlags, effective.Tunnel)
	applyBuiltInHostname(&flags.tunnelFlags, service, c.worktree)
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
	} else if _, found := c.tnl.Services[service]; !found {
		return fmt.Errorf("service %q is not configured", service)
	}
	effective, err := c.tnl.EffectiveService(service)
	if err != nil {
		return err
	}
	flags.Service = service
	flags.projectRoot = c.root
	flags.project = c
	if flags.ServerURL == "" && effective.Server != nil {
		flags.ServerURL = *effective.Server
		flags.serverFromConfig = true
	}
	if flags.AccessToken != "" && flags.serverFromConfig {
		return errors.New("an explicit access token with a project-provided server requires --server or TNL_SERVER")
	}
	if flags.Team != "" {
		flags.selectedTeam = flags.Team
	} else if effective.Team != nil {
		flags.selectedTeam = *effective.Team
	}
	if service == "" {
		flags.commandDir = c.root
	} else {
		flags.commandDir = c.directories[service]
		if flags.commandDir == "" {
			flags.commandDir = c.root
		}
	}
	if flags.commandDir == "" && c.selection.Path != "" {
		flags.commandDir = filepath.Dir(c.selection.Path)
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
	_, ephemeralFromEnvironment := os.LookupEnv("TNL_EPHEMERAL")
	runtimeServerOverride := flags.ServerURL != "" && !flags.serverFromConfig
	flags.useMetadataHostname = flags.Host == "" && flags.Subdomain == "" && flags.Team == "" &&
		flags.Ephemeral && !runtimeServerOverride && !ephemeralFromEnvironment &&
		effective.Tunnel != nil && effective.Tunnel.Ephemeral != nil && *effective.Tunnel.Ephemeral
	applyBuiltInHostname(&flags.tunnelFlags, service, c.worktree)
	if flags.StartupTimeout == 0 {
		flags.StartupTimeout = defaultDevStartupTimeout
	}
	return validateTunnelFlags(flags.tunnelFlags)
}

func (c projectConfiguration) defaultService() (string, error) {
	if len(c.tnl.Services) == 0 {
		return "", nil
	}
	names := make([]string, 0, len(c.tnl.Services))
	for name := range c.tnl.Services {
		names = append(names, name)
	}
	slices.Sort(names)
	if len(names) == 1 {
		return names[0], nil
	}
	return "", diagnostic.Wrap(
		diagnostic.ServiceAmbiguous,
		fmt.Errorf("service is required; configured services: %s", strings.Join(names, ", ")),
	)
}

func applyBuiltInHostname(flags *tunnelFlags, service string, worktree projectconfig.Worktree) {
	if flags.Host == "" && flags.Subdomain == "" && !flags.Ephemeral {
		flags.Subdomain = projectconfig.ServiceWorktreeLabel(service, worktree.Label)
	}
}

func applyTunnelConfiguration(flags *tunnelFlags, tunnel *projectconfig.Tunnel) {
	if tunnel == nil {
		return
	}
	if flags.Host == "" && flags.Subdomain == "" {
		if tunnel.Host != nil {
			flags.Host = *tunnel.Host
		}
		if tunnel.Subdomain != nil {
			flags.Subdomain = *tunnel.Subdomain
		}
	}
	_, ephemeralFromEnvironment := os.LookupEnv("TNL_EPHEMERAL")
	if tunnel.Ephemeral != nil && !flags.ephemeralFromCLI && !ephemeralFromEnvironment {
		flags.Ephemeral = *tunnel.Ephemeral
	}
	_, publicFromEnvironment := os.LookupEnv("TNL_PUBLIC")
	if !flags.publicFromCLI && flags.AllowIP == nil && !publicFromEnvironment {
		flags.AllowIP = slices.Clone(tunnel.AllowIP)
		if tunnel.Public != nil {
			flags.Public = *tunnel.Public
		}
	}
}

func validateTunnelFlags(flags tunnelFlags) error {
	if flags.Host != "" && flags.Subdomain != "" {
		return errors.New("--host and --subdomain are mutually exclusive")
	}
	if flags.Public && flags.AllowIP != nil {
		return errors.New("--public and --allow-ip are mutually exclusive")
	}
	if len(flags.AllowIP) > 63 {
		return errors.New("--allow-ip may be repeated at most 63 times")
	}
	return nil
}

func runConfigPath(flags cli, stdout io.Writer) error {
	selection, _, err := selectProjectConfiguration(flags)
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
	if !loaded.found {
		return errors.New("no project configuration file found")
	}
	return clioutput.Write(stdout, clioutput.Frame{
		Command: "tnl config check", State: "valid",
		Blocks: []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "path", Value: loaded.selection.Path})},
	})
}

func projectSensitiveCommand(command string) bool {
	return strings.HasPrefix(command, "team ") || strings.HasPrefix(command, "domain ") || strings.HasPrefix(command, "route ")
}

func applyProjectCommandContext(command string, project projectConfiguration, flags *cli) error {
	server, team := "", ""
	if project.tnl.Server != nil {
		server = *project.tnl.Server
	}
	if project.tnl.Team != nil {
		team = *project.tnl.Team
	}
	var contextErr error
	apply := func(remote *remoteFlags, useTeam bool) {
		if remote.ServerURL == "" {
			if server != "" && remote.AccessToken != "" {
				contextErr = errors.New("an explicit access token with a project-provided server requires --server or TNL_SERVER")
			}
			remote.ServerURL = server
		}
		if useTeam {
			remote.ProjectTeam = team
		}
	}
	switch command {
	case "team current":
		apply(&flags.Team.Current.remoteFlags, true)
	case "team list":
		apply(&flags.Team.List.remoteFlags, false)
	case "team use <team>":
		apply(&flags.Team.Use.remoteFlags, false)
	case "team create <display-name>":
		apply(&flags.Team.Create.remoteFlags, false)
	case "team members":
		apply(&flags.Team.Members.remoteFlags, true)
	case "team invite create":
		apply(&flags.Team.Invite.Create.remoteFlags, true)
	case "team invite list":
		apply(&flags.Team.Invite.List.remoteFlags, true)
	case "team invite revoke <invitation-id>":
		apply(&flags.Team.Invite.Revoke.remoteFlags, true)
	case "team join <secret>":
		apply(&flags.Team.Join.remoteFlags, false)
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
	case "domain release <domain>":
		apply(&flags.Domain.Release.remoteFlags, true)
	case "route list":
		apply(&flags.Route.List.remoteFlags, true)
	case "route delete <route-id>":
		apply(&flags.Route.Delete.remoteFlags, true)
	}
	return contextErr
}
