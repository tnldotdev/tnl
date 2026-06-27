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

	"github.com/tnldotdev/tnl/internal/clioutput"
	projectconfig "github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/tnlts"
)

type projectConfiguration struct {
	selection projectconfig.Selection
	tnl       projectconfig.TNL
	found     bool
}

func selectProjectConfiguration(flags cli) (projectconfig.Selection, string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return projectconfig.Selection{}, "", fmt.Errorf("read working directory: %w", err)
	}
	selection, err := projectconfig.SelectProjectConfig(cwd, flags.ConfigPath, os.Getenv("TNL_CONFIG"), flags.NoConfig)
	return selection, cwd, err
}

func loadProjectConfiguration(ctx context.Context, flags cli) (projectConfiguration, error) {
	selection, cwd, err := selectProjectConfiguration(flags)
	if err != nil {
		return projectConfiguration{}, err
	}
	if selection.Path == "" {
		return projectConfiguration{}, nil
	}
	result := projectConfiguration{selection: selection, found: true}
	if strings.EqualFold(filepath.Ext(selection.Path), ".ts") {
		result.tnl, err = tnlts.Load(ctx, selection.Path, cwd)
		if err != nil {
			return projectConfiguration{}, err
		}
		return result, nil
	}
	document, err := projectconfig.LoadDocument(selection.Path)
	if err != nil {
		return projectConfiguration{}, err
	}
	if document.TNL != nil {
		result.tnl = *document.TNL
	}
	return result, nil
}

func (c projectConfiguration) applyPublish(flags *publishCommand) error {
	if c.found {
		if flags.ServerURL == "" && c.tnl.Server != nil {
			flags.ServerURL = *c.tnl.Server
			flags.serverFromConfig = true
		}
		if flags.AccessToken != "" && flags.serverFromConfig {
			return errors.New("an explicit access token with a project-provided server requires --server or TNL_SERVER")
		}
		if flags.Target == "" && c.tnl.Publish != nil && c.tnl.Publish.Target != nil {
			flags.Target = string(*c.tnl.Publish.Target)
		}
		applyTunnelConfiguration(&flags.tunnelFlags, c.tnl.Tunnel)
	}
	if flags.Target == "" {
		return errors.New("local target is required as an argument or publish.target in project configuration")
	}
	return validateTunnelFlags(flags.tunnelFlags)
}

func (c projectConfiguration) applyDev(flags *devCommand) error {
	if c.found {
		if flags.ServerURL == "" && c.tnl.Server != nil {
			flags.ServerURL = *c.tnl.Server
			flags.serverFromConfig = true
		}
		if flags.AccessToken != "" && flags.serverFromConfig {
			return errors.New("an explicit access token with a project-provided server requires --server or TNL_SERVER")
		}
		if len(flags.Command) == 0 && c.tnl.Dev != nil && c.tnl.Dev.Command != nil {
			flags.Command = slices.Clone(c.tnl.Dev.Command)
			flags.commandDir = filepath.Dir(c.selection.Path)
		}
		if flags.Port == 0 && c.tnl.Dev != nil && c.tnl.Dev.Port != nil {
			flags.Port = *c.tnl.Dev.Port
		}
		if flags.StartupTimeout == 0 && c.tnl.Dev != nil && c.tnl.Dev.StartupTimeout != nil {
			flags.StartupTimeout = c.tnl.Dev.StartupTimeout.Value()
		}
		applyTunnelConfiguration(&flags.tunnelFlags, c.tnl.Tunnel)
	}
	if flags.StartupTimeout == 0 {
		flags.StartupTimeout = defaultDevStartupTimeout
	}
	return validateTunnelFlags(flags.tunnelFlags)
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
	if flags.Public || flags.AllowIP != nil {
		return
	}
	flags.AllowIP = slices.Clone(tunnel.AllowIP)
	if tunnel.Public != nil {
		flags.Public = *tunnel.Public
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

func runConfigCheck(ctx context.Context, flags cli, stdout io.Writer) error {
	loaded, err := loadProjectConfiguration(ctx, flags)
	if err != nil {
		return err
	}
	if !loaded.found {
		return errors.New("no project configuration file found")
	}
	return clioutput.Write(stdout, clioutput.Frame{
		Command: "tnl config check", State: "valid",
		Blocks: []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "path", Value: loaded.selection.Path})},
	})
}
