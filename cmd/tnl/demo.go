package main

import "errors"

func prepareDemoPublish(flags *publishCommand, configPath string, interactive bool) error {
	if flags.Target != "" {
		return errors.New("--demo does not take a service or target")
	}
	if configPath != "" {
		return errors.New("--demo does not use project configuration; remove --config")
	}
	if flags.demoNameFromCLI || flags.PublicURL != "" {
		return errors.New("--demo chooses its own public URL; remove --name or --public-url")
	}
	if flags.ephemeralFromCLI && !flags.Ephemeral {
		return errors.New("--demo requires an ephemeral public URL; remove --ephemeral=false")
	}
	// ignore project hostname environment defaults for a fresh demo URL.
	flags.Name = ""
	flags.Ephemeral = true
	flags.selectedTeam = flags.Team
	if !flags.openFromCLI && interactive && flags.Output == publishOutputHuman {
		flags.Open = true
	}
	return validateTunnelFlags(flags.tunnelFlags)
}
