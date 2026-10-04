package main

import (
	"errors"

	"github.com/tnldotdev/tnl/internal/failure"
)

func prepareDemoPublish(flags *publishCommand, configPath string, interactive bool) error {
	if flags.Target != "" {
		return failure.Wrap("validate demo target", failure.DemoTargetNotAllowed,
			errors.New("--demo does not take a service or target"))
	}
	if configPath != "" {
		return failure.Wrap("validate demo configuration", failure.DemoConfigNotUsed,
			errors.New("--demo does not use project configuration"))
	}
	if flags.demoNameFromCLI || flags.PublicURL != "" {
		return failure.Wrap("validate demo public URL", failure.DemoURLManaged,
			errors.New("--demo chooses its own public URL"))
	}
	if flags.ephemeralFromCLI && !flags.Ephemeral {
		return failure.Wrap("validate demo public URL lifetime", failure.DemoMustBeEphemeral,
			errors.New("--demo requires an ephemeral public URL"))
	}
	// ignore project hostname environment defaults for a fresh demo URL.
	flags.Name = ""
	flags.Ephemeral = true
	flags.selectedTeam = flags.Team
	if !flags.openFromCLI && interactive && flags.Output == publishOutputHuman {
		flags.Open = true
	}
	if err := validateTunnelFlags(flags.tunnelFlags); err != nil {
		return failure.Wrap("validate demo options", failure.InvalidTunnelFlags, err)
	}
	return nil
}
