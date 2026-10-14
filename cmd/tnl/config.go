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
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
)

type projectConfiguration struct {
	projectconfig.Project
}

func selectProjectConfiguration(ctx context.Context, flags cli) (projectconfig.Selection, string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return projectconfig.Selection{}, "", failure.Wrap("read working directory", failure.CurrentDirectoryUnavailable, err)
	}
	selection, err := projectconfig.SelectProjectConfig(ctx, cwd, flags.ConfigPath, os.Getenv("TNL_CONFIG"), flags.NoConfig)
	return selection, cwd, failure.Wrap("select project configuration", failure.ProjectConfigInvalid, err)
}

func loadProjectConfiguration(ctx context.Context, flags cli, stateRoot string) (projectConfiguration, error) {
	state, err := clientstate.Open(ctx, stateRoot)
	if err != nil {
		return projectConfiguration{}, failure.Wrap("open client state", failure.ClientStateUnavailable, err)
	}
	salt, err := state.WorktreeHashSalt(ctx)
	closeErr := state.Close()
	if err != nil {
		return projectConfiguration{}, failure.Wrap("read worktree identity", failure.ClientStateUnavailable, err)
	}
	if closeErr != nil {
		return projectConfiguration{}, failure.Wrap("close client state", failure.ClientStateUnavailable, closeErr)
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
		return projectConfiguration{}, failure.Wrap("load project configuration", failure.ProjectConfigInvalid, err)
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
	} else if flags.Target == "" && flags.EnrollKey == "" {
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
	flags.project = c
	flags.projectRoot = c.Root
	flags.ServerURL, flags.serverFromConfig, err = resolveProjectServer(flags.ServerURL, effective.Server, flags.AccessToken)
	if err != nil {
		return err
	}
	if flags.Team != "" {
		flags.selectedTeam = flags.Team
	} else {
		flags.selectedTeam, err = projectTeamForServer(flags.ServerURL, effective.Server, effective.Team)
		if err != nil {
			return err
		}
	}
	usingConfiguredTarget := flags.Target == ""
	if flags.Protocol == "" && effective.Publish != nil && effective.Publish.Protocol != nil {
		flags.Protocol = *effective.Publish.Protocol
	}
	if usingConfiguredTarget && effective.Publish != nil && effective.Publish.Target != nil {
		flags.Target = string(*effective.Publish.Target)
	}
	if usingConfiguredTarget && service != "" {
		if selected := c.Config.Services[service].Target; selected != nil && selected.Type == "docker" {
			flags.dockerTarget = &dockerPublishTarget{selection: selected.DockerSelection, projectLabel: c.Worktree.Label.FullLabel}
		}
	}
	if usingConfiguredTarget && flags.TargetCAFile == "" && effective.Publish != nil && effective.Publish.TargetCAFile != nil {
		flags.TargetCAFile = *effective.Publish.TargetCAFile
	}
	if usingConfiguredTarget && flags.TargetTLSName == "" && effective.Publish != nil && effective.Publish.TargetTLSName != nil {
		flags.TargetTLSName = *effective.Publish.TargetTLSName
	}
	if usingConfiguredTarget && !flags.TargetTLS && effective.Publish != nil && effective.Publish.TargetTLS != nil {
		flags.TargetTLS = *effective.Publish.TargetTLS
	}
	if flags.EnrollKey == "" {
		applyTunnelConfiguration(&flags.tunnelFlags, effective.Tunnel, flags.Protocol)
	} else if effective.Tunnel != nil && flags.Protocol != "" {
		// a saved URL supplies hostname and visitor policy; local admission is still configurable.
		applyTunnelLimits(&flags.tunnelFlags, effective.Tunnel.Limits, flags.Protocol)
	}
	applyInspection(&flags.tunnelFlags, effective)
	if service != "" && c.Config.Services[service].TCP != nil && c.Config.Services[service].TCP.VisitorTLS != nil && !flags.visitorTLSFromCLI {
		flags.VisitorTLSPassthrough = *c.Config.Services[service].TCP.VisitorTLS == "passthrough"
	}
	applyOpenConfiguration(&flags.openOptions, effective.Tunnel)
	if flags.EnrollKey == "" {
		applyBuiltInHostname(&flags.tunnelFlags, service, c.Worktree)
	}
	if flags.Target == "" && flags.EnrollKey == "" && flags.dockerTarget == nil {
		if service != "" {
			if selected := c.Config.Services[service].Target; selected != nil && selected.Type == "app" {
				return failure.Wrap("select app service", failure.MissingTarget,
					fmt.Errorf("service %q expects an app registration; start the app normally instead of running tnl publish", service))
			}
			return failure.Wrap("select target for service", failure.MissingTarget,
				fmt.Errorf("target is required for service %q through publish.target", service))
		}
		return failure.Wrap("select target", failure.MissingTarget,
			errors.New("target is required as an argument or publish.target in project configuration"))
	}
	if flags.EnrollKey == "" || flags.Protocol != "" {
		if err := validateTunnelFlags(flags.tunnelFlags); err != nil {
			return failure.Wrap("validate tunnel options", failure.InvalidTunnelFlags, err)
		}
	}
	return nil
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

func applyTunnelConfiguration(flags *tunnelFlags, tunnel *config.Tunnel, protocol ...string) {
	settings := flags.settings()
	localpublisher.ApplyTunnel(&settings, tunnel, protocol...)
	flags.applySettings(settings)
}

func applyTunnelLimits(flags *tunnelFlags, limits *config.Limits, protocol ...string) {
	settings := flags.settings()
	localpublisher.ApplyLimits(&settings, limits, protocol...)
	flags.applySettings(settings)
}

func applyInspection(flags *tunnelFlags, effective config.TNL) {
	settings := flags.settings()
	localpublisher.ApplyInspection(&settings, effective)
	flags.applySettings(settings)
}

func validateTunnelFlags(flags tunnelFlags) error {
	for _, selected := range []*int{flags.TrafficConnections, flags.TrafficRateCount, flags.TrafficRateBurst} {
		if selected != nil && *selected <= 0 {
			return errors.New("traffic connection limits must be positive")
		}
	}
	if flags.TrafficRatePer != "" {
		period, err := time.ParseDuration(flags.TrafficRatePer)
		if err != nil || period < time.Millisecond || period > 24*time.Hour {
			return errors.New("--traffic-rate-per must be between 1ms and 24h")
		}
	}
	for _, value := range []string{flags.TrafficUpload, flags.TrafficDownload} {
		if value != "" {
			if _, err := trafficlimits.ParseByteRate(value); err != nil {
				return fmt.Errorf("invalid visitor bandwidth: %w", err)
			}
		}
	}
	if !flags.InspectionMode.Valid() {
		return errors.New("--inspection-mode must be summary or detailed")
	}
	if flags.inspectionRetentionFromCLI && flags.InspectionRetention == 0 ||
		flags.InspectionRetention < 0 || flags.InspectionRetention > inspection.MaxRetention ||
		flags.InspectionRetention != 0 && flags.InspectionRetention < time.Minute {
		return errors.New("--inspection-retention must be between 1m and 720h")
	}
	if flags.inspectionMaxBytesFromCLI && flags.InspectionMaxBytes == "" {
		return errors.New("--inspection-max-bytes requires a byte size")
	}
	if flags.InspectionMaxBytes != "" {
		if _, err := config.ParseByteSize(flags.InspectionMaxBytes); err != nil {
			return fmt.Errorf("--inspection-max-bytes: %w", err)
		}
	}
	if flags.Requests != nil && *flags.Requests <= 0 || flags.Concurrency != nil && *flags.Concurrency <= 0 {
		return errors.New("--total and --concurrency must be greater than zero")
	}
	if (flags.RateRequests == nil) != (flags.RatePer == "") {
		return errors.New("--rate-count and --rate-per must be supplied together")
	}
	if flags.RateRequests != nil {
		period, err := time.ParseDuration(flags.RatePer)
		if *flags.RateRequests <= 0 || err != nil || period <= 0 {
			return errors.New("--rate-count and --rate-per must be positive")
		}
	}
	if flags.RateBurst != nil && (*flags.RateBurst <= 0 || flags.RateRequests == nil) {
		return errors.New("--rate-burst requires a positive rate")
	}
	if flags.PublicURL != "" && flags.Name != "" {
		return errors.New("--public-url and --name are mutually exclusive")
	}
	if flags.AllowAllIPs && flags.AllowIP != nil {
		return errors.New("--allow-all-ips cannot be combined with --allow-ip")
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
		return failure.Wrap("check project configuration", failure.ProjectConfigMissing, errors.New("no project configuration file found"))
	}
	return clioutput.Write(stdout, clioutput.Frame{
		Command: "tnl config check", State: "valid",
		Blocks: []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "path", Value: loaded.Selection.Path})},
	})
}

func projectSensitiveCommand(command string) bool {
	if strings.HasPrefix(command, "publisher service ") || strings.HasPrefix(command, "publisher stop ") {
		return false
	}
	return strings.HasPrefix(command, "auth ") || strings.HasPrefix(command, "limits ") || strings.HasPrefix(command, "admin ") ||
		strings.HasPrefix(command, "team ") || strings.HasPrefix(command, "domain ") || strings.HasPrefix(command, "url ") || strings.HasPrefix(command, "publisher ") || strings.HasPrefix(command, "share ") || strings.HasPrefix(command, "feedback ") || strings.HasPrefix(command, "webhook ") || strings.HasPrefix(command, "alias ")
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
	case "limits show <service>":
		apply(&flags.Limits.Show.remoteFlags, false)
	case "webhook use <endpoint>":
		apply(&flags.Webhook.Use.remoteFlags, false)
	case "webhook release <endpoint>":
		apply(&flags.Webhook.Release.remoteFlags, false)
	case "alias use <name>":
		apply(&flags.Alias.Use.remoteFlags, true)
	case "alias release <name>":
		apply(&flags.Alias.Release.remoteFlags, true)
	case "auth status":
		apply(&flags.Auth.Status.remoteFlags, false)
	case "auth login", "auth login run", "auth login start":
		flags.Auth.Login.ServerURL, _, contextErr = resolveProjectServer(flags.Auth.Login.ServerURL, project.Config.Server, os.Getenv("TNL_LOGIN_TOKEN"))
	case "auth login wait <operation-id>", "auth login inspect <operation-id>", "auth login cancel <operation-id>":
		flags.Auth.Login.ServerURL, _, contextErr = resolveProjectServer(flags.Auth.Login.ServerURL, project.Config.Server, "")
	case "auth logout":
		flags.Auth.Logout.ServerURL, _, contextErr = resolveProjectServer(flags.Auth.Logout.ServerURL, project.Config.Server, "")
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
	case "team feedback show":
		apply(&flags.Team.Feedback.Show.remoteFlags, true)
	case "team feedback set":
		apply(&flags.Team.Feedback.Set.remoteFlags, true)
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
	case "url show <service-or-public-url-id>":
		apply(&flags.URL.Show.remoteFlags, true)
	case "url update <public-url-id>":
		apply(&flags.URL.Update.remoteFlags, true)
	case "url delete <public-url-id>":
		apply(&flags.URL.Delete.remoteFlags, true)
	case "url ip set <public-url-id>":
		apply(&flags.URL.IP.Set.remoteFlags, true)
	case "url ip add <public-url-id> <ip>":
		apply(&flags.URL.IP.Add.remoteFlags, true)
	case "url ip list <public-url-id>":
		apply(&flags.URL.IP.List.remoteFlags, true)
	case "url ip remove <public-url-id> <entry-id>":
		apply(&flags.URL.IP.Remove.remoteFlags, true)
	case "publisher enroll <service-or-public-url-id>":
		apply(&flags.Publisher.Enroll.remoteFlags, true)
	case "publisher list":
		apply(&flags.Publisher.List.remoteFlags, true)
	case "publisher revoke <publisher-id>":
		apply(&flags.Publisher.Revoke.remoteFlags, true)
	case "publisher grant add <publisher-id> <public-url-id>":
		apply(&flags.Publisher.Grant.Add.remoteFlags, true)
	case "publisher grant revoke <publisher-id> <grant-id>":
		apply(&flags.Publisher.Grant.Revoke.remoteFlags, true)
	case "share link create <url>":
		apply(&flags.Share.Link.Create.remoteFlags, true)
	case "share list <url>":
		apply(&flags.Share.List.remoteFlags, true)
	case "share link revoke <share-id>":
		apply(&flags.Share.Link.Revoke.remoteFlags, true)
	case "share team create <url>":
		apply(&flags.Share.Team.Create.remoteFlags, true)
	case "share team revoke":
		apply(&flags.Share.Team.Revoke.remoteFlags, true)
	case "feedback list":
		apply(&flags.Feedback.List.remoteFlags, true)
	case "feedback inspect <feedback-id>":
		apply(&flags.Feedback.Inspect.remoteFlags, true)
	case "feedback watch":
		apply(&flags.Feedback.Watch.remoteFlags, true)
	case "feedback reply <feedback-id>":
		apply(&flags.Feedback.Reply.remoteFlags, true)
	case "feedback update <feedback-id>":
		apply(&flags.Feedback.Update.remoteFlags, true)
	case "feedback resolve <feedback-id>":
		apply(&flags.Feedback.Resolve.remoteFlags, true)
	case "feedback reopen <feedback-id>":
		apply(&flags.Feedback.Reopen.remoteFlags, true)
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
