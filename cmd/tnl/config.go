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
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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
	flags.namedOverrides = flags.Anonymous || len(flags.IP) != 0 || flags.PublicURL != "" || flags.Name != "" || flags.Domain != "" || flags.Ephemeral ||
		flags.TargetTLS != nil || flags.TargetTLSName != "" || flags.TargetCAFile != "" || flags.Requests != nil || flags.Concurrency != nil || flags.RateRequests != nil || flags.RatePer != "" || flags.RateBurst != nil || flags.inspectionModeFromCLI
	service := ""
	enrolled := flags.EnrollmentKey != "" || flags.PublisherID != "" || flags.PublisherFile != ""
	if _, found := c.Config.Services[flags.Target]; found && flags.Target != "" {
		service, flags.Target = flags.Target, ""
	} else if flags.Target == "" && !enrolled {
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
	if service != "" && config.PublisherName(c.Config.Services[service]) != "local" {
		return publisherCLIError("this service belongs to a remote publisher group; run tnl apply and tnl publisher serve --group NAME")
	}
	flags.project = c
	flags.projectRoot = c.Root
	credential := flags.AccessToken
	if enrolled && credential == "" {
		credential = "publisher selection"
	}
	flags.ServerURL, flags.serverFromConfig, err = resolveProjectServer(flags.ServerURL, effective.Server, credential)
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
	local := config.ServicePublish(c.Config.Services[service])
	if usingConfiguredTarget {
		if err := validateConfiguredTargetTrust(*flags, local); err != nil {
			return err
		}
	}
	if flags.TargetTLS != nil && !*flags.TargetTLS && (local.TargetTLS != nil && *local.TargetTLS || flags.TargetTLSName != "" || flags.TargetCAFile != "") {
		return publisherCLIError("target TLS cannot be disabled while target trust is configured")
	}
	if usingConfiguredTarget && flags.TargetTLS == nil {
		flags.TargetTLS = local.TargetTLS
	}
	private := service != "" && !config.IsPublicService(c.Config.Services[service])
	flags.privateService = private
	if private && (flags.Anonymous || len(flags.IP) != 0 || flags.PublicURL != "" || flags.Ephemeral || flags.Open) {
		return publisherCLIError("this configured service is private; add an explicit publicURL block to enable public HTTPS")
	}
	if private && flags.Protocol != "" && flags.Protocol != config.Protocol(c.Config.Services[service]) {
		return publisherCLIError("--protocol differs from the configured private service")
	}
	if service != "" && flags.Protocol != "" && flags.Protocol != config.Protocol(c.Config.Services[service]) {
		return publisherCLIError("--protocol differs from the configured service")
	}
	if flags.Protocol == "" && service != "" {
		flags.Protocol = config.Protocol(c.Config.Services[service])
	}
	if usingConfiguredTarget && local.Target != nil {
		flags.Target = string(*local.Target)
	}
	if usingConfiguredTarget && flags.TargetCAFile == "" && local.TargetCAFile != nil {
		flags.TargetCAFile = *local.TargetCAFile
	}
	if usingConfiguredTarget && flags.TargetTLSName == "" && local.TargetTLSName != nil {
		flags.TargetTLSName = *local.TargetTLSName
	}
	if !enrolled {
		if !private && !config.PrivateProtocol(flags.Protocol) {
			applyTunnelConfiguration(&flags.tunnelFlags, effective.Tunnel)
		}
	} else if service != "" && config.IsPublicService(c.Config.Services[service]) && effective.Tunnel != nil {
		applyTunnelLimits(&flags.tunnelFlags, effective.Tunnel.Limits)
	}
	applyInspection(&flags.tunnelFlags, effective)
	if !private && !config.PrivateProtocol(flags.Protocol) {
		applyOpenConfiguration(&flags.openOptions, effective.Tunnel)
	}
	if !private && !enrolled && !config.PrivateProtocol(flags.Protocol) {
		applyBuiltInHostname(&flags.tunnelFlags, service, c.Worktree)
	}
	if flags.Target == "" && service == "" && !enrolled {
		return failure.Wrap("select target", failure.MissingTarget,
			errors.New("pass a target or select a configured service"))
	}
	if enrolled && flags.Protocol == "" {
		// the enrolled URL selects the protocol before its limits are applied.
		return nil
	}
	protocol, err := publishProtocol(flags.Protocol)
	if err != nil {
		return err
	}
	if err := applyProtocolLimits(&flags.tunnelFlags, string(protocol)); err != nil {
		return failure.Wrap("resolve application limits", failure.InvalidTunnelFlags, err)
	}
	if err := selectPublishInspection(flags, protocol); err != nil {
		return err
	}
	return nil
}

// applyInstalledService snapshots only local target settings. installed jobs
// reuse their saved URL policy and never create a URL from project settings.
func (c projectConfiguration) applyInstalledService(flags *publishCommand) error {
	service := flags.Target
	definition, found := c.Config.Services[service]
	if !found || service == "" {
		return nil
	}
	effective, err := c.EffectiveService(service)
	if err != nil {
		return err
	}
	if flags.ServiceName != "" && flags.ServiceName != service {
		return publisherCLIError("--service-name must match the configured service; use its name with tnl service start, stop, and remove")
	}
	flags.Service, flags.project, flags.projectRoot = service, c, c.Root
	if !flags.inspectionModeFromCLI {
		flags.InspectionMode = config.InspectionNone
	}
	if config.PublisherName(definition) != "local" {
		return publisherCLIError("install the assigned publisher group with tnl publisher serve --group NAME --install")
	}
	flags.privateService = !config.IsPublicService(definition)
	flags.ServiceName = service
	flags.Target = ""
	selected, _, err := resolveProjectServer(flags.ServerURL, effective.Server, "")
	if err != nil {
		return err
	}
	flags.ServerURL = selected
	local := config.ServicePublish(definition)
	if err := validateConfiguredTargetTrust(*flags, local); err != nil {
		return err
	}
	if flags.TargetTLS != nil && !*flags.TargetTLS && (local.TargetTLS != nil && *local.TargetTLS || flags.TargetTLSName != "" || flags.TargetCAFile != "") {
		return publisherCLIError("target TLS cannot be disabled while target trust is configured")
	}
	if flags.TargetTLS == nil {
		flags.TargetTLS = local.TargetTLS
	}
	if flags.Protocol == "" {
		flags.Protocol = config.Protocol(definition)
	}
	if local.Target != nil {
		flags.Target = string(*local.Target)
	}
	if flags.TargetCAFile == "" && local.TargetCAFile != nil {
		flags.TargetCAFile = *local.TargetCAFile
	}
	if flags.TargetTLSName == "" && local.TargetTLSName != nil {
		flags.TargetTLSName = *local.TargetTLSName
	}
	if flags.privateService || config.PrivateProtocol(flags.Protocol) {
		if config.TargetType(definition) == "app" {
			return failure.Wrap("select installed target", failure.InstalledTargetMissing, errors.New("private service requires an address, Docker, or Compose target"))
		}
		return nil
	}
	if flags.Target == "" {
		return failure.Wrap("select installed target", failure.InstalledTargetMissing, errors.New("configured service has no stable target"))
	}
	if flags.TargetCAFile == "" && local.TargetCAFile != nil {
		flags.TargetCAFile = *local.TargetCAFile
	}
	if flags.TargetTLSName == "" && local.TargetTLSName != nil {
		flags.TargetTLSName = *local.TargetTLSName
	}
	if effective.Tunnel != nil {
		applyTunnelLimits(&flags.tunnelFlags, effective.Tunnel.Limits)
		if effective.Tunnel.Ephemeral != nil && *effective.Tunnel.Ephemeral {
			return publisherCLIError("installed publications require a saved public URL")
		}
	}
	if err := applyProtocolLimits(&flags.tunnelFlags, flags.Protocol); err != nil {
		return err
	}
	flags.Target, err = normalizePublishTarget(flags.Target, controlv1.PublicURLServiceProtocol(flags.Protocol))
	return err
}

func validateConfiguredTargetTrust(flags publishCommand, local *config.Publish) error {
	if local.TargetTLS == nil {
		if flags.TargetTLS != nil && *flags.TargetTLS || flags.TargetTLSName != "" || flags.TargetCAFile != "" {
			return publisherCLIError("configure the named service's target trust under target.tls")
		}
		return nil
	}
	if flags.TargetTLS != nil && !*flags.TargetTLS || flags.TargetTLSName != "" && (local.TargetTLSName == nil || flags.TargetTLSName != *local.TargetTLSName) || flags.TargetCAFile != "" && (local.TargetCAFile == nil || flags.TargetCAFile != *local.TargetCAFile) {
		return publisherCLIError("target TLS flags differ from the configured target.tls")
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

func applyTunnelConfiguration(flags *tunnelFlags, tunnel *config.Tunnel) {
	if tunnel == nil {
		return
	}
	applyTunnelLimits(flags, tunnel.Limits)
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
	if tunnel.Access != nil {
		flags.access = tunnel.Access
	}
	_, ephemeralFromEnvironment := os.LookupEnv("TNL_EPHEMERAL")
	if tunnel.Ephemeral != nil && !flags.ephemeralFromCLI && !ephemeralFromEnvironment {
		flags.Ephemeral = *tunnel.Ephemeral
	}
}

func applyTunnelLimits(flags *tunnelFlags, limits *config.Limits) {
	flags.workLimits = limits
}

func applyProtocolLimits(flags *tunnelFlags, protocol string) error {
	resolved, err := config.ResolveWorkLimits(flags.workLimits, protocol)
	if err != nil {
		return err
	}
	if flags.Requests == nil && resolved.Requests != 0 {
		flags.Requests = &resolved.Requests
	}
	if flags.Concurrency == nil && resolved.Concurrency != 0 {
		flags.Concurrency = &resolved.Concurrency
	}
	if flags.RateRequests == nil && resolved.RateRequests != 0 {
		flags.RateRequests = &resolved.RateRequests
	}
	if flags.RatePer == "" && resolved.RatePer != 0 {
		flags.RatePer = resolved.RatePer.String()
	}
	if flags.RateBurst == nil && resolved.RateBurst != 0 {
		flags.RateBurst = &resolved.RateBurst
	}
	return validateTunnelFlags(*flags)
}

func applyInspection(flags *tunnelFlags, effective config.TNL) {
	flags.inspection = effective.Inspection
	if effective.Inspection != nil {
		if !flags.inspectionModeFromCLI && effective.Inspection.Mode != nil {
			flags.InspectionMode = *effective.Inspection.Mode
			flags.inspectionModeFromConfig = true
		}
	}
	if flags.InspectionMode == "" {
		flags.InspectionMode = config.InspectionSummary
	}
}

func validateTunnelFlags(flags tunnelFlags) error {
	if !flags.InspectionMode.Valid() {
		return errors.New("--inspection-mode must be none or summary")
	}
	if flags.Requests != nil && (*flags.Requests <= 0 || *flags.Requests > config.MaxConfigInteger) || flags.Concurrency != nil && (*flags.Concurrency <= 0 || *flags.Concurrency > config.MaxConfigInteger) {
		return errors.New("--requests and --concurrency must be positive safe integers")
	}
	if (flags.RateRequests == nil) != (flags.RatePer == "") {
		return errors.New("--rate-requests and --rate-per must be supplied together")
	}
	if flags.RateRequests != nil {
		period, err := time.ParseDuration(flags.RatePer)
		if *flags.RateRequests <= 0 || *flags.RateRequests > config.MaxConfigInteger || err != nil || period <= 0 {
			return errors.New("--rate-requests and --rate-per must be positive")
		}
	}
	if flags.RateBurst != nil && (*flags.RateBurst <= 0 || *flags.RateBurst > config.MaxConfigInteger || flags.RateRequests == nil) {
		return errors.New("--rate-burst must be positive and requires a rate limit")
	}
	if flags.PublicURL != "" && flags.Name != "" {
		return errors.New("--public-url and --name are mutually exclusive")
	}
	if flags.Ephemeral && (flags.PublicURL != "" || flags.Name != "") {
		return errors.New("temporary publication chooses its own public URL; omit --name and --public-url")
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
	return command == "apply" || command == "audit list" || strings.HasPrefix(command, "auth ") || strings.HasPrefix(command, "admin ") ||
		command == "connect available" ||
		strings.HasPrefix(command, "publisher ") ||
		strings.HasPrefix(command, "team ") || strings.HasPrefix(command, "domain ") || strings.HasPrefix(command, "url ") || strings.HasPrefix(command, "share ") || strings.HasPrefix(command, "feedback ") || strings.HasPrefix(command, "webhook ") || strings.HasPrefix(command, "alias ")
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
	case "audit list":
		apply(&flags.Audit.List.remoteFlags, true)
	case "connect available":
		apply(&flags.Connect.Available.remoteFlags, false)
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
		flags.Auth.Login.ServerURL, _, contextErr = resolveProjectServer(flags.Auth.Login.ServerURL, project.Config.Server, "")
		if flags.Auth.Login.Team == "" && project.Config.Team != nil {
			flags.Auth.Login.Team = *project.Config.Team
		}
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
	case "url access show <url>":
		apply(&flags.URL.Access.Show.remoteFlags, true)
	case "url access set <url> <mode>":
		apply(&flags.URL.Access.Set.remoteFlags, true)
	case "url update <public-url-id>":
		apply(&flags.URL.Update.remoteFlags, true)
	case "url delete <public-url-id>":
		apply(&flags.URL.Delete.remoteFlags, true)
	case "url inventory":
		apply(&flags.URL.Inventory.remoteFlags, true)
	case "url available":
		apply(&flags.URL.Available.remoteFlags, false)
	case "publisher enroll", "publisher enroll <public-url-id>":
		apply(&flags.Publisher.Enroll.remoteFlags, true)
	case "publisher provision":
		apply(&flags.Publisher.Provision.remoteFlags, true)
	case "publisher list":
		apply(&flags.Publisher.List.remoteFlags, true)
	case "publisher revoke <publisher-id>":
		apply(&flags.Publisher.Revoke.remoteFlags, true)
	case "publisher grant add <publisher-id>":
		apply(&flags.Publisher.Grant.Add.remoteFlags, true)
	case "publisher grant revoke <publisher-id> <grant-id>":
		apply(&flags.Publisher.Grant.Revoke.remoteFlags, true)
	case "auth browser <url>":
		apply(&flags.Auth.Browser.remoteFlags, false)
	case "team feedback get":
		apply(&flags.Team.Feedback.Get.remoteFlags, true)
	case "team feedback set <authors>":
		apply(&flags.Team.Feedback.Set.remoteFlags, true)
	case "share invite create <url>":
		apply(&flags.Share.Invite.Create.remoteFlags, false)
	case "share invite accept <secret>":
		apply(&flags.Share.Invite.Accept.remoteFlags, false)
	case "share invite list <url>":
		apply(&flags.Share.Invite.List.remoteFlags, false)
	case "share invite revoke <url> <invitation-id>":
		apply(&flags.Share.Invite.Revoke.remoteFlags, false)
	case "share link create <url>":
		apply(&flags.Share.Link.Create.remoteFlags, true)
	case "share token create <url>":
		apply(&flags.Share.Token.Create.remoteFlags, true)
	case "share list <url>":
		apply(&flags.Share.List.remoteFlags, true)
	case "share revoke <share-id>":
		apply(&flags.Share.Revoke.remoteFlags, true)
	case "share team create <url>":
		apply(&flags.Share.Team.Create.remoteFlags, true)
	case "share team revoke", "share team revoke <url>":
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
