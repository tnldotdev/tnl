package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/internal/publisher"
)

const (
	devProtocolVersion       = "1"
	devShutdownWait          = 5 * time.Second
	maxDevRuntimeBytes       = 64 << 10
	defaultDevStartupTimeout = 2 * time.Minute
)

var errDevLockHeld = errors.New("another tnl dev is already running for this project service")

type devCommand struct {
	openOptions    `embed:""`
	remoteFlags    `embed:""`
	tunnelFlags    `embed:""`
	Service        string        `arg:"" name:"service" optional:"" help:"Configured service name."`
	Command        []string      `kong:"-"`
	Port           int           `name:"port" help:"Port for the local service. Usually detected automatically."`
	StartupTimeout time.Duration `name:"startup-timeout" help:"Time to wait for the local service to start and report its target."`

	commandDir            string
	serverFromConfig      bool
	selectedTeam          string
	projectRoot           string
	project               projectConfiguration
	useMetadataHostname   bool
	portFromCLI           bool
	startupTimeoutFromCLI bool
	metadataWriter        *devMetadataWriter
	coordinated           bool
	groupTargets          *devGroupTargets
}

type childExitError struct {
	code int
}

func (e *childExitError) Error() string { return fmt.Sprintf("command exited with status %d", e.code) }

func runDev(ctx context.Context, flags devCommand, stdin io.Reader, stdout, stderr io.Writer, reporters ...telemetryReporter) (result error) {
	telemetry := optionalTelemetryReporter(reporters)
	configuredCommand := flags.Command
	if detail := devCommandRecursion(configuredCommand, flags.commandDir); detail != "" {
		return diagnostic.WrapMessage(diagnostic.DevCommandRecursion, detail, errors.New("dev command starts tnl dev"))
	}
	command, err := resolveDevCommand(flags.Command, flags.commandDir)
	if err != nil {
		return err
	}
	flags.Command = command
	if flags.Port < 0 || flags.Port > 65535 {
		return diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("port must be between 1 and 65535"))
	}
	if flags.StartupTimeout <= 0 || flags.StartupTimeout > 10*time.Minute {
		return failure.Wrap("validate startup timeout", failure.InvalidStartupTimeout, errors.New("startup timeout must be greater than zero and at most 10 minutes"))
	}

	forcedTarget := ""
	if flags.Port != 0 {
		forcedTarget, err = localproxy.NormalizeTarget(strconv.Itoa(flags.Port))
		if err != nil {
			return err
		}
	}
	if flags.projectRoot == "" {
		flags.projectRoot, err = currentProjectRoot(ctx)
		if err != nil {
			return err
		}
	}
	if err := rejectNestedDevSession(flags.projectRoot, flags.Service, configuredCommand); err != nil {
		return err
	}
	serverURL, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	if err := requireSignInOutsideDemo(ctx, state, serverURL, flags.AccessToken); err != nil {
		return err
	}
	if flags.project.Root == "" {
		worktree, resolveErr := projectconfig.ResolveWorktree(ctx, flags.projectRoot)
		if resolveErr != nil {
			return fmt.Errorf("resolve development worktree: %w", resolveErr)
		}
		salt, saltErr := state.WorktreeHashSalt(ctx)
		if saltErr != nil {
			return saltErr
		}
		flags.project = projectConfiguration{
			Project: projectconfig.Project{
				Root: flags.projectRoot, Worktree: projectconfig.ApplyWorktreeHashSalt(worktree, flags.projectRoot, salt),
				ServiceDirectories: map[string]string{}, RelativeServiceDirectories: map[string]string{},
			},
		}
	}
	metadataResolver := newProjectMetadataResolver(state, flags.project, stdin, stderr, "tnl dev")
	if err := metadataResolver.LoadFallbackServer(ctx); err != nil {
		return err
	}
	if !flags.project.Found() {
		flags.project.Config.Server = &serverURL
		if flags.selectedTeam != "" {
			flags.project.Config.Team = &flags.selectedTeam
		}
		metadataResolver.project = flags.project
	}
	authenticated, err := authenticatePublisher(ctx, state, serverURL, flags.AccessToken, "tnl dev", stdin, stderr)
	if err != nil {
		return err
	}
	metadataResolver.Seed(serverURL, authenticated)
	partialReason, err := devMetadataPartialReason(flags, serverURL, metadataResolver.savedServer)
	if err != nil {
		return err
	}
	var metadata projectmeta.Metadata
	var metadataErr error
	if partialReason == "" {
		metadata, metadataErr = metadataResolver.Generate(ctx)
	}
	var services publisherServices
	if partialReason != "" || metadataErr != nil {
		// a one-off server or team override can still publish the selected service
		// when another configured service cannot produce static metadata.
		flags.useMetadataHostname = false
		services, err = preparePublisherServices(
			ctx, state, serverURL, flags.PublicURL, flags.Name, flags.Domain, flags.selectedTeam, flags.Ephemeral, authenticated,
		)
		if err != nil {
			return err
		}
		metadata, err = selectedDevMetadata(flags, services)
		if err != nil {
			return err
		}
		if metadataErr != nil {
			presented := presentFailure(failure.Wrap("resolve project metadata", failure.ProjectConfigInvalid, metadataErr))
			partialReason = presented.message + "; " + presented.action
		}
		if err := writeHumanFrame(stderr, "tnl dev", "partial project metadata", "selected service can still start",
			clioutput.Text(partialReason)); err != nil {
			return err
		}
	}
	if flags.project.Found() {
		write := func() error { return projectmeta.Write(ctx, flags.project.Root, metadata) }
		if flags.metadataWriter != nil {
			write = func() error { return flags.metadataWriter.write(ctx, flags.project.Root, metadata) }
		}
		if err := write(); err != nil {
			return err
		}
	}
	if flags.useMetadataHostname {
		if service, found := metadata.Services[flags.Service]; found {
			flags.PublicURL = service.URL
		}
	}
	policy, err := resolveIPPolicy(ctx, authenticated.Control, flags.AllowIP, flags.AllowProvider, flags.AllowAllIPs)
	if err != nil {
		return err
	}
	if partialReason == "" {
		services, err = preparePublisherServices(
			ctx, state, serverURL, flags.PublicURL, flags.Name, flags.Domain, flags.selectedTeam, flags.Ephemeral, authenticated,
		)
		if err != nil {
			return err
		}
	}
	previewID := ""
	if flags.project.Found() && flags.Service != "" {
		previewID, err = ensurePreview(ctx, state, services.state, services.routes, serverURL, services.teamID, flags.project.Root)
		if err != nil {
			return err
		}
	}
	tunnel, err := state.BeginTunnel(ctx, clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandDev, Server: serverURL, Target: forcedTarget,
		Project: flags.projectRoot, Service: flags.Service,
	})
	if err != nil {
		return err
	}
	ctx = tunnel.Context()
	defer func() {
		if cause := context.Cause(ctx); cause != nil && (result == nil || errors.Is(result, context.Canceled)) {
			result = cause
		}
		finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result = errors.Join(result, tunnel.Finish(finishCtx, result))
	}()

	bootstrap, err := newDevBootstrap(ctx, forcedTarget, flags.projectRoot, flags.Service)
	if err != nil {
		return devBootstrapError(err, flags.projectRoot, flags.Service, configuredCommand)
	}
	defer func() { result = errors.Join(result, bootstrap.Close()) }()

	assignment := devConfigurationResponse{
		Protocol: 1, TunnelID: tunnel.ID(), Service: nullableService(flags.Service),
		Namespace: services.namespace, Hostname: services.hostname,
		PublicURL: "https://" + services.hostname,
		Project:   runtimeProjectMetadata(metadata, flags.Service, services.namespace, services.hostname),
	}
	projectPayload, err := json.Marshal(assignment.Project)
	if err != nil {
		return failure.Wrap("serialize development project metadata", failure.ProjectConfigInvalid, err)
	}
	if len(projectPayload) > maxDevRuntimeBytes {
		return failure.Wrap("validate development project metadata", failure.ProjectConfigInvalid, fmt.Errorf("development project metadata exceeds %d bytes", maxDevRuntimeBytes))
	}
	child, err := startDevProcess(flags.Command, devEnvironment(bootstrap, flags.Port, string(projectPayload)), stdin, stdout, stderr, flags.commandDir)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, child.Stop(devShutdownWait)) }()

	started, err := awaitDevStartup(ctx, flags.StartupTimeout, forcedTarget, bootstrap, child, tunnel, assignment)
	if err != nil {
		return err
	}
	target, framework, frameworkDone := started.target, started.framework, started.frameworkDone
	var mountTargets map[string]string
	if flags.groupTargets != nil {
		mountTargets, err = flags.groupTargets.wait(ctx, child, flags.Service, target)
		if err != nil {
			return err
		}
	}
	mounts, err := resolveProjectMounts(flags.project, flags.Service, mountTargets)
	if err != nil {
		return err
	}
	var frameworkMu sync.RWMutex
	currentFramework := func() string {
		frameworkMu.RLock()
		defer frameworkMu.RUnlock()
		return framework
	}
	commandName := "tnl dev"
	if flags.coordinated {
		commandName += " " + flags.Service
	}
	output, err := newPublishOutput("human", commandName, stdout, stderr, browserOpener(ctx, flags.Open, authenticated.Discovery.DnsAutomation))
	if err != nil {
		return err
	}
	output.setFramework(framework)
	output.setIPPolicy(policy)
	if err := output.starting(tunnel.ID(), target); err != nil {
		return err
	}
	if policy.current != "" {
		if err := output.currentIP(policy.current); err != nil {
			return err
		}
	}
	publishCtx, cancelPublish := context.WithCancel(ctx)
	defer cancelPublish()
	publishDone := make(chan error, 1)
	recorder := tunnel.NewRequestRecorder(flags.projectRoot, flags.Service)
	defer recorder.Close()
	go func() {
		publisherConfig := services.config(target, policy.prefixes, flags.requestLimit())
		publisherConfig.ObserveRequest = requestObservation(recorder)
		publisherConfig.ControlURL = authenticated.ServerEndpoint
		publisherConfig.BrowserLoginAvailable = authenticated.Discovery.BrowserLoginAvailable != nil && *authenticated.Discovery.BrowserLoginAvailable
		publisherConfig.PreviewID = previewID
		publisherConfig.ProjectRoot = flags.project.Root
		publisherConfig.Service = flags.Service
		publisherConfig.Feedback = flags.project.Config.Feedback != nil && *flags.project.Config.Feedback
		publisherConfig.Mounts = mounts
		publisherConfig.Logf = output.logf
		publisherConfig.Observe = withTelemetryObserver(telemetry, telemetryDev, serverURL, currentFramework, func(event publisher.Event) error {
			if previewID != "" && event.Type == publisher.EventPublicURLAssigned {
				preview, err := services.routes.AddPreviewPublicURL(publishCtx, previewID, event.PublicURLID)
				if err != nil {
					return fmt.Errorf("associate service %q with preview: %w", flags.Service, err)
				}
				if preview.Id != previewID || preview.TeamId != services.teamID || !slices.Contains(preview.PublicUrlIds, event.PublicURLID) {
					return failure.Wrap("associate preview public URL", failure.ServerResponseInvalid, errors.New("server returned a preview without the assigned public URL"))
				}
			}
			return handlePublisherEvent(publishCtx, tunnel, output, event)
		})
		publishDone <- publisher.Run(publishCtx, publisherConfig)
	}()

	for {
		select {
		case configuredResult := <-frameworkDone:
			frameworkDone = nil
			if configuredResult.err != nil {
				cancelPublish()
				<-publishDone
				return configuredResult.err
			}
			if configuredResult.target != target {
				cancelPublish()
				<-publishDone
				return diagnostic.Wrap(
					diagnostic.TargetMismatch,
					errors.New("development target changed after publishing started"),
				)
			}
			frameworkMu.Lock()
			framework = configuredResult.framework
			frameworkMu.Unlock()
			output.setFramework(configuredResult.framework)
		case <-child.Done():
			cancelPublish()
			publishErr := <-publishDone
			if err := childResult(child.Err()); err != nil {
				return err
			}
			if publishErr != nil && !errors.Is(publishErr, context.Canceled) {
				return publishErr
			}
			return nil
		case err := <-publishDone:
			if ctx.Err() != nil && errors.Is(err, context.Canceled) {
				return context.Cause(ctx)
			}
			return err
		case <-ctx.Done():
			cancelPublish()
			<-publishDone
			return context.Cause(ctx)
		}
	}
}

func metadataServerDiffers(configured *string, selected, fallback string) bool {
	if configured == nil {
		return fallback != selected
	}
	return *configured != selected
}

func devMetadataPartialReason(flags devCommand, selectedServer, fallbackServer string) (string, error) {
	if !flags.project.Found() {
		return "", nil
	}
	if flags.Team != "" || flags.ServerURL != "" && !flags.serverFromConfig {
		return "this run overrides the project server or team", nil
	}
	// avoid prompting for an unrelated server before starting this service.
	for name := range flags.project.Config.Services {
		effective, err := flags.project.EffectiveService(name)
		if err != nil {
			presented := presentFailure(failure.Wrap("resolve configured service", failure.ProjectConfigInvalid, err))
			return presented.message + "; " + presented.action, nil
		}
		if metadataServerDiffers(effective.Server, selectedServer, fallbackServer) {
			return "another configured service uses a different server", nil
		}
	}
	root, err := flags.project.EffectiveService("")
	if err != nil {
		presented := presentFailure(failure.Wrap("resolve project default", failure.ProjectConfigInvalid, err))
		return presented.message + "; " + presented.action, nil
	}
	if metadataServerDiffers(root.Server, selectedServer, fallbackServer) {
		return "the project default uses a different server", nil
	}
	return "", nil
}

func selectedDevMetadata(flags devCommand, services publisherServices) (projectmeta.Metadata, error) {
	metadata := projectmeta.Metadata{
		Version: projectmeta.Version, Namespace: services.namespace,
		Services: map[string]projectmeta.Service{}, ServiceDirectories: map[string]string{},
	}
	if flags.Service != "" {
		directory, err := filepath.Rel(flags.project.Root, flags.commandDir)
		if err != nil {
			return projectmeta.Metadata{}, err
		}
		metadata.Services[flags.Service] = projectmeta.Service{
			Namespace: services.namespace, Hostname: services.hostname, URL: "https://" + services.hostname,
		}
		metadata.ServiceDirectories[flags.Service] = filepath.ToSlash(directory)
	}
	return metadata, metadata.Validate()
}
