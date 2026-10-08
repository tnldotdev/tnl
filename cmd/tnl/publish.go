package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/demo"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/integrationurls"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publisher"
)

type publishCommand struct {
	openOptions `embed:""`
	remoteFlags `embed:""`
	tunnelFlags `embed:""`
	Target      string            `arg:"" name:"service-or-target" optional:"" help:"Configured service name, local port, or HTTP URL on this computer."`
	Output      publishOutputMode `name:"output" enum:"human,ndjson" default:"human" help:"Output format: ${enum}."`
	Demo        bool              `name:"demo" help:"Publish a built-in local demo; no service or target needed."`

	serverFromConfig bool
	selectedTeam     string
	projectRoot      string
	demoNameFromCLI  bool
	Service          string `kong:"-"`
	project          projectConfiguration
}

func runPublish(ctx context.Context, flags publishCommand, stdout, stderr io.Writer, reporters ...telemetryReporter) (result error) {
	telemetry := optionalTelemetryReporter(reporters)
	output, err := newPublishOutput(flags.Output, "tnl publish", stdout, stderr, nil)
	if err != nil {
		return err
	}
	output.setRequestInspection(flags.RequestInspection)
	defer func() { result = output.finish(ctx, result) }()
	var localDemo *demo.Server
	if flags.Demo {
		flags.projectRoot, err = currentProjectRoot(ctx)
		if err != nil {
			return err
		}
		localDemo, err = demo.Start(demoPingHandler(output, telemetry))
		if err != nil {
			return failure.Wrap("start local demo", failure.DemoLocalServiceUnavailable, err)
		}
		defer func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result = errors.Join(result, localDemo.Close(closeCtx))
		}()
		flags.Target = localDemo.Target()
		output.setDemo()
	}
	target, err := localproxy.NormalizeTarget(flags.Target)
	if err != nil {
		return err
	}
	serverURL, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	var oauthHostname string
	if !flags.Demo {
		if err := requireSignInOutsideDemo(ctx, state, serverURL, flags.AccessToken); err != nil {
			return err
		}
	}
	tunnel, err := state.BeginTunnel(ctx, clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: serverURL, Target: target,
		Project: flags.projectRoot, Service: flags.Service,
	})
	if err != nil {
		return err
	}
	ctx = tunnel.Context()
	defer func() {
		finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result = errors.Join(result, tunnel.Finish(finishCtx, result))
	}()
	if err := output.starting(tunnel.ID(), target); err != nil {
		return err
	}
	if err := localproxy.Preflight(ctx, target); err != nil {
		return err
	}
	var guest *clientstate.GuestSession
	if flags.Demo {
		guest, err = guestForDemo(ctx, state, serverURL, flags)
		if err != nil {
			return err
		}
		if guest != nil {
			output.setGuestDemo()
			localDemo.SetGuest()
		}
		if guest == nil {
			label := make([]byte, 4)
			if _, err := rand.Read(label); err != nil {
				return err
			}
			flags.Name = "demo-" + hex.EncodeToString(label)
		}
	}
	accessToken := flags.AccessToken
	if guest != nil {
		accessToken = guest.AccessToken
	}
	authenticated, err := authenticatePublisher(ctx, state, serverURL, accessToken, "tnl publish", os.Stdin, stderr)
	if err != nil {
		return err
	}
	output.openURL = browserOpener(ctx, flags.Open, authenticated.Discovery.DnsAutomation)
	policy, err := resolveIPPolicy(ctx, authenticated.Control, flags.AllowIP, flags.AllowAllIPs)
	if err != nil {
		return err
	}
	if policy.current != "" {
		if err := output.currentIP(policy.current); err != nil {
			return err
		}
	}
	if guest != nil {
		allocated, err := authenticated.Control.AllocateGuestDemoNumber(ctx)
		if err != nil {
			return err
		}
		flags.Name = "demo-" + strconv.FormatInt(allocated.Number, 10)
	}
	var services publisherServices
	if guest != nil {
		services, err = guestPublisherServices(ctx, state, serverURL, flags.Name, *guest, authenticated.Control)
	} else {
		services, err = preparePublisherServices(
			ctx, state, serverURL, flags.PublicURL, flags.Name, flags.Domain, flags.selectedTeam, flags.Ephemeral, authenticated,
		)
	}
	if err != nil {
		return err
	}
	integrationGroup := ""
	if !flags.Demo && (flags.project.Config.OAuth || len(flags.project.Config.Webhooks) != 0 || len(flags.project.Config.Aliases) != 0) {
		if flags.project.Root == "" {
			worktree, resolveErr := projectconfig.ResolveWorktree(ctx, flags.projectRoot)
			if resolveErr != nil {
				return resolveErr
			}
			flags.project.Project = projectconfig.Project{Root: flags.projectRoot, Worktree: worktree}
		}
		integrationGroup = projectIntegrationGroup(flags.project.Project, services.namespace)
		if err := tunnel.SetIntegrationGroup(ctx, integrationGroup); err != nil {
			return err
		}
	}
	if !flags.Demo && flags.project.Config.OAuth {
		oauth, oauthServices, resolveErr := projectOAuthPublisher(ctx, state, flags.project.Project, serverURL, flags.selectedTeam, authenticated)
		if resolveErr != nil {
			return resolveErr
		}
		stopCallbacks := startOAuthIntegrationURL(ctx, state, oauthServices, oauth, tunnel, output, telemetry)
		defer stopCallbacks()
		oauthHostname = oauth.Hostname
	}
	if !flags.Demo && len(flags.project.Config.Webhooks) > 0 {
		stopWebhooks := startWebhookIntegrationURL(ctx, state, services, flags.project.Project, tunnel, flags.Service, integrationGroup, output, telemetry)
		defer stopWebhooks()
	}
	publisherConfig := services.config(target, policy.prefixes, flags.requestLimit())
	recorder, err := newRequestRecorder(ctx, tunnel, flags.projectRoot, flags.Service)
	if err != nil {
		return err
	}
	defer recorder.Close()
	publisherConfig.ObserveRequest = requestObservation(recorder)
	publisherConfig.RequestInspection = flags.RequestInspection
	if oauthHostname != "" {
		publisherConfig.ObserveResponse = integrationurls.Observer(state, serverURL, oauthHostname, integrationGroup, tunnel.ID())
	}
	publisherConfig.ControlURL = authenticated.ServerEndpoint
	publisherConfig.BrowserLoginAvailable = authenticated.Discovery.BrowserLoginAvailable != nil && *authenticated.Discovery.BrowserLoginAvailable
	if flags.Demo {
		publisherConfig.Demo, publisherConfig.Feedback, publisherConfig.Service = true, true, "demo"
	}
	publisherConfig.Mounts, err = resolveProjectMounts(flags.project, flags.Service, nil)
	if err != nil {
		return err
	}
	publisherConfig.Logf = output.logf
	publisherConfig.Observe = withTelemetryObserver(telemetry, telemetryPublish, serverURL, nil, func(event publisher.Event) error {
		if localDemo != nil && event.Type == publisher.EventReady {
			localDemo.SetPublicURL(event.PublicURL)
		}
		return handlePublisherEvent(ctx, tunnel, output, event)
	})
	if !flags.Demo && len(flags.project.Config.Aliases) != 0 {
		stopAliases := startProjectAliases(ctx, state, flags.project, flags.Service, flags.selectedTeam, services, publisherConfig, integrationGroup, tunnel, output)
		defer stopAliases()
	}
	err = publisher.Run(ctx, publisherConfig)
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if err != nil && !(ctx.Err() != nil && errors.Is(err, context.Canceled)) {
		return err
	}
	return output.stopped()
}

func demoPingHandler(output *publishOutput, telemetry telemetryReporter) func(demo.State) error {
	var reportedPing sync.Once
	return func(state demo.State) error {
		if err := output.demoPing(state); err != nil {
			return err
		}
		if telemetry != nil {
			reportedPing.Do(func() { telemetry.Report(newTelemetryDemoPing()) })
		}
		return nil
	}
}
