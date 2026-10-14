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
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publishCommand struct {
	openOptions       `embed:""`
	remoteFlags       `embed:""`
	tunnelFlags       `embed:""`
	Target            string            `arg:"" name:"service-or-target" optional:"" env:"TNL_TARGET" help:"Configured service name, local port, HTTP origin, or TCP host:port."`
	Protocol          string            `name:"protocol" env:"TNL_PROTOCOL" help:"Local service protocol; defaults to http."`
	TargetTLSName     string            `name:"target-tls-name" env:"TNL_TARGET_TLS_NAME" help:"Hostname expected in the target's TLS certificate; defaults to the target host."`
	TargetTLS         bool              `name:"target-tls" env:"TNL_TARGET_TLS" help:"Use verified TLS for the TCP target."`
	PublishCredential string            `name:"credential" env:"TNL_CREDENTIAL" help:"Credential for publishing one saved public URL without a control session."`
	EnrollKey         string            `name:"enroll-key" help:"One-use publisher enrollment key, or - to read it from stdin."`
	Background        bool              `name:"bg" help:"Enroll a saved public URL as a system publisher job (run as root)."`
	Output            publishOutputMode `name:"output" enum:"human,ndjson" default:"human" help:"Output format: ${enum}."`
	Demo              bool              `name:"demo" help:"Publish a built-in local demo; no service or target needed."`

	serverFromConfig bool
	selectedTeam     string
	projectRoot      string
	demoNameFromCLI  bool
	Service          string `kong:"-"`
	project          projectConfiguration
}

func runPublish(ctx context.Context, flags publishCommand, stdout, stderr io.Writer, reporters ...telemetryReporter) (result error) {
	if flags.Background {
		return runBackgroundEnrollment(ctx, flags, stdout, os.Stdin)
	}
	telemetry := optionalTelemetryReporter(reporters)
	output, err := newPublishOutput(flags.Output, "tnl publish", stdout, stderr, nil)
	if err != nil {
		return err
	}
	defer func() { result = output.finish(ctx, result) }()
	if flags.EnrollKey != "" {
		if flags.PublishCredential != "" || flags.Demo || flags.AccessToken != "" {
			return failure.Wrap("validate enrollment options", failure.InvalidTunnelFlags, errors.New("--enroll-key cannot be combined with a credential, demo, or access token"))
		}
		return runEnrolledPublish(ctx, flags, output, telemetry, os.Stdin)
	}
	if flags.PublishCredential != "" {
		if flags.Demo {
			return failure.Wrap("validate demo options", failure.InvalidTunnelFlags, errors.New("a public URL publish credential cannot be used with --demo"))
		}
		return runScopedPublish(ctx, flags, output, telemetry)
	}
	protocol, err := publishProtocol(flags.Protocol)
	if err != nil {
		return err
	}
	if err := selectPublishInspection(&flags, protocol); err != nil {
		return err
	}
	if protocol != controlv1.Http && flags.Demo {
		return failure.Wrap("validate TCP publish options", failure.InvalidTunnelFlags,
			errors.New("TCP publication cannot run the demo"))
	}
	if err := validateTCPPublishOptions(flags, protocol); err != nil {
		return err
	}
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
	target, err := normalizePublishTarget(flags.Target, protocol)
	if err != nil {
		return err
	}
	targetOptions, err := targetOptionsForCA(flags.TargetCAFile, flags.projectRoot)
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
		Command: clientstate.TunnelCommandPublish, Server: serverURL, Target: target, ServiceProtocol: protocol,
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
	if protocol == controlv1.Http {
		if err := localproxy.PreflightWithOptions(ctx, target, targetOptions); err != nil {
			return err
		}
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
	if protocol == controlv1.Http {
		output.openURL = browserOpener(ctx, flags.Open, authenticated.Discovery.DnsAutomation)
	}
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
	if protocol == controlv1.Http && !flags.Demo && (flags.project.Config.OAuth || len(flags.project.Config.Webhooks) != 0 || len(flags.project.Config.Aliases) != 0) {
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
	traffic, err := flags.traffic()
	if err != nil {
		return failure.Wrap("validate traffic limits", failure.InvalidTunnelFlags, err)
	}
	services.traffic = traffic
	if protocol == controlv1.Http && !flags.Demo && flags.project.Config.OAuth {
		oauth, oauthServices, resolveErr := projectOAuthPublisher(ctx, state, flags.project.Project, serverURL, flags.selectedTeam, authenticated)
		if resolveErr != nil {
			return resolveErr
		}
		stopCallbacks := startOAuthIntegrationURL(ctx, state, oauthServices, oauth, tunnel, output, telemetry)
		defer stopCallbacks()
		oauthHostname = oauth.Hostname
	}
	if protocol == controlv1.Http && !flags.Demo && len(flags.project.Config.Webhooks) > 0 {
		stopWebhooks := startWebhookIntegrationURL(ctx, state, services, flags.project.Project, tunnel, flags.Service, integrationGroup, output, telemetry)
		defer stopWebhooks()
	}
	publisherConfig := services.config(target, policy.prefixes, flags.limits(), traffic)
	publisherConfig.ServiceProtocol = protocol
	publisherConfig.TargetTLSName = flags.TargetTLSName
	publisherConfig.TargetTLS = flags.TargetTLS
	publisherConfig.TargetOptions = targetOptions
	recorder, err := newInspectionRecorder(ctx, tunnel, flags.projectRoot, flags.Service, flags.tunnelFlags)
	if err != nil {
		return err
	}
	defer recorder.Close()
	publisherConfig.ObserveRequest = httpObservation(recorder)
	if protocol == controlv1.Mysql || protocol == controlv1.Postgres {
		publisherConfig.ObserveDatabase = sqlObservation(recorder)
	}
	publisherConfig.InspectionMode = flags.InspectionMode
	if oauthHostname != "" {
		publisherConfig.ObserveResponse = integrationurls.Observer(state, serverURL, oauthHostname, integrationGroup, tunnel.ID())
	}
	publisherConfig.ControlURL = authenticated.ServerEndpoint
	publisherConfig.BrowserLoginAvailable = authenticated.Discovery.BrowserLoginAvailable != nil && *authenticated.Discovery.BrowserLoginAvailable
	if flags.Demo {
		publisherConfig.Demo, publisherConfig.Feedback, publisherConfig.Service = true, true, "demo"
		publisherConfig.Purpose = controlv1.Demo
	}
	publisherConfig.Mounts, err = resolveProjectMounts(flags.project, flags.Service)
	if err != nil {
		return err
	}
	if protocol != controlv1.Http && len(publisherConfig.Mounts) != 0 {
		return failure.Wrap("validate TCP publish options", failure.InvalidTunnelFlags,
			errors.New("TCP public URLs cannot use HTTP path mounts"))
	}
	publisherConfig.Logf = output.logf
	publisherConfig.Observe = withTelemetryObserver(telemetry, telemetryPublish, serverURL, nil, func(event publisher.Event) error {
		if localDemo != nil && event.Type == publisher.EventReady {
			localDemo.SetPublicURL(event.PublicURL)
		}
		return handlePublisherEvent(ctx, tunnel, output, event)
	})
	if protocol == controlv1.Http && !flags.Demo && len(flags.project.Config.Aliases) != 0 {
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
