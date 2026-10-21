package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/demo"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/internal/integrationurls"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectpublisher"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publishCommand struct {
	openOptions            `embed:""`
	remoteFlags            `embed:""`
	tunnelFlags            `embed:""`
	backgroundPublishFlags `embed:""`
	Target                 string            `arg:"" name:"service-or-target" optional:"" env:"TNL_TARGET" help:"Configured service name, local port, HTTP origin, or TCP host:port."`
	Protocol               string            `name:"protocol" env:"TNL_PROTOCOL" help:"Service protocol: http (default), tcp, mysql, or postgres. Configured services need publicURL for public HTTPS."`
	TargetTLS              *bool             `name:"target-tls" help:"Verify publisher-to-target TLS using native protocol negotiation. Independent of visitor TLS."`
	TargetTLSName          string            `name:"target-tls-name" env:"TNL_TARGET_TLS_NAME" help:"Hostname expected in the target's TLS certificate; defaults to the target host."`
	EnrollmentKey          string            `name:"enroll-key" env:"TNL_ENROLL_KEY" help:"One-use publisher enrollment key; use - to read stdin."`
	Enrolled               bool              `name:"enrolled" help:"Use only this target's retained publisher identity; enroll on first start with TNL_ENROLL_KEY."`
	PublisherID            string            `name:"publisher" env:"TNL_PUBLISHER" help:"Saved scoped publisher identity ID."`
	PublisherFile          string            `name:"publisher-file" env:"TNL_PUBLISHER_FILE" type:"path" help:"Portable scoped publisher identity file; no login session is used."`
	Output                 publishOutputMode `name:"output" enum:"human,ndjson" default:"human" help:"Output format: ${enum}."`
	Demo                   bool              `name:"demo" help:"Publish a built-in local demo; no service or target needed."`

	serverFromConfig bool
	selectedTeam     string
	projectRoot      string
	demoNameFromCLI  bool
	Service          string `kong:"-"`
	project          projectConfiguration
	privateService   bool
	namedOverrides   bool
}

func runPublish(ctx context.Context, flags publishCommand, stdout, stderr io.Writer, reporters ...telemetryReporter) (result error) {
	telemetry := optionalTelemetryReporter(reporters)
	if flags.Enrolled {
		var err error
		flags, err = retainedPublishFlags(ctx, flags)
		if err != nil {
			return err
		}
	}
	selection := enrolledPublishSelection{EnrollmentKey: flags.EnrollmentKey, PublisherID: flags.PublisherID, PublisherFile: flags.PublisherFile}
	if flags.Foreground && (flags.Install || flags.Detach) {
		return publisherCLIError("select only one of --foreground, --detach, or --install")
	}
	if flags.Install && flags.Detach {
		return publisherCLIError("--install and --detach cannot be combined")
	}
	credentialOwned := flags.EnrollmentKey != "" || flags.PublisherID != "" || flags.PublisherFile != ""
	if credentialOwned && flags.Service != "" {
		resolved, err := projectpublisher.ResolveTarget(ctx, flags.project.Project, flags.Service, runtimeTargetResolver)
		if err != nil {
			return err
		}
		if resolved.Target == nil {
			return publisherCLIError("scoped publication requires an address, Docker, or Compose target")
		}
		flags.Target = string(*resolved.Target)
	}
	if flags.privateService && !flags.Install && flags.Service != "" && !credentialOwned {
		invocation, err := resolveNamedPrivate(flags)
		if err != nil {
			return err
		}
		output, err := newPublishOutput(flags.Output, "tnl publish", stdout, stderr, nil)
		if err != nil {
			return err
		}
		output.detachedCtx = ctx
		defer func() { result = output.finish(ctx, result) }()
		return runNamedPublish(ctx, invocation.resolvedNamedInvocation, flags.StateDir, output)
	}
	if flags.privateService || flags.Protocol != "" && flags.Protocol != "http" {
		return runPrivatePublish(ctx, flags, stdout, stderr)
	}
	if flags.Install {
		if flags.Output != "human" {
			return publisherCLIError("--install requires --output=human")
		}
		if !credentialOwned && (flags.Service == "" || flags.System) {
			return runPublicationInstall(ctx, flags, stdout, stderr)
		}
		return runEnrolledBackgroundPublish(ctx, flags, selection, flags.backgroundPublishFlags, stdout, os.Stdin, nil)
	}
	if flags.System || flags.ServiceName != "" || flags.SystemStateDir != "" || flags.ServerCAFile != "" {
		return publisherCLIError("--system, --service-name, --system-state-dir, and --server-ca-file require --install")
	}
	output, err := newPublishOutput(flags.Output, "tnl publish", stdout, stderr, nil)
	if err != nil {
		return err
	}
	output.detachedCtx = ctx
	defer func() { result = output.finish(ctx, result) }()
	if flags.EnrollmentKey != "" || flags.PublisherID != "" || flags.PublisherFile != "" {
		return runEnrolledPublish(ctx, flags, selection, output, telemetry, os.Stdin)
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
	if flags.Service != "" {
		invocation, err := resolveNamedPublic(flags)
		if err != nil {
			return err
		}
		if protocol == controlv1.Http {
			output.openURL = browserOpener(ctx, flags.Open, true)
		}
		return runNamedPublish(ctx, invocation.resolvedNamedInvocation, flags.StateDir, output)
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
	if protocol == controlv1.Http {
		targetOptions.ServerName = flags.TargetTLSName
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
	policy, err := resolveVisitorAccess(ctx, authenticated.Control, flags.access, flags.Anonymous, flags.IP)
	if err != nil {
		return err
	}
	if guest != nil {
		// guest publication remains bound to its issuing IP. control discards
		// that prefix after checking it, so browser visits use the guest link.
		guestPrefixes, sourceErr := accessIPPrefixes(ctx, authenticated.Control, []string{"current"})
		if sourceErr != nil {
			return sourceErr
		}
		policy.prefixes = guestPrefixes
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
	publisherConfig := services.config(target, policy.prefixes, flags.limits())
	if policy.explicit {
		publisherConfig.AccessMode = policy.access
	}
	publisherConfig.ServiceProtocol = protocol
	if protocol != controlv1.Http {
		publisherConfig.TargetTLSName = flags.TargetTLSName
	}
	publisherConfig.TargetOptions = targetOptions
	recorder, err := newInspectionRecorder(ctx, tunnel, flags.projectRoot, flags.Service, flags.InspectionMode, flags.inspection)
	if err != nil {
		return err
	}
	defer recorder.Close()
	publisherConfig.ObserveSummary = summaryObservation(recorder)
	publisherConfig.InspectionMode = inspection.Mode(flags.InspectionMode)
	publisherConfig.OnWarning = publishWarning(tunnel, output)
	if oauthHostname != "" {
		publisherConfig.ObserveResponse = integrationurls.Observer(state, serverURL, oauthHostname, integrationGroup, tunnel.ID())
	}
	publisherConfig.ControlURL = authenticated.ServerEndpoint
	publisherConfig.BrowserLoginAvailable = authenticated.Discovery.BrowserLoginAvailable != nil && *authenticated.Discovery.BrowserLoginAvailable
	if flags.Demo {
		publisherConfig.Demo, publisherConfig.Feedback, publisherConfig.Service = true, true, "demo"
		if guest != nil {
			publisherConfig.Purpose = controlv1.Demo
		}
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
	cleanup, err := selectForegroundPublisher(ctx, state, services, &publisherConfig, guest)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, cleanup()) }()
	publisherConfig.Observe = withTelemetryObserver(telemetry, telemetryPublish, serverURL, nil, func(event publisher.Event) error {
		if guest != nil && event.Type == publisher.EventPublicURLAssigned {
			secret := make([]byte, 32)
			if _, err := rand.Read(secret); err != nil {
				return err
			}
			fingerprint := sha256.Sum256(secret)
			key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
			if err != nil {
				return err
			}
			share, err := authenticated.Control.CreateURLShare(ctx, key, controlv1.CreateShareRequest{
				PublicUrlIds: []string{event.PublicURLID}, SecretFingerprint: hex.EncodeToString(fingerprint[:]), ExpiresAt: guest.ExpiresAt,
			})
			if err != nil {
				return fmt.Errorf("create guest share: %w", err)
			}
			if share.Scope != controlv1.ShareScopeGuest || len(share.PublicUrlIds) != 1 || share.PublicUrlIds[0] != event.PublicURLID {
				return failure.Wrap("create guest share", failure.ServerResponseInvalid, errors.New("server returned a share for another public URL"))
			}
			output.setGuestShare(share.Id + "." + base64.RawURLEncoding.EncodeToString(secret))
		}
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
