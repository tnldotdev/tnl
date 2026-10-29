package main

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/demo"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publishCommand struct {
	openOptions             `embed:""`
	remoteFlags             `embed:""`
	tunnelFlags             `embed:""`
	backgroundPublishFlags  `embed:""`
	Target                  string            `arg:"" name:"service-or-target" optional:"" env:"TNL_TARGET" help:"Configured service name, local port, HTTP origin, or TCP host:port."`
	Protocol                string            `name:"protocol" env:"TNL_PROTOCOL" help:"Service protocol: http (default), tcp, mysql, or postgres. Configured services need publicURL for public HTTPS."`
	TargetTLS               *bool             `name:"target-tls" help:"Verify publisher-to-target TLS using native protocol negotiation. Independent of visitor TLS."`
	TargetTLSName           string            `name:"target-tls-name" env:"TNL_TARGET_TLS_NAME" help:"Hostname expected in the target's TLS certificate; defaults to the target host."`
	EnrollmentKey           string            `name:"enroll-key" env:"TNL_ENROLL_KEY" help:"One-use publisher enrollment key; use - to read stdin."`
	Enrolled                bool              `name:"enrolled" help:"Use only this target's retained publisher identity; enroll on first start with TNL_ENROLL_KEY."`
	PublisherIdentityID     string            `name:"publisher-identity" env:"TNL_PUBLISHER_IDENTITY_ID" help:"Saved scoped publisher identity ID."`
	PublisherCredentialFile string            `name:"publisher-credential-file" env:"TNL_PUBLISHER_CREDENTIAL_FILE" type:"path" help:"Portable scoped publisher identity file; no login session is used."`
	Output                  publishOutputMode `name:"output" enum:"human,ndjson" default:"human" help:"Output format: ${enum}."`
	Demo                    bool              `name:"demo" help:"Publish a built-in local demo; no service or target needed."`

	serverFromConfig  bool
	selectedTeam      string
	projectRoot       string
	demoNameFromCLI   bool
	Service           string `kong:"-"`
	project           projectConfiguration
	service           bool
	namedOverrides    bool
	telemetryDisabled bool
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
	selection := enrolledPublishSelection{EnrollmentKey: flags.EnrollmentKey, PublisherIdentityID: flags.PublisherIdentityID, PublisherCredentialFile: flags.PublisherCredentialFile}
	if flags.Foreground && (flags.Install || flags.Detach) {
		return publisherCLIError("select only one of --foreground, --detach, or --install")
	}
	if flags.Install && flags.Detach {
		return publisherCLIError("--install and --detach cannot be combined")
	}
	credentialOwned := flags.EnrollmentKey != "" || flags.PublisherIdentityID != "" || flags.PublisherCredentialFile != ""
	if credentialOwned && flags.Service != "" {
		resolved, err := target.ResolveTarget(ctx, flags.project.Project, flags.Service, runtimeTargetResolver)
		if err != nil {
			return err
		}
		if resolved.Target == nil {
			return publisherCLIError("scoped publication requires an address, Docker, or Compose target")
		}
		flags.Target = string(*resolved.Target)
	}
	if flags.service && !flags.Install && flags.Service != "" && !credentialOwned {
		selected, err := resolveNamedPrivate(flags)
		if err != nil {
			return err
		}
		output, err := newPublishOutput(flags.Output, "tnl publish", stdout, stderr, nil)
		if err != nil {
			return err
		}
		output.detachedCtx = ctx
		defer func() { result = output.finish(ctx, result) }()
		return runNamedPublish(ctx, selected.resolvedNamedInvocation, flags.StateDir, flags.telemetryDisabled, output)
	}
	if flags.service || flags.Protocol != "" && flags.Protocol != "http" {
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
	if credentialOwned {
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
		return failure.Wrap("validate TCP publish options", failure.InvalidTunnelFlags, errors.New("TCP publication cannot run the demo"))
	}
	if err := validateTCPPublishOptions(flags, protocol); err != nil {
		return err
	}
	if flags.Service != "" {
		selected, err := resolveNamedPublic(flags)
		if err != nil {
			return err
		}
		if protocol == controlv1.Http {
			output.openURL = browserOpener(ctx, flags.Open, true)
		}
		return runNamedPublish(ctx, selected.resolvedNamedInvocation, flags.StateDir, flags.telemetryDisabled, output)
	}
	if flags.Demo {
		flags.projectRoot, err = currentProjectRoot(ctx)
		if err != nil {
			return err
		}
	}
	options := publicOptions(flags)
	options.Authenticate = publisherAuthentication(stderr)
	presentation := publicationPresentation(ctx, flags, output, telemetry)
	return invocation.PublishHTTP(ctx, options, presentation)
}

func publicOptions(flags publishCommand) invocation.PublicOptions {
	return invocation.PublicOptions{Target: flags.Target, TargetCAFile: flags.TargetCAFile, TargetTLSName: flags.TargetTLSName, ProjectRoot: flags.projectRoot, Project: flags.project.Project, Service: flags.Service, StateDir: flags.StateDir, ServerURL: flags.ServerURL, AccessToken: flags.AccessToken, PublicURL: flags.PublicURL, Name: flags.Name, Domain: flags.Domain, Team: flags.Team, SelectedTeam: flags.selectedTeam, Ephemeral: flags.Ephemeral, Demo: flags.Demo, Anonymous: flags.Anonymous, IP: flags.IP, Access: flags.access, Limits: flags.limits(), InspectionMode: flags.InspectionMode, Inspection: flags.inspection, Resolver: runtimeTargetResolver, TelemetryDisabled: flags.telemetryDisabled}
}

func publisherAuthentication(stderr io.Writer) func(context.Context, *clientstate.Database, string, string) (*auth.Client, error) {
	return func(ctx context.Context, state *clientstate.Database, server, token string) (*auth.Client, error) {
		return authenticatePublisher(ctx, state, server, token, "tnl publish", os.Stdin, stderr)
	}
}

func publicationPresentation(ctx context.Context, flags publishCommand, output *publishOutput, telemetry telemetryReporter) *invocation.Presentation {
	var observe func(publisher.Event) error
	var observing sync.Once
	presentation := &invocation.Presentation{
		Starting: output.starting, Provisioning: output.provisioning, Ready: output.ready, Stopped: output.stopped,
		Progress: func(p invocation.Progress) error { return output.integrationURLMessage(p.State, p.Hint, p.Details...) },
		Warning: func(message string) error {
			output.mu.Lock()
			defer output.mu.Unlock()
			if output.mode == publishOutputNDJSON {
				return output.emitLocked(publishEvent{Type: publishEventWarning, Message: message})
			}
			return writeHumanFrame(output.stderr, output.command, "warning", "", clioutput.Text(message))
		},
		ConfigureBrowser: func(automated bool) { output.openURL = browserOpener(ctx, flags.Open, automated) },
		Demo:             output.setDemo, GuestDemo: output.setGuestDemo, GuestShare: output.setGuestShare, DemoPing: demoPingHandler(output, telemetry), Logf: output.logf,
		PublisherEvent: func(ctx context.Context, tunnel *clientstate.Tunnel, server string, event publisher.Event) error {
			observing.Do(func() {
				observe = withTelemetryObserver(telemetry, server, nil, func(event publisher.Event) error { return handlePublisherEvent(ctx, tunnel, output, event) })
			})
			return observe(event)
		},
	}
	if telemetry != nil {
		presentation.Observe = func(event invocation.IntegrationObservation) {
			telemetry.Report(newIntegrationTelemetry(string(event.Event), telemetryWebhookDelivery(event.Delivery)))
		}
	}
	return presentation
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
