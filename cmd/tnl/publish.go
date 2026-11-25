package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/tnldotdev/tnl/internal/client/detached"
	"golang.org/x/term"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/region"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publishCommand struct {
	PreferredRegions        []string `name:"prefer-region" env:"TNL_PREFERRED_REGIONS" help:"Prefer an exact provider:region, such as fly:sjc; repeat in priority order. Nearby capacity is a fallback, not a hard provider constraint."`
	openOptions             `embed:""`
	remoteFlags             `embed:""`
	tunnelFlags             `embed:""`
	backgroundPublishFlags  `embed:""`
	Target                  string            `arg:"" name:"service-or-target" optional:"" env:"TNL_TARGET" help:"Configured service name, local port, HTTP origin, or TCP host:port."`
	Protocol                string            `name:"protocol" env:"TNL_PROTOCOL" help:"Service protocol: http (default), tcp, mysql, or postgres. Set public: true on a configured binding for public endpoint access."`
	TargetTLS               *bool             `name:"target-tls" help:"Verify publisher-to-target TLS using native protocol negotiation. Independent of visitor TLS."`
	TargetTLSName           string            `name:"target-tls-name" env:"TNL_TARGET_TLS_NAME" help:"Hostname expected in the target's TLS certificate; defaults to the target host."`
	EnrollmentKey           string            `name:"enroll-key" env:"TNL_ENROLL_KEY" help:"One-use publisher enrollment key; use - to read stdin."`
	Enrolled                bool              `name:"enrolled" help:"Use only this target's retained publisher identity; enroll on first start with TNL_ENROLL_KEY."`
	PublisherIdentityID     string            `name:"publisher-identity" env:"TNL_PUBLISHER_IDENTITY_ID" help:"Saved scoped publisher identity ID."`
	PublisherCredentialFile string            `name:"publisher-credential-file" env:"TNL_PUBLISHER_CREDENTIAL_FILE" type:"path" help:"Portable scoped publisher identity file; no login session is used."`
	Output                  publishOutputMode `name:"output" enum:"human,ndjson" default:"human" help:"Output format: ${enum}."`
	Demo                    bool              `name:"demo" help:"Publish a built-in local demo; anonymous when signed in unless --anonymous=false."`

	serverFromConfig  bool
	selectedTeam      string
	projectRoot       string
	fallbackName      string
	demoNameFromCLI   bool
	Service           string
	TelemetryDisabled bool
	telemetry         *clienttelemetry.Collector
	project           projectConfiguration
	service           bool
	namedOverrides    bool
}

func runPublish(ctx context.Context, flags publishCommand, stdout, stderr io.Writer) (result error) {
	var err error
	flags.PreferredRegions, err = region.Preferences(flags.PreferredRegions)
	if err != nil {
		return failure.Wrap("select publisher regions", failure.InvalidTunnelFlags, err)
	}
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
	if !flags.Install && (flags.System || flags.ServiceName != "" || flags.SystemStateDir != "" || flags.ServerCAFile != "") {
		return publisherCLIError("--system, --service-name, --system-state-dir, and --server-ca-file require --install")
	}
	credentialOwned := flags.EnrollmentKey != "" || flags.PublisherIdentityID != "" || flags.PublisherCredentialFile != ""
	if len(flags.PreferredRegions) != 0 && flags.Service != "" && !credentialOwned {
		return publisherCLIError("--prefer-region requires an ad-hoc target or scoped publisher credentials; named publications use the project owner")
	}
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
	if !flags.Install && flags.Service != "" && !credentialOwned {
		selected, err := namedInvocation(flags)
		if err != nil {
			return err
		}
		binding := selected.project.Config.Services[selected.service]
		publicHTTP := config.Protocol(binding) == "http" && binding.Public != nil && *binding.Public
		if flags.Open && !publicHTTP {
			return publisherCLIError("--open requires a public HTTP service")
		}
		output, err := newPublishOutput(flags.Output, "tnl publish", stdout, stderr, nil)
		if err != nil {
			return err
		}
		output.detachedCtx = ctx
		if publicHTTP {
			output.openURL = browserOpener(ctx, flags.Open, true)
		} else {
			output.connectCommand = publishedConnectCommand(ctx, flags, selected.service, true)
		}
		defer func() { result = output.finish(ctx, result) }()
		return runNamedPublish(ctx, selected, flags.StateDir, output)
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
	output, err := newPublishOutput(flags.Output, "tnl publish", stdout, stderr, nil)
	if err != nil {
		return err
	}
	output.detachedCtx = ctx
	defer func() { result = output.finish(ctx, result) }()
	if credentialOwned {
		return runEnrolledPublish(ctx, flags, selection, output, os.Stdin)
	}
	protocol, err := publishProtocol(flags.Protocol)
	if err != nil {
		return err
	}
	if protocol != controlv1.ServiceProtocolHTTP && flags.Demo {
		return failure.Wrap("validate TCP publish options", failure.InvalidTunnelFlags, errors.New("TCP publication cannot run the demo"))
	}
	if err := validateTCPPublishOptions(flags, protocol); err != nil {
		return err
	}
	if flags.Demo {
		flags.projectRoot, err = currentProjectRoot(ctx)
		if err != nil {
			return err
		}
	}
	options := publicOptions(flags)
	options.Authenticate = publisherAuthentication(stderr)
	presentation := publicationPresentation(ctx, flags, output)
	return invocation.PublishHTTP(ctx, options, presentation)
}

func publicOptions(flags publishCommand) invocation.PublicOptions {
	return invocation.PublicOptions{Telemetry: flags.telemetry, TelemetryDisabled: flags.TelemetryDisabled, PreferredRegions: flags.PreferredRegions, RequirePostQuantum: flags.RequirePostQuantum, Target: flags.Target, TargetCAFile: flags.TargetCAFile, TargetTLSName: flags.TargetTLSName, ProjectRoot: flags.projectRoot, Project: flags.project.Project, Service: flags.Service, StateDir: flags.StateDir, ServerURL: flags.ServerURL, AccessToken: flags.AccessToken, PublicURL: flags.PublicURL, Name: flags.Name, FallbackName: flags.fallbackName, Domain: flags.Domain, Team: flags.Team, SelectedTeam: flags.selectedTeam, Ephemeral: flags.Ephemeral, Demo: flags.Demo, Anonymous: flags.Anonymous, IP: flags.IP, Access: flags.access, Limits: flags.limits(), InspectionMode: flags.InspectionMode, Inspection: flags.inspection, Resolver: runtimeTargetResolver}
}

func publisherAuthentication(stderr io.Writer) func(context.Context, *clientstate.Database, string, string) (*auth.Client, error) {
	return func(ctx context.Context, state *clientstate.Database, server, token string) (*auth.Client, error) {
		return authenticatePublisher(ctx, state, server, token, "tnl publish", os.Stdin, stderr)
	}
}

func publicationPresentation(ctx context.Context, flags publishCommand, output *publishOutput) *invocation.Presentation {
	return &invocation.Presentation{
		Starting: output.starting, Provisioning: output.provisioning, Ready: output.ready, Stopped: output.stopped,
		Resume: func(url, team, server string) error {
			if output.mode != publishOutputHuman {
				return nil
			}
			// saved policy comes from control, not from the current project config.
			command := "tnl --no-config publish " + shellWord(flags.Target) + " --hostname " + shellWord(url)
			if team != "" {
				command += " --team " + shellWord(team)
			}
			if pin := suggestedServer(ctx, server, nil, "", flags.StateDir, nil); pin != "" {
				command += " --server " + shellWord(pin)
			}
			if flags.StateDir != "" {
				command += " --state-dir " + shellWord(flags.StateDir)
			}
			output.resumeCommand = command
			return nil
		},
		ProvisioningStalled: output.provisioningStalled, TransportFallback: output.transportFallback, TargetUnavailable: output.targetUnavailable,
		Progress: func(p invocation.Progress) error { return output.integrationURLMessage(p.State, p.Hint, p.Details...) },
		Warning: func(message string) error {
			output.mu.Lock()
			defer output.mu.Unlock()
			if output.mode == publishOutputNDJSON {
				return output.emitLocked(publishEvent{Type: publishEventWarning, Message: message})
			}
			return writeResult(output.stderr, clioutput.Text(message))
		},
		ConfigureBrowser: func(automated bool) { output.openURL = browserOpener(ctx, flags.Open, automated) },
		Demo:             output.setDemo, GuestDemo: output.setGuestDemo, GuestShare: output.setGuestShare, DemoPing: output.demoPing, Logf: output.logf,
	}
}

func (a *commandApp) newPublishCommand() *cobra.Command {
	f := a.flags
	cPublish := &cobra.Command{
		Use: "publish", Short: "Publish a local port or configured service.", GroupID: "start",
		Long: "Give a running HTTP server an HTTPS URL, or publish a service by its name in the project configuration. For HTTP, visitors normally need a sign-in, share link, or token. The built-in demo also works without a local app.",
	}
	a.leaf(cPublish, &f.Publish, func(call commandCall) error {
		return a.publish(call)
	})
	limits := applicationlimits.Limits{}
	cPublish.Flags().Lookup("concurrency").Usage += fmt.Sprintf(" Defaults to %d for HTTP and %d for TCP.", limits.Defaults(false).Concurrency, limits.Defaults(true).Concurrency)
	return cPublish
}

func (a *commandApp) publish(call commandCall) error {
	ctx, flags := call.ctx, a.flags
	flags.Publish.configArgs = configArgs(flags.NoConfig, flags.ConfigPath)
	if flags.Publish.Foreground && (flags.Publish.Install || flags.Publish.Detach) {
		return publisherCLIError("select only one of --foreground, --detach, or --install")
	}
	if flags.Publish.Detach && flags.Publish.Install {
		return publisherCLIError("--install and --detach cannot be combined")
	}
	if flags.Publish.Detach {
		if flags.Publish.EnrollmentKey == "-" {
			return publisherCLIError("--detach cannot read an enrollment key from stdin; use --publisher-identity or --publisher-credential-file")
		}
		if flags.Publish.Output != "human" {
			return publisherCLIError("--detach requires --output=human")
		}
		if flags.Publish.System || flags.Publish.ServiceName != "" || flags.Publish.SystemStateDir != "" || flags.Publish.ServerCAFile != "" {
			return publisherCLIError("--system, --service-name, --system-state-dir, and --server-ca-file require --install")
		}
		return detachPublish(ctx, a.argv, flags.Publish.StateDir, a.out, "tnl publish")
	}
	if flags.Publish.DetachedChild != "" {
		root, err := clientStateRoot(flags.Publish.StateDir)
		if err != nil {
			return err
		}
		var cleanup func()
		ctx, cleanup, err = detached.Serve(ctx, root, flags.Publish.DetachedChild)
		if err != nil {
			return err
		}
		defer cleanup()
	}
	if flags.Publish.Demo {
		if err := prepareDemoPublish(&flags.Publish, flags.ConfigPath, term.IsTerminal(int(os.Stdin.Fd()))); err != nil {
			return err
		}
	} else if err := a.preparePublish(ctx, call.command); err != nil {
		return err
	}
	call.started()
	return runPublish(ctx, flags.Publish, a.out, a.errOut)
}

func (a *commandApp) preparePublish(ctx context.Context, cmd *cobra.Command) error {
	flags := a.flags
	if flags.Publish.Install {
		selection, _, err := selectProjectConfiguration(ctx, *flags)
		if err != nil || selection.Path == "" {
			return err
		}
	} else if flags.Publish.PublisherCredentialFile != "" {
		server, err := invocation.PublisherCredentialFileServer(flags.Publish.ServerURL, flags.Publish.PublisherCredentialFile)
		if err != nil {
			return err
		}
		flags.Publish.ServerURL = server
	}
	root, err := commandStateRoot(cmd)
	if err != nil {
		return err
	}
	project, err := loadProjectConfiguration(ctx, *flags, root)
	if err != nil {
		return err
	}
	if flags.Publish.Install {
		return project.applyInstalledService(&flags.Publish)
	}
	return project.applyPublish(&flags.Publish)
}
