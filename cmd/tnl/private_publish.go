package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/tnldotdev/tnl/internal/client/background"
	"github.com/tnldotdev/tnl/internal/clioutput"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func runPrivatePublish(ctx context.Context, flags publishCommand, output, diagnostics io.Writer) error {
	if flags.Install && flags.Output != "" && flags.Output != publishOutputHuman {
		return publishOutputModeError("--install")
	}
	protocol, err := publishProtocol(flags.Protocol)
	if err != nil {
		return err
	}
	if protocol == controlv1.ServiceProtocolHTTP && !flags.service || flags.Demo {
		return publisherCLIError("HTTP service publication requires a configured binding; select tcp, mysql, or postgres for an opaque target")
	}
	if err := applyProtocolLimits(&flags.tunnelFlags, string(protocol)); err != nil {
		return err
	}
	if err := validateTCPPublishOptions(flags, protocol); err != nil {
		return err
	}
	if flags.System && !flags.Install || flags.ServiceName != "" && !flags.Install || flags.SystemStateDir != "" && !flags.Install || flags.ServerCAFile != "" && !flags.Install {
		return publisherCLIError("--system, --service-name, --system-state-dir, and --server-ca-file require --install")
	}
	options := privateOptions(flags)
	options.Authenticate = publisherAuthentication(diagnostics)
	if flags.Install {
		options.Installation, err = (systemStateFlags{System: flags.System, SystemStateDir: flags.SystemStateDir}).options()
		if err != nil {
			return err
		}
		if err := requireInstalledService(ctx, options.Installation, nil); err != nil {
			return err
		}
	}
	return invocation.PublishPrivate(ctx, options, privatePresentation(ctx, flags, output, diagnostics))
}

func privatePresentation(ctx context.Context, flags publishCommand, output, diagnostics io.Writer) *invocation.ServicePresentation {
	return &invocation.ServicePresentation{
		Installed: func(jobs []installedjobs.Job, selected string) error {
			return writeInstalledPublicationReceipt(output, jobs, selected)
		},
		Event: func(event invocation.ServiceEvent) error {
			var address string
			var connect []string
			if event.State == "provisioning" {
				background.Reconnecting(ctx)
			}
			if event.State == "ready" {
				if event.Public {
					address = net.JoinHostPort(event.Hostname, strconv.Itoa(event.Port))
					if event.Protocol == "http" {
						if event.Port == 443 {
							address = event.Hostname
						}
						address = "https://" + address
					}
				} else {
					connect = publishedConnectArgs(ctx, flags, event.ServiceID, false)
				}
				if err := background.Ready(ctx, background.Readiness{Target: event.Target, Address: address, ServiceID: event.ServiceID, ConnectCommand: connect}); err != nil {
					return err
				}
			}
			if flags.Output == publishOutputNDJSON {
				return json.NewEncoder(output).Encode(struct {
					SchemaVersion int    `json:"schema_version"`
					Type          string `json:"type"`
					ServiceID     string `json:"service_id"`
					Name          string `json:"name,omitempty"`
					Target        string `json:"target"`
				}{1, event.State, event.ServiceID, event.Name, event.Target})
			}
			if event.State != "ready" {
				return writeResult(diagnostics, clioutput.Line(event.Name+": "+event.State))
			}
			var blocks []clioutput.Block
			if event.Public {
				blocks = append(blocks, clioutput.Literal(address),
					clioutput.Text("Public and connector access. Visitors still need access."))
			} else {
				blocks = append(blocks, clioutput.Literal(guidanceCommand(connect)), clioutput.Line("Connector access only. TLS hostname: "+event.Hostname))
			}
			blocks = append(blocks, clioutput.Line("Forwarding to "+event.Target), clioutput.Text("Visitor TLS: verified native TLS. Ctrl+C to stop."))
			return writeResult(diagnostics, blocks...)
		},
	}
}

func publishedConnectArgs(ctx context.Context, flags publishCommand, selector string, configured bool) []string {
	args := append([]string{"tnl"}, flags.projectArgs...)
	args = append(args, "connect")
	server := flags.project.Config.Server
	if configured {
		// a configured service may also be a subcommand, such as "available".
		args = append(args, "start")
		if effective, err := flags.project.EffectiveService(selector); err == nil {
			server = effective.Server
		}
	}
	args = append(args, selector)
	if pin := suggestedServer(ctx, flags.ServerURL, server, os.Getenv("TNL_ACCESS_TOKEN"), flags.StateDir, nil); pin != "" {
		args = append(args, "--server", pin)
	}
	if flags.Team != "" {
		args = append(args, "--team", flags.Team)
	}
	if flags.StateDir != "" {
		args = append(args, "--state-dir", flags.StateDir)
	}
	return args
}

func privateOptions(flags publishCommand) invocation.ServiceOptions {
	return invocation.ServiceOptions{PublicOptions: publicOptions(flags), Protocol: flags.Protocol, ConfiguredPrivate: flags.service, TargetTLS: flags.TargetTLS, EnrollmentKey: flags.EnrollmentKey, PublisherIdentityID: flags.PublisherIdentityID, PublisherCredentialFile: flags.PublisherCredentialFile, EnrollmentInput: os.Stdin, Install: flags.Install, System: flags.System, ServiceName: flags.ServiceName, SystemStateDir: flags.SystemStateDir, ServerCAFile: flags.ServerCAFile, Traffic: flags.traffic}
}

func captureServiceTargetTrust(ctx context.Context, flags publishCommand, protocol controlv1.ServiceProtocol, target string) (*targettrust.Snapshot, error) {
	return invocation.CaptureServiceTargetTrust(ctx, privateOptions(flags), protocol, target)
}
