package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/tnldotdev/tnl/internal/client/supervisor"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func runPrivatePublish(ctx context.Context, flags publishCommand, output, diagnostics io.Writer) error {
	if flags.Install && flags.Output != "" && flags.Output != publishOutputHuman {
		return publisherCLIError("--install requires --output=human")
	}
	protocol, err := privatePublishProtocol(flags.Protocol)
	if err != nil {
		return err
	}
	if protocol == controlv1.ServiceProtocolHTTP && !flags.service || flags.Demo {
		return publisherCLIError("private HTTP requires a configured service without publicURL; select tcp, mysql, or postgres for an opaque target")
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
		Starting: func() { detachedPublicationStarting(ctx) }, Ready: func() { detachedPublicationReady(ctx) },
		Installed: func(jobs []supervisor.Job, selected string) error {
			return renderSystemJobs(output, "tnl publish", jobs, selected)
		},
		Event: func(event invocation.ServiceEvent) error {
			if flags.Output == publishOutputNDJSON {
				return json.NewEncoder(output).Encode(struct {
					SchemaVersion int    `json:"schema_version"`
					Type          string `json:"type"`
					ServiceID     string `json:"service_id"`
					Name          string `json:"name,omitempty"`
					Target        string `json:"target"`
				}{1, event.State, event.ServiceID, event.Name, event.Target})
			}
			return writeHumanFrame(diagnostics, "tnl publish", event.State, "", clioutput.Fields(clioutput.Field{Label: "service ID", Value: event.ServiceID}, clioutput.Field{Label: "name", Value: event.Name}, clioutput.Field{Label: "endpoint", Value: net.JoinHostPort(event.Hostname, strconv.Itoa(event.Port))}, clioutput.Field{Label: "visitor TLS", Value: "verified native TLS"}, clioutput.Field{Label: "target", Value: event.Target}))
		},
	}
}

func privateOptions(flags publishCommand) invocation.ServiceOptions {
	return invocation.ServiceOptions{PublicOptions: publicOptions(flags), Protocol: flags.Protocol, ConfiguredPrivate: flags.service, TargetTLS: flags.TargetTLS, EnrollmentKey: flags.EnrollmentKey, PublisherIdentityID: flags.PublisherIdentityID, PublisherCredentialFile: flags.PublisherCredentialFile, EnrollmentInput: os.Stdin, Install: flags.Install, System: flags.System, ServiceName: flags.ServiceName, SystemStateDir: flags.SystemStateDir, ServerCAFile: flags.ServerCAFile}
}

func captureServiceTargetTrust(ctx context.Context, flags publishCommand, protocol controlv1.ServiceProtocol, target string) (*targettrust.Snapshot, error) {
	return invocation.CaptureServiceTargetTrust(ctx, privateOptions(flags), protocol, target)
}
