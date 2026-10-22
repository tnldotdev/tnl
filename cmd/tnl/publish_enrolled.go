package main

import (
	"context"
	"io"

	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type enrolledPublishSelection struct{ EnrollmentKey, PublisherIdentityID, PublisherCredentialFile string }

func runEnrolledPublish(ctx context.Context, flags publishCommand, selection enrolledPublishSelection, output *publishOutput, telemetry telemetryReporter, input io.Reader) error {
	options := invocation.EnrolledOptions{PublicOptions: publicOptions(flags), Protocol: flags.Protocol, TargetTLS: flags.TargetTLS, Enrolled: flags.Enrolled, WorkLimits: flags.workLimits, ReadinessPath: flags.publicationReadinessPath(), ServicePresentation: privatePresentation(ctx, flags, output.stdout, output.stderr)}
	options.Authenticate = publisherAuthentication(output.stderr)
	options.SelectProtocol = func(protocol controlv1.PublicURLServiceProtocol) (publisher.ApplicationLimits, error) {
		if err := selectPublishInspection(&flags, protocol); err != nil {
			return publisher.ApplicationLimits{}, err
		}
		if err := applyProtocolLimits(&flags.tunnelFlags, string(protocol)); err != nil {
			return publisher.ApplicationLimits{}, err
		}
		if err := validateTCPPublishOptions(flags, protocol); err != nil {
			return publisher.ApplicationLimits{}, err
		}
		return flags.limits(), nil
	}
	options.SelectPrivate = func(protocol controlv1.ServiceProtocol) (publisher.ApplicationLimits, error) {
		flags.Protocol, flags.service = string(protocol), true
		if err := applyProtocolLimits(&flags.tunnelFlags, string(protocol)); err != nil {
			return publisher.ApplicationLimits{}, err
		}
		if err := validateTCPPublishOptions(flags, protocol); err != nil {
			return publisher.ApplicationLimits{}, err
		}
		return flags.limits(), nil
	}
	presentation := publicationPresentation(ctx, flags, output, telemetry)
	presentation.Delegated = func() { output.delegatedLifecycle = true }
	return invocation.PublishEnrolled(ctx, options, invocation.EnrolledSelection{EnrollmentKey: selection.EnrollmentKey, PublisherIdentityID: selection.PublisherIdentityID, PublisherCredentialFile: selection.PublisherCredentialFile}, presentation, input)
}
