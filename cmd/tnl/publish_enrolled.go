package main

import (
	"context"
	"io"

	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type enrolledPublishSelection struct{ EnrollmentKey, PublisherIdentityID, PublisherCredentialFile string }

func runEnrolledPublish(ctx context.Context, flags publishCommand, selection enrolledPublishSelection, output *publishOutput, input io.Reader) error {
	options := invocation.EnrolledOptions{PublicOptions: publicOptions(flags), Protocol: flags.Protocol, TargetTLS: flags.TargetTLS, Enrolled: flags.Enrolled, Traffic: flags.traffic, ReadinessPath: flags.publicationReadinessPath(), ServicePresentation: privatePresentation(ctx, flags, output.stdout, output.stderr)}
	options.Authenticate = publisherAuthentication(output.stderr)
	options.SelectProtocol = func(protocol controlv1.ServiceProtocol) (applicationlimits.Limits, error) {
		if err := applyProtocolLimits(&flags.tunnelFlags, string(protocol)); err != nil {
			return applicationlimits.Limits{}, err
		}
		if err := validateTCPPublishOptions(flags, protocol); err != nil {
			return applicationlimits.Limits{}, err
		}
		return flags.limits(), nil
	}
	presentation := publicationPresentation(ctx, flags, output)
	presentation.Delegated = func() { output.delegatedLifecycle = true }
	return invocation.PublishEnrolled(ctx, options, invocation.EnrolledSelection{EnrollmentKey: selection.EnrollmentKey, PublisherIdentityID: selection.PublisherIdentityID, PublisherCredentialFile: selection.PublisherCredentialFile}, presentation, input)
}
