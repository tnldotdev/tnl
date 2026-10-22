package main

import (
	"context"
	"io"

	"github.com/tnldotdev/tnl/internal/client/supervisor"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
)

// keep flag-selection assertions on the command adapter while exercising the
// canonical installation operation with the same fake control and executor.
func installBackgroundJob(ctx context.Context, registry *supervisor.Registry, flags publishCommand, selection enrolledPublishSelection, background backgroundPublishFlags, input io.Reader, clients supervisor.ClientFactory, installedID *string) error {
	return invocation.InstallBackgroundJob(ctx, registry, backgroundOptions(flags), invocation.EnrolledSelection{EnrollmentKey: selection.EnrollmentKey, PublisherIdentityID: selection.PublisherIdentityID, PublisherCredentialFile: selection.PublisherCredentialFile}, background.settings(), input, clients, installedID)
}
