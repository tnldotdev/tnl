package main

import (
	"context"
	"io"

	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
)

// keep flag-selection assertions on the command adapter while exercising the
// canonical installation operation with the same fake control and executor.
func installBackgroundJob(ctx context.Context, registry *installedjobs.Registry, flags publishCommand, selection enrolledPublishSelection, background backgroundPublishFlags, input io.Reader, clients installedjobs.ClientFactory, installedID *string) error {
	return invocation.InstallBackgroundJob(ctx, registry, backgroundOptions(flags), invocation.EnrolledSelection{EnrollmentKey: selection.EnrollmentKey, PublisherIdentityID: selection.PublisherIdentityID, PublisherCredentialFile: selection.PublisherCredentialFile}, background.settings(), input, clients, installedID)
}
