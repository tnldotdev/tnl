package main

import (
	"context"
	"io"

	publisherjob "github.com/tnldotdev/tnl/internal/client/service"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
)

// keep flag-selection assertions on the command adapter while exercising the
// canonical installation operation with the same fake control and executor.
func installBackgroundJob(ctx context.Context, registry *publisherjob.Registry, flags publishCommand, selection enrolledPublishSelection, background backgroundPublishFlags, input io.Reader, clients publisherjob.ClientFactory, installedID *string) error {
	return invocation.InstallBackgroundJob(ctx, registry, backgroundOptions(flags), invocation.EnrolledSelection{EnrollmentKey: selection.EnrollmentKey, PublisherID: selection.PublisherID, PublisherFile: selection.PublisherFile}, background.settings(), input, clients, installedID)
}
