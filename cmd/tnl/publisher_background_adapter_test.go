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
	payload, err := invocation.PrepareBackgroundInstallation(ctx, registry.Profile, backgroundOptions(flags), invocation.EnrolledSelection{EnrollmentKey: selection.EnrollmentKey, PublisherIdentityID: selection.PublisherIdentityID, PublisherCredentialFile: selection.PublisherCredentialFile}, background.settings(), input, clients)
	if err != nil {
		return err
	}
	identity, key, err := payload.Credential.Validate()
	if err != nil {
		return err
	}
	job, err := registry.Install(ctx, payload.Job, identity, key)
	if err == nil && installedID != nil {
		*installedID = job.ID
	}
	return err
}
