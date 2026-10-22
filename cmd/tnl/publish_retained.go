package main

import (
	"context"
	"os"
	"regexp"

	"github.com/tnldotdev/tnl/internal/publisher/invocation"
)

var pinnedPublisherImage = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[a-f0-9]{64}$`)

func validatePublisherImage(lookup func(string) (string, bool)) error {
	if image, present := lookup("TNL_IMAGE"); present && image != "" && (len(image) > 512 || !pinnedPublisherImage.MatchString(image)) {
		return publisherCLIError("TNL_IMAGE must be a published immutable image@sha256 digest")
	}
	return nil
}

// retained mode is explicit and fail-closed. an empty volume cannot turn an
// unattended container into an operator login or an arbitrary URL allocation.
func retainedPublishFlags(ctx context.Context, flags publishCommand) (publishCommand, error) {
	if err := validatePublisherImage(os.LookupEnv); err != nil {
		return flags, err
	}
	if flags.Install || flags.Detach || flags.Service != "" || flags.PublisherID != "" || flags.PublisherFile != "" || flags.Name != "" || flags.PublicURL != "" || flags.Team != "" || flags.AccessToken != "" || flags.Anonymous || flags.access != nil || len(flags.IP) != 0 || flags.Ephemeral || flags.Demo || flags.ServerURL == "" {
		return flags, publisherCLIError("--enrolled requires an explicit server and HTTP target; the saved grant owns policy and scope")
	}
	selected, err := invocation.SelectRetained(ctx, invocation.RetainedOptions{StateDir: flags.StateDir, Server: flags.ServerURL, Target: flags.Target, EnrollmentKey: flags.EnrollmentKey})
	if err != nil {
		return flags, err
	}
	flags.Target, flags.EnrollmentKey, flags.PublisherID = selected.Target, selected.EnrollmentKey, selected.PublisherID
	return flags, nil
}
