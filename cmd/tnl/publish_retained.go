package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"regexp"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func retainedPublicationScope(target string) string {
	digest := sha256.Sum256([]byte(target))
	return "foreground:" + hex.EncodeToString(digest[:])
}

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
	target, err := normalizePublishTarget(flags.Target, controlv1.Http)
	if err != nil {
		return flags, err
	}
	flags.Target = target
	server, err := clientstate.CanonicalServer(flags.ServerURL)
	if err != nil {
		return flags, err
	}
	root, err := clientStateRoot(flags.StateDir)
	if err != nil {
		return flags, err
	}
	database, err := clientstate.OpenWithOptions(ctx, root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		return flags, err
	}
	defer database.Close()
	profile, err := database.Server(ctx, server)
	if err != nil {
		return flags, err
	}
	if _, found, err := profile.ControlSession(ctx); err != nil {
		return flags, err
	} else if found {
		return flags, publisherCLIError("--enrolled requires a separate publisher-only state directory")
	}
	saved, found, err := profile.SelectedPublisherIdentity(ctx, "job", retainedPublicationScope(target))
	if err != nil {
		return flags, err
	}
	if found {
		// once enrolled, even an expired or consumed environment key is ignored.
		flags.EnrollmentKey, flags.PublisherID = "", saved.ID
	} else if flags.EnrollmentKey == "" {
		return flags, failure.Wrap("load enrolled publication", failure.PublisherEnrollmentRequired, errors.New("publisher state is missing"))
	}
	return flags, nil
}

func retainPublication(ctx context.Context, profile *clientstate.Store, flags publishCommand, id string) error {
	if !flags.Enrolled {
		return nil
	}
	return profile.SelectPublisherIdentity(ctx, "job", retainedPublicationScope(flags.Target), id)
}
