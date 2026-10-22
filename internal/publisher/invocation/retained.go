package invocation

import (
	"context"
	"errors"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type RetainedOptions struct{ StateDir, Server, Target, EnrollmentKey string }
type RetainedSelection struct{ Target, EnrollmentKey, PublisherID string }

func SelectRetained(ctx context.Context, options RetainedOptions) (RetainedSelection, error) {
	selection := RetainedSelection{EnrollmentKey: options.EnrollmentKey}
	address, err := target.NormalizePublicAddress(options.Target, controlv1.Http)
	if err != nil {
		return selection, err
	}
	selection.Target = address
	server, err := clientstate.CanonicalServer(options.Server)
	if err != nil {
		return selection, err
	}
	root, err := clientStateRoot(options.StateDir)
	if err != nil {
		return selection, err
	}
	database, err := clientstate.OpenWithOptions(ctx, root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		return selection, err
	}
	defer database.Close()
	profile, err := database.Server(ctx, server)
	if err != nil {
		return selection, err
	}
	if _, found, err := profile.ControlSession(ctx); err != nil {
		return selection, err
	} else if found {
		return selection, publisherCLIError("--enrolled requires a separate publisher-only state directory")
	}
	saved, found, err := profile.SelectedPublisherIdentity(ctx, "job", RetainedScope(address))
	if err != nil {
		return selection, err
	}
	if found {
		selection.EnrollmentKey, selection.PublisherID = "", saved.ID
	} else if options.EnrollmentKey == "" {
		return selection, failure.Wrap("load enrolled publication", failure.PublisherEnrollmentRequired, errors.New("publisher state is missing"))
	}
	return selection, nil
}
