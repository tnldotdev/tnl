package setup

import (
	"context"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// EnsurePublication uses an isolated setup store, not the operator's profile.
// the connector owner journal retains a pending secret before redemption and the
// resulting exact-URL signing identity before any privileged installation.
func EnsurePublication(ctx context.Context, store *clientstate.Store, operator publisheridentity.OwnerControl, control publisheridentity.NativeControl, authority publisheridentity.EnrollmentAuthority, server string, publicURL controlv1.PublicURL) (credentialfile.File, error) {
	_, identity, err := publisheridentity.EnsureOwner(ctx, store, operator, authority, publicURL)
	if err != nil {
		return credentialfile.File{}, err
	}
	saved, found, err := store.PublisherIdentity(ctx, identity.ClientId)
	if err != nil {
		return credentialfile.File{}, err
	}
	if !found {
		return credentialfile.File{}, publisheridentity.ErrScope
	}
	native, err := publisheridentity.NewNative(control, authority, identity, saved.SigningKey)
	if err != nil {
		return credentialfile.File{}, err
	}
	current, err := native.SavedPublicURL(ctx)
	if err != nil {
		return credentialfile.File{}, err
	}
	if current.Id != publicURL.Id || current.TeamId != publicURL.TeamId {
		return credentialfile.File{}, publisheridentity.ErrScope
	}
	return credentialfile.New(server, identity, saved.SigningKey)
}
