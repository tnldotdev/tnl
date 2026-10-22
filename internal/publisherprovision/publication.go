package publisherprovision

import (
	"context"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// EnsurePublication uses an isolated setup store, not the operator's profile.
// the native owner journal retains a pending secret before redemption and the
// resulting exact-URL signing identity before any privileged installation.
func EnsurePublication(ctx context.Context, store *clientstate.Store, operator nativeauth.OwnerControl, control nativeauth.NativeControl, authority nativeauth.EnrollmentAuthority, server string, route controlv1.PublicURL) (credentialfile.File, error) {
	_, identity, err := nativeauth.EnsureOwner(ctx, store, operator, authority, route)
	if err != nil {
		return credentialfile.File{}, err
	}
	saved, found, err := store.PublisherSigningIdentity(ctx, "publisher:"+identity.ClientId)
	if err != nil {
		return credentialfile.File{}, err
	}
	if !found {
		return credentialfile.File{}, nativeauth.ErrScope
	}
	native, err := nativeauth.NewNative(control, authority, identity, saved.PrivateValue)
	if err != nil {
		return credentialfile.File{}, err
	}
	current, err := native.SavedURL(ctx)
	if err != nil {
		return credentialfile.File{}, err
	}
	if current.Id != route.Id || current.TeamId != route.TeamId {
		return credentialfile.File{}, nativeauth.ErrScope
	}
	return credentialfile.New(server, identity, saved.PrivateValue)
}
