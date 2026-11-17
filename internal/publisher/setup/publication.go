package setup

import (
	"context"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// EnsurePublication uses an isolated setup store, not the operator's profile.
// owner journal retains a pending secret before redemption and the resulting
// exact-service signing identity before any privileged installation.
func EnsurePublication(ctx context.Context, store *clientstate.Store, operator publisheridentity.ServiceOwnerControl, control publisheridentity.NativeControl, authority publisheridentity.EnrollmentAuthority, server string, service controlv1.Service) (credentialfile.File, error) {
	if service.Ephemeral {
		return credentialfile.File{}, publisheridentity.ErrScope
	}
	trust, err := publisheridentity.ServiceTrust(service)
	if err != nil {
		return credentialfile.File{}, err
	}
	_, identity, err := publisheridentity.EnsureServiceOwner(ctx, store, operator, authority, service)
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
	current, err := native.SavedService(ctx)
	if err != nil {
		return credentialfile.File{}, err
	}
	if current.Id != service.Id || current.TeamId != service.TeamId || current.TrustRevision != service.TrustRevision || current.Protocol != service.Protocol || current.PublisherPool != service.PublisherPool || current.Ephemeral {
		return credentialfile.File{}, publisheridentity.ErrScope
	}
	if err := publisheridentity.MatchServiceDeclaration(current, string(service.Protocol), trust); err != nil {
		return credentialfile.File{}, err
	}
	return credentialfile.New(server, identity, saved.SigningKey)
}
