//go:build !js || !wasm

package identity

import (
	"context"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type ServiceOwnerControl interface {
	OwnerControl
	ServiceControl
}

// EnsureServiceOwner saves a pending enrollment before redemption, so
// response loss never issues a second grant or abandons the original key.
func EnsureServiceOwner(ctx context.Context, state *clientstate.Store, control ServiceOwnerControl, authority EnrollmentAuthority, service controlv1.Service) (*Native, authorityv1.PublisherEnrollmentResult, error) {
	if state == nil || control == nil || authority == nil || !service.Enabled || !opaqueid.Valid(service.Id, opaqueid.ServicePrefix) || service.TeamId == "" {
		return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
	}
	if _, err := ServiceTrust(service); err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	}
	return ensureSelectedEnrollment(ctx, state, control, NativeControl{Services: control}, authority, enrollmentSelection{kind: "service", team: service.TeamId, id: service.Id})
}
