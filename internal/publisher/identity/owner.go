package identity

import (
	"context"
	"errors"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// OwnerControl uses a current control session only to issue enrollment. the
// resulting adapter authenticates publishing with its own key and exact grant.
type OwnerControl interface {
	CreatePublisherEnrollment(context.Context, controlv1.CreatePublisherEnrollmentRequest) (controlv1.PublisherEnrollment, error)
}

// NamespaceScope rejects exact-service and guest grants before an ad-hoc worker
// allocates anything. one fork belongs to one invocation and exact cleanup.
func (n *Native) NamespaceScope() error {
	if n == nil || n.identity.kind != "namespace" {
		return ErrScope
	}
	return nil
}

func (n *Native) Fork() (*Native, error) {
	if n == nil {
		return nil, ErrScope
	}
	copy, err := newNative(n.NativeControl, n.authority, n.identity, n.private)
	if err != nil {
		return nil, err
	}
	copy.selectedServiceID = n.selectedServiceID
	copy.allocationInvocation = n.allocationInvocation
	copy.allocatedServiceID = n.allocatedServiceID
	copy.allocationFinished = n.allocationFinished
	copy.deploymentAllocation = n.deploymentAllocation
	return copy.WithTraffic(n.traffic)
}

// ControlURL lets native-only callers keep certificate state on the same
// server as the adapter's explicit HTTP authentication boundary.
func (n *Native) ControlURL() string {
	return n.Services.ControlURL()
}

var ErrSelection = errors.New("select one publisher enrollment key, saved publisher ID, or native publisher")

// Resolve selects explicit scoped authentication without falling back to a
// control session or an arbitrary team namespace.
func Resolve(ctx context.Context, state *clientstate.Store, control NativeControl, authority EnrollmentAuthority, enrollmentKey, publisherIdentityID string, adapter *Native) (*Native, error) {
	selections := 0
	if enrollmentKey != "" {
		selections++
	}
	if publisherIdentityID != "" {
		selections++
	}
	if adapter != nil {
		selections++
	}
	if selections != 1 {
		return nil, ErrSelection
	}
	if adapter != nil {
		return adapter.Fork()
	}
	if enrollmentKey != "" {
		n, _, err := EnrollNative(ctx, state, control, authority, enrollmentKey)
		return n, err
	}
	n, _, err := LoadNative(ctx, state, control, authority, publisherIdentityID)
	return n, err
}
