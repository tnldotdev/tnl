package identity

import (
	"context"
	"errors"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// OwnerControl uses a current control session only to issue enrollment. the
// resulting adapter authenticates publishing with its own key and exact grant.
type OwnerControl interface {
	NativeControl
	CreatePublisherEnrollment(context.Context, controlv1.CreatePublisherEnrollmentRequest) (controlv1.PublisherEnrollment, error)
}

// EnsureOwner prepares a saved URL for an interactive owner or directory
// publisher. one server-scoped local lock protects enrollment and reuse. the
// short-lived pending secret is encrypted in client state, then replaced with
// the signing key after redemption; it never enters public metadata.
func EnsureOwner(ctx context.Context, state *clientstate.Store, control OwnerControl, authority EnrollmentAuthority, publicURL controlv1.PublicURL) (*Native, authorityv1.PublisherEnrollmentResult, error) {
	if state == nil || control == nil || authority == nil || publicURL.Ephemeral || publicURL.LifecycleState != controlv1.Enabled || !publicURL.Purpose.Valid() || !opaqueid.Valid(publicURL.Id, opaqueid.PublicURLPrefix) || publicURL.TeamId == "" {
		return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
	}
	return ensureSelectedEnrollment(ctx, state, control, authority, enrollmentSelection{
		kind: "saved_public_url", team: publicURL.TeamId, id: publicURL.Id, publicURL: &publicURL,
	})
}

// NamespaceScope rejects saved URL and guest grants before an ad-hoc worker
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
	copy, err := NewNative(n.NativeControl, n.authority, n.identity.enrollment(), n.private)
	if err != nil {
		return nil, err
	}
	return copy.WithTraffic(n.traffic)
}

// ControlURL lets native-only callers keep certificate state on the same
// server as the adapter's explicit HTTP authentication boundary.
func (n *Native) ControlURL() string {
	if n == nil {
		return ""
	}
	if client, ok := n.NativeControl.(interface{ ControlURL() string }); ok {
		return client.ControlURL()
	}
	return ""
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
