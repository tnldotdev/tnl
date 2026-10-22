package native

import (
	"context"
	"encoding/json"
	"errors"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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
func EnsureOwner(ctx context.Context, state *clientstate.Store, control OwnerControl, authority EnrollmentAuthority, route controlv1.PublicURL) (*Native, authorityv1.PublisherEnrollmentResult, error) {
	if state == nil || control == nil || authority == nil || route.Ephemeral || route.LifecycleState != controlv1.Enabled || !route.Purpose.Valid() || !opaqueid.Valid(route.Id, opaqueid.PublicURLPrefix) || route.TeamId == "" {
		return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
	}
	scope := "owner-url:" + route.Id
	lock, err := state.LockPublisherSigningIdentity(ctx, scope)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	}
	defer lock.Close()
	saved, found, err := state.SelectedPublisherIdentity(ctx, "project", scope)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	}
	if found {
		var identity authorityv1.PublisherEnrollmentResult
		if json.Unmarshal(saved.PublicDocument, &identity) != nil || identity.ClientId != saved.ID {
			return nil, identity, ErrScope
		}
		if identity.ClientId != "" {
			if identity.Kind != "saved_url" || identity.PublicUrlId == nil || *identity.PublicUrlId != route.Id || identity.TeamId != route.TeamId {
				return nil, identity, ErrScope
			}
			adapter, current, err := LoadNative(ctx, state, control, authority, identity.ClientId)
			if err != nil {
				return nil, current, err
			}
			if err := adapter.SelectRoute(route); err != nil {
				return nil, current, err
			}
			return adapter, current, nil
		}
	}
	pending, found, err := state.PendingPublisherEnrollmentForSelection(ctx, "project", scope)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	}
	if !found {
		enrollment, err := control.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: route.TeamId, PublicUrlId: &route.Id, Name: "tnl", Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled})
		if err != nil {
			return nil, authorityv1.PublisherEnrollmentResult{}, err
		}
		if enrollment.Kind != "saved_url" || enrollment.TeamId != route.TeamId || enrollment.PublicUrlId == nil || *enrollment.PublicUrlId != route.Id || enrollment.EnrollmentKey == "" || !opaqueid.Valid(enrollment.Id, opaqueid.PublisherEnrollmentPrefix) {
			return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
		}
		pending, err = savePendingEnrollment(ctx, state, "project", scope, enrollment.Id, enrollment.EnrollmentKey)
		if err != nil {
			return nil, authorityv1.PublisherEnrollmentResult{}, err
		}
	}
	adapter, identity, err := EnrollNative(ctx, state, control, authority, string(pending.EnrollmentSecret))
	if err != nil {
		return nil, identity, err
	}
	if identity.Kind != "saved_url" || identity.PublicUrlId == nil || *identity.PublicUrlId != route.Id || identity.TeamId != route.TeamId {
		return nil, identity, ErrScope
	}
	if err := adapter.SelectRoute(route); err != nil {
		return nil, identity, err
	}
	return adapter, identity, nil
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
func Resolve(ctx context.Context, state *clientstate.Store, control NativeControl, authority EnrollmentAuthority, enrollmentKey, publisherID string, adapter *Native) (*Native, error) {
	selections := 0
	if enrollmentKey != "" {
		selections++
	}
	if publisherID != "" {
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
	n, _, err := LoadNative(ctx, state, control, authority, publisherID)
	return n, err
}
