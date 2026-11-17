//go:build !js || !wasm

package identity

import (
	"context"
	"errors"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
)

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
