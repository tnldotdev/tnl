package oidcauth

import (
	"context"
	"errors"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
)

func observe(ctx context.Context, operation string) (context.Context, func(error)) {
	ctx, finish := observability.ControlOperation(ctx, operation)
	return ctx, func(err error) {
		// provider availability is not a rejected identity. preserve structured
		// causes for callers and export only owned failure classifications.
		switch {
		case errors.Is(err, ErrUnavailable):
			err = failure.Wrap(failure.Operation(operation), failure.ServerIdentityProviderUnavailable, err)
		case errors.Is(err, ErrUnauthenticated):
			err = failure.Wrap(failure.Operation(operation), failure.Authentication, err)
		}
		finish(err)
	}
}
