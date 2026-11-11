package oidc

import (
	"context"
	"errors"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
)

func observe(ctx context.Context, operation observability.ServerOperation) (context.Context, func(error)) {
	ctx, finish := observability.ControlOperation(ctx, operation)
	return ctx, func(err error) {
		// provider availability is not a rejected identity. preserve structured
		// causes for callers and export only owned failure classifications.
		switch {
		case errors.Is(err, ErrUnavailable):
			err = failure.Wrap(failure.Operation(operation.String()), failure.ServerIdentityProviderUnavailable, err)
		case errors.Is(err, ErrUnauthenticated):
			err = failure.Wrap(failure.Operation(operation.String()), failure.Authentication, err)
		}
		finish(err)
	}
}
