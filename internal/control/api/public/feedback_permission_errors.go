package public

import (
	"context"
	"errors"
	"net/http"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func writeFeedbackProblem(ctx context.Context, w http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrVisitorSignIn):
		writeProblem(w, 401, controlv1.Unauthenticated, "feedback requires sign-in; sign in and retry")
	case errors.Is(err, controlstate.ErrFeedbackAccess), errors.Is(err, controlstate.ErrPreviewAccess), errors.Is(err, controlstate.ErrServiceAccess), errors.Is(err, controlstate.ErrVisitorPermission), errors.Is(err, authorization.ErrForbidden):
		writeProblem(w, 403, controlv1.Forbidden, "feedback permission denied")
	case errors.Is(err, controlstate.ErrFeedbackInvalid):
		writeControlStateProblem(ctx, w, operation, err)
	default:
		writeUnavailableProblem(ctx, w, failure.Operation(operation), "feedback authorization is unavailable; retry", failure.ServerAuthorityUnavailable, err)
	}
}
