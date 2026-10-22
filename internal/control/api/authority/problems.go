package authorityapi

import (
	"encoding/json"
	"errors"
	"net/http"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	problemtype "github.com/tnldotdev/tnl/internal/failure/problem"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func writeControlStateProblem(response http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrProjectManaged):
		writeProblem(response, http.StatusConflict, authorityv1.ProjectManaged, "resource is managed by project configuration; change the declaration and run tnl apply")
	case errors.Is(err, controlstate.ErrAuthorityInvalid):
		writeProblem(response, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid request")
	case errors.Is(err, controlstate.ErrTeamNotFound), errors.Is(err, controlstate.ErrMembershipNotFound), errors.Is(err, controlstate.ErrInvitationNotFound),
		errors.Is(err, controlstate.ErrDomainNotFound):
		writeProblem(response, http.StatusNotFound, authorityv1.NotFound, "resource not found")
	case errors.Is(err, controlstate.ErrAuthorityAccess):
		writeProblem(response, http.StatusForbidden, authorityv1.Forbidden, "operation is not authorized")
	case errors.Is(err, controlstate.ErrTeamNameUnavailable):
		writeProblem(response, http.StatusConflict, authorityv1.NameUnavailable, "team name unavailable")
	case errors.Is(err, controlstate.ErrMemberSlugRequired):
		writeProblem(response, http.StatusBadRequest, authorityv1.InvalidRequest, "member slug cannot be derived; provide member_slug")
	case errors.Is(err, controlstate.ErrAuthorityConflict), errors.Is(err, controlstate.ErrAuthorityIdempotency):
		writeProblem(response, http.StatusConflict, authorityv1.Conflict, "authority state conflict")
	default:
		requestID := writeProblem(response, http.StatusInternalServerError, authorityv1.Internal, "internal server error")
		operatorlog.ReportContext(observability.ResponseContext(response), failure.Operation(operation), failure.ServerAPIInternal, requestID, err)
	}
}

func decodeJSON(response http.ResponseWriter, request *http.Request, target any) error {
	request.Body = http.MaxBytesReader(response, request.Body, 64<<10)
	return httpjson.Decode(json.NewDecoder(request.Body), target)
}

func writeBearerProblem(response http.ResponseWriter) {
	response.Header().Set("WWW-Authenticate", `Bearer realm="tnl"`)
	writeProblem(response, http.StatusUnauthorized, authorityv1.Unauthenticated, "authentication required")
}

func notFound(response http.ResponseWriter, _ *http.Request) {
	writeProblem(response, http.StatusNotFound, authorityv1.NotFound, "resource not found")
}

func writeProblem(response http.ResponseWriter, status int, code authorityv1.ProblemCode, title string) string {
	return problemtype.Write(response, status, string(code), title, title)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	httpjson.Write(response, status, value)
}
