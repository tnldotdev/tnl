package public

import (
	"encoding/json"
	"errors"
	"net/http"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	failureproblem "github.com/tnldotdev/tnl/internal/failure/problem"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func writeControlStateProblem(response http.ResponseWriter, operation string, err error) {
	// the peer has already ended this request. match the private API boundary:
	// do not turn its interrupted database work into a server failure response.
	if observability.ResponseContext(response).Err() != nil {
		return
	}
	switch {
	case errors.Is(err, controlstate.ErrProjectManaged):
		writeProblem(response, http.StatusConflict, controlv1.ProjectManaged, "resource is managed by project configuration; change the declaration and run tnl apply")
	case errors.Is(err, controlstate.ErrTrafficSelection):
		writeProblem(response, http.StatusBadRequest, controlv1.TrafficSelectionInvalid, "traffic selection is invalid or exceeds operator ceilings; lower the selected limits and retry")
	case errors.Is(err, controlstate.ErrVisitorSignIn):
		writeProblem(response, http.StatusUnauthorized, controlv1.Unauthenticated, "feedback requires sign-in; sign in and retry")
	case errors.Is(err, controlstate.ErrDNSAuthorityInvalid):
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid DNS authority request")
	case errors.Is(err, controlstate.ErrDNSAuthorityNotFound):
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "DNS authority not found")
	case errors.Is(err, controlstate.ErrDNSAuthorityIdempotency), errors.Is(err, controlstate.ErrDNSAuthorityWorkStale):
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "DNS authority state conflict")
	case errors.Is(err, controlstate.ErrPublicURLInvalid), errors.Is(err, controlstate.ErrShareInvalid), errors.Is(err, controlstate.ErrFeedbackInvalid):
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
	case errors.Is(err, controlstate.ErrPublicURLNotFound), errors.Is(err, controlstate.ErrTeamNotFound), errors.Is(err, controlstate.ErrPreviewNotFound), errors.Is(err, controlstate.ErrShareNotFound), errors.Is(err, controlstate.ErrFeedbackNotFound):
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
	case errors.Is(err, controlstate.ErrPublicURLAccess), errors.Is(err, controlstate.ErrPreviewAccess), errors.Is(err, controlstate.ErrFeedbackAccess):
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "public URL access denied")
	case errors.Is(err, controlstate.ErrGuestTrialSpent):
		writeProblem(response, http.StatusForbidden, controlv1.GuestTrialExhausted, "guest demo limit reached; run tnl auth login to continue")
	case errors.Is(err, controlstate.ErrPublicURLConflict):
		writeProblem(response, http.StatusConflict, controlv1.NameUnavailable, "public URL hostname is unavailable")
	case errors.Is(err, controlstate.ErrPublishRunOpen):
		writeProblem(response, http.StatusConflict, controlv1.PublishRunOpen, "public URL has an open publish run")
	case errors.Is(err, controlstate.ErrPublicURLNotEnabled):
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "public URL is not enabled")
	case errors.Is(err, controlstate.ErrShareLimit):
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "share limit reached; revoke an old share or wait for one to expire")
	case errors.Is(err, controlstate.ErrPublicURLIdempotency), errors.Is(err, controlstate.ErrPublishRunIdempotency), errors.Is(err, controlstate.ErrShareIdempotency), errors.Is(err, controlstate.ErrShareStale), errors.Is(err, controlstate.ErrFeedbackIdempotency), errors.Is(err, controlstate.ErrFeedbackState),
		errors.Is(err, controlstate.ErrPublishRunConflict), errors.Is(err, controlstate.ErrPublicURLMutationStale), errors.Is(err, controlstate.ErrPreviewStale),
		errors.Is(err, controlstate.ErrPublicURLAuthority), errors.Is(err, controlstate.ErrPublishRunStale),
		errors.Is(err, controlstate.ErrPublishRunNotReady), errors.Is(err, controlstate.ErrPublicURLCertificate):
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "public URL state conflict")
	case errors.Is(err, controlstate.ErrCertificateIssuanceInvalid):
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid certificate issuance request")
	case errors.Is(err, controlstate.ErrCertificateIssuanceNotFound):
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "certificate issuance not found")
	case errors.Is(err, controlstate.ErrCertificateIssuanceIdempotency):
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "certificate issuance state conflict")
	case errors.Is(err, controlstate.ErrPublishRunCredential), errors.Is(err, controlstate.ErrPublisherIdentity):
		writeBearerProblem(response)
	case errors.Is(err, controlstate.ErrPublicURLCreationGated), errors.Is(err, controlstate.ErrPublishRunCreationGated),
		errors.Is(err, controlstate.ErrCertificateIssuanceGated):
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "operation is disabled")
	case errors.Is(err, controlstate.ErrInsufficientRelayServices):
		writeProblem(response, http.StatusServiceUnavailable, controlv1.PlacementUnavailable, "relay placement is unavailable")
	default:
		requestID := writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
		operatorlog.ReportContext(observability.ResponseContext(response), failure.Operation(operation), failure.ServerAPIInternal, requestID, err)
	}
}

func decodeJSON(response http.ResponseWriter, request *http.Request, target any) error {
	return decodeJSONLimited(response, request, target, 64<<10)
}

func decodeJSONLimited(response http.ResponseWriter, request *http.Request, target any, limit int64) error {
	request.Body = http.MaxBytesReader(response, request.Body, limit)
	return httpjson.Decode(json.NewDecoder(request.Body), target)
}

func writeBearerProblem(response http.ResponseWriter) {
	response.Header().Set("WWW-Authenticate", `Bearer realm="tnl"`)
	writeProblem(response, http.StatusUnauthorized, controlv1.Unauthenticated, "authentication required")
}

func notFound(response http.ResponseWriter, _ *http.Request) {
	writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
}

func writeProblem(response http.ResponseWriter, status int, code controlv1.ProblemCode, title string) string {
	return failureproblem.Write(response, status, string(code), title, title)
}

func writeUnavailableProblem(response http.ResponseWriter, operation failure.Operation, title string, reason failure.Reason, err error) {
	requestID := writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, title)
	operatorlog.ReportContext(observability.ResponseContext(response), operation, reason, requestID, err)
}

func newRequestID() string { return failureproblem.NewRequestID() }

func writeJSON(response http.ResponseWriter, status int, value any) {
	httpjson.Write(response, status, value)
}
