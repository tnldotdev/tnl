package controlapi

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/problemtype"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func writeControlStateProblem(response http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrDNSAuthorityInvalid):
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid DNS authority request")
	case errors.Is(err, controlstate.ErrDNSAuthorityNotFound):
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "DNS authority not found")
	case errors.Is(err, controlstate.ErrDNSAuthorityIdempotency), errors.Is(err, controlstate.ErrDNSAuthorityWorkStale):
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "DNS authority state conflict")
	case errors.Is(err, controlstate.ErrPublicURLInvalid):
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
	case errors.Is(err, controlstate.ErrPublicURLNotFound), errors.Is(err, controlstate.ErrTeamNotFound):
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
	case errors.Is(err, controlstate.ErrPublicURLAccess):
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "public URL access denied")
	case errors.Is(err, controlstate.ErrPublicURLConflict):
		writeProblem(response, http.StatusConflict, controlv1.NameUnavailable, "public URL hostname is unavailable")
	case errors.Is(err, controlstate.ErrPublishRunOpen):
		writeProblem(response, http.StatusConflict, controlv1.PublishRunOpen, "public URL has an open publish run")
	case errors.Is(err, controlstate.ErrPublicURLNotEnabled):
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "public URL is not enabled")
	case errors.Is(err, controlstate.ErrPublicURLIdempotency), errors.Is(err, controlstate.ErrPublishRunIdempotency),
		errors.Is(err, controlstate.ErrPublishRunConflict), errors.Is(err, controlstate.ErrPublicURLMutationStale),
		errors.Is(err, controlstate.ErrPublicURLAuthority), errors.Is(err, controlstate.ErrPublishRunStale),
		errors.Is(err, controlstate.ErrPublishRunNotReady), errors.Is(err, controlstate.ErrPublicURLCertificate):
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "public URL state conflict")
	case errors.Is(err, controlstate.ErrCertificateIssuanceInvalid):
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid certificate issuance request")
	case errors.Is(err, controlstate.ErrCertificateIssuanceNotFound):
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "certificate issuance not found")
	case errors.Is(err, controlstate.ErrCertificateIssuanceIdempotency):
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "certificate issuance state conflict")
	case errors.Is(err, controlstate.ErrCertificateChallengeNotReady):
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "certificate challenge state conflict")
	case errors.Is(err, controlstate.ErrPublicURLCredential), errors.Is(err, controlstate.ErrPublishRunCredential):
		writeBearerProblem(response)
	case errors.Is(err, controlstate.ErrPublicURLCreationGated), errors.Is(err, controlstate.ErrPublishRunCreationGated),
		errors.Is(err, controlstate.ErrCertificateIssuanceGated):
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "operation is disabled")
	case errors.Is(err, controlstate.ErrInsufficientRelayServices):
		writeProblem(response, http.StatusServiceUnavailable, controlv1.PlacementUnavailable, "relay placement is unavailable")
	default:
		requestID := writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
		log.Printf("%s request_id=%s: %v", operation, requestID, err)
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
	requestID := newRequestID()
	details := map[string]any{}
	httpjson.WriteProblem(response, status, controlv1.Problem{
		Type: problemtype.URL(string(code)), Title: title,
		Status: status, Code: code, RequestId: requestID, Details: &details,
	})
	return requestID
}

func newRequestID() string {
	requestID, err := opaqueid.New("request_")
	if err != nil {
		return "request_unavailable"
	}
	return requestID
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	httpjson.Write(response, status, value)
}
