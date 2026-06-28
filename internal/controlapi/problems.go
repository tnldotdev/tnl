package controlapi

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func writeControlStateProblem(response http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrAuthorityInvalid):
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
	case errors.Is(err, controlstate.ErrMembershipNotFound), errors.Is(err, controlstate.ErrInvitationNotFound),
		errors.Is(err, controlstate.ErrDomainNotFound):
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
	case errors.Is(err, controlstate.ErrAuthorityAccess):
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "operation is not authorized")
	case errors.Is(err, controlstate.ErrAuthorityConflict), errors.Is(err, controlstate.ErrAuthorityIdempotency):
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "authority state conflict")
	case errors.Is(err, controlstate.ErrDNSAuthorityInvalid):
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid DNS authority request")
	case errors.Is(err, controlstate.ErrDNSAuthorityNotFound):
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "DNS authority not found")
	case errors.Is(err, controlstate.ErrDNSAuthorityIdempotency), errors.Is(err, controlstate.ErrDNSAuthorityFenced):
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "DNS authority state conflict")
	case errors.Is(err, controlstate.ErrRouteInvalid):
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
	case errors.Is(err, controlstate.ErrRouteNotFound), errors.Is(err, controlstate.ErrTeamNotFound):
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
	case errors.Is(err, controlstate.ErrRouteAccess):
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "route access denied")
	case errors.Is(err, controlstate.ErrRouteConflict):
		writeProblem(response, http.StatusConflict, controlv1.NameUnavailable, "route hostname is unavailable")
	case errors.Is(err, controlstate.ErrRouteIdempotency), errors.Is(err, controlstate.ErrRouteSessionIdempotency),
		errors.Is(err, controlstate.ErrRouteSessionConflict), errors.Is(err, controlstate.ErrRouteNotEnabled),
		errors.Is(err, controlstate.ErrRouteAuthority), errors.Is(err, controlstate.ErrRouteSessionStale),
		errors.Is(err, controlstate.ErrRouteSessionNotReady), errors.Is(err, controlstate.ErrRouteCertificate):
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "route state conflict")
	case errors.Is(err, controlstate.ErrCertificateIssuanceInvalid):
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid certificate issuance request")
	case errors.Is(err, controlstate.ErrCertificateIssuanceNotFound):
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "certificate issuance not found")
	case errors.Is(err, controlstate.ErrCertificateIssuanceIdempotency):
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "certificate issuance state conflict")
	case errors.Is(err, controlstate.ErrCertificateChallengeNotReady):
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "certificate challenge state conflict")
	case errors.Is(err, controlstate.ErrRouteCredential), errors.Is(err, controlstate.ErrRouteSessionCredential):
		writeBearerProblem(response)
	case errors.Is(err, controlstate.ErrRouteCreationGated), errors.Is(err, controlstate.ErrRouteSessionCreationGated),
		errors.Is(err, controlstate.ErrCertificateIssuanceGated):
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "operation is disabled")
	case errors.Is(err, controlstate.ErrInsufficientRelayServices):
		writeProblem(response, http.StatusServiceUnavailable, controlv1.PlacementUnavailable, "relay placement is unavailable")
	default:
		log.Printf("%s: %v", operation, err)
		writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
	}
}

func decodeJSON(response http.ResponseWriter, request *http.Request, target any) error {
	request.Body = http.MaxBytesReader(response, request.Body, 64<<10)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request body contains trailing content")
	}
	return nil
}

func writeBearerProblem(response http.ResponseWriter) {
	response.Header().Set("WWW-Authenticate", `Bearer realm="tnl"`)
	writeProblem(response, http.StatusUnauthorized, controlv1.Unauthenticated, "authentication required")
}

func writeProblem(response http.ResponseWriter, status int, code controlv1.ProblemCode, title string) {
	requestID, err := opaqueid.New("request_")
	if err != nil {
		requestID = "request_unavailable"
	}
	details := map[string]any{}
	writeJSON(response, status, controlv1.Problem{
		Type: "https://tnl.dev/problems/" + string(code), Title: title,
		Status: status, Code: code, RequestId: requestID, Details: &details,
	})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(value); err != nil {
		panic(http.ErrAbortHandler)
	}
}
