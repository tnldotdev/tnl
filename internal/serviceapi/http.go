// Package serviceapi provides HTTP helpers for the private service APIs.
package serviceapi

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/problemtype"
)

const MaximumRequestBytes = 64 << 10

// ProblemError describes a private service API failure without HTTP client or
// server details.
type ProblemError struct {
	Status int
	Type   string
	Title  string
	Detail string
}

func (e *ProblemError) Error() string {
	if e.Type != "" {
		return fmt.Sprintf("service API returned %d (%s): %s", e.Status, e.Type, e.Detail)
	}
	return fmt.Sprintf("service API returned HTTP %d", e.Status)
}

func NewProblemError(status int, problemType, detail string) *ProblemError {
	return &ProblemError{
		Status: status, Type: problemtype.URL(problemType),
		Title: strings.ReplaceAll(problemType, "_", " "), Detail: detail,
	}
}

func DecodeJSON(response http.ResponseWriter, request *http.Request, destination any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		WriteProblem(response, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, MaximumRequestBytes)
	reader := bufio.NewReader(request.Body)
	if !startsWithJSONObject(reader) {
		WriteProblem(response, http.StatusBadRequest, "invalid_json", "Request body must be one JSON object matching the service schema")
		return false
	}
	if err := httpjson.Decode(json.NewDecoder(reader), destination); err != nil {
		detail := "Request body must be one JSON object matching the service schema"
		if errors.Is(err, httpjson.ErrTrailingContent) {
			detail = "Request body must contain exactly one JSON value"
		}
		WriteProblem(response, http.StatusBadRequest, "invalid_json", detail)
		return false
	}
	return true
}

func startsWithJSONObject(reader *bufio.Reader) bool {
	for {
		character, err := reader.ReadByte()
		if err != nil {
			return false
		}
		if character == '{' {
			return reader.UnreadByte() == nil
		}
		if character != ' ' && character != '\t' && character != '\r' && character != '\n' {
			return false
		}
	}
}

func WriteJSON(response http.ResponseWriter, status int, value any) {
	httpjson.Write(response, status, value)
}

func WriteProblem(response http.ResponseWriter, status int, problemType, detail string) {
	WriteProblemError(response, NewProblemError(status, problemType, detail))
}

func WriteProblemError(response http.ResponseWriter, problem *ProblemError) {
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(problem.Status)
	_ = json.NewEncoder(response).Encode(struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}{
		Type: problem.Type, Title: problem.Title, Status: problem.Status, Detail: problem.Detail,
	})
}

// AuthenticateClusterRequest applies the private API's cache and authentication
// policy before dispatching a request to a role-specific router.
func AuthenticateClusterRequest(response http.ResponseWriter, request *http.Request, secrets BearerSecrets) bool {
	response.Header().Set("Cache-Control", "no-store")
	if secrets.Authenticate(request.Header) {
		return true
	}
	response.Header().Set("WWW-Authenticate", "Bearer")
	WriteProblem(response, http.StatusUnauthorized, "unauthenticated", "A valid cluster secret is required")
	return false
}

// WriteServiceError handles the shared private API error boundary. Callers
// supply only the role-specific detail for unexpected failures.
func WriteServiceError(
	response http.ResponseWriter,
	request *http.Request,
	err error,
	report func(error),
	detail string,
) bool {
	if err == nil {
		return false
	}
	if request.Context().Err() != nil {
		return true
	}
	var problem *ProblemError
	if errors.As(err, &problem) {
		WriteProblemError(response, problem)
		return true
	}
	report(err)
	WriteProblem(response, http.StatusInternalServerError, "internal", detail)
	return true
}

func ValidIdentifiers(values ...string) bool {
	for _, value := range values {
		if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
			return false
		}
	}
	return true
}

func Positive(value int64) (uint64, bool) {
	return uint64(value), value > 0
}

func Nonnegative(value int64) (uint64, bool) {
	return uint64(value), value >= 0
}
