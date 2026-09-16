// Package serviceapi provides HTTP helpers for the private service APIs.
package serviceapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/tnldotdev/tnl/internal/httpjson"
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
		Status: status, Type: "https://tnl.dev/problems/" + problemType,
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
	if err := httpjson.Decode(json.NewDecoder(request.Body), destination); err != nil {
		detail := "Request body must be one JSON object matching the service schema"
		if errors.Is(err, httpjson.ErrTrailingContent) {
			detail = "Request body must contain exactly one JSON value"
		}
		WriteProblem(response, http.StatusBadRequest, "invalid_json", detail)
		return false
	}
	return true
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
