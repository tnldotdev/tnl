// Package serviceapi contains HTTP primitives shared by the private service APIs.
package serviceapi

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"

	"github.com/tnldotdev/tnl/internal/httpjson"
)

const MaximumRequestBytes = 64 << 10

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
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}{
		Type: "https://tnl.dev/problems/" + problemType, Title: strings.ReplaceAll(problemType, "_", " "),
		Status: status, Detail: detail,
	})
}

func MatchingPathValue(response http.ResponseWriter, request *http.Request, name, bodyValue string) bool {
	if bodyValue == request.PathValue(name) {
		return true
	}
	WriteProblem(response, http.StatusBadRequest, "invalid_request", "Path and request body identifiers do not match")
	return false
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
