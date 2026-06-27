// Package serviceapi contains HTTP primitives shared by the private service APIs.
package serviceapi

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
)

const MaximumRequestBytes = 64 << 10

type CertificateIdentityFunc func(*x509.Certificate) (string, error)

func VerifiedIdentity(request *http.Request, identity CertificateIdentityFunc) (string, error) {
	if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 || len(request.TLS.VerifiedChains) == 0 {
		return "", errors.New("serviceapi: client certificate is not verified")
	}
	value, err := identity(request.TLS.PeerCertificates[0])
	if err != nil || !ValidIdentifiers(value) {
		return "", errors.New("serviceapi: client certificate identity is invalid")
	}
	return value, nil
}

func DecodeJSON(response http.ResponseWriter, request *http.Request, destination any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		WriteProblem(response, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, MaximumRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		WriteProblem(response, http.StatusBadRequest, "invalid_json", "Request body must be one JSON object matching the service schema")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		WriteProblem(response, http.StatusBadRequest, "invalid_json", "Request body must contain exactly one JSON value")
		return false
	}
	return true
}

func WriteJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(value); err != nil {
		panic(http.ErrAbortHandler)
	}
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
