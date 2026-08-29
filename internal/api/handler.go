// Package api serves the core HTTP API.
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/0xcadams/tnl/pkg/protocol/corev1"
)

const (
	capabilitiesPath     = "/v1/capabilities"
	requestIDHeader      = "X-Request-ID"
	maxJSONResponseBytes = 64 << 10
)

var errResponseTooLarge = errors.New("api: JSON response exceeds limit")

type handler struct {
	capabilities corev1.Capabilities
}

// NewHandler creates the core API handler without binding a listener.
func NewHandler(capabilities corev1.Capabilities) http.Handler {
	return &handler{capabilities: capabilities}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := requestID(r)
	w.Header().Set(requestIDHeader, requestID)

	if r.URL.Path != capabilitiesPath {
		writeProblem(w, requestID, http.StatusNotFound, corev1.NotFound, "Not found", "not-found")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeProblem(
			w,
			requestID,
			http.StatusMethodNotAllowed,
			corev1.InvalidArgument,
			"Method not allowed",
			"method-not-allowed",
		)
		return
	}

	body, err := marshalJSON(h.capabilities)
	if err != nil {
		writeProblem(
			w,
			requestID,
			http.StatusInternalServerError,
			corev1.Internal,
			"Internal server error",
			"internal",
		)
		return
	}
	writeJSON(w, http.StatusOK, "application/json", body)
}

func requestID(r *http.Request) string {
	values := r.Header.Values(requestIDHeader)
	if len(values) == 1 && validRequestID(values[0]) {
		return values[0]
	}

	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "req_internal"
	}
	return "req_" + hex.EncodeToString(random[:])
}

func validRequestID(value string) bool {
	const prefix = "req_"
	if !strings.HasPrefix(value, prefix) || len(value) == len(prefix) || len(value) > len(prefix)+64 {
		return false
	}
	for _, char := range value[len(prefix):] {
		if (char < 'a' || char > 'z') &&
			(char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func marshalJSON(value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(body) > maxJSONResponseBytes {
		return nil, errResponseTooLarge
	}
	return body, nil
}

func writeProblem(
	w http.ResponseWriter,
	requestID string,
	status int,
	code corev1.ProblemCode,
	title string,
	problemType string,
) {
	body, err := marshalJSON(corev1.Problem{
		Type:      "https://tnl.dev/problems/" + problemType,
		Title:     title,
		Status:    status,
		Code:      code,
		RequestId: requestID,
		Details:   map[string]interface{}{},
	})
	if err != nil {
		http.Error(w, title, status)
		return
	}
	writeJSON(w, status, "application/problem+json", body)
}

func writeJSON(w http.ResponseWriter, status int, contentType string, body []byte) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
