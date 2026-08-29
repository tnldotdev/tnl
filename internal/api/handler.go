// Package api serves the core HTTP API.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/0xcadams/tnl/internal/auth"
	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/pkg/protocol/corev1"
)

const (
	capabilitiesPath     = "/v1/capabilities"
	tokenExchangePath    = "/v1/auth/token"
	requestIDHeader      = "X-Request-ID"
	maxCredentialBytes   = 128
	maxJSONRequestBytes  = 16 << 10
	maxJSONResponseBytes = 64 << 10
)

var (
	errInvalidJSON          = errors.New("api: invalid JSON request")
	errResponseTooLarge     = errors.New("api: JSON response exceeds limit")
	errUnsupportedMediaType = errors.New("api: unsupported media type")
)

// TokenExchanger exchanges a bootstrap token without exposing storage to HTTP.
type TokenExchanger interface {
	Exchange(context.Context, credentials.BootstrapToken) (auth.IssuedAccessToken, error)
}

type handler struct {
	capabilities corev1.Capabilities
	tokens       TokenExchanger
}

// NewHandler creates the core API handler without binding a listener.
func NewHandler(capabilities corev1.Capabilities, tokens TokenExchanger) http.Handler {
	return &handler{capabilities: capabilities, tokens: tokens}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := requestID(r)
	w.Header().Set(requestIDHeader, requestID)

	switch r.URL.Path {
	case capabilitiesPath:
		h.serveCapabilities(w, r, requestID)
	case tokenExchangePath:
		h.serveTokenExchange(w, r, requestID)
	default:
		writeProblem(w, requestID, http.StatusNotFound, corev1.NotFound, "Not found", "not-found")
	}
}

func (h *handler) serveCapabilities(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, requestID, http.MethodGet)
		return
	}

	body, err := marshalJSON(h.capabilities)
	if err != nil {
		writeInternalProblem(w, requestID)
		return
	}
	writeJSON(w, http.StatusOK, "application/json", body)
}

func (h *handler) serveTokenExchange(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	var request corev1.TokenExchangeRequest
	if err := decodeJSON(w, r, &request); err != nil {
		status, title, problemType := http.StatusBadRequest, "Invalid request", "invalid-request"
		var maxBytesError *http.MaxBytesError
		switch {
		case errors.As(err, &maxBytesError):
			status, title, problemType = http.StatusRequestEntityTooLarge, "Request body too large", "request-too-large"
		case errors.Is(err, errUnsupportedMediaType):
			status, title, problemType = http.StatusUnsupportedMediaType, "Unsupported media type", "unsupported-media-type"
		}
		writeProblem(w, requestID, status, corev1.InvalidArgument, title, problemType)
		return
	}
	if request.BootstrapToken == "" || len(request.BootstrapToken) > maxCredentialBytes {
		writeProblem(
			w, requestID, http.StatusBadRequest, corev1.InvalidArgument,
			"Invalid request", "invalid-request",
		)
		return
	}
	if h.tokens == nil {
		writeInternalProblem(w, requestID)
		return
	}
	issued, err := h.tokens.Exchange(r.Context(), credentials.BootstrapToken(request.BootstrapToken))
	if errors.Is(err, auth.ErrUnauthenticated) {
		writeProblem(
			w, requestID, http.StatusUnauthorized, corev1.Unauthenticated,
			"Unauthenticated", "unauthenticated",
		)
		return
	}
	if err != nil {
		writeInternalProblem(w, requestID)
		return
	}
	body, err := marshalJSON(corev1.TokenExchangeResponse{
		AccessToken:  issued.Token.String(),
		CredentialId: issued.CredentialID.String(),
		ExpiresAt:    issued.ExpiresAt,
		TokenType:    corev1.Bearer,
	})
	if err != nil {
		writeInternalProblem(w, requestID)
		return
	}
	writeJSON(w, http.StatusOK, "application/json", body)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errUnsupportedMediaType
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errInvalidJSON
	}
	return nil
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

func writeInternalProblem(w http.ResponseWriter, requestID string) {
	writeProblem(
		w, requestID, http.StatusInternalServerError, corev1.Internal,
		"Internal server error", "internal",
	)
}

func writeMethodNotAllowed(w http.ResponseWriter, requestID, allow string) {
	w.Header().Set("Allow", allow)
	writeProblem(
		w, requestID, http.StatusMethodNotAllowed, corev1.InvalidArgument,
		"Method not allowed", "method-not-allowed",
	)
}

func writeJSON(w http.ResponseWriter, status int, contentType string, body []byte) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
