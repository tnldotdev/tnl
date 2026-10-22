package proxy

import (
	"context"
	"net/http"
)

type readinessKey struct{}

// WithReadinessProbe marks a request only after publisher proof verification.
// the wire header alone never enables readiness behavior.
func WithReadinessProbe(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), readinessKey{}, true))
}

func IsReadinessProbe(r *http.Request) bool {
	return r != nil && r.Context().Value(readinessKey{}) == true
}
