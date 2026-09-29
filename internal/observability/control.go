package observability

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// APIRequests records matched route patterns, never URLs or resource IDs. Wrap
// the router so authentication and parameter-binding failures are counted too.
func (m *Metrics) APIRequests(surface string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		response := &controlResponseWriter{ResponseWriter: w, status: http.StatusOK}
		m.apiInFlight.WithLabelValues(surface).Inc()
		defer func() {
			m.apiInFlight.WithLabelValues(surface).Dec()
			operation := r.Pattern
			if operation == "" || operation == "/" {
				operation = "unmatched"
			}
			outcome := "success"
			switch {
			case errors.Is(r.Context().Err(), context.DeadlineExceeded):
				outcome = "deadline_exceeded"
			case r.Context().Err() != nil:
				outcome = "canceled"
			case response.status >= 500:
				outcome = "server_error"
			case response.status >= 400:
				outcome = "client_error"
			}
			m.ObserveAPIRequest(surface, operation, outcome, time.Since(started))
		}()
		next.ServeHTTP(response, r)
	})
}

type controlResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *controlResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *controlResponseWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.status, w.wroteHeader = status, status >= 200
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *controlResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}
