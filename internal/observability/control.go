package observability

import (
	"net/http"
	"time"
)

// ControlRequests records matched route patterns, never URLs or route IDs.
func (m *Metrics) ControlRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		operation := r.Pattern
		if operation == "" {
			operation = "unmatched"
		}
		started := time.Now()
		response := &controlResponseWriter{ResponseWriter: w, status: http.StatusOK}
		m.controlInFlight.WithLabelValues(operation).Inc()
		defer func() {
			m.controlInFlight.WithLabelValues(operation).Dec()
			outcome := "success"
			switch {
			case r.Context().Err() != nil:
				outcome = "canceled"
			case response.status >= 500:
				outcome = "server_error"
			case response.status >= 400:
				outcome = "client_error"
			}
			m.ObserveControlRequest(operation, outcome, time.Since(started))
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
