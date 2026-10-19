package observability

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// APIRequests records matched route patterns, never URLs or resource IDs. wrap
// the router so authentication and parameter-binding failures are counted too.
func (m *Metrics) APIRequests(surface string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithMetrics(r.Context(), m)
		ctx = propagation.TraceContext{}.Extract(ctx, propagation.HeaderCarrier(r.Header))
		ctx, span := m.tracer().Start(ctx, "tnl."+surface+".request", trace.WithSpanKind(trace.SpanKindServer))
		defer span.End()
		decision := &atomic.Bool{}
		r = r.WithContext(context.WithValue(ctx, decisionKey{}, decision))
		started := time.Now()
		response := &controlResponseWriter{ResponseWriter: w, status: http.StatusOK}
		m.apiInFlight.WithLabelValues(surface).Inc()
		defer func() {
			m.apiInFlight.WithLabelValues(surface).Dec()
			operation := r.Pattern
			if operation == "" || operation == "/" {
				operation = "unmatched"
			}
			outcome := APIRequestSuccess
			switch {
			case errors.Is(r.Context().Err(), context.DeadlineExceeded):
				outcome = APIRequestDeadlineExceeded
			case r.Context().Err() != nil:
				outcome = APIRequestCanceled
			case response.status >= 500:
				outcome = APIRequestServerError
			case response.status >= 400:
				outcome = APIRequestClientError
			case decision.Load():
				outcome = APIRequestDenied
			}
			span.SetName(surface + " " + operation)
			span.SetAttributes(attribute.String("http.route", operation), attribute.Int("http.response.status_code", response.status))
			finishSpan(span, string(outcome))
			m.ObserveAPIRequest(surface, operation, outcome, time.Since(started))
		}()
		next.ServeHTTP(response, r)
	})
}

type decisionKey struct{}

// AuthorizationDecision records the semantic result separately from HTTP status.
// a valid HTTP 200 response may still deny access. operation is a compiled name.
func AuthorizationDecision(ctx context.Context, operation string, allowed bool) {
	result := "denied"
	if allowed {
		result = "allowed"
	} else if denied, ok := ctx.Value(decisionKey{}).(*atomic.Bool); ok {
		denied.Store(true)
	}
	trace.SpanFromContext(ctx).SetAttributes(attribute.String("authorization.decision", result))
	if m := FromContext(ctx); m != nil {
		m.authDecisions.WithLabelValues(operation, result).Inc()
	}
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
