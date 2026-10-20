package observability

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

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
		decision := &atomic.Int32{}
		r = r.WithContext(context.WithValue(ctx, decisionKey{}, decision))
		started := time.Now()
		response := &controlResponseWriter{ResponseWriter: w, status: http.StatusOK, ctx: r.Context()}
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
			case decision.Load() == 3:
				outcome = APIRequestDraining
			case response.status >= 500:
				outcome = APIRequestServerError
			case response.status == http.StatusUnauthorized || response.status == http.StatusForbidden:
				outcome = APIRequestDenied
			case response.status >= 400:
				outcome = APIRequestClientError
			case decision.Load() == 1:
				outcome = APIRequestDenied
			case decision.Load() == 2:
				outcome = APIRequestNotAdmitted
			}
			span.SetName(surface + " " + operation)
			route := operation
			if _, template, ok := strings.Cut(operation, " "); ok {
				route = template
			}
			span.SetAttributes(HTTPRoute.String(route), HTTPMethod.String(httpMethod(r.Method)), HTTPStatus.Int(response.status), Component.String(surface))
			finishSpan(span, string(outcome))
			m.observeAPIRequest(surface, r.Method, route, outcome, time.Since(started))
		}()
		next.ServeHTTP(response, r)
	})
}

type decisionKey struct{}

// DrainingRequest marks an intentional process admission rejection, even when
// its retryable HTTP response is 503. it is not an infrastructure failure.
func DrainingRequest(ctx context.Context) {
	if decision, ok := ctx.Value(decisionKey{}).(*atomic.Int32); ok {
		decision.Store(3)
	}
}

// AuthorizationDecision records the semantic result separately from HTTP status.
// a valid HTTP 200 response may still deny access. operation is a compiled name.
func AuthorizationDecision(ctx context.Context, operation string, allowed bool) {
	result := "denied"
	if allowed {
		result = "allowed"
	} else if denied, ok := ctx.Value(decisionKey{}).(*atomic.Int32); ok {
		denied.Store(1)
	}
	outcome, _ := classifyResult(result)
	trace.SpanFromContext(ctx).SetAttributes(OutcomeKey.String(string(outcome)))
	if m := FromContext(ctx); m != nil {
		m.authDecisions.WithLabelValues(operation, result).Inc()
	}
}

// AuthorizationAdmission distinguishes a valid credential from capacity/run
// admission. an allowed visitor that was not admitted is not an access denial.
func AuthorizationAdmission(ctx context.Context, operation string, allowed, admitted bool) {
	if !allowed || admitted {
		AuthorizationDecision(ctx, operation, allowed)
		return
	}
	if decision, ok := ctx.Value(decisionKey{}).(*atomic.Int32); ok {
		decision.CompareAndSwap(0, 2)
	}
	trace.SpanFromContext(ctx).SetAttributes(OutcomeKey.String(string(Rejected)), Reason.String("not_admitted"))
	if m := FromContext(ctx); m != nil {
		m.authDecisions.WithLabelValues(operation, "not_admitted").Inc()
	}
}

type controlResponseWriter struct {
	http.ResponseWriter
	ctx         context.Context
	status      int
	wroteHeader bool
}

func (w *controlResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *controlResponseWriter) ObservabilityContext() context.Context { return w.ctx }

// ResponseContext lets existing problem adapters retain request correlation
// without retaining requests or changing every authored problem's signature.
func ResponseContext(w http.ResponseWriter) context.Context {
	for {
		if scoped, ok := w.(interface{ ObservabilityContext() context.Context }); ok {
			return scoped.ObservabilityContext()
		}
		wrapper, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return context.Background()
		}
		w = wrapper.Unwrap()
	}
}

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
