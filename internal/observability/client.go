package observability

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
	"go.opentelemetry.io/otel/trace"
)

// LaunchTraceparent is a one-launch carrier, consumed before starting workers.
// it never belongs in a handle, project metadata, persisted job, or app payload.
const LaunchTraceparent = "TNL_TRACEPARENT"
const CLIShutdownTimeout = 250 * time.Millisecond

func LaunchEnvironment(ctx context.Context, environment []string) []string {
	out := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, LaunchTraceparent+"=") {
			out = append(out, entry)
		}
	}
	if parent := WireTrace(ctx).TraceParent; parent != "" {
		out = append(out, LaunchTraceparent+"="+parent)
	}
	return out
}

func ExtractLaunch(ctx context.Context, parent string) context.Context {
	return extractHTTPTrace(ctx, http.Header{"Traceparent": []string{parent}})
}

type schedulingLinkKey struct{}

// Independent keeps local ownership and cancellation, but later attempts are
// roots linked to the scheduling operation, never its indefinitely held child.
func Independent(ctx context.Context) context.Context {
	sc := trace.SpanContextFromContext(ctx)
	if sc.IsValid() {
		ctx = context.WithValue(ctx, schedulingLinkKey{}, trace.Link{SpanContext: sc.WithTraceState(trace.TraceState{})})
	}
	return trace.ContextWithSpanContext(ctx, trace.SpanContext{})
}

// LinkContext keeps the worker owner's values and cancellation. only scheduling
// IDs cross from the request; request identity and lifetime never become state.
func LinkContext(owner, scheduling context.Context) context.Context {
	return Independent(trace.ContextWithSpanContext(owner, trace.SpanContextFromContext(scheduling)))
}

// ClientOperation measures one finite client-owned boundary exactly once.
func ClientOperation(ctx context.Context, operation operationName, options ...trace.SpanStartOption) (context.Context, func(error)) {
	started := time.Now()
	ctx, end := Start(ctx, operation, options...)
	var once sync.Once
	return ctx, func(err error) {
		once.Do(func() {
			end(err)
			if m := FromContext(ctx); m != nil {
				m.clientOperations.With(Operation.Dimension(operation), OutcomeKey.Dimension(ErrorOutcome(err))).ObserveContext(ctx, time.Since(started).Seconds())
			}
		})
	}
}

// ClientCommand accepts only compiled parser commands. serving commands measure
// startup, renewal, recovery and cleanup in their lifecycle owners instead.
func ClientCommand(ctx context.Context, command string) (context.Context, func(error)) {
	var operation operationName
	switch command {
	case "apply":
		operation = "client.apply"
	case "status":
		operation = "client.status"
	case "wait":
		operation = "client.wait"
	case "connect available":
		operation = "client.connect.available"
	case "connect list":
		operation = "client.connect.list"
	case "connect stop <name>":
		operation = "client.connect.stop"
	case "connect remove <name>":
		operation = "client.connect.remove"
	case "auth status":
		operation = "client.auth.status"
	case "auth login", "auth login run":
		operation = "client.auth.login"
	case "auth login start":
		operation = "client.auth.start"
	case "auth login wait <operation-id>":
		operation = "client.auth.wait"
	case "auth login inspect <operation-id>":
		operation = "client.auth.inspect"
	case "auth login cancel <operation-id>":
		operation = "client.auth.cancel"
	case "auth logout":
		operation = "client.auth.logout"
	case "auth browser <url>":
		operation = "client.auth.browser"
	case "publisher enroll", "publisher enroll <public-url-id>":
		operation = "client.enroll"
	case "publisher setup":
		operation = "client.publisher.setup"
	case "service install", "service register":
		operation = "client.install"
	case "runtime endpoint", "runtime owner-endpoint":
		operation = "client.owner.launch"
	case "runtime connections start":
		operation = "client.connections.launch"
	case "runtime connections identity":
		operation = "client.connections.identity"
	case "runtime connections attach":
		operation = "client.connections.attach"
	case "runtime connections read":
		operation = "client.connections.read"
	case "runtime connections status":
		operation = "client.connections.status"
	case "runtime connections stop":
		operation = "client.connections.stop"
	case "runtime connections recover":
		operation = "client.connections.recover"
	case "runtime connections kube-credential":
		operation = "client.connections.credential"
	case "connect kube-credential":
		operation = "client.connections.credential"
	}
	if operation == "" {
		return ctx, func(error) {}
	}
	return ClientOperation(ctx, operation)
}

// LocalRequests traces only the private native IPC routes. no supplied path,
// capability, request body, or project name enters the observation.
func LocalRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		operation := localOperation(r.URL.Path)
		ctx := extractHTTPTrace(r.Context(), r.Header)
		if operation == "" {
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		ctx, end := ClientOperation(ctx, operation, trace.WithSpanKind(trace.SpanKindServer))
		response := &controlResponseWriter{ResponseWriter: w, status: 200, ctx: ctx}
		completed := false
		defer func() {
			if completed || response.wroteHeader {
				trace.SpanFromContext(ctx).SetAttributes(HTTPStatus.Int(response.status))
			}
			var err error
			if !completed {
				err = failure.Wrap("local publisher operation", failure.Unexpected, localHTTPError(0))
			} else if ctx.Err() != nil {
				err = ctx.Err()
			} else if response.status >= 400 {
				reason := failure.InvalidCommand
				if response.status >= 500 {
					reason = failure.ServerUnavailable
				} else if response.status == 401 || response.status == 403 {
					reason = failure.ServerDenied
				}
				err = failure.Wrap("local publisher operation", reason, localHTTPError(response.status))
			}
			end(err)
		}()
		next.ServeHTTP(response, r.WithContext(ctx))
		completed = true
	})
}

type localHTTPError int

func (localHTTPError) Error() string { return "local publisher operation failed" }

func localOperation(path string) operationName {
	switch path {
	case "/v1/health":
		return "native.app.health"
	case "/v1/capabilities":
		return "native.app.capability"
	case "/v1/prepare":
		return "native.app.prepare"
	case "/v1/register":
		return "native.app.register"
	case "/v1/leases":
		return "native.app.acquire"
	case "/v1/ad-hoc/register":
		return "native.app.open"
	case "/v1/renew":
		return "native.app.renew"
	case "/v1/unregister":
		return "native.app.unregister"
	case "/v1/status":
		return "native.app.status"
	case "/v1/events":
		return "native.app.events"
	case "/v1/check":
		return "native.app.check"
	case "/v1/connections/attach":
		return "connector.connections.attach"
	case "/v1/connections/status":
		return "connector.connections.status"
	case "/v1/connections/connect", "/v1/connections/prepare":
		return "connector.connections.prepare"
	case "/v1/connections/prepared":
		return "connector.connections.read"
	case "/v1/connections/stop":
		return "connector.connections.stop"
	case "/v1/connections/kube-credential":
		return "connector.connections.credential"
	}
	return ""
}

// InjectLocalTrace sends a canonical parent only, even without an exporter.
func InjectLocalTrace(ctx context.Context, header http.Header) {
	header.Del("Traceparent")
	header.Del("Tracestate")
	header.Del("Baggage")
	if parent := WireTrace(ctx).TraceParent; parent != "" && (tunnelv1.TraceContext{TraceParent: parent}).Validate() == nil {
		header.Set("Traceparent", parent)
	}
}

// ClientLifecycle is called at the authoritative transition, not by status or
// watch readers. bound listeners are observed separately by the SDK that binds.
func ClientLifecycle(ctx context.Context, event LifecycleEvent) {
	if event != EventRegistered && event != EventPublicationReady {
		return
	}
	if m := FromContext(ctx); m != nil {
		m.clientLifecycle.With(Event.Dimension(event)).Inc()
		_, finish := Start(Independent(ctx), "native.app.lifecycle", trace.WithAttributes(Event.Value(event)))
		finish(nil)
	}
}
