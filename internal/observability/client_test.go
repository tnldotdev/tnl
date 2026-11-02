package observability

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

func TestClientTraceLaunchAndIndependentAttempts(t *testing.T) {
	f := newLinkTraceFixture(t, 1)
	ctx := WithMetrics(t.Context(), f.owner)
	ctx, end := ClientOperation(ctx, "client.connections.launch")
	parent := WireTrace(ctx)
	environment := LaunchEnvironment(ctx, []string{"PATH=/bin", LaunchTraceparent + "=stale", "OTHER=value"})
	if len(environment) != 3 || environment[2] != LaunchTraceparent+"="+parent.TraceParent {
		t.Fatal("stale launch carrier survived")
	}
	child, finish := ClientOperation(ExtractLaunch(WithMetrics(t.Context(), f.owner), strings.TrimPrefix(environment[2], LaunchTraceparent+"=")), "connector.connections.startup")
	finish(nil)
	end(nil)
	_, finish = ClientOperation(Independent(child), "connector.connections.renew")
	finish(nil)
	spans := f.exported(t)
	launch, startup, renewal := spans["client.connections.launch"], spans["connector.connections.startup"], spans["connector.connections.renew"]
	if launch == nil || startup == nil || renewal == nil || !bytes.Equal(startup.ParentSpanId, launch.SpanId) || !bytes.Equal(startup.TraceId, launch.TraceId) {
		t.Fatal("launch lost parentage")
	}
	if len(renewal.ParentSpanId) != 0 || bytes.Equal(renewal.TraceId, startup.TraceId) || len(renewal.Links) != 1 || !bytes.Equal(renewal.Links[0].SpanId, startup.SpanId) {
		t.Fatal("renewal retained startup as a parent")
	}
	if got := LaunchEnvironment(context.Background(), environment); len(got) != 2 {
		t.Fatal("ambient stale parent forwarded")
	}
}

func TestClientTraceIPCParentIsPerRequestAndCanonical(t *testing.T) {
	f := newLinkTraceFixture(t, 1)
	base := WithMetrics(t.Context(), f.owner)
	ctx, finish := ClientOperation(base, "client.status")
	defer finish(nil)
	first := WireTrace(ctx).TraceParent
	pooled, wrong := ClientOperation(base, "client.wait")
	wrong(nil)
	for index, parents := range [][]string{{first}, {}, {first, first}, {strings.ToUpper(first)}, {first + "-extra"}} {
		r := httptest.NewRequest("POST", "/v1/connections/status", strings.NewReader(`{"secret":"private"}`))
		r = r.WithContext(pooled)
		r.Header["Traceparent"] = parents
		r.Header.Set("Baggage", "secret=value")
		r.Header.Set("Tracestate", "secret=value")
		LocalRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sc := trace.SpanContextFromContext(r.Context())
			if index == 0 && sc.TraceID() != trace.SpanContextFromContext(ctx).TraceID() {
				t.Error("valid IPC parent lost")
			}
			if index != 0 && sc.TraceID() == trace.SpanContextFromContext(ctx).TraceID() {
				t.Error("invalid IPC parent retained")
			}
			if sc.TraceID() == trace.SpanContextFromContext(pooled).TraceID() {
				t.Error("pooled parent leaked into IPC")
			}
			w.WriteHeader(204)
		})).ServeHTTP(httptest.NewRecorder(), r)
	}
	// flush the real queue; repeated IPC operations deliberately have the same name.
	if err := f.owner.ForceFlush(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if bytes.Contains(f.payload, []byte("secret")) {
		t.Fatal("IPC payload exported")
	}
	count := 0
	for _, span := range f.spans {
		if span.Name == "connector.connections.status" {
			count++
		}
	}
	if count != 5 {
		t.Fatalf("got %d IPC spans", count)
	}
}

func TestClientTraceIPCPanicDoesNotInventSuccessOrExportCause(t *testing.T) {
	f := newLinkTraceFixture(t, 1)
	request := httptest.NewRequest("POST", "/v1/prepare", nil).WithContext(WithMetrics(t.Context(), f.owner))
	panicked := false
	func() {
		defer func() {
			if recover() == "secret panic" {
				panicked = true
			}
		}()
		LocalRequests(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("secret panic") })).ServeHTTP(httptest.NewRecorder(), request)
	}()
	if !panicked {
		t.Fatal("IPC instrumentation changed panic control flow")
	}
	span := f.exported(t)["native.app.prepare"]
	if span == nil || span.Status.GetMessage() != "error" {
		t.Fatal("interrupted IPC recorded success")
	}
	for _, attr := range span.Attributes {
		if attr.Key == string(HTTPStatus.Key()) {
			t.Fatal("unsent response acquired a status")
		}
	}
}

func TestClientTracePreparedReadAndPreparationHaveDistinctOperations(t *testing.T) {
	f := newLinkTraceFixture(t, 1)
	for _, path := range []string{"/v1/connections/prepare", "/v1/connections/prepared"} {
		request := httptest.NewRequest("POST", path, nil).WithContext(WithMetrics(t.Context(), f.owner))
		LocalRequests(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(httptest.NewRecorder(), request)
	}
	spans := f.exported(t)
	if spans["connector.connections.prepare"] == nil || spans["connector.connections.read"] == nil {
		t.Fatal("async preparation or synchronous prepared read lost its operation")
	}
}
