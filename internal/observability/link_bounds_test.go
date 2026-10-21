package observability

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/trace"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

type linkTraceFixture struct {
	owner   *Metrics
	mu      sync.Mutex
	spans   []*tracepb.Span
	payload []byte
}

// use the real process owner, queue, span limits, and OTLP/HTTP exporter rather
// than replacing the tracer provider with a synthetic test provider.
func newLinkTraceFixture(t *testing.T, ratio float64) *linkTraceFixture {
	t.Helper()
	f := &linkTraceFixture{}
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/traces" {
			t.Error("unexpected export path", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			t.Error(err)
			return
		}
		var request collectortrace.ExportTraceServiceRequest
		if err := proto.Unmarshal(body, &request); err != nil {
			t.Error(err)
			return
		}
		f.mu.Lock()
		f.payload = append(f.payload, body...)
		for _, resource := range request.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				f.spans = append(f.spans, scope.Spans...)
			}
		}
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	t.Cleanup(receiver.Close)
	owner, err := newOwner("control", Config{
		Traces:  SignalConfig{Endpoint: receiver.URL + "/v1/traces", Timeout: time.Second, TLS: receiver.Client().Transport.(*http.Transport).TLSClientConfig.Clone()},
		Sampler: "parentbased_traceidratio", SampleRatio: ratio, BatchDelay: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.owner = owner
	t.Cleanup(func() { _ = owner.Shutdown(context.Background()) })
	return f
}

func (f *linkTraceFixture) exported(t *testing.T) map[string]*tracepb.Span {
	t.Helper()
	if err := f.owner.ForceFlush(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if bytes.Contains(f.payload, []byte("secret")) {
		t.Fatal("link or HTTP payload escaped through the native OTLP exporter")
	}
	spans := make(map[string]*tracepb.Span)
	for _, span := range f.spans {
		if span.TraceState != "" || len(span.Events) != 0 {
			t.Fatal("unexpected vendor state or event payload", span.Name)
		}
		if _, exists := spans[span.Name]; exists {
			t.Fatal("duplicate span", span.Name)
		}
		spans[span.Name] = span
	}
	return spans
}

func TestNativeOTLPLinksAreBoundedAttributeFreeAndParentOnly(t *testing.T) {
	f := newLinkTraceFixture(t, 1)
	state, err := trace.ParseTraceState("private=secret-link-state")
	if err != nil {
		t.Fatal(err)
	}
	var links []trace.Link
	for i := range 12 {
		tid, _ := trace.TraceIDFromHex(fmt.Sprintf("%032x", i+1))
		sid, _ := trace.SpanIDFromHex(fmt.Sprintf("%016x", i+1))
		links = append(links, trace.Link{
			SpanContext: trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.TraceFlags(i % 2), Remote: i%2 == 0, TraceState: state}),
			Attributes:  []attribute.KeyValue{attribute.String("secret-key", "secret-link-payload"), attribute.String("tnl.team_id", "secret-untrusted-team")},
		})
	}
	parent := trace.ContextWithSpanContext(WithMetrics(t.Context(), f.owner), links[0].SpanContext)
	started := time.Now().Add(-time.Second)
	_, finish := Start(parent, "bounded.links", trace.WithNewRoot(), trace.WithSpanKind(trace.SpanKindConsumer), trace.WithTimestamp(started), trace.WithAttributes(Component.String("control")), trace.WithLinks(links[:6]...), trace.WithLinks(links[6:]...))
	finish(nil)
	// direct SDK links, including AddLink, prove that raw zero means no attributes
	// even when a caller does not use Start's vendor-state sanitizer.
	cleanContext := links[0].SpanContext.WithTraceState(trace.TraceState{})
	_, direct := f.owner.tracer().Start(WithMetrics(t.Context(), f.owner), "sdk.links", trace.WithLinks(trace.Link{SpanContext: cleanContext, Attributes: links[0].Attributes}))
	direct.AddLink(trace.Link{SpanContext: cleanContext, Attributes: links[0].Attributes})
	direct.End()
	spans := f.exported(t)
	span := spans["bounded.links"]
	if len(spans) != 2 || span == nil || span.Kind != tracepb.Span_SPAN_KIND_CONSUMER || span.StartTimeUnixNano != uint64(started.UnixNano()) || len(span.ParentSpanId) != 0 || span.TraceId == nil {
		t.Fatal("sanitizing links changed span start options")
	}
	component := false
	for _, attr := range span.Attributes {
		component = component || attr.Key == string(Component.Key()) && attr.Value.GetStringValue() == "control"
	}
	if !component || len(span.Links) != 8 || span.DroppedLinksCount != 4 {
		t.Fatal("span attributes or SDK link count changed", span)
	}
	for i, link := range span.Links {
		expected := links[i+4].SpanContext
		tid, sid := expected.TraceID(), expected.SpanID()
		if !bytes.Equal(link.TraceId, tid[:]) || !bytes.Equal(link.SpanId, sid[:]) || byte(link.Flags) != byte(expected.TraceFlags()) || link.TraceState != "" || len(link.Attributes) != 0 || link.DroppedAttributesCount != 2 {
			t.Fatal("link IDs/flags lost or SDK attribute/state policy violated", i, link)
		}
		if link.Flags&uint32(tracepb.SpanFlags_SPAN_FLAGS_CONTEXT_HAS_IS_REMOTE_MASK) == 0 || (link.Flags&uint32(tracepb.SpanFlags_SPAN_FLAGS_CONTEXT_IS_REMOTE_MASK) != 0) != expected.IsRemote() {
			t.Fatal("link remote-context flags changed", i, link.Flags)
		}
	}
	if direct := spans["sdk.links"]; direct == nil || len(direct.Links) != 2 || direct.Links[0].DroppedAttributesCount != 2 || direct.Links[1].DroppedAttributesCount != 2 || len(direct.Links[0].Attributes) != 0 || len(direct.Links[1].Attributes) != 0 {
		t.Fatal("raw SDK zero did not drop initial and late link attributes")
	}
	if links[0].SpanContext.TraceState().String() != state.String() || len(links[0].Attributes) != 2 {
		t.Fatal("Start mutated caller-owned links")
	}
	if text := metricsText(t, f.owner); strings.Contains(text, "secret") || strings.Contains(text, links[0].SpanContext.TraceID().String()) {
		t.Fatal("link correlation became a metric dimension")
	}
}

func TestNativeHTTPParentsAndWorkerLinksExcludeVisitorState(t *testing.T) {
	for _, sampled := range []bool{false, true} {
		for _, flags := range []string{"00", "01"} {
			t.Run(fmt.Sprintf("sampled=%t/remote=%s", sampled, flags), func(t *testing.T) {
				ratio := 0.0
				if sampled {
					ratio = 1
				}
				f := newLinkTraceFixture(t, ratio)
				forwarded := make(chan string, 1)
				sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Tracestate") != "" || r.Header.Get("Baggage") != "" {
						t.Error("owned HTTP forwarded visitor state or baggage")
					}
					forwarded <- r.Header.Get("Traceparent")
					w.WriteHeader(http.StatusNoContent)
				}))
				defer sink.Close()
				router := http.NewServeMux()
				router.HandleFunc("GET /work/{id}", func(w http.ResponseWriter, r *http.Request) {
					if trace.SpanContextFromContext(r.Context()).TraceState().Len() != 0 || baggage.FromContext(r.Context()).Len() != 0 {
						t.Error("HTTP carrier extracted visitor state or baggage")
					}
					state, _ := trace.ParseTraceState("private=secret-scheduling-state")
					scheduling := trace.ContextWithSpanContext(r.Context(), trace.SpanContextFromContext(r.Context()).WithTraceState(state))
					worker, finish := WorkerAttempt(scheduling, "dns.authority.attempt")
					f.owner.ObserveDatabaseQueryContext(worker, databaseFixtureOperations.Lookup("LockAppliedProject"), nil, time.Millisecond)
					finish(nil)
					request, err := http.NewRequestWithContext(r.Context(), "GET", sink.URL, nil)
					if err != nil {
						t.Error(err)
						return
					}
					request.Header = r.Header.Clone()
					response, err := OwnedHTTPClient(sink.Client(), "control").Do(request)
					if err != nil {
						t.Error(err)
						return
					}
					response.Body.Close()
					w.WriteHeader(http.StatusNoContent)
				})
				parent := "00-0123456789abcdef0123456789abcdef-0123456789abcdef-" + flags
				request := httptest.NewRequest("GET", "/work/secret-path?token=secret-query", nil)
				request.Header.Set("Traceparent", parent)
				request.Header.Set("Tracestate", "private=secret-visitor-state")
				request.Header.Set("Baggage", "tenant=secret-visitor-baggage")
				response := httptest.NewRecorder()
				f.owner.APIRequests("control", router).ServeHTTP(response, request)
				if response.Code != http.StatusNoContent {
					t.Fatal("request failed", response.Code)
				}
				wire := <-forwarded
				if (tunnelv1.TraceContext{TraceParent: wire}).Validate() != nil || wire[3:35] != parent[3:35] || (wire[53:] == "01") != sampled {
					t.Fatal("owned HTTP lost parent IDs or trusted remote sampling", wire)
				}
				spans := f.exported(t)
				if !sampled {
					if len(spans) != 0 {
						t.Fatal("remote flags overrode local sampling")
					}
					return
				}
				api, client, worker, query := spans["control GET /work/{id}"], spans["tnl.control.request"], spans["dns.authority.attempt"], spans["database.LockAppliedProject"]
				if len(spans) != 4 || api == nil || client == nil || worker == nil || query == nil {
					t.Fatal("missing API/worker/database/client trace")
				}
				if fmt.Sprintf("%x", api.TraceId) != parent[3:35] || fmt.Sprintf("%x", api.ParentSpanId) != parent[36:52] || !bytes.Equal(client.ParentSpanId, api.SpanId) || fmt.Sprintf("%x", client.SpanId) != wire[36:52] {
					t.Fatal("legitimate API/client parentage was changed")
				}
				if len(worker.ParentSpanId) != 0 || bytes.Equal(worker.TraceId, api.TraceId) || len(worker.Links) != 1 || !bytes.Equal(query.ParentSpanId, worker.SpanId) || !bytes.Equal(query.TraceId, worker.TraceId) {
					t.Fatal("worker root/link or database parentage was changed")
				}
				link := worker.Links[0]
				if !bytes.Equal(link.TraceId, api.TraceId) || !bytes.Equal(link.SpanId, api.SpanId) || byte(link.Flags) != byte(api.Flags) || link.TraceState != "" || len(link.Attributes) != 0 {
					t.Fatal("scheduling link was lost or carried payload", link)
				}
			})
		}
	}
}

func TestHTTPTraceParentRequiresSingleCanonicalBoundedValue(t *testing.T) {
	const parent = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
	state, _ := trace.ParseTraceState("private=secret-pooled-state")
	tid, _ := trace.TraceIDFromHex(parent[3:35])
	sid, _ := trace.SpanIDFromHex(parent[36:52])
	previous := trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceState: state})
	for _, values := range [][]string{nil, {""}, {parent, parent}, {parent + "," + parent}, {parent + " "}, {" " + parent}, {strings.ToUpper(parent)}, {"01" + parent[2:]}, {parent + "-secret"}, {strings.Repeat("s", 4096)}, {parent[:53] + "ff"}} {
		header := http.Header{"Traceparent": values, "Tracestate": {state.String()}, "Baggage": {"tenant=secret"}}
		ctx := extractHTTPTrace(trace.ContextWithSpanContext(t.Context(), previous), header)
		if sc := trace.SpanContextFromContext(ctx); sc.IsValid() || sc.TraceState().Len() != 0 {
			t.Fatal("invalid HTTP parent inherited pooled state")
		}
	}
	ctx := extractHTTPTrace(t.Context(), http.Header{"Traceparent": {parent}, "Tracestate": {state.String()}, "Baggage": {"tenant=secret"}})
	sc := trace.SpanContextFromContext(ctx)
	if sc.TraceID() != tid || sc.SpanID() != sid || !sc.IsRemote() || !sc.IsSampled() || sc.TraceState().Len() != 0 || baggage.FromContext(ctx).Len() != 0 {
		t.Fatal("canonical parent was lost or visitor state was retained", sc)
	}
}
