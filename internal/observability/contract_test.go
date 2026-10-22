package observability

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestIdentityScopesDoNotCrossAuthenticationBoundaries(t *testing.T) {
	ctx := ReplaceIdentity(t.Context(), Identity{TeamID: "team-a", PublisherGroupID: "group-a", PublisherIdentityID: "publisher-a", DeploymentID: "deployment-a", ReplicaKey: "replica-a", ServiceID: "service-a"})
	child := NarrowIdentity(ctx, Identity{PublicURLID: "url-a"})
	id := IdentityFromContext(child)
	if id.ServiceID != "" || id.PublicURLID != "url-a" || id.ServiceKind != PublicURL || id.DeploymentID != "deployment-a" {
		t.Fatal(id)
	}
	other := NarrowIdentity(child, Identity{TeamID: "team-b", ServiceID: "service-b"})
	id = IdentityFromContext(other)
	if id.PublisherGroupID != "" || id.DeploymentID != "" || id.ReplicaKey != "" || id.PublisherIdentityID != "" || id.PublicURLID != "" || id.ServiceKind != Service {
		t.Fatal("cross-team scope inherited", id)
	}
	for _, invalid := range []Identity{{ServiceID: "service", PublicURLID: "url"}, {ServiceID: "service", ServiceKind: PublicURL}, {TeamID: strings.Repeat("x", 129)}} {
		if got := IdentityFromContext(ReplaceIdentity(child, invalid)); got != (Identity{}) {
			t.Fatal("invalid scope retained previous identity", got)
		}
	}
	if got := IdentityFromContext(ReplaceIdentity(child, Identity{})); got != (Identity{}) {
		t.Fatal("empty replacement did not clear scope")
	}
	if got := IdentityFromContext(NarrowIdentity(child, Identity{})); got.ServiceKind != 0 || got.PublicURLID != "" || got.DeploymentID != "deployment-a" {
		t.Fatal("narrow did not clear service", got)
	}
}

func TestOwnerResourceIsUniqueAndDoesNotInstallGlobals(t *testing.T) {
	previousMeter, previousTrace, previousErrors := otel.GetMeterProvider(), otel.GetTracerProvider(), otel.GetErrorHandler()
	first, second := New("client"), New("publisher")
	defer first.Shutdown(context.Background())
	defer second.Shutdown(context.Background())
	instance := func(m *Metrics) string {
		v, _ := m.resource.Set().Value(attribute.Key(ServiceInstanceID.Key()))
		return v.AsString()
	}
	if instance(first) == "" || instance(first) == instance(second) {
		t.Fatal("runtime instance is missing or shared")
	}
	for _, m := range []*Metrics{first, second} {
		attrs := m.resource.Attributes()
		if !containsAttribute(attrs, string(ServiceNamespace.Key()), "tnl") || !containsAttribute(attrs, string(ServiceName.Key()), "tnl") {
			t.Fatal(attrs)
		}
		for _, a := range attrs {
			if strings.HasPrefix(string(a.Key), "cloud.") {
				t.Fatal("unknown cloud fact invented")
			}
		}
	}
	if otel.GetMeterProvider() != previousMeter || otel.GetTracerProvider() != previousTrace || fmt.Sprintf("%p", otel.GetErrorHandler()) != fmt.Sprintf("%p", previousErrors) {
		t.Fatal("owner changed global SDK state")
	}
}

func TestInstrumentAllowlistDropsTraceOnlyAndUnrelatedDimensions(t *testing.T) {
	m := New("publisher")
	defer m.Shutdown(context.Background())
	m.publisherOperations.Record(t.Context(), .5, metric.WithAttributes(Operation.Value("connect"), OutcomeKey.Value(Success), TeamID.String("team"), VisitorConnectionID.String("secret-visitor"), HTTPRoute.String("secret-path"), attribute.String("unapproved", "secret")))
	text := metricsText(t, m)
	if strings.Contains(text, "secret") || !strings.Contains(text, `tnl_team_id="team"`) {
		t.Fatal("per-instrument allowlist failed", text)
	}
	for _, spec := range m.InstrumentDefinitions() {
		for _, key := range spec.Dimensions {
			defs := VocabularyAttributes()
			index := slices.IndexFunc(defs, func(d AttributeDefinition) bool { return d.Key == key })
			if index < 0 || defs[index].DimensionPolicy == PolicyTraceLog {
				t.Fatalf("%s permits undocumented or trace-only %s", spec.Name, key)
			}
		}
	}
}

func TestLifecycleReasonsRemainBoundedDimensions(t *testing.T) {
	m := New("standalone")
	defer m.Shutdown(context.Background())
	m.ObservePublisherExit(true)
	m.ObserveRelayStreamRejection("stale_assignment")
	m.AddAssignmentReplacements("failed_ready", 1)
	m.SetRelayLeases("secret-unbounded-state", 1)
	text := metricsText(t, m)
	for _, reason := range []string{"unexpected", "stale_assignment", "failed_ready"} {
		if !strings.Contains(text, `tnl_reason="`+reason+`"`) {
			t.Fatal("lifecycle reason was filtered", reason)
		}
	}
	if strings.Contains(text, "secret-unbounded-state") {
		t.Fatal("unknown lease state exported")
	}
}

func TestFiniteOperationsKeepParentsLinksSafeErrorsAndSingleRecording(t *testing.T) {
	m := New("publisher")
	defer m.Shutdown(context.Background())
	exporter := tracetest.NewInMemoryExporter()
	m.tracerProvider = sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	ctx, parent := m.tracer().Start(WithMetrics(t.Context(), m), "parent")
	link := trace.Link{SpanContext: parent.SpanContext()}
	child, finish := Start(ctx, "finite", trace.WithLinks(link))
	cause := errors.New("secret provider error")
	err := failure.Wrap("connect target", failure.Authentication, cause)
	finish(err)
	finish(nil)
	_, end := PublisherOperation(child, "connect")
	end(context.DeadlineExceeded)
	end(nil)
	parent.End()
	spans := exporter.GetSpans()
	if len(spans) != 3 || len(spans[0].Links) != 1 || spans[0].Parent.SpanID() != parent.SpanContext().SpanID() {
		t.Fatal("lost parent/link or duplicate finish", spans)
	}
	if !containsAttribute(spans[0].Attributes, string(ErrorType.Key()), string(failure.Authentication)) || !containsAttribute(spans[0].Attributes, string(OutcomeKey.Key()), Denied.String()) {
		t.Fatal("owned failure not classified", spans[0])
	}
	if strings.Contains(fmt.Sprint(spans), "secret") || !errors.Is(err, cause) {
		t.Fatal("cause lost or exported")
	}
	exportFailure := safeExportError("trace export failed", cause)
	if !errors.Is(exportFailure, cause) || strings.Contains(fmt.Sprintf("%v %+v %#v", exportFailure, exportFailure, exportFailure), "secret") {
		t.Fatal("export error lost cause or exposed it while formatting")
	}
	if !strings.Contains(metricsText(t, m), `tnl_publisher_operation_duration_seconds_count{tnl_operation="connect",tnl_outcome="timeout"} 1`) {
		t.Fatal("finite operation not recorded exactly once")
	}
	var absent *Metrics
	if err := absent.ForceFlush(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, noop := Start(t.Context(), "nil_owner")
	noop(cause)
}

func TestSDKDisabledIgnoresBrokenExporterSettingsAndRecordsNoApplicationData(t *testing.T) {
	c, err := ConfigFromEnv(func(key string) string {
		return map[string]string{"OTEL_SDK_DISABLED": "TRUE", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://secret.invalid", "OTEL_EXPORTER_OTLP_HEADERS": "bad secret", "OTEL_SERVICE_NAME": "secret"}[key]
	})
	if err != nil || !c.Disabled {
		t.Fatal(err)
	}
	m, err := newOwner("publisher", c)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown(context.Background())
	ctx := WithMetrics(t.Context(), m)
	_, end := PublisherOperation(ctx, "connect")
	end(nil)
	if strings.Contains(metricsText(t, m), "tnl_") {
		t.Fatal("disabled SDK recorded application metrics")
	}
}

func TestCompletedOperationContextUsesParent(t *testing.T) {
	m := New("control")
	defer m.Shutdown(context.Background())
	exporter := tracetest.NewInMemoryExporter()
	m.tracerProvider = sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	ctx, parent := m.tracer().Start(t.Context(), "request")
	m.ObserveOperationContext(ctx, "CreatePublishRun", context.Canceled, time.Millisecond)
	parent.End()
	spans := exporter.GetSpans()
	if len(spans) != 2 || spans[0].Parent.SpanID() != parent.SpanContext().SpanID() {
		t.Fatal(spans)
	}
}

func TestOTLPHTTPSRetriesTransientFailureWithinExportDeadline(t *testing.T) {
	var attempts atomic.Int64
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("secret receiver rejection"))
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer receiver.Close()
	m, err := newOwner("publisher", Config{SampleRatio: 1, QueueSize: 2, BatchSize: 1, BatchDelay: time.Hour, Traces: SignalConfig{Endpoint: receiver.URL + "/v1/traces", Timeout: time.Second, TLS: receiver.Client().Transport.(*http.Transport).TLSClientConfig.Clone()}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown(context.Background())
	_, finish := Start(WithMetrics(t.Context(), m), "retry_fixture")
	finish(nil)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := m.ForceFlush(ctx); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 2 {
		t.Fatal("transient export did not retry", attempts.Load())
	}
	if !strings.Contains(metricsText(t, m), `tnl_observability_export_failures_total{tnl_signal="traces"} 0`) {
		t.Fatal("successful retry counted as lost batch")
	}
}
