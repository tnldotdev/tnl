package observability

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"
)

var disabledChild = flag.Bool("tnl-observability-disabled-child", false, "isolated disabled process owner regression")

func TestNativeDisabledProviderIgnoresAmbientEnvironment(t *testing.T) {
	if *disabledChild {
		before := strings.Join(os.Environ(), "\n")
		ctx, m, err := StartProcess(t.Context(), "standalone")
		if err != nil {
			t.Fatal("disabled owner failed to start", err)
		}
		_, finish := Start(ctx, "disabled.fixture")
		finish(nil)
		m.ObserveOperation("CreatePublishRun", nil, time.Millisecond)
		text := metricsText(t, m)
		if strings.Contains(text, "tnl_") || !strings.Contains(text, "go_goroutines") {
			t.Fatal("disabled owner must keep only passive runtime metrics")
		}
		if err := m.ForceFlush(ctx); err != nil {
			t.Fatal(err)
		}
		if err := m.Shutdown(ctx); err != nil {
			t.Fatal(err)
		}
		if strings.Join(os.Environ(), "\n") != before {
			t.Fatal("owner mutated process environment")
		}
		return
	}
	for _, setting := range []string{"OTEL_GO_X_CARDINALITY_LIMIT", "OTEL_TRACES_SAMPLER", "OTEL_METRIC_EXPORT_INTERVAL", "OTEL_RESOURCE_ATTRIBUTES"} {
		t.Run(setting, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestNativeDisabledProviderIgnoresAmbientEnvironment$", "-tnl-observability-disabled-child")
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "OTEL_") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "OTEL_SDK_DISABLED=TrUe", "OTEL_EXPORTER_OTLP_ENDPOINT=http://secret-export.invalid", setting+"=secret-malformed-config")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			stdout, err := cmd.Output()
			if err != nil || stderr.Len() != 0 || bytes.Contains(stdout, []byte("secret")) {
				t.Fatalf("disabled subprocess: %v stdout=%s stderr=%s", err, stdout, &stderr)
			}
		})
	}
}

func TestNativeOTLPExemplarsAndGaugeContract(t *testing.T) {
	for _, filter := range []string{"trace_based", "always_on"} {
		t.Run(filter, func(t *testing.T) {
			t.Setenv("OTEL_METRICS_EXEMPLAR_FILTER", filter)
			var mu sync.Mutex
			var payload collectormetrics.ExportMetricsServiceRequest
			receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
				if err != nil {
					t.Error(err)
				}
				mu.Lock()
				err = proto.Unmarshal(body, &payload)
				mu.Unlock()
				if err != nil {
					t.Error(err)
				}
				w.Header().Set("Content-Type", "application/x-protobuf")
			}))
			defer receiver.Close()
			m, err := newOwner("standalone", Config{Metrics: SignalConfig{Endpoint: receiver.URL, Timeout: time.Second, TLS: receiver.Client().Transport.(*http.Transport).TLSClientConfig.Clone()}, Interval: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			defer m.Shutdown(context.Background())
			sc := trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled})
			ctx := trace.ContextWithSpanContext(t.Context(), sc)
			dimensions := []attribute.KeyValue{Operation.Value("CreatePublishRun"), attribute.String("unapproved", "secret-attribute"), RequestID.String("secret-request"), ServiceID.String("secret-service"), attribute.Int(string(OutcomeKey.Key()), 42)}
			// bypass semantic helpers with direct SDK recording, including a wrong
			// value type and a valid key disallowed on this particular instrument.
			m.controlOperations.instrument.Record(ctx, .25, metric.WithAttributes(dimensions...))
			m.capacityRejections.instrument.Add(ctx, 1, metric.WithAttributes(attribute.String("unapproved", "secret-counter")))
			m.SetIngressStreams(4)
			m.SetIngressStreams(7)
			m.AddRelayStreams(3)
			m.AddRelayStreams(-1)
			m.publisherLease.Record(ctx, 1234)
			for _, instrument := range []metric.Int64UpDownCounter{m.publisherData.httpActive, m.publisherData.streamsActive, m.publisherData.connections} {
				options := metric.WithAttributes(ServiceID.String("service-fixture"), attribute.String("unapproved", "secret-active"))
				instrument.Add(ctx, 3, options)
				instrument.Add(ctx, -1, options)
			}
			if err := m.ForceFlush(t.Context()); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			seenExemplars, seenStateSums, seenActiveSums, seenGauges := 0, 0, 0, 0
			for _, resource := range payload.ResourceMetrics {
				for _, scope := range resource.ScopeMetrics {
					for _, point := range scope.Metrics {
						check := func(attrs []*commonpb.KeyValue, exemplars []*metricspb.Exemplar) {
							for _, a := range attrs {
								if a.Key != string(Operation.Key()) {
									t.Error("disallowed measurement dimension", a.Key)
								}
							}
							for _, e := range exemplars {
								seenExemplars++
								id, spanID := sc.TraceID(), sc.SpanID()
								if len(e.FilteredAttributes) != 0 || !bytes.Equal(e.TraceId, id[:]) || !bytes.Equal(e.SpanId, spanID[:]) {
									t.Error("exemplar leaked dropped dimensions or lost trace correlation", e)
								}
							}
						}
						switch point.Name {
						case "tnl_control_operation_duration_seconds":
							for _, p := range point.GetHistogram().GetDataPoints() {
								check(p.Attributes, p.Exemplars)
							}
						case "tnl_admission_rejections_total":
							for _, p := range point.GetSum().GetDataPoints() {
								check(p.Attributes, p.Exemplars)
							}
						case "tnl_ingress_backend_streams", "tnl_relay_visitor_stream_slots_occupied":
							seenStateSums++
							expected := float64(7)
							if point.Name == "tnl_relay_visitor_stream_slots_occupied" {
								expected = 2
							}
							sum := point.GetSum()
							if sum == nil || sum.IsMonotonic || sum.AggregationTemporality != metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE || len(sum.DataPoints) != 1 || sum.DataPoints[0].GetAsDouble() != expected {
								t.Error("absolute state differs from the receiver's non-monotonic cumulative sum contract", point)
							}
						case "tnl_publisher_lease_expiration_timestamp_seconds":
							seenGauges++
							g := point.GetGauge()
							if g == nil || len(g.DataPoints) != 1 || g.DataPoints[0].GetAsDouble() != 1234 {
								t.Error("synchronous gauge changed its OTLP type/value", point)
							}
						case "tnl_publisher_http_requests_active", "tnl_publisher_visitor_streams_active", "tnl_publisher_connections_active":
							seenActiveSums++
							// the hosted receiver admits these semantic gauges as
							// cumulative non-monotonic sums, never monotonic totals.
							sum := point.GetSum()
							if sum == nil || sum.IsMonotonic || sum.AggregationTemporality != metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE || len(sum.DataPoints) != 1 || sum.DataPoints[0].GetAsInt() != 2 {
								t.Fatal("publisher active sum changed its OTLP contract", point)
							}
							p := sum.DataPoints[0]
							if len(p.Attributes) != 1 || p.Attributes[0].Key != string(ServiceID.Key()) || p.Attributes[0].Value.GetStringValue() != "service-fixture" {
								t.Error("publisher sum lost scope or accepted a disallowed dimension", p)
							}
							check(nil, p.Exemplars)
						}
					}
				}
			}
			if seenExemplars < 5 || seenGauges != 1 || seenStateSums != 2 || seenActiveSums != 3 {
				t.Fatal("missing actual OTLP exemplar, gauge or active sum proof", seenExemplars, seenGauges, seenStateSums, seenActiveSums)
			}
			if strings.Contains(fmt.Sprint(&payload), "secret") {
				t.Fatal("rejected attribute escaped into actual OTLP payload")
			}
			t.Logf("decoded OTLP: filter=%s exemplars=%d filtered_attributes=0 trace_and_span_ids=preserved gauges=%d absolute_sums=%d scoped_active_sums=%d", filter, seenExemplars, seenGauges, seenStateSums, seenActiveSums)
		})
	}
}
