package daemon

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

// setupSpan is a secretless projection, not an OTLP payload archive. durations
// are measured within one process; no stage subtracts clocks on different hosts.
type setupSpan struct {
	TraceID, SpanID, ParentID, VisitorID string
	Operation, Route, Outcome            string
	Started                              time.Time
	Duration                             time.Duration
}

func startSeparatedSetupTraces(t *testing.T, ctx context.Context, component string) context.Context {
	t.Helper()
	listener, err := net.Listen("tcp", ":9093")
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join("/results", component+"-setup-spans.jsonl"))
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	var mu sync.Mutex
	var spans []setupSpan
	var owner atomic.Pointer[observability.Metrics]
	encoder := json.NewEncoder(file)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/traces", func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
		var batch collectortrace.ExportTraceServiceRequest
		if err != nil || proto.Unmarshal(data, &batch) != nil {
			http.Error(w, "invalid trace batch", http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for _, resource := range batch.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				for _, span := range scope.Spans {
					if len(spans) >= 100_000 || span.EndTimeUnixNano < span.StartTimeUnixNano {
						t.Error("setup trace bound exceeded or invalid span timing")
						http.Error(w, "trace bound exceeded", http.StatusInsufficientStorage)
						return
					}
					row := setupSpan{TraceID: hex.EncodeToString(span.TraceId), SpanID: hex.EncodeToString(span.SpanId), ParentID: hex.EncodeToString(span.ParentSpanId),
						Operation: span.Name, Started: time.Unix(0, int64(span.StartTimeUnixNano)), Duration: time.Duration(span.EndTimeUnixNano - span.StartTimeUnixNano)}
					for _, value := range span.Attributes {
						switch value.Key {
						case string(observability.VisitorConnectionID.Key()):
							row.VisitorID = value.Value.GetStringValue()
						case string(observability.HTTPRoute.Key()):
							row.Route = value.Value.GetStringValue()
						case string(observability.OutcomeKey.Key()):
							row.Outcome = value.Value.GetStringValue()
						}
					}
					spans = append(spans, row)
					if err := encoder.Encode(row); err != nil {
						t.Errorf("save setup span: %v", err)
						http.Error(w, "trace write failed", http.StatusInsufficientStorage)
						return
					}
				}
			}
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /spans", func(w http.ResponseWriter, r *http.Request) {
		if metrics := owner.Load(); metrics != nil {
			if err := metrics.ForceFlush(r.Context()); err != nil {
				t.Error("setup evidence could not flush traces")
				http.Error(w, "trace flush failed", http.StatusServiceUnavailable)
				return
			}
			families, err := metrics.Gather()
			if err != nil {
				t.Error("setup evidence could not read export accounting")
				http.Error(w, "export accounting failed", http.StatusServiceUnavailable)
				return
			}
			for _, family := range families {
				switch family.GetName() {
				case "tnl_observability_queue_dropped_spans_total", "tnl_observability_export_lost_spans_total", "tnl_observability_export_failures_total":
					for _, metric := range family.Metric {
						if metric.GetCounter().GetValue() != 0 {
							t.Errorf("setup evidence lost telemetry: %s=%g", family.GetName(), metric.GetCounter().GetValue())
							http.Error(w, "incomplete setup evidence", http.StatusServiceUnavailable)
							return
						}
					}
				}
			}
		}
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(spans)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: time.Second}
	server.TLSConfig, err = staticServerTLS("/load/collector.pem", "/load/collector.key")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	t.Cleanup(func() { _ = server.Close(); <-done; _ = file.Close() })
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://localhost:9093/v1/traces")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE", "/load/roots.pem")
	// collector sockets are evidence-only. avoid racing an idle timeout against
	// the first export after the deliberate permission-aging pause.
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "Connection=close")
	t.Setenv("OTEL_TRACES_SAMPLER", "always_on")
	t.Setenv("OTEL_BSP_SCHEDULE_DELAY", "100")
	role := "client"
	for _, candidate := range []string{"control", "ingress", "relay", "publisher"} {
		if strings.HasPrefix(component, candidate) {
			role = candidate
			break
		}
	}
	ctx, metrics, err := observability.StartProcess(ctx, role)
	if err != nil {
		t.Fatal(err)
	}
	owner.Store(metrics)
	t.Cleanup(func() {
		if err := metrics.Shutdown(context.Background()); err != nil {
			t.Errorf("setup trace shutdown: %v", err)
		}
	})
	return ctx
}

func captureSeparatedSetupTraces(t *testing.T, name string) map[string][]setupSpan {
	t.Helper()
	// child CLI exporters share the collector but own their providers. leave one
	// export interval before flushing each fixture provider, outside measurement.
	time.Sleep(250 * time.Millisecond)
	result := make(map[string][]setupSpan)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: separatedRoots(t, "roots.pem"), ServerName: "localhost"}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	for _, component := range append(separatedServerRoles(), append(separatedPublisherComponents(), "visitor-1", "visitor-2", "visitor-3", "visitor-4")...) {
		response, err := integrationGET(t.Context(), client, "https://"+component+":9093/spans")
		if err != nil {
			t.Fatal(err)
		}
		var spans []setupSpan
		err = json.NewDecoder(io.LimitReader(response.Body, 64<<20)).Decode(&spans)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("read setup spans for %s: %v status=%d", component, err, response.StatusCode)
		}
		result[component] = spans
	}
	separatedResult(t, name+"-setup-spans", result)
	return result
}

type setupVisitorEvidence struct {
	Stages       map[string][]time.Duration `json:"stages"`
	ControlCalls map[string]int             `json:"control_calls"`
}

type setupEvidence struct {
	Visitors                 map[string]*setupVisitorEvidence `json:"visitors"`
	UnattributedControlCalls map[string]int                   `json:"unattributed_control_calls"`
}

func summarizeSetupSpans(spans map[string][]setupSpan, start, end time.Time) setupEvidence {
	result := setupEvidence{Visitors: make(map[string]*setupVisitorEvidence), UnattributedControlCalls: make(map[string]int)}
	traceVisitors := make(map[string]string)
	for _, rows := range spans {
		for _, row := range rows {
			if row.VisitorID != "" {
				traceVisitors[row.TraceID] = row.VisitorID
			}
		}
	}
	for component, rows := range spans {
		for _, row := range rows {
			if row.Started.Before(start) || !row.Started.Before(end) {
				continue
			}
			visitor := row.VisitorID
			if visitor == "" {
				visitor = traceVisitors[row.TraceID]
			}
			controlCall := strings.HasPrefix(component, "control") && row.Route != ""
			if visitor == "" {
				if controlCall {
					result.UnattributedControlCalls[row.Operation]++
				}
				continue
			}
			evidence := result.Visitors[visitor]
			if evidence == nil {
				evidence = &setupVisitorEvidence{Stages: make(map[string][]time.Duration), ControlCalls: make(map[string]int)}
				result.Visitors[visitor] = evidence
			}
			evidence.Stages[component+"/"+row.Operation] = append(evidence.Stages[component+"/"+row.Operation], row.Duration)
			if controlCall {
				evidence.ControlCalls[row.Operation]++
			}
		}
	}
	return result
}

func reportSeparatedSetupEvidence(t *testing.T, name string, start, end time.Time) setupEvidence {
	t.Helper()
	spans := captureSeparatedSetupTraces(t, name)
	evidence := summarizeSetupSpans(spans, start, end)
	separatedResult(t, name+"-setup-evidence", evidence)
	return evidence
}

func TestSetupEvidenceSeparatesVisitorRPCsFromUnattributedTraffic(t *testing.T) {
	start := time.Now()
	spans := map[string][]setupSpan{
		"ingress-a": {{TraceID: "visitor", VisitorID: "vc_one", Started: start, Operation: "ingress.visitor_authorization", Duration: time.Millisecond}},
		"control-a": {
			{TraceID: "visitor", Started: start, Operation: "private_ingress POST /stream", Route: "/stream", Duration: time.Millisecond},
			{TraceID: "background", Started: start, Operation: "private_ingress POST /renew", Route: "/renew"},
			{TraceID: "visitor", Started: start.Add(-time.Second), Operation: "outside", Route: "/stream"},
		},
	}
	result := summarizeSetupSpans(spans, start, start.Add(time.Second))
	visitor := result.Visitors["vc_one"]
	if len(result.Visitors) != 1 || visitor.ControlCalls["private_ingress POST /stream"] != 1 || len(visitor.ControlCalls) != 1 || result.UnattributedControlCalls["private_ingress POST /renew"] != 1 || len(visitor.Stages["ingress-a/ingress.visitor_authorization"]) != 1 {
		t.Fatalf("incorrect evidence attribution: %+v visitor=%+v", result, visitor)
	}
}
