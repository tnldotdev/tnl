// package workerobservation records actual worker spans and operator diagnostics
// through a process-owned exporter and a local HTTPS collector.
package workerobservation

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tnldotdev/tnl/internal/observability"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

type Recorder struct {
	Owner *observability.Metrics
	mu    sync.Mutex
	spans []*tracepb.Span
	logs  bytes.Buffer
}

func Start(t *testing.T) (context.Context, *Recorder) {
	t.Helper()
	r := &Recorder{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(io.LimitReader(request.Body, 8<<20))
		var batch collectortrace.ExportTraceServiceRequest
		if err != nil || proto.Unmarshal(body, &batch) != nil {
			http.Error(w, "invalid export", 400)
			return
		}
		r.mu.Lock()
		for _, resource := range batch.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				r.spans = append(r.spans, scope.Spans...)
			}
		}
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write([]byte{})
	}))
	t.Cleanup(server.Close)
	certificate := filepath.Join(t.TempDir(), "collector.pem")
	if err := os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS", "OTEL_SDK_DISABLED"} {
		t.Setenv(key, "")
	}
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", server.URL+"/v1/traces")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE", certificate)
	t.Setenv("OTEL_TRACES_SAMPLER", "parentbased_always_on")
	t.Setenv("OTEL_BSP_SCHEDULE_DELAY", "60000")
	ctx, owner, err := observability.StartProcess(t.Context(), "control")
	if err != nil {
		t.Fatal(err)
	}
	r.Owner = owner
	t.Cleanup(func() {
		if err := owner.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	previous := log.Writer()
	log.SetOutput(r)
	t.Cleanup(func() { log.SetOutput(previous) })
	return ctx, r
}

func (r *Recorder) Write(value []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.logs.Write(value)
}

func (r *Recorder) Logs() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.logs.String()
}

func Attribute(span *tracepb.Span, key string) string {
	for _, a := range span.Attributes {
		if a.Key == key {
			return a.Value.GetStringValue()
		}
	}
	return ""
}

func (r *Recorder) Attempts(t *testing.T, name string) []*tracepb.Span {
	t.Helper()
	if err := r.Owner.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var result []*tracepb.Span
	for _, s := range r.spans {
		if s.Name == name {
			result = append(result, s)
		}
	}
	if len(result) == 0 {
		t.Fatalf("missing owner attempt %q", name)
	}
	return result
}

func (r *Recorder) AssertFailure(t *testing.T, name, outcome, reason string) {
	t.Helper()
	spans := r.Attempts(t, name)
	span := spans[0]
	if Attribute(span, "tnl.outcome") != outcome || Attribute(span, "error.type") != reason || span.Status.GetCode() != tracepb.Status_STATUS_CODE_ERROR {
		t.Fatalf("owner attempt lost failure: %v", span)
	}
	logs := r.Logs()
	if strings.Count(logs, "reason="+reason) != 1 || !strings.Contains(logs, "trace_id="+hex.EncodeToString(span.TraceId)+" span_id="+hex.EncodeToString(span.SpanId)) || strings.Contains(logs, "private-provider-cause") {
		t.Fatalf("missing, duplicated, uncorrelated, or unsafe diagnostic: %s", logs)
	}
}
