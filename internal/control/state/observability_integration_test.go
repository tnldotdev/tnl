package state

import (
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability"
	collector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

func TestIntegrationServerDatabaseSpanCausality(t *testing.T) {
	d, _ := newControlStateIntegrationDatabase(t, "server_span_causality")
	var mu sync.Mutex
	var spans []*tracepb.Span
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		var batch collector.ExportTraceServiceRequest
		if err != nil || proto.Unmarshal(data, &batch) != nil {
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		for _, resource := range batch.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				spans = append(spans, scope.Spans...)
			}
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer receiver.Close()
	certificate := filepath.Join(t.TempDir(), "collector.pem")
	if err := os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", receiver.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE", certificate)
	t.Setenv("OTEL_TRACES_SAMPLER", "always_on")
	ctx, m, err := observability.StartProcess(t.Context(), "control")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown(t.Context())
	d.Instrument(m)
	ctx, root := observability.Start(ctx, "request")
	ctx, operation := d.observeOperation(ctx, "CreatePublishRun")
	conn, err := d.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = controlstatedb.New(conn).ServicePortPoolCapacity(ctx); err != nil {
		t.Fatal(err)
	}
	var secret string
	err = conn.QueryRow(ctx, "SELECT $1::text AS secret_statement", "secret_argument").Scan(&secret)
	conn.Release()
	operation(err)
	root(err)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.ForceFlush(t.Context()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	var parent *tracepb.Span
	for _, span := range spans {
		if span.Name == "CreatePublishRun" {
			parent = span
		}
	}
	if parent == nil || len(parent.ParentSpanId) == 0 {
		t.Fatal("missing request operation parent", spans)
	}
	for _, name := range []string{"database.acquire", "database.ServicePortPoolCapacity", "database.unknown"} {
		found := false
		for _, span := range spans {
			if span.Name == name {
				found = true
				if string(span.ParentSpanId) != string(parent.SpanId) || string(span.TraceId) != string(parent.TraceId) {
					t.Fatal("database span lost caller", span)
				}
			}
		}
		if !found {
			t.Fatal("missing real PostgreSQL span", name)
		}
	}
	for _, span := range spans {
		if strings.Contains(span.String(), "secret_") || strings.Contains(span.String(), "SELECT ") {
			t.Fatal("SQL or arguments escaped", span)
		}
	}
}
