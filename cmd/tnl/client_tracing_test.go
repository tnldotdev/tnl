package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	connectionruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/observability"
)

func TestClientTracingRuntimeInitializesOwnerBeforeDispatch(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://private-invalid")
	var out, diagnostics bytes.Buffer
	err := run(context.WithValue(t.Context(), nativeProcessKey{}, true), []string{"--no-telemetry", "runtime", "connections", "capabilities"}, &out, &diagnostics)
	if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "private-invalid") {
		t.Fatal("runtime bypassed safe exporter initialization")
	}
}

func TestClientTracingExporterDownDoesNotFailCLIAndFlushIsBounded(t *testing.T) {
	started := make(chan struct{}, 1)
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer receiver.Close()
	ca := filepath.Join(t.TempDir(), "receiver.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", receiver.URL+"/v1/traces")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE", ca)
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "5000")
	t.Setenv("OTEL_METRICS_EXPORTER", "none")
	t.Setenv("OTEL_LOGS_EXPORTER", "none")
	t.Setenv("OTEL_BSP_SCHEDULE_DELAY", "60000")
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := connectionruntime.NewDirectory(parent)
	if err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	before := time.Now()
	err = run(context.WithValue(t.Context(), nativeProcessKey{}, true), []string{"--no-telemetry", "runtime", "connections", "recover", "--handle", filepath.Join(directory, "handle.json")}, &out, &diagnostics)
	if err != nil || !strings.Contains(out.String(), `"state":"stopped"`) || diagnostics.Len() != 0 {
		t.Fatal("export failure changed command result", err)
	}
	if elapsed := time.Since(before); elapsed > observability.CLIShutdownTimeout+time.Second {
		t.Fatalf("CLI flush took %s", elapsed)
	}
	select {
	case <-started:
	default:
		t.Fatal("CLI did not attempt to flush its completed span")
	}
}
