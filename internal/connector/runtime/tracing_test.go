package connectionruntime

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

func TestConnectionOwnerReadinessAndIPCDoNotWaitForExporter(t *testing.T) {
	blocked := make(chan struct{}, 1)
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case blocked <- struct{}{}:
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
	t.Setenv("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "1")
	ctx, m, err := observability.StartProcess(t.Context(), "client")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), observability.CLIShutdownTimeout)
		defer cancel()
		_ = m.Shutdown(shutdown)
	}()
	_, finish := observability.ClientOperation(ctx, "client.status")
	finish(nil)
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("exporter did not block")
	}
	scope := fixtureScope(t)
	directory, err := NewDirectory(scope.Directory)
	if err != nil {
		t.Fatal(err)
	}
	lifetime, cancel := context.WithCancel(ctx)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	done := make(chan struct{})
	var result error
	go func() {
		result = Serve(lifetime, scope, directory, "/test/tnl", &fixtureBackend{deadline: time.Now().Add(time.Hour)}, writer)
		close(done)
	}()
	defer func() { cancel(); <-done }()
	ready := make(chan Status, 1)
	go func() { var state Status; _ = json.NewDecoder(reader).Decode(&state); ready <- state }()
	var state Status
	select {
	case state = <-ready:
	case <-time.After(time.Second):
		t.Fatal("exporter blocked owner readiness")
	}
	if state.State != "ready" {
		t.Fatal("export failure changed readiness")
	}
	call, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	request := Request{Schema: Schema, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest}
	if err := Call(call, state.PrivateHandle, "status", request, new(Status)); err != nil {
		t.Fatal("exporter blocked IPC", err)
	}
	if err := Call(call, state.PrivateHandle, "stop", request, nil); err != nil {
		t.Fatal("exporter blocked stop", err)
	}
	select {
	case <-done:
	case <-call.Done():
		t.Fatal("exporter blocked joined cleanup")
	}
	if result != nil {
		t.Fatal(result)
	}
}
