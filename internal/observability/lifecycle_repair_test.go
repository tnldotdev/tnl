package observability

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestNativeOTLPSlowLogsCannotStarveTraceFlushOrShutdown(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		name := "flush"
		if shutdown {
			name = "shutdown"
		}
		t.Run(name, func(t *testing.T) {
			logStarted := make(chan struct{}, 1)
			logStopped := make(chan struct{}, 1)
			var traceExports atomic.Int64
			receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				if r.URL.Path == "/v1/logs" {
					logStarted <- struct{}{}
					<-r.Context().Done()
					logStopped <- struct{}{}
					return
				}
				traceExports.Add(1)
				w.Header().Set("Content-Type", "application/x-protobuf")
			}))
			defer receiver.Close()
			signal := SignalConfig{Endpoint: receiver.URL + "/v1/traces", Timeout: 10 * time.Second, TLS: receiver.Client().Transport.(*http.Transport).TLSClientConfig.Clone()}
			config := Config{Traces: signal, Logs: signal, BatchDelay: time.Hour, LogBatchDelay: time.Hour, SampleRatio: 1}
			config.Logs.Endpoint = receiver.URL + "/v1/logs"
			m, err := newOwner("publisher", config)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Shutdown(context.Background())
			ctx := WithMetrics(t.Context(), m)
			_, finish := Start(ctx, "queued.fixture")
			finish(nil)
			OperationalFailure(ctx, "renew publisher lease", failure.Unexpected, "", errors.New("secret log cause"))
			bound, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
			defer cancel()
			var work func(context.Context) error = m.ForceFlush
			if shutdown {
				work = m.Shutdown
			}
			started := time.Now()
			err = work(bound)
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
				t.Fatal("shared export bound or cause lost", err)
			}
			select {
			case <-logStarted:
			default:
				t.Fatal("did not exercise a real stalled log request")
			}
			if traceExports.Load() != 1 {
				t.Fatal("slow logs starved the queued trace", traceExports.Load())
			}
			if !shutdown {
				stop, stopCancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
				defer stopCancel()
				_ = m.Shutdown(stop)
			}
			select {
			case <-m.spanQueue.done:
			case <-time.After(time.Second):
				t.Fatal("trace worker survived native shutdown")
			}
			select {
			case <-logStopped:
			case <-time.After(time.Second):
				t.Fatal("log HTTP export survived its bound")
			}
			_, after := Start(ctx, "after.shutdown")
			after(nil)
			if traceExports.Load() != 1 {
				t.Fatal("native trace export continued after shutdown")
			}
		})
	}
}

type failingDrainExporter struct{ export, shutdown error }

func (e failingDrainExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error {
	return e.export
}
func (e failingDrainExporter) Shutdown(context.Context) error { return e.shutdown }

func TestOwnerLifecycleErrorsRetainAllDrainCauses(t *testing.T) {
	exportCause, shutdownCause := errors.New("secret export error"), errors.New("secret shutdown error")
	m := New("publisher")
	m.spanQueue = newSpanQueue(failingDrainExporter{exportCause, shutdownCause}, &exportState{}, 4, 4, time.Hour, time.Second)
	m.tracerProvider = sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(m.spanQueue))
	_, span := m.tracer().Start(t.Context(), "flush.fixture")
	span.End()
	if err := m.ForceFlush(t.Context()); !errors.Is(err, exportCause) || err.Error() != "observability provider operation failed" {
		t.Fatal("flush cause lost or exposed", err)
	}
	_, span = m.tracer().Start(t.Context(), "shutdown.fixture")
	span.End()
	if err := m.Shutdown(t.Context()); !errors.Is(err, exportCause) || !errors.Is(err, shutdownCause) || err.Error() != "observability provider operation failed" {
		t.Fatal("shutdown causes lost or exposed", err)
	}
}

func TestProviderWorkRetainsCancellationAfterProvidersJoin(t *testing.T) {
	providerFailure := errors.New("secret provider failure")
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, errors.New("secret caller failure")} {
		for _, completedFailure := range []error{nil, providerFailure} {
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			var joined atomic.Int64
			err := providerWork(ctx, func(context.Context) error {
				cancel(cause)
				joined.Add(1)
				return nil
			}, func(ctx context.Context) error {
				<-ctx.Done()
				joined.Add(1)
				return completedFailure
			})
			if joined.Load() != 2 || !errors.Is(err, cause) || completedFailure != nil && !errors.Is(err, completedFailure) {
				t.Fatal("joined providers lost the caller or completed failure", err)
			}
			if err.Error() != "observability provider operation failed" {
				t.Fatal("provider cancellation exposed an internal cause", err)
			}
		}
	}
}
