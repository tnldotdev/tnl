package observability

import (
	"context"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type stalledExporter struct {
	started  chan struct{}
	finished chan struct{}
}

func (e stalledExporter) ExportSpans(ctx context.Context, _ []sdktrace.ReadOnlySpan) error {
	close(e.started)
	<-ctx.Done()
	close(e.finished)
	return ctx.Err()
}
func (e stalledExporter) Shutdown(context.Context) error { return nil }

func TestShutdownCancelsInFlightExportAndJoinsWorker(t *testing.T) {
	e := stalledExporter{make(chan struct{}), make(chan struct{})}
	q := newSpanQueue(e, &exportState{}, 2, 1, time.Hour, 10*time.Second)
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(q))
	_, span := provider.Tracer(scope).Start(t.Context(), "fixture")
	span.End()
	select {
	case <-e.started:
	case <-time.After(time.Second):
		t.Fatal("export did not start")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_ = provider.Shutdown(ctx)
	select {
	case <-q.done:
	case <-time.After(time.Second):
		t.Fatal("shutdown left export worker running")
	}
	select {
	case <-e.finished:
	default:
		t.Fatal("in-flight export was not canceled")
	}
}
