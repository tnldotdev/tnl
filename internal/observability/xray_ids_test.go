package observability

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"
)

func TestXRayRootIDsRetainTimestampAndPropagatedParent(t *testing.T) {
	owner := New("publisher")
	t.Cleanup(func() { _ = owner.Shutdown(context.Background()) })
	tracer := owner.tracer()
	before := uint32(time.Now().Unix())
	ctx, root := tracer.Start(t.Context(), "root")
	defer root.End()
	id := root.SpanContext().TraceID()
	after := uint32(time.Now().Unix())
	if timestamp := binary.BigEndian.Uint32(id[:4]); timestamp < before || timestamp > after {
		t.Fatal("root trace ID lacks the current X-Ray timestamp prefix")
	}
	_, child := tracer.Start(ctx, "child")
	defer child.End()
	if child.SpanContext().TraceID() != id || child.SpanContext().SpanID() == root.SpanContext().SpanID() {
		t.Fatal("local child changed trace or reused span ID")
	}
	remote := trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1, 2, 3, 4, 5}, SpanID: trace.SpanID{6}, Remote: true})
	_, external := tracer.Start(trace.ContextWithRemoteSpanContext(t.Context(), remote), "remote-child")
	defer external.End()
	if external.SpanContext().TraceID() != remote.TraceID() {
		t.Fatal("propagated parent ID was rewritten")
	}
}
