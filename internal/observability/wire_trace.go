package observability

import (
	"context"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
	"go.opentelemetry.io/otel/trace"
)

// WireTrace exports only the current span's bounded W3C parent. process identity,
// tenant fields, tracestate, and baggage never cross this telemetry boundary.
func WireTrace(ctx context.Context) tunnelv1.TraceContext {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return tunnelv1.TraceContext{}
	}
	flags := "00"
	if sc.IsSampled() {
		flags = "01"
	}
	return tunnelv1.TraceContext{TraceParent: "00-" + sc.TraceID().String() + "-" + sc.SpanID().String() + "-" + flags}
}

// ExtractWireTrace replaces only span parentage, retaining the receiver's local
// identity and instruments. remote sampling is untrusted: the parent is marked
// remote with its sampled flag cleared; the receiver's remote-parent sampler
// must use local policy. an
// empty or malformed parent clears any pooled session's span to prevent leaks.
func ExtractWireTrace(ctx context.Context, tc tunnelv1.TraceContext) context.Context {
	if tc.TraceParent == "" || tc.Validate() != nil {
		return trace.ContextWithSpanContext(ctx, trace.SpanContext{})
	}
	tid, _ := trace.TraceIDFromHex(tc.TraceParent[3:35])
	sid, _ := trace.SpanIDFromHex(tc.TraceParent[36:52])
	return trace.ContextWithRemoteSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, Remote: true}))
}
