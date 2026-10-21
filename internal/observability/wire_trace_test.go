package observability

import (
	"context"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
	"go.opentelemetry.io/otel/baggage"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestWireTraceRetainsLocalOwnershipAndOnlyTelemetryParent(t *testing.T) {
	metrics := New("relay")
	defer metrics.Shutdown(context.Background())
	identity := Identity{TeamID: "local-team", PublisherIdentityID: "local-publisher", DeploymentID: "local-deployment"}
	owner, cancel := context.WithCancel(ReplaceIdentity(WithMetrics(t.Context(), metrics), identity))
	defer cancel()
	tid, _ := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	sid, _ := trace.SpanIDFromHex("0123456789abcdef")
	sending := trace.ContextWithSpanContext(t.Context(), trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled}))
	member, _ := baggage.NewMember("tenant", "untrusted")
	bg, _ := baggage.New(member)
	sending = baggage.ContextWithBaggage(sending, bg)
	tc := WireTrace(sending)
	if tc.TraceParent != "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01" {
		t.Fatal(tc)
	}
	received := ExtractWireTrace(owner, tc)
	sc := trace.SpanContextFromContext(received)
	if sc.TraceID() != tid || sc.SpanID() != sid || !sc.IsRemote() || sc.IsSampled() || sc.TraceState().Len() != 0 {
		t.Fatal(sc)
	}
	if FromContext(received) != metrics || IdentityFromContext(received) != identity || baggage.FromContext(received).Len() != 0 {
		t.Fatal("wire telemetry changed receiver ownership")
	}
	cancel()
	if received.Err() != context.Canceled {
		t.Fatal("owner cancellation lost")
	}
	for _, tc := range []tunnelv1.TraceContext{{}, {TraceParent: "malformed"}} {
		if trace.SpanContextFromContext(ExtractWireTrace(sending, tc)).IsValid() {
			t.Fatal("empty/invalid visitor inherited another span")
		}
	}
}

func TestWireTraceSamplingUsesLocalPolicyForEitherRemoteFlag(t *testing.T) {
	for _, sample := range []bool{false, true} {
		for _, flags := range []string{"00", "01"} {
			t.Run(strings.Join([]string{map[bool]string{true: "on", false: "off"}[sample], flags}, "/"), func(t *testing.T) {
				root := sdktrace.NeverSample()
				if sample {
					root = sdktrace.AlwaysSample()
				}
				exporter := tracetest.NewInMemoryExporter()
				provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter), sdktrace.WithSampler(sdktrace.ParentBased(root, sdktrace.WithRemoteParentSampled(root), sdktrace.WithRemoteParentNotSampled(root))))
				defer provider.Shutdown(t.Context())
				owner := WithMetrics(t.Context(), &Metrics{tracerProvider: provider})
				tc := tunnelv1.TraceContext{TraceParent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-" + flags}
				ctx, end := Start(ExtractWireTrace(owner, tc), "relay.test_setup")
				if trace.SpanContextFromContext(ctx).IsSampled() != sample {
					t.Fatal("remote flag overrode local policy")
				}
				end(nil)
				if sample {
					spans := exporter.GetSpans()
					if len(spans) != 1 || spans[0].Parent.SpanID().String() != "0123456789abcdef" {
						t.Fatal("parent chain lost")
					}
				} else if len(exporter.GetSpans()) != 0 {
					t.Fatal("local drop exported span")
				}
			})
		}
	}
}
