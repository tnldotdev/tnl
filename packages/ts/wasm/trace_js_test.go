package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPortableOperationsPreserveIncomingWireTrace(t *testing.T) {
	// wire receive clears remote sampling. local operations pass the parent
	// through without creating a recording span or changing cancellation.
	const parent = "00-00000000000000000000000000000001-0000000000000001-01"
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx = observability.ExtractWireTrace(ctx, tunnelv1.TraceContext{TraceParent: parent})
	want := observability.WireTrace(ctx)
	if want.TraceParent != parent[:len(parent)-2]+"00" {
		t.Fatalf("unexpected wire parent: %q", want.TraceParent)
	}
	ctx, end := observability.Start(ctx, "portable.test")
	defer end(nil)
	ctx, done := observability.PublisherOperation(ctx, "visitor_authorization")
	defer done(nil)
	handler := observability.PublisherHTTP(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if got := observability.WireTrace(r.Context()); got != want {
			t.Errorf("wire trace = %v, want %v", got, want)
		}
		if r.Context().Err() != context.Canceled {
			t.Error("portable instrumentation changed the caller's cancellation")
		}
	}))
	cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(nil, request)
}
