package ingress

import (
	"context"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"go.opentelemetry.io/otel/trace"
)

type traceOwnerConnector struct {
	contexts chan context.Context
	stopped  chan struct{}
}

func (c traceOwnerConnector) Credential() string { return forwardingClusterSecret }
func (c traceOwnerConnector) Connect(ctx context.Context, _ relayTarget) (muxsession.Session, error) {
	c.contexts <- ctx
	<-ctx.Done()
	close(c.stopped)
	return nil, ctx.Err()
}

func TestForwarderPooledSetupRetainsOwnerNotVisitorContext(t *testing.T) {
	metrics := observability.New("ingress")
	defer metrics.Shutdown(context.Background())
	identity := observability.Identity{TeamID: "owner-team", DeploymentID: "owner-deployment"}
	owner, stopOwner := context.WithCancel(observability.ReplaceIdentity(observability.WithMetrics(t.Context(), metrics), identity))
	defer stopOwner()
	owner, finishOwner := observability.Start(owner, "fixture.owner")
	defer finishOwner(nil)
	connector := traceOwnerConnector{contexts: make(chan context.Context, 1), stopped: make(chan struct{})}
	forwarder := newForwarderContext(owner, connector)
	defer forwarder.Close()
	visitor, stopVisitor := context.WithCancel(observability.ReplaceIdentity(owner, observability.Identity{TeamID: "visitor-team"}))
	defer stopVisitor()
	tid, _ := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	sid, _ := trace.SpanIDFromHex("0123456789abcdef")
	visitor = trace.ContextWithSpanContext(visitor, trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid}))
	result := ingressWorker(t, stopVisitor, func() error {
		_, _, err := forwarder.session(visitor, relayTarget{address: "relay:443", relayID: "relay"})
		return err
	})
	connecting := ingressAwait(t, connector.contexts)
	if observability.FromContext(connecting) != metrics || observability.IdentityFromContext(connecting) != identity {
		t.Fatal("pooled setup lost owner instrumentation or inherited visitor identity")
	}
	if trace.SpanContextFromContext(connecting).TraceID() != trace.SpanContextFromContext(owner).TraceID() {
		t.Fatal("pooled setup adopted visitor trace")
	}
	stopVisitor()
	if err := ingressAwait(t, result); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if connecting.Err() != nil {
		t.Fatal("visitor canceled pooled setup")
	}
	stopOwner()
	ingressAwait(t, connector.stopped)
	if !errors.Is(connecting.Err(), context.Canceled) {
		t.Fatal("pooled setup lost owner lifetime")
	}
}
