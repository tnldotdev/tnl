package tunnel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestVisitorPromoterWaitsForAcknowledgementAndUsesSeparateStreams(t *testing.T) {
	publisher, relay := newAuthenticatedPair(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	decision := make(chan struct{})
	entered := make(chan struct{}, 1)
	var calls atomic.Int32
	done := tunnelWorker(t, func() { cancel(); _ = relay.Close() }, func() error {
		return relay.ServeAdmissions(ctx, tunnelv1.PublisherAdmissionStream, func(ctx context.Context, h tunnelv1.AdmissionHeader) tunnelv1.AdmissionResult {
			calls.Add(1)
			entered <- struct{}{}
			select {
			case <-decision:
			case <-ctx.Done():
			}
			return tunnelv1.AdmissionResult{Type: tunnelv1.StreamRejected, Code: tunnelv1.CapacityExceeded}
		})
	})
	promote := NewVisitorPromoter(func(h tunnelv1.VisitorStreamHeader) tunnelv1.VisitorStreamHeader { return h }, func(string) *Session { return publisher })
	h := visitorStreamHeader()
	h.IPPolicyDenied = true
	result := tunnelWorker(t, func() { _ = publisher.Close() }, func() error { return promote(ctx, h) })
	await(t, entered)
	select {
	case err := <-result:
		t.Fatalf("promoted before ack: %v", err)
	default:
	}
	close(decision)
	var protocolError *ProtocolError
	if err := await(t, result); !errors.As(err, &protocolError) || protocolError.Code != tunnelv1.CapacityExceeded {
		t.Fatal(err)
	}
	h.ConnectionAssignmentRevision++
	if err := promote(ctx, h); !errors.As(err, &protocolError) || protocolError.Code != tunnelv1.StaleConnectionAssignment {
		t.Fatal(err)
	}
	h.IPPolicyDenied = false
	if err := promote(ctx, h); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
	cancel()
	_ = publisher.Close()
	await(t, done)
}
