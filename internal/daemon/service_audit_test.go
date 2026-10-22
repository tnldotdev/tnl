package tnldruntime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

type leaseAuditClient struct {
	mu     sync.Mutex
	leases []controlstate.IngressLeaseIdentity
	events []serviceaudit.Observation
	first  chan struct{}
	retry  chan struct{}
}

func (c *leaseAuditClient) IngestServiceObservations(ctx context.Context, lease controlstate.IngressLeaseIdentity, b serviceaudit.Batch) (controlstate.ServiceObservationResult, error) {
	c.mu.Lock()
	c.leases = append(c.leases, lease)
	c.events = append(c.events, b.Events...)
	n := len(c.leases)
	c.mu.Unlock()
	if n == 1 && c.first != nil {
		close(c.first)
		select {
		case <-c.retry:
		case <-ctx.Done():
			return controlstate.ServiceObservationResult{}, ctx.Err()
		}
		return controlstate.ServiceObservationResult{}, errors.New("retry")
	}
	return controlstate.ServiceObservationResult{Accepted: len(b.Events)}, nil
}

func TestIngressAuditRenewalRetainsBoundLeaseAcrossRetries(t *testing.T) {
	c := &leaseAuditClient{first: make(chan struct{}), retry: make(chan struct{})}
	a := &ingressServiceAudit{ctx: t.Context(), client: c, metrics: observability.New("ingress")}
	lease := ingressv1.IngressLease{IngressId: "ingress-a", IngressRunId: "process-a", IngressLeaseRevision: 3, LeaseExpiresAt: time.Now().Add(time.Minute)}
	if err := a.bind(lease); err != nil {
		t.Fatal(err)
	}
	o := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: "url_0123456789ABCDEFGHIJKL", ServiceKind: "public_url", EventType: "connection.open", OccurredAt: time.Now(), RunID: "pr_0123456789ABCDEFGHIJKL", RunNumber: 1, VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL", Outcome: "forwarded"}
	if !a.Observe(o) {
		t.Fatal("observation rejected")
	}
	done := make(chan error, 1)
	// closing forces the short batch immediately without waiting for its timer.
	go func() { done <- a.queue.Close(t.Context()) }()
	<-c.first
	lease.LeaseExpiresAt = lease.LeaseExpiresAt.Add(time.Minute)
	if err := a.bind(lease); err != nil {
		t.Fatal("renewal replaced queue", err)
	}
	lease.IngressLeaseRevision++
	if err := a.bind(lease); !errors.Is(err, ingress.ErrIngressLeaseLost) {
		t.Fatalf("old events relabeled as a new lease: %v", err)
	}
	close(c.retry)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.leases) != 2 || c.leases[0] != c.leases[1] || c.leases[1].IngressLeaseRevision != 3 || c.events[0].EventID != c.events[1].EventID {
		t.Fatal("retry changed its sender or event identity")
	}
}
