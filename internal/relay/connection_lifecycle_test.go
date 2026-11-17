package relay

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func relayAwait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("relay worker timed out")
		var zero T
		return zero
	}
}

func relayWorker(t *testing.T, unblock func(), run func() error) <-chan error {
	t.Helper()
	result, done := make(chan error, 1), make(chan struct{})
	t.Cleanup(func() { unblock(); relayAwait(t, done) })
	go func() { defer close(done); result <- run() }()
	return result
}

type waitingDrainContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *waitingDrainContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestRegistryInsertionReplacementAndStaleRemoval(t *testing.T) {
	first, _, registry, header := privateLifecycleFixture(t)
	if n, s := registry.Load(); n != 1 || s != 0 {
		t.Fatalf("load=%d/%d", n, s)
	}
	var protocol *tunnel.ProtocolError
	if err := registry.insert(first); !errors.As(err, &protocol) || protocol.Code != tunnelv1.DuplicatePublisherConnection {
		t.Fatalf("duplicate insert=%v", err)
	}
	staleHeader := header
	staleHeader.PublisherConnectionID = opaqueid.PublisherConnectionPrefix + strings.Repeat("b", 22)
	staleHeader.ConnectionAssignmentRevision--
	stale, _ := serviceConnectionFixture(t, staleHeader)
	if err := registry.insert(stale); !errors.As(err, &protocol) || protocol.Code != tunnelv1.StaleConnectionAssignment {
		t.Fatalf("stale insert=%v", err)
	}
	nextHeader := header
	nextHeader.PublisherConnectionID = opaqueid.PublisherConnectionPrefix + strings.Repeat("c", 22)
	nextHeader.ConnectionAssignmentRevision++
	next, _ := serviceConnectionFixture(t, nextHeader)
	if err := registry.insert(next); err != nil {
		t.Fatal(err)
	}
	if err := first.paths.beginOpen(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("replaced connection stayed open", err)
	}
	if err := registry.remove(first); err != nil {
		t.Fatal(err)
	}
	if got, ok := registry.candidate(nextHeader, next.lease, time.Now()); !ok || got != next {
		t.Fatal("stale removal removed the replacement")
	}
	if _, ok := registry.candidate(header, first.lease, time.Now()); ok {
		t.Fatal("replaced assignment stayed selectable")
	}
	if err := registry.remove(next); err != nil {
		t.Fatal(err)
	}
	if err := registry.remove(next); err != nil {
		t.Fatal(err)
	}
	if n, s := registry.Load(); n != 0 || s != 0 {
		t.Fatalf("load after removal=%d/%d", n, s)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	if err := registry.insert(stale); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed registry accepted a connection", err)
	}
}
