package service

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// Done is evaluated after the authority snapshot, while preparing select.
// hold that boundary so drain and the exact receipt are both ready before
// selection, without changing the production callback or its timers.
type deliverySelectContext struct {
	context.Context
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (c *deliverySelectContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered); <-c.release })
	return c.Context.Done()
}

func TestConnectorSimultaneousDrainAndReceiptHonorPublishedDeadline(t *testing.T) {
	for _, outcome := range []string{"expired", "before_deadline", "revoked"} {
		// either ready select case is legal; every choice must enforce the
		// published deadline rather than the older authority snapshot.
		for attempt := range 32 {
			t.Run(outcome+"/"+strconv.Itoa(attempt), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					bound, peer, admission, entry, receipts := newConnectorDeliveryAdmission(t, config.ProtocolTCP, 3*time.Second)
					released := make(chan struct{})
					release := sync.OnceFunc(func() { close(released) })
					defer release()
					boundary := &deliverySelectContext{Context: admission.ctx, entered: make(chan struct{}), release: released}
					admission.ctx = boundary
					done := make(chan error, 1)
					go func() { done <- admission.finishDelivery(nil) }()
					<-boundary.entered
					before := time.Now()
					receipts.Complete(peer, tunnelv1.ConnectorVisitorCompletion{Kind: tunnelv1.ConnectorVisitorCompleted,
						VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration})
					time.Sleep(500 * time.Millisecond)
					until := before.Add(time.Second)
					var want error
					if outcome == "expired" {
						until = before.Add(250 * time.Millisecond)
						want = context.DeadlineExceeded
					}
					if err := bound.startDrain(until); err != nil {
						t.Fatal(err)
					}
					if outcome == "revoked" {
						admission.cancel()
						want = context.Canceled
					}
					select {
					case <-bound.drainStarted:
					default:
						t.Fatal("drain was not published before selection")
					}
					select {
					case <-admission.completed:
					default:
						t.Fatal("exact receipt was not ready before selection")
					}
					release()
					if err := <-done; !errors.Is(err, want) {
						t.Fatal("simultaneous receipt bypassed the published deadline or revocation", err, want)
					}
					if elapsed := time.Since(before); elapsed != 500*time.Millisecond {
						t.Fatal("ready receipt or revocation waited for another timer", elapsed)
					}
				})
			})
		}
	}
}
