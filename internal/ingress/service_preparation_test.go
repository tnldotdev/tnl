package ingress

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

type blockedPreparationControl struct {
	PrivateControl
	VisitorPreparationControl
	started, cleanup, release chan struct{}
	calls                     atomic.Int64
}

func (c *blockedPreparationControl) GetServiceSnapshot(ctx context.Context, _ string, _ ingressv1.GetServiceSnapshotParams) (ingressv1.ServiceSnapshot, error) {
	c.calls.Add(1)
	close(c.started)
	<-ctx.Done()
	close(c.cleanup)
	<-c.release
	return ingressv1.ServiceSnapshot{}, context.Cause(ctx)
}

func TestConnectorCloseCancelsAndJoinsPreparedRouting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		connector, control, _, _, _, _ := privateTestSetup(t)
		// this owner starts without any prepared runs. all control work must
		// stay in the blocked routing reader, including during shutdown.
		connector.prepared = make(map[string]*preparedVisitorRun)
		connector.config.Routing.Clear()
		blocked := &blockedPreparationControl{PrivateControl: control, started: make(chan struct{}), cleanup: make(chan struct{}), release: make(chan struct{})}
		connector.config.Control, connector.config.VisitorControl = blocked, blocked
		done := make(chan error, 1)
		go func() { done <- connector.Run(t.Context()) }()
		<-blocked.started
		if err := connector.Run(t.Context()); !errors.Is(err, ErrServiceAdmission) {
			t.Fatalf("a second preparation owner started: %v", err)
		}
		closed := make(chan error, 1)
		go func() { closed <- connector.Close() }()
		<-blocked.cleanup
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("connector closed before joining routing cleanup")
		default:
		}
		close(blocked.release)
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if blocked.calls.Load() != 1 {
			t.Fatal("shutdown or duplicate Run started more control work")
		}
		if err := connector.Run(t.Context()); !errors.Is(err, ErrServiceAdmission) {
			t.Fatal("closed connector restarted preparation", err)
		}
	})
}

type stalledRetirementClient struct {
	streamCapacityClient
	active  atomic.Int64
	maximum atomic.Int64
}

func (c *stalledRetirementClient) RetireStreamCapacity(ctx context.Context, _, _ string, _ ingressv1.StreamCapacityRetirement) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	active := c.active.Add(1)
	defer c.active.Add(-1)
	for previous := c.maximum.Load(); active > previous; previous = c.maximum.Load() {
		if c.maximum.CompareAndSwap(previous, active) {
			break
		}
	}
	<-ctx.Done()
	return context.Cause(ctx)
}

func TestPreparedVisitorRetirementHasOneSharedShutdownBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &stalledRetirementClient{}
		finished := make(chan struct{})
		close(finished)
		var runs []*preparedVisitorRun
		for range 24 {
			lease, err := visitorlease.New(visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("a", 22)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			runs = append(runs, &preparedVisitorRun{
				policy:   &visitorPolicy{lease: lease, cancel: func() {}, done: finished},
				capacity: &streamCapacity{client: client, cancel: func() {}, done: finished},
			})
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		started := time.Now()
		retirePreparedVisitors(ctx, runs)
		if elapsed := time.Since(started); elapsed != 2*time.Second {
			t.Fatalf("retirement multiplied its shutdown budget by run count: %s", elapsed)
		}
		if requests := client.maximum.Load(); requests != 8 || client.active.Load() != 0 {
			t.Fatalf("retirement did not bound and join its worker set: maximum=%d", requests)
		}
	})
}
