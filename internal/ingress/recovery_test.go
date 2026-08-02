package ingress

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

func TestNewRecoveryReporterRejectsNegativeRetryInterval(t *testing.T) {
	t.Parallel()
	if _, err := NewRecoveryReporter(t.Context(), &testRecoveryControl{}, -time.Second, nil); err == nil {
		t.Fatal("NewRecoveryReporter accepted a negative retry interval")
	}
}

func TestRecoveryReporterRetriesAndDeduplicates(t *testing.T) {
	synctest.Test(t, testRecoveryReporterRetriesAndDeduplicates)
}

func testRecoveryReporterRetriesAndDeduplicates(t *testing.T) {
	control := &testRecoveryControl{attempted: make(chan struct{}, 2)}
	ctx, cancel := context.WithCancel(t.Context())
	reporter, err := NewRecoveryReporter(ctx, control, time.Second, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		ctx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := reporter.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	observedAt := time.Now().UTC()
	reporter.Observe("route_test", 3, 7, observedAt)
	synctest.Wait()
	reporter.Observe("route_test", 3, 7, observedAt.Add(time.Second))

	for range 2 {
		select {
		case <-control.attempted:
		case <-time.After(2 * time.Second):
			t.Fatal("recovery observation was not retried")
		}
	}
	closeCtx, stop := context.WithTimeout(t.Context(), 2*time.Second)
	defer stop()
	if err := reporter.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if control.attempts != 2 || control.routeID != "route_test" || control.routeVersion != 3 ||
		control.episodeID != 7 || !control.observedAt.Equal(observedAt) {
		t.Fatalf("recovery attempts = %#v", control)
	}
}

type testRecoveryControl struct {
	mu           sync.Mutex
	attempted    chan struct{}
	attempts     int
	routeID      string
	routeVersion uint64
	episodeID    uint64
	observedAt   time.Time
}

func (c *testRecoveryControl) ObserveRecovery(
	_ context.Context,
	routeID string,
	routeVersion, episodeID uint64,
	observedAt time.Time,
) (ingressv1.RouteRecoveryObservation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts++
	c.routeID = routeID
	c.routeVersion = routeVersion
	c.episodeID = episodeID
	c.observedAt = observedAt
	c.attempted <- struct{}{}
	if c.attempts == 1 {
		return ingressv1.RouteRecoveryObservation{}, errors.New("temporary failure")
	}
	return ingressv1.RouteRecoveryObservation{}, nil
}
