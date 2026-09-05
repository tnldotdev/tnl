package ingress

import (
	"context"
	"errors"
	"sync"
	"testing"
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
	control := &testRecoveryControl{attempted: make(chan struct{}, 2)}
	reporter, err := NewRecoveryReporter(t.Context(), control, time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	observedAt := time.Now().UTC()
	reporter.Observe("route_test", 3, 7, observedAt)
	reporter.Observe("route_test", 3, 7, observedAt.Add(time.Second))

	for range 2 {
		select {
		case <-control.attempted:
		case <-time.After(time.Second):
			t.Fatal("recovery observation was not retried")
		}
	}
	if err := reporter.Close(t.Context()); err != nil {
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
