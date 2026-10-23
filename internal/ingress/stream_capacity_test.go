package ingress

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type capacityClientFixture struct {
	calls   atomic.Int64
	retired atomic.Int64
	fail    atomic.Bool
	pending atomic.Bool
	mu      sync.Mutex
	ids     map[string]string
}

func (c *capacityClientFixture) AllocateStreamCapacity(_ context.Context, owner string, body ingressv1.StreamCapacityRequest) (controlv1.StreamCapacityAllocation, error) {
	c.calls.Add(1)
	if c.fail.Load() {
		return controlv1.StreamCapacityAllocation{}, errors.New("control is unavailable")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ids == nil {
		c.ids = make(map[string]string)
	}
	if c.ids[body.RequestId] == "" {
		id, err := opaqueid.New("salloc_")
		if err != nil {
			return controlv1.StreamCapacityAllocation{}, err
		}
		c.ids[body.RequestId] = id
	}
	now := time.Now()
	return controlv1.StreamCapacityAllocation{Id: c.ids[body.RequestId], Resource: body.Resource, RunId: body.RunId, RunNumber: body.RunNumber,
		IngressId: owner, IngressRunId: body.IngressRunId, IngressLeaseRevision: body.IngressLeaseRevision, Capacity: body.Capacity,
		ObservedAt: now, ValidUntil: now.Add(10 * time.Second), PublisherObserved: !c.pending.Load()}, nil
}

func TestStreamCapacityBackgroundExpansionUsesLocalOccupancy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &capacityClientFixture{}
		capacity := prepareCapacityFixture(t, client)
		run := &publicVisitorRun{capacity: capacity, limit: 4}
		defer func() {
			for _, extra := range run.additional {
				_ = extra.Close(t.Context())
			}
		}()
		reservation, err := capacity.reserve("vc_"+strings.Repeat("V", 22), func() {})
		if err != nil {
			t.Fatal(err)
		}
		defer reservation.Close()
		if client.calls.Load() != 1 {
			t.Fatal("visitor triggered capacity work")
		}
		run.expand(t.Context(), nil)
		if len(run.additional) != 1 || client.calls.Load() != 2 {
			t.Fatal("background occupancy did not prepare another portion")
		}
		run.expand(t.Context(), nil)
		if client.calls.Load() != 2 {
			t.Fatal("expansion exceeded the configured run limit")
		}
		another, err := run.additional[0].reserve("vc_"+strings.Repeat("W", 22), func() {})
		if err != nil {
			t.Fatal(err)
		}
		defer another.Close()
		if another.header.AllocationID == reservation.header.AllocationID {
			t.Fatal("another portion reused allocation identity")
		}
	})
}

func TestStreamCapacityWaitsForPublisherBackgroundObservation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &capacityClientFixture{}
		client.pending.Store(true)
		c := prepareCapacityFixture(t, client)
		if _, err := c.reserve("vc_"+strings.Repeat("V", 22), func() {}); !errors.Is(err, ErrStreamReservation) {
			t.Fatal("unobserved allocation reached a visitor", err)
		}
		client.pending.Store(false)
		time.Sleep(2*time.Second + time.Millisecond)
		synctest.Wait()
		reservation, err := c.reserve("vc_"+strings.Repeat("V", 22), func() {})
		if err != nil {
			t.Fatal(err)
		}
		reservation.Close()
		if client.calls.Load() != 2 {
			t.Fatal("visitor started allocation work")
		}
	})
}

func (c *capacityClientFixture) RetireStreamCapacity(context.Context, string, string, ingressv1.StreamCapacityRetirement) error {
	c.retired.Add(1)
	return nil
}

func prepareCapacityFixture(t *testing.T, client *capacityClientFixture) *streamCapacity {
	t.Helper()
	a := reservationAllocation(time.Now())
	c, err := prepareStreamCapacity(t.Context(), client, ingressv1.IngressLease{IngressId: a.IngressID, IngressRunId: a.IngressRunID, IngressLeaseRevision: int64(a.IngressLeaseRevision), LeaseExpiresAt: time.Now().Add(time.Minute)},
		ingressv1.StreamCapacityRequest{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKind(a.ResourceKind), Id: a.ResourceID}, RunId: a.RunID, RunNumber: int64(a.RunNumber), Capacity: 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return c
}

func TestStreamCapacityPreparedReservationsMakeNoControlCalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &capacityClientFixture{}
		c := prepareCapacityFixture(t, client)
		var first, sequence uint64
		for range 100 {
			r, err := c.reserve("vc_"+strings.Repeat("V", 22), func() {})
			if err != nil {
				t.Fatal(err)
			}
			sequence = r.header.Sequence
			if first == 0 {
				first = sequence
			}
			r.Close()
		}
		if client.calls.Load() != 1 || sequence != first+99 {
			t.Fatal("visitor reservations performed control work or reset replay watermarks")
		}
	})
}

func TestStreamCapacityRenewsHeldSlotsAndJoinsOnShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &capacityClientFixture{}
		c := prepareCapacityFixture(t, client)
		var stopped atomic.Int64
		r, err := c.reserve("vc_"+strings.Repeat("V", 22), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(13 * time.Second)
		synctest.Wait()
		if stopped.Load() != 0 || client.calls.Load() < 6 {
			t.Fatal("successful background renewal interrupted a held connection")
		}
		if err := c.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		calls := client.calls.Load()
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if stopped.Load() != 1 || calls != client.calls.Load() || client.retired.Load() != 1 {
			t.Fatal("shutdown retained traffic or background allocation work")
		}
		r.Close()
	})
}

func TestStreamCapacityOutageExpiresAndRecoversWithNewIdentity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &capacityClientFixture{}
		c := prepareCapacityFixture(t, client)
		var stopped atomic.Int64
		old, err := c.reserve("vc_"+strings.Repeat("V", 22), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		client.fail.Store(true)
		time.Sleep(11 * time.Second)
		synctest.Wait()
		if stopped.Load() != 1 {
			t.Fatal("control outage left usable reservations after the fixed deadline")
		}
		if _, err := c.reserve(old.header.VisitorConnectionID, func() {}); !errors.Is(err, ErrStreamReservation) {
			t.Fatal("expired allocation admitted a new connection", err)
		}
		client.fail.Store(false)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		next, err := c.reserve(old.header.VisitorConnectionID, func() {})
		if err != nil {
			t.Fatal(err)
		}
		defer next.Close()
		old.Close()
		if old.header.AllocationID == next.header.AllocationID || stopped.Load() != 1 {
			t.Fatal("recovery reused old authority or revived stopped traffic")
		}
	})
}
