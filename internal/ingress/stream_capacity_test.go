package ingress

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
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
	calls           atomic.Int64
	retired         atomic.Int64
	fail            atomic.Bool
	pending         atomic.Bool
	publisherExpiry atomic.Int64
	lifetime        time.Duration
	mu              sync.Mutex
	ids             map[string]string
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
	lifetime := c.lifetime
	if lifetime == 0 {
		lifetime = 10 * time.Second
	}
	publisherUntil := now.Add(lifetime)
	if expiry := c.publisherExpiry.Load(); expiry != 0 {
		publisherUntil = time.Unix(0, expiry)
	}
	return controlv1.StreamCapacityAllocation{Id: c.ids[body.RequestId], Resource: body.Resource, RunId: body.RunId, RunNumber: body.RunNumber,
		IngressId: owner, IngressRunId: body.IngressRunId, IngressLeaseRevision: body.IngressLeaseRevision, Capacity: body.Capacity,
		ObservedAt: now, ValidUntil: now.Add(lifetime), PublisherObserved: !c.pending.Load(), PublisherObservedUntil: &publisherUntil, ReservationKey: bytes.Repeat([]byte{0x42}, 32)}, nil
}

func TestStreamCapacityShortLeaseRenewsBeforeObservationRoundsConsumeIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &capacityClientFixture{lifetime: 4 * time.Second}
		_ = prepareCapacityFixture(t, client)
		time.Sleep(time.Second + time.Millisecond)
		synctest.Wait()
		if client.calls.Load() != 2 {
			t.Fatal("short allocation still waits the ordinary two-second renewal interval")
		}
		client.fail.Store(true)
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if client.calls.Load() != 7 {
			t.Fatal("outage changed renewal cadence into an expiry-driven request spin", client.calls.Load())
		}
	})
}

func TestStreamCapacityPreparedLocalBoundNeedsNoExpansion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &capacityClientFixture{}
		run := prepareCapacityFixture(t, client)
		capacity := run.capacity
		reservation, err := capacity.reserve("vc_"+strings.Repeat("V", 22), netip.MustParseAddr("192.0.2.1"), func() {})
		if err != nil {
			t.Fatal(err)
		}
		defer reservation.Close()
		if client.calls.Load() != 1 {
			t.Fatal("visitor triggered capacity work")
		}
		another, err := capacity.reserve("vc_"+strings.Repeat("W", 22), netip.MustParseAddr("192.0.2.1"), func() {})
		if err != nil {
			t.Fatal(err)
		}
		defer another.Close()
		if another.header.AllocationID != reservation.header.AllocationID || another.header.Slot == reservation.header.Slot {
			t.Fatal("local setup did not use independent slots in one prepared allocation")
		}
		if _, err := capacity.reserve("vc_"+strings.Repeat("X", 22), netip.MustParseAddr("192.0.2.1"), func() {}); !errors.Is(err, ErrStreamReservation) {
			t.Fatal("local setup exceeded its configured bound", err)
		}
		if client.calls.Load() != 1 {
			t.Fatal("local occupancy or overflow started control work")
		}
	})
}

func TestStreamCapacityWaitsForPublisherBackgroundObservation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &capacityClientFixture{}
		client.pending.Store(true)
		run := prepareCapacityFixture(t, client)
		c := run.capacity
		if _, err := c.reserve("vc_"+strings.Repeat("V", 22), netip.MustParseAddr("192.0.2.1"), func() {}); !errors.Is(err, ErrStreamReservation) {
			t.Fatal("unobserved allocation reached a visitor", err)
		}
		client.pending.Store(false)
		time.Sleep(2*time.Second + time.Millisecond)
		synctest.Wait()
		reservation, err := c.reserve("vc_"+strings.Repeat("V", 22), netip.MustParseAddr("192.0.2.1"), func() {})
		if err != nil {
			t.Fatal(err)
		}
		reservation.Close()
		if client.calls.Load() != 2 {
			t.Fatal("visitor started allocation work")
		}
	})
}

func TestStreamCapacityPublisherDeadlineExpiresBeforeRenewedSetup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &capacityClientFixture{}
		client.publisherExpiry.Store(time.Now().Add(5 * time.Second).UnixNano())
		run := prepareCapacityFixture(t, client)
		capacity := run.capacity
		time.Sleep(4 * time.Second)
		synctest.Wait()
		client.fail.Store(true)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		calls := client.calls.Load()
		if _, err := capacity.reserve("vc_"+strings.Repeat("V", 22), netip.MustParseAddr("192.0.2.1"), func() {}); !errors.Is(err, ErrStreamReservation) {
			t.Fatal("renewed local setup retained expired publisher readiness", err)
		}
		if client.calls.Load() != calls {
			t.Fatal("expired readiness made a visitor-time control call")
		}
		client.publisherExpiry.Store(time.Now().Add(8 * time.Second).UnixNano())
		client.fail.Store(false)
		if err := capacity.refresh(t.Context()); err != nil {
			t.Fatal(err)
		}
		reservation, err := capacity.reserve("vc_"+strings.Repeat("V", 22), netip.MustParseAddr("192.0.2.1"), func() {})
		if err != nil {
			t.Fatal("fresh background publisher evidence did not restore local readiness", err)
		}
		reservation.Close()
	})
}

func (c *capacityClientFixture) RetireStreamCapacity(context.Context, string, string, ingressv1.StreamCapacityRetirement) error {
	c.retired.Add(1)
	return nil
}

func (*capacityClientFixture) ReadIngressVisitorPolicy(_ context.Context, _ string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
	return ingressPolicyResponse(body), nil
}

func prepareCapacityFixture(t *testing.T, client *capacityClientFixture) *publicVisitorRun {
	t.Helper()
	a := reservationAllocation(time.Now())
	process := ingressv1.IngressLease{IngressId: a.IngressID, IngressRunId: a.IngressRunID, IngressLeaseRevision: int64(a.IngressLeaseRevision), LeaseExpiresAt: time.Now().Add(time.Minute)}
	run, err := preparePublicVisitorRun(t.Context(), client, func() ingressv1.IngressLease { return process }, ingressv1.IngressRoutingTableEntry{
		PublicUrlId: "url_" + strings.Repeat("B", 22), PublishRunId: "pr_" + strings.Repeat("C", 22), PublishRunNumber: int64(a.RunNumber),
		Traffic: &ingressv1.IngressTrafficLimits{Connections: 2},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		run.close(context.Background())
		if err := run.capacity.closeErr; err != nil {
			t.Error(err)
		}
	})
	return run
}

func TestStreamCapacityPreparedReservationsMakeNoControlCalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &capacityClientFixture{}
		run := prepareCapacityFixture(t, client)
		c := run.capacity
		var first, sequence uint64
		for range 100 {
			r, err := c.reserve("vc_"+strings.Repeat("V", 22), netip.MustParseAddr("192.0.2.1"), func() {})
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
		run := prepareCapacityFixture(t, client)
		c := run.capacity
		var stopped atomic.Int64
		r, err := c.reserve("vc_"+strings.Repeat("V", 22), netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(13 * time.Second)
		synctest.Wait()
		if stopped.Load() != 0 || client.calls.Load() < 6 {
			t.Fatal("successful background renewal interrupted a held connection")
		}
		run.close(context.Background())
		if err := c.closeErr; err != nil {
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
		run := prepareCapacityFixture(t, client)
		c := run.capacity
		var stopped atomic.Int64
		old, err := c.reserve("vc_"+strings.Repeat("V", 22), netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		client.fail.Store(true)
		time.Sleep(11 * time.Second)
		synctest.Wait()
		if stopped.Load() != 1 {
			t.Fatal("control outage left usable reservations after the fixed deadline")
		}
		if _, err := c.reserve(old.header.VisitorConnectionID, netip.MustParseAddr("192.0.2.1"), func() {}); !errors.Is(err, ErrStreamReservation) {
			t.Fatal("expired allocation admitted a new connection", err)
		}
		client.fail.Store(false)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		next, err := c.reserve(old.header.VisitorConnectionID, netip.MustParseAddr("192.0.2.1"), func() {})
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
