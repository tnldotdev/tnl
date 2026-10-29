package ingress

import (
	"context"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type streamCapacityClient interface {
	AllocateStreamCapacity(context.Context, string, ingressv1.StreamCapacityRequest) (controlv1.StreamCapacityAllocation, error)
	RetireStreamCapacity(context.Context, string, string, ingressv1.StreamCapacityRetirement) error
}

func (c *HTTPControlClient) AllocateStreamCapacity(ctx context.Context, id string, body ingressv1.StreamCapacityRequest) (controlv1.StreamCapacityAllocation, error) {
	response, err := c.client.AllocateStreamCapacityWithResponse(ctx, id, body)
	if err != nil {
		return controlv1.StreamCapacityAllocation{}, err
	}
	if response == nil {
		return controlv1.StreamCapacityAllocation{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return controlv1.StreamCapacityAllocation{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) RetireStreamCapacity(ctx context.Context, id, allocation string, body ingressv1.StreamCapacityRetirement) error {
	response, err := c.client.RetireStreamCapacityWithResponse(ctx, id, allocation, body)
	if err != nil {
		return err
	}
	if response == nil {
		return ingressHTTPProblem(0, nil)
	}
	if response.StatusCode() != http.StatusNoContent {
		return ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return nil
}

// streamCapacity renews source-bound slots for one exact run. public URL slots
// bound local setup, not the publisher's authorized stream count. service slots
// retain their delegated capacity. the serving path uses prepared local state
// only; it never requests capacity on demand.
type streamCapacity struct {
	client         streamCapacityClient
	pool           *streamReservations
	owner          ingressv1.IngressLease
	body           ingressv1.StreamCapacityRequest
	until          time.Time
	mu             sync.Mutex
	id             string
	ready          bool
	publisherUntil time.Time
	renewAfter     time.Duration
	closeOnce      sync.Once
	closeErr       error
}

func newStreamCapacity(client streamCapacityClient, owner ingressv1.IngressLease, body ingressv1.StreamCapacityRequest) (*streamCapacity, error) {
	if client == nil || owner.Draining || owner.IngressLeaseRevision < 1 || !owner.LeaseExpiresAt.After(time.Now()) {
		return nil, ErrStreamReservation
	}
	body.IngressRunId, body.IngressLeaseRevision = owner.IngressRunId, owner.IngressLeaseRevision
	body.RequestId = ""
	return &streamCapacity{client: client, owner: owner, body: body, pool: newStreamReservations(nil)}, nil
}

func (c *streamCapacity) refresh(ctx context.Context) error {
	started := time.Now()
	if c.body.RequestId == "" || !started.Before(c.until) {
		id, err := opaqueid.New(opaqueid.IdempotencyPrefix)
		if err != nil {
			return err
		}
		c.body.RequestId, c.until = id, started.Add(10*time.Second)
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	a, err := c.client.AllocateStreamCapacity(call, c.owner.IngressId, c.body)
	if err != nil {
		return err
	}
	if err := call.Err(); err != nil {
		return err
	}
	if a.Resource != c.body.Resource || a.RunId != c.body.RunId || a.RunNumber != c.body.RunNumber || a.Capacity > c.body.Capacity || a.Retired ||
		a.IngressId != c.owner.IngressId || a.IngressRunId != c.owner.IngressRunId || a.IngressLeaseRevision != c.owner.IngressLeaseRevision {
		return ErrStreamReservation
	}
	if len(a.ReservationKey) != 32 {
		return ErrStreamReservation
	}
	allocation := streamAllocation{ID: a.Id, ResourceKind: string(a.Resource.Kind), ResourceID: a.Resource.Id, RunID: a.RunId, RunNumber: uint64(a.RunNumber),
		IngressID: a.IngressId, IngressRunID: a.IngressRunId, IngressLeaseRevision: uint64(a.IngressLeaseRevision), Capacity: a.Capacity, ObservedAt: a.ObservedAt, ValidUntil: a.ValidUntil}
	copy(allocation.ProofKey[:], a.ReservationKey)
	if err := c.pool.apply(allocation, started); err != nil {
		return err
	}
	c.until = started.Add(a.ValidUntil.Sub(a.ObservedAt))
	c.mu.Lock()
	c.id = a.Id
	// leave several observation rounds within short process/guest horizons.
	// retain this cadence during outages; time remaining must not drive a spin.
	c.renewAfter = min(2*time.Second, max(100*time.Millisecond, a.ValidUntil.Sub(a.ObservedAt)/4))
	c.ready = a.PublisherObserved && a.PublisherObservedUntil != nil
	c.publisherUntil = time.Time{}
	if a.PublisherObservedUntil != nil {
		c.publisherUntil = started.Add(a.PublisherObservedUntil.Sub(a.ObservedAt))
	}
	c.mu.Unlock()
	return nil
}

func (c *streamCapacity) refreshInterval() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.renewAfter
}

func (c *streamCapacity) reserve(visitorID string, source netip.Addr, stop func()) (*streamReservation, error) {
	c.mu.Lock()
	id := c.id
	ready := c.ready && c.pool.now().Before(c.publisherUntil)
	c.mu.Unlock()
	if !ready {
		return nil, ErrStreamReservation
	}
	return c.pool.reserve(id, visitorID, source, stop)
}

func (c *streamCapacity) Close(ctx context.Context) error {
	c.closeOnce.Do(func() {
		c.pool.Close()
		if c.id == "" {
			return
		}
		call, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		c.closeErr = c.client.RetireStreamCapacity(call, c.owner.IngressId, c.id, ingressv1.StreamCapacityRetirement{IngressRunId: c.owner.IngressRunId, IngressLeaseRevision: c.owner.IngressLeaseRevision})
	})
	return c.closeErr
}
