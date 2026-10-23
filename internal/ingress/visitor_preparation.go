package ingress

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

// VisitorPreparationControl prepares policy and capacity independently of visitor
// arrivals. public URL and service owners compose these exact-run lifetimes.
type VisitorPreparationControl interface {
	visitorPolicyClient
	streamCapacityClient
}

type preparedVisitorRun struct {
	policy        *visitorPolicy
	capacity      *streamCapacity
	mu            sync.Mutex
	additional    []*streamCapacity
	limit         int
	nextExpansion time.Time
}

func (r *preparedVisitorRun) close(ctx context.Context) {
	r.policy.Close()
	cleanup, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for _, capacity := range r.capacities() {
		_ = capacity.Close(cleanup)
	}
}

// retirePreparedVisitors gives every run the same independent shutdown budget.
// one unavailable control endpoint cannot multiply that deadline by run count.
func retirePreparedVisitors(ctx context.Context, runs []*preparedVisitorRun) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	jobs := make(chan *preparedVisitorRun)
	var workers sync.WaitGroup
	for range min(8, len(runs)) {
		workers.Go(func() {
			for run := range jobs {
				run.close(cleanup)
			}
		})
	}
	for _, run := range runs {
		jobs <- run
	}
	close(jobs)
	workers.Wait()
}

func (r *preparedVisitorRun) active() bool {
	for _, capacity := range r.capacities() {
		capacity.pool.mu.Lock()
		active := len(capacity.pool.active) != 0
		capacity.pool.mu.Unlock()
		if active {
			return true
		}
	}
	return false
}

func (r *preparedVisitorRun) capacities() []*streamCapacity {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*streamCapacity{r.capacity}, r.additional...)
}

func (r *preparedVisitorRun) expand(ctx context.Context, report func(error)) {
	var used, delegated int
	for _, capacity := range r.capacities() {
		capacity.pool.mu.Lock()
		used += len(capacity.pool.active)
		for _, slots := range capacity.pool.allocations {
			if !slots.allocation.Retired && slots.allocation.ValidUntil.After(time.Now()) {
				delegated += slots.allocation.Capacity
			}
		}
		capacity.pool.mu.Unlock()
	}
	if used < max(1, delegated*3/4) || delegated >= r.limit || len(r.additional) >= 31 || time.Now().Before(r.nextExpansion) {
		return
	}
	r.nextExpansion = time.Now().Add(2 * time.Second)
	body := ingressv1.StreamCapacityRequest{Resource: r.capacity.body.Resource, RunId: r.capacity.body.RunId, RunNumber: r.capacity.body.RunNumber, Capacity: r.capacity.body.Capacity}
	body.Capacity = min(body.Capacity, r.limit-delegated)
	extra, err := prepareStreamCapacity(ctx, r.capacity.client, r.capacity.owner, body, report)
	if err != nil {
		return
	}
	r.mu.Lock()
	r.additional = append(r.additional, extra)
	r.mu.Unlock()
}

func (r *preparedVisitorRun) reserve(visitor string, source netip.Addr, stop func()) (*streamReservation, *visitorlease.ReservationGuard, error) {
	for _, capacity := range r.capacities() {
		reservation, err := capacity.reserve(visitor, stop)
		if err != nil {
			continue
		}
		guard, err := r.policy.lease.BindReservationFrom(reservation.header, source, stop)
		if err != nil {
			reservation.Close()
			continue
		}
		return reservation, guard, nil
	}
	return nil, nil, ErrStreamReservation
}
