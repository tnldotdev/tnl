package state

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var ErrStreamCapacity = errors.New("stream capacity is unavailable")

type StreamCapacityRequest struct {
	Owner     IngressLeaseIdentity
	Scope     visitorscope.Scope
	RunID     string
	RunNumber int64
	RequestID string
	Capacity  int32
}

type StreamCapacityAllocation struct {
	ID                     string
	Scope                  visitorscope.Scope
	RunID                  string
	RunNumber              int64
	Owner                  IngressLeaseIdentity
	Capacity               int32
	ObservedAt, ValidUntil time.Time
	Retired                bool
}

func (a StreamCapacityAllocation) Wire() controlv1.StreamCapacityAllocation {
	return controlv1.StreamCapacityAllocation{Id: a.ID, Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKind(a.Scope.Kind), Id: a.Scope.ID}, RunId: a.RunID, RunNumber: a.RunNumber,
		IngressId: a.Owner.IngressID, IngressRunId: a.Owner.IngressRunID, IngressLeaseRevision: int64(a.Owner.IngressLeaseRevision), Capacity: int(a.Capacity), ObservedAt: a.ObservedAt, ValidUntil: a.ValidUntil, Retired: a.Retired}
}

func allocationRecord(row controlstatedb.ControlStreamCapacityAllocation, now time.Time) StreamCapacityAllocation {
	return StreamCapacityAllocation{ID: row.ID, Scope: visitorscope.Scope{Kind: visitorscope.Kind(row.ResourceKind), ID: row.ResourceID}, RunID: row.RunID, RunNumber: row.RunNumber,
		Owner: IngressLeaseIdentity{IngressID: row.IngressID, IngressRunID: row.IngressRunID, IngressLeaseRevision: uint64(row.IngressLeaseRevision)}, Capacity: row.Capacity, ObservedAt: now, ValidUntil: row.ValidUntil.Time, Retired: row.RetiredAt.Valid}
}

// AllocateStreamCapacity holds the existing team/resource/run admission guards.
// allocations count all owners until their fixed deadlines, including retired
// owners. no connection reservation creates or renews a database row.
func (d *Database) AllocateStreamCapacity(ctx context.Context, request StreamCapacityRequest, now time.Time) (result StreamCapacityAllocation, retErr error) {
	if !request.Scope.Valid() || request.RunNumber < 1 || !validIdempotencyKey(request.RequestID) || request.Capacity < 1 || request.Capacity > 1<<20 {
		return result, ErrStreamCapacity
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "allocate stream capacity", &retErr)()
	q := controlstatedb.New(tx)
	resource, err := lockVisitorResource(ctx, tx, request.Scope, now)
	if err != nil {
		return result, err
	}
	var capacity int64
	var expires time.Time
	switch request.Scope.Kind {
	case visitorscope.PublicURL:
		run, err := q.LockPublishRun(ctx, request.RunID)
		if err != nil {
			return result, publisherLookupError(err, ErrStreamCapacity)
		}
		if run.PublicURLID != request.Scope.ID || run.PublishRunNumber != request.RunNumber || run.ClosedAt.Valid || (run.State != "starting" && run.State != "ready") || !run.PublisherExpiresAt.Time.After(now) {
			return result, ErrStreamCapacity
		}
		limits := trafficlimits.Default()
		if len(run.TrafficLimits) > 0 && json.Unmarshal(run.TrafficLimits, &limits) != nil {
			return result, ErrStreamCapacity
		}
		capacity, expires = int64(limits.Connections), run.PublisherExpiresAt.Time
	case visitorscope.Service:
		run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: request.RunID, ServiceID: request.Scope.ID})
		if err != nil {
			return result, publisherLookupError(err, ErrStreamCapacity)
		}
		if run.RunNumber != request.RunNumber || run.ClosedAt.Valid || (run.State != "starting" && run.State != "ready") || !run.PublisherExpiresAt.Time.After(now) {
			return result, ErrStreamCapacity
		}
		capacity, expires = int64(run.StreamCapacity), run.PublisherExpiresAt.Time
	}
	if !resource.ExpiresAt.IsZero() {
		expires = minTime(expires, resource.ExpiresAt)
	}
	lease, err := lockCurrentIngressLease(ctx, q, request.Owner, now)
	if err != nil {
		return result, err
	}
	if lease.Draining {
		return result, ErrStreamCapacity
	}
	if resource.IngressPoolID != lease.IngressPoolID {
		return result, ErrStreamCapacity
	}
	until := minTime(now.Add(10*time.Second), minTime(expires, lease.LeaseExpiresAt.Time))
	if !until.After(now) {
		return result, ErrStreamCapacity
	}
	used, err := q.SumStreamCapacityAllocations(ctx, controlstatedb.SumStreamCapacityAllocationsParams{ResourceKind: string(request.Scope.Kind), ResourceID: request.Scope.ID, RunID: request.RunID, Now: timestamptz(now)})
	if err != nil {
		return result, err
	}
	prior, err := q.FindStreamCapacityAllocation(ctx, controlstatedb.FindStreamCapacityAllocationParams{ResourceKind: string(request.Scope.Kind), ResourceID: request.Scope.ID, RunID: request.RunID,
		IngressID: request.Owner.IngressID, IngressRunID: request.Owner.IngressRunID, IngressLeaseRevision: int64(request.Owner.IngressLeaseRevision), RequestID: request.RequestID})
	if err == nil {
		if prior.RetiredAt.Valid || !prior.ValidUntil.Time.After(now) || prior.RunNumber != request.RunNumber || used > capacity {
			return result, ErrStreamCapacity
		}
		prior, err = q.RenewStreamCapacityAllocation(ctx, controlstatedb.RenewStreamCapacityAllocationParams{ID: prior.ID, Now: timestamptz(now), ValidUntil: timestamptz(until)})
		if err != nil {
			return result, err
		}
		result = allocationRecord(prior, now)
		return result, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	available := capacity - used
	if available < 1 {
		return result, ErrStreamCapacity
	}
	allocations, err := q.CountStreamCapacityAllocations(ctx, controlstatedb.CountStreamCapacityAllocationsParams{ResourceKind: string(request.Scope.Kind), ResourceID: request.Scope.ID, Now: timestamptz(now)})
	if err != nil {
		return result, err
	}
	if allocations >= 2048 {
		return result, ErrStreamCapacity
	}
	amount := int32(min(int64(request.Capacity), available))
	id, err := opaqueid.New("salloc_")
	if err != nil {
		return result, err
	}
	row, err := q.CreateStreamCapacityAllocation(ctx, controlstatedb.CreateStreamCapacityAllocationParams{ID: id, ResourceKind: string(request.Scope.Kind), ResourceID: request.Scope.ID, RunID: request.RunID, RunNumber: request.RunNumber,
		IngressID: request.Owner.IngressID, IngressRunID: request.Owner.IngressRunID, IngressLeaseRevision: int64(request.Owner.IngressLeaseRevision), RequestID: request.RequestID, Capacity: amount, Now: timestamptz(now), ValidUntil: timestamptz(until)})
	if err != nil {
		return result, err
	}
	result = allocationRecord(row, now)
	return result, tx.Commit(ctx)
}

func (d *Database) RetireStreamCapacity(ctx context.Context, owner IngressLeaseIdentity, id string, now time.Time) (retErr error) {
	if !opaqueid.Valid(id, "salloc_") {
		return ErrStreamCapacity
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "retire stream capacity", &retErr)()
	if _, err := lockCurrentIngressLease(ctx, controlstatedb.New(tx), owner, now); err != nil {
		return err
	}
	count, err := controlstatedb.New(tx).RetireStreamCapacityAllocation(ctx, controlstatedb.RetireStreamCapacityAllocationParams{ID: id, IngressID: owner.IngressID, IngressRunID: owner.IngressRunID, IngressLeaseRevision: int64(owner.IngressLeaseRevision), Now: timestamptz(now)})
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrStreamCapacity
	}
	return tx.Commit(ctx)
}
