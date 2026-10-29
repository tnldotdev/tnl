package ingress

import (
	"errors"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrStreamReservation = errors.New("stream reservation capacity is unavailable")

// streamAllocation is control's bounded grant to this exact process. timestamps
// are converted from its observation to the local request-start clock on apply.
type streamAllocation struct {
	ID                              string
	ResourceKind, ResourceID, RunID string
	RunNumber                       uint64
	IngressID, IngressRunID         string
	IngressLeaseRevision            uint64
	Capacity                        int
	ObservedAt, ValidUntil          time.Time
	Retired                         bool
	ProofKey                        [32]byte
}

type streamReservations struct {
	mu          sync.Mutex
	now         func() time.Time
	allocations map[string]*allocationSlots
	active      map[string]*streamReservation
	closed      bool
}

type allocationSlots struct {
	allocation streamAllocation
	occupied   map[uint32]*streamReservation
	sequences  map[uint32]uint64
	timer      *time.Timer
}

type streamReservation struct {
	owner  *streamReservations
	slots  *allocationSlots
	header tunnelv1.StreamReservation
	stop   func()
	closed bool
}

func newStreamReservations(now func() time.Time) *streamReservations {
	if now == nil {
		now = time.Now
	}
	return &streamReservations{now: now, allocations: make(map[string]*allocationSlots), active: make(map[string]*streamReservation)}
}

func (s *streamReservations) apply(allocation streamAllocation, started time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	duration := allocation.ValidUntil.Sub(allocation.ObservedAt)
	if s.closed || started.IsZero() || s.now().Before(started) || !opaqueid.Valid(allocation.ID, "salloc_") || allocation.ProofKey == ([32]byte{}) || allocation.Capacity < 1 || allocation.Capacity > 1<<20 || duration <= 0 || duration > 10*time.Second || !s.now().Before(started.Add(duration)) {
		return ErrStreamReservation
	}
	probe := tunnelv1.StreamReservation{ID: "sres_aaaaaaaaaaaaaaaaaaaaaa", AllocationID: allocation.ID, Sequence: 1, ResourceKind: allocation.ResourceKind, ResourceID: allocation.ResourceID, RunID: allocation.RunID, RunNumber: allocation.RunNumber,
		VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", IngressID: allocation.IngressID, IngressRunID: allocation.IngressRunID, IngressLeaseRevision: allocation.IngressLeaseRevision}
	if probe.Validate() != nil {
		return ErrStreamReservation
	}
	allocation.ObservedAt, allocation.ValidUntil = started, started.Add(duration)
	slots := s.allocations[allocation.ID]
	if slots != nil {
		old := slots.allocation
		if !s.now().Before(old.ValidUntil) || old.Retired || allocation.ObservedAt.Before(old.ObservedAt) || old.ProofKey != allocation.ProofKey || old.Capacity != allocation.Capacity || old.ResourceKind != allocation.ResourceKind || old.ResourceID != allocation.ResourceID || old.RunID != allocation.RunID || old.RunNumber != allocation.RunNumber || old.IngressID != allocation.IngressID || old.IngressRunID != allocation.IngressRunID || old.IngressLeaseRevision != allocation.IngressLeaseRevision {
			return ErrStreamReservation
		}
		slots.allocation = allocation
		slots.timer.Reset(allocation.ValidUntil.Sub(s.now()))
		return nil
	}
	slots = &allocationSlots{allocation: allocation, occupied: make(map[uint32]*streamReservation), sequences: make(map[uint32]uint64)}
	slots.timer = time.AfterFunc(allocation.ValidUntil.Sub(s.now()), func() { s.expire(allocation.ID, slots) })
	s.allocations[allocation.ID] = slots
	return nil
}

func (s *streamReservations) reserve(allocationID, visitorID string, source netip.Addr, stop func()) (*streamReservation, error) {
	if !opaqueid.Valid(visitorID, opaqueid.VisitorConnectionPrefix) || !source.IsValid() || source.Zone() != "" || stop == nil {
		return nil, ErrStreamReservation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	slots := s.allocations[allocationID]
	if s.closed || slots == nil || slots.allocation.Retired || !s.now().Before(slots.allocation.ValidUntil) || len(slots.occupied) >= slots.allocation.Capacity || s.active[visitorID] != nil {
		return nil, ErrStreamReservation
	}
	id, err := opaqueid.New("sres_")
	if err != nil {
		return nil, err
	}
	a := slots.allocation
	var slot uint32
	for slot < uint32(a.Capacity) && (slots.occupied[slot] != nil || slots.sequences[slot] == math.MaxUint64) {
		slot++
	}
	if slot == uint32(a.Capacity) {
		return nil, ErrStreamReservation
	}
	slots.sequences[slot]++
	r := &streamReservation{owner: s, slots: slots, stop: stop, header: tunnelv1.StreamReservation{ID: id, AllocationID: a.ID, Slot: slot, Sequence: slots.sequences[slot], ResourceKind: a.ResourceKind, ResourceID: a.ResourceID, RunID: a.RunID, RunNumber: a.RunNumber,
		VisitorConnectionID: visitorID, IngressID: a.IngressID, IngressRunID: a.IngressRunID, IngressLeaseRevision: a.IngressLeaseRevision}}
	if err := visitortoken.SignReservation(a.ProofKey[:], &r.header, source); err != nil {
		return nil, ErrStreamReservation
	}
	slots.occupied[slot] = r
	s.active[visitorID] = r
	return r, nil
}

func (r *streamReservation) Close() {
	s := r.owner
	s.mu.Lock()
	if !r.closed {
		r.closed = true
		if s.active[r.header.VisitorConnectionID] == r {
			delete(s.active, r.header.VisitorConnectionID)
		}
		if r.slots.occupied[r.header.Slot] == r {
			delete(r.slots.occupied, r.header.Slot)
		}
	}
	s.mu.Unlock()
}

func (s *streamReservations) expire(id string, slots *allocationSlots) {
	s.mu.Lock()
	if s.allocations[id] != slots || s.now().Before(slots.allocation.ValidUntil) {
		s.mu.Unlock()
		return
	}
	// an old reply can remain in flight for at most the allocation lifetime.
	// keep a tombstone through that window, then discard its slot watermarks.
	if slots.allocation.Retired && !s.now().Before(slots.allocation.ValidUntil.Add(10*time.Second)) {
		delete(s.allocations, id)
		s.mu.Unlock()
		return
	}
	slots.allocation.Retired = true
	slots.timer.Reset(max(0, slots.allocation.ValidUntil.Add(10*time.Second).Sub(s.now())))
	var expired []*streamReservation
	for visitor, r := range s.active {
		if r.slots == slots {
			r.closed = true
			delete(slots.occupied, r.header.Slot)
			delete(s.active, visitor)
			expired = append(expired, r)
		}
	}
	s.mu.Unlock()
	for _, r := range expired {
		r.stop()
	}
}

func (s *streamReservations) Close() {
	s.mu.Lock()
	s.closed = true
	for _, slots := range s.allocations {
		slots.timer.Stop()
	}
	var active []*streamReservation
	for visitor, r := range s.active {
		r.closed = true
		delete(r.slots.occupied, r.header.Slot)
		delete(s.active, visitor)
		active = append(active, r)
	}
	clear(s.allocations)
	s.mu.Unlock()
	for _, r := range active {
		r.stop()
	}
}
