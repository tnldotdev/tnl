package routes

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/naming"
	"github.com/0xcadams/tnl/internal/tailtransport"
	"github.com/0xcadams/tnl/internal/worker"
	"github.com/0xcadams/tnl/pkg/protocol/transportv1"
	"tailscale.com/types/key"
)

var ErrNoWorkerCapacity = errors.New("routes: no worker capacity")

const (
	routeLockStripes  = 64
	leaseReapInterval = time.Second
)

type LeaseSetup struct {
	Provisioning
	IngressPublicKey string
}

type ActiveRoute struct {
	RouteID    string
	Generation uint64
	Backend    worker.RouteBackend
}

// routeSnapshot is immutable after publication for lock-free ingress reads.
type routeSnapshot struct {
	byHostname map[string]ActiveRoute
}

type ownerState struct {
	id       string
	owner    worker.RouteOwner
	draining bool
	routes   map[string]worker.OwnedRoute
}

type assignment struct {
	ref       worker.RouteRef
	hostname  string
	expiresAt time.Time
	owner     *ownerState
	backend   worker.OwnedRoute
}

type pendingLease struct {
	hostname  string
	key       key.NodePrivate
	expiresAt time.Time
}

type Coordinator struct {
	store     *Store
	bootEpoch string

	// mutationMu sequences generation changes; routeLocks fence leases; mu guards runtime state.
	mu          sync.Mutex
	mutationMu  sync.Mutex
	owners      map[string]*ownerState
	pending     map[worker.RouteRef]pendingLease
	assignments map[string]*assignment
	challenges  map[string]*assignment
	routeLocks  [routeLockStripes]sync.Mutex
	snapshot    atomic.Pointer[routeSnapshot]
	closed      bool
	stopReaper  context.CancelFunc
	reaperDone  chan struct{}
}

func NewCoordinator(ctx context.Context, store *Store, bootEpoch string) (*Coordinator, error) {
	if store == nil || strings.TrimSpace(bootEpoch) == "" {
		return nil, errors.New("routes: store and boot epoch are required")
	}
	if err := store.InvalidateOtherBoots(ctx, bootEpoch); err != nil {
		return nil, err
	}
	reaperCtx, stopReaper := context.WithCancel(ctx)
	c := &Coordinator{
		store:       store,
		bootEpoch:   bootEpoch,
		owners:      make(map[string]*ownerState),
		pending:     make(map[worker.RouteRef]pendingLease),
		assignments: make(map[string]*assignment),
		challenges:  make(map[string]*assignment),
		stopReaper:  stopReaper,
		reaperDone:  make(chan struct{}),
	}
	c.snapshot.Store(&routeSnapshot{byHostname: map[string]ActiveRoute{}})
	go c.reapLeases(reaperCtx)
	return c, nil
}

func (c *Coordinator) AddOwner(id string, owner worker.RouteOwner) error {
	if strings.TrimSpace(id) == "" || owner == nil {
		return errors.New("routes: owner ID and implementation are required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if _, exists := c.owners[id]; exists {
		return errors.New("routes: duplicate owner ID")
	}
	c.owners[id] = &ownerState{id: id, owner: owner, routes: make(map[string]worker.OwnedRoute)}
	return nil
}

func (c *Coordinator) Create(
	ctx context.Context,
	principalID, hostname, displayTarget string,
	routeToken credentials.RouteToken,
) (LeaseSetup, error) {
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	if c.isClosed() {
		return LeaseSetup{}, net.ErrClosed
	}
	existingRouteID, err := c.store.ActiveRouteID(ctx, principalID, hostname)
	if err != nil {
		return LeaseSetup{}, err
	}
	if existingRouteID != "" {
		lock := c.routeLock(existingRouteID)
		lock.Lock()
		defer lock.Unlock()
	}
	provisioning, err := c.store.Create(ctx, principalID, hostname, displayTarget, c.bootEpoch, routeToken)
	if err != nil {
		return LeaseSetup{}, err
	}
	if provisioning.Route.Generation > 1 {
		c.deactivate(provisioning.Route.ID)
	}
	return c.prepare(provisioning)
}

func (c *Coordinator) Acquire(
	ctx context.Context,
	principalID, routeID string,
	token credentials.RouteToken,
) (LeaseSetup, error) {
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	if c.isClosed() {
		return LeaseSetup{}, net.ErrClosed
	}
	if _, err := c.store.AuthorizeRoute(ctx, principalID, routeID, token); err != nil {
		return LeaseSetup{}, err
	}
	lock := c.routeLock(routeID)
	lock.Lock()
	defer lock.Unlock()
	provisioning, err := c.store.Acquire(ctx, principalID, routeID, c.bootEpoch, token)
	if err != nil {
		return LeaseSetup{}, err
	}
	c.deactivate(routeID)
	return c.prepare(provisioning)
}

func (c *Coordinator) prepare(provisioning Provisioning) (LeaseSetup, error) {
	ingressKey := key.NewNode()
	ref := worker.RouteRef{RouteID: provisioning.Route.ID, Generation: provisioning.Lease.Generation}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return LeaseSetup{}, net.ErrClosed
	}
	for existing := range c.pending {
		if existing.RouteID == ref.RouteID {
			delete(c.pending, existing)
		}
	}
	c.pending[ref] = pendingLease{
		hostname: provisioning.Route.Hostname, key: ingressKey, expiresAt: provisioning.Lease.ExpiresAt,
	}
	c.mu.Unlock()
	return LeaseSetup{Provisioning: provisioning, IngressPublicKey: ingressKey.Public().String()}, nil
}

func (c *Coordinator) RegisterTransport(
	ctx context.Context,
	routeID string,
	generation uint64,
	token credentials.LeaseToken,
	serverPublicKey, relayProfile string,
) error {
	lock := c.routeLock(routeID)
	lock.Lock()
	defer lock.Unlock()
	lease, err := c.store.AuthenticateLease(ctx, routeID, generation, token, c.bootEpoch)
	if err != nil {
		return err
	}
	ref := worker.RouteRef{RouteID: routeID, Generation: generation}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	if current := c.assignments[routeID]; current != nil && current.ref == ref {
		c.mu.Unlock()
		if lease.ServerPublicKey != serverPublicKey || lease.RelayProfile != relayProfile {
			return ErrInvalidState
		}
		return nil
	}
	if lease.Status == "starting" &&
		(lease.ServerPublicKey != serverPublicKey || lease.RelayProfile != relayProfile) {
		c.mu.Unlock()
		return ErrInvalidState
	}
	pending, ok := c.pending[ref]
	c.mu.Unlock()
	if !ok {
		return ErrStaleLease
	}
	endpoint := tailtransport.Endpoint{
		Version:         transportv1.TailcatDescriptorVersion,
		ServerPublicKey: serverPublicKey,
		RelayProfile:    relayProfile,
	}
	if err := c.store.RegisterTransport(ctx, lease, serverPublicKey, relayProfile); err != nil {
		return err
	}

	tried := make(map[string]struct{})
	for {
		owner := c.selectOwner(tried)
		if owner == nil {
			return ErrNoWorkerCapacity
		}
		tried[owner.id] = struct{}{}
		backend, err := owner.owner.Attach(ctx, worker.Assignment{RouteRef: ref, Endpoint: endpoint, Key: pending.key})
		if errors.Is(err, worker.ErrAtCapacity) || errors.Is(err, worker.ErrDraining) || errors.Is(err, net.ErrClosed) {
			continue
		}
		if err != nil {
			return fmt.Errorf("routes: attach worker route: %w", err)
		}

		// Attach runs without c.mu; recheck the owner and lease before storing its backend.
		c.mu.Lock()
		currentOwner := c.owners[owner.id]
		currentPending, stillPending := c.pending[ref]
		leaseCurrent := stillPending && currentPending.expiresAt.After(c.store.now())
		if currentOwner != owner || owner.draining || !leaseCurrent {
			c.mu.Unlock()
			_ = backend.Close()
			if !leaseCurrent {
				return ErrStaleLease
			}
			continue
		}
		previous := c.assignments[routeID]
		assignment := &assignment{
			ref: ref, hostname: currentPending.hostname, expiresAt: lease.ExpiresAt, owner: owner, backend: backend,
		}
		c.assignments[routeID] = assignment
		c.challenges[assignment.hostname] = assignment
		owner.routes[routeID] = backend
		c.mu.Unlock()
		if previous != nil {
			_ = previous.backend.Close()
		}
		return nil
	}
}

func (c *Coordinator) Ready(
	ctx context.Context,
	routeID string,
	generation uint64,
	token credentials.LeaseToken,
) error {
	lock := c.routeLock(routeID)
	lock.Lock()
	defer lock.Unlock()
	lease, err := c.store.AuthenticateLease(ctx, routeID, generation, token, c.bootEpoch)
	if err != nil {
		return err
	}
	c.mu.Lock()
	current := c.assignments[routeID]
	if current == nil || current.ref.Generation != generation {
		c.mu.Unlock()
		return ErrInvalidState
	}
	c.mu.Unlock()
	if err := c.store.Ready(ctx, lease); err != nil {
		return err
	}
	// Owner loss may race the durable update, so publish only the same assignment.
	c.mu.Lock()
	if c.assignments[routeID] != current {
		c.mu.Unlock()
		return ErrStaleLease
	}
	c.publishLocked(current)
	delete(c.pending, current.ref)
	c.mu.Unlock()
	return nil
}

func (c *Coordinator) Heartbeat(
	ctx context.Context,
	routeID string,
	generation uint64,
	token credentials.LeaseToken,
) (time.Time, error) {
	lock := c.routeLock(routeID)
	lock.Lock()
	defer lock.Unlock()
	lease, err := c.store.AuthenticateLease(ctx, routeID, generation, token, c.bootEpoch)
	if err != nil {
		return time.Time{}, err
	}
	expiresAt, err := c.store.Heartbeat(ctx, lease)
	if err != nil {
		return time.Time{}, err
	}
	ref := worker.RouteRef{RouteID: routeID, Generation: generation}
	c.mu.Lock()
	updated := false
	if pending, ok := c.pending[ref]; ok {
		pending.expiresAt = expiresAt
		c.pending[ref] = pending
		updated = true
	}
	if current := c.assignments[routeID]; current != nil && current.ref == ref {
		current.expiresAt = expiresAt
		updated = true
	}
	c.mu.Unlock()
	if !updated {
		return time.Time{}, ErrStaleLease
	}
	return expiresAt, nil
}

// AuthorizeLease verifies that a lease token owns the current route generation
// without mutating the lease lifetime or route state.
func (c *Coordinator) AuthorizeLease(
	ctx context.Context,
	routeID string,
	generation uint64,
	token credentials.LeaseToken,
) error {
	if c.isClosed() {
		return net.ErrClosed
	}
	_, err := c.store.AuthenticateLease(ctx, routeID, generation, token, c.bootEpoch)
	return err
}

func (c *Coordinator) List(ctx context.Context, principalID string) ([]Route, error) {
	return c.store.List(ctx, principalID)
}

func (c *Coordinator) Delete(ctx context.Context, principalID, routeID string) error {
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	if c.isClosed() {
		return net.ErrClosed
	}
	if err := c.store.AuthorizePrincipal(ctx, principalID, routeID); err != nil {
		return err
	}
	lock := c.routeLock(routeID)
	lock.Lock()
	defer lock.Unlock()
	if err := c.store.Delete(ctx, principalID, routeID); err != nil {
		return err
	}
	c.deactivate(routeID)
	return nil
}

func (c *Coordinator) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *Coordinator) Lookup(hostname string) (ActiveRoute, bool) {
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname {
		return ActiveRoute{}, false
	}
	result, ok := c.snapshot.Load().byHostname[canonical]
	return result, ok
}

// LookupChallenge resolves current assigned routes before ordinary traffic is
// published. Callers must use it only for TLS-ALPN-01 ClientHellos.
func (c *Coordinator) LookupChallenge(hostname string) (ActiveRoute, bool) {
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname {
		return ActiveRoute{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ActiveRoute{}, false
	}
	current := c.challenges[hostname]
	if current != nil && current.expiresAt.After(c.store.now()) {
		return ActiveRoute{
			RouteID: current.ref.RouteID, Generation: current.ref.Generation, Backend: current.backend,
		}, true
	}
	return ActiveRoute{}, false
}

func (c *Coordinator) DrainOwner(ctx context.Context, id string) error {
	c.mu.Lock()
	owner := c.owners[id]
	if owner == nil {
		c.mu.Unlock()
		return ErrNotFound
	}
	owner.draining = true
	assigned := c.ownerAssignmentsLocked(owner)
	for _, current := range assigned {
		c.unpublishLocked(current.ref.RouteID, current.ref.Generation)
	}
	c.mu.Unlock()
	for _, current := range assigned {
		_ = c.store.Expire(ctx, current.ref.RouteID, current.ref.Generation)
	}
	err := owner.owner.Drain(ctx)
	c.removeOwner(owner)
	return err
}

func (c *Coordinator) RemoveOwner(id string) {
	c.mu.Lock()
	owner := c.owners[id]
	c.mu.Unlock()
	if owner != nil {
		c.removeOwner(owner)
	}
}

func (c *Coordinator) Close() error {
	c.mu.Lock()
	if c.closed {
		reaperDone := c.reaperDone
		c.mu.Unlock()
		<-reaperDone
		return nil
	}
	c.closed = true
	stopReaper := c.stopReaper
	reaperDone := c.reaperDone
	owners := make([]*ownerState, 0, len(c.owners))
	for _, owner := range c.owners {
		owners = append(owners, owner)
	}
	clear(c.owners)
	clear(c.pending)
	clear(c.assignments)
	c.snapshot.Store(&routeSnapshot{byHostname: map[string]ActiveRoute{}})
	c.mu.Unlock()
	stopReaper()
	<-reaperDone
	var result error
	for _, owner := range owners {
		result = errors.Join(result, owner.owner.Close())
	}
	return result
}

func (c *Coordinator) selectOwner(tried map[string]struct{}) *ownerState {
	c.mu.Lock()
	defer c.mu.Unlock()
	candidates := make([]*ownerState, 0, len(c.owners))
	for id, owner := range c.owners {
		if _, seen := tried[id]; seen || owner.draining {
			continue
		}
		capacity := owner.owner.Capacity()
		if capacity.Draining || capacity.Active >= capacity.Limit {
			continue
		}
		candidates = append(candidates, owner)
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := candidates[i].owner.Capacity(), candidates[j].owner.Capacity()
		if left.Active != right.Active {
			return left.Active < right.Active
		}
		return candidates[i].id < candidates[j].id
	})
	if len(candidates) == 0 {
		return nil
	}
	return candidates[0]
}

func (c *Coordinator) deactivate(routeID string) {
	c.mu.Lock()
	for ref := range c.pending {
		if ref.RouteID == routeID {
			delete(c.pending, ref)
		}
	}
	current := c.assignments[routeID]
	if current != nil {
		delete(c.assignments, routeID)
		if c.challenges[current.hostname] == current {
			delete(c.challenges, current.hostname)
		}
		delete(current.owner.routes, routeID)
		c.unpublishLocked(routeID, current.ref.Generation)
	}
	c.mu.Unlock()
	if current != nil {
		_ = current.backend.Close()
	}
}

func (c *Coordinator) publishLocked(current *assignment) {
	next := cloneSnapshot(c.snapshot.Load())
	next.byHostname[current.hostname] = ActiveRoute{
		RouteID: current.ref.RouteID, Generation: current.ref.Generation, Backend: current.backend,
	}
	c.snapshot.Store(next)
}

func (c *Coordinator) unpublishLocked(routeID string, generation uint64) {
	current := c.snapshot.Load()
	next := cloneSnapshot(current)
	for hostname, route := range next.byHostname {
		if route.RouteID == routeID && route.Generation == generation {
			delete(next.byHostname, hostname)
		}
	}
	c.snapshot.Store(next)
}

func cloneSnapshot(current *routeSnapshot) *routeSnapshot {
	next := &routeSnapshot{byHostname: make(map[string]ActiveRoute, len(current.byHostname))}
	for hostname, route := range current.byHostname {
		next.byHostname[hostname] = route
	}
	return next
}

func (c *Coordinator) removeOwner(owner *ownerState) {
	c.mu.Lock()
	if c.owners[owner.id] != owner {
		c.mu.Unlock()
		return
	}
	delete(c.owners, owner.id)
	assigned := c.ownerAssignmentsLocked(owner)
	for _, current := range assigned {
		delete(c.assignments, current.ref.RouteID)
		if c.challenges[current.hostname] == current {
			delete(c.challenges, current.hostname)
		}
		delete(c.pending, current.ref)
		c.unpublishLocked(current.ref.RouteID, current.ref.Generation)
	}
	c.mu.Unlock()
	_ = owner.owner.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, current := range assigned {
		_ = c.store.Expire(ctx, current.ref.RouteID, current.ref.Generation)
	}
}

func (c *Coordinator) ownerAssignmentsLocked(owner *ownerState) []*assignment {
	assigned := make([]*assignment, 0, len(owner.routes))
	for routeID := range owner.routes {
		if current := c.assignments[routeID]; current != nil && current.owner == owner {
			assigned = append(assigned, current)
		}
	}
	return assigned
}

func (c *Coordinator) routeLock(routeID string) *sync.Mutex {
	var hash uint32 = 2166136261
	for index := range len(routeID) {
		hash ^= uint32(routeID[index])
		hash *= 16777619
	}
	return &c.routeLocks[hash%routeLockStripes]
}

func (c *Coordinator) reapLeases(ctx context.Context) {
	defer close(c.reaperDone)
	ticker := time.NewTicker(leaseReapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			c.expireDue(ctx, now)
		}
	}
}

func (c *Coordinator) expireDue(ctx context.Context, now time.Time) {
	c.mu.Lock()
	due := make(map[worker.RouteRef]struct{})
	for ref, pending := range c.pending {
		if !pending.expiresAt.After(now) {
			due[ref] = struct{}{}
		}
	}
	for _, current := range c.assignments {
		if !current.expiresAt.After(now) {
			due[current.ref] = struct{}{}
		}
	}
	c.mu.Unlock()

	// A heartbeat may race the scan, so recheck each candidate under its route lock.
	for ref := range due {
		lock := c.routeLock(ref.RouteID)
		lock.Lock()
		backend, expired := c.expireMemory(ref, now)
		if expired {
			_ = c.store.Expire(ctx, ref.RouteID, ref.Generation)
		}
		lock.Unlock()
		if backend != nil {
			_ = backend.Close()
		}
	}
}

func (c *Coordinator) expireMemory(ref worker.RouteRef, now time.Time) (worker.OwnedRoute, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	expired := false
	if pending, ok := c.pending[ref]; ok && !pending.expiresAt.After(now) {
		delete(c.pending, ref)
		expired = true
	}
	current := c.assignments[ref.RouteID]
	if current == nil || current.ref != ref || current.expiresAt.After(now) {
		return nil, expired
	}
	delete(c.assignments, ref.RouteID)
	if c.challenges[current.hostname] == current {
		delete(c.challenges, current.hostname)
	}
	delete(current.owner.routes, ref.RouteID)
	c.unpublishLocked(ref.RouteID, ref.Generation)
	return current.backend, true
}

func (c *Coordinator) Stats() (provisioning, active int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending), len(c.snapshot.Load().byHostname)
}
