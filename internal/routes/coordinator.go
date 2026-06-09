package routes

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/tailtransport"
	"github.com/tnldotdev/tnl/internal/worker"
	"github.com/tnldotdev/tnl/pkg/protocol/transportv1"
	"tailscale.com/types/key"
)

var ErrNoWorkerCapacity = errors.New("routes: no worker capacity")

const (
	sessionReapInterval = time.Second
)

type SessionSetup struct {
	Provisioning
	WorkerPublicKey string
}

type RoutableRoute struct {
	RouteID           string
	RouteVersion      uint64
	AllowedIPPrefixes []netip.Prefix
	Backend           worker.RouteBackend
	expires           time.Time
}

// routeSnapshot is immutable after publishing for lock-free ingress reads.
type routeSnapshot struct {
	byHostname map[string]RoutableRoute
}

type workerState struct {
	id       string
	worker   worker.RouteWorker
	draining bool
	routes   map[string]worker.WorkerRoute
}

type assignment struct {
	ref               worker.RouteRef
	hostname          string
	allowedIPPrefixes []netip.Prefix
	expiresAt         time.Time
	worker            *workerState
	backend           worker.WorkerRoute
}

type pendingSession struct {
	hostname          string
	allowedIPPrefixes []netip.Prefix
	key               key.NodePrivate
	expiresAt         time.Time
}

type routeMutex struct {
	sync.Mutex
	users int
}

type Coordinator struct {
	store            *Store
	serverInstanceID string
	config           CoordinatorConfig

	// mutationMu sequences hostname and route changes; routeLocks fence sessions; mu guards runtime state.
	mu           sync.Mutex
	mutationMu   sync.Mutex
	routeLocksMu sync.Mutex
	workers      map[string]*workerState
	pending      map[worker.RouteRef]pendingSession
	assignments  map[string]*assignment
	challenges   map[string]*assignment
	routeLocks   map[string]*routeMutex
	snapshot     atomic.Pointer[routeSnapshot]
	closed       bool
	stopReaper   context.CancelFunc
	reaperDone   chan struct{}
}

func NewCoordinator(
	ctx context.Context,
	store *Store,
	serverInstanceID string,
	configs ...CoordinatorConfig,
) (*Coordinator, error) {
	if store == nil || strings.TrimSpace(serverInstanceID) == "" {
		return nil, errors.New("routes: store and server instance ID are required")
	}
	if len(configs) > 1 {
		return nil, errors.New("routes: multiple coordinator configurations")
	}
	var config CoordinatorConfig
	if len(configs) == 1 {
		config = configs[0]
	}
	if err := store.InvalidateOtherServerInstances(ctx, serverInstanceID); err != nil {
		return nil, err
	}
	reaperCtx, stopReaper := context.WithCancel(ctx)
	c := &Coordinator{
		store:            store,
		serverInstanceID: serverInstanceID,
		config:           config,
		workers:          make(map[string]*workerState),
		pending:          make(map[worker.RouteRef]pendingSession),
		assignments:      make(map[string]*assignment),
		challenges:       make(map[string]*assignment),
		routeLocks:       make(map[string]*routeMutex),
		stopReaper:       stopReaper,
		reaperDone:       make(chan struct{}),
	}
	c.snapshot.Store(&routeSnapshot{byHostname: map[string]RoutableRoute{}})
	go c.reapSessions(reaperCtx)
	return c, nil
}

func (c *Coordinator) AddWorker(id string, routeWorker worker.RouteWorker) error {
	if strings.TrimSpace(id) == "" || routeWorker == nil {
		return errors.New("routes: worker ID and implementation are required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if _, exists := c.workers[id]; exists {
		return errors.New("routes: duplicate worker ID")
	}
	c.workers[id] = &workerState{id: id, worker: routeWorker, routes: make(map[string]worker.WorkerRoute)}
	return nil
}

func (c *Coordinator) Create(
	ctx context.Context,
	identityID, hostname, localTarget string,
	routeToken credentials.RouteToken,
	allowedIPPrefixes []string,
) (SessionSetup, error) {
	removed := false
	defer func() {
		if removed {
			c.observeRouteRemoval(RouteRemovalRouteVersionReplaced)
		}
	}()
	if c.config.CheckHostnamePublishability != nil {
		if err := c.config.CheckHostnamePublishability(ctx, hostname); err != nil {
			return SessionSetup{}, ErrUnavailable
		}
	}
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	if c.isClosed() {
		return SessionSetup{}, net.ErrClosed
	}
	existingRouteID, err := c.store.EnabledRouteID(ctx, identityID, hostname)
	if err != nil {
		return SessionSetup{}, err
	}
	if existingRouteID != "" {
		unlockRoute := c.lockRoute(existingRouteID)
		defer unlockRoute()
	}
	provisioning, err := c.store.Create(
		ctx, identityID, hostname, localTarget, c.serverInstanceID, routeToken, allowedIPPrefixes,
	)
	if err != nil {
		return SessionSetup{}, err
	}
	if provisioning.Route.RouteVersion > 1 {
		removed = c.deactivate(provisioning.Route.ID)
	}
	return c.prepare(provisioning)
}

func (c *Coordinator) CreateSession(
	ctx context.Context,
	identityID, routeID string,
	token credentials.RouteToken,
	allowedIPPrefixes []string,
) (SessionSetup, error) {
	removed := false
	defer func() {
		if removed {
			c.observeRouteRemoval(RouteRemovalRouteVersionReplaced)
		}
	}()
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	if c.isClosed() {
		return SessionSetup{}, net.ErrClosed
	}
	if _, err := c.store.AuthorizeRoute(ctx, identityID, routeID, token); err != nil {
		return SessionSetup{}, err
	}
	unlockRoute := c.lockRoute(routeID)
	defer unlockRoute()
	provisioning, err := c.store.CreateSession(
		ctx, identityID, routeID, c.serverInstanceID, token, allowedIPPrefixes,
	)
	if err != nil {
		return SessionSetup{}, err
	}
	removed = c.deactivate(routeID)
	return c.prepare(provisioning)
}

func (c *Coordinator) CreateSigned(
	ctx context.Context,
	hostname, localTarget string,
	routeToken credentials.RouteToken,
	request SignedRequest,
) (SessionSetup, error) {
	removed := false
	defer func() {
		if removed {
			c.observeRouteRemoval(RouteRemovalRouteVersionReplaced)
		}
	}()
	validated, err := c.store.validateSignedCreate(hostname, localTarget, routeToken, request)
	if err != nil {
		return SessionSetup{}, err
	}
	if c.config.CheckHostnamePublishability != nil {
		if err := c.config.CheckHostnamePublishability(ctx, validated.hostname); err != nil {
			return SessionSetup{}, ErrUnavailable
		}
	}
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	if c.isClosed() {
		return SessionSetup{}, net.ErrClosed
	}
	existingRouteID, err := c.store.CurrentSignedRouteID(ctx, validated.hostname)
	if err != nil {
		return SessionSetup{}, err
	}
	if existingRouteID != "" {
		unlockRoute := c.lockRoute(existingRouteID)
		defer unlockRoute()
	}
	provisioning, err := c.store.CreateSigned(
		ctx, validated.hostname, localTarget, c.serverInstanceID, routeToken, request,
	)
	if err != nil {
		return SessionSetup{}, err
	}
	if provisioning.Restored || !provisioning.ReusedResult && provisioning.Route.RouteVersion > 1 {
		removed = c.deactivate(provisioning.Route.ID)
	}
	return c.prepare(provisioning)
}

func (c *Coordinator) CreateSignedSession(
	ctx context.Context,
	routeID string,
	routeToken credentials.RouteToken,
	request SignedRequest,
) (SessionSetup, error) {
	removed := false
	defer func() {
		if removed {
			c.observeRouteRemoval(RouteRemovalRouteVersionReplaced)
		}
	}()
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	if c.isClosed() {
		return SessionSetup{}, net.ErrClosed
	}
	unlockRoute := c.lockRoute(routeID)
	defer unlockRoute()
	provisioning, err := c.store.CreateSignedSession(
		ctx, routeID, c.serverInstanceID, routeToken, request,
	)
	if err != nil {
		return SessionSetup{}, err
	}
	if provisioning.Restored || !provisioning.ReusedResult {
		removed = c.deactivate(routeID)
	}
	return c.prepare(provisioning)
}

func (c *Coordinator) prepare(provisioning Provisioning) (SessionSetup, error) {
	allowedIPPrefixes := make([]netip.Prefix, len(provisioning.Route.AllowedIPPrefixes))
	for index, value := range provisioning.Route.AllowedIPPrefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.String() != value {
			return SessionSetup{}, errors.New("routes: stored IP policy is invalid")
		}
		allowedIPPrefixes[index] = prefix
	}
	tailcatDialerKey := key.NewNode()
	if provisioning.Route.AuthorizationID != "" {
		var err error
		tailcatDialerKey, err = signedTailcatDialerKey(provisioning.SessionToken)
		if err != nil {
			return SessionSetup{}, err
		}
	}
	ref := worker.RouteRef{RouteID: provisioning.Route.ID, RouteVersion: provisioning.Session.RouteVersion}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return SessionSetup{}, net.ErrClosed
	}
	for existing := range c.pending {
		if existing.RouteID == ref.RouteID {
			delete(c.pending, existing)
		}
	}
	c.pending[ref] = pendingSession{
		hostname: provisioning.Route.Hostname, allowedIPPrefixes: allowedIPPrefixes,
		key: tailcatDialerKey, expiresAt: provisioning.Session.ExpiresAt,
	}
	c.mu.Unlock()
	return SessionSetup{Provisioning: provisioning, WorkerPublicKey: tailcatDialerKey.Public().String()}, nil
}

func (c *Coordinator) AttachRouteTransport(
	ctx context.Context,
	routeID string,
	routeVersion uint64,
	token credentials.SessionToken,
	publisherPublicKey, relayRegion string,
) (err error) {
	lockStarted := time.Now()
	unlockRoute := c.lockRoute(routeID)
	lockWait := time.Since(lockStarted)
	replaced := false
	defer func() {
		unlockRoute()
		c.observeStage(CoordinatorStageTransportRouteLockWait, lockWait)
		if replaced {
			c.observeRouteRemoval(RouteRemovalRouteVersionReplaced)
		}
		if errors.Is(err, ErrNoWorkerCapacity) {
			c.observeWorkerCapacityRejection()
		}
	}()
	session, err := c.store.AuthenticateSession(ctx, routeID, routeVersion, token, c.serverInstanceID)
	if err != nil {
		return err
	}
	ref := worker.RouteRef{RouteID: routeID, RouteVersion: routeVersion}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	if current := c.assignments[routeID]; current != nil && current.ref == ref {
		c.mu.Unlock()
		if session.PublisherPublicKey != publisherPublicKey || session.RelayRegion != relayRegion {
			return ErrInvalidStatus
		}
		return nil
	}
	if session.Status == SessionStatusStarting &&
		(session.PublisherPublicKey != publisherPublicKey || session.RelayRegion != relayRegion) {
		c.mu.Unlock()
		return ErrInvalidStatus
	}
	pending, ok := c.pending[ref]
	c.mu.Unlock()
	if !ok {
		return ErrStaleSession
	}
	endpoint := tailtransport.TransportDescriptor{
		Version:            transportv1.TailcatDescriptorVersion,
		PublisherPublicKey: publisherPublicKey,
		RelayRegion:        relayRegion,
	}
	if err := c.store.AttachRouteTransport(ctx, session, publisherPublicKey, relayRegion); err != nil {
		return err
	}

	tried := make(map[string]struct{})
	for {
		selectedWorker := c.selectWorker(tried)
		if selectedWorker == nil {
			return ErrNoWorkerCapacity
		}
		tried[selectedWorker.id] = struct{}{}
		attachStarted := time.Now()
		backend, err := selectedWorker.worker.Attach(ctx, worker.Assignment{RouteRef: ref, Endpoint: endpoint, Key: pending.key})
		c.observeStage(CoordinatorStageTransportWorkerAttach, time.Since(attachStarted))
		if errors.Is(err, worker.ErrAtCapacity) || errors.Is(err, worker.ErrDraining) || errors.Is(err, net.ErrClosed) {
			continue
		}
		if err != nil {
			return fmt.Errorf("routes: attach worker route: %w", err)
		}

		// Attach runs without c.mu; recheck the worker and session before storing its backend.
		c.mu.Lock()
		currentWorker := c.workers[selectedWorker.id]
		currentPending, stillPending := c.pending[ref]
		sessionCurrent := stillPending && currentPending.expiresAt.After(c.store.now())
		if currentWorker != selectedWorker || selectedWorker.draining || !sessionCurrent {
			c.mu.Unlock()
			_ = backend.Close()
			if !sessionCurrent {
				return ErrStaleSession
			}
			continue
		}
		previous := c.assignments[routeID]
		assignment := &assignment{
			ref: ref, hostname: currentPending.hostname, allowedIPPrefixes: currentPending.allowedIPPrefixes,
			expiresAt: session.ExpiresAt, worker: selectedWorker, backend: backend,
		}
		c.assignments[routeID] = assignment
		c.challenges[assignment.hostname] = assignment
		selectedWorker.routes[routeID] = backend
		c.mu.Unlock()
		if previous != nil {
			_ = previous.backend.Close()
			replaced = true
		}
		return nil
	}
}

func (c *Coordinator) Ready(
	ctx context.Context,
	routeID string,
	routeVersion uint64,
	token credentials.SessionToken,
) error {
	lockStarted := time.Now()
	unlockRoute := c.lockRoute(routeID)
	lockWait := time.Since(lockStarted)
	defer func() {
		unlockRoute()
		c.observeStage(CoordinatorStageReadyRouteLockWait, lockWait)
	}()
	session, err := c.store.AuthenticateSession(ctx, routeID, routeVersion, token, c.serverInstanceID)
	if err != nil {
		return err
	}
	c.mu.Lock()
	current := c.assignments[routeID]
	if current == nil || current.ref.RouteVersion != routeVersion {
		c.mu.Unlock()
		return ErrInvalidStatus
	}
	c.mu.Unlock()
	if err := c.store.Ready(ctx, session); err != nil {
		return err
	}
	// Worker loss may race the durable update, so publish only the same assignment.
	publishStarted := time.Now()
	c.mu.Lock()
	if c.assignments[routeID] != current {
		c.mu.Unlock()
		c.observeStage(CoordinatorStageReadyPublish, time.Since(publishStarted))
		return ErrStaleSession
	}
	c.publishLocked(current)
	delete(c.pending, current.ref)
	c.mu.Unlock()
	c.observeStage(CoordinatorStageReadyPublish, time.Since(publishStarted))
	return nil
}

func (c *Coordinator) Heartbeat(
	ctx context.Context,
	routeID string,
	routeVersion uint64,
	token credentials.SessionToken,
) (expiresAt time.Time, err error) {
	lockStarted := time.Now()
	unlockRoute := c.lockRoute(routeID)
	lockWait := time.Since(lockStarted)
	defer func() {
		unlockRoute()
		c.observeStage(CoordinatorStageHeartbeatRouteLockWait, lockWait)
		c.observeHeartbeat(heartbeatResult(err))
	}()
	session, err := c.store.AuthenticateSession(ctx, routeID, routeVersion, token, c.serverInstanceID)
	if err != nil {
		return time.Time{}, err
	}
	expiresAt, err = c.store.Heartbeat(ctx, session)
	if err != nil {
		return time.Time{}, err
	}
	if err := c.updateHeartbeatExpiry(routeID, routeVersion, expiresAt); err != nil {
		return time.Time{}, err
	}
	return expiresAt, nil
}

func (c *Coordinator) HeartbeatSigned(
	ctx context.Context,
	routeID string,
	routeVersion uint64,
	token credentials.SessionToken,
	signedAuthorization string,
	requestHash authorization.Digest,
) (expiresAt time.Time, err error) {
	lockStarted := time.Now()
	unlockRoute := c.lockRoute(routeID)
	lockWait := time.Since(lockStarted)
	defer func() {
		unlockRoute()
		c.observeStage(CoordinatorStageHeartbeatRouteLockWait, lockWait)
		c.observeHeartbeat(heartbeatResult(err))
	}()
	var session Session
	if signedAuthorization == "" {
		session, err = c.store.AuthenticateSession(ctx, routeID, routeVersion, token, c.serverInstanceID)
	} else {
		session, err = c.store.AuthenticateSessionForRenewal(ctx, routeID, routeVersion, token, c.serverInstanceID)
	}
	if err != nil {
		return time.Time{}, err
	}
	expiresAt, err = c.store.HeartbeatSigned(ctx, session, signedAuthorization, requestHash)
	if err != nil {
		return time.Time{}, err
	}
	if err := c.updateHeartbeatExpiry(routeID, routeVersion, expiresAt); err != nil {
		return time.Time{}, err
	}
	return expiresAt, nil
}

func (c *Coordinator) updateHeartbeatExpiry(routeID string, routeVersion uint64, expiresAt time.Time) error {
	ref := worker.RouteRef{RouteID: routeID, RouteVersion: routeVersion}
	stateStarted := time.Now()
	c.mu.Lock()
	updated := false
	if pending, ok := c.pending[ref]; ok {
		pending.expiresAt = expiresAt
		c.pending[ref] = pending
		updated = true
	}
	if current := c.assignments[routeID]; current != nil && current.ref == ref {
		current.expiresAt = expiresAt
		c.publishLocked(current)
		updated = true
	}
	c.mu.Unlock()
	c.observeStage(CoordinatorStageHeartbeatPersistence, time.Since(stateStarted))
	if !updated {
		return ErrStaleSession
	}
	return nil
}

func signedTailcatDialerKey(token credentials.SessionToken) (key.NodePrivate, error) {
	material, err := credentials.DeriveSessionKeyMaterial(token)
	if err != nil {
		return key.NodePrivate{}, ErrUnauthenticated
	}
	material[0] &= 248
	material[31] &= 127
	material[31] |= 64
	var result key.NodePrivate
	if err := result.UnmarshalText([]byte("privkey:" + hex.EncodeToString(material[:]))); err != nil {
		return key.NodePrivate{}, fmt.Errorf("routes: derive signed tailcat dialer key: %w", err)
	}
	return result, nil
}

// AuthorizeSession verifies that a session token owns the current route version
// without mutating the session lifetime or route state.
func (c *Coordinator) AuthorizeSession(
	ctx context.Context,
	routeID string,
	routeVersion uint64,
	token credentials.SessionToken,
) error {
	if c.isClosed() {
		return net.ErrClosed
	}
	_, err := c.store.AuthenticateSession(ctx, routeID, routeVersion, token, c.serverInstanceID)
	return err
}

func (c *Coordinator) List(ctx context.Context, identityID string) ([]Route, error) {
	return c.store.List(ctx, identityID)
}

func (c *Coordinator) ClaimManagedHostname(
	ctx context.Context,
	identityID, label, idempotencyKey string,
) (Hostname, error) {
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	if c.isClosed() {
		return Hostname{}, net.ErrClosed
	}
	return c.store.ClaimManagedHostname(ctx, identityID, label, idempotencyKey)
}

func (c *Coordinator) ClaimHostname(
	ctx context.Context,
	identityID, kind, label, idempotencyKey string,
) (Hostname, error) {
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	if c.isClosed() {
		return Hostname{}, net.ErrClosed
	}
	return c.store.ClaimHostname(ctx, identityID, kind, label, idempotencyKey)
}

func (c *Coordinator) ListHostnames(ctx context.Context, identityID string) ([]Hostname, error) {
	if c.isClosed() {
		return nil, net.ErrClosed
	}
	return c.store.ListHostnames(ctx, identityID)
}

func (c *Coordinator) ListHostnamesPage(
	ctx context.Context,
	identityID, cursor string,
) ([]Hostname, string, error) {
	if c.isClosed() {
		return nil, "", net.ErrClosed
	}
	return c.store.ListHostnamesPage(ctx, identityID, cursor)
}

func (c *Coordinator) CreateDomainVerification(
	ctx context.Context,
	identityID, domain, idempotencyKey string,
) (DomainVerification, error) {
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	if c.isClosed() {
		return DomainVerification{}, net.ErrClosed
	}
	return c.store.CreateDomainVerification(ctx, identityID, domain, idempotencyKey)
}

func (c *Coordinator) GetDomainVerification(ctx context.Context, identityID, id string) (DomainVerification, error) {
	if c.isClosed() {
		return DomainVerification{}, net.ErrClosed
	}
	return c.store.GetDomainVerification(ctx, identityID, id)
}

func (c *Coordinator) CompleteDomainVerification(
	ctx context.Context,
	identityID, id string,
) (Hostname, error) {
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	if c.isClosed() {
		return Hostname{}, net.ErrClosed
	}
	if err := c.store.checkDomainVerification(ctx, identityID, id); err != nil {
		return Hostname{}, err
	}
	hostname, stoppedRouteIDs, err := c.store.activateDomainVerification(ctx, identityID, id)
	if err != nil {
		return Hostname{}, err
	}
	for _, routeID := range stoppedRouteIDs {
		unlockRoute := c.lockRoute(routeID)
		removed := c.deactivate(routeID)
		unlockRoute()
		if removed {
			c.observeRouteRemoval(RouteRemovalHostnameRemoved)
		}
	}
	return hostname, nil
}

func (c *Coordinator) ReleaseHostname(ctx context.Context, identityID, hostnameID string) (err error) {
	removed := false
	defer func() {
		if removed {
			c.observeRouteRemoval(RouteRemovalHostnameRemoved)
		}
	}()
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	if c.isClosed() {
		return net.ErrClosed
	}
	routeIDs, err := c.store.EnabledRouteIDsForHostname(ctx, identityID, hostnameID)
	if err != nil {
		return err
	}
	for _, routeID := range routeIDs {
		unlockRoute := c.lockRoute(routeID)
		defer unlockRoute()
	}
	if err := c.store.ReleaseHostname(ctx, identityID, hostnameID); err != nil {
		return err
	}
	for _, routeID := range routeIDs {
		removed = c.deactivate(routeID) || removed
	}
	return nil
}

func (c *Coordinator) Delete(ctx context.Context, identityID, routeID string) (err error) {
	removed := false
	defer func() {
		if removed {
			c.observeRouteRemoval(RouteRemovalDeleted)
		}
	}()
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	if c.isClosed() {
		return net.ErrClosed
	}
	if err := c.store.AuthorizeIdentity(ctx, identityID, routeID); err != nil {
		return err
	}
	unlockRoute := c.lockRoute(routeID)
	defer unlockRoute()
	if err := c.store.Delete(ctx, identityID, routeID); err != nil {
		return err
	}
	removed = c.deactivate(routeID)
	return nil
}

func (c *Coordinator) DeleteSigned(ctx context.Context, routeID string, token credentials.RouteToken) (err error) {
	removed := false
	defer func() {
		if removed {
			c.observeRouteRemoval(RouteRemovalDeleted)
		}
	}()
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	if c.isClosed() {
		return net.ErrClosed
	}
	unlockRoute := c.lockRoute(routeID)
	defer unlockRoute()
	if err := c.store.DeleteSigned(ctx, routeID, token); err != nil {
		return err
	}
	removed = c.deactivate(routeID)
	return nil
}

func (c *Coordinator) ListAdminRoutes(ctx context.Context, cursor string) ([]Route, string, error) {
	if c.isClosed() {
		return nil, "", net.ErrClosed
	}
	return c.store.ListAdminRoutes(ctx, cursor)
}

func (c *Coordinator) GetAdminRoute(ctx context.Context, routeID string) (Route, error) {
	if c.isClosed() {
		return Route{}, net.ErrClosed
	}
	return c.store.GetAdminRoute(ctx, routeID)
}

func (c *Coordinator) SuspendAdminRoute(
	ctx context.Context,
	routeID string,
	revision uint64,
	reason, actor, requestID string,
) (Route, error) {
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	if c.isClosed() {
		return Route{}, net.ErrClosed
	}
	unlockRoute := c.lockRoute(routeID)
	defer unlockRoute()
	route, err := c.store.SuspendAdminRoute(ctx, routeID, revision, reason, actor, requestID)
	if err != nil {
		return Route{}, err
	}
	if c.deactivateDraining(ctx, routeID) {
		c.observeRouteRemoval(RouteRemovalSuspended)
	}
	return route, nil
}

func (c *Coordinator) ResumeAdminRoute(
	ctx context.Context,
	routeID string,
	revision uint64,
	actor, requestID string,
) (Route, error) {
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	if c.isClosed() {
		return Route{}, net.ErrClosed
	}
	unlockRoute := c.lockRoute(routeID)
	defer unlockRoute()
	return c.store.ResumeAdminRoute(ctx, routeID, revision, actor, requestID)
}

func (c *Coordinator) ListAdminHostnames(ctx context.Context, cursor string) ([]Hostname, string, error) {
	if c.isClosed() {
		return nil, "", net.ErrClosed
	}
	return c.store.ListAdminHostnames(ctx, cursor)
}

func (c *Coordinator) GetAdminHostname(ctx context.Context, hostnameID string) (Hostname, error) {
	if c.isClosed() {
		return Hostname{}, net.ErrClosed
	}
	return c.store.GetAdminHostname(ctx, hostnameID)
}

func (c *Coordinator) RemoveAdminHostname(ctx context.Context, hostnameID, actor, requestID string) error {
	return c.mutateAdminHostname(ctx, hostnameID, RouteRemovalHostnameRemoved, func() ([]string, error) {
		return c.store.RemoveAdminHostname(ctx, hostnameID, actor, requestID)
	})
}

func (c *Coordinator) QuarantineAdminHostname(
	ctx context.Context,
	hostnameID, reason, actor, requestID string,
) error {
	return c.mutateAdminHostname(ctx, hostnameID, RouteRemovalHostnameQuarantined, func() ([]string, error) {
		return c.store.QuarantineAdminHostname(ctx, hostnameID, reason, actor, requestID)
	})
}

func (c *Coordinator) mutateAdminHostname(
	ctx context.Context,
	hostnameID string,
	removal RouteRemovalReason,
	mutate func() ([]string, error),
) error {
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	if c.isClosed() {
		return net.ErrClosed
	}
	routeIDs, err := c.store.ListCurrentAdminHostnameRouteIDs(ctx, hostnameID)
	if err != nil {
		return err
	}
	for _, routeID := range routeIDs {
		unlockRoute := c.lockRoute(routeID)
		defer unlockRoute()
	}
	mutatedRoutes, err := mutate()
	if err != nil {
		return err
	}
	for _, routeID := range mutatedRoutes {
		if c.deactivateDraining(ctx, routeID) {
			c.observeRouteRemoval(removal)
		}
	}
	return nil
}

func (c *Coordinator) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *Coordinator) Lookup(hostname string) (RoutableRoute, bool) {
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname {
		return RoutableRoute{}, false
	}
	result, ok := c.snapshot.Load().byHostname[canonical]
	return result, ok && result.expires.After(c.store.now())
}

// LookupChallenge resolves current assigned routes before ordinary traffic is
// published. Callers must use it only for TLS-ALPN-01 ClientHellos.
func (c *Coordinator) LookupChallenge(hostname string) (RoutableRoute, bool) {
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname {
		return RoutableRoute{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return RoutableRoute{}, false
	}
	current := c.challenges[hostname]
	if current != nil && current.expiresAt.After(c.store.now()) {
		return RoutableRoute{
			RouteID: current.ref.RouteID, RouteVersion: current.ref.RouteVersion, Backend: current.backend,
		}, true
	}
	return RoutableRoute{}, false
}

func (c *Coordinator) DrainWorker(ctx context.Context, id string) error {
	c.mu.Lock()
	worker := c.workers[id]
	if worker == nil {
		c.mu.Unlock()
		return ErrNotFound
	}
	worker.draining = true
	assigned := c.ownerAssignmentsLocked(worker)
	for _, current := range assigned {
		c.unpublishLocked(current.ref.RouteID, current.ref.RouteVersion)
	}
	c.mu.Unlock()
	for _, current := range assigned {
		_ = c.store.Expire(ctx, current.ref.RouteID, current.ref.RouteVersion)
	}
	err := worker.worker.Drain(ctx)
	c.removeWorker(worker, RouteRemovalWorkerDraining)
	return err
}

func (c *Coordinator) RemoveWorker(id string) {
	c.mu.Lock()
	worker := c.workers[id]
	c.mu.Unlock()
	if worker != nil {
		c.removeWorker(worker, RouteRemovalWorkerDisconnected)
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
	workers := make([]*workerState, 0, len(c.workers))
	for _, worker := range c.workers {
		workers = append(workers, worker)
	}
	clear(c.workers)
	clear(c.pending)
	clear(c.assignments)
	c.snapshot.Store(&routeSnapshot{byHostname: map[string]RoutableRoute{}})
	c.mu.Unlock()
	stopReaper()
	<-reaperDone
	var result error
	for _, worker := range workers {
		result = errors.Join(result, worker.worker.Close())
	}
	return result
}

func (c *Coordinator) selectWorker(tried map[string]struct{}) *workerState {
	c.mu.Lock()
	defer c.mu.Unlock()
	candidates := make([]*workerState, 0, len(c.workers))
	for id, worker := range c.workers {
		if _, seen := tried[id]; seen || worker.draining {
			continue
		}
		capacity := worker.worker.Capacity()
		if capacity.Draining || capacity.Active >= capacity.Limit {
			continue
		}
		candidates = append(candidates, worker)
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := candidates[i].worker.Capacity(), candidates[j].worker.Capacity()
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

func (c *Coordinator) deactivate(routeID string) bool {
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
		delete(current.worker.routes, routeID)
		c.unpublishLocked(routeID, current.ref.RouteVersion)
	}
	c.mu.Unlock()
	if current != nil {
		_ = current.backend.Close()
	}
	return current != nil
}

func (c *Coordinator) deactivateDraining(ctx context.Context, routeID string) bool {
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
		delete(current.worker.routes, routeID)
		c.unpublishLocked(routeID, current.ref.RouteVersion)
	}
	c.mu.Unlock()
	if current != nil {
		_ = current.backend.Drain(ctx)
		_ = current.backend.Close()
	}
	return current != nil
}

func (c *Coordinator) publishLocked(current *assignment) {
	next := cloneSnapshot(c.snapshot.Load())
	next.byHostname[current.hostname] = RoutableRoute{
		RouteID: current.ref.RouteID, RouteVersion: current.ref.RouteVersion,
		AllowedIPPrefixes: current.allowedIPPrefixes, Backend: current.backend, expires: current.expiresAt,
	}
	c.snapshot.Store(next)
}

func (c *Coordinator) unpublishLocked(routeID string, routeVersion uint64) {
	current := c.snapshot.Load()
	next := cloneSnapshot(current)
	for hostname, route := range next.byHostname {
		if route.RouteID == routeID && route.RouteVersion == routeVersion {
			delete(next.byHostname, hostname)
		}
	}
	c.snapshot.Store(next)
}

func cloneSnapshot(current *routeSnapshot) *routeSnapshot {
	next := &routeSnapshot{byHostname: make(map[string]RoutableRoute, len(current.byHostname))}
	for hostname, route := range current.byHostname {
		next.byHostname[hostname] = route
	}
	return next
}

func (c *Coordinator) removeWorker(worker *workerState, reason RouteRemovalReason) {
	c.mu.Lock()
	if c.workers[worker.id] != worker {
		c.mu.Unlock()
		return
	}
	delete(c.workers, worker.id)
	assigned := c.ownerAssignmentsLocked(worker)
	for _, current := range assigned {
		delete(c.assignments, current.ref.RouteID)
		if c.challenges[current.hostname] == current {
			delete(c.challenges, current.hostname)
		}
		delete(c.pending, current.ref)
		c.unpublishLocked(current.ref.RouteID, current.ref.RouteVersion)
	}
	c.mu.Unlock()
	for range assigned {
		c.observeRouteRemoval(reason)
	}
	_ = worker.worker.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, current := range assigned {
		_ = c.store.Expire(ctx, current.ref.RouteID, current.ref.RouteVersion)
	}
}

func (c *Coordinator) ownerAssignmentsLocked(worker *workerState) []*assignment {
	assigned := make([]*assignment, 0, len(worker.routes))
	for routeID := range worker.routes {
		if current := c.assignments[routeID]; current != nil && current.worker == worker {
			assigned = append(assigned, current)
		}
	}
	return assigned
}

func (c *Coordinator) lockRoute(routeID string) func() {
	c.routeLocksMu.Lock()
	lock := c.routeLocks[routeID]
	if lock == nil {
		lock = new(routeMutex)
		c.routeLocks[routeID] = lock
	}
	lock.users++
	c.routeLocksMu.Unlock()

	lock.Lock()
	return func() {
		lock.Unlock()
		c.routeLocksMu.Lock()
		lock.users--
		if lock.users == 0 {
			delete(c.routeLocks, routeID)
		}
		c.routeLocksMu.Unlock()
	}
}

func (c *Coordinator) reapSessions(ctx context.Context) {
	defer close(c.reaperDone)
	ticker := time.NewTicker(sessionReapInterval)
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
		unlockRoute := c.lockRoute(ref.RouteID)
		backend, expired, removed := c.expireMemory(ref, now)
		if expired {
			_ = c.store.Expire(ctx, ref.RouteID, ref.RouteVersion)
		}
		unlockRoute()
		if backend != nil {
			_ = backend.Close()
		}
		if removed {
			c.observeRouteRemoval(RouteRemovalSessionExpired)
		}
	}
	removed, err := c.store.CleanupAbandonedTemporary(ctx, now)
	if err != nil {
		return
	}
	for _, routeID := range removed {
		if c.deactivate(routeID) {
			c.observeRouteRemoval(RouteRemovalSessionExpired)
		}
	}
}

func (c *Coordinator) expireMemory(ref worker.RouteRef, now time.Time) (worker.WorkerRoute, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	expired := false
	if pending, ok := c.pending[ref]; ok && !pending.expiresAt.After(now) {
		delete(c.pending, ref)
		expired = true
	}
	current := c.assignments[ref.RouteID]
	if current == nil || current.ref != ref || current.expiresAt.After(now) {
		return nil, expired, false
	}
	delete(c.assignments, ref.RouteID)
	if c.challenges[current.hostname] == current {
		delete(c.challenges, current.hostname)
	}
	delete(current.worker.routes, ref.RouteID)
	c.unpublishLocked(ref.RouteID, ref.RouteVersion)
	return current.backend, true, true
}

func (c *Coordinator) Stats() (provisioning, routable int) {
	stats := c.HealthStats()
	return stats.Provisioning, stats.Routable
}

func (c *Coordinator) HealthStats() HealthStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.store.now()
	snapshot := c.snapshot.Load()
	stats := HealthStats{
		Provisioning:     len(c.pending),
		Routable:         len(snapshot.byHostname),
		ConnectedWorkers: len(c.workers),
	}
	hasProvisioning := false
	for _, pending := range c.pending {
		remaining := max(0, pending.expiresAt.Sub(now).Seconds())
		if !hasProvisioning || remaining < stats.MinimumProvisioningSessionSeconds {
			stats.MinimumProvisioningSessionSeconds = remaining
			hasProvisioning = true
		}
	}
	hasRoutable := false
	for _, route := range snapshot.byHostname {
		current := c.assignments[route.RouteID]
		if current == nil || current.ref.RouteVersion != route.RouteVersion {
			continue
		}
		remaining := max(0, current.expiresAt.Sub(now).Seconds())
		if !hasRoutable || remaining < stats.MinimumRoutableSessionSeconds {
			stats.MinimumRoutableSessionSeconds = remaining
			hasRoutable = true
		}
	}
	return stats
}

func (c *Coordinator) observeHeartbeat(result HeartbeatResult) {
	if c.config.ObserveHeartbeat != nil {
		c.config.ObserveHeartbeat(result)
	}
}

func (c *Coordinator) observeRouteRemoval(reason RouteRemovalReason) {
	if c.config.ObserveRouteRemoval != nil {
		c.config.ObserveRouteRemoval(reason)
	}
}

func (c *Coordinator) observeWorkerCapacityRejection() {
	if c.config.ObserveWorkerCapacityRejection != nil {
		c.config.ObserveWorkerCapacityRejection()
	}
}

func (c *Coordinator) observeStage(stage CoordinatorStage, duration time.Duration) {
	if c.config.ObserveStage != nil {
		c.config.ObserveStage(stage, duration)
	}
}

func heartbeatResult(err error) HeartbeatResult {
	if err == nil {
		return HeartbeatResultSuccess
	}
	if errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrStaleSession) {
		return HeartbeatResultRejected
	}
	return HeartbeatResultError
}
