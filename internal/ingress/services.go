package ingress

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/controloutage"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ServiceRoutingClient interface {
	ReadIngressServices(context.Context, string, ingressv1.IngressLeaseIdentity) (ingressv1.IngressServices, error)
}

type serviceEndpoint struct {
	hostname string
	port     int
}

// serviceRoute is checked once when control's snapshot arrives. its source key
// signs socket addresses only; it cannot authorize a visitor.
type serviceRoute struct {
	run                   ingressv1.IngressServiceRun
	until                 time.Time
	ip                    *ippolicy.Policy
	source                tunnelv1.VisitorSourceAuthority
	sourceKey             [32]byte
	traffic               TrafficLimits
	observedAt, startedAt time.Time
	sequence              *sourceCounter
}

func (serviceRoute) String() string   { return "service routing" }
func (serviceRoute) GoString() string { return "service routing" }

func (r *serviceRoute) authorityTime(now time.Time) time.Time {
	return r.observedAt.Add(now.Sub(r.startedAt))
}

type routedVisitor struct {
	serviceID        string
	runID            string
	runNumber        int64
	endpointRevision int64
	source           netip.Addr
	until            time.Time
	stop             func()
}

type sourceCounter struct {
	next       atomic.Uint64
	validUntil int64
	until      time.Time
}

type terminalServiceRun struct {
	lease ingressv1.IngressLeaseIdentity
	until time.Time
}

// ServiceRouting keeps short-lived serving information for one ingress process.
// refresh replaces the whole snapshot; failed refreshes never extend its life.
type ServiceRouting struct {
	mu             sync.Mutex
	lease          ingressv1.IngressLease
	observedAt     time.Time
	startedAt      time.Time
	validUntil     time.Time
	runs           map[string]*serviceRoute
	endpoints      map[serviceEndpoint][]*serviceRoute
	visitors       map[*routedVisitor]struct{}
	stopping       []*routedVisitor
	changed        chan struct{}
	updated        chan struct{}
	done           chan struct{}
	sourceCounters map[[32]byte]*sourceCounter
	terminalRuns   map[ingressv1.ServiceRunReference]terminalServiceRun
	closed         bool
}

func NewServiceRouting() *ServiceRouting {
	r := &ServiceRouting{
		runs: make(map[string]*serviceRoute), endpoints: make(map[serviceEndpoint][]*serviceRoute),
		visitors: make(map[*routedVisitor]struct{}), changed: make(chan struct{}, 1), updated: make(chan struct{}), done: make(chan struct{}),
		sourceCounters: make(map[[32]byte]*sourceCounter),
		terminalRuns:   make(map[ingressv1.ServiceRunReference]terminalServiceRun),
	}
	go r.expireVisitors()
	return r
}

// RefreshServices runs independently of arriving visitors. it also removes
// finished traffic budgets without putting a control call on connection setup.
func (s *Server) RefreshServices(ctx context.Context) error {
	r := s.services
	ctx, cancelRefresh := context.WithCancel(ctx)
	defer cancelRefresh()
	stopped := make(chan struct{})
	stop := context.AfterFunc(s.openContext, func() { defer close(stopped); cancelRefresh() })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	defer r.Close()
	for {
		delay := min(s.config.RecheckInterval, time.Second)
		lease := s.config.CurrentLease()
		if lease.IngressLeaseRevision > 0 && !lease.Draining && lease.ServingUntil.After(time.Now()) {
			started := time.Now()
			call, cancel := context.WithTimeout(ctx, min(s.config.RecheckTimeout, 2*time.Second))
			snapshot, err := s.config.Control.ReadIngressServices(call, lease.IngressId, ingressv1.IngressLeaseIdentity{
				IngressId: lease.IngressId, IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
			})
			if err == nil {
				err = context.Cause(call)
			}
			if deadline, ok := call.Deadline(); ok && !time.Now().Before(deadline) {
				err = errors.Join(err, context.DeadlineExceeded)
			}
			if err == nil && samePrivateLease(lease, s.config.CurrentLease()) {
				err = r.apply(started, lease, snapshot)
				if err == nil {
					s.retireClosedTrafficRuns(call, lease)
				}
			}
			cancel()
			if err != nil && ctx.Err() == nil && s.config.OnError != nil {
				s.config.OnError(err)
			}
			if err != nil {
				var problem *ControlProblemError
				if errors.Is(err, ErrIngressLeaseLost) ||
					errors.As(ingressControlError("read services", err), &problem) && problem.Problem != nil && problem.Problem.Code == ingressv1.IngressLeaseStale {
					return errors.Join(ErrIngressLeaseLost, err)
				}
			}
		} else {
			delay = min(delay, 100*time.Millisecond)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func (r *ServiceRouting) apply(started time.Time, lease ingressv1.IngressLease, snapshot ingressv1.IngressServices) error {
	now := time.Now()
	snapshotDeadline, err := controloutage.LocalDeadline(started, snapshot.ObservedAt, snapshot.ValidUntil, now)
	if err != nil || !lease.ServingUntil.After(now) || lease.Draining {
		return ErrServiceAdmission
	}
	runs := make(map[string]*serviceRoute, len(snapshot.Runs))
	endpoints := make(map[serviceEndpoint][]*serviceRoute)
	for _, run := range snapshot.Runs {
		if !serviceendpoint.Valid(string(run.Protocol), run.Hostname, run.Port, true) ||
			run.EndpointRevision < 1 || run.RunNumber < 1 || runs[run.ServiceRunId] != nil ||
			run.ValidUntil.After(snapshot.ValidUntil) || !run.ValidUntil.After(snapshot.ObservedAt) ||
			len(run.SourceKey) != 32 || len(run.ConnectedRelays) == 0 || len(run.ConnectedRelays) > 2 ||
			run.Anonymous && run.Protocol != "http" {
			return ErrServiceAdmission
		}
		traffic, err := routingTraffic(run.Traffic)
		if err != nil {
			return err
		}
		if err := validateServiceRelays(run.ConnectedRelays, snapshot.ObservedAt); err != nil {
			return err
		}
		run.ConnectedRelays = slices.Clone(run.ConnectedRelays)
		for i := range run.ConnectedRelays {
			run.ConnectedRelays[i].ServingUntil = started.Add(run.ConnectedRelays[i].ServingUntil.Sub(snapshot.ObservedAt))
		}
		source, err := tunnelv1.ReadVisitorSourceAuthority(run.SourceAuthority)
		if err != nil || source.ServiceID != run.ServiceId || source.ServiceRunID != run.ServiceRunId ||
			source.RunNumber != uint64(run.RunNumber) || source.EndpointRevision != run.EndpointRevision || source.IngressID != lease.IngressId ||
			source.IngressRunID != lease.IngressRunId || source.IngressLeaseRevision != uint64(lease.IngressLeaseRevision) ||
			source.ValidUntil > run.ValidUntil.Unix() || source.ValidUntil <= snapshot.ObservedAt.Unix() {
			return ErrServiceAdmission
		}
		// use the request's start time so a slow response spends, rather than
		// extends, the serving deadline. the ingress lease may end sooner.
		until := started.Add(time.Unix(source.ValidUntil, 0).Sub(snapshot.ObservedAt))
		route := cloneServiceRoute(&serviceRoute{run: run, source: source, traffic: traffic, until: privateMinTime(until, lease.ServingUntil),
			observedAt: snapshot.ObservedAt, startedAt: started})
		copy(route.sourceKey[:], run.SourceKey)
		route.run.SourceKey, route.run.SourceAuthority, route.run.Ip = nil, nil, nil
		if route.sourceKey == [32]byte{} {
			return ErrServiceAdmission
		}
		if run.Ip != nil {
			if len(run.Ip.Key) != 32 || len(run.Ip.Prefixes) > 2048 {
				return ErrServiceAdmission
			}
			key := [32]byte(run.Ip.Key)
			prefixes := make([]ippolicy.Entry, 0, len(run.Ip.Prefixes))
			for _, prefix := range run.Ip.Prefixes {
				prefixes = append(prefixes, ippolicy.Entry{Family: string(prefix.Family), Bits: prefix.PrefixLength, Digest: prefix.Digest})
			}
			ip, err := ippolicy.New(key, prefixes)
			if err != nil {
				return err
			}
			route.ip = &ip
		}
		endpoint := serviceEndpoint{port: run.Port}
		if run.Protocol == "http" {
			endpoint.hostname = run.Hostname
		}
		if previous := endpoints[endpoint]; len(previous) != 0 && previous[0].run.ServiceId != run.ServiceId {
			return ErrServiceAdmission
		}
		runs[run.ServiceRunId] = route
		endpoints[endpoint] = append(endpoints[endpoint], route)
	}
	r.mu.Lock()
	now = time.Now()
	if r.closed || started.Before(r.startedAt) || !snapshot.ObservedAt.After(r.observedAt) ||
		!now.Before(snapshotDeadline) || !lease.ServingUntil.After(now) ||
		r.lease.IngressLeaseRevision > lease.IngressLeaseRevision {
		r.mu.Unlock()
		return ErrServiceAdmission
	}
	for _, route := range runs {
		ref := ingressv1.ServiceRunReference{ServiceId: route.run.ServiceId, ServiceRunId: route.run.ServiceRunId, RunNumber: route.run.RunNumber}
		if terminal, ok := r.terminalRuns[ref]; ok && terminal.until.After(now) &&
			terminal.lease == (ingressv1.IngressLeaseIdentity{IngressId: lease.IngressId, IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision}) {
			r.mu.Unlock()
			return ErrServiceAdmission
		}
	}
	r.pruneTerminalLocked(lease, now)
	if r.lease.IngressLeaseRevision != 0 && !samePrivateLease(r.lease, lease) {
		for visitor := range r.visitors {
			r.stopping = append(r.stopping, visitor)
		}
		clear(r.visitors)
	}
	// keep sequence numbers for an unchanged authority even if a run briefly
	// disappears from routing. another service cannot spend its replay window.
	for key, counter := range r.sourceCounters {
		if counter.validUntil <= snapshot.ObservedAt.Unix() {
			delete(r.sourceCounters, key)
		}
	}
	for _, route := range runs {
		key := [32]byte(route.source.MAC)
		counter := r.sourceCounters[key]
		if counter == nil {
			counter = &sourceCounter{validUntil: route.source.ValidUntil, until: route.until}
			r.sourceCounters[key] = counter
		} else {
			// the same signed source authority has one absolute expiry, even
			// across a temporary routing omission or changed response latency.
			counter.until = privateMinTime(counter.until, route.until)
			route.until = counter.until
		}
		route.sequence = counter
	}
	r.lease, r.startedAt, r.observedAt, r.runs, r.endpoints = cloneIngressLease(lease), started, snapshot.ObservedAt, runs, endpoints
	r.validUntil = privateMinTime(snapshotDeadline, lease.ServingUntil)
	r.stopping = append(r.stopping, r.expireVisitorsLocked(now)...)
	close(r.updated)
	r.updated = make(chan struct{})
	r.wake()
	r.mu.Unlock()
	return nil
}

// cloneServiceRoute owns mutable snapshot fields at both routing boundaries.
// validated ip policy maps are immutable; only the atomic source sequence is shared.
func cloneServiceRoute(route *serviceRoute) *serviceRoute {
	result := *route
	result.run.ConnectedRelays = slices.Clone(route.run.ConnectedRelays)
	result.run.SourceAuthority = slices.Clone(route.run.SourceAuthority)
	result.run.SourceKey = slices.Clone(route.run.SourceKey)
	if route.run.RecoveryEpisodeId != nil {
		result.run.RecoveryEpisodeId = new(*route.run.RecoveryEpisodeId)
	}
	if route.run.Traffic.TotalConnections != nil {
		result.run.Traffic.TotalConnections = new(*route.run.Traffic.TotalConnections)
	}
	if route.run.Traffic.TotalUploadBytes != nil {
		result.run.Traffic.TotalUploadBytes = new(*route.run.Traffic.TotalUploadBytes)
	}
	if route.run.Traffic.TotalDownloadBytes != nil {
		result.run.Traffic.TotalDownloadBytes = new(*route.run.Traffic.TotalDownloadBytes)
	}
	if route.run.Ip != nil {
		ip := *route.run.Ip
		ip.Key = slices.Clone(ip.Key)
		ip.Prefixes = slices.Clone(ip.Prefixes)
		result.run.Ip = &ip
	}
	result.source.MAC = slices.Clone(route.source.MAC)
	return &result
}

func (r *ServiceRouting) pruneTerminalLocked(lease ingressv1.IngressLease, now time.Time) {
	identity := ingressv1.IngressLeaseIdentity{IngressId: lease.IngressId, IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision}
	for ref, terminal := range r.terminalRuns {
		if terminal.lease != identity || !terminal.until.After(now) {
			delete(r.terminalRuns, ref)
		}
	}
}

// retireTerminal fences exact control-confirmed tuples before their budgets can
// be forgotten. fences end at this lease's captured expiry, not a renewed lease.
func (r *ServiceRouting) retireTerminal(lease ingressv1.IngressLease, refs []ingressv1.ServiceRunReference) bool {
	r.mu.Lock()
	now := time.Now()
	if r.closed || !lease.ServingUntil.After(now) || lease.Draining ||
		r.lease.IngressLeaseRevision != 0 && !samePrivateLease(r.lease, lease) {
		r.mu.Unlock()
		return false
	}
	r.pruneTerminalLocked(lease, now)
	additional := 0
	for _, ref := range refs {
		if _, ok := r.terminalRuns[ref]; !ok {
			additional++
		}
	}
	if len(r.terminalRuns)+additional > maxTrafficKeys {
		// forgetting a confirmed closure could revive its run. stop this routing
		// owner instead; retain the budgets and join visitors through its worker.
		r.closed = true
		close(r.updated)
		r.wake()
		r.mu.Unlock()
		r.Close()
		return false
	}
	identity := ingressv1.IngressLeaseIdentity{IngressId: lease.IngressId, IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision}
	for _, ref := range refs {
		until := lease.ServingUntil
		if previous, ok := r.terminalRuns[ref]; ok {
			until = privateMinTime(until, previous.until)
		}
		r.terminalRuns[ref] = terminalServiceRun{lease: identity, until: until}
	}
	runs := make(map[string]*serviceRoute, len(r.runs))
	endpoints := make(map[serviceEndpoint][]*serviceRoute, len(r.endpoints))
	for endpoint, routes := range r.endpoints {
		for _, route := range routes {
			ref := ingressv1.ServiceRunReference{ServiceId: route.run.ServiceId, ServiceRunId: route.run.ServiceRunId, RunNumber: route.run.RunNumber}
			if _, closed := r.terminalRuns[ref]; !closed {
				runs[route.run.ServiceRunId] = route
				endpoints[endpoint] = append(endpoints[endpoint], route)
			}
		}
	}
	r.runs, r.endpoints = runs, endpoints
	r.stopping = append(r.stopping, r.expireVisitorsLocked(now)...)
	close(r.updated)
	r.updated = make(chan struct{})
	r.wake()
	r.mu.Unlock()
	return true
}

func (r *ServiceRouting) lookup(hostname string, port int, lease ingressv1.IngressLease, now time.Time) []*serviceRoute {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := r.lookupLocked(hostname, port, lease, now)
	for index, route := range result {
		result[index] = cloneServiceRoute(route)
	}
	return result
}

func (r *ServiceRouting) lookupLocked(hostname string, port int, lease ingressv1.IngressLease, now time.Time) []*serviceRoute {
	if r.closed || !samePrivateLease(r.lease, lease) || !lease.ServingUntil.After(now) || lease.Draining {
		return nil
	}
	var result []*serviceRoute
	for _, route := range r.endpoints[serviceEndpoint{hostname: hostname, port: port}] {
		if route.until.After(now) {
			result = append(result, route)
		}
	}
	return result
}

// reserveHTTP checks the opened assignment while holding routing stable through
// the local capacity debit. this callback performs no control I/O.
func (r *ServiceRouting) reserveHTTP(route *serviceRoute, relay ingressv1.ServiceRelay, lease ingressv1.IngressLease, source netip.Addr, reserve func() error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	current := r.runs[route.run.ServiceRunId]
	if r.closed || !samePrivateLease(r.lease, lease) || lease.Draining || !lease.ServingUntil.After(now) ||
		current == nil || current.run.ServiceId != route.run.ServiceId || current.run.RunNumber != route.run.RunNumber ||
		current.run.EndpointRevision != route.run.EndpointRevision || !route.until.After(now) || !current.until.After(now) ||
		current.ip != nil && !current.ip.Allows(source) || !relay.ServingUntil.After(now) {
		return ErrServiceAdmission
	}
	for _, candidate := range current.run.ConnectedRelays {
		if candidate.ServingUntil.After(now) && sameServiceRelayAssignment(candidate, relay) {
			return reserve()
		}
	}
	return ErrServiceAdmission
}

// waitForEndpoint keeps a first connection inside its original setup budget
// while independently scheduled routing catches up with a newly ready run.
// a cache hit never waits; a fresh miss is final. this never requests a refresh.
func (r *ServiceRouting) waitForEndpoint(ctx context.Context, hostname string, lease ingressv1.IngressLease) error {
	entered := time.Now()
	for {
		r.mu.Lock()
		now := time.Now()
		available := len(r.lookupLocked(hostname, 443, lease, now)) != 0
		finished := r.closed || !lease.ServingUntil.After(now) || lease.Draining || !r.startedAt.Before(entered)
		updated := r.updated
		r.mu.Unlock()
		if err := context.Cause(ctx); err != nil {
			return err
		}
		if available {
			return nil
		}
		if finished {
			return ErrServiceAdmission
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-updated:
		}
	}
}

// waitForRelayReplacement borrows new relay assignments for the same run only
// after every old opening failed before a visitor byte. it never renews the
// original source proof, setup deadline, run selection, or capacity debit.
func (r *ServiceRouting) waitForRelayReplacement(ctx context.Context, previous *serviceRoute, lease ingressv1.IngressLease, source netip.Addr) (*serviceRoute, error) {
	entered := time.Now()
	for {
		r.mu.Lock()
		now := time.Now()
		current := r.runs[previous.run.ServiceRunId]
		valid := !r.closed && samePrivateLease(r.lease, lease) && !lease.Draining && lease.ServingUntil.After(now) &&
			previous.until.After(now) && current != nil && current.until.After(now) &&
			current.run.ServiceId == previous.run.ServiceId && current.run.RunNumber == previous.run.RunNumber &&
			current.run.EndpointRevision == previous.run.EndpointRevision && (current.ip == nil || current.ip.Allows(source))
		replaced := valid && len(replacementRelays(previous.run.ConnectedRelays, current.run.ConnectedRelays)) != 0
		fresh := !r.startedAt.Before(entered)
		updated := r.updated
		r.mu.Unlock()
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		if !valid || fresh && !replaced {
			return nil, ErrServiceAdmission
		}
		if replaced {
			return current, nil
		}
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-updated:
		}
	}
}

func replacementRelays(previous, current []ingressv1.ServiceRelay) []ingressv1.ServiceRelay {
	var result []ingressv1.ServiceRelay
	for _, candidate := range current {
		found := false
		for _, attempted := range previous {
			// lease renewal alone cannot retry a failed connection assignment.
			if sameServiceRelayAssignment(candidate, attempted) {
				found = true
				break
			}
		}
		if !found {
			result = append(result, candidate)
		}
	}
	return result
}

func sameServiceRelayAssignment(a, b ingressv1.ServiceRelay) bool {
	a.LeaseExpiresAt, b.LeaseExpiresAt = time.Time{}, time.Time{}
	a.ServingUntil, b.ServingUntil = time.Time{}, time.Time{}
	return a == b
}

func (r *ServiceRouting) bind(route *serviceRoute, source netip.Addr, stop func()) (func(), error) {
	r.mu.Lock()
	now := time.Now()
	current := r.runs[route.run.ServiceRunId]
	if r.closed || current == nil || current.run.ServiceId != route.run.ServiceId || current.run.RunNumber != route.run.RunNumber ||
		current.run.EndpointRevision != route.run.EndpointRevision || stop == nil ||
		!route.until.After(now) || !current.until.After(now) || current.ip != nil && !current.ip.Allows(source) {
		r.mu.Unlock()
		return nil, ErrServiceAdmission
	}
	visitor := &routedVisitor{serviceID: route.run.ServiceId, runID: route.run.ServiceRunId, runNumber: route.run.RunNumber, endpointRevision: route.run.EndpointRevision,
		source: source, until: current.until, stop: stop}
	r.visitors[visitor] = struct{}{}
	r.wake()
	r.mu.Unlock()
	return sync.OnceFunc(func() {
		r.mu.Lock()
		delete(r.visitors, visitor)
		r.mu.Unlock()
	}), nil
}

func (s *Server) RoutingReady(now time.Time) bool {
	r := s.services
	r.mu.Lock()
	defer r.mu.Unlock()
	lease := s.config.CurrentLease()
	return !r.closed && samePrivateLease(r.lease, lease) && !lease.Draining &&
		r.validUntil.After(now) && lease.ServingUntil.After(now)
}

// RoutingObservedAt is control's timestamp for the last applied snapshot.
// reading it does not fetch or extend routing authority.
func (s *Server) RoutingObservedAt() time.Time {
	s.services.mu.Lock()
	defer s.services.mu.Unlock()
	return s.services.observedAt
}

func (r *ServiceRouting) expireVisitorsLocked(now time.Time) []*routedVisitor {
	var stopped []*routedVisitor
	for visitor := range r.visitors {
		current := r.runs[visitor.runID]
		if !visitor.until.After(now) || current == nil || current.run.ServiceId != visitor.serviceID || current.run.RunNumber != visitor.runNumber ||
			current.run.EndpointRevision != visitor.endpointRevision ||
			!current.until.After(now) || current.ip != nil && !current.ip.Allows(visitor.source) {
			delete(r.visitors, visitor)
			stopped = append(stopped, visitor)
		} else {
			visitor.until = current.until
		}
	}
	return stopped
}

// one worker owns expiry and connection stops. Close wakes it and waits for it;
// no timer callback or connection stop can outlive the routing owner.
func (r *ServiceRouting) expireVisitors() {
	defer close(r.done)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		r.mu.Lock()
		now := time.Now()
		stopped := append(r.stopping, r.expireVisitorsLocked(now)...)
		r.stopping = nil
		closed := r.closed
		var next time.Time
		for visitor := range r.visitors {
			if closed {
				stopped = append(stopped, visitor)
			} else if next.IsZero() || visitor.until.Before(next) {
				next = visitor.until
			}
		}
		if closed {
			clear(r.visitors)
		}
		r.mu.Unlock()
		stopRoutedVisitors(stopped)
		if closed {
			return
		}
		var expiry <-chan time.Time
		if !next.IsZero() {
			timer.Reset(time.Until(next))
			expiry = timer.C
		}
		select {
		case <-r.changed:
			timer.Stop()
		case <-expiry:
		}
	}
}

func (r *ServiceRouting) Close() {
	r.mu.Lock()
	if !r.closed {
		close(r.updated)
	}
	r.closed = true
	clear(r.runs)
	clear(r.endpoints)
	clear(r.sourceCounters)
	clear(r.terminalRuns)
	r.wake()
	r.mu.Unlock()
	<-r.done
}

func (r *ServiceRouting) wake() {
	select {
	case r.changed <- struct{}{}:
	default:
	}
}

func stopRoutedVisitors(visitors []*routedVisitor) {
	for _, visitor := range visitors {
		visitor.stop()
	}
}
