package ingress

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// a selected run supplies the same forwarding facts for every protocol. HTTP
// uses prepared routing and local access checks; native certificates retain
// control's current certificate and identity checks.
type visitorAccessKind uint8

const (
	httpRequestAccess visitorAccessKind = iota + 1
	clientCertificateAccess
)

type selectedServiceRun struct {
	access                      visitorAccessKind
	serviceID, runID, visitorID string
	number                      int64
	expiresAt                   time.Time
	relays                      []ingressv1.ServiceRelay
	limits                      TrafficLimits
	anonymous                   bool
	recoveryEpisodeID           *int64
	http                        *serviceRoute
	certificate                 *ingressv1.PublicServiceVisitorLookup
	denialReason                controlv1.ServiceObservationReason
}

func (s *Server) selectPublicRun(ctx context.Context, lease ingressv1.IngressLease, source, destination netip.AddrPort, hostname string, capacity *visitorAdmission) (selected selectedServiceRun, result error) {
	// one original budget bounds local scanning and every native admit/close.
	// candidate rejection never restarts it.
	ctx, cancel := context.WithDeadline(ctx, privateMinTime(capacity.deadline, lease.ServingUntil))
	defer cancel()
	if err := context.Cause(ctx); err != nil {
		return selected, err
	}
	if destination.Port() == 443 {
		runs := s.services.candidates(hostname, 443, lease, time.Now())
		available := false
		for _, run := range runs {
			if err := context.Cause(ctx); err != nil {
				return selected, err
			}
			if run.until.After(time.Now()) {
				available = true
				break
			}
		}
		if !available {
			// never wait for unknown or stale policy without a bounded slot.
			// a cache hit selects its accounting class without borrowing one.
			if reason := capacity.admitPending(); reason != "" {
				s.rejectCapacity(reason)
				selected.denialReason = controlv1.ObservationCapacity
				return selected, ErrServiceAdmission
			}
			if err := s.services.waitForEndpoint(ctx, hostname, lease); err != nil {
				return selected, err
			}
			runs = s.services.candidates(hostname, 443, lease, time.Now())
		}
		if len(runs) == 0 {
			return selected, ErrServiceAdmission
		}
		first := int((s.nextServiceRun.Add(1) - 1) % uint64(len(runs)))
		// visit this finite snapshot once, rotating the start for each visitor.
		// unusable entries do not consume a separate fixed candidate budget.
		for attempt := range len(runs) {
			if err := context.Cause(ctx); err != nil {
				return selected, err
			}
			run := runs[(first+attempt)%len(runs)]
			if !run.until.After(time.Now()) {
				continue
			}
			selected = selectedServiceRun{
				access:    httpRequestAccess,
				serviceID: run.run.ServiceId, runID: run.run.ServiceRunId, number: run.run.RunNumber,
				expiresAt: run.until, limits: run.traffic, anonymous: run.run.Anonymous, http: cloneServiceRoute(run),
				recoveryEpisodeID: run.run.RecoveryEpisodeId,
				denialReason:      controlv1.ObservationUnavailable,
			}
			selected.recoveryEpisodeID = selected.http.run.RecoveryEpisodeId
			selected.visitorID, result = opaqueid.New(opaqueid.VisitorConnectionPrefix)
			if result != nil {
				return selected, result
			}
			if run.ip != nil && !run.ip.Allows(source.Addr().Unmap()) {
				selected.denialReason = controlv1.ObservationIPPolicy
				return selected, ErrServiceAdmission
			}
			selected.relays = nil
			for _, relay := range run.run.ConnectedRelays {
				if relay.ServingUntil.After(time.Now()) {
					selected.relays = append(selected.relays, relay)
				}
			}
			if len(selected.relays) == 0 {
				continue
			}
			current, err := s.lease(time.Now())
			if err != nil || !samePrivateLease(current, lease) || ctx.Err() != nil || !run.until.After(time.Now()) {
				return selected, ErrServiceAdmission
			}
			key := trafficKey{service: selected.serviceID, id: selected.runID, run: uint64(selected.number)}
			var reason string
			if !selected.anonymous {
				// this is only a pre-byte availability check, not a reservation
				// or permission. authorized visitors must acquire atomically later.
				reason = s.traffic.available(key, selected.limits)
			}
			if reason == "" {
				reason = capacity.selectRun(key, selected.limits, source.Addr().Unmap(), selected.anonymous)
			}
			if reason == "" {
				return selected, nil
			}
			s.rejectCapacity(reason)
			selected.denialReason = controlv1.ObservationCapacity
			if !retryServiceRunSelection(reason) {
				return selected, ErrServiceAdmission
			}
		}
		return selected, errors.Join(ErrServiceAdmission, ErrServiceSelectionLimit)
	}

	if reason := capacity.admitPending(); reason != "" {
		s.rejectCapacity(reason)
		selected.denialReason = controlv1.ObservationCapacity
		return selected, ErrServiceAdmission
	}
	lookup := &ingressv1.PublicServiceVisitorLookup{IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision, ObservedSourceIp: source.Addr().Unmap().String()}
	selected.certificate = lookup
	selected.access = clientCertificateAccess
	claim := ingressv1.PublicServiceVisitorClaim{
		IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
		IngressPoolId: s.config.IngressPoolID, DestinationPort: int(destination.Port()), ObservedSourceIp: source.Addr().Unmap().String(),
	}
	visited := make(map[string]struct{})
	for {
		if ctx.Err() != nil {
			return selected, context.Cause(ctx)
		}
		current, err := s.lease(time.Now())
		if err != nil || !samePrivateLease(current, lease) {
			return selected, ErrServiceAdmission
		}
		claim.VisitorConnectionId, err = opaqueid.New(opaqueid.VisitorConnectionPrefix)
		if err != nil {
			return selected, err
		}
		lookup.VisitorConnectionId = claim.VisitorConnectionId
		admitted, err := s.config.Control.AdmitPublicServiceVisitor(ctx, lease.IngressId, claim)
		if err != nil {
			// an ambiguous response may own this exact reservation. the caller
			// closes it; never turn a lost response into another selection.
			return selected, err
		}
		if admitted.VisitorConnectionId != claim.VisitorConnectionId || validatePublicServiceAdmission(admitted, time.Now()) != nil ||
			selected.serviceID != "" && selected.serviceID != admitted.ServiceId {
			return selected, ErrServiceAdmission
		}
		if _, repeated := visited[admitted.ServiceRunId]; repeated {
			return selected, ErrServiceAdmission
		}
		visited[admitted.ServiceRunId] = struct{}{}
		if cursor := claim.RunCursor; cursor != nil {
			if admitted.ServiceId != cursor.Start.ServiceId || admitted.ServiceRunId == cursor.Start.ServiceRunId ||
				admitted.ServiceRunId == cursor.After.ServiceRunId || !serviceRunCursorAllows(*cursor, admitted.RunNumber) {
				return selected, ErrServiceAdmission
			}
		}
		selected = selectedServiceRun{
			access:    clientCertificateAccess,
			serviceID: admitted.ServiceId, runID: admitted.ServiceRunId, number: admitted.RunNumber, visitorID: admitted.VisitorConnectionId,
			expiresAt: admitted.ExpiresAt, relays: admitted.ConnectedRelays, certificate: lookup, recoveryEpisodeID: admitted.RecoveryEpisodeId,
		}
		selected.limits, err = routingTraffic(admitted.Traffic)
		if err != nil {
			return selected, err
		}
		current, err = s.lease(time.Now())
		if err != nil || !samePrivateLease(current, lease) || ctx.Err() != nil || !selected.expiresAt.After(time.Now()) {
			return selected, ErrServiceAdmission
		}
		reason := capacity.selectRun(trafficKey{service: selected.serviceID, id: selected.runID, run: uint64(selected.number)}, selected.limits, source.Addr().Unmap(), false)
		if reason == "" {
			return selected, nil
		}
		s.rejectCapacity(reason)
		if !retryServiceRunSelection(reason) {
			return selected, ErrServiceAdmission
		}
		if err := s.config.Control.ClosePublicServiceVisitor(ctx, lease.IngressId, *lookup); err != nil {
			return selected, err
		}
		lookup.VisitorConnectionId = ""
		ref := ingressv1.ServiceRunReference{ServiceId: selected.serviceID, ServiceRunId: selected.runID, RunNumber: selected.number}
		if claim.RunCursor == nil {
			claim.RunCursor = &ingressv1.ServiceRunCursor{Start: ref}
		}
		claim.RunCursor.After = ref
	}
}

// continuation is a single circular pass after the load-selected first run.
// monotonic run numbers keep later pages stable even if reported load changes.
func serviceRunCursorAllows(cursor ingressv1.ServiceRunCursor, number int64) bool {
	if cursor.After.RunNumber >= cursor.Start.RunNumber {
		return number > cursor.After.RunNumber || number < cursor.Start.RunNumber
	}
	return number > cursor.After.RunNumber && number < cursor.Start.RunNumber
}
