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
	if destination.Port() == 443 {
		runs := s.services.lookup(hostname, 443, lease, time.Now())
		if len(runs) == 0 {
			return selected, ErrServiceAdmission
		}
		first := int((s.nextServiceRun.Add(1) - 1) % uint64(len(runs)))
		for attempt := range min(len(runs), 8) {
			run := runs[(first+attempt)%len(runs)]
			selected = selectedServiceRun{
				access:    httpRequestAccess,
				serviceID: run.run.ServiceId, runID: run.run.ServiceRunId, number: run.run.RunNumber,
				expiresAt: run.until, relays: run.run.ConnectedRelays, limits: run.traffic, anonymous: run.run.Anonymous, http: run,
				recoveryEpisodeID: run.run.RecoveryEpisodeId,
				denialReason:      controlv1.ObservationUnavailable,
			}
			selected.visitorID, result = opaqueid.New(opaqueid.VisitorConnectionPrefix)
			if result != nil {
				return selected, result
			}
			if ctx.Err() != nil || !run.until.After(time.Now()) {
				return selected, ErrServiceAdmission
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
			reason := capacity.selectRun(trafficKey{service: selected.serviceID, id: selected.runID, run: uint64(selected.number)}, selected.limits, source.Addr().Unmap(), selected.anonymous)
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

	lookup := &ingressv1.PublicServiceVisitorLookup{IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision}
	selected.certificate = lookup
	selected.access = clientCertificateAccess
	claim := ingressv1.PublicServiceVisitorClaim{
		IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
		IngressPoolId: s.config.IngressPoolID, DestinationPort: int(destination.Port()), ObservedSourceIp: source.Addr().Unmap().String(),
	}
	for range 8 {
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
		for _, excluded := range claim.ExcludedRuns {
			if admitted.ServiceRunId == excluded.ServiceRunId || admitted.RunNumber == excluded.RunNumber {
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
		claim.ExcludedRuns = append(claim.ExcludedRuns, ingressv1.ServiceRunReference{ServiceId: selected.serviceID, ServiceRunId: selected.runID, RunNumber: selected.number})
	}
	return selected, errors.Join(ErrServiceAdmission, ErrServiceSelectionLimit)
}
