package ingressapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

type service struct {
	store               Store
	leaseDuration       time.Duration
	routingPollInterval time.Duration
	now                 func() time.Time
	report              func(error)
}

func newService(config DirectConfig) (*service, error) {
	if config.Store == nil || config.LeaseDuration <= 0 {
		return nil, errors.New("ingressapi: store and lease duration are required")
	}
	if config.RoutingPollInterval <= 0 {
		config.RoutingPollInterval = 250 * time.Millisecond
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Report == nil {
		config.Report = func(err error) { log.Printf("ingress service: %v", err) }
	}
	return &service{
		store: config.Store, leaseDuration: config.LeaseDuration,
		routingPollInterval: config.RoutingPollInterval, now: config.Now, report: config.Report,
	}, nil
}

func (s *service) RegisterIngress(ctx context.Context, body ingressv1.IngressRegistration) (ingressv1.IngressLease, error) {
	if !serviceapi.ValidIdentifiers(body.IngressId, body.IngressRunId) {
		return ingressv1.IngressLease{}, serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Ingress registration identifiers are invalid",
		)
	}
	protocolVersion, protocolOK := serviceapi.Positive(body.ProtocolVersion)
	connectionCapacity, capacityOK := serviceapi.Positive(body.ConnectionCapacity)
	if !protocolOK || !capacityOK {
		return ingressv1.IngressLease{}, serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Ingress protocol and connection capacity must be positive",
		)
	}
	lease, err := s.store.RegisterIngress(ctx, controlstate.IngressRegistration{
		IngressID: body.IngressId, IngressRunID: body.IngressRunId,
		ProtocolVersion: protocolVersion, ConnectionCapacity: connectionCapacity,
	}, s.now(), s.leaseDuration)
	if err != nil {
		return ingressv1.IngressLease{}, s.storeError(ctx, err)
	}
	return ingressLease(lease), nil
}

func (s *service) RenewIngress(
	ctx context.Context,
	ingressID ingressv1.IngressID,
	body ingressv1.IngressRenewal,
) (ingressv1.IngressLease, error) {
	if ingressID != body.IngressId {
		return ingressv1.IngressLease{}, pathMismatchError()
	}
	identity, ok := ingressLeaseIdentity(body.IngressId, body.IngressRunId, body.IngressLeaseRevision)
	reportedConnections, connectionsOK := serviceapi.Nonnegative(body.ReportedConnections)
	routingRevision, revisionOK := serviceapi.Nonnegative(body.RoutingTableRevision)
	if !ok || !connectionsOK || !revisionOK {
		return ingressv1.IngressLease{}, serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Ingress renewal identity or counters are invalid",
		)
	}
	lease, err := s.store.RenewIngress(ctx, controlstate.IngressRenewal{
		IngressLeaseIdentity: identity, ReportedConnections: reportedConnections,
		RoutingTableRevision: routingRevision,
	}, s.now(), s.leaseDuration)
	if err != nil {
		return ingressv1.IngressLease{}, s.storeError(ctx, err)
	}
	return ingressLease(lease), nil
}

func (s *service) DrainIngress(
	ctx context.Context,
	ingressID ingressv1.IngressID,
	body ingressv1.IngressDrainRequest,
) (ingressv1.IngressLease, error) {
	if ingressID != body.IngressId {
		return ingressv1.IngressLease{}, pathMismatchError()
	}
	identity, ok := ingressLeaseIdentity(body.IngressId, body.IngressRunId, body.IngressLeaseRevision)
	if !ok || !body.Deadline.After(s.now()) {
		return ingressv1.IngressLease{}, serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Ingress drain identity or deadline is invalid",
		)
	}
	lease, err := s.store.BeginIngressDrain(ctx, identity, s.now(), body.Deadline)
	if err != nil {
		return ingressv1.IngressLease{}, s.storeError(ctx, err)
	}
	return ingressLease(lease), nil
}

func (s *service) GetIngressRoutingTableSnapshot(
	ctx context.Context,
	ingressID ingressv1.IngressID,
	params ingressv1.GetIngressRoutingTableSnapshotParams,
) (ingressv1.IngressRoutingTableSnapshot, error) {
	identity, ok := ingressLeaseIdentity(ingressID, params.IngressRunId, params.IngressLeaseRevision)
	if !ok {
		return ingressv1.IngressRoutingTableSnapshot{}, serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Ingress lease identity is invalid",
		)
	}
	snapshot, err := s.store.ReadIngressRoutingTableSnapshot(ctx, identity, s.now())
	if err != nil {
		return ingressv1.IngressRoutingTableSnapshot{}, s.storeError(ctx, err)
	}
	return routingTableSnapshot(snapshot), nil
}

func (s *service) GetIngressRoutingTableEvents(
	ctx context.Context,
	ingressID ingressv1.IngressID,
	params ingressv1.GetIngressRoutingTableEventsParams,
) (ingressv1.IngressRoutingTablePage, error) {
	identity, ok := ingressLeaseIdentity(ingressID, params.IngressRunId, params.IngressLeaseRevision)
	after, afterOK := serviceapi.Nonnegative(params.After)
	if !afterOK {
		return ingressv1.IngressRoutingTablePage{}, serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request", "after must be a non-negative routing-table revision",
		)
	}
	limit := defaultRoutingTablePageSize
	if params.Limit != nil {
		limit = *params.Limit
	}
	if limit < 1 || limit > controlstate.MaximumIngressRoutingTablePageSize {
		return ingressv1.IngressRoutingTablePage{}, serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request", "limit must be between 1 and 1000",
		)
	}
	wait := defaultRoutingTableWait
	if params.Wait != nil {
		var err error
		wait, err = time.ParseDuration(*params.Wait)
		if err != nil || wait < 0 || wait > defaultRoutingTableWait || wait%time.Second != 0 {
			return ingressv1.IngressRoutingTablePage{}, serviceapi.NewProblemError(
				http.StatusBadRequest, "invalid_request", "wait must be a whole-second duration between 0s and 25s",
			)
		}
	}
	if !ok {
		return ingressv1.IngressRoutingTablePage{}, serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Ingress lease identity is invalid",
		)
	}
	deadline := time.Now().Add(wait)
	for {
		page, err := s.store.ReadIngressRoutingTableEvents(ctx, identity, after, limit, s.now())
		if err != nil {
			return ingressv1.IngressRoutingTablePage{}, s.storeError(ctx, err)
		}
		if page.ResnapshotRequired {
			return ingressv1.IngressRoutingTablePage{}, serviceapi.NewProblemError(
				http.StatusConflict, "routing_table_resnapshot_required",
				"The routing-table revision was compacted; load a new snapshot",
			)
		}
		if len(page.Events) != 0 || page.More || wait == 0 || !time.Now().Before(deadline) {
			return routingTablePage(page), nil
		}
		poll := s.routingPollInterval
		if remaining := time.Until(deadline); poll > remaining {
			poll = remaining
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ingressv1.IngressRoutingTablePage{}, context.Cause(ctx)
		case <-timer.C:
		}
	}
}

func (s *service) ReportIngressUsage(
	ctx context.Context,
	ingressID ingressv1.IngressID,
	body ingressv1.IngressUsageReportBatch,
) error {
	if ingressID != body.IngressId {
		return pathMismatchError()
	}
	identity, ok := ingressLeaseIdentity(body.IngressId, body.IngressRunId, body.IngressLeaseRevision)
	batch, batchOK := ingressUsageBatch(body)
	if !ok || !batchOK {
		return serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Ingress usage reports are invalid",
		)
	}
	if err := s.store.ReportIngressUsage(ctx, identity, batch, s.now()); err != nil {
		return s.storeError(ctx, err)
	}
	return nil
}

func (s *service) ObserveRouteRecovery(
	ctx context.Context,
	ingressID ingressv1.IngressID,
	episodeID int64,
	body ingressv1.RouteRecoveryObservationRequest,
) (ingressv1.RouteRecoveryObservation, error) {
	if ingressID != body.IngressId {
		return ingressv1.RouteRecoveryObservation{}, pathMismatchError()
	}
	identity, ok := ingressLeaseIdentity(body.IngressId, body.IngressRunId, body.IngressLeaseRevision)
	routeVersion, routeOK := serviceapi.Positive(body.RouteVersion)
	episode, episodeOK := serviceapi.Positive(episodeID)
	if !ok || !routeOK || !episodeOK || !serviceapi.ValidIdentifiers(body.RouteId) || body.ObservedAt.IsZero() {
		return ingressv1.RouteRecoveryObservation{}, serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Recovery observation identity is invalid",
		)
	}
	observation, err := s.store.ObserveRouteRecovery(
		ctx, identity, body.RouteId, routeVersion, episode, body.ObservedAt,
	)
	if err != nil {
		return ingressv1.RouteRecoveryObservation{}, s.storeError(ctx, err)
	}
	return ingressv1.RouteRecoveryObservation{
		EpisodeId: int64(observation.EpisodeID), RouteId: observation.RouteID,
		RouteVersion: int64(observation.RouteVersion), OpenedAt: observation.OpenedAt,
		ObservedAt: observation.ObservedAt, ObservedSeconds: observation.ObservedSeconds,
	}, nil
}

func (s *service) storeError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	status, kind, detail := storeProblem(err, s.report)
	return serviceapi.NewProblemError(status, kind, detail)
}

func pathMismatchError() error {
	return serviceapi.NewProblemError(
		http.StatusBadRequest, "invalid_request", "Path and request body identifiers do not match",
	)
}
