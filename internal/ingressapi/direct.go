package ingressapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

type DirectConfig struct {
	Store               Store
	LeaseDuration       time.Duration
	RoutingPollInterval time.Duration
	Now                 func() time.Time
}

type DirectClient struct {
	store               Store
	leaseDuration       time.Duration
	routingPollInterval time.Duration
	now                 func() time.Time
}

func NewDirectClient(config DirectConfig) (*DirectClient, error) {
	if config.Store == nil || config.LeaseDuration <= 0 {
		return nil, errors.New("ingressapi: direct store and lease duration are required")
	}
	if config.RoutingPollInterval <= 0 {
		config.RoutingPollInterval = 250 * time.Millisecond
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &DirectClient{
		store: config.Store, leaseDuration: config.LeaseDuration,
		routingPollInterval: config.RoutingPollInterval, now: config.Now,
	}, nil
}

func (c *DirectClient) RegisterIngressWithResponse(
	ctx context.Context,
	body ingressv1.RegisterIngressJSONRequestBody,
	_ ...ingressv1.RequestEditorFn,
) (*ingressv1.RegisterIngressResponse, error) {
	protocolVersion, protocolOK := serviceapi.Positive(body.ProtocolVersion)
	connectionCapacity, capacityOK := serviceapi.Positive(body.ConnectionCapacity)
	if !protocolOK || !capacityOK {
		return nil, errors.New("ingressapi: direct registration is invalid")
	}
	lease, err := c.store.RegisterIngress(ctx, controlstate.IngressRegistration{
		IngressID: body.IngressId, IngressRunID: body.IngressRunId,
		ProtocolVersion: protocolVersion, ConnectionCapacity: connectionCapacity,
	}, c.now(), c.leaseDuration)
	if err != nil {
		return nil, err
	}
	result := ingressLease(lease)
	return &ingressv1.RegisterIngressResponse{JSON200: &result}, nil
}

func (c *DirectClient) RenewIngressWithResponse(
	ctx context.Context,
	_ ingressv1.IngressID,
	body ingressv1.RenewIngressJSONRequestBody,
	_ ...ingressv1.RequestEditorFn,
) (*ingressv1.RenewIngressResponse, error) {
	identity, ok := ingressLeaseIdentity(body.IngressId, body.IngressRunId, body.IngressLeaseRevision)
	reportedConnections, connectionsOK := serviceapi.Nonnegative(body.ReportedConnections)
	routingRevision, revisionOK := serviceapi.Nonnegative(body.RoutingTableRevision)
	if !ok || !connectionsOK || !revisionOK {
		return nil, errors.New("ingressapi: direct renewal is invalid")
	}
	lease, err := c.store.RenewIngress(ctx, controlstate.IngressRenewal{
		IngressLeaseIdentity: identity, ReportedConnections: reportedConnections,
		RoutingTableRevision: routingRevision,
	}, c.now(), c.leaseDuration)
	if err != nil {
		return nil, err
	}
	result := ingressLease(lease)
	return &ingressv1.RenewIngressResponse{JSON200: &result}, nil
}

func (c *DirectClient) DrainIngressWithResponse(
	ctx context.Context,
	_ ingressv1.IngressID,
	body ingressv1.DrainIngressJSONRequestBody,
	_ ...ingressv1.RequestEditorFn,
) (*ingressv1.DrainIngressResponse, error) {
	identity, ok := ingressLeaseIdentity(body.IngressId, body.IngressRunId, body.IngressLeaseRevision)
	if !ok {
		return nil, errors.New("ingressapi: direct drain is invalid")
	}
	lease, err := c.store.BeginIngressDrain(ctx, identity, c.now(), body.Deadline)
	if err != nil {
		return nil, err
	}
	result := ingressLease(lease)
	return &ingressv1.DrainIngressResponse{JSON200: &result}, nil
}

func (c *DirectClient) GetIngressRoutingTableSnapshotWithResponse(
	ctx context.Context,
	ingressID ingressv1.IngressID,
	params *ingressv1.GetIngressRoutingTableSnapshotParams,
	_ ...ingressv1.RequestEditorFn,
) (*ingressv1.GetIngressRoutingTableSnapshotResponse, error) {
	if params == nil {
		return nil, errors.New("ingressapi: direct routing-table snapshot parameters are required")
	}
	identity, ok := ingressLeaseIdentity(ingressID, params.IngressRunId, params.IngressLeaseRevision)
	if !ok {
		return nil, errors.New("ingressapi: direct routing-table snapshot identity is invalid")
	}
	snapshot, err := c.store.ReadIngressRoutingTableSnapshot(ctx, identity, c.now())
	if err != nil {
		return nil, err
	}
	result := routingTableSnapshot(snapshot)
	return &ingressv1.GetIngressRoutingTableSnapshotResponse{JSON200: &result}, nil
}

func (c *DirectClient) GetIngressRoutingTableEventsWithResponse(
	ctx context.Context,
	ingressID ingressv1.IngressID,
	params *ingressv1.GetIngressRoutingTableEventsParams,
	_ ...ingressv1.RequestEditorFn,
) (*ingressv1.GetIngressRoutingTableEventsResponse, error) {
	if params == nil {
		return nil, errors.New("ingressapi: direct routing-table event parameters are required")
	}
	identity, ok := ingressLeaseIdentity(ingressID, params.IngressRunId, params.IngressLeaseRevision)
	after, afterOK := serviceapi.Nonnegative(params.After)
	limit := defaultRoutingTablePageSize
	if params.Limit != nil {
		limit = *params.Limit
	}
	wait := time.Duration(0)
	if params.Wait != nil {
		var err error
		wait, err = time.ParseDuration(*params.Wait)
		if err != nil || wait < 0 || wait > 25*time.Second || wait%time.Second != 0 {
			return nil, errors.New("ingressapi: direct routing-table wait is invalid")
		}
	}
	if !ok || !afterOK || limit <= 0 || limit > controlstate.MaximumIngressRoutingTablePageSize {
		return nil, errors.New("ingressapi: direct routing-table event parameters are invalid")
	}
	deadline := time.Now().Add(wait)
	for {
		page, err := c.store.ReadIngressRoutingTableEvents(ctx, identity, after, limit, c.now())
		if err != nil {
			return nil, err
		}
		if page.ResnapshotRequired {
			problem := ingressv1.Problem{
				Type: "https://tnl.dev/problems/routing_table_resnapshot_required", Title: "Conflict",
				Status: http.StatusConflict, Detail: "The routing-table revision was compacted; load a new snapshot",
			}
			return &ingressv1.GetIngressRoutingTableEventsResponse{
				HTTPResponse: httpStatusResponse(http.StatusConflict), ApplicationproblemJSON409: &problem,
			}, nil
		}
		if len(page.Events) != 0 || page.More || wait == 0 || !time.Now().Before(deadline) {
			result := routingTablePage(page)
			return &ingressv1.GetIngressRoutingTableEventsResponse{JSON200: &result}, nil
		}
		poll := c.routingPollInterval
		if remaining := time.Until(deadline); poll > remaining {
			poll = remaining
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (c *DirectClient) ReportIngressUsageWithResponse(
	ctx context.Context,
	_ ingressv1.IngressID,
	body ingressv1.ReportIngressUsageJSONRequestBody,
	_ ...ingressv1.RequestEditorFn,
) (*ingressv1.ReportIngressUsageResponse, error) {
	identity, ok := ingressLeaseIdentity(body.IngressId, body.IngressRunId, body.IngressLeaseRevision)
	batch, batchOK := ingressUsageBatch(body)
	if !ok || !batchOK {
		return nil, errors.New("ingressapi: direct usage report is invalid")
	}
	if err := c.store.ReportIngressUsage(ctx, identity, batch, c.now()); err != nil {
		return nil, err
	}
	return &ingressv1.ReportIngressUsageResponse{HTTPResponse: httpStatusResponse(http.StatusNoContent)}, nil
}

func (c *DirectClient) ObserveRouteRecoveryWithResponse(
	ctx context.Context,
	_ ingressv1.IngressID,
	episodeID int64,
	body ingressv1.ObserveRouteRecoveryJSONRequestBody,
	_ ...ingressv1.RequestEditorFn,
) (*ingressv1.ObserveRouteRecoveryResponse, error) {
	identity, ok := ingressLeaseIdentity(body.IngressId, body.IngressRunId, body.IngressLeaseRevision)
	routeVersion, routeOK := serviceapi.Positive(body.RouteVersion)
	episode, episodeOK := serviceapi.Positive(episodeID)
	if !ok || !routeOK || !episodeOK {
		return nil, errors.New("ingressapi: direct recovery observation is invalid")
	}
	observation, err := c.store.ObserveRouteRecovery(ctx, identity, body.RouteId, routeVersion, episode, body.ObservedAt)
	if err != nil {
		return nil, err
	}
	result := ingressv1.RouteRecoveryObservation{
		EpisodeId: int64(observation.EpisodeID), RouteId: observation.RouteID,
		RouteVersion: int64(observation.RouteVersion), OpenedAt: observation.OpenedAt,
		ObservedAt: observation.ObservedAt, ObservedSeconds: observation.ObservedSeconds,
	}
	return &ingressv1.ObserveRouteRecoveryResponse{JSON200: &result}, nil
}

func httpStatusResponse(status int) *http.Response {
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: make(http.Header)}
}
