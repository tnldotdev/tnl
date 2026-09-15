// Package ingressapi serves the cluster-authenticated private control API for ingress.
package ingressapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

const defaultRoutingTablePageSize = 256
const defaultRoutingTableWait = 25 * time.Second

type Store interface {
	RegisterIngress(context.Context, controlstate.IngressRegistration, time.Time, time.Duration) (controlstate.IngressLease, error)
	RenewIngress(context.Context, controlstate.IngressRenewal, time.Time, time.Duration) (controlstate.IngressLease, error)
	BeginIngressDrain(context.Context, controlstate.IngressLeaseIdentity, time.Time, time.Time) (controlstate.IngressLease, error)
	ReadIngressRoutingTableSnapshot(context.Context, controlstate.IngressLeaseIdentity, time.Time) (controlstate.IngressRoutingTableSnapshot, error)
	ReadIngressRoutingTableEvents(context.Context, controlstate.IngressLeaseIdentity, uint64, int, time.Time) (controlstate.IngressRoutingTablePage, error)
	ReportIngressUsage(context.Context, controlstate.IngressLeaseIdentity, controlstate.IngressUsageBatch, time.Time) error
	ObserveRouteRecovery(context.Context, controlstate.IngressLeaseIdentity, string, uint64, uint64, time.Time) (controlstate.RouteRecoveryObservation, error)
}

type Config struct {
	Store               Store
	ClusterSecrets      serviceapi.BearerSecrets
	LeaseDuration       time.Duration
	RoutingPollInterval time.Duration
	Now                 func() time.Time
	Report              func(error)
}

type handler struct {
	store               Store
	clusterSecrets      serviceapi.BearerSecrets
	leaseDuration       time.Duration
	routingPollInterval time.Duration
	now                 func() time.Time
	report              func(error)
	mux                 *http.ServeMux
}

// NewHandler constructs the private ingress service.
func NewHandler(config Config) (http.Handler, error) {
	if config.Store == nil || !config.ClusterSecrets.Valid() {
		return nil, errors.New("ingressapi: store and cluster secrets are required")
	}
	if config.LeaseDuration <= 0 {
		return nil, errors.New("ingressapi: ingress lease duration must be positive")
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
	h := &handler{
		store: config.Store, clusterSecrets: config.ClusterSecrets, leaseDuration: config.LeaseDuration,
		routingPollInterval: config.RoutingPollInterval, now: config.Now, report: config.Report,
		mux: http.NewServeMux(),
	}
	ingressv1.HandlerWithOptions(generatedServer{handler: h}, ingressv1.StdHTTPServerOptions{
		BaseRouter: h.mux,
		ErrorHandlerFunc: func(response http.ResponseWriter, _ *http.Request, _ error) {
			serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Ingress request parameters are invalid")
		},
	})
	h.mux.HandleFunc("/", func(response http.ResponseWriter, _ *http.Request) {
		serviceapi.WriteProblem(response, http.StatusNotFound, "not_found", "Ingress service endpoint not found")
	})
	return h, nil
}

func (h *handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	if !h.clusterSecrets.Authenticate(request.Header) {
		response.Header().Set("WWW-Authenticate", "Bearer")
		serviceapi.WriteProblem(response, http.StatusUnauthorized, "unauthenticated", "A valid cluster secret is required")
		return
	}
	h.mux.ServeHTTP(response, request)
}

func (h *handler) registerIngress(response http.ResponseWriter, request *http.Request) {
	var body ingressv1.IngressRegistration
	if !serviceapi.DecodeJSON(response, request, &body) {
		return
	}
	if !serviceapi.ValidIdentifiers(body.IngressId, body.IngressRunId) {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Ingress registration identifiers are invalid")
		return
	}
	protocolVersion, protocolOK := serviceapi.Positive(body.ProtocolVersion)
	connectionCapacity, capacityOK := serviceapi.Positive(body.ConnectionCapacity)
	if !protocolOK || !capacityOK {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Ingress protocol and connection capacity must be positive")
		return
	}
	lease, err := h.store.RegisterIngress(request.Context(), controlstate.IngressRegistration{
		IngressID: body.IngressId, IngressRunID: body.IngressRunId,
		ProtocolVersion: protocolVersion, ConnectionCapacity: connectionCapacity,
	}, h.now(), h.leaseDuration)
	if err != nil {
		h.writeStoreError(response, err)
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, ingressLease(lease))
}

func (h *handler) renewIngress(response http.ResponseWriter, request *http.Request) {
	var body ingressv1.IngressRenewal
	if !serviceapi.DecodeJSON(response, request, &body) ||
		!serviceapi.MatchingPathValue(response, request, "ingress_id", body.IngressId) {
		return
	}
	identity, ok := ingressLeaseIdentity(body.IngressId, body.IngressRunId, body.IngressLeaseRevision)
	reportedConnections, connectionsOK := serviceapi.Nonnegative(body.ReportedConnections)
	routingRevision, revisionOK := serviceapi.Nonnegative(body.RoutingTableRevision)
	if !ok || !connectionsOK || !revisionOK {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Ingress renewal identity or counters are invalid")
		return
	}
	lease, err := h.store.RenewIngress(request.Context(), controlstate.IngressRenewal{
		IngressLeaseIdentity: identity, ReportedConnections: reportedConnections,
		RoutingTableRevision: routingRevision,
	}, h.now(), h.leaseDuration)
	if err != nil {
		h.writeStoreError(response, err)
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, ingressLease(lease))
}

func (h *handler) drainIngress(response http.ResponseWriter, request *http.Request) {
	var body ingressv1.IngressDrainRequest
	if !serviceapi.DecodeJSON(response, request, &body) ||
		!serviceapi.MatchingPathValue(response, request, "ingress_id", body.IngressId) {
		return
	}
	identity, ok := ingressLeaseIdentity(body.IngressId, body.IngressRunId, body.IngressLeaseRevision)
	if !ok || !body.Deadline.After(h.now()) {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Ingress drain identity or deadline is invalid")
		return
	}
	lease, err := h.store.BeginIngressDrain(request.Context(), identity, h.now(), body.Deadline)
	if err != nil {
		h.writeStoreError(response, err)
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, ingressLease(lease))
}

func (h *handler) routingTableSnapshot(response http.ResponseWriter, request *http.Request) {
	identity, ok := h.ingressIdentityFromQuery(response, request)
	if !ok {
		return
	}
	snapshot, err := h.store.ReadIngressRoutingTableSnapshot(request.Context(), identity, h.now())
	if err != nil {
		h.writeStoreError(response, err)
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, routingTableSnapshot(snapshot))
}

func (h *handler) routingTableEvents(response http.ResponseWriter, request *http.Request) {
	identity, ok := h.ingressIdentityFromQuery(response, request)
	if !ok {
		return
	}
	after, err := strconv.ParseUint(request.URL.Query().Get("after"), 10, 64)
	if err != nil {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "after must be a non-negative routing-table revision")
		return
	}
	limit, ok := queryInteger(request, "limit", defaultRoutingTablePageSize, 1, controlstate.MaximumIngressRoutingTablePageSize)
	if !ok {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 1000")
		return
	}
	wait, ok := queryWholeSecondDuration(request, "wait", defaultRoutingTableWait, defaultRoutingTableWait)
	if !ok {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "wait must be a whole-second duration between 0s and 25s")
		return
	}
	deadline := time.Now().Add(wait)
	for {
		page, err := h.store.ReadIngressRoutingTableEvents(request.Context(), identity, after, limit, h.now())
		if err != nil {
			h.writeStoreError(response, err)
			return
		}
		if page.ResnapshotRequired {
			serviceapi.WriteProblem(response, http.StatusConflict, "routing_table_resnapshot_required", "The routing-table revision was compacted; load a new snapshot")
			return
		}
		if len(page.Events) != 0 || page.More || wait == 0 || !time.Now().Before(deadline) {
			serviceapi.WriteJSON(response, http.StatusOK, routingTablePage(page))
			return
		}
		poll := h.routingPollInterval
		if remaining := time.Until(deadline); poll > remaining {
			poll = remaining
		}
		timer := time.NewTimer(poll)
		select {
		case <-request.Context().Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (h *handler) reportUsage(response http.ResponseWriter, request *http.Request) {
	var body ingressv1.IngressUsageReportBatch
	if !serviceapi.DecodeJSON(response, request, &body) ||
		!serviceapi.MatchingPathValue(response, request, "ingress_id", body.IngressId) {
		return
	}
	identity, ok := ingressLeaseIdentity(body.IngressId, body.IngressRunId, body.IngressLeaseRevision)
	if !ok {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Ingress usage lease identity is invalid")
		return
	}
	batch, ok := ingressUsageBatch(body)
	if !ok {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Ingress usage reports are invalid")
		return
	}
	if err := h.store.ReportIngressUsage(request.Context(), identity, batch, h.now()); err != nil {
		h.writeStoreError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *handler) observeRecovery(response http.ResponseWriter, request *http.Request) {
	episodeID, err := strconv.ParseUint(request.PathValue("episode_id"), 10, 64)
	if err != nil || episodeID == 0 {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Recovery episode ID is invalid")
		return
	}
	var body ingressv1.RouteRecoveryObservationRequest
	if !serviceapi.DecodeJSON(response, request, &body) ||
		!serviceapi.MatchingPathValue(response, request, "ingress_id", body.IngressId) {
		return
	}
	identity, ok := ingressLeaseIdentity(body.IngressId, body.IngressRunId, body.IngressLeaseRevision)
	routeVersion, routeOK := serviceapi.Positive(body.RouteVersion)
	if !ok || !routeOK || !serviceapi.ValidIdentifiers(body.RouteId) || body.ObservedAt.IsZero() {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Recovery observation identity is invalid")
		return
	}
	observation, err := h.store.ObserveRouteRecovery(
		request.Context(), identity, body.RouteId, routeVersion, episodeID, body.ObservedAt,
	)
	if err != nil {
		h.writeStoreError(response, err)
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, ingressv1.RouteRecoveryObservation{
		EpisodeId: int64(observation.EpisodeID), RouteId: observation.RouteID,
		RouteVersion: int64(observation.RouteVersion), OpenedAt: observation.OpenedAt,
		ObservedAt: observation.ObservedAt, ObservedSeconds: observation.ObservedSeconds,
	})
}

func (h *handler) ingressIdentityFromQuery(
	response http.ResponseWriter,
	request *http.Request,
) (controlstate.IngressLeaseIdentity, bool) {
	ingressID := request.PathValue("ingress_id")
	revision, err := strconv.ParseInt(request.URL.Query().Get("ingress_lease_revision"), 10, 64)
	if err != nil {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "ingress_lease_revision must be positive")
		return controlstate.IngressLeaseIdentity{}, false
	}
	identity, ok := ingressLeaseIdentity(ingressID, request.URL.Query().Get("ingress_run_id"), revision)
	if !ok {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Ingress lease identity is invalid")
		return controlstate.IngressLeaseIdentity{}, false
	}
	return identity, true
}

func (h *handler) writeStoreError(response http.ResponseWriter, err error) {
	status, kind, detail := storeProblem(err, h.report)
	serviceapi.WriteProblem(response, status, kind, detail)
}

// storeProblem is shared by HTTP and standalone adapters. Role controllers see
// API problems, never controlstate error identities.
func storeProblem(err error, report func(error)) (status int, kind, detail string) {
	switch {
	case errors.Is(err, controlstate.ErrIngressAlreadyRunning):
		return http.StatusConflict, "ingress_already_running", "Another process run holds the ingress lease"
	case errors.Is(err, controlstate.ErrIngressLeaseStale):
		return http.StatusConflict, "ingress_lease_stale", "The ingress lease is no longer current"
	case errors.Is(err, controlstate.ErrRouteRecoveryEpisodeStale):
		return http.StatusConflict, "recovery_episode_stale", "The route recovery episode is no longer current"
	case errors.Is(err, controlstate.ErrIngressUsageReportInvalid):
		return http.StatusBadRequest, "invalid_usage_report", "The ingress usage report is invalid"
	case errors.Is(err, controlstate.ErrIngressUsageRouteNotFound):
		return http.StatusNotFound, "usage_route_not_found", "The reported route version was not found"
	case errors.Is(err, controlstate.ErrIngressUsageReportStale):
		return http.StatusConflict, "stale_usage_report", "The ingress usage report revision is stale"
	case errors.Is(err, controlstate.ErrIngressUsageReportConflict):
		return http.StatusConflict, "usage_report_conflict", "The ingress usage report conflicts with stored state"
	case errors.Is(err, controlstate.ErrRouteUsageBucketFinalized):
		return http.StatusConflict, "usage_bucket_finalized", "The route usage bucket is already finalized"
	default:
		report(err)
		return http.StatusInternalServerError, "internal", "The ingress service request failed"
	}
}

func ingressLeaseIdentity(
	ingressID, ingressRunID string,
	ingressLeaseRevision int64,
) (controlstate.IngressLeaseIdentity, bool) {
	revision, ok := serviceapi.Positive(ingressLeaseRevision)
	if !ok || !serviceapi.ValidIdentifiers(ingressID, ingressRunID) {
		return controlstate.IngressLeaseIdentity{}, false
	}
	return controlstate.IngressLeaseIdentity{
		IngressID: ingressID, IngressRunID: ingressRunID, IngressLeaseRevision: revision,
	}, true
}

func ingressUsageBatch(value ingressv1.IngressUsageReportBatch) (controlstate.IngressUsageBatch, bool) {
	if len(value.Reports) > 256 || value.Complete && value.ObservedThrough == nil ||
		len(value.Reports) == 0 && value.ObservedThrough == nil ||
		value.ObservedThrough != nil && value.ObservedThrough.IsZero() {
		return controlstate.IngressUsageBatch{}, false
	}
	reports := make([]controlstate.IngressUsageReport, len(value.Reports))
	for index, report := range value.Reports {
		routeVersion, routeOK := serviceapi.Positive(report.RouteVersion)
		reportRevision, revisionOK := serviceapi.Positive(report.ReportRevision)
		connectionAttempts, attemptsOK := serviceapi.Nonnegative(report.ConnectionAttempts)
		policyDenials, policyOK := serviceapi.Nonnegative(report.PolicyDenials)
		capacityDenials, capacityOK := serviceapi.Nonnegative(report.CapacityDenials)
		publisherOpenFailures, failuresOK := serviceapi.Nonnegative(report.PublisherOpenFailures)
		successfulStreams, streamsOK := serviceapi.Nonnegative(report.SuccessfulStreams)
		connectionNanoseconds, nanosecondsOK := serviceapi.Nonnegative(report.ConnectionNanoseconds)
		ingressBytes, ingressOK := serviceapi.Nonnegative(report.IngressBytes)
		egressBytes, egressOK := serviceapi.Nonnegative(report.EgressBytes)
		if !serviceapi.ValidIdentifiers(report.RouteId) || !routeOK || !revisionOK ||
			!attemptsOK || !policyOK || !capacityOK || !failuresOK || !streamsOK ||
			!nanosecondsOK || !ingressOK || !egressOK || report.BucketStart.IsZero() ||
			!report.BucketEnd.After(report.BucketStart) || report.ObservedThrough.Before(report.BucketStart) ||
			report.ObservedThrough.After(report.BucketEnd) || value.Complete && !report.Final {
			return controlstate.IngressUsageBatch{}, false
		}
		reports[index] = controlstate.IngressUsageReport{
			RouteID: report.RouteId, RouteVersion: routeVersion, BucketStart: report.BucketStart,
			BucketEnd: report.BucketEnd, ObservedThrough: report.ObservedThrough, ReportRevision: reportRevision,
			ConnectionAttempts: connectionAttempts, PolicyDenials: policyDenials,
			CapacityDenials: capacityDenials, PublisherOpenFailures: publisherOpenFailures,
			SuccessfulStreams: successfulStreams, ConnectionNanoseconds: connectionNanoseconds,
			IngressBytes: ingressBytes, EgressBytes: egressBytes,
			HistogramData: report.HistogramData, Final: report.Final,
		}
	}
	return controlstate.IngressUsageBatch{
		Reports: reports, ObservedThrough: value.ObservedThrough, Complete: value.Complete,
	}, true
}

func ingressLease(lease controlstate.IngressLease) ingressv1.IngressLease {
	visitorNetworkHashKeys := make([]ingressv1.VisitorNetworkHashKey, len(lease.VisitorNetworkHashKeys))
	for index, key := range lease.VisitorNetworkHashKeys {
		visitorNetworkHashKeys[index] = ingressv1.VisitorNetworkHashKey{
			UtcDate: openapi_types.Date{Time: key.UTCDate}, Key: key.Key[:],
		}
	}
	return ingressv1.IngressLease{
		IngressId: lease.IngressID, IngressRunId: lease.IngressRunID,
		IngressLeaseRevision: int64(lease.IngressLeaseRevision), ProtocolVersion: int64(lease.ProtocolVersion),
		ConnectionCapacity: int64(lease.ConnectionCapacity), ReportedConnections: int64(lease.ReportedConnections),
		RoutingTableRevision: int64(lease.RoutingTableRevision), VisitorNetworkHashKeys: visitorNetworkHashKeys,
		Draining:      lease.Draining,
		DrainDeadline: lease.DrainDeadline, RegisteredAt: lease.RegisteredAt,
		RenewedAt: lease.RenewedAt, LeaseExpiresAt: lease.LeaseExpiresAt,
	}
}

func routingTableSnapshot(snapshot controlstate.IngressRoutingTableSnapshot) ingressv1.IngressRoutingTableSnapshot {
	entries := make([]ingressv1.IngressRoutingTableEvent, len(snapshot.Routes))
	for index, event := range snapshot.Routes {
		entries[index] = routingTableEvent(event)
	}
	return ingressv1.IngressRoutingTableSnapshot{
		ThroughRevision:       int64(snapshot.RoutingTableRevision),
		RetainedAfterRevision: int64(snapshot.RetainedAfterRevision), Entries: entries,
	}
}

func routingTablePage(page controlstate.IngressRoutingTablePage) ingressv1.IngressRoutingTablePage {
	events := make([]ingressv1.IngressRoutingTableEvent, len(page.Events))
	for index, event := range page.Events {
		events[index] = routingTableEvent(event)
	}
	return ingressv1.IngressRoutingTablePage{
		ThroughRevision: int64(page.ThroughRevision), RetainedAfterRevision: int64(page.RetainedAfterRevision),
		NextRevision: int64(page.NextRevision), More: page.More, Events: events,
	}
}

func routingTableEvent(event controlstate.IngressRoutingTableEvent) ingressv1.IngressRoutingTableEvent {
	return ingressv1.IngressRoutingTableEvent{
		RoutingTableRevision: int64(event.RoutingTableRevision), Kind: ingressv1.IngressRoutingTableEventKind(event.Kind),
		RouteId: event.RouteID, RouteVersion: int64(event.RouteVersion), CanonicalHostname: event.CanonicalHostname,
		EntryRevision: int64(event.EntryRevision), Entry: routingTableEntry(event.Projection),
		RouteExpiresAt: event.RouteExpiresAt, CreatedAt: event.CreatedAt,
	}
}

func routingTableEntry(projection controlstate.IngressRoutingTableProjection) ingressv1.IngressRoutingTableEntry {
	prefixes := make([]string, len(projection.AllowedIPPrefixes))
	for index, prefix := range projection.AllowedIPPrefixes {
		prefixes[index] = prefix.String()
	}
	connections := make([]ingressv1.IngressRoutingPublisherConnection, len(projection.PublisherConnections))
	for index, connection := range projection.PublisherConnections {
		connections[index] = ingressv1.IngressRoutingPublisherConnection{
			ConnectionSlot: connection.ConnectionSlot, PublisherConnectionId: connection.PublisherConnectionID,
			ConnectionAssignmentRevision: int64(connection.ConnectionAssignmentRevision),
			RelayServiceId:               connection.RelayServiceID, RelayId: connection.RelayID,
			RelayRunId: connection.RelayRunID, RelayLeaseRevision: int64(connection.RelayLeaseRevision),
			InternalRelayAddress: connection.InternalRelayAddress, TlsServerName: connection.TLSServerName,
			LeaseExpiresAt: connection.LeaseExpiresAt,
		}
	}
	var recoveryEpisodeID *int64
	if projection.RecoveryEpisodeID != nil {
		value := int64(*projection.RecoveryEpisodeID)
		recoveryEpisodeID = &value
	}
	return ingressv1.IngressRoutingTableEntry{
		RouteSessionId: projection.RouteSessionID, RouteId: projection.RouteID,
		RouteVersion: int64(projection.RouteVersion), CanonicalHostname: projection.CanonicalHostname,
		PolicyRevision:    int64(projection.PolicyRevision),
		IpPolicy:          ingressv1.IngressRoutingTableEntryIpPolicy(projection.IPPolicy),
		AllowedIpPrefixes: prefixes, RouteExpiresAt: projection.RouteExpiresAt,
		RecoveryEpisodeId: recoveryEpisodeID, PublisherConnections: connections,
	}
}

func queryInteger(request *http.Request, name string, defaultValue, minimum, maximum int) (int, bool) {
	value := request.URL.Query().Get(name)
	if value == "" {
		return defaultValue, true
	}
	parsed, err := strconv.Atoi(value)
	return parsed, err == nil && parsed >= minimum && parsed <= maximum
}

func queryWholeSecondDuration(
	request *http.Request,
	name string,
	defaultValue, maximum time.Duration,
) (time.Duration, bool) {
	value := request.URL.Query().Get(name)
	if value == "" {
		return defaultValue, true
	}
	parsed, err := time.ParseDuration(value)
	return parsed, err == nil && parsed >= 0 && parsed <= maximum && parsed%time.Second == 0
}
