// Package ingressapi serves control's private API for ingress processes.
package ingressapi

import (
	"context"
	"errors"
	"net/http"
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
	ObservePublicURLRecovery(context.Context, controlstate.IngressLeaseIdentity, string, uint64, uint64, time.Time) (controlstate.PublicURLRecoveryObservation, error)
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
	service        *service
	clusterSecrets serviceapi.BearerSecrets
	mux            *http.ServeMux
}

// NewHandler constructs the private ingress service.
func NewHandler(config Config) (http.Handler, error) {
	if config.Store == nil || !config.ClusterSecrets.Valid() {
		return nil, errors.New("ingressapi: store and cluster secrets are required")
	}
	if config.LeaseDuration <= 0 {
		return nil, errors.New("ingressapi: ingress lease duration must be positive")
	}
	service, err := newService(DirectConfig{
		Store: config.Store, LeaseDuration: config.LeaseDuration,
		RoutingPollInterval: config.RoutingPollInterval, Now: config.Now, Report: config.Report,
	})
	if err != nil {
		return nil, err
	}
	h := &handler{
		service: service, clusterSecrets: config.ClusterSecrets, mux: http.NewServeMux(),
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
	if !serviceapi.AuthenticateClusterRequest(response, request, h.clusterSecrets) {
		return
	}
	h.mux.ServeHTTP(response, request)
}

// MatchedPattern is safe to call before authentication; it never returns an ID.
func (h *handler) MatchedPattern(request *http.Request) string {
	_, pattern := h.mux.Handler(request)
	return pattern
}

func (h *handler) registerIngress(response http.ResponseWriter, request *http.Request) {
	var body ingressv1.IngressRegistration
	if !serviceapi.DecodeJSON(response, request, &body) {
		return
	}
	lease, err := h.service.RegisterIngress(request.Context(), body)
	if h.writeServiceError(response, request, err) {
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, lease)
}

func (h *handler) renewIngress(response http.ResponseWriter, request *http.Request, ingressID ingressv1.IngressID) {
	var body ingressv1.IngressRenewal
	if !serviceapi.DecodeJSON(response, request, &body) {
		return
	}
	lease, err := h.service.RenewIngress(request.Context(), ingressID, body)
	if h.writeServiceError(response, request, err) {
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, lease)
}

func (h *handler) drainIngress(response http.ResponseWriter, request *http.Request, ingressID ingressv1.IngressID) {
	var body ingressv1.IngressDrainRequest
	if !serviceapi.DecodeJSON(response, request, &body) {
		return
	}
	lease, err := h.service.DrainIngress(request.Context(), ingressID, body)
	if h.writeServiceError(response, request, err) {
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, lease)
}

func (h *handler) routingTableSnapshot(
	response http.ResponseWriter,
	request *http.Request,
	ingressID ingressv1.IngressID,
	params ingressv1.GetIngressRoutingTableSnapshotParams,
) {
	snapshot, err := h.service.GetIngressRoutingTableSnapshot(request.Context(), ingressID, params)
	if h.writeServiceError(response, request, err) {
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, snapshot)
}

func (h *handler) routingTableEvents(
	response http.ResponseWriter,
	request *http.Request,
	ingressID ingressv1.IngressID,
	params ingressv1.GetIngressRoutingTableEventsParams,
) {
	page, err := h.service.GetIngressRoutingTableEvents(request.Context(), ingressID, params)
	if h.writeServiceError(response, request, err) {
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, page)
}

func (h *handler) reportUsage(response http.ResponseWriter, request *http.Request, ingressID ingressv1.IngressID) {
	var body ingressv1.IngressUsageReportBatch
	if !serviceapi.DecodeJSON(response, request, &body) {
		return
	}
	if h.writeServiceError(response, request, h.service.ReportIngressUsage(request.Context(), ingressID, body)) {
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *handler) observeRecovery(
	response http.ResponseWriter,
	request *http.Request,
	ingressID ingressv1.IngressID,
	recoveryEpisodeID int64,
) {
	var body ingressv1.PublicURLRecoveryObservationRequest
	if !serviceapi.DecodeJSON(response, request, &body) {
		return
	}
	observation, err := h.service.ObservePublicURLRecovery(request.Context(), ingressID, recoveryEpisodeID, body)
	if h.writeServiceError(response, request, err) {
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, observation)
}

func (h *handler) writeServiceError(response http.ResponseWriter, request *http.Request, err error) bool {
	return serviceapi.WriteServiceError(response, request, err, h.service.report, "The ingress service request failed")
}

// storeProblem is shared by HTTP and standalone adapters. Role controllers see
// API problems, never controlstate error identities.
func storeProblem(err error, report func(error)) (status int, kind, detail string) {
	switch {
	case errors.Is(err, controlstate.ErrIngressAlreadyRunning):
		return http.StatusConflict, "ingress_already_running", "Another process run holds the ingress lease"
	case errors.Is(err, controlstate.ErrIngressLeaseStale):
		return http.StatusConflict, "ingress_lease_stale", "The ingress lease is no longer current"
	case errors.Is(err, controlstate.ErrPublicURLRecoveryEpisodeStale):
		return http.StatusConflict, "recovery_episode_stale", "The public URL recovery episode is no longer current"
	case errors.Is(err, controlstate.ErrIngressUsageReportInvalid):
		return http.StatusBadRequest, "invalid_usage_report", "The ingress usage report is invalid"
	case errors.Is(err, controlstate.ErrIngressUsagePublicURLNotFound):
		return http.StatusNotFound, "usage_route_not_found", "The reported publish run number was not found"
	case errors.Is(err, controlstate.ErrIngressUsageReportStale):
		return http.StatusConflict, "stale_usage_report", "The ingress usage report revision is stale"
	case errors.Is(err, controlstate.ErrIngressUsageReportConflict):
		return http.StatusConflict, "usage_report_conflict", "The ingress usage report conflicts with stored state"
	case errors.Is(err, controlstate.ErrPublicURLUsageBucketFinalized):
		return http.StatusConflict, "usage_bucket_finalized", "The public URL usage bucket is already finalized"
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
		publishRunNumber, routeOK := serviceapi.Positive(report.PublishRunNumber)
		reportRevision, revisionOK := serviceapi.Positive(report.ReportRevision)
		connectionAttempts, attemptsOK := serviceapi.Nonnegative(report.ConnectionAttempts)
		policyDenials, policyOK := serviceapi.Nonnegative(report.PolicyDenials)
		capacityDenials, capacityOK := serviceapi.Nonnegative(report.CapacityDenials)
		visitorStreamOpenFailures, failuresOK := serviceapi.Nonnegative(report.VisitorStreamOpenFailures)
		successfulStreams, streamsOK := serviceapi.Nonnegative(report.SuccessfulStreams)
		connectionNanoseconds, nanosecondsOK := serviceapi.Nonnegative(report.ConnectionNanoseconds)
		ingressBytes, ingressOK := serviceapi.Nonnegative(report.IngressBytes)
		egressBytes, egressOK := serviceapi.Nonnegative(report.EgressBytes)
		if !serviceapi.ValidIdentifiers(report.PublicUrlId) || !routeOK || !revisionOK ||
			!attemptsOK || !policyOK || !capacityOK || !failuresOK || !streamsOK ||
			!nanosecondsOK || !ingressOK || !egressOK || report.BucketStart.IsZero() ||
			!report.BucketEnd.After(report.BucketStart) || report.ObservedThrough.Before(report.BucketStart) ||
			report.ObservedThrough.After(report.BucketEnd) || value.Complete && !report.Final {
			return controlstate.IngressUsageBatch{}, false
		}
		reports[index] = controlstate.IngressUsageReport{
			PublicURLID: report.PublicUrlId, PublishRunNumber: publishRunNumber, BucketStart: report.BucketStart,
			BucketEnd: report.BucketEnd, ObservedThrough: report.ObservedThrough, ReportRevision: reportRevision,
			ConnectionAttempts: connectionAttempts, PolicyDenials: policyDenials,
			CapacityDenials: capacityDenials, VisitorStreamOpenFailures: visitorStreamOpenFailures,
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
	entries := make([]ingressv1.IngressRoutingTableEvent, len(snapshot.Entries))
	for index, event := range snapshot.Entries {
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
		PublicUrlId: event.PublicURLID, PublishRunNumber: int64(event.PublishRunNumber), CanonicalHostname: event.CanonicalHostname,
		EntryRevision: int64(event.EntryRevision), Entry: routingTableEntry(event.Projection),
		PublicUrlExpiresAt: event.PublicUrlExpiresAt, CreatedAt: event.CreatedAt,
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
		PublishRunId: projection.PublishRunID, PublicUrlId: projection.PublicURLID,
		PublishRunNumber: int64(projection.PublishRunNumber), CanonicalHostname: projection.CanonicalHostname,
		PolicyRevision:    int64(projection.PolicyRevision),
		IpPolicy:          ingressv1.IngressRoutingTableEntryIpPolicy(projection.IPPolicy),
		AllowedIpPrefixes: prefixes, PublicUrlExpiresAt: projection.PublicUrlExpiresAt,
		RecoveryEpisodeId: recoveryEpisodeID, PublisherConnections: connections,
	}
}
