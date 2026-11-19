package ingress

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
	"github.com/tnldotdev/tnl/internal/region"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

type service struct {
	store         Store
	leaseDuration time.Duration
	now           func() time.Time
	report        func(error)
}

func newService(config DirectConfig) (*service, error) {
	if config.Store == nil || config.LeaseDuration <= 0 {
		return nil, errors.New("ingressapi: store and lease duration are required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Report == nil {
		config.Report = func(err error) { operatorlog.Report("serve ingress API", failure.ServerAPIInternal, "", err) }
	}
	return &service{
		store: config.Store, leaseDuration: config.LeaseDuration,
		now: config.Now, report: config.Report,
	}, nil
}

func (s *service) RegisterIngress(ctx context.Context, body ingressv1.IngressRegistration) (ingressv1.IngressLease, error) {
	if !region.ID(body.Region).Valid() {
		return ingressv1.IngressLease{}, serverhttp.NewProblemError(http.StatusBadRequest, "invalid_request", "ingress region must be an exact catalog provider:region ID or local")
	}
	if !serverhttp.ValidIdentifiers(body.IngressPoolId) || body.ServicePorts == nil || !tcpport.ValidServicePorts(body.ServicePorts) {
		return ingressv1.IngressLease{}, serverhttp.NewProblemError(http.StatusBadRequest, "invalid_request", "ingress service port inventory is invalid")
	}
	if !serverhttp.ValidIdentifiers(body.IngressId, body.IngressRunId) {
		return ingressv1.IngressLease{}, serverhttp.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Ingress registration identifiers are invalid",
		)
	}
	protocolVersion, protocolOK := serverhttp.Positive(body.ProtocolVersion)
	connectionCapacity, capacityOK := serverhttp.Positive(body.ConnectionCapacity)
	if !protocolOK || !capacityOK {
		return ingressv1.IngressLease{}, serverhttp.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Ingress protocol and connection capacity must be positive",
		)
	}
	lease, err := s.store.RegisterIngress(ctx, controlstate.IngressRegistration{
		Region:    region.ID(body.Region),
		IngressID: body.IngressId, IngressRunID: body.IngressRunId,
		ProtocolVersion: protocolVersion, ConnectionCapacity: connectionCapacity,
		IngressPoolID: body.IngressPoolId, HTTPS: body.Https, ServicePorts: servicePorts(body.ServicePorts),
	}, s.now(), s.leaseDuration)
	if err != nil {
		return ingressv1.IngressLease{}, s.storeError(ctx, err)
	}
	return ingressLease(lease), nil
}

func servicePorts(values []int) []int32 {
	result := make([]int32, len(values))
	for index, port := range values {
		result[index] = int32(port)
	}
	return result
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
	reportedConnections, connectionsOK := serverhttp.Nonnegative(body.ReportedConnections)
	if !ok || !connectionsOK {
		return ingressv1.IngressLease{}, serverhttp.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Ingress renewal identity or counters are invalid",
		)
	}
	lease, err := s.store.RenewIngress(ctx, controlstate.IngressRenewal{
		IngressLeaseIdentity: identity, ReportedConnections: reportedConnections,
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
		return ingressv1.IngressLease{}, serverhttp.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Ingress drain identity or deadline is invalid",
		)
	}
	lease, err := s.store.BeginIngressDrain(ctx, identity, s.now(), body.Deadline)
	if err != nil {
		return ingressv1.IngressLease{}, s.storeError(ctx, err)
	}
	return ingressLease(lease), nil
}

func (s *service) ObserveServiceRecovery(
	ctx context.Context,
	ingressID ingressv1.IngressID,
	recoveryEpisodeID int64,
	body ingressv1.ServiceRecoveryObservationRequest,
) (ingressv1.ServiceRecoveryObservation, error) {
	if ingressID != body.IngressId {
		return ingressv1.ServiceRecoveryObservation{}, pathMismatchError()
	}
	identity, ok := ingressLeaseIdentity(body.IngressId, body.IngressRunId, body.IngressLeaseRevision)
	episode, episodeOK := serverhttp.Positive(recoveryEpisodeID)
	if !ok || !episodeOK || body.RunNumber <= 0 || !opaqueid.Valid(body.ServiceId, opaqueid.ServicePrefix) ||
		!opaqueid.Valid(body.ServiceRunId, opaqueid.ServiceRunPrefix) || !opaqueid.Valid(body.VisitorConnectionId, opaqueid.VisitorConnectionPrefix) || body.ObservedAt.IsZero() || len(body.SourceEvidence) > 2048 {
		return ingressv1.ServiceRecoveryObservation{}, serverhttp.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Recovery observation identity is invalid",
		)
	}
	observation, err := s.store.ObserveServiceRecovery(
		ctx, identity, controlstate.ServiceRunReference{ServiceID: body.ServiceId, RunID: body.ServiceRunId, RunNumber: body.RunNumber},
		body.VisitorConnectionId, episode, body.ObservedAt, body.SourceEvidence, s.now(),
	)
	if err != nil {
		return ingressv1.ServiceRecoveryObservation{}, s.storeError(ctx, err)
	}
	return ingressv1.ServiceRecoveryObservation{
		RecoveryEpisodeId: int64(observation.RecoveryEpisodeID), ServiceId: observation.ServiceID, ServiceRunId: observation.RunID,
		RunNumber: observation.RunNumber, OpenedAt: observation.OpenedAt,
		ObservedAt: observation.ObservedAt, ObservedSeconds: observation.ObservedSeconds,
	}, nil
}

func (s *service) storeError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	status, kind, detail := storeProblem(err, s.report)
	return serverhttp.NewProblemError(status, kind, detail)
}

func pathMismatchError() error {
	return serverhttp.NewProblemError(
		http.StatusBadRequest, "invalid_request", "Path and request body identifiers do not match",
	)
}
