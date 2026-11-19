// Package ingressapi serves control's private API for ingress processes.
package ingress

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

type Store interface {
	publicServiceStore
	serviceAuditStore
	RegisterIngress(context.Context, controlstate.IngressRegistration, time.Time, time.Duration) (controlstate.IngressLease, error)
	RenewIngress(context.Context, controlstate.IngressRenewal, time.Time, time.Duration) (controlstate.IngressLease, error)
	BeginIngressDrain(context.Context, controlstate.IngressLeaseIdentity, time.Time, time.Time) (controlstate.IngressLease, error)
	ObserveServiceRecovery(context.Context, controlstate.IngressLeaseIdentity, controlstate.ServiceRunReference, string, uint64, time.Time, []byte, time.Time) (controlstate.ServiceRecoveryObservation, error)
}

type Config struct {
	Store          Store
	ClusterSecrets serverhttp.BearerSecrets
	LeaseDuration  time.Duration
	Now            func() time.Time
	Report         func(error)
}

type handler struct {
	service        *service
	clusterSecrets serverhttp.BearerSecrets
	mux            *http.ServeMux
}

// NewHandler constructs the private ingress service.
func NewHandler(config Config) (*handler, error) {
	if config.Store == nil || !config.ClusterSecrets.Valid() {
		return nil, errors.New("ingressapi: store and cluster secrets are required")
	}
	if config.LeaseDuration <= 0 {
		return nil, errors.New("ingressapi: ingress lease duration must be positive")
	}
	service, err := newService(DirectConfig{
		Store: config.Store, LeaseDuration: config.LeaseDuration,
		Now: config.Now, Report: config.Report,
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
			serverhttp.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Ingress request parameters are invalid", "")
		},
	})
	h.mux.HandleFunc("/", func(response http.ResponseWriter, _ *http.Request) {
		serverhttp.WriteProblem(response, http.StatusNotFound, "not_found", "Ingress service endpoint not found", "")
	})
	return h, nil
}

func (h *handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if !serverhttp.AuthenticateClusterRequest(response, request, h.clusterSecrets) {
		return
	}
	h.mux.ServeHTTP(response, request)
}

// MatchedPattern is safe to call before authentication; it never returns an ID.
func (h *handler) MatchedPattern(request *http.Request) string {
	_, pattern := h.mux.Handler(request)
	return pattern
}

// the full sorted port inventory takes about 370 KiB in compact JSON.
const registrationRequestBytes = 512 << 10

func (h *handler) registerIngress(response http.ResponseWriter, request *http.Request) {
	var body ingressv1.IngressRegistration
	if !serverhttp.DecodeJSONLimited(response, request, &body, registrationRequestBytes) {
		return
	}
	lease, err := h.service.RegisterIngress(request.Context(), body)
	if h.writeServiceError(response, request, err) {
		return
	}
	serverhttp.WriteJSON(response, http.StatusOK, lease)
}

func (h *handler) renewIngress(response http.ResponseWriter, request *http.Request, ingressID ingressv1.IngressID) {
	var body ingressv1.IngressRenewal
	if !serverhttp.DecodeJSON(response, request, &body) {
		return
	}
	lease, err := h.service.RenewIngress(request.Context(), ingressID, body)
	if h.writeServiceError(response, request, err) {
		return
	}
	serverhttp.WriteJSON(response, http.StatusOK, lease)
}

func (h *handler) drainIngress(response http.ResponseWriter, request *http.Request, ingressID ingressv1.IngressID) {
	var body ingressv1.IngressDrainRequest
	if !serverhttp.DecodeJSON(response, request, &body) {
		return
	}
	lease, err := h.service.DrainIngress(request.Context(), ingressID, body)
	if h.writeServiceError(response, request, err) {
		return
	}
	serverhttp.WriteJSON(response, http.StatusOK, lease)
}

func (h *handler) observeRecovery(
	response http.ResponseWriter,
	request *http.Request,
	ingressID ingressv1.IngressID,
	recoveryEpisodeID int64,
) {
	var body ingressv1.ServiceRecoveryObservationRequest
	if !serverhttp.DecodeJSON(response, request, &body) {
		return
	}
	observation, err := h.service.ObserveServiceRecovery(request.Context(), ingressID, recoveryEpisodeID, body)
	if h.writeServiceError(response, request, err) {
		return
	}
	serverhttp.WriteJSON(response, http.StatusOK, observation)
}

func (h *handler) writeServiceError(response http.ResponseWriter, request *http.Request, err error) bool {
	if err != nil {
		var problem *serverhttp.ProblemError
		if !errors.As(err, &problem) {
			err = h.service.privateStateError(request.Context(), err)
		}
	}
	return serverhttp.WriteError(response, request, err, h.service.report, "The ingress service request failed")
}

// storeProblem is shared by HTTP and standalone adapters. role controllers see
// API problems, never controlstate error identities.
func storeProblem(err error, report func(error)) (status int, kind, detail string) {
	switch {
	case errors.Is(err, controlstate.ErrIngressAlreadyRunning):
		return http.StatusConflict, "ingress_already_running", "Another process run holds the ingress lease"
	case errors.Is(err, controlstate.ErrIngressLeaseStale):
		return http.StatusConflict, "ingress_lease_stale", "The ingress lease is no longer current"
	case errors.Is(err, controlstate.ErrServiceRecoveryEpisodeStale):
		return http.StatusConflict, "recovery_episode_stale", "The service recovery episode is no longer current"
	default:
		report(err)
		return http.StatusInternalServerError, "internal", "The ingress service request failed"
	}
}

func ingressLeaseIdentity(
	ingressID, ingressRunID string,
	ingressLeaseRevision int64,
) (controlstate.IngressLeaseIdentity, bool) {
	revision, ok := serverhttp.Positive(ingressLeaseRevision)
	if !ok || !serverhttp.ValidIdentifiers(ingressID, ingressRunID) {
		return controlstate.IngressLeaseIdentity{}, false
	}
	return controlstate.IngressLeaseIdentity{
		IngressID: ingressID, IngressRunID: ingressRunID, IngressLeaseRevision: revision,
	}, true
}

func ingressLease(lease controlstate.IngressLease) ingressv1.IngressLease {
	return ingressv1.IngressLease{
		Region:    string(lease.Region),
		IngressId: lease.IngressID, IngressRunId: lease.IngressRunID,
		IngressLeaseRevision: int64(lease.IngressLeaseRevision), ProtocolVersion: int64(lease.ProtocolVersion),
		ConnectionCapacity: int64(lease.ConnectionCapacity), ReportedConnections: int64(lease.ReportedConnections),
		Draining:      lease.Draining,
		DrainDeadline: lease.DrainDeadline, RegisteredAt: lease.RegisteredAt,
		RenewedAt: lease.RenewedAt, LeaseExpiresAt: lease.LeaseExpiresAt, ServingUntil: lease.ServingUntil,
	}
}
