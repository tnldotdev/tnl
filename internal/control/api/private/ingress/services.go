package ingress

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (s *service) ReadIngressServices(ctx context.Context, id string, body ingressv1.IngressLeaseIdentity) (ingressv1.IngressServices, error) {
	var result ingressv1.IngressServices
	identity, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	if !ok || body.IngressId != id {
		return result, serverhttp.NewProblemError(http.StatusBadRequest, "invalid_request", "invalid ingress lease")
	}
	current, err := s.store.ReadIngressServices(ctx, identity, s.now())
	if err != nil {
		return result, s.privateStateError(ctx, err)
	}
	result.ObservedAt, result.ValidUntil = current.ObservedAt, current.ValidUntil
	result.Runs = make([]ingressv1.IngressServiceRun, 0, len(current.Runs))
	for _, run := range current.Runs {
		result.Runs = append(result.Runs, ingressv1.IngressServiceRun{
			ServiceId: run.ServiceID, ServiceRunId: run.RunID, RunNumber: run.RunNumber,
			Protocol: controlv1.ServiceProtocol(run.Protocol), Hostname: run.Hostname, Port: run.Port,
			RunHostname:      run.RunHostname,
			AliasDnsUntil:    run.AliasDNSUntil,
			EndpointRevision: run.EndpointRevision, ValidUntil: run.ValidUntil, Anonymous: run.Anonymous,
			Ip: run.IP, Traffic: ingressTraffic(run.Traffic), ConnectedRelays: privateRelayResponses(run.Relays),
			SourceAuthority: run.SourceAuthority, SourceKey: run.SourceKey,
			RecoveryEpisodeId: run.RecoveryEpisodeID,
		})
	}
	return result, nil
}

func (s generatedServer) ReadIngressServices(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID) {
	var body ingressv1.IngressLeaseIdentity
	if !serverhttp.DecodeJSON(w, r, &body) {
		return
	}
	result, err := s.handler.service.ReadIngressServices(r.Context(), id, body)
	if !s.handler.writeServiceError(w, r, err) {
		serverhttp.WriteJSON(w, http.StatusOK, result)
	}
}

func ingressTraffic(limits trafficlimits.Limits) ingressv1.IngressTrafficLimits {
	result := ingressv1.IngressTrafficLimits{
		Connections: limits.Connections, Rate: limits.Rate, RatePerNs: int64(limits.Period()), Burst: limits.Burst,
		UploadBytes: limits.UploadBytes, DownloadBytes: limits.DownloadBytes,
	}
	if limits.TotalConnections > 0 {
		result.TotalConnections = &limits.TotalConnections
	}
	if limits.TotalUploadBytes > 0 {
		result.TotalUploadBytes = &limits.TotalUploadBytes
	}
	if limits.TotalDownloadBytes > 0 {
		result.TotalDownloadBytes = &limits.TotalDownloadBytes
	}
	return result
}
