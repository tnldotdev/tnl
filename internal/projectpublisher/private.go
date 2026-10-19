package projectpublisher

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/targettransport"
)

func (w *Workers) runPrivate(ctx context.Context, service clientruntime.Service, configuration Configuration, observe func(uint64, bool) error) error {
	var entry *proofEntry
	defer func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.proofs[service.RegistrationID] == entry {
			delete(w.proofs, service.RegistrationID)
		}
	}()
	return configuration.RunPrivate(ctx, func(run uint64, routable bool) error {
		if run == 0 || ctx.Err() != nil || !w.Manager.Current(service.Name, service.RegistrationID, service.Target, 0) {
			return clientruntime.ErrRegistrationStale
		}
		if err := observe(run, routable); err != nil {
			return err
		}
		entry = &proofEntry{service: service, run: publisher.PublishRunIdentity{Number: run}, privateCheck: configuration.CheckPrivate}
		w.mu.Lock()
		if w.proofs == nil {
			w.proofs = map[string]*proofEntry{}
		}
		w.proofs[service.RegistrationID] = entry
		w.mu.Unlock()
		return nil
	})
}

// ProbePrivateTarget checks the actual local target for a ready private run.
// it does not claim a public visitor proof or require a public hostname.
func ProbePrivateTarget(ctx context.Context, service clientruntime.Service, target targettransport.Transport) clientruntime.Observation {
	observation := clientruntime.Observation{Target: service.Target, RegistrationID: service.RegistrationID, PublishRunNumber: service.PublishRunNumber, Readiness: service.Readiness, CheckedAt: time.Now().UTC(), Reason: "runtime.probe_failed"}
	protocol := config.ProtocolName(service.ServiceProtocol)
	if protocol == "" {
		protocol = config.ProtocolHTTP
	}
	if protocol != target.Protocol || target.Validate() != nil {
		return observation
	}
	if service.ServiceProtocol == "http" || service.ServiceProtocol == "" {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = target.TLS
		defer transport.CloseIdleConnections()
		local := service
		{
			origin, err := url.Parse(local.Target)
			if err != nil || origin.Host == "" {
				return observation
			}
			origin.Scheme = "http"
			if target.TLS != nil {
				origin.Scheme = "https"
			}
			local.Target = origin.String()
		}
		local.PublicURL = local.Target
		return clientruntime.Probe(ctx, local, transport)
	}
	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	address := service.Target
	if origin, err := url.Parse(address); err == nil && origin.Host != "" {
		address = origin.Host
	}
	if err := target.Preflight(probe, address); err == nil {
		observation.Ready, observation.Reason = true, ""
	}
	return observation
}
