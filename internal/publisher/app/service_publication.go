package app

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
)

func (w *Workers) runService(ctx context.Context, service Service, publication *ServicePublication, journal *publicationJournal, observe func(PublicationUpdate) error) error {
	var entry *readinessEntry
	var observations sync.Mutex
	var stopReadiness func()
	defer func() {
		if stopReadiness != nil {
			stopReadiness()
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.checks[service.RegistrationID] == entry {
			delete(w.checks, service.RegistrationID)
		}
	}()
	record := SummaryObservation(journal.recorder)
	return publication.Run(ctx, journal.tunnel, func(run uint64, routable bool) error {
		// serialize the owning operation's callbacks so a late older run cannot
		// change the local journal before the manager rejects its observation.
		observations.Lock()
		defer observations.Unlock()
		if run == 0 || ctx.Err() != nil || !w.Manager.CurrentRegistration(service.Name, service.RegistrationID, service.Target) {
			return ErrRegistrationStale
		}
		if entry != nil && run < entry.run {
			return ErrRegistrationStale
		}
		newRun := entry == nil || run != entry.run
		if stopReadiness != nil && (!routable || newRun) {
			stopReadiness()
		}
		if routable {
			if err := journal.tunnel.SetReady(ctx, publication.URL, run); err != nil {
				return err
			}
		} else if err := journal.tunnel.SetProvisioning(ctx, run); err != nil {
			return err
		}
		if err := observe(PublicationUpdate{RunNumber: run, Routable: routable, TunnelID: journal.tunnel.ID(), Target: service.Target, PublicURL: publication.URL}); err != nil {
			return err
		}
		if newRun {
			entry = &readinessEntry{target: service.Target, run: run, check: publication.Check}
			w.mu.Lock()
			if w.checks == nil {
				w.checks = map[string]*readinessEntry{}
			}
			w.checks[service.RegistrationID] = entry
			w.mu.Unlock()
			stopReadiness = nil
		}
		// retain a stopped check until the run changes: repeated readiness or
		// recovery of this same run must not grant another automatic budget.
		if w.AutomaticReadiness && routable && stopReadiness == nil {
			stopReadiness = w.startReadiness(ctx, service, run)
		}
		return nil
	}, func(summary inspection.Summary) {
		if record != nil {
			record(summary)
		}
	})
}

// ProbeServiceTarget checks the actual local target independently of ingress.
// it does not claim a public visitor proof or require a public hostname.
func ProbeServiceTarget(ctx context.Context, service Service, target targettransport.Transport) Observation {
	observation := Observation{Target: service.Target, RegistrationID: service.RegistrationID, RunNumber: service.RunNumber, Readiness: service.Readiness, CheckedAt: time.Now().UTC(), Reason: "runtime.probe_failed"}
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
		return Probe(ctx, local, transport)
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
