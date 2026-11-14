package app

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	telemetryv1 "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

type Configuration struct {
	Service          *ServicePublication
	Publisher        publisher.Config
	Inspection       inspection.Policy
	PrimaryRoot      string
	SharedRoot       string
	IntegrationScope clientstate.IntegrationScope
	TargetBinding    *target.TargetBinding
	// cleanup owns resources allocated before the worker starts, including when
	// target capture or local tunnel creation fails. it runs after drain/join.
	Cleanup func() error
	Attach  func(context.Context, *clientstate.Tunnel, *publisher.Config) (func(), error)
}

// ServicePublication supplies an operation, not another publisher engine. the
// worker owns local journaling and inspection until the operation joins its work.
type ServicePublication struct {
	Options clientstate.BeginTunnelOptions
	URL     string
	Run     func(context.Context, func(uint64, bool) error, inspection.Observer) error
	Check   func(context.Context, Service) Observation
}

type publicationJournal struct {
	tunnel   *clientstate.Tunnel
	recorder *clientstate.InspectionRecorder
}

// the caller finalizes a non-nil journal even when binding fails, so cleanup
// errors and the original operation failure share one terminal observation.
func (w *Workers) beginPublication(ctx context.Context, service Service, cfg Configuration, options clientstate.BeginTunnelOptions) (*publicationJournal, error) {
	if options.Target != service.Target {
		return nil, ErrRegistrationStale
	}
	tunnel, err := w.Database.BeginTunnel(ctx, options)
	if err != nil {
		return nil, err
	}
	journal := &publicationJournal{tunnel: tunnel}
	if err := w.Manager.BindTunnel(service.Name, service.RegistrationID, service.Target, tunnel.ID()); err != nil {
		return journal, err
	}
	if cfg.PrimaryRoot == "" {
		cfg.PrimaryRoot = options.Project
	}
	if cfg.SharedRoot == "" {
		cfg.SharedRoot = cfg.PrimaryRoot
	}
	if cfg.Inspection.Mode == inspection.SummaryMode {
		journal.recorder = tunnel.NewInspectionRecorder(cfg.PrimaryRoot, options.Project, cfg.SharedRoot, service.Name, cfg.Inspection)
	}
	return journal, nil
}

func (j *publicationJournal) close(result error, cleanup func() error) error {
	j.recorder.Close()
	if cleanup != nil {
		result = errors.Join(result, cleanup())
	}
	finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return errors.Join(result, j.tunnel.Finish(finish, result))
}

type proofEntry struct {
	service      Service
	run          publisher.PublishRunIdentity
	proof        *httpaccess.ReadinessProof
	target       *target.TargetBinding
	check        sync.Mutex
	serviceCheck func(context.Context, Service) Observation
}

type Workers struct {
	Database           *clientstate.Database
	Manager            *Manager
	Configure          func(context.Context, Service) (Configuration, error)
	RunPublisher       func(context.Context, publisher.Config) error
	HTTPTransport      http.RoundTripper
	AutomaticReadiness bool
	// zero values use the public readiness retry policy; tests can shorten time.
	readinessBudget time.Duration
	readinessDelay  func(int) time.Duration
	acceptReadiness func(Observation) bool
	mu              sync.Mutex
	proofs          map[string]*proofEntry
}

func (w *Workers) Run(ctx context.Context, service Service, observe func(uint64, bool) error) (result error) {
	configuration, err := w.Configure(ctx, service)
	if err != nil {
		return err
	}
	var journal *publicationJournal
	defer func() {
		if journal != nil {
			// operation and attachment workers have joined before recorder drain.
			// include independent configuration cleanup failures in the terminal row.
			result = journal.close(result, configuration.Cleanup)
		} else if configuration.Cleanup != nil {
			result = errors.Join(result, configuration.Cleanup())
		}
	}()
	if configuration.Service != nil {
		publication := configuration.Service
		if publication.Run == nil || publication.Check == nil {
			return ErrRegistrationStale
		}
		journal, err = w.beginPublication(ctx, service, configuration, publication.Options)
		if err != nil {
			return err
		}
		return w.runService(journal.tunnel.Context(), service, publication, journal, observe)
	}
	cfg := configuration.Publisher
	if service.Framework != "" {
		cfg.TelemetryFramework = telemetryv1.PublicationReadyFramework(service.Framework)
		if !cfg.TelemetryFramework.Valid() {
			cfg.TelemetryFramework = telemetryv1.PublicationReadyFrameworkOther
		}
	}
	var captured target.TargetSnapshot
	if configuration.TargetBinding != nil {
		previous := configuration.TargetBinding.Changed
		configuration.TargetBinding.Changed = func() {
			w.Manager.TargetChanged(service.Name, service.RegistrationID, service.Target)
			if previous != nil {
				previous()
			}
		}
		captured, err = configuration.TargetBinding.Capture(ctx)
		if err != nil {
			return err
		}
		if captured.Address != cfg.Target {
			return diagnostic.Wrap(diagnostic.TargetUnavailable, errors.New("target changed before publication"))
		}
	}
	// service.Name is the registration key, which may be an invocation ID.
	// cfg.Service is only a configured service name; ad-hoc tunnels have none.
	journal, err = w.beginPublication(ctx, service, configuration, clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: cfg.ControlURL, Target: service.Target, Project: cfg.ProjectRoot, Service: cfg.Service, ServiceProtocol: controlv1.ServiceProtocol(cfg.ServiceProtocol), IntegrationScope: configuration.IntegrationScope})
	if err != nil {
		return err
	}
	tunnel := journal.tunnel
	ctx = tunnel.Context()
	// attachments can start alias publishers immediately. give them the same
	// current target check before they copy the entry service's request hook.
	if configuration.TargetBinding != nil {
		prior := cfg.AdmitRequest
		cfg.AdmitRequest = func(request *http.Request, run publisher.PublishRunIdentity) error {
			if ctx.Err() != nil || !w.Manager.CurrentRegistration(service.Name, service.RegistrationID, service.Target) {
				return diagnostic.Wrap(diagnostic.TargetUnavailable, ErrRegistrationStale)
			}
			if _, err := configuration.TargetBinding.Capture(request.Context()); err != nil {
				return diagnostic.Wrap(diagnostic.TargetUnavailable, err)
			}
			if prior != nil {
				return prior(request, run)
			}
			return nil
		}
	}
	if configuration.Attach != nil {
		stop, err := configuration.Attach(ctx, tunnel, &cfg)
		if err != nil {
			return err
		}
		if stop != nil {
			defer stop()
		}
	}
	cfg.InspectionMode = configuration.Inspection.Mode
	previousSummary := cfg.ObserveSummary
	recordSummary := SummaryObservation(journal.recorder)
	cfg.ObserveSummary = func(summary inspection.Summary) {
		if previousSummary != nil {
			previousSummary(summary)
		}
		if recordSummary != nil {
			recordSummary(summary)
		}
	}
	current := func(run uint64) error {
		if ctx.Err() != nil || !w.Manager.CurrentRun(service.Name, service.RegistrationID, service.Target, run) {
			return diagnostic.Wrap(diagnostic.TargetUnavailable, ErrRegistrationStale)
		}
		return nil
	}
	currentTarget := func(ctx context.Context) error {
		if configuration.TargetBinding != nil {
			if _, err := configuration.TargetBinding.Capture(ctx); err != nil {
				return diagnostic.Wrap(diagnostic.TargetUnavailable, err)
			}
		}
		return nil
	}
	admit := cfg.AdmitRequest
	cfg.AdmitRequest = func(request *http.Request, run publisher.PublishRunIdentity) error {
		if err := current(run.Number); err != nil {
			return err
		}
		if err := currentTarget(request.Context()); err != nil {
			return err
		}
		if admit != nil {
			return admit(request, run)
		}
		return nil
	}
	guard := cfg.AdmitVisitor
	cfg.AdmitVisitor = func(ctx context.Context, visitor publisher.Visitor) error {
		if err := current(visitor.Run.Number); err != nil {
			return err
		}
		if err := currentTarget(ctx); err != nil {
			return err
		}
		if guard != nil {
			return guard(ctx, visitor)
		}
		return nil
	}
	// nil promotion lets the publisher use its authenticated visitor stream. a
	// successful ownership check must never substitute for that decision.
	warning := cfg.OnWarning
	cfg.OnWarning = func(reason string) {
		w.Manager.RecordWarning(service.Name, service.RegistrationID, reason)
		if warning != nil {
			warning(reason)
		}
	}
	var entry *proofEntry
	if cfg.ServiceProtocol == "http" || cfg.ServiceProtocol == "" {
		cfg.ReadinessProof = func(run publisher.PublishRunIdentity) *httpaccess.ReadinessProof {
			path := service.Readiness.Path
			if path == "" {
				path = "/"
			}
			proof, err := httpaccess.NewReadinessProof(httpaccess.ReadinessRun{Subject: visitorscope.Scope{Kind: visitorscope.PublicURL, ID: run.PublicURLID}, ID: run.PublishRunID, Number: run.Number, Hostname: run.Hostname}, path)
			if err != nil {
				return nil
			}
			entry = &proofEntry{service: service, run: run, proof: proof, target: configuration.TargetBinding}
			w.mu.Lock()
			if w.proofs == nil {
				w.proofs = map[string]*proofEntry{}
			}
			w.proofs[service.RegistrationID] = entry
			w.mu.Unlock()
			return proof
		}
	}
	defer func() {
		w.mu.Lock()
		if w.proofs[service.RegistrationID] == entry {
			delete(w.proofs, service.RegistrationID)
		}
		w.mu.Unlock()
	}()
	// lifecycle events are ordered by the publisher. each run gets one bounded
	// automatic check, even if ready is reported again after that check finishes.
	lastReadinessRun := uint64(0)
	stopReadiness := func() {}
	defer func() { stopReadiness() }()
	previous := cfg.Observe
	cfg.Observe = func(event publisher.Event) error {
		if event.Type == publisher.EventProvisioning || event.Type == publisher.EventDraining {
			stopReadiness()
		}
		if previous != nil {
			if err := previous(event); err != nil {
				return err
			}
		}
		switch event.Type {
		case publisher.EventPublicURLAssigned:
			return tunnel.SetPublicURL(ctx, event.PublicURLID, event.Hostname)
		case publisher.EventProvisioning:
			if cfg.ServiceProtocol != "http" && cfg.ServiceProtocol != "" {
				entry = &proofEntry{service: service, run: publisher.PublishRunIdentity{Number: event.PublishRunNumber}, target: configuration.TargetBinding}
				w.mu.Lock()
				if w.proofs == nil {
					w.proofs = map[string]*proofEntry{}
				}
				w.proofs[service.RegistrationID] = entry
				w.mu.Unlock()
			}
			if err := tunnel.SetProvisioning(ctx, event.PublishRunNumber); err != nil {
				return err
			}
			return observe(event.PublishRunNumber, false)
		case publisher.EventReady:
			if err := tunnel.SetReady(ctx, event.PublicURL, event.PublishRunNumber); err != nil {
				return err
			}
			if err := observe(event.PublishRunNumber, true); err != nil {
				return err
			}
			if w.AutomaticReadiness && event.PublishRunNumber > lastReadinessRun {
				stopReadiness()
				lastReadinessRun = event.PublishRunNumber
				stopReadiness = w.startReadiness(ctx, service, event.PublishRunNumber)
			}
			return nil
		case publisher.EventDraining:
			if err := tunnel.SetDraining(ctx); err != nil {
				return err
			}
			return observe(event.PublishRunNumber, false)
		case publisher.EventProvisioningStep:
			w.Manager.SetProvisioningStage(service.Name, service.RegistrationID, event.PublishRunNumber, event.ProvisioningStage)
		}
		return nil
	}
	run := w.RunPublisher
	if run == nil {
		run = publisher.Run
	}
	return run(ctx, cfg)
}

// Check probes public URLs with visitor proofs and private runs at their local
// targets. observations require the same registration, target, run and path.
func (w *Workers) Check(ctx context.Context, names []string) (Snapshot, error) {
	snapshot := w.Manager.Snapshot()
	for _, name := range names {
		if !slices.ContainsFunc(snapshot.Services, func(s Service) bool { return s.Name == name }) {
			return snapshot, errors.New("service is not configured")
		}
	}
	var checks sync.WaitGroup
	for _, service := range snapshot.Services {
		if len(names) != 0 && !slices.Contains(names, service.Name) || !service.Registered || !service.Routable {
			continue
		}
		checks.Add(1)
		go func() {
			defer checks.Done()
			w.checkService(ctx, service)
		}()
	}
	checks.Wait()
	return w.Manager.Snapshot(), nil
}

// checkService reports this probe's accepted result. a later target change may
// invalidate the journal, but cannot restart a completed automatic check.
func (w *Workers) checkService(ctx context.Context, service Service) (ready bool) {
	var entry *proofEntry
	var captured target.TargetSnapshot
	var capturedTarget bool
	observation := Observation{Target: service.Target, RegistrationID: service.RegistrationID, RunNumber: service.RunNumber, CheckedAt: time.Now().UTC(), Readiness: service.Readiness, Reason: "runtime.probe_failed"}
	defer func() {
		if entry != nil && entry.target != nil && capturedTarget && !entry.target.Current(ctx, captured) {
			observation.Ready = false
			observation.Reason = "runtime.target_changed"
		}
		accept := w.acceptReadiness
		if accept == nil {
			accept = w.Manager.Observe
		}
		ready = accept(observation) && observation.Ready
	}()
	w.mu.Lock()
	entry = w.proofs[service.RegistrationID]
	w.mu.Unlock()
	if entry == nil || entry.run.Number != service.RunNumber || entry.service.Target != service.Target {
		return false
	}
	if entry.target != nil {
		var err error
		captured, err = entry.target.Capture(ctx)
		if err != nil {
			return false
		}
		capturedTarget = true
	}
	if entry.serviceCheck != nil {
		observation = entry.serviceCheck(ctx, service)
	} else if service.ServiceProtocol == "http" || service.ServiceProtocol == "" {
		if entry.proof == nil {
			return false
		}
		entry.check.Lock()
		defer entry.check.Unlock()
		if ctx.Err() != nil {
			return false
		}
		secret, err := entry.proof.Renew()
		if err != nil {
			return false
		}
		observation = ProbeWithProof(ctx, service, w.HTTPTransport, secret)
	}
	return false
}
