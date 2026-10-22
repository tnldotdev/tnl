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
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/target"
)

type Configuration struct {
	RunPrivate       func(context.Context, func(uint64, bool) error) error
	CheckPrivate     func(context.Context, Service) Observation
	Publisher        publisher.Config
	Inspection       inspection.Policy
	PrimaryRoot      string
	SharedRoot       string
	IntegrationGroup string
	TargetBinding    *target.TargetBinding
	// cleanup owns resources allocated before the worker starts, including when
	// target capture or local tunnel creation fails. it runs after drain/join.
	Cleanup func() error
	Attach  func(context.Context, *clientstate.Tunnel, *publisher.Config) (func(), error)
}

type proofEntry struct {
	service      Service
	run          publisher.PublishRunIdentity
	proof        *publisher.ReadinessProof
	target       *target.TargetBinding
	check        sync.Mutex
	privateCheck func(context.Context, Service) Observation
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
	if configuration.Cleanup != nil {
		defer func() { result = errors.Join(result, configuration.Cleanup()) }()
	}
	if configuration.RunPrivate != nil {
		return w.runPrivate(ctx, service, configuration, observe)
	}
	cfg := configuration.Publisher
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
	tunnel, err := w.Database.BeginTunnel(ctx, clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: cfg.ControlURL, Target: service.Target, Project: cfg.ProjectRoot, Service: cfg.Service, ServiceProtocol: cfg.ServiceProtocol, IntegrationGroup: configuration.IntegrationGroup})
	if err != nil {
		return err
	}
	ctx = tunnel.Context()
	defer func() {
		finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result = errors.Join(result, tunnel.Finish(finish, result))
	}()
	if err := w.Manager.BindTunnel(service.Name, service.RegistrationID, service.Target, tunnel.ID()); err != nil {
		return err
	}
	if configuration.PrimaryRoot == "" {
		configuration.PrimaryRoot = cfg.ProjectRoot
	}
	if configuration.SharedRoot == "" {
		configuration.SharedRoot = configuration.PrimaryRoot
	}
	var recorder *clientstate.InspectionRecorder
	if configuration.Inspection.Mode == inspection.SummaryMode {
		recorder = tunnel.NewInspectionRecorder(configuration.PrimaryRoot, cfg.ProjectRoot, configuration.SharedRoot, service.Name, configuration.Inspection)
		defer recorder.Close()
	}
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
	recordSummary := SummaryObservation(recorder)
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
	// nil promotion lets the publisher use its authenticated sideband. a
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
		cfg.ReadinessProof = func(run publisher.PublishRunIdentity) *publisher.ReadinessProof {
			path := service.Readiness.Path
			if path == "" {
				path = "/"
			}
			proof, err := publisher.NewReadinessProof(run, path)
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
	observation := Observation{Target: service.Target, RegistrationID: service.RegistrationID, PublishRunNumber: service.PublishRunNumber, CheckedAt: time.Now().UTC(), Readiness: service.Readiness, Reason: "runtime.probe_failed"}
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
	if entry == nil || entry.run.Number != service.PublishRunNumber || entry.service.Target != service.Target {
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
	if entry.privateCheck != nil {
		observation = entry.privateCheck(ctx, service)
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
