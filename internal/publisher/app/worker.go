package app

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
)

type Configuration struct {
	Service     *ServicePublication
	Inspection  inspection.Policy
	PrimaryRoot string
	SharedRoot  string
	// cleanup owns resources allocated before the worker starts, including when
	// local tunnel creation fails. it runs after operation and inspection joins.
	Cleanup func() error
}

// ServicePublication supplies an operation, not another publisher engine. the
// worker owns its local journal and inspection until the operation joins its work.
// run composes integrations using that same journal-owned tunnel.
type ServicePublication struct {
	Options clientstate.BeginTunnelOptions
	URL     string
	Run     func(context.Context, *clientstate.Tunnel, func(uint64, bool) error, inspection.Observer) error
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

type readinessEntry struct {
	target string
	run    uint64
	check  func(context.Context, Service) Observation
}

type Workers struct {
	Database           *clientstate.Database
	Manager            *Manager
	Configure          func(context.Context, Service) (Configuration, error)
	AutomaticReadiness bool
	// zero values use the public readiness retry policy; tests can shorten time.
	readinessBudget time.Duration
	readinessDelay  func(int) time.Duration
	acceptReadiness func(Observation) bool
	mu              sync.Mutex
	checks          map[string]*readinessEntry
}

func (w *Workers) Run(ctx context.Context, service Service, observe func(PublicationUpdate) error) (result error) {
	configuration, err := w.Configure(ctx, service)
	if err != nil {
		return err
	}
	var journal *publicationJournal
	defer func() {
		if journal != nil {
			// operation workers have joined before recorder drain. include
			// independent configuration cleanup failures in the terminal row.
			result = journal.close(result, configuration.Cleanup)
		} else if configuration.Cleanup != nil {
			result = errors.Join(result, configuration.Cleanup())
		}
	}()
	publication := configuration.Service
	if publication == nil || publication.Run == nil || publication.Check == nil {
		return ErrRegistrationStale
	}
	journal, err = w.beginPublication(ctx, service, configuration, publication.Options)
	if err != nil {
		return err
	}
	return w.runService(journal.tunnel.Context(), service, publication, journal, observe)
}

// Check delegates to each operation's readiness owner. observations require the
// same registration, target, run and path before the manager accepts them.
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
		checks.Go(func() { w.checkService(ctx, service) })
	}
	checks.Wait()
	return w.Manager.Snapshot(), nil
}

// checkService reports this probe's accepted result. a later target change may
// invalidate the journal; the run owner then joins this check before rechecking.
func (w *Workers) checkService(ctx context.Context, service Service) (ready bool) {
	observation := Observation{Target: service.Target, RegistrationID: service.RegistrationID, RunNumber: service.RunNumber,
		CheckedAt: time.Now().UTC(), Readiness: service.Readiness, Reason: "runtime.probe_failed"}
	defer func() {
		accept := w.acceptReadiness
		if accept == nil {
			accept = w.Manager.Observe
		}
		ready = accept(observation) && observation.Ready
	}()
	w.mu.Lock()
	entry := w.checks[service.RegistrationID]
	w.mu.Unlock()
	if entry == nil || entry.run != service.RunNumber || entry.target != service.Target {
		return false
	}
	observation = entry.check(ctx, service)
	return false
}
