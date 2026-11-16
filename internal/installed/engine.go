package installed

import (
	"context"
	"crypto/tls"
	"errors"
	"math/rand/v2"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/filelock"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	processidentity "github.com/tnldotdev/tnl/internal/publisher/processidentity"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type DiscoveryClient interface {
	Discovery(context.Context) (controlv1.ControlDiscovery, error)
}

type PublisherClients struct {
	publisheridentity.NativeControl
	Discovery DiscoveryClient
}

type ClientFactory func(Job) (PublisherClients, publisheridentity.EnrollmentAuthority, error)

// Clients creates isolated HTTP transports for one server's trust configuration.
// relay trust stays WebPKI, as required by the relay transport boundary.
func Clients(job Job) (PublisherClients, publisheridentity.EnrollmentAuthority, error) {
	roots, err := trustRoots(job.ServerCAPEM)
	if err != nil {
		return PublisherClients{}, nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	transport.DisableKeepAlives = true
	httpClient := &http.Client{Transport: transport}
	control, err := clientcontrol.New(job.Server, httpClient, "")
	if err != nil {
		return PublisherClients{}, nil, err
	}
	authority, err := clientauthority.New(job.Server, httpClient, "")
	return PublisherClients{NativeControl: publisheridentity.NativeControl{PublicURLControl: control, Services: control, Runtime: control}, Discovery: control}, authority, err
}

type Engine struct {
	Telemetry *clienttelemetry.Collector
	Registry  *Registry
	// UserJobs lets the user-login supervisor host another job kind with its
	// own registry and credentials. the system publisher service leaves it empty.
	UserJobs   []UserJobRunner
	Clients    ClientFactory
	Publish    func(context.Context, publisher.Config) error
	Connect    func(context.Context, Job, *clienttelemetry.Collector, func() error) error
	Deployment func(context.Context, Job, *clienttelemetry.Collector, func(int64, bool) error) error
	Observe    func(Job, Status) error
	// Initialize runs local desired-state setup while holding service.lock,
	// before any worker starts. it must not contact remote services.
	Initialize   func(context.Context) error
	PollInterval time.Duration
	RetryMin     time.Duration
	RetryMax     time.Duration
	DrainTime    time.Duration
}

// UserJobRunner owns its own registry and reconciliation. Serve joins its
// workers before returning when the shared user-login context is canceled.
type UserJobRunner interface{ Serve(context.Context) error }

type worker struct {
	revision uint64
	cancel   context.CancelFunc
	done     chan struct{}
}

// Serve runs every enabled job after boot. failures and drain waits belong to
// individual workers; the reconciler never waits on a target or control server.
// callers must keep Registry open until Serve returns, including its drain join.
func (e Engine) Serve(ctx context.Context) error {
	if e.Registry == nil {
		return ErrUnsafeState
	}
	if e.Clients == nil {
		e.Clients = Clients
	}
	if e.Publish == nil {
		e.Publish = publisher.Run
	}
	if e.PollInterval == 0 {
		e.PollInterval = 200 * time.Millisecond
	}
	if e.RetryMin == 0 {
		e.RetryMin = time.Second
	}
	if e.RetryMax == 0 {
		e.RetryMax = time.Minute
	}
	if e.DrainTime == 0 {
		e.DrainTime = 30 * time.Second
	}
	if e.PollInterval < time.Millisecond || e.RetryMin < time.Millisecond || e.RetryMax < e.RetryMin || e.RetryMax > 5*time.Minute || e.DrainTime < 0 || e.DrainTime > time.Minute {
		return ErrScope
	}
	if err := e.Registry.validate(); err != nil {
		return err
	}
	serviceLock, err := filelock.Acquire(filepath.Join(e.Registry.root, "service.lock"), filelock.Nonblocking, e.Registry.owner)
	if err != nil {
		return err
	}
	defer serviceLock.Close()
	if e.Initialize != nil {
		if err := e.Initialize(ctx); err != nil {
			return err
		}
	}
	for _, runner := range e.UserJobs {
		if runner == nil {
			return ErrScope
		}
	}
	userCtx, cancelUser := context.WithCancel(ctx)
	userDone := make(chan error, len(e.UserJobs))
	var userWorkers sync.WaitGroup
	for _, runner := range e.UserJobs {
		userWorkers.Go(func() { userDone <- runner.Serve(userCtx) })
	}
	defer func() { cancelUser(); userWorkers.Wait() }()
	workers := map[string]*worker{}
	defer func() {
		for _, w := range workers {
			w.cancel()
		}
		for _, w := range workers {
			<-w.done
		}
		// record the joined boundary with a fresh revision, including local stops.
		finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		jobs, err := e.Registry.List(finish)
		if err == nil {
			for _, job := range jobs {
				_ = e.Registry.status(finish, job.ID, job.Revision, Status{State: JobStopped})
			}
		}
	}()
	for {
		if ctx.Err() != nil {
			return nil
		}
		select {
		case err := <-userDone:
			if ctx.Err() != nil {
				return nil
			}
			if err == nil {
				return ErrScope
			}
			return err
		default:
		}
		jobs, err := e.Registry.List(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		for _, job := range jobs {
			w := workers[job.ID]
			if w != nil {
				if !job.Enabled || job.Revision != w.revision {
					w.cancel()
				}
				select {
				case <-w.done:
					delete(workers, job.ID)
					w = nil
				default:
				}
			}
			if w != nil {
				continue
			}
			if !job.Enabled {
				if job.Status.State != JobStopped {
					if err := e.Registry.status(ctx, job.ID, job.Revision, Status{State: JobStopped}); err != nil {
						return err
					}
				}
				continue
			}
			workerCtx, cancel := context.WithCancel(ctx)
			w = &worker{revision: job.Revision, cancel: cancel, done: make(chan struct{})}
			workers[job.ID] = w
			go func() { defer close(w.done); e.run(workerCtx, job) }()
		}
		if err := wait(ctx, e.PollInterval); err != nil {
			return nil
		}
	}
}

func (e Engine) run(ctx context.Context, job Job) {
	if job.TelemetryDisabled {
		e.Telemetry = nil
	}
	var runtime *processidentity.Owner
	defer func() {
		if runtime != nil {
			finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = runtime.Stop(finish)
		}
	}()
	backoff := e.RetryMin
	var attempts uint64
	for ctx.Err() == nil {
		attempts++
		if err := e.status(ctx, job, Status{State: JobStarting, Attempts: attempts}); err != nil {
			return
		}
		ready, err := e.attempt(ctx, job, attempts, &runtime)
		if ctx.Err() != nil {
			return
		}
		if ready {
			backoff = e.RetryMin
		}
		status := Status{State: JobRetrying, Failure: safeFailure(err), Attempts: attempts}
		// bad grants and settings wait for local Start rather than hammering control.
		if blockedFailure(err) {
			status.State = JobBlocked
			_ = e.status(ctx, job, status)
			<-ctx.Done()
			return
		}
		if err := e.status(ctx, job, status); err != nil {
			return
		}
		if err := wait(ctx, backoff+time.Duration(rand.Int64N(int64(backoff/4)+1))); err != nil {
			return
		}
		backoff = min(e.RetryMax, backoff*2)
	}
}

func blockedFailure(err error) bool {
	if errors.Is(err, publisheridentity.ErrScope) || errors.Is(err, ErrScope) || errors.Is(err, ErrUnsafeState) || errors.Is(err, clientcontrol.ErrUnauthenticated) || errors.Is(err, clientauthority.ErrUnauthenticated) || errors.Is(err, clientcontrol.ErrNotFound) || errors.Is(err, clientauthority.ErrNotFound) {
		return true
	}
	if reason, ok := failure.ReasonOf(err); ok {
		definition, _ := failure.DefinitionFor(reason)
		return definition.Retry != failure.RetryLater
	}
	return false
}

func safeFailure(err error) string {
	if err == nil {
		return "publication ended"
	}
	if errors.Is(err, publisheridentity.ErrScope) || errors.Is(err, ErrScope) {
		return "grant scope changed"
	}
	if errors.Is(err, ErrUnsafeState) {
		return "private state changed"
	}
	if errors.Is(err, clientcontrol.ErrUnauthenticated) || errors.Is(err, clientauthority.ErrUnauthenticated) {
		return "publisher authorization rejected"
	}
	if errors.Is(err, clientcontrol.ErrNotFound) {
		return "saved URL unavailable"
	}
	if reason, ok := failure.ReasonOf(err); ok {
		return string(reason)
	}
	return "publication unavailable"
}

func (e Engine) attempt(ctx context.Context, job Job, attempts uint64, runtime **processidentity.Owner) (bool, error) {
	if err := validateJob(&job); err != nil {
		return false, err
	}
	if job.Kind == KindDeployment {
		if e.Deployment == nil || !e.Registry.deployments {
			return false, ErrScope
		}
		var ready atomic.Bool
		err := e.Deployment(ctx, job, e.Telemetry, func(revision int64, healthy bool) error {
			ready.Store(healthy)
			state := JobReconciling
			if healthy {
				state = JobReady
			}
			return e.status(ctx, job, Status{State: state, Attempts: attempts, ObservedRevision: revision})
		})
		return ready.Load(), err
	}
	if job.Kind == KindConnector {
		if e.Connect == nil || !e.Registry.user {
			return false, ErrScope
		}
		var ready atomic.Bool
		err := e.Connect(ctx, job, e.Telemetry, func() error {
			ready.Store(true)
			return e.Registry.status(ctx, job.ID, job.Revision, Status{State: JobReady, Attempts: attempts})
		})
		return ready.Load(), err
	}
	return e.publishJob(ctx, job, attempts, runtime)
}

func (e Engine) status(ctx context.Context, job Job, status Status) error {
	if err := e.Registry.status(ctx, job.ID, job.Revision, status); err != nil {
		return err
	}
	if e.Observe != nil {
		return e.Observe(job, status)
	}
	return nil
}

func wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return nil
	}
}
