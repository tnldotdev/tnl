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
	publisherdeployment "github.com/tnldotdev/tnl/internal/publisher/deployment"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	processidentity "github.com/tnldotdev/tnl/internal/publisher/processidentity"
)

type PublisherClients struct {
	publisheridentity.NativeControl
	Discovery publisherdeployment.ServerDiscovery
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
	return PublisherClients{NativeControl: publisheridentity.NativeControl{Services: control, Runtime: control}, Discovery: control}, authority, err
}

type Engine struct {
	Telemetry *clienttelemetry.Collector
	Registry  *Registry
	// UserJobs lets the user-login supervisor host another job kind with its
	// own registry and credentials. the system publisher service leaves it empty.
	UserJobs   []UserJobRunner
	Clients    ClientFactory
	Connect    func(context.Context, Job, *clienttelemetry.Collector, func() error, func() time.Time) error
	Deployment func(context.Context, Job, *clienttelemetry.Collector, func(int64, bool) error, func() time.Time) error
	Observe    func(Job, Status) error
	// Initialize runs local desired-state setup while holding service.lock,
	// before any worker starts. it must not contact remote services.
	Initialize       func(context.Context) error
	PollInterval     time.Duration
	RetryMin         time.Duration
	RetryMax         time.Duration
	DrainTime        time.Duration
	ShutdownDeadline func() time.Time
}

// UserJobRunner owns its own registry and reconciliation. Serve joins its
// workers before returning when the shared user-login context is canceled.
type UserJobRunner interface {
	Serve(context.Context, func() time.Time) error
}

type worker struct {
	revision uint64
	cancel   context.CancelFunc
	done     chan struct{}
	err      error
}

// Serve runs every enabled job after boot. failures and drain waits belong to
// individual workers; the reconciler never waits on a target or control server.
// callers must keep Registry open until Serve returns, including its drain join.
func (e Engine) Serve(ctx context.Context) (result error) {
	if e.Registry == nil {
		return ErrUnsafeState
	}
	if e.Clients == nil {
		e.Clients = Clients
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
		e.DrainTime = 10 * time.Second
	}
	if e.PollInterval < time.Millisecond || e.RetryMin < time.Millisecond || e.RetryMax < e.RetryMin || e.RetryMax > 5*time.Minute || e.DrainTime < 0 || e.DrainTime > time.Minute {
		return ErrScope
	}
	var joinShutdown func()
	e.ShutdownDeadline, joinShutdown = installedShutdown(ctx, e.DrainTime, e.ShutdownDeadline)
	defer joinShutdown()
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
		userWorkers.Go(func() { userDone <- runner.Serve(userCtx, e.ShutdownDeadline) })
	}
	defer func() {
		e.ShutdownDeadline()
		cancelUser()
		userWorkers.Wait()
		for range e.UserJobs {
			err := <-userDone
			if err != nil && !failure.Only(err, context.Canceled) {
				result = errors.Join(result, err)
			}
		}
	}()
	workers := map[string]*worker{}
	var stopping atomic.Bool
	defer func() {
		stopping.Store(true)
		e.ShutdownDeadline()
		cancelUser()
		for _, w := range workers {
			w.cancel()
		}
		for _, w := range workers {
			<-w.done
			result = errors.Join(result, w.err)
		}
		// record the joined boundary with a fresh revision, including local stops.
		finish, cancel := context.WithDeadline(context.Background(), e.ShutdownDeadline())
		defer cancel()
		jobs, err := e.Registry.List(finish)
		if err == nil {
			for _, job := range jobs {
				result = errors.Join(result, e.status(finish, job, Status{State: JobStopped}))
			}
		} else {
			result = errors.Join(result, err)
		}
	}()
	for {
		if ctx.Err() != nil {
			return nil
		}
		select {
		case err := <-userDone:
			// retain this result for the joined final collection too.
			userDone <- err
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
					if w.err != nil {
						return w.err
					}
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
			jobEngine := e
			jobEngine.ShutdownDeadline = func() time.Time {
				if stopping.Load() || ctx.Err() != nil {
					return e.ShutdownDeadline()
				}
				return time.Time{}
			}
			go func() { defer close(w.done); w.err = jobEngine.run(workerCtx, job) }()
		}
		if err := wait(ctx, e.PollInterval); err != nil {
			return nil
		}
	}
}

func (e Engine) run(ctx context.Context, job Job) (result error) {
	var joinShutdown func()
	e.ShutdownDeadline, joinShutdown = installedShutdown(ctx, e.DrainTime, e.ShutdownDeadline)
	defer joinShutdown()
	if job.TelemetryDisabled {
		e.Telemetry = nil
	}
	var runtime *processidentity.Owner
	defer func() {
		if runtime != nil {
			finish, cancel := context.WithDeadline(context.Background(), e.ShutdownDeadline())
			defer cancel()
			result = errors.Join(result, runtime.Stop(finish))
		}
		if ctx.Err() != nil && failure.Only(result, context.Canceled) {
			result = nil
		}
	}()
	backoff := e.RetryMin
	var attempts uint64
	for ctx.Err() == nil {
		attempts++
		if err := e.status(ctx, job, Status{State: JobStarting, Attempts: attempts}); err != nil {
			return err
		}
		attemptEngine := e
		attemptEngine.ShutdownDeadline = func() time.Time {
			if ctx.Err() != nil {
				return e.ShutdownDeadline()
			}
			// a retried service run does not stop the installed job.
			return time.Time{}
		}
		ready, err := attemptEngine.attempt(ctx, job, attempts, &runtime)
		if ctx.Err() != nil {
			if err != nil && !failure.Only(err, context.Canceled) {
				return err
			}
			return nil
		}
		if ready {
			backoff = e.RetryMin
		}
		status := Status{State: JobRetrying, Failure: safeFailure(err), Attempts: attempts}
		// bad grants and settings wait for local Start rather than hammering control.
		if blockedFailure(err) {
			status.State = JobBlocked
			if observeErr := e.status(ctx, job, status); observeErr != nil {
				return errors.Join(err, observeErr)
			}
			<-ctx.Done()
			return nil
		}
		if err := e.status(ctx, job, status); err != nil {
			return err
		}
		if err := wait(ctx, backoff+time.Duration(rand.Int64N(int64(backoff/4)+1))); err != nil {
			return nil
		}
		backoff = min(e.RetryMax, backoff*2)
	}
	return nil
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
		return "service unavailable"
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
		}, e.ShutdownDeadline)
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
		}, e.ShutdownDeadline)
		return ready.Load(), err
	}
	return e.publishJob(ctx, job, attempts, runtime)
}

// installedShutdown starts the job's budget on its first stop and caps it at the
// supervisor's original deadline only when that supervisor is also stopping.
func installedShutdown(ctx context.Context, duration time.Duration, parent func() time.Time) (func() time.Time, func()) {
	if duration == 0 {
		duration = 10 * time.Second
	}
	deadline := sync.OnceValue(func() time.Time {
		var outer time.Time
		if parent != nil {
			outer = parent()
		}
		until := time.Now().Add(duration)
		if !outer.IsZero() && outer.Before(until) {
			until = outer
		}
		return until
	})
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); deadline() })
	return deadline, func() {
		deadline()
		if !stop() {
			<-done
		}
	}
}

func (e Engine) status(ctx context.Context, job Job, status Status) error {
	applied, err := e.Registry.updateStatus(ctx, job.ID, job.Revision, status)
	if err != nil {
		return err
	}
	if applied && e.Observe != nil {
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
