package installed

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publicationReadiness struct {
	ctx        context.Context
	cancel     context.CancelCauseFunc
	job        Job
	service    controlv1.Service
	attempts   uint64
	observe    func(context.Context, Status) error
	probe      func(context.Context, httpaccess.ReadinessRun, string, *httpaccess.ReadinessProof) error
	localProbe func(context.Context, string) bool
	everReady  atomic.Bool
	mu         sync.Mutex
	target     string
	current    *installedReadinessRun
	failures   error
}

type installedReadinessRun struct {
	owner   *publicationReadiness
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	changed chan struct{}
	run     httpaccess.ReadinessRun
	address string
	target  string
	mu      sync.Mutex
	status  publisherservice.RunStatus
	proof   *httpaccess.ReadinessProof
	err     error
	healthy atomic.Bool
	checked atomic.Int64
}

func newPublicationReadiness(ctx context.Context, cancel context.CancelCauseFunc, job Job, service controlv1.Service, attempts uint64, observe func(context.Context, Status) error) *publicationReadiness {
	if job.ReadinessPath == "" {
		job.ReadinessPath = "/"
	}
	r := &publicationReadiness{ctx: ctx, cancel: cancel, job: job, service: service, attempts: attempts, observe: observe, probe: VerifyServiceReadiness, target: job.Target}
	r.localProbe = r.checkTarget
	return r
}

func (r *publicationReadiness) Capture(target targetplan.TargetSnapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.target = target.Address
	return nil
}

func (r *publicationReadiness) checkTarget(ctx context.Context, address string) bool {
	transport, err := targetplan.PrivateTransport(r.job.TargetPlan())
	if err != nil {
		return false
	}
	if r.job.Protocol != "http" {
		return publisherapp.ProbeServiceTarget(ctx, publisherapp.Service{Target: address, ServiceProtocol: string(r.job.Protocol)}, transport).Ready
	}
	if !strings.Contains(address, "://") {
		address = "http://" + address
		if r.job.Trust != nil {
			address = "https://" + strings.TrimPrefix(address, "http://")
		}
	}
	return publisherapp.ProbeServiceTarget(ctx, publisherapp.Service{Target: address, ServiceProtocol: "http", Readiness: publisherapp.Readiness{Path: r.job.ReadinessPath}}, transport).Ready
}

// the heartbeat reads a recent local observation; it never waits for target I/O.
func (r *publicationReadiness) Healthy(ctx context.Context) bool {
	r.mu.Lock()
	run := r.current
	r.mu.Unlock()
	return ctx.Err() == nil && run != nil && run.ctx.Err() == nil && run.healthy.Load() &&
		time.Since(time.Unix(0, run.checked.Load())) < 10*time.Second
}

// preparation is outside the heartbeat loop. replacement cancels and joins the
// old run's probe and observations before another run can publish local status.
func (r *publicationReadiness) Prepared(prepared controlv1.ServiceRunPreparation) error {
	if r.service.Endpoint == nil || prepared.ServiceId != r.job.ServiceID || prepared.ServiceRunId == "" || prepared.RunNumber < 1 || prepared.Hostname != r.service.Endpoint.Hostname {
		return ErrScope
	}
	r.stopCurrent()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failures != nil {
		return r.failures
	}
	if r.ctx.Err() != nil {
		return context.Cause(r.ctx)
	}
	ctx, cancel := context.WithCancel(r.ctx)
	run := &installedReadinessRun{owner: r, ctx: ctx, cancel: cancel, done: make(chan struct{}), changed: make(chan struct{}, 1), target: r.target,
		run: httpaccess.ReadinessRun{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: prepared.ServiceId}, ID: prepared.ServiceRunId, Number: uint64(prepared.RunNumber), Hostname: prepared.Hostname}}
	if r.service.Protocol == controlv1.ServiceProtocolHTTP {
		run.address = "https://" + prepared.Hostname
	} else if r.service.Endpoint.Port > 0 {
		run.address = net.JoinHostPort(prepared.Hostname, strconv.Itoa(r.service.Endpoint.Port))
	}
	r.current = run
	go run.serve()
	return nil
}

func (r *publicationReadiness) Proof(identity httpaccess.ReadinessRun) *httpaccess.ReadinessProof {
	r.mu.Lock()
	defer r.mu.Unlock()
	run := r.current
	if run == nil || identity != run.run || run.ctx.Err() != nil {
		return nil
	}
	proof, err := httpaccess.NewReadinessProof(identity, r.job.ReadinessPath)
	if err != nil {
		r.cancel(err)
		return nil
	}
	run.mu.Lock()
	if run.proof != nil {
		proof = run.proof
	}
	run.proof = proof
	run.mu.Unlock()
	select {
	case run.changed <- struct{}{}:
	default:
	}
	return proof
}

// callbacks only replace a small snapshot and wake the owned worker. registry
// writes and public HTTP requests never block the service heartbeat loop.
func (r *publicationReadiness) Observe(status publisherservice.RunStatus) {
	r.mu.Lock()
	run := r.current
	r.mu.Unlock()
	if run == nil {
		return
	}
	run.mu.Lock()
	run.status = status
	run.mu.Unlock()
	select {
	case run.changed <- struct{}{}:
	default:
	}
}

func (r *publicationReadiness) stopCurrent() {
	r.mu.Lock()
	run := r.current
	r.current = nil
	r.mu.Unlock()
	if run != nil {
		run.cancel()
		<-run.done
		r.mu.Lock()
		r.failures = errors.Join(r.failures, run.err)
		r.mu.Unlock()
	}
}

func (r *publicationReadiness) Close() (bool, error) {
	r.stopCurrent()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.everReady.Load(), r.failures
}

func (r *installedReadinessRun) serve() {
	defer close(r.done)
	healthCtx, healthCancel := context.WithCancel(r.ctx)
	healthDone := make(chan struct{})
	go func() {
		defer close(healthDone)
		for healthCtx.Err() == nil {
			healthy := r.owner.localProbe(healthCtx, r.target)
			if healthCtx.Err() != nil {
				return
			}
			r.checked.Store(time.Now().UnixNano())
			r.healthy.Store(healthy)
			if wait(healthCtx, time.Second) != nil {
				return
			}
		}
	}()
	defer func() {
		healthCancel()
		<-healthDone
	}()
	var probeCancel context.CancelFunc
	var probeDone chan error
	stopProbe := func() {
		if probeDone == nil {
			return
		}
		probeCancel()
		if err := <-probeDone; err != nil && !failure.Only(err, context.Canceled) {
			r.err = errors.Join(r.err, err)
		}
		probeDone = nil
	}
	defer stopProbe()
	verified := false
	last := Status{}
	defer func() {
		finish, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 5*time.Second)
		r.err = errors.Join(r.err, r.owner.observe(finish, Status{State: JobDraining, Attempts: r.owner.attempts, RunNumber: r.run.Number, Address: r.address}))
		cancel()
	}()
	for {
		if r.ctx.Err() != nil {
			return
		}
		r.mu.Lock()
		status, proof := r.status, r.proof
		r.mu.Unlock()
		public := r.owner.service.Endpoint.Public && r.owner.service.Protocol == controlv1.ServiceProtocolHTTP
		observation := Status{State: JobProvisioning, Attempts: r.owner.attempts, RunNumber: r.run.Number, Address: r.address}
		if !status.Ready {
			stopProbe()
			if !status.TargetHealthy && !status.LastCheck.IsZero() {
				observation.State = JobTargetUnavailable
			}
		} else if !public || verified {
			observation.State = JobReady
			r.owner.everReady.Store(true)
		} else if probeDone == nil && proof != nil {
			probeCtx, cancel := context.WithCancel(r.ctx)
			probeCancel, probeDone = cancel, make(chan error, 1)
			result := probeDone
			go func() { result <- r.owner.probe(probeCtx, r.run, r.owner.job.ReadinessPath, proof) }()
		}
		if observation != last {
			check, cancel := context.WithTimeout(r.ctx, 5*time.Second)
			err := r.owner.observe(check, observation)
			cancel()
			if err != nil && !(r.ctx.Err() != nil && failure.Only(err, context.Canceled)) {
				r.err = errors.Join(r.err, err)
				r.owner.cancel(err)
				return
			}
			last = observation
		}
		select {
		case <-r.ctx.Done():
			return
		case <-r.changed:
		case err := <-probeDone:
			probeCancel()
			probeDone = nil
			if err != nil {
				if r.ctx.Err() != nil && failure.Only(err, context.Canceled) {
					continue
				}
				r.err = errors.Join(r.err, err)
				r.owner.cancel(err)
				return
			}
			r.mu.Lock()
			verified = r.ctx.Err() == nil && r.status.Ready
			r.mu.Unlock()
		}
	}
}

// VerifyServiceReadiness requires both a successful public response and local
// consumption of this exact service run's one-use proof. it sends no user session.
func VerifyServiceReadiness(ctx context.Context, run httpaccess.ReadinessRun, path string, proof *httpaccess.ReadinessProof) error {
	return verifyServiceReadiness(ctx, run, path, proof, nil)
}

func verifyServiceReadiness(ctx context.Context, run httpaccess.ReadinessRun, path string, proof *httpaccess.ReadinessProof, transport http.RoundTripper) error {
	if path == "" {
		path = "/"
	}
	if run.Subject.Kind != visitorscope.Service || !run.Subject.Valid() || proof == nil {
		return ErrScope
	}
	check, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	for {
		secret, err := proof.Renew()
		if err != nil {
			return err
		}
		observation := publisherapp.ProbeWithProof(check, publisherapp.Service{PublicURL: "https://" + run.Hostname, RunNumber: run.Number, Readiness: publisherapp.Readiness{Path: path}}, transport, secret)
		if check.Err() != nil {
			return context.Cause(check)
		}
		if observation.Ready && proof.HeaderValue() == "" {
			return nil
		}
		if err := wait(check, 250*time.Millisecond); err != nil {
			return failure.Wrap("verify service endpoint", failure.AppReadinessTimeout, errors.Join(err, context.Cause(check)))
		}
	}
}
