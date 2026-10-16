package publisherjob

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/filelock"
	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/managedssh"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/publisher"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/crypto/ssh"
)

type ClientFactory func(Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error)

// Clients creates isolated HTTP transports for one server's trust configuration.
// relay trust stays WebPKI, as required by the relay transport boundary.
func Clients(job Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error) {
	roots, err := trustRoots(job.ServerCAPEM)
	if err != nil {
		return nil, nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	transport.DisableKeepAlives = true
	httpClient := &http.Client{Transport: transport}
	control, err := controlclient.New(job.Server, httpClient, "")
	if err != nil {
		return nil, nil, err
	}
	authority, err := authorityclient.New(job.Server, httpClient, "")
	return control, authority, err
}

type Engine struct {
	Registry     *Registry
	Clients      ClientFactory
	Publish      func(context.Context, publisher.Config) error
	PollInterval time.Duration
	RetryMin     time.Duration
	RetryMax     time.Duration
	DrainTime    time.Duration
}

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
				_ = e.Registry.status(finish, job.ID, job.Revision, Status{State: "stopped"})
			}
		}
	}()
	for {
		if ctx.Err() != nil {
			return nil
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
				if job.Status.State != "stopped" {
					if err := e.Registry.status(ctx, job.ID, job.Revision, Status{State: "stopped"}); err != nil {
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
	backoff := e.RetryMin
	var attempts uint64
	for ctx.Err() == nil {
		attempts++
		if err := e.Registry.status(ctx, job.ID, job.Revision, Status{State: "starting", Attempts: attempts}); err != nil {
			return
		}
		ready, err := e.attempt(ctx, job, attempts)
		if ctx.Err() != nil {
			return
		}
		if ready {
			backoff = e.RetryMin
		}
		status := Status{State: "retrying", Failure: safeFailure(err), Attempts: attempts}
		// bad grants and settings wait for local Start rather than hammering control.
		if blockedFailure(err) {
			status.State = "blocked"
			_ = e.Registry.status(ctx, job.ID, job.Revision, status)
			<-ctx.Done()
			return
		}
		if err := e.Registry.status(ctx, job.ID, job.Revision, status); err != nil {
			return
		}
		if err := wait(ctx, backoff); err != nil {
			return
		}
		backoff = min(e.RetryMax, backoff*2)
	}
}

func blockedFailure(err error) bool {
	if errors.Is(err, nativeauth.ErrScope) || errors.Is(err, ErrScope) || errors.Is(err, ErrUnsafeState) || errors.Is(err, controlclient.ErrUnauthenticated) || errors.Is(err, authorityclient.ErrUnauthenticated) || errors.Is(err, controlclient.ErrNotFound) || errors.Is(err, authorityclient.ErrNotFound) {
		return true
	}
	if typed, ok := failure.Of(err); ok {
		definition, _ := failure.DefinitionFor(typed.Reason())
		return definition.Retry != failure.RetryLater
	}
	return false
}

func safeFailure(err error) string {
	if err == nil {
		return "publication ended"
	}
	if errors.Is(err, nativeauth.ErrScope) || errors.Is(err, ErrScope) {
		return "grant scope changed"
	}
	if errors.Is(err, ErrUnsafeState) {
		return "private state changed"
	}
	if errors.Is(err, controlclient.ErrUnauthenticated) || errors.Is(err, authorityclient.ErrUnauthenticated) {
		return "publisher authorization rejected"
	}
	if errors.Is(err, controlclient.ErrNotFound) {
		return "saved URL unavailable"
	}
	if typed, ok := failure.Of(err); ok {
		return string(typed.Reason())
	}
	return "publication unavailable"
}

func (e Engine) attempt(ctx context.Context, job Job, attempts uint64) (bool, error) {
	identity, private, profile, err := e.Registry.signingIdentity(ctx, job)
	if err != nil {
		return false, err
	}
	control, authority, err := e.Clients(job)
	if err != nil {
		return false, err
	}
	native, err := nativeauth.NewNative(control, authority, identity, private)
	if err != nil {
		return false, err
	}
	publicURL, err := native.SavedURL(ctx)
	if err != nil {
		return false, err
	}
	cfg, err := publicationConfig(job, publicURL)
	if err != nil {
		return false, err
	}
	cfg.Control, cfg.State, cfg.DrainTime = native, profile, e.DrainTime
	transportTLS := &tls.Config{MinVersion: tls.VersionTLS13}
	cfg.QUICConnector = muxsession.QUICConnector{TLSConfig: transportTLS}
	cfg.TCPConnector = muxsession.TLSYamuxConnector{TLSConfig: transportTLS}
	var mu sync.Mutex
	ready := false
	cfg.Observe = func(event publisher.Event) error {
		status := Status{State: "provisioning", Attempts: attempts, PublishRunNumber: event.PublishRunNumber}
		switch event.Type {
		case publisher.EventReady:
			mu.Lock()
			ready = true
			mu.Unlock()
			status.State = "ready"
		case publisher.EventDraining:
			status.State = "draining"
		case publisher.EventTargetUnavailable:
			status.State = "target unavailable"
		case publisher.EventProvisioning, publisher.EventPublicURLAssigned:
		default:
			return nil
		}
		observationCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return e.Registry.status(observationCtx, job.ID, job.Revision, status)
	}
	// native runtime log messages can contain external error text. system jobs
	// expose only approved observations through the registry and CLI renderer.
	err = e.Publish(ctx, cfg)
	mu.Lock()
	defer mu.Unlock()
	return ready, err
}

func publicationConfig(job Job, publicURL controlv1.PublicURL) (publisher.Config, error) {
	if err := validateJob(&job); err != nil {
		return publisher.Config{}, err
	}
	if publicURL.Id != job.PublicURLID || publicURL.ServiceProtocol != job.Protocol || publicURL.Ephemeral || publicURL.Purpose != controlv1.App || publicURL.LifecycleState != controlv1.Enabled {
		return publisher.Config{}, ErrScope
	}
	if publicURL.Target != "" && (job.Protocol != "http" || publicURL.Target != job.Target) {
		return publisher.Config{}, ErrScope
	}
	roots, err := trustRoots(job.TargetCAPEM)
	if err != nil {
		return publisher.Config{}, err
	}
	cfg := publisher.Config{ControlURL: job.Server, TeamID: publicURL.TeamId, DomainID: publicURL.DomainId, PolicyRevision: uint64(publicURL.PolicyRevision), PublicURLScope: publicURL.PublicUrlScope, Purpose: publicURL.Purpose, Hostname: publicURL.CanonicalHostname, Target: job.Target, ServiceProtocol: job.Protocol, TargetTLS: job.TargetTLS, TargetTLSName: job.TargetTLSName, TargetOptions: localproxy.TargetOptions{RootCAs: roots}, PreserveSavedURLTarget: publicURL.Target == "", InspectionMode: inspection.Mode("none")}
	cfg.Limits = job.Limits
	if job.Protocol == controlv1.Ssh {
		signer, err := managedssh.ParseHostKey(job.SSHHostKey)
		if err != nil || publicURL.AccessMode != controlv1.Restricted || publicURL.SshHostKey == nil || *publicURL.SshHostKey != strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) {
			return publisher.Config{}, ErrScope
		}
		cfg.SSH = &publisher.SSHConfig{HostKey: signer, Users: slices.Clone(job.SSHUsers)}
	}
	if publicURL.MembershipId != nil {
		cfg.MembershipID = *publicURL.MembershipId
	}
	if publicURL.AllowedIpPrefixes != nil {
		cfg.AllowedIPPrefixes = slices.Clone(*publicURL.AllowedIpPrefixes)
	}
	return cfg, nil
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
