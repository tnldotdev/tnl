package benchworkload

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type PublisherConfig struct {
	Server, LoginToken, Domain, StateRoot, Target string
	HostnamePrefix                                string
	Ephemeral                                     bool
	HTTPClient                                    *http.Client
	RelayTLS                                      *tls.Config
	AllowedIPPrefixes                             []string
	// mixed forces alternating QUIC/TLS-TCP cohorts; auto uses production fallback.
	Transport                   string
	QUICDisablePathMTUDiscovery bool
	QUICQlog                    bool
	QUICKeepAlive               time.Duration
	Parallel                    int
	RequestLimit                int
	// StartParallel overrides Parallel only during activation; shutdown has its own bound.
	StartParallel             int
	ReadyTimeout, StopTimeout time.Duration
	DrainTime                 time.Duration
	OnFailure                 func()
	OnActivationFailure       func(index int)
	Observe                   func(int, publisher.Event) error
	Report                    func(index int, err error)
}

type PublishedPublicURL struct {
	Index      int             `json:"index"`
	Ready      publisher.Event `json:"ready"`
	Activation time.Duration   `json:"activation"`
}

type ShutdownResult struct {
	StartedAt                     time.Time     `json:"started_at"`
	Duration                      time.Duration `json:"duration"`
	Attempts, Successes, Failures int
	Timings                       []time.Duration `json:"timings"`
}

type publicURLProcess struct {
	index  int
	cancel context.CancelFunc
	done   chan struct{}
	err    error              // published by closing done
	ready  PublishedPublicURL // published by the activation channel
}

type Publishers struct {
	config      PublisherConfig
	base        publisher.Config
	namespace   string
	database    *clientstate.Database
	ctx         context.Context
	cancel      context.CancelFunc
	processes   []*publicURLProcess
	failures    chan error
	failureOnce sync.Once
	run         func(context.Context, publisher.Config) error
}

func OpenPublishers(ctx context.Context, config PublisherConfig) (_ *Publishers, retErr error) {
	if config.Parallel < 1 || config.StartParallel < 0 || config.ReadyTimeout <= 0 || config.StopTimeout <= 0 || config.DrainTime < 0 {
		return nil, errors.New("publisher concurrency and deadlines must be positive")
	}
	if config.Transport != "auto" && config.Transport != "mixed" && config.Transport != "quic" && config.Transport != "tcp" {
		return nil, errors.New("publisher transport must be auto, mixed, quic, or tcp")
	}
	database, err := clientstate.Open(ctx, config.StateRoot)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, database.Close())
		}
	}()
	authConfig := clientauth.Config{
		ServerEndpoint: config.Server, State: database, HTTPClient: config.HTTPClient,
		Diagnostics: io.Discard,
	}
	if config.LoginToken != "" {
		authConfig.ForceLoginToken = true
		authConfig.LoginToken = func() (credentials.LoginToken, error) { return credentials.LoginToken(config.LoginToken), nil }
	} else {
		authConfig.AuthenticationPrompt = func(oidcauth.Prompt) error {
			return fmt.Errorf("saved login needs renewal; run tnl login --server=%s", config.Server)
		}
		store, err := database.Server(ctx, config.Server)
		if err != nil {
			return nil, err
		}
		if session, found, err := store.ControlSession(ctx); err != nil {
			return nil, err
		} else if !found || !session.RefreshExpiresAt.After(time.Now().Add(time.Minute)) {
			return nil, fmt.Errorf("no usable saved login for %s; run tnl login --server=%s", config.Server, config.Server)
		}
	}
	var auth *clientauth.Client
	authCtx, cancelAuth := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelAuth()
	for {
		auth, err = clientauth.Authenticate(authCtx, authConfig)
		if !errors.Is(err, controlclient.ErrUnavailable) {
			break
		}
		if waitErr := WaitUntil(authCtx, time.Now().Add(time.Second)); waitErr != nil {
			return nil, errors.Join(err, waitErr)
		}
	}
	if err != nil {
		return nil, err
	}
	managedDomain := auth.Discovery.ManagedDeploymentDomain
	if managedDomain == "" {
		return nil, errors.New("server has no managed deployment domain for benchmark public URLs")
	}
	if config.Domain != "" && managedDomain != config.Domain {
		return nil, errors.New("configured domain differs from control discovery")
	}
	identity, err := auth.Authority.IdentityContext(ctx)
	if err != nil {
		return nil, err
	}
	var membership authorityv1.Membership
	for _, member := range identity.Memberships {
		if member.TeamId == identity.PersonalTeamId {
			membership = member
			break
		}
	}
	if membership.Id == "" {
		return nil, errors.New("publisher identity has no personal membership")
	}
	team, err := auth.Authority.GetTeam(ctx, membership.TeamId)
	if err != nil {
		return nil, err
	}
	domains, err := auth.Authority.ListTeamDomains(ctx, team.Id)
	if err != nil {
		return nil, err
	}
	var domain authorityv1.Domain
	for _, candidate := range domains.Domains {
		if candidate.Kind == authorityv1.Managed && candidate.State == authorityv1.DomainStateReady && candidate.CanonicalDomain == managedDomain {
			domain = candidate
			break
		}
	}
	if domain.Id == "" || team.PolicyRevision < 0 {
		return nil, errors.New("publisher domain or policy is not ready")
	}
	store, err := database.Server(ctx, auth.ServerEndpoint)
	if err != nil {
		return nil, err
	}
	groupCtx, cancel := context.WithCancel(ctx)
	return &Publishers{config: config, database: database, ctx: groupCtx, cancel: cancel,
		namespace: membership.ManagedLabel + "." + domain.CanonicalDomain, failures: make(chan error, 1), run: publisher.Run,
		base: publisher.Config{Control: auth.Control, State: store, Target: config.Target, DrainTime: config.DrainTime,
			RequestLimit: config.RequestLimit,
			Ephemeral:    config.Ephemeral,
			TeamID:       team.Id, MembershipID: membership.Id, DomainID: domain.Id, PublicURLScope: controlv1.Member,
			PolicyRevision: uint64(team.PolicyRevision), AllowedIPPrefixes: config.AllowedIPPrefixes,
			QUICConnector: muxsession.QUICConnector{TLSConfig: config.RelayTLS, Config: benchmarkQUICConfig(config.QUICDisablePathMTUDiscovery, config.QUICQlog, config.QUICKeepAlive)},
			TCPConnector:  muxsession.TLSYamuxConnector{TLSConfig: config.RelayTLS},
			FallbackDelay: 250 * time.Millisecond},
	}, nil
}

func benchmarkQUICConfig(disablePathMTUDiscovery, trace bool, keepAlive time.Duration) muxsession.QUICConfig {
	if !disablePathMTUDiscovery && !trace && keepAlive == 0 {
		return muxsession.QUICConfig{}
	}
	config := &quic.Config{DisablePathMTUDiscovery: disablePathMTUDiscovery, KeepAlivePeriod: keepAlive}
	if trace {
		config.Tracer = qlog.DefaultConnectionTracer
	}
	return muxsession.QUICConfig{Config: config}
}

func (g *Publishers) Failures() <-chan error { return g.failures }
func (g *Publishers) Started() int           { return len(g.processes) }

// Start returns any ready results collected before failure, then cancels the
// group. the coordinator must call Close even after partial activation and
// call lifecycle methods serially.
func (g *Publishers) Start(ctx context.Context, indexes []int) ([]PublishedPublicURL, error) {
	type activation struct {
		process *publicURLProcess
		err     error
	}
	parallel := g.config.StartParallel
	if parallel == 0 {
		parallel = g.config.Parallel
	}
	activated := make(chan activation, parallel)
	start := func(index int) {
		publicURLCtx, cancel := context.WithCancel(g.ctx)
		process := &publicURLProcess{index: index, cancel: cancel, done: make(chan struct{})}
		g.processes = append(g.processes, process)
		cfg := g.base
		prefix := g.config.HostnamePrefix
		if prefix == "" {
			prefix = "tnlbench"
		}
		cfg.Hostname = fmt.Sprintf("%s-r%06d.%s", prefix, index, g.namespace)
		if g.config.Report != nil {
			cfg.Logf = func(format string, args ...any) {
				g.config.Report(index, fmt.Errorf(format, args...))
			}
		}
		transport := g.config.Transport
		if transport == "mixed" {
			if index%2 == 0 {
				transport = "quic"
			} else {
				transport = "tcp"
			}
		}
		if transport == "quic" {
			cfg.TCPConnector = disabledConnector{}
		}
		if transport == "tcp" {
			cfg.QUICConnector = disabledConnector{}
		}
		go func() {
			began := time.Now()
			ready := make(chan struct{})
			var once sync.Once
			cfg.Observe = func(event publisher.Event) error {
				if g.config.Observe != nil {
					if err := g.config.Observe(index, event); err != nil {
						return err
					}
				}
				if event.Type == publisher.EventReady {
					once.Do(func() {
						process.ready = PublishedPublicURL{Index: index, Ready: event, Activation: time.Since(began)}
						close(ready)
					})
				}
				return nil
			}
			go func() {
				process.err = g.run(publicURLCtx, cfg)
				if publicURLCtx.Err() == nil {
					process.err = fmt.Errorf("publisher %d exited unexpectedly: %w", index, errors.Join(errors.New("publisher exited"), process.err))
					g.failureOnce.Do(func() {
						g.failures <- process.err
					})
				}
				close(process.done)
			}()
			timer := time.NewTimer(g.config.ReadyTimeout)
			defer timer.Stop()
			var err error
			select {
			case <-ready:
			case <-process.done:
				err = errors.Join(errors.New("publisher exited before readiness"), process.err)
			case <-timer.C:
				err = fmt.Errorf("publisher %d readiness exceeded %s", index, g.config.ReadyTimeout)
			case <-ctx.Done():
				err = ctx.Err()
			case <-publicURLCtx.Done():
				err = publicURLCtx.Err()
			}
			activated <- activation{process, err}
		}()
	}
	var result []PublishedPublicURL
	next, active := 0, 0
	var firstErr error
	var capture sync.Once
	for next < len(indexes) || active > 0 {
		for firstErr == nil && next < len(indexes) && active < parallel {
			if ctx.Err() != nil {
				firstErr = ctx.Err()
				break
			}
			start(indexes[next])
			next++
			active++
		}
		if active == 0 {
			break
		}
		value := <-activated
		active--
		if value.err != nil {
			if firstErr == nil && g.config.OnActivationFailure != nil {
				g.config.OnActivationFailure(value.process.index)
			}
			firstErr = errors.Join(firstErr, value.err)
		} else {
			result = append(result, value.process.ready)
		}
		if firstErr != nil {
			if g.config.OnFailure != nil {
				capture.Do(g.config.OnFailure)
			}
			g.cancel()
		}
	}
	return result, firstErr
}

// Stop leaves public URLs running until their bounded shutdown slot is available.
func (g *Publishers) Stop(ctx context.Context, indexes []int) (ShutdownResult, error) {
	result := ShutdownResult{StartedAt: time.Now()}
	wanted := make(map[int]bool, len(indexes))
	for _, index := range indexes {
		wanted[index] = true
	}
	var selected []*publicURLProcess
	for _, process := range g.processes {
		if wanted[process.index] {
			selected = append(selected, process)
		}
	}
	durations := make([]time.Duration, len(selected))
	errorsByPublicURL := make([]error, len(selected))
	var workers sync.WaitGroup
	var firstFailure sync.Once
	parallel := min(g.config.Parallel, len(selected))
	for worker := range parallel {
		workers.Go(func() {
			for i := worker; i < len(selected); i += parallel {
				process := selected[i]
				started := time.Now()
				process.cancel()
				stopCtx, cancel := context.WithTimeout(ctx, g.config.StopTimeout)
				select {
				case <-process.done:
					if !CancellationOnly(process.err) {
						errorsByPublicURL[i] = fmt.Errorf("stop publisher %d: %w", process.index, process.err)
					}
				case <-stopCtx.Done():
					errorsByPublicURL[i] = fmt.Errorf("stop publisher %d: %w", process.index, stopCtx.Err())
				}
				cancel()
				if errorsByPublicURL[i] != nil && g.config.OnFailure != nil {
					firstFailure.Do(g.config.OnFailure)
				}
				durations[i] = time.Since(started)
			}
		})
	}
	workers.Wait()
	result.Duration = time.Since(result.StartedAt)
	result.Timings = durations
	result.Attempts = len(selected)
	for _, err := range errorsByPublicURL {
		if err != nil {
			result.Failures++
		} else {
			result.Successes++
		}
	}
	return result, errors.Join(errorsByPublicURL...)
}

func (g *Publishers) Close(ctx context.Context) (ShutdownResult, error) {
	indexes := make([]int, len(g.processes))
	for i, process := range g.processes {
		indexes[i] = process.index
	}
	result, err := g.Stop(ctx, indexes)
	g.cancel()
	// do not close SQLite while a publisher still uses it.
	for _, process := range g.processes {
		select {
		case <-process.done:
		default:
			return result, err
		}
	}
	return result, errors.Join(err, g.database.Close())
}

type disabledConnector struct{}

func (disabledConnector) Connect(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
	return nil, errors.New("transport disabled by workload")
}

// errors.Is alone would hide a close failure joined with cancellation.
func CancellationOnly(err error) bool {
	if err == nil || err == context.Canceled {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !CancellationOnly(child) {
				return false
			}
		}
		return true
	}
	if wrapped := errors.Unwrap(err); wrapped != nil {
		return CancellationOnly(wrapped)
	}
	return false
}
