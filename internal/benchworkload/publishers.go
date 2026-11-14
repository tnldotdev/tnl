package benchworkload

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/tnldotdev/tnl/internal/client/auth"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// TransportChoice selects a benchmark publisher cohort or production fallback.
type TransportChoice string

const (
	TransportAuto  TransportChoice = "auto"
	TransportMixed TransportChoice = "mixed"
	TransportQUIC  TransportChoice = "quic"
	TransportTCP   TransportChoice = "tcp"
)

func (transport TransportChoice) Valid() bool {
	return transport == TransportAuto || transport == TransportMixed || transport == TransportQUIC || transport == TransportTCP
}

type PublisherConfig struct {
	Server, Domain, StateRoot, Target string
	HostnamePrefix                    string
	Ephemeral                         bool
	HTTPClient                        *http.Client
	RelayTLS                          *tls.Config
	AllowedIPPrefixes                 []string
	// mixed forces alternating QUIC/TLS-TCP cohorts; auto uses production fallback.
	Transport                   TransportChoice
	QUICDisablePathMTUDiscovery bool
	QUICQlog                    bool
	QUICKeepAlive               time.Duration
	Parallel                    int
	Concurrency                 int
	RateRequests                int
	// StartParallel overrides Parallel only during activation; shutdown has its own bound.
	StartParallel             int
	ReadyTimeout, StopTimeout time.Duration
	DrainTime                 time.Duration
	OnFailure                 func()
	OnActivationFailure       func(index int)
	ObserveTransport          func(int, TransportObservation) error
	Report                    func(index int, err error)
}

// service run measurements contain publication identity, never run credentials.
type ServiceRun struct {
	ServiceID string                    `json:"service_id"`
	RunID     string                    `json:"service_run_id"`
	Number    int64                     `json:"run_number"`
	Endpoint  controlv1.ServiceEndpoint `json:"endpoint"`
}

func (r ServiceRun) Valid() bool {
	return opaqueid.Valid(r.ServiceID, opaqueid.ServicePrefix) && opaqueid.Valid(r.RunID, opaqueid.ServiceRunPrefix) &&
		r.Number > 0 && r.Endpoint.Public && r.Endpoint.Port == 443 &&
		serviceendpoint.Valid("http", r.Endpoint.Hostname, r.Endpoint.Port, r.Endpoint.Public)
}

func (r ServiceRun) URL() string { return "https://" + r.Endpoint.Hostname }

type PublishedService struct {
	Index      int           `json:"index"`
	Run        ServiceRun    `json:"run"`
	Activation time.Duration `json:"activation"`
}

type TransportObservation struct {
	Slot          uint8            `json:"connection_slot"`
	Transport     tunnel.Transport `json:"transport"`
	PreferredTCP  bool             `json:"preferred_tcp"`
	FirstFallback bool             `json:"first_fallback"`
}

type ShutdownResult struct {
	StartedAt                     time.Time     `json:"started_at"`
	Duration                      time.Duration `json:"duration"`
	Attempts, Successes, Failures int
	Timings                       []time.Duration `json:"timings"`
}

type serviceProcess struct {
	index  int
	cancel context.CancelFunc
	done   chan struct{}
	err    error            // published by closing done
	ready  PublishedService // published by the activation channel
}

type Publishers struct {
	config      PublisherConfig
	base        publisherservice.RunConfig
	database    *clientstate.Database
	ctx         context.Context
	cancel      context.CancelFunc
	processes   []*serviceProcess
	failures    chan error
	failureOnce sync.Once
	run         func(context.Context, publisherservice.RunConfig) error
	prepare     func(context.Context, int, publisherservice.RunConfig) (publisherservice.RunConfig, func(context.Context) error, error)
}

func OpenPublishers(ctx context.Context, config PublisherConfig) (_ *Publishers, retErr error) {
	if config.Parallel < 1 || config.StartParallel < 0 || config.RateRequests < 0 || config.ReadyTimeout <= 0 || config.StopTimeout <= 0 || config.DrainTime < 0 {
		return nil, errors.New("publisher concurrency and deadlines must be positive")
	}
	if !config.Transport.Valid() {
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
	authConfig := auth.Config{
		ServerEndpoint: config.Server, State: database, HTTPClient: config.HTTPClient,
		Diagnostics: io.Discard,
	}
	{
		store, err := database.Server(ctx, config.Server)
		if err != nil {
			return nil, err
		}
		if session, found, err := store.ControlSession(ctx); err != nil {
			return nil, err
		} else if !found || !session.RefreshExpiresAt.After(time.Now().Add(time.Minute)) {
			return nil, fmt.Errorf("no usable saved login for %s; run tnl auth login --server=%s", config.Server, config.Server)
		}
	}
	declaration, target, trust, err := benchmarkDeclaration(config)
	if err != nil {
		return nil, err
	}
	authenticate := auth.Authenticate
	var auth *auth.Client
	authCtx, cancelAuth := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelAuth()
	for {
		auth, err = authenticate(authCtx, authConfig)
		if !errors.Is(err, clientcontrol.ErrUnavailable) {
			break
		}
		if waitErr := WaitUntil(authCtx, time.Now().Add(time.Second)); waitErr != nil {
			return nil, errors.Join(err, waitErr)
		}
	}
	if err != nil {
		return nil, err
	}
	managedDomain := auth.Discovery.ManagedDomain
	if managedDomain == "" {
		return nil, errors.New("server has no managed domain for benchmark services")
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
	var prepare func(context.Context, int, publisherservice.RunConfig) (publisherservice.RunConfig, func(context.Context) error, error)
	namespace := membership.ManagedLabel + "." + domain.CanonicalDomain
	if config.Ephemeral {
		native, _, err := publisheridentity.EnsureNamespace(ctx, store, auth.Control, auth.Authority, team.Id, domain.Id, namespace)
		if err != nil {
			return nil, err
		}
		// supply explicit service capabilities to the existing namespace key;
		// neither allocation nor worker selection issues a replacement grant.
		native.Services, native.Allocations = auth.Control, auth.Control
		prepare = func(ctx context.Context, _ int, cfg publisherservice.RunConfig) (publisherservice.RunConfig, func(context.Context) error, error) {
			worker, err := native.Fork()
			if err != nil {
				return cfg, nil, err
			}
			invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
			if err != nil {
				return cfg, nil, err
			}
			request := controlv1.AllocateServiceRequest{InvocationId: invocation, Configuration: declaration}
			service, cleanup, err := allocateBenchmarkService(ctx, worker, request)
			if err != nil {
				return cfg, cleanup, err
			}
			if err := validateBenchmarkService(service, team.Id, domain.Id, "", true, trust); err != nil {
				return cfg, cleanup, err
			}
			return bindBenchmarkService(cfg, worker, service), cleanup, nil
		}
	} else {
		prepare = func(ctx context.Context, index int, cfg publisherservice.RunConfig) (publisherservice.RunConfig, func(context.Context) error, error) {
			prefix := config.HostnamePrefix
			if prefix == "" {
				prefix = "tnl-load"
			}
			name := fmt.Sprintf("%s-r%06d", prefix, index)
			hostname := name + "." + namespace
			desired := declaration
			desired.Name, desired.Hostname, desired.DomainId = &name, &hostname, &domain.Id
			key := sha256.Sum256([]byte(team.Id + "\x00" + hostname))
			service, err := auth.Control.CreateService(ctx, team.Id, name, fmt.Sprintf("benchmark-%x", key), controlv1.ServiceMetadata{}, &desired)
			if err != nil {
				return cfg, nil, err
			}
			if err := validateBenchmarkService(service, team.Id, domain.Id, hostname, false, trust); err != nil {
				return cfg, nil, err
			}
			native, _, err := publisheridentity.EnsureServiceOwner(ctx, store, auth.Control, auth.Authority, service)
			if err != nil {
				return cfg, nil, err
			}
			return bindBenchmarkService(cfg, native, service), nil, nil
		}
	}
	groupCtx, cancel := context.WithCancel(ctx)
	base := publisherservice.RunConfig{State: store, Target: target, DrainTime: config.DrainTime, TransportTLS: config.RelayTLS}
	if diagnostic := benchmarkQUICConfig(config.QUICDisablePathMTUDiscovery, config.QUICQlog, config.QUICKeepAlive); diagnostic.Config != nil {
		base.RelayQUIC = muxsession.OwnedQUICConnector{TLSConfig: config.RelayTLS, Config: diagnostic}
	}
	return &Publishers{config: config, database: database, ctx: groupCtx, cancel: cancel,
		failures: make(chan error, 1), run: publisherservice.Publish, prepare: prepare, base: base,
	}, nil
}

type benchmarkServiceAllocator interface {
	AllocateService(context.Context, controlv1.AllocateServiceRequest) (controlv1.Service, error)
	DeleteAllocatedService(context.Context, string) error
}

func allocateBenchmarkService(ctx context.Context, native benchmarkServiceAllocator, request controlv1.AllocateServiceRequest) (controlv1.Service, func(context.Context) error, error) {
	service, err := native.AllocateService(ctx, request)
	return service, func(cleanup context.Context) error {
		id := service.Id
		var recoveryErr error
		if id == "" {
			// an uncertain response authorizes no deletion. recover only this
			// worker's original invocation before asking it to delete anything.
			recovered, err := native.AllocateService(cleanup, request)
			id, recoveryErr = recovered.Id, err
			if id == "" {
				return errors.Join(errors.New("benchmark allocation cleanup could not recover its exact service"), recoveryErr)
			}
		}
		return errors.Join(recoveryErr, native.DeleteAllocatedService(cleanup, id))
	}, err
}

func benchmarkDeclaration(config PublisherConfig) (controlv1.ProjectServiceConfiguration, string, *targettrust.Snapshot, error) {
	declaration := controlv1.ProjectServiceConfiguration{
		Protocol: new(controlv1.ServiceProtocolHTTP), Public: new(true), Ephemeral: &config.Ephemeral,
		Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: new(controlv1.VisitorAccessMode("anonymous"))}},
	}
	origin, err := targetsyntax.NormalizeTarget(config.Target)
	if err != nil {
		return declaration, "", nil, err
	}
	address, err := url.Parse(origin)
	if err != nil {
		return declaration, "", nil, err
	}
	declaration.Target = address.Host
	var trust *targettrust.Snapshot
	if address.Scheme == "https" {
		desired, err := targettrust.NewDeclaration(address.Hostname(), nil)
		if err != nil {
			return declaration, "", nil, err
		}
		snapshot, err := desired.Snapshot()
		if err != nil {
			return declaration, "", nil, err
		}
		trust = snapshot
		declaration.TargetTls = &controlv1.ProjectTargetTLS{Hostname: desired.Hostname, Digest: desired.Digest}
	}
	if config.AllowedIPPrefixes != nil {
		if len(config.AllowedIPPrefixes) == 0 {
			return declaration, "", nil, errors.New("benchmark IP policy must not be empty when supplied")
		}
		prefixes := slices.Clone(config.AllowedIPPrefixes)
		declaration.Http.Access.Ip = &prefixes
	}
	if config.Concurrency < 0 || config.RateRequests < 0 {
		return declaration, "", nil, errors.New("benchmark HTTP request limits must not be negative")
	}
	if config.Concurrency > 0 || config.RateRequests > 0 {
		declaration.Http.Limits = &controlv1.ProjectHTTPApplicationLimits{}
		if config.Concurrency > 0 {
			declaration.Http.Limits.Concurrency = &config.Concurrency
		}
		if config.RateRequests > 0 {
			declaration.Http.Limits.Rate = &controlv1.ProjectApplicationRate{Count: config.RateRequests, Per: "1s", Burst: &config.RateRequests}
		}
	}
	return declaration, address.Host, trust, nil
}

func validateBenchmarkService(service controlv1.Service, team, domain, hostname string, ephemeral bool, trust *targettrust.Snapshot) error {
	if !opaqueid.Valid(service.Id, opaqueid.ServicePrefix) || service.TeamId != team || service.DomainId == nil || *service.DomainId != domain ||
		!service.Enabled || service.Ephemeral != ephemeral || service.Protocol != controlv1.ServiceProtocolHTTP ||
		service.Endpoint == nil || !service.Endpoint.Public || service.Endpoint.Port != 443 ||
		!serviceendpoint.Valid("http", service.Endpoint.Hostname, service.Endpoint.Port, service.Endpoint.Public) ||
		hostname != "" && service.Endpoint.Hostname != hostname {
		return publisheridentity.ErrScope
	}
	return publisheridentity.MatchServiceDeclaration(service, "http", trust)
}

func bindBenchmarkService(cfg publisherservice.RunConfig, native *publisheridentity.Native, service controlv1.Service) publisherservice.RunConfig {
	cfg.Control, cfg.Access, cfg.ServiceID = native, native.Access, service.Id
	cfg.PublisherIdentityID, cfg.PublisherGrantID, cfg.PublisherKeyID = native.PublisherIdentityID(), native.PublisherGrantID(), native.PublisherKeyID()
	cfg.Metadata = publisheridentity.ServiceMetadata(service)
	cfg.Metadata.Endpoint = service.Endpoint
	return cfg
}

func benchmarkQUICConfig(disablePathMTUDiscovery, trace bool, keepAlive time.Duration) muxsession.QUICConfig {
	if !disablePathMTUDiscovery && !trace && keepAlive == 0 {
		return muxsession.QUICConfig{}
	}
	config := &quic.Config{EnableDatagrams: true, DisablePathMTUDiscovery: disablePathMTUDiscovery, KeepAlivePeriod: keepAlive}
	if trace {
		config.Tracer = qlog.DefaultConnectionTracer
	}
	return muxsession.QUICConfig{Config: config}
}

func (g *Publishers) Failures() <-chan error { return g.failures }
func (g *Publishers) Started() int           { return len(g.processes) }

// start returns any ready results collected before failure, then cancels the
// group. the coordinator must call Close even after partial activation and
// call lifecycle methods serially.
func (g *Publishers) Start(ctx context.Context, indexes []int) ([]PublishedService, error) {
	type activation struct {
		process *serviceProcess
		err     error
	}
	parallel := g.config.StartParallel
	if parallel == 0 {
		parallel = g.config.Parallel
	}
	activated := make(chan activation, parallel)
	start := func(index int) {
		serviceCtx, cancel := context.WithCancel(g.ctx)
		process := &serviceProcess{index: index, cancel: cancel, done: make(chan struct{})}
		g.processes = append(g.processes, process)
		go func() {
			began := time.Now()
			ready := make(chan struct{})
			go func() {
				cfg := g.base
				var cleanup func(context.Context) error
				if g.prepare != nil {
					var err error
					cfg, cleanup, err = g.prepare(serviceCtx, index, cfg)
					process.err = err
				}
				if process.err == nil {
					runCtx, stop := context.WithCancelCause(serviceCtx)
					var run ServiceRun
					cfg.Prepared = func(preparation controlv1.ServiceRunPreparation) error {
						if cfg.Metadata.Endpoint == nil || preparation.ServiceId != cfg.ServiceID || preparation.Hostname != cfg.Metadata.Endpoint.Hostname || run.RunID != "" {
							return errors.New("benchmark preparation changed the selected service endpoint")
						}
						run = ServiceRun{ServiceID: preparation.ServiceId, RunID: preparation.ServiceRunId, Number: preparation.RunNumber, Endpoint: *cfg.Metadata.Endpoint}
						if !run.Valid() {
							return errors.New("benchmark preparation has invalid service run identity")
						}
						return nil
					}
					cfg.Ready = sync.OnceValue(func() error {
						if !run.Valid() {
							return errors.New("benchmark readiness preceded a validated service run")
						}
						process.ready = PublishedService{Index: index, Run: run, Activation: time.Since(began)}
						close(ready)
						return nil
					})
					connect := cfg.Connect
					if connect == nil {
						connect = func(ctx context.Context, bound *publisherservice.Bound, slot uint8, options publisherservice.ConnectOptions) (publisherservice.SlotSession, error) {
							return bound.ConnectSlot(ctx, slot, options)
						}
					}
					cfg.Connect = g.observeConnections(index, connect, stop)
					switch g.cohort(index) {
					case TransportQUIC:
						cfg.RelayTCP = disabledConnector{}
					case TransportTCP:
						cfg.RelayQUIC = disabledConnector{}
					}
					process.err = g.run(runCtx, cfg)
					if cause := context.Cause(runCtx); cause != nil && !failure.Only(cause, context.Canceled) {
						process.err = errors.Join(process.err, cause)
					}
					stop(nil)
				}
				if cleanup != nil {
					cleanupCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
					process.err = errors.Join(process.err, cleanup(cleanupCtx))
					stop()
				}
				if serviceCtx.Err() == nil {
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
			case <-serviceCtx.Done():
				err = serviceCtx.Err()
			}
			activated <- activation{process, err}
		}()
	}
	var result []PublishedService
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

func (g *Publishers) cohort(index int) TransportChoice {
	if g.config.Transport != TransportMixed {
		return g.config.Transport
	}
	if index%2 == 0 {
		return TransportQUIC
	}
	return TransportTCP
}

func (g *Publishers) observeConnections(index int, connect func(context.Context, *publisherservice.Bound, uint8, publisherservice.ConnectOptions) (publisherservice.SlotSession, error), stop context.CancelCauseFunc) func(context.Context, *publisherservice.Bound, uint8, publisherservice.ConnectOptions) (publisherservice.SlotSession, error) {
	var fallback sync.Once
	return func(ctx context.Context, bound *publisherservice.Bound, slot uint8, options publisherservice.ConnectOptions) (publisherservice.SlotSession, error) {
		switch g.cohort(index) {
		case TransportQUIC:
			options.PreferTCP = false
		case TransportTCP:
			options.PreferTCP = true
		}
		session, err := connect(ctx, bound, slot, options)
		if err == nil && session == nil {
			err = errors.New("benchmark connection returned no claimed slot session")
		}
		if err != nil {
			if session != nil {
				if cleanupErr := session.Close(); cleanupErr != nil {
					err = errors.Join(err, cleanupErr)
					stop(err)
				}
			}
			if g.config.Report != nil && !failure.Only(err, context.Canceled) {
				g.config.Report(index, err)
			}
			return nil, err
		}
		observation := TransportObservation{Slot: slot, Transport: session.Transport(), PreferredTCP: options.PreferTCP}
		if g.cohort(index) == TransportAuto && observation.Transport == tunnel.TransportTLSTCP && !options.PreferTCP {
			fallback.Do(func() { observation.FirstFallback = true })
		}
		if g.config.ObserveTransport != nil {
			if err := g.config.ObserveTransport(index, observation); err != nil {
				err = errors.Join(err, session.Close())
				stop(err)
				return nil, err
			}
		}
		return session, nil
	}
}

// stop leaves service runs active until their bounded shutdown slot is available.
func (g *Publishers) Stop(ctx context.Context, indexes []int) (ShutdownResult, error) {
	result := ShutdownResult{StartedAt: time.Now()}
	wanted := make(map[int]bool, len(indexes))
	for _, index := range indexes {
		wanted[index] = true
	}
	var selected []*serviceProcess
	for _, process := range g.processes {
		if wanted[process.index] {
			selected = append(selected, process)
		}
	}
	durations := make([]time.Duration, len(selected))
	errorsByService := make([]error, len(selected))
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
					if process.err != nil && !failure.Only(process.err, context.Canceled) {
						errorsByService[i] = fmt.Errorf("stop publisher %d: %w", process.index, process.err)
					}
				case <-stopCtx.Done():
					errorsByService[i] = fmt.Errorf("stop publisher %d: %w", process.index, stopCtx.Err())
				}
				cancel()
				if errorsByService[i] != nil && g.config.OnFailure != nil {
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
	for _, err := range errorsByService {
		if err != nil {
			result.Failures++
		} else {
			result.Successes++
		}
	}
	return result, errors.Join(errorsByService...)
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
