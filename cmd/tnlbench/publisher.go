package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publisherCommand struct {
	workerCommand
	ServerURL          string        `name:"server" env:"TNL_BENCH_SERVER" required:"" help:"Control URL."`
	LoginToken         string        `name:"login-token" env:"TNL_BENCH_LOGIN_TOKEN" required:"" help:"Built-in authority login token."`
	ControlCAFile      string        `name:"control-ca-file" env:"TNL_BENCH_CONTROL_CA_FILE" type:"path" help:"Optional PEM CA for the control API."`
	HostnameSuffix     string        `name:"hostname-suffix" env:"TNL_BENCH_HOSTNAME_SUFFIX" required:"" help:"Managed deployment domain used by benchmark routes."`
	Routes             int           `name:"routes" env:"TNL_BENCH_ROUTES" required:"" help:"Total route count in the cell."`
	AssignedRoutes     int           `name:"assigned-routes" env:"TNL_BENCH_ASSIGNED_ROUTES" required:"" help:"Routes assigned to this worker."`
	RoutesPerPublisher int           `name:"routes-per-publisher" env:"TNL_BENCH_ROUTES_PER_PUBLISHER" required:"" help:"Stable route-index band assigned to each publisher generator."`
	RoutesPerChurn     int           `name:"routes-per-churn-route" env:"TNL_BENCH_ROUTES_PER_CHURN_ROUTE" required:"" help:"Active routes represented by each lifecycle-churn route."`
	StateRoot          string        `name:"state-root" env:"TNL_BENCH_STATE_ROOT" default:"/state" type:"path" help:"Persistent state root for this publisher generator."`
	FreshRate          int           `name:"fresh-connections-per-second" env:"TNL_BENCH_FRESH_CONNECTIONS_PER_SECOND" required:"" help:"Total fresh visitor connection rate for the cell."`
	HeldStreams        int           `name:"held-streams" env:"TNL_BENCH_HELD_STREAMS" help:"Total held-open streams for the cell."`
	ChurnRate          int           `name:"lifecycle-churn-per-second" env:"TNL_BENCH_LIFECYCLE_CHURN_PER_SECOND" help:"Total route-session lifecycle operations per second for the cell."`
	AssignedChurnRate  int           `name:"assigned-lifecycle-churn-per-second" env:"TNL_BENCH_ASSIGNED_LIFECYCLE_CHURN_PER_SECOND" help:"Route-session lifecycle operations per second assigned to this publisher."`
	Parallel           int           `name:"parallel" env:"TNL_BENCH_PARALLEL" default:"16" help:"Maximum concurrent route operations."`
	PayloadBytes       int           `name:"payload-bytes" env:"TNL_BENCH_PAYLOAD_BYTES" default:"16384" help:"Fresh-response payload size."`
	MetricsURLs        []string      `name:"metrics-url" env:"TNL_BENCH_METRICS_URLS" help:"Private process metrics URL; repeat for each process."`
	DiagnosticURLs     []string      `name:"database-diagnostics-url" env:"TNL_BENCH_DATABASE_DIAGNOSTICS_URLS" help:"Private control database diagnostics URL; repeat for each control process."`
	NoProgressTimeout  time.Duration `name:"no-progress-timeout" env:"TNL_BENCH_NO_PROGRESS_TIMEOUT" default:"2m" help:"Maximum time without another route becoming ready during activation."`
	Timeout            time.Duration `name:"timeout" env:"TNL_BENCH_TIMEOUT" default:"30m" help:"Worker deadline."`
	onFailure          func()
}

func (c publisherCommand) Validate() error {
	if err := c.workerCommand.validate(); err != nil {
		return err
	}
	if c.Routes <= 0 || c.AssignedRoutes <= 0 || c.RoutesPerPublisher <= 0 || c.RoutesPerPublisher > 10_000 ||
		c.RoutesPerChurn <= 0 || c.RoutesPerChurn > c.RoutesPerPublisher ||
		c.RoutesPerPublisher%c.RoutesPerChurn != 0 ||
		c.AssignedRoutes != len(benchmarkRouteIndexes(c.Routes, c.RoutesPerPublisher, c.WorkerCount, c.WorkerIndex)) {
		return errors.New("publisher route assignment is invalid")
	}
	if c.FreshRate <= 0 || c.HeldStreams < 0 || c.ChurnRate < 0 || c.AssignedChurnRate < 0 || c.AssignedChurnRate > c.ChurnRate {
		return errors.New("publisher cell load shape is invalid")
	}
	if c.AssignedChurnRate != benchmarkPublisherChurnAssignment(c.ChurnRate, c.WorkerCount, c.WorkerIndex) {
		return errors.New("publisher lifecycle churn assignment is invalid")
	}
	if c.Parallel <= 0 || c.Parallel > 256 || c.PayloadBytes <= 0 || c.PayloadBytes > 16<<20 || c.Timeout <= 0 || c.NoProgressTimeout < 0 {
		return errors.New("publisher parallelism, payload, or timeout is invalid")
	}
	if _, err := credentials.ParseLoginToken(credentials.LoginToken(c.LoginToken)); err != nil {
		return errors.New("publisher login token is invalid")
	}
	if !filepath.IsAbs(c.StateRoot) {
		return errors.New("publisher state root must be absolute")
	}
	hostname, err := naming.CanonicalizeHostname(c.HostnameSuffix)
	if err != nil || hostname != c.HostnameSuffix {
		return errors.New("hostname suffix must be canonical")
	}
	return nil
}

type routeProcess struct {
	index    int
	hostname string
	routeID  string
	cancel   context.CancelFunc
	done     chan error
}

type benchmarkRouteContext struct {
	teamID         string
	membershipID   string
	domainID       string
	routeScope     controlv1.RouteScope
	policyRevision uint64
}

type benchmarkRouteSpec struct {
	index        int
	hostname     string
	namespace    string
	control      *controlclient.Client
	routeContext benchmarkRouteContext
	state        *clientstate.Store
}

func (c publisherCommand) run(parent context.Context) error {
	started := time.Now().UTC()
	ctx, cancel := context.WithTimeout(parent, c.Timeout)
	defer cancel()
	coordinator, err := newCoordinatorClient(c.CoordinatorURL, c.CoordinatorToken)
	if err != nil {
		return err
	}
	worker := resultWorker{Kind: "publisher", Index: c.WorkerIndex, Count: c.WorkerCount}
	configuration := resultConfiguration{
		Axis: c.Axis, Sequence: c.Sequence, Routes: c.Routes, AssignedRoutes: c.AssignedRoutes,
		FreshConnectionsPerSecond: c.FreshRate, HeldStreams: c.HeldStreams, PayloadBytes: c.PayloadBytes,
		LifecycleChurnPerSecond: c.ChurnRate, AssignedLifecycleChurn: c.AssignedChurnRate,
	}
	failureMetricsURLs := c.MetricsURLs
	if c.WorkerIndex != 0 {
		c.MetricsURLs = nil
	}
	resources := sampleResources(ctx, c.MetricsURLs, "before_activation")
	sampler := startResourceSampler(context.WithoutCancel(ctx), c.MetricsURLs, 5*time.Second)
	defer sampler.Stop()
	failure := &failureCapture{ctx: ctx, metricsURLs: failureMetricsURLs, diagnosticURLs: c.DiagnosticURLs}
	c.onFailure = failure.capture
	result, runErr := c.execute(ctx, worker, configuration)
	if runErr != nil {
		failure.capture()
	}
	if runErr != nil && result.SchemaVersion == 0 {
		partial := result
		result = failedResult(c.CellID, c.Suite, c.Repetition, worker, configuration, started, runErr)
		result.Phases = append(partial.Phases, result.Phases...)
	}
	resources = append(resources, sampler.Stop()...)
	result.Resources = append(resources, result.Resources...)
	result.Resources = append(result.Resources, failure.resources...)
	result.DroppedResourceSamples = sampler.dropped
	result.DatabaseDiagnostics = failure.diagnostics
	postCtx, postCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer postCancel()
	if err := coordinator.postResult(postCtx, result); err != nil {
		return errors.Join(runErr, fmt.Errorf("post publisher result: %w", err))
	}
	return runErr
}

func (c publisherCommand) execute(ctx context.Context, worker resultWorker, configuration resultConfiguration) (result benchmarkResult, retErr error) {
	coordinator, _ := newCoordinatorClient(c.CoordinatorURL, c.CoordinatorToken)
	controlRoots, err := loadCertPool(c.ControlCAFile)
	if err != nil {
		return benchmarkResult{}, err
	}
	controlHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: controlRoots, MinVersion: tls.VersionTLS13,
	}}, Timeout: 30 * time.Second}
	anonymous, err := controlclient.New(c.ServerURL, controlHTTP, "")
	if err != nil {
		return benchmarkResult{}, err
	}
	discovery, err := retryBenchmarkDiscovery(ctx, 2*time.Minute, anonymous.Discovery)
	if err != nil {
		return benchmarkResult{}, fmt.Errorf("read control discovery: %w", err)
	}
	anonymousAuthority, err := authorityclient.New(discovery.AuthorityEndpoint, controlHTTP, "")
	if err != nil {
		return benchmarkResult{}, err
	}
	if _, err := benchmarkHostnameSuffix(discovery, c.HostnameSuffix); err != nil {
		return benchmarkResult{}, err
	}
	payload := make([]byte, c.PayloadBytes)
	for index := range payload {
		payload[index] = byte(index)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-TNL-Bench-Host", request.Host)
		if request.URL.Path == "/hold" {
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write([]byte{1})
			if flusher, ok := response.(http.Flusher); ok {
				flusher.Flush()
			}
			<-request.Context().Done()
			return
		}
		_, _ = response.Write(payload)
	}))
	defer origin.Close()

	activationStarted := time.Now().UTC()
	routeSpecs, stateDatabases, err := prepareBenchmarkRoutes(
		ctx, c, controlHTTP, anonymousAuthority, discovery.AuthorityEndpoint,
		benchmarkRouteIndexes(c.Routes, c.RoutesPerPublisher, c.WorkerCount, c.WorkerIndex),
	)
	if err != nil {
		return benchmarkResult{}, err
	}
	defer func() {
		for _, database := range stateDatabases {
			_ = database.Close()
		}
	}()
	processes, activation, err := activateRoutes(
		ctx, c, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: controlRoots}, origin.URL, routeSpecs,
	)
	if err != nil {
		phase := activationResult("activation", activationStarted, processes, activation, err)
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		shutdown, stopErr := stopRoutes(cleanupCtx, processes, c.Parallel, c.onFailure)
		return benchmarkResult{Phases: []phaseResult{phase, shutdown}}, errors.Join(err, stopErr)
	}
	activationElapsed := time.Since(activationStarted)
	activationPhase := activationResult("activation", activationStarted, processes, activation, nil)
	cleaned := false
	defer func() {
		if !cleaned {
			if retErr != nil && c.onFailure != nil {
				c.onFailure()
			}
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cleanupCancel()
			shutdown, stopErr := stopRoutes(cleanupCtx, processes, c.Parallel, c.onFailure)
			result.Phases = append(result.Phases, shutdown)
			retErr = errors.Join(retErr, stopErr)
		}
	}()
	churnRoutes := benchmarkChurnRoutes(routeSpecs, c.WorkerIndex, c.RoutesPerChurn)
	var churnWarmupPhase *phaseResult
	var churnWarmupShutdown *phaseResult
	if c.AssignedChurnRate > 0 {
		warmupStarted := time.Now().UTC()
		warmProcesses, warmup, err := activateRoutes(
			ctx, c, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: controlRoots}, origin.URL, churnRoutes,
		)
		if err != nil {
			phase := activationResult("lifecycle_churn_warmup", warmupStarted, warmProcesses, warmup, err)
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cleanupCancel()
			shutdown, stopErr := stopRoutes(cleanupCtx, warmProcesses, c.Parallel, c.onFailure)
			shutdown.Name = "lifecycle_churn_warmup_deactivation"
			return benchmarkResult{Phases: []phaseResult{
				activationPhase, phase, shutdown,
			}}, fmt.Errorf("warm lifecycle churn routes: %w", errors.Join(err, stopErr))
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		shutdown, cleanupErr := stopRoutes(cleanupCtx, warmProcesses, c.Parallel, c.onFailure)
		cleanupCancel()
		shutdown.Name = "lifecycle_churn_warmup_deactivation"
		churnWarmupShutdown = &shutdown
		if cleanupErr != nil {
			return benchmarkResult{Phases: []phaseResult{activationPhase, shutdown}}, fmt.Errorf("stop lifecycle churn warmup: %w", cleanupErr)
		}
		churnWarmupPhase = &phaseResult{
			Name: "lifecycle_churn_warmup", StartedAt: warmupStarted,
			DurationMilliseconds: milliseconds(time.Since(warmupStarted)),
			Attempts:             len(warmup), Successes: len(warmup), Total: newDurationHistogram(warmup),
		}
	}
	resources := sampleResources(ctx, c.MetricsURLs, "ready")
	registrations := make([]benchmarkRouteRegistration, 0, len(processes))
	for _, process := range processes {
		if process != nil {
			registrations = append(registrations, benchmarkRouteRegistration{Index: process.index, Hostname: process.hostname})
		}
	}
	if err := coordinator.publisherReady(ctx, c.WorkerIndex, registrations); err != nil {
		return benchmarkResult{}, err
	}
	var churnPhase *phaseResult
	var workloadErr error
	if c.AssignedChurnRate == 0 {
		workloadErr = coordinator.waitLoad(ctx)
	} else {
		loadDone := make(chan error, 1)
		go func() { loadDone <- coordinator.waitLoad(ctx) }()
		phase, err := runLifecycleChurn(
			ctx, c, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: controlRoots}, origin.URL,
			churnRoutes, loadDone,
		)
		churnPhase = &phase
		workloadErr = err
	}
	if workloadErr != nil && c.onFailure != nil {
		c.onFailure()
	}
	resources = append(resources, sampleResources(ctx, c.MetricsURLs, "loaded")...)
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	teardown, cleanupErr := stopRoutes(cleanupCtx, processes, c.Parallel, c.onFailure)
	cleanupCancel()
	cleaned = true
	phases := []phaseResult{
		{
			Name: "activation", StartedAt: activationStarted, DurationMilliseconds: milliseconds(activationElapsed),
			Attempts: len(activation), Successes: len(activation), Total: newDurationHistogram(activation),
		},
		teardown,
	}
	if churnWarmupPhase != nil {
		phases = append(phases, *churnWarmupPhase)
		phases = append(phases, *churnWarmupShutdown)
	}
	if churnPhase != nil {
		phases = append(phases, *churnPhase)
	}
	retainedRoutes := teardown.Attempts
	if churnWarmupPhase != nil {
		retainedRoutes += len(churnRoutes)
	}
	result = benchmarkResult{
		SchemaVersion: benchmarkResultSchemaVersion, CellID: c.CellID, Status: "passed", Suite: c.Suite,
		Repetition: c.Repetition, Worker: worker, Configuration: configuration, Resources: resources,
		Phases:  phases,
		Cleanup: resultCleanup{RoutesRetained: retainedRoutes, Exact: cleanupErr == nil},
	}
	runErr := errors.Join(workloadErr, cleanupErr)
	if runErr != nil {
		result.Status = "failed"
		result.Failure = &resultFailure{Message: runErr.Error(), Stage: "measurement"}
		if cleanupErr != nil {
			result.Failure.Stage = "cleanup"
		}
	}
	return result, runErr
}

func retryBenchmarkDiscovery(
	ctx context.Context,
	timeout time.Duration,
	request func(context.Context) (controlv1.ControlDiscovery, error),
) (controlv1.ControlDiscovery, error) {
	retryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		discovery, err := request(retryCtx)
		if err == nil || !errors.Is(err, controlclient.ErrUnavailable) {
			return discovery, err
		}
		if sleepErr := sleepContext(retryCtx, time.Second); sleepErr != nil {
			return controlv1.ControlDiscovery{}, errors.Join(err, sleepErr)
		}
	}
}

func prepareBenchmarkRoutes(
	ctx context.Context,
	flags publisherCommand,
	httpClient *http.Client,
	anonymousAuthority *authorityclient.Client,
	authorityEndpoint string,
	routeIndexes []int,
) ([]benchmarkRouteSpec, []*clientstate.Database, error) {
	routes := make([]benchmarkRouteSpec, 0, len(routeIndexes))
	login := credentials.LoginToken(flags.LoginToken)
	issued, err := anonymousAuthority.Exchange(ctx, login)
	if err != nil {
		return nil, nil, fmt.Errorf("exchange login token: %w", err)
	}
	access := credentials.AccessToken(issued.AccessToken)
	if _, _, err := credentials.ParseAccessToken(access); err != nil {
		return nil, nil, errors.New("authority returned an invalid access token")
	}
	control, err := controlclient.New(flags.ServerURL, httpClient, access)
	if err != nil {
		return nil, nil, err
	}
	authority, err := authorityclient.New(authorityEndpoint, httpClient, access)
	if err != nil {
		return nil, nil, err
	}
	routeContext, namespace, err := resolveBenchmarkRouteContext(ctx, authority, flags.HostnameSuffix)
	if err != nil {
		return nil, nil, err
	}
	stateDatabase, err := clientstate.Open(ctx, flags.StateRoot)
	if err != nil {
		return nil, nil, err
	}
	state, err := stateDatabase.Server(ctx, flags.ServerURL)
	if err != nil {
		_ = stateDatabase.Close()
		return nil, nil, err
	}
	for _, routeIndex := range routeIndexes {
		routes = append(routes, benchmarkRouteSpec{
			index: routeIndex, hostname: benchmarkHostname(routeIndex, namespace), namespace: namespace, control: control,
			routeContext: routeContext, state: state,
		})
	}
	return routes, []*clientstate.Database{stateDatabase}, nil
}

func benchmarkChurnRoutes(routes []benchmarkRouteSpec, worker, routesPerChurn int) []benchmarkRouteSpec {
	seen := make(map[int]struct{})
	result := make([]benchmarkRouteSpec, 0)
	for _, route := range routes {
		group := route.index / routesPerChurn
		if _, exists := seen[group]; exists {
			continue
		}
		seen[group] = struct{}{}
		churn := route
		churn.index = -1
		churn.hostname = fmt.Sprintf("tnlbench-churn-w%02d-g%06d.%s", worker, group, route.namespace)
		result = append(result, churn)
	}
	return result
}

func runLifecycleChurn(
	ctx context.Context,
	flags publisherCommand,
	transportTLS *tls.Config,
	target string,
	routes []benchmarkRouteSpec,
	loadDone <-chan error,
) (phaseResult, error) {
	started := time.Now().UTC()
	phase := phaseResult{Name: "lifecycle_churn", StartedAt: started}
	if flags.AssignedChurnRate <= 0 || len(routes) == 0 {
		return phase, errors.New("lifecycle churn has no assigned routes")
	}
	available := make(chan benchmarkRouteSpec, len(routes))
	for _, route := range routes {
		available <- route
	}
	type churnResult struct {
		duration time.Duration
		err      error
	}
	results := make(chan churnResult, len(routes))
	interval := time.Second / time.Duration(flags.AssignedChurnRate)
	timer := time.NewTimer(0)
	defer timer.Stop()
	attempts, completed := 0, 0
	loadComplete := false
	var durations []time.Duration
	var loadErr error
	missed, failed := 0, 0
	var failureSamples []string
	for !loadComplete || completed < attempts {
		select {
		case err := <-loadDone:
			loadComplete = true
			loadDone = nil
			loadErr = err
		case result := <-results:
			completed++
			if result.err != nil {
				phase.Errors++
				failed++
				if len(failureSamples) < 3 && !slices.Contains(failureSamples, result.err.Error()) {
					failureSamples = append(failureSamples, result.err.Error())
				}
			} else {
				phase.Successes++
				durations = append(durations, result.duration)
			}
		case <-timer.C:
			if loadComplete {
				continue
			}
			select {
			case route := <-available:
				attempts++
				go func() {
					duration, err := runChurnRoute(ctx, route, transportTLS, target)
					available <- route
					results <- churnResult{duration: duration, err: err}
				}()
			default:
				attempts++
				completed++
				phase.Errors++
				missed++
			}
			timer.Reset(interval)
		case <-ctx.Done():
			return phase, errors.Join(loadErr, lifecycleChurnError(missed, failed, failureSamples, len(routes)), ctx.Err())
		}
	}
	phase.Attempts = attempts
	phase.DurationMilliseconds = milliseconds(time.Since(started))
	phase.AchievedRate = float64(phase.Successes) / time.Since(started).Seconds()
	phase.Total = newDurationHistogram(durations)
	churnErr := errors.Join(loadErr, lifecycleChurnError(missed, failed, failureSamples, len(routes)))
	if phase.AchievedRate < 0.95*float64(flags.AssignedChurnRate) {
		churnErr = errors.Join(churnErr, fmt.Errorf(
			"lifecycle churn rate %.2f/s was below 95%% of the %.2f/s target",
			phase.AchievedRate, float64(flags.AssignedChurnRate),
		))
	}
	return phase, churnErr
}

func lifecycleChurnError(missed, failed int, samples []string, routes int) error {
	var err error
	if missed > 0 {
		err = fmt.Errorf("%d lifecycle churn attempts could not start because all %d churn routes were busy", missed, routes)
	}
	if failed > 0 {
		message := fmt.Sprintf("%d lifecycle churn operations failed", failed)
		if len(samples) != 0 {
			message += "; samples: " + strings.Join(samples, "; ")
		}
		err = errors.Join(err, errors.New(message))
	}
	return err
}

func runChurnRoute(
	ctx context.Context,
	route benchmarkRouteSpec,
	transportTLS *tls.Config,
	target string,
) (time.Duration, error) {
	started := time.Now()
	routeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	ready := false
	err := publisher.Run(routeCtx, publisher.Config{
		Control: route.control, TeamID: route.routeContext.teamID, MembershipID: route.routeContext.membershipID,
		DomainID: route.routeContext.domainID, Hostname: route.hostname, RouteScope: route.routeContext.routeScope,
		PolicyRevision: route.routeContext.policyRevision, Target: target, State: route.state,
		QUICConnector: muxsession.QUICConnector{TLSConfig: transportTLS},
		TCPConnector:  muxsession.TLSYamuxConnector{TLSConfig: transportTLS},
		Observe: func(event publisher.Event) error {
			if event.Type == publisher.EventReady {
				ready = true
				cancel()
			}
			return nil
		},
	})
	if ready && (err == nil || errors.Is(err, context.Canceled)) {
		return time.Since(started), nil
	}
	if err == nil {
		err = errors.New("publisher exited before lifecycle route became ready")
	}
	return time.Since(started), err
}

func resolveBenchmarkRouteContext(ctx context.Context, authority *authorityclient.Client, managedDomain string) (benchmarkRouteContext, string, error) {
	identity, err := authority.IdentityContext(ctx)
	if err != nil {
		return benchmarkRouteContext{}, "", fmt.Errorf("read identity context: %w", err)
	}
	var membership authorityv1.Membership
	for _, candidate := range identity.Memberships {
		if candidate.TeamId == identity.PersonalTeamId {
			membership = candidate
			break
		}
	}
	if membership.Id == "" {
		return benchmarkRouteContext{}, "", errors.New("benchmark identity has no personal-team membership")
	}
	team, err := authority.GetTeam(ctx, membership.TeamId)
	if err != nil {
		return benchmarkRouteContext{}, "", fmt.Errorf("read benchmark team: %w", err)
	}
	domains, err := authority.ListTeamDomains(ctx, team.Id)
	if err != nil {
		return benchmarkRouteContext{}, "", fmt.Errorf("list benchmark domains: %w", err)
	}
	var domain authorityv1.Domain
	for _, candidate := range domains.Domains {
		if candidate.State != authorityv1.DomainStateReady || candidate.CanonicalDomain != managedDomain || candidate.Kind != authorityv1.Managed {
			continue
		}
		if len(candidate.CanonicalDomain) > len(domain.CanonicalDomain) {
			domain = candidate
		}
	}
	if domain.Id == "" {
		return benchmarkRouteContext{}, "", fmt.Errorf("managed deployment domain %s is not ready for the personal team", managedDomain)
	}
	namespace := membership.ManagedLabel + "." + domain.CanonicalDomain
	if team.PolicyRevision < 0 {
		return benchmarkRouteContext{}, "", errors.New("authority returned an invalid team policy revision")
	}
	return benchmarkRouteContext{
		teamID: team.Id, membershipID: membership.Id, domainID: domain.Id,
		routeScope: controlv1.Member, policyRevision: uint64(team.PolicyRevision),
	}, namespace, nil
}

func activateRoutes(
	ctx context.Context,
	flags publisherCommand,
	transportTLS *tls.Config,
	target string,
	specs []benchmarkRouteSpec,
) ([]*routeProcess, []time.Duration, error) {
	return activateRoutesWithRunner(ctx, flags, transportTLS, target, specs, publisher.Run)
}

func activateRoutesWithRunner(
	ctx context.Context,
	flags publisherCommand,
	transportTLS *tls.Config,
	target string,
	specs []benchmarkRouteSpec,
	run func(context.Context, publisher.Config) error,
) (processes []*routeProcess, timings []time.Duration, retErr error) {
	defer func() {
		if retErr != nil && flags.onFailure != nil {
			// Capture the wait graph while the other publishers are still alive.
			flags.onFailure()
		}
	}()
	processes = make([]*routeProcess, len(specs))
	activated := make(chan struct {
		route    int
		duration time.Duration
		err      error
	}, len(specs))
	start := func(slot int, spec benchmarkRouteSpec) {
		routeCtx, cancel := context.WithCancel(ctx)
		process := &routeProcess{
			index: spec.index, hostname: spec.hostname, cancel: cancel, done: make(chan error, 1),
		}
		processes[slot] = process
		go func() {
			started := time.Now()
			var signal sync.Once
			signalResult := func(err error) {
				signal.Do(func() {
					activated <- struct {
						route    int
						duration time.Duration
						err      error
					}{route: spec.index, duration: time.Since(started), err: err}
				})
			}
			ready := false
			err := run(routeCtx, publisher.Config{
				Control: spec.control, TeamID: spec.routeContext.teamID, MembershipID: spec.routeContext.membershipID,
				DomainID: spec.routeContext.domainID, Hostname: process.hostname, RouteScope: spec.routeContext.routeScope,
				PolicyRevision: spec.routeContext.policyRevision, Target: target, State: spec.state,
				QUICConnector: muxsession.QUICConnector{TLSConfig: transportTLS},
				TCPConnector:  muxsession.TLSYamuxConnector{TLSConfig: transportTLS},
				Observe: func(event publisher.Event) error {
					switch event.Type {
					case publisher.EventRouteAssigned:
						process.routeID = event.RouteID
					case publisher.EventReady:
						ready = true
						signalResult(nil)
					}
					return nil
				},
			})
			if ready && routeCtx.Err() == nil {
				fmt.Fprintf(os.Stderr, "tnlbench: route %d publisher exited after readiness: %v\n", spec.index, err)
			}
			if !ready && err == nil {
				err = errors.New("publisher exited before route became ready")
			}
			signalResult(err)
			process.done <- err
			close(process.done)
		}()
	}
	noProgress := flags.NoProgressTimeout
	if noProgress == 0 {
		noProgress = 2 * time.Minute
	}
	timer := time.NewTimer(noProgress)
	defer timer.Stop()
	next, active := 0, 0
	for len(timings) < len(specs) {
		for next < len(specs) && active < flags.Parallel {
			if ctx.Err() != nil {
				return processes, timings, ctx.Err()
			}
			start(next, specs[next])
			next++
			active++
		}
		select {
		case result := <-activated:
			active--
			if result.err != nil {
				return processes, timings, fmt.Errorf("activate route %d (%d ready, %d started): %w", result.route, len(timings), next, result.err)
			}
			timings = append(timings, result.duration)
			timer.Reset(noProgress)
		case <-timer.C:
			return processes, timings, fmt.Errorf("activation made no progress for %s (%d ready, %d started, %d pending)", noProgress, len(timings), next, active)
		case <-ctx.Done():
			return processes, timings, ctx.Err()
		}
	}
	return processes, timings, nil
}

func activationResult(name string, started time.Time, processes []*routeProcess, timings []time.Duration, err error) phaseResult {
	phase := phaseResult{Name: name, StartedAt: started, DurationMilliseconds: milliseconds(time.Since(started)),
		Successes: len(timings), Total: newDurationHistogram(timings)}
	for _, process := range processes {
		if process != nil {
			phase.Attempts++
		}
	}
	if err != nil {
		phase.Errors = 1
	}
	return phase
}

func benchmarkHostnameSuffix(discovery controlv1.ControlDiscovery, configured string) (string, error) {
	managed, err := naming.CanonicalizeHostname(discovery.ManagedDeploymentDomain)
	if err != nil || managed != discovery.ManagedDeploymentDomain || configured != managed {
		return "", errors.New("configured hostname suffix does not match the server managed deployment domain")
	}
	return configured, nil
}

func benchmarkHostname(routeIndex int, suffix string) string {
	return fmt.Sprintf("tnlbench-r%06d.%s", routeIndex, suffix)
}
