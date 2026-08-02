package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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
	ServerURL      string        `name:"server" env:"TNL_BENCH_SERVER" required:"" help:"Control URL."`
	LoginToken     string        `name:"login-token" env:"TNL_BENCH_LOGIN_TOKEN" required:"" help:"Built-in authority login token."`
	ControlCAFile  string        `name:"control-ca-file" env:"TNL_BENCH_CONTROL_CA_FILE" type:"path" help:"Optional PEM CA for the control API."`
	HostnameSuffix string        `name:"hostname-suffix" env:"TNL_BENCH_HOSTNAME_SUFFIX" required:"" help:"Managed deployment domain used by benchmark routes."`
	Routes         int           `name:"routes" env:"TNL_BENCH_ROUTES" required:"" help:"Total route count in the cell."`
	RouteOffset    int           `name:"route-offset" env:"TNL_BENCH_ROUTE_OFFSET" help:"First global route index assigned to this worker."`
	AssignedRoutes int           `name:"assigned-routes" env:"TNL_BENCH_ASSIGNED_ROUTES" required:"" help:"Routes assigned to this worker."`
	FreshRate      int           `name:"fresh-connections-per-second" env:"TNL_BENCH_FRESH_CONNECTIONS_PER_SECOND" required:"" help:"Total fresh visitor connection rate for the cell."`
	HeldStreams    int           `name:"held-streams" env:"TNL_BENCH_HELD_STREAMS" help:"Total held-open streams for the cell."`
	Parallel       int           `name:"parallel" env:"TNL_BENCH_PARALLEL" default:"16" help:"Maximum concurrent route operations."`
	PayloadBytes   int           `name:"payload-bytes" env:"TNL_BENCH_PAYLOAD_BYTES" default:"16384" help:"Fresh-response payload size."`
	MetricsURLs    []string      `name:"metrics-url" env:"TNL_BENCH_METRICS_URLS" help:"Private process metrics URL; repeat for each process."`
	Timeout        time.Duration `name:"timeout" env:"TNL_BENCH_TIMEOUT" default:"30m" help:"Worker deadline."`
}

func (c publisherCommand) Validate() error {
	if err := c.workerCommand.validate(); err != nil {
		return err
	}
	if c.Routes <= 0 || c.RouteOffset < 0 || c.AssignedRoutes <= 0 || c.RouteOffset+c.AssignedRoutes > c.Routes {
		return errors.New("publisher route assignment is invalid")
	}
	if c.FreshRate <= 0 || c.HeldStreams < 0 {
		return errors.New("publisher cell load shape is invalid")
	}
	if c.Parallel <= 0 || c.Parallel > 256 || c.PayloadBytes <= 0 || c.PayloadBytes > 16<<20 || c.Timeout <= 0 {
		return errors.New("publisher parallelism, payload, or timeout is invalid")
	}
	hostname, err := naming.CanonicalizeHostname(c.HostnameSuffix)
	if err != nil || hostname != c.HostnameSuffix {
		return errors.New("hostname suffix must be canonical")
	}
	return nil
}

type routeProcess struct {
	hostname string
	teamID   string
	routeID  string
	cancel   context.CancelFunc
	done     chan error
}

type routeCleaner interface {
	DeleteRoute(context.Context, string) error
	ListRoutes(context.Context, string) ([]controlv1.Route, error)
}

type benchmarkRouteContext struct {
	teamID         string
	membershipID   string
	domainID       string
	routeScope     controlv1.RouteScope
	policyRevision uint64
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
		Sequence: c.Sequence, Routes: c.Routes, AssignedRoutes: c.AssignedRoutes,
		FreshConnectionsPerSecond: c.FreshRate, HeldStreams: c.HeldStreams, PayloadBytes: c.PayloadBytes,
	}
	result, runErr := c.execute(ctx, worker, configuration)
	if runErr != nil && result.SchemaVersion == 0 {
		result = failedResult(c.CellID, c.Suite, c.Repetition, worker, configuration, started, runErr)
	}
	postCtx, postCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer postCancel()
	if err := coordinator.postResult(postCtx, result); err != nil {
		return errors.Join(runErr, fmt.Errorf("post publisher result: %w", err))
	}
	return runErr
}

func (c publisherCommand) execute(ctx context.Context, worker resultWorker, configuration resultConfiguration) (benchmarkResult, error) {
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
	login := credentials.LoginToken(c.LoginToken)
	if _, err := credentials.ParseLoginToken(login); err != nil {
		return benchmarkResult{}, errors.New("invalid login token")
	}
	discovery, err := anonymous.Discovery(ctx)
	if err != nil {
		return benchmarkResult{}, fmt.Errorf("read control discovery: %w", err)
	}
	authority, err := authorityclient.New(discovery.AuthorityEndpoint, controlHTTP, "")
	if err != nil {
		return benchmarkResult{}, err
	}
	issued, err := authority.Exchange(ctx, login)
	if err != nil {
		return benchmarkResult{}, fmt.Errorf("exchange login token: %w", err)
	}
	access := credentials.AccessToken(issued.AccessToken)
	if _, _, err := credentials.ParseAccessToken(access); err != nil {
		return benchmarkResult{}, errors.New("authority returned an invalid access token")
	}
	control, err := controlclient.New(c.ServerURL, controlHTTP, access)
	if err != nil {
		return benchmarkResult{}, err
	}
	authority, err = authorityclient.New(discovery.AuthorityEndpoint, controlHTTP, access)
	if err != nil {
		return benchmarkResult{}, err
	}
	if _, err := benchmarkHostnameSuffix(discovery, c.HostnameSuffix); err != nil {
		return benchmarkResult{}, err
	}
	hostnames := make([]string, c.AssignedRoutes)
	for index := range hostnames {
		hostnames[index] = benchmarkHostname(c.RouteOffset+index, c.HostnameSuffix)
	}
	routeContext, err := resolveBenchmarkRouteContext(ctx, authority, hostnames[0])
	if err != nil {
		return benchmarkResult{}, err
	}
	stateRoot, err := os.MkdirTemp("", "tnlbench-state-")
	if err != nil {
		return benchmarkResult{}, err
	}
	defer os.RemoveAll(stateRoot)
	stateDatabase, err := clientstate.Open(ctx, stateRoot)
	if err != nil {
		return benchmarkResult{}, err
	}
	defer stateDatabase.Close()
	state, err := stateDatabase.Server(ctx, c.ServerURL)
	if err != nil {
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
	processes, activation, err := activateRoutes(
		ctx, c, control, routeContext, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: controlRoots},
		state, origin.URL, hostnames,
	)
	if err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		_, _ = cleanupRoutes(cleanupCtx, c.Parallel, control, processes)
		return benchmarkResult{}, err
	}
	activationElapsed := time.Since(activationStarted)
	cleaned := false
	defer func() {
		if !cleaned {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cleanupCancel()
			_, _ = cleanupRoutes(cleanupCtx, c.Parallel, control, processes)
		}
	}()
	resources := sampleResources(ctx, c.MetricsURLs, "ready")
	if err := coordinator.publisherReady(ctx, c.WorkerIndex); err != nil {
		return benchmarkResult{}, err
	}
	if err := coordinator.waitLoad(ctx); err != nil {
		return benchmarkResult{}, err
	}
	resources = append(resources, sampleResources(ctx, c.MetricsURLs, "loaded")...)
	cleanupStarted := time.Now().UTC()
	teardown, cleanupErr := cleanupRoutes(ctx, c.Parallel, control, processes)
	cleanupElapsed := time.Since(cleanupStarted)
	cleaned = true
	if cleanupErr != nil {
		return benchmarkResult{}, cleanupErr
	}
	return benchmarkResult{
		SchemaVersion: benchmarkResultSchemaVersion, CellID: c.CellID, Status: "passed", Suite: c.Suite,
		Repetition: c.Repetition, Worker: worker, Configuration: configuration, Resources: resources,
		Phases: []phaseResult{
			{
				Name: "activation", StartedAt: activationStarted, DurationMilliseconds: milliseconds(activationElapsed),
				Attempts: len(activation), Successes: len(activation), Total: newDurationHistogram(activation),
			},
			{
				Name: "cleanup", StartedAt: cleanupStarted, DurationMilliseconds: milliseconds(cleanupElapsed),
				Attempts: len(teardown), Successes: len(teardown), Total: newDurationHistogram(teardown),
			},
		},
		Cleanup: resultCleanup{RoutesDeleted: len(teardown), Exact: true},
	}, nil
}

func resolveBenchmarkRouteContext(ctx context.Context, authority *authorityclient.Client, hostname string) (benchmarkRouteContext, error) {
	identity, err := authority.IdentityContext(ctx)
	if err != nil {
		return benchmarkRouteContext{}, fmt.Errorf("read identity context: %w", err)
	}
	var membership authorityv1.Membership
	for _, candidate := range identity.Memberships {
		if candidate.TeamId == identity.PersonalTeamId {
			membership = candidate
			break
		}
	}
	if membership.Id == "" {
		return benchmarkRouteContext{}, errors.New("benchmark identity has no personal-team membership")
	}
	team, err := authority.GetTeam(ctx, membership.TeamId)
	if err != nil {
		return benchmarkRouteContext{}, fmt.Errorf("read benchmark team: %w", err)
	}
	domains, err := authority.ListTeamDomains(ctx, team.Id)
	if err != nil {
		return benchmarkRouteContext{}, fmt.Errorf("list benchmark domains: %w", err)
	}
	var domain authorityv1.Domain
	for _, candidate := range domains.Domains {
		if candidate.State != authorityv1.DomainStateReady || hostname != candidate.CanonicalDomain && !strings.HasSuffix(hostname, "."+candidate.CanonicalDomain) {
			continue
		}
		if len(candidate.CanonicalDomain) > len(domain.CanonicalDomain) {
			domain = candidate
		}
	}
	if domain.Id == "" {
		return benchmarkRouteContext{}, fmt.Errorf("benchmark hostname %s is outside the personal team's ready domains", hostname)
	}
	label := membership.MemberSlug
	if domain.Kind == authorityv1.Managed {
		label = membership.ManagedLabel
	}
	namespace := label + "." + domain.CanonicalDomain
	routeScope := controlv1.Shared
	if hostname == namespace || strings.HasSuffix(hostname, "."+namespace) && strings.Count(strings.TrimSuffix(hostname, "."+namespace), ".") == 0 {
		routeScope = controlv1.Member
	} else if membership.Role == authorityv1.TeamRoleMember {
		return benchmarkRouteContext{}, errors.New("benchmark hostname requires a shared route but the personal-team membership is not an administrator")
	}
	if team.PolicyRevision < 0 {
		return benchmarkRouteContext{}, errors.New("authority returned an invalid team policy revision")
	}
	return benchmarkRouteContext{
		teamID: team.Id, membershipID: membership.Id, domainID: domain.Id,
		routeScope: routeScope, policyRevision: uint64(team.PolicyRevision),
	}, nil
}

func activateRoutes(
	ctx context.Context,
	flags publisherCommand,
	routes *controlclient.Client,
	routeContext benchmarkRouteContext,
	transportTLS *tls.Config,
	state *clientstate.Store,
	target string,
	hostnames []string,
) ([]*routeProcess, []time.Duration, error) {
	processes := make([]*routeProcess, len(hostnames))
	activated := make(chan struct {
		index    int
		duration time.Duration
		err      error
	}, len(hostnames))
	semaphore := make(chan struct{}, flags.Parallel)
	for index := range hostnames {
		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			return processes, nil, ctx.Err()
		}
		routeCtx, cancel := context.WithCancel(ctx)
		process := &routeProcess{hostname: hostnames[index], teamID: routeContext.teamID, cancel: cancel, done: make(chan error, 1)}
		processes[index] = process
		go func(index int, process *routeProcess) {
			started := time.Now()
			var signal sync.Once
			signalResult := func(err error) {
				signal.Do(func() {
					<-semaphore
					activated <- struct {
						index    int
						duration time.Duration
						err      error
					}{index: index, duration: time.Since(started), err: err}
				})
			}
			ready := false
			err := publisher.Run(routeCtx, publisher.Config{
				Control: routes, TeamID: routeContext.teamID, MembershipID: routeContext.membershipID,
				DomainID: routeContext.domainID, Hostname: process.hostname, RouteScope: routeContext.routeScope,
				PolicyRevision: routeContext.policyRevision, Target: target, State: state,
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
				fmt.Fprintf(os.Stderr, "tnlbench: route %d publisher exited after readiness: %v\n", index, err)
			}
			signalResult(err)
			process.done <- err
			close(process.done)
		}(index, process)
	}
	timings := make([]time.Duration, len(hostnames))
	for completed := 1; completed <= len(hostnames); completed++ {
		select {
		case result := <-activated:
			if result.err != nil {
				return processes, nil, fmt.Errorf("activate route %d: %w", result.index, result.err)
			}
			timings[result.index] = result.duration
		case <-ctx.Done():
			return processes, nil, ctx.Err()
		}
	}
	return processes, timings, nil
}

func cleanupRoutes(ctx context.Context, parallel int, server routeCleaner, processes []*routeProcess) ([]time.Duration, error) {
	started := time.Now()
	teamID := ""
	for _, process := range processes {
		if process != nil {
			if teamID == "" {
				teamID = process.teamID
			}
			process.cancel()
		}
	}
	routeIDs := make([]string, len(processes))
	var cleanupErr error
	for index, process := range processes {
		if process == nil {
			continue
		}
		select {
		case err := <-process.done:
			if err != nil && !errors.Is(err, context.Canceled) {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("stop route %d: %w", index, err))
			}
			routeIDs[index] = process.routeID
		case <-ctx.Done():
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("stop route %d: %w", index, ctx.Err()))
			routeIDs[index] = process.routeID
		}
	}
	cleanupCtx := ctx
	cancelCleanup := func() {}
	if ctx.Err() != nil {
		cleanupCtx, cancelCleanup = context.WithTimeout(context.Background(), 30*time.Second)
	}
	defer cancelCleanup()
	remaining, verifyErr := remainingRoutes(cleanupCtx, server, teamID, routeIDs)
	if verifyErr != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("list benchmark routes for cleanup: %w", verifyErr))
	} else {
		type cleanupResult struct{ err error }
		results := make(chan cleanupResult, len(remaining))
		semaphore := make(chan struct{}, parallel)
		for _, routeID := range routeIDs {
			route, found := remaining[routeID]
			if routeID == "" || !found {
				continue
			}
			semaphore <- struct{}{}
			go func(route controlv1.Route) {
				defer func() { <-semaphore }()
				err := server.DeleteRoute(cleanupCtx, route.Id)
				if errors.Is(err, controlclient.ErrNotFound) {
					err = nil
				}
				results <- cleanupResult{err: err}
			}(route)
		}
		for range remaining {
			cleanupErr = errors.Join(cleanupErr, (<-results).err)
		}
		if stillRemaining, err := remainingRoutes(cleanupCtx, server, teamID, routeIDs); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("verify benchmark route cleanup: %w", err))
		} else if len(stillRemaining) != 0 {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("benchmark cleanup left %d routes", len(stillRemaining)))
		}
	}
	timings := make([]time.Duration, 0, len(processes))
	for _, process := range processes {
		if process != nil {
			timings = append(timings, time.Since(started))
		}
	}
	return timings, cleanupErr
}

func remainingRoutes(ctx context.Context, server routeCleaner, teamID string, routeIDs []string) (map[string]controlv1.Route, error) {
	wanted := make(map[string]struct{}, len(routeIDs))
	for _, routeID := range routeIDs {
		if routeID != "" {
			wanted[routeID] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return nil, nil
	}
	routes, err := server.ListRoutes(ctx, teamID)
	if err != nil {
		return nil, err
	}
	remaining := make(map[string]controlv1.Route)
	for _, route := range routes {
		if _, found := wanted[route.Id]; found {
			remaining[route.Id] = route
		}
	}
	return remaining, nil
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
