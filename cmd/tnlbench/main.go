package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/routeclient"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type cli struct {
	CellID              string        `name:"cell-id" env:"TNL_BENCH_CELL_ID" help:"Stable expanded benchmark cell ID."`
	Suite               string        `name:"suite" env:"TNL_BENCH_SUITE" default:"legacy" help:"Benchmark suite name."`
	Workload            string        `name:"workload" env:"TNL_BENCH_WORKLOAD" default:"agent-worktrees-assumed-v1" help:"Benchmark workload ID."`
	Repetition          int           `name:"repetition" env:"TNL_BENCH_REPETITION" default:"1" help:"One-based cell repetition."`
	Topology            string        `name:"topology" env:"TNL_BENCH_TOPOLOGY" enum:"standalone,split" required:"" help:"Deployment topology under test: ${enum}."`
	ServerURL           string        `name:"server" env:"TNL_BENCH_SERVER" required:"" help:"Server HTTPS origin."`
	LoginToken          string        `name:"login-token" env:"TNL_BENCH_LOGIN_TOKEN" required:"" help:"Server login token."`
	ControlCAFile       string        `name:"control-ca-file" env:"TNL_BENCH_CONTROL_CA_FILE" type:"path" help:"Optional PEM CA for the server endpoint; system roots are used when omitted."`
	PublicAddress       string        `name:"public-address" env:"TNL_BENCH_PUBLIC_ADDRESS" required:"" help:"Public ingress host:port to dial."`
	HostnameSuffix      string        `name:"hostname-suffix" env:"TNL_BENCH_HOSTNAME_SUFFIX" required:"" help:"Suffix below which benchmark routes are created."`
	RelayMetricsURLs    []string      `name:"relay-metrics-url" env:"TNL_BENCH_RELAY_METRICS_URLS" help:"Private relay metrics URL; repeat for each relay process."`
	ControlMetricsURL   string        `name:"control-metrics-url" env:"TNL_BENCH_CONTROL_METRICS_URL" help:"Private control metrics URL used for failure evidence."`
	Routes              int           `name:"routes" env:"TNL_BENCH_ROUTES" default:"1" help:"Routes to activate."`
	ExpectedConnections int           `name:"expected-publisher-connections" env:"TNL_BENCH_EXPECTED_PUBLISHER_CONNECTIONS" help:"Aggregate ready publisher connections used to coordinate driver shards; defaults to two per route."`
	DriverIndex         int           `name:"driver-index" env:"TNL_BENCH_DRIVER_INDEX" help:"Zero-based index of this driver shard."`
	DriverCount         int           `name:"driver-count" env:"TNL_BENCH_DRIVER_COUNT" default:"1" help:"Number of coordinated driver shards."`
	BarrierURL          string        `name:"barrier-url" env:"TNL_BENCH_BARRIER_URL" help:"Driver coordinator URL."`
	BarrierListen       string        `name:"barrier-listen" env:"TNL_BENCH_BARRIER_LISTEN" help:"Driver coordinator listen address; set on driver zero."`
	BarrierToken        string        `name:"barrier-token" env:"TNL_BENCH_BARRIER_TOKEN" help:"Driver coordinator bearer token."`
	Parallel            int           `name:"parallel" env:"TNL_BENCH_PARALLEL" default:"8" help:"Maximum concurrent setup, load, and cleanup operations."`
	PayloadBytes        int           `name:"payload-bytes" env:"TNL_BENCH_PAYLOAD_BYTES" default:"65536" help:"Response bytes transferred per route."`
	Timeout             time.Duration `name:"timeout" env:"TNL_BENCH_TIMEOUT" default:"30m" help:"Overall benchmark deadline."`
}

type benchmarkCLI struct {
	Plan   planCommand   `cmd:"" help:"Expand and price a benchmark suite without creating resources."`
	Driver cli           `cmd:"" help:"Run one benchmark driver shard."`
	Report reportCommand `cmd:"" help:"Merge driver results and write report artifacts."`
}

func (c cli) Validate() error {
	if c.Repetition <= 0 {
		return errors.New("repetition must be positive")
	}
	if c.Routes <= 0 || c.Routes > 5000 {
		return errors.New("routes must be between 1 and 5000")
	}
	if expected := c.expectedPublisherConnections(); expected < c.Routes*2 || expected > 300000 {
		return errors.New("expected publisher connections must be between two per route and 300000")
	}
	if c.DriverCount <= 0 || c.DriverIndex < 0 || c.DriverIndex >= c.DriverCount {
		return errors.New("driver index must identify one configured driver")
	}
	if c.DriverCount > 1 {
		barrierURL, err := url.Parse(c.BarrierURL)
		if err != nil || barrierURL.Scheme != "http" || barrierURL.Host == "" || barrierURL.User != nil {
			return errors.New("multi-driver benchmark requires an HTTP barrier URL")
		}
		if c.BarrierToken == "" || (c.DriverIndex == 0 && c.BarrierListen == "") {
			return errors.New("multi-driver benchmark requires barrier credentials and a driver-zero listener")
		}
	}
	if c.Parallel <= 0 || c.Parallel > 256 {
		return errors.New("parallel must be between 1 and 256")
	}
	if c.PayloadBytes <= 0 || c.PayloadBytes > 16<<20 {
		return errors.New("payload bytes must be between 1 and 16 MiB")
	}
	if c.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if _, _, err := net.SplitHostPort(c.PublicAddress); err != nil {
		return fmt.Errorf("public address: %w", err)
	}
	hostname, err := naming.CanonicalizeHostname(c.HostnameSuffix)
	if err != nil || hostname != c.HostnameSuffix {
		return errors.New("hostname suffix must be canonical")
	}
	for _, rawURL := range c.RelayMetricsURLs {
		if err := validateMetricsURL(rawURL); err != nil {
			return fmt.Errorf("invalid metrics URL %q", rawURL)
		}
	}
	if c.ControlMetricsURL != "" {
		if err := validateMetricsURL(c.ControlMetricsURL); err != nil {
			return fmt.Errorf("invalid control metrics URL %q", c.ControlMetricsURL)
		}
	}
	return nil
}

func validateMetricsURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil {
		return errors.New("metrics URL must be an HTTP URL without credentials")
	}
	return nil
}

func (c cli) expectedPublisherConnections() int {
	if c.ExpectedConnections == 0 {
		return c.Routes * 2
	}
	return c.ExpectedConnections
}

func (c cli) cellID() string {
	if c.CellID != "" {
		return c.CellID
	}
	return fmt.Sprintf("%s-r%d-rep%d", c.Topology, c.expectedPublisherConnections()/2, c.Repetition)
}

type routeProcess struct {
	hostname string
	teamID   string
	routeID  string
	cancel   context.CancelFunc
	done     chan error
}

type routeCleaner interface {
	DeleteRoute(context.Context, controlv1.Route) error
	ListRoutes(context.Context, string) ([]controlv1.Route, error)
}

type benchmarkRouteContext struct {
	teamID         string
	membershipID   string
	domainID       string
	routeScope     controlv1.RouteScope
	policyRevision uint64
}

type relaySample struct {
	Relay                int     `json:"relay"`
	PublisherConnections int     `json:"publisher_connections"`
	RSSBytes             float64 `json:"rss_bytes"`
	Goroutines           int     `json:"goroutines"`
	OpenFDs              int     `json:"open_fds"`
	MaxFDs               int     `json:"max_fds"`
}

type failureEvidence struct {
	EvidenceSchemaVersion int                `json:"evidence_schema_version"`
	Kind                  string             `json:"kind"`
	Relays                []relaySample      `json:"relays,omitempty"`
	RelayError            string             `json:"relay_error,omitempty"`
	Control               map[string]float64 `json:"control,omitempty"`
	ControlError          string             `json:"control_error,omitempty"`
}

type measurements struct {
	ActivationStarted time.Time
	ActivationElapsed time.Duration
	Activation        []time.Duration
	RequestStarted    time.Time
	RequestElapsed    time.Duration
	FirstByte         []time.Duration
	Request           []time.Duration
	CleanupStarted    time.Time
	CleanupElapsed    time.Duration
	Teardown          []time.Duration
	ReadyRelays       []relaySample
	SettledRelays     []relaySample
}

func main() {
	var commands benchmarkCLI
	parsed := kong.Parse(&commands, kong.Name("tnlbench"), kong.Description("Benchmark the complete tnl route path."))
	switch parsed.Command() {
	case "plan":
		if err := commands.Plan.run(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "tnlbench: plan: %v\n", err)
			os.Exit(1)
		}
	case "driver":
		runDriver(commands.Driver)
	case "report":
		if err := commands.Report.run(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "tnlbench: report: %v\n", err)
			os.Exit(1)
		}
	default:
		panic("unhandled tnlbench command")
	}
}

func runDriver(flags cli) {
	started := time.Now().UTC()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, flags.Timeout)
	defer cancel()
	stopBarrier, err := startDriverBarrier(flags)
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(newBenchmarkResult(flags, started, measurements{}, err))
		fmt.Fprintf(os.Stderr, "tnlbench: start driver barrier: %v\n", err)
		os.Exit(1)
	}
	defer stopBarrier()
	go func() {
		<-ctx.Done()
		timer := time.NewTimer(2 * time.Minute)
		defer timer.Stop()
		<-timer.C
		fmt.Fprintln(os.Stderr, "tnlbench: cleanup exceeded two minutes; forcing exit")
		os.Exit(1)
	}()
	measured, runErr := run(ctx, flags)
	benchmarkResult := newBenchmarkResult(flags, started, measured, runErr)
	if err := json.NewEncoder(os.Stdout).Encode(benchmarkResult); err != nil {
		fmt.Fprintf(os.Stderr, "tnlbench: encode result: %v\n", err)
		os.Exit(1)
	}
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "tnlbench: %v\n", runErr)
		os.Exit(1)
	}
}

func run(ctx context.Context, flags cli) (measurements, error) {
	fmt.Fprintf(
		os.Stderr, "tnlbench: starting %s shard with %d routes and %d expected publisher connections\n",
		flags.Topology, flags.Routes, flags.expectedPublisherConnections(),
	)
	controlRoots, err := loadCertPool(flags.ControlCAFile)
	if err != nil {
		return measurements{}, err
	}
	controlHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: controlRoots, MinVersion: tls.VersionTLS13,
	}}, Timeout: 30 * time.Second}
	anonymous, err := controlclient.New(flags.ServerURL, controlHTTP, "")
	if err != nil {
		return measurements{}, err
	}
	login := credentials.LoginToken(flags.LoginToken)
	if _, err := credentials.ParseLoginToken(login); err != nil {
		return measurements{}, errors.New("invalid login token")
	}
	discovery, err := anonymous.Discovery(ctx)
	if err != nil {
		return measurements{}, fmt.Errorf("read control discovery: %w", err)
	}
	authority, err := authorityclient.New(discovery.AuthorityEndpoint, controlHTTP, "")
	if err != nil {
		return measurements{}, err
	}
	issued, err := authority.Exchange(ctx, login)
	if err != nil {
		return measurements{}, fmt.Errorf("exchange login token: %w", err)
	}
	access := credentials.AccessToken(issued.AccessToken)
	if _, _, err := credentials.ParseAccessToken(access); err != nil {
		return measurements{}, errors.New("authority returned an invalid access token")
	}
	control, err := controlclient.New(flags.ServerURL, controlHTTP, access)
	if err != nil {
		return measurements{}, err
	}
	authority, err = authorityclient.New(discovery.AuthorityEndpoint, controlHTTP, access)
	if err != nil {
		return measurements{}, err
	}
	hostnameSuffix, err := benchmarkHostnameSuffix(discovery, flags.HostnameSuffix)
	if err != nil {
		return measurements{}, err
	}
	hostnames := make([]string, flags.Routes)
	for index := range hostnames {
		hostnames[index] = benchmarkHostname(flags.DriverIndex, index, hostnameSuffix)
	}
	routeContext, err := resolveBenchmarkRouteContext(ctx, authority, hostnames[0])
	if err != nil {
		return measurements{}, err
	}
	routes, err := routeclient.New(control)
	if err != nil {
		return measurements{}, err
	}
	stateRoot, err := os.MkdirTemp("", "tnlbench-state-")
	if err != nil {
		return measurements{}, err
	}
	defer os.RemoveAll(stateRoot)
	stateDatabase, err := clientstate.Open(ctx, stateRoot)
	if err != nil {
		return measurements{}, err
	}
	defer stateDatabase.Close()
	state, err := stateDatabase.Server(ctx, flags.ServerURL)
	if err != nil {
		return measurements{}, err
	}
	payload := make([]byte, flags.PayloadBytes)
	for index := range payload {
		payload[index] = byte(index)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-TNL-Bench-Host", request.Host)
		_, _ = response.Write(payload)
	}))
	defer origin.Close()

	activationStarted := time.Now().UTC()
	processes, activation, err := activateRoutes(
		ctx, flags, routes, routeContext, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: controlRoots},
		state, origin.URL, hostnames,
	)
	if err != nil {
		writeFailureEvidence(flags)
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_, _ = cleanupRoutes(cleanupCtx, flags, routes, processes)
		return measurements{}, err
	}
	activationElapsed := time.Since(activationStarted)
	fmt.Fprintln(os.Stderr, "tnlbench: activation complete")
	cleaned := false
	defer func() {
		if !cleaned {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			_, _ = cleanupRoutes(cleanupCtx, flags, routes, processes)
		}
	}()
	// Barriers keep faster shards from entering the next phase early.
	if err := waitDriverBarrier(ctx, flags, "activated"); err != nil {
		return measurements{}, err
	}
	readyRelays, err := waitPublisherConnections(ctx, flags.RelayMetricsURLs, flags.expectedPublisherConnections())
	if err != nil {
		writeFailureEvidence(flags)
		return measurements{}, err
	}
	fmt.Fprintln(os.Stderr, "tnlbench: publisher connection count ready")
	if err := waitDriverBarrier(ctx, flags, "ready"); err != nil {
		return measurements{}, err
	}
	requestStarted := time.Now().UTC()
	firstByte, requests, elapsed, err := loadRoutes(ctx, flags, processes, payload)
	if err != nil {
		return measurements{}, err
	}
	fmt.Fprintln(os.Stderr, "tnlbench: request load complete")
	if err := waitDriverBarrier(ctx, flags, "loaded"); err != nil {
		return measurements{}, err
	}
	cleanupStarted := time.Now().UTC()
	teardown, err := cleanupRoutes(ctx, flags, routes, processes)
	if err != nil {
		return measurements{}, err
	}
	cleanupElapsed := time.Since(cleanupStarted)
	fmt.Fprintln(os.Stderr, "tnlbench: route cleanup complete")
	cleaned = true
	settledRelays, err := waitPublisherConnections(ctx, flags.RelayMetricsURLs, 0)
	if err != nil {
		return measurements{}, err
	}
	fmt.Fprintln(os.Stderr, "tnlbench: publisher connection count settled")
	return measurements{
		ActivationStarted: activationStarted, ActivationElapsed: activationElapsed, Activation: activation,
		RequestStarted: requestStarted, RequestElapsed: elapsed, FirstByte: firstByte, Request: requests,
		CleanupStarted: cleanupStarted, CleanupElapsed: cleanupElapsed, Teardown: teardown,
		ReadyRelays: readyRelays, SettledRelays: settledRelays,
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
	flags cli,
	routes *routeclient.Client,
	routeContext benchmarkRouteContext,
	transportTLS *tls.Config,
	state *clientstate.Store,
	target string,
	hostnames []string,
) ([]*routeProcess, []time.Duration, error) {
	processes := make([]*routeProcess, flags.Routes)
	activated := make(chan struct {
		index    int
		duration time.Duration
		err      error
	}, flags.Routes)
	// Create the session before timing; the slot ends at readiness while publishing continues.
	semaphore := make(chan struct{}, flags.Parallel)
	for index := 0; index < flags.Routes; index++ {
		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			return processes, nil, ctx.Err()
		}
		routeCtx, cancel := context.WithCancel(ctx)
		process := &routeProcess{
			hostname: hostnames[index], teamID: routeContext.teamID, cancel: cancel, done: make(chan error, 1),
		}
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
	timings := make([]time.Duration, flags.Routes)
	for completed := 1; completed <= flags.Routes; completed++ {
		select {
		case result := <-activated:
			if result.err != nil {
				return processes, nil, fmt.Errorf("activate route %d: %w", result.index, result.err)
			}
			timings[result.index] = result.duration
			if completed%50 == 0 || completed == flags.Routes {
				fmt.Fprintf(os.Stderr, "tnlbench: activated %d/%d routes\n", completed, flags.Routes)
			}
		case <-ctx.Done():
			return processes, nil, ctx.Err()
		}
	}
	return processes, timings, nil
}

func loadRoutes(
	ctx context.Context,
	flags cli,
	processes []*routeProcess,
	wantPayload []byte,
) ([]time.Duration, []time.Duration, time.Duration, error) {
	// Force a new ingress stream for every sample.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, "tcp", flags.PublicAddress)
		},
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		DisableKeepAlives: true, ForceAttemptHTTP2: false, DisableCompression: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	type requestResult struct {
		index     int
		firstByte time.Duration
		total     time.Duration
		err       error
	}
	results := make(chan requestResult, len(processes))
	semaphore := make(chan struct{}, flags.Parallel)
	// Batch throughput includes queueing; request latency starts after admission.
	startedAll := time.Now()
	for index, process := range processes {
		semaphore <- struct{}{}
		go func(index int, process *routeProcess) {
			defer func() { <-semaphore }()
			started := time.Now()
			var firstByte time.Duration
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+process.hostname+"/bench", nil)
			if err == nil {
				request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
					GotFirstResponseByte: func() { firstByte = time.Since(started) },
				}))
			}
			var response *http.Response
			if err == nil {
				response, err = client.Do(request)
			}
			if err == nil {
				defer response.Body.Close()
				body, readErr := io.ReadAll(io.LimitReader(response.Body, int64(len(wantPayload)+1)))
				err = readErr
				if err == nil && response.StatusCode != http.StatusOK {
					err = fmt.Errorf("HTTP %d", response.StatusCode)
				}
				if err == nil && response.Header.Get("X-TNL-Bench-Host") != process.hostname {
					err = errors.New("origin observed wrong host")
				}
				if err == nil && !bytes.Equal(body, wantPayload) {
					err = errors.New("response payload mismatch")
				}
			}
			results <- requestResult{index: index, firstByte: firstByte, total: time.Since(started), err: err}
		}(index, process)
	}
	firstByte := make([]time.Duration, len(processes))
	total := make([]time.Duration, len(processes))
	for range processes {
		select {
		case result := <-results:
			if result.err != nil {
				return nil, nil, 0, fmt.Errorf("request route %d: %w", result.index, result.err)
			}
			firstByte[result.index] = result.firstByte
			total[result.index] = result.total
		case <-ctx.Done():
			return nil, nil, 0, ctx.Err()
		}
	}
	return firstByte, total, time.Since(startedAll), nil
}

func cleanupRoutes(ctx context.Context, flags cli, server routeCleaner, processes []*routeProcess) ([]time.Duration, error) {
	// Publisher shutdown closes route sessions; benchmark routes are then deleted explicitly.
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
			if err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("stop route %d: %w", index, err))
			}
			routeIDs[index] = process.routeID
		case <-ctx.Done():
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("stop route %d: %w", index, ctx.Err()))
			routeIDs[index] = process.routeID
		}
	}

	type cleanupResult struct {
		index int
		err   error
	}
	results := make(chan cleanupResult, len(processes))
	semaphore := make(chan struct{}, flags.Parallel)
	cleanupCtx := ctx
	cancelCleanup := func() {}
	if ctx.Err() != nil {
		cleanupCtx, cancelCleanup = context.WithTimeout(context.Background(), 30*time.Second)
	}
	defer cancelCleanup()

	remaining, verifyErr := remainingRoutes(cleanupCtx, server, teamID, routeIDs)
	if verifyErr != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("list benchmark routes for cleanup: %w", verifyErr))
	} else if len(remaining) != 0 {
		fmt.Fprintf(os.Stderr, "tnlbench: deleting %d durable benchmark routes\n", len(remaining))
		count := 0
		for index, routeID := range routeIDs {
			route, found := remaining[routeID]
			if routeID == "" || !found {
				continue
			}
			count++
			semaphore <- struct{}{}
			go func(index int, route controlv1.Route) {
				defer func() { <-semaphore }()
				err := server.DeleteRoute(cleanupCtx, route)
				if errors.Is(err, controlclient.ErrNotFound) {
					err = nil
				}
				if err != nil {
					err = fmt.Errorf("fallback delete route %d: %w", index, err)
				}
				results <- cleanupResult{index: index, err: err}
			}(index, route)
		}
		for range count {
			result := <-results
			cleanupErr = errors.Join(cleanupErr, result.err)
		}
		if stillRemaining, err := remainingRoutes(cleanupCtx, server, teamID, routeIDs); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("verify benchmark route cleanup: %w", err))
		} else if len(stillRemaining) != 0 {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("benchmark cleanup left %d routes", len(stillRemaining)))
		}
	}

	timings := make([]time.Duration, 0, len(processes))
	for _, process := range processes {
		if process == nil {
			continue
		}
		timings = append(timings, time.Since(started))
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

func waitPublisherConnections(ctx context.Context, metricsURLs []string, want int) ([]relaySample, error) {
	if len(metricsURLs) == 0 {
		return nil, nil
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var lastSamples []relaySample
	lastTotal := -1
	maxTotal := -1
	var lastErr error
	for {
		samples, err := sampleRelays(ctx, metricsURLs)
		if err == nil {
			total := 0
			for _, sample := range samples {
				total += sample.PublisherConnections
			}
			lastSamples = samples
			lastTotal = total
			maxTotal = max(maxTotal, total)
			lastErr = nil
			// Allow activation overshoot across shards, but require exact zero after teardown.
			if total == want || want > 0 && total > want {
				return samples, nil
			}
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			if lastTotal >= 0 {
				counts := make([]int, len(lastSamples))
				for index, sample := range lastSamples {
					counts[index] = sample.PublisherConnections
				}
				return nil, fmt.Errorf(
					"publisher connections did not reach %d (last=%d max=%d relays=%v): %w",
					want, lastTotal, maxTotal, counts, ctx.Err(),
				)
			}
			return nil, errors.Join(errors.New("sample relay publisher connections"), lastErr, ctx.Err())
		case <-ticker.C:
		}
	}
}

func sampleRelays(ctx context.Context, metricsURLs []string) ([]relaySample, error) {
	samples := make([]relaySample, len(metricsURLs))
	for index, metricsURL := range metricsURLs {
		values, err := sampleMetrics(ctx, metricsURL)
		if err != nil {
			return nil, fmt.Errorf("metrics relay %d: %w", index, err)
		}
		samples[index] = relaySample{
			Relay: index, PublisherConnections: int(values[`tnl_publisher_connections{state="ready"}`]),
			RSSBytes:   values["process_resident_memory_bytes"],
			Goroutines: int(values["go_goroutines"]), OpenFDs: int(values["process_open_fds"]),
			MaxFDs: int(values["process_max_fds"]),
		}
	}
	return samples, nil
}

func sampleMetrics(ctx context.Context, metricsURL string) (map[string]float64, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metricsURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	closeErr := response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	return parseMetrics(string(body)), nil
}

func writeFailureEvidence(flags cli) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	evidence := failureEvidence{EvidenceSchemaVersion: 1, Kind: "server_metrics"}
	relays, err := sampleRelays(ctx, flags.RelayMetricsURLs)
	if err != nil {
		evidence.RelayError = err.Error()
	} else {
		evidence.Relays = relays
	}
	if flags.ControlMetricsURL != "" {
		values, err := sampleMetrics(ctx, flags.ControlMetricsURL)
		if err != nil {
			evidence.ControlError = err.Error()
		} else {
			evidence.Control = make(map[string]float64)
			for name, value := range values {
				if strings.HasPrefix(name, "tnl_") || name == "process_open_fds" || name == "process_max_fds" {
					evidence.Control[name] = value
				}
			}
		}
	}
	if err := json.NewEncoder(os.Stderr).Encode(evidence); err != nil {
		fmt.Fprintf(os.Stderr, "tnlbench: encode failure evidence: %v\n", err)
	}
}

func benchmarkHostnameSuffix(discovery controlv1.ControlDiscovery, configured string) (string, error) {
	managed, err := naming.CanonicalizeHostname(discovery.ManagedDeploymentDomain)
	if err != nil || managed != discovery.ManagedDeploymentDomain {
		return "", errors.New("server advertises an invalid managed deployment domain")
	}
	return configured, nil
}

func benchmarkRouteLabel(driverIndex, routeIndex int) string {
	return fmt.Sprintf("tnlbench-d%d-r%d", driverIndex, routeIndex)
}

func benchmarkHostname(driverIndex, routeIndex int, suffix string) string {
	return benchmarkRouteLabel(driverIndex, routeIndex) + "." + suffix
}

func parseMetrics(body string) map[string]float64 {
	values := make(map[string]float64)
	for line := range strings.SplitSeq(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err == nil {
			values[fields[0]] = value
		}
	}
	return values
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}
