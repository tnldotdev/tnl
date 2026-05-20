package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/serverclient"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

type cli struct {
	CellID             string        `name:"cell-id" env:"TNL_BENCH_CELL_ID" help:"Stable expanded benchmark cell ID."`
	Suite              string        `name:"suite" env:"TNL_BENCH_SUITE" default:"legacy" help:"Benchmark suite name."`
	Workload           string        `name:"workload" env:"TNL_BENCH_WORKLOAD" default:"agent-worktrees-assumed-v1" help:"Benchmark workload ID."`
	Repetition         int           `name:"repetition" env:"TNL_BENCH_REPETITION" default:"1" help:"One-based cell repetition."`
	Topology           string        `name:"topology" env:"TNL_BENCH_TOPOLOGY" enum:"single-node,ha" required:"" help:"Deployment topology under test."`
	ServerURL          string        `name:"server" env:"TNL_BENCH_SERVER" required:"" help:"Server HTTPS origin."`
	LoginToken         string        `name:"login-token" env:"TNL_BENCH_LOGIN_TOKEN" required:"" help:"Server login token."`
	ControlCAFile      string        `name:"control-ca-file" env:"TNL_BENCH_CONTROL_CA_FILE" type:"path" help:"Optional PEM CA for the server endpoint; system roots are used when omitted."`
	CertificateFile    string        `name:"certificate-file" env:"TNL_BENCH_CERTIFICATE_FILE" type:"path" help:"Optional PEM certificate chain shared by benchmark routes."`
	CertificateKeyFile string        `name:"certificate-key-file" env:"TNL_BENCH_CERTIFICATE_KEY_FILE" type:"path" help:"Private key for --certificate-file."`
	PublicAddress      string        `name:"public-address" env:"TNL_BENCH_PUBLIC_ADDRESS" required:"" help:"Public ingress host:port to dial."`
	HostnameSuffix     string        `name:"hostname-suffix" env:"TNL_BENCH_HOSTNAME_SUFFIX" required:"" help:"Suffix below which benchmark routes are created."`
	MetricsURLs        []string      `name:"metrics-url" env:"TNL_BENCH_METRICS_URLS" help:"Private worker metrics URL; repeat for each worker."`
	EdgeMetricsURL     string        `name:"edge-metrics-url" env:"TNL_BENCH_EDGE_METRICS_URL" help:"Private edge metrics URL used for failure evidence."`
	Routes             int           `name:"routes" env:"TNL_BENCH_ROUTES" default:"1" help:"Routes to activate."`
	ExpectedRoutes     int           `name:"expected-routes" env:"TNL_BENCH_EXPECTED_ROUTES" help:"Aggregate worker route count used to coordinate driver shards; defaults to routes."`
	DriverIndex        int           `name:"driver-index" env:"TNL_BENCH_DRIVER_INDEX" help:"Zero-based index of this driver shard."`
	DriverCount        int           `name:"driver-count" env:"TNL_BENCH_DRIVER_COUNT" default:"1" help:"Number of coordinated driver shards."`
	BarrierURL         string        `name:"barrier-url" env:"TNL_BENCH_BARRIER_URL" help:"Driver coordinator URL."`
	BarrierListen      string        `name:"barrier-listen" env:"TNL_BENCH_BARRIER_LISTEN" help:"Driver coordinator listen address; set on driver zero."`
	BarrierToken       string        `name:"barrier-token" env:"TNL_BENCH_BARRIER_TOKEN" help:"Driver coordinator bearer token."`
	Parallel           int           `name:"parallel" env:"TNL_BENCH_PARALLEL" default:"8" help:"Maximum concurrent setup, load, and cleanup operations."`
	PayloadBytes       int           `name:"payload-bytes" env:"TNL_BENCH_PAYLOAD_BYTES" default:"65536" help:"Response bytes transferred per route."`
	Timeout            time.Duration `name:"timeout" env:"TNL_BENCH_TIMEOUT" default:"30m" help:"Overall benchmark deadline."`
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
	if (c.CertificateFile == "") != (c.CertificateKeyFile == "") {
		return errors.New("certificate file and key file must be provided together")
	}
	if c.Routes <= 0 || c.Routes > 5000 {
		return errors.New("routes must be between 1 and 5000")
	}
	if expected := c.expectedRoutes(); expected < c.Routes || expected > 100000 {
		return errors.New("expected routes must be between routes and 100000")
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
	for _, rawURL := range c.MetricsURLs {
		if err := validateMetricsURL(rawURL); err != nil {
			return fmt.Errorf("invalid metrics URL %q", rawURL)
		}
	}
	if c.EdgeMetricsURL != "" {
		if err := validateMetricsURL(c.EdgeMetricsURL); err != nil {
			return fmt.Errorf("invalid edge metrics URL %q", c.EdgeMetricsURL)
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

func (c cli) expectedRoutes() int {
	if c.ExpectedRoutes == 0 {
		return c.Routes
	}
	return c.ExpectedRoutes
}

func (c cli) cellID() string {
	if c.CellID != "" {
		return c.CellID
	}
	return fmt.Sprintf("%s-r%d-rep%d", c.Topology, c.expectedRoutes(), c.Repetition)
}

type routeProcess struct {
	hostname      string
	routeID       string
	hostnameID    string
	hostnameOwner hostnameOwner
	cancel        context.CancelFunc
	done          chan error
}

type routeCleaner interface {
	DeleteRoute(context.Context, string) error
	ListRoutes(context.Context) ([]serverv1.Route, error)
}

type hostnameOwner interface {
	RemoveHostname(context.Context, string) error
}

type timingSummary struct {
	P50Milliseconds float64 `json:"p50_milliseconds"`
	P95Milliseconds float64 `json:"p95_milliseconds"`
	MaxMilliseconds float64 `json:"max_milliseconds"`
}

type workerSample struct {
	Worker                               int     `json:"worker"`
	Routes                               int     `json:"routes"`
	Capacity                             int     `json:"capacity"`
	RSSBytes                             float64 `json:"rss_bytes"`
	Goroutines                           int     `json:"goroutines"`
	OpenFDs                              int     `json:"open_fds"`
	MaxFDs                               int     `json:"max_fds"`
	TailcatProcessFileLimitStartFailures int     `json:"tailcat_process_file_limit_start_failures,omitempty"`
	TailcatSystemFileLimitStartFailures  int     `json:"tailcat_system_file_limit_start_failures,omitempty"`
}

type failureEvidence struct {
	EvidenceSchemaVersion int                `json:"evidence_schema_version"`
	Kind                  string             `json:"kind"`
	Workers               []workerSample     `json:"workers,omitempty"`
	WorkerError           string             `json:"worker_error,omitempty"`
	Edge                  map[string]float64 `json:"edge,omitempty"`
	EdgeError             string             `json:"edge_error,omitempty"`
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
	ReadyWorkers      []workerSample
	SettledWorkers    []workerSample
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
		os.Stderr, "tnlbench: starting %s shard with %d of %d routes\n",
		flags.Topology, flags.Routes, flags.expectedRoutes(),
	)
	controlRoots, err := loadCertPool(flags.ControlCAFile)
	if err != nil {
		return measurements{}, err
	}
	controlHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: controlRoots, MinVersion: tls.VersionTLS13,
	}}, Timeout: 30 * time.Second}
	anonymous, err := serverclient.New(flags.ServerURL, controlHTTP, "")
	if err != nil {
		return measurements{}, err
	}
	login := credentials.LoginToken(flags.LoginToken)
	if _, err := credentials.ParseLoginToken(login); err != nil {
		return measurements{}, errors.New("invalid login token")
	}
	issued, err := anonymous.Exchange(ctx, login)
	if err != nil {
		return measurements{}, fmt.Errorf("exchange login token: %w", err)
	}
	access := credentials.AccessToken(issued.AccessToken)
	if _, _, err := credentials.ParseAccessToken(access); err != nil {
		return measurements{}, errors.New("server returned invalid access token")
	}
	server, err := serverclient.New(flags.ServerURL, controlHTTP, access)
	if err != nil {
		return measurements{}, err
	}
	capabilities, err := server.Capabilities(ctx)
	if err != nil {
		return measurements{}, fmt.Errorf("read capabilities: %w", err)
	}
	if capabilities.Transport.Type != serverv1.Tailcat || capabilities.Transport.Version != serverv1.TransportCapabilitiesVersionN1 {
		return measurements{}, errors.New("server does not advertise Tailcat transport version 1")
	}
	hostnameSuffix, err := benchmarkHostnameSuffix(capabilities, flags.HostnameSuffix)
	if err != nil {
		return measurements{}, err
	}
	relayMap, err := server.RelayMap(ctx)
	if err != nil {
		return measurements{}, fmt.Errorf("read server relay map: %w", err)
	}
	regions, err := config.DecodeRelayRegions(relayMap)
	if err != nil {
		return measurements{}, err
	}
	if regions[capabilities.Transport.RelayRegion] == nil {
		return measurements{}, fmt.Errorf("relay region %q is absent from the relay map", capabilities.Transport.RelayRegion)
	}
	hostnames := make([]string, flags.Routes)
	for index := range hostnames {
		hostnames[index] = benchmarkHostname(flags.DriverIndex, index, hostnameSuffix)
	}
	applicationCertificates, applicationRoots, err := benchmarkCertificates(
		hostnames, flags.CertificateFile, flags.CertificateKeyFile,
	)
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
		ctx, flags, server, regions, capabilities.Transport.RelayRegion, origin.URL, hostnames, applicationCertificates,
	)
	if err != nil {
		writeFailureEvidence(flags)
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_, _ = cleanupRoutes(cleanupCtx, flags, server, processes)
		return measurements{}, err
	}
	activationElapsed := time.Since(activationStarted)
	fmt.Fprintln(os.Stderr, "tnlbench: activation complete")
	cleaned := false
	defer func() {
		if !cleaned {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			_, _ = cleanupRoutes(cleanupCtx, flags, server, processes)
		}
	}()
	// Barriers keep faster shards from entering the next phase early.
	if err := waitDriverBarrier(ctx, flags, "activated"); err != nil {
		return measurements{}, err
	}
	readyWorkers, err := waitWorkerRoutes(ctx, flags.MetricsURLs, flags.expectedRoutes())
	if err != nil {
		writeFailureEvidence(flags)
		return measurements{}, err
	}
	fmt.Fprintln(os.Stderr, "tnlbench: worker route count ready")
	if err := waitDriverBarrier(ctx, flags, "ready"); err != nil {
		return measurements{}, err
	}
	requestStarted := time.Now().UTC()
	firstByte, requests, elapsed, err := loadRoutes(ctx, flags, processes, applicationRoots, payload)
	if err != nil {
		return measurements{}, err
	}
	fmt.Fprintln(os.Stderr, "tnlbench: request load complete")
	if err := waitDriverBarrier(ctx, flags, "loaded"); err != nil {
		return measurements{}, err
	}
	cleanupStarted := time.Now().UTC()
	teardown, err := cleanupRoutes(ctx, flags, server, processes)
	if err != nil {
		return measurements{}, err
	}
	cleanupElapsed := time.Since(cleanupStarted)
	fmt.Fprintln(os.Stderr, "tnlbench: route cleanup complete")
	cleaned = true
	settledWorkers, err := waitWorkerRoutes(ctx, flags.MetricsURLs, 0)
	if err != nil {
		return measurements{}, err
	}
	fmt.Fprintln(os.Stderr, "tnlbench: worker route count settled")
	return measurements{
		ActivationStarted: activationStarted, ActivationElapsed: activationElapsed, Activation: activation,
		RequestStarted: requestStarted, RequestElapsed: elapsed, FirstByte: firstByte, Request: requests,
		CleanupStarted: cleanupStarted, CleanupElapsed: cleanupElapsed, Teardown: teardown,
		ReadyWorkers: readyWorkers, SettledWorkers: settledWorkers,
	}, nil
}

func activateRoutes(
	ctx context.Context,
	flags cli,
	server *serverclient.Client,
	regions map[string]*tailcfg.DERPRegion,
	relayRegion, target string,
	hostnames []string,
	certificates []tls.Certificate,
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
			hostname: hostnames[index], hostnameOwner: server, cancel: cancel, done: make(chan error, 1),
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
			hostname, err := server.AddHostname(
				routeCtx, serverv1.AddHostnameRequestKindManaged,
				benchmarkRouteLabel(flags.DriverIndex, index), benchmarkHostnameRequestKey(flags.DriverIndex, index),
			)
			if err != nil {
				err = fmt.Errorf("hostname: %w", err)
			} else {
				process.hostnameID = hostname.Id
				if hostname.Id == "" || hostname.Hostname != process.hostname {
					err = errors.New("server returned an unexpected hostname")
				}
			}
			ready := false
			if err == nil {
				err = publisher.Run(routeCtx, publisher.Config{
					Server: server, Hostname: process.hostname, Target: target, Certificate: certificates[index],
					RelayRegion: relayRegion, Regions: regions, Logf: logger.Discard,
					Observe: func(event publisher.Event) error {
						switch event.Type {
						case publisher.EventRoute:
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
	roots *x509.CertPool,
	wantPayload []byte,
) ([]time.Duration, []time.Duration, time.Duration, error) {
	// Force a new ingress stream for every sample.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, "tcp", flags.PublicAddress)
		},
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
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
	// Publishers own route deletion. Hostnames are removed only after that deletion is verified.
	started := time.Now()
	for _, process := range processes {
		if process != nil {
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

	remaining, verifyErr := remainingRoutes(cleanupCtx, server, routeIDs)
	if verifyErr != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("verify publisher route cleanup: %w", verifyErr))
	} else if len(remaining) != 0 {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("publisher cleanup left %d routes", len(remaining)))
		fmt.Fprintf(os.Stderr, "tnlbench: publisher cleanup left %d routes; using explicit deletion fallback\n", len(remaining))
		count := 0
		for index, routeID := range routeIDs {
			if _, found := remaining[routeID]; routeID == "" || !found {
				continue
			}
			count++
			semaphore <- struct{}{}
			go func(index int, routeID string) {
				defer func() { <-semaphore }()
				err := server.DeleteRoute(cleanupCtx, routeID)
				if errors.Is(err, serverclient.ErrNotFound) {
					err = nil
				}
				if err != nil {
					err = fmt.Errorf("fallback delete route %d: %w", index, err)
				}
				results <- cleanupResult{index: index, err: err}
			}(index, routeID)
		}
		for range count {
			result := <-results
			cleanupErr = errors.Join(cleanupErr, result.err)
		}
		if stillRemaining, err := remainingRoutes(cleanupCtx, server, routeIDs); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("verify fallback route cleanup: %w", err))
		} else if len(stillRemaining) != 0 {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("fallback cleanup left %d routes", len(stillRemaining)))
		}
	}

	completed := make([]time.Duration, len(processes))
	count := 0
	for index, process := range processes {
		if process == nil || process.hostnameID == "" {
			continue
		}
		if process.hostnameOwner == nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove hostname %d: missing owner", index))
			completed[index] = time.Since(started)
			continue
		}
		count++
		semaphore <- struct{}{}
		go func(index int, process *routeProcess) {
			defer func() { <-semaphore }()
			var err error
			if releaseErr := process.hostnameOwner.RemoveHostname(cleanupCtx, process.hostnameID); releaseErr != nil {
				err = fmt.Errorf("remove hostname %d: %w", index, releaseErr)
			}
			completed[index] = time.Since(started)
			results <- cleanupResult{index: index, err: err}
		}(index, process)
	}
	for range count {
		result := <-results
		cleanupErr = errors.Join(cleanupErr, result.err)
	}
	timings := make([]time.Duration, 0, len(processes))
	for index, process := range processes {
		if process == nil {
			continue
		}
		if completed[index] == 0 {
			completed[index] = time.Since(started)
		}
		timings = append(timings, completed[index])
	}
	return timings, cleanupErr
}

func remainingRoutes(ctx context.Context, server routeCleaner, routeIDs []string) (map[string]struct{}, error) {
	wanted := make(map[string]struct{}, len(routeIDs))
	for _, routeID := range routeIDs {
		if routeID != "" {
			wanted[routeID] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return nil, nil
	}
	routes, err := server.ListRoutes(ctx)
	if err != nil {
		return nil, err
	}
	remaining := make(map[string]struct{})
	for _, route := range routes {
		if _, found := wanted[route.Id]; found {
			remaining[route.Id] = struct{}{}
		}
	}
	return remaining, nil
}

func waitWorkerRoutes(ctx context.Context, metricsURLs []string, want int) ([]workerSample, error) {
	if len(metricsURLs) == 0 {
		return nil, nil
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var lastSamples []workerSample
	lastTotal := -1
	maxTotal := -1
	var lastErr error
	for {
		samples, err := sampleWorkers(ctx, metricsURLs)
		if err == nil {
			total := 0
			valid := true
			for _, sample := range samples {
				total += sample.Routes
				valid = valid && sample.Routes <= sample.Capacity
			}
			lastSamples = samples
			lastTotal = total
			maxTotal = max(maxTotal, total)
			lastErr = nil
			// Allow activation overshoot across shards, but require exact zero after teardown.
			if valid && (total == want || want > 0 && total > want) {
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
					counts[index] = sample.Routes
				}
				return nil, fmt.Errorf(
					"worker routes did not reach %d (last=%d max=%d workers=%v): %w",
					want, lastTotal, maxTotal, counts, ctx.Err(),
				)
			}
			return nil, errors.Join(errors.New("sample worker routes"), lastErr, ctx.Err())
		case <-ticker.C:
		}
	}
}

func sampleWorkers(ctx context.Context, metricsURLs []string) ([]workerSample, error) {
	samples := make([]workerSample, len(metricsURLs))
	for index, metricsURL := range metricsURLs {
		values, err := sampleMetrics(ctx, metricsURL)
		if err != nil {
			return nil, fmt.Errorf("metrics worker %d: %w", index, err)
		}
		samples[index] = workerSample{
			Worker: index, Routes: int(values["tnl_worker_routes_active"]),
			Capacity: int(values["tnl_worker_route_capacity"]), RSSBytes: values["process_resident_memory_bytes"],
			Goroutines: int(values["go_goroutines"]), OpenFDs: int(values["process_open_fds"]),
			MaxFDs:                               int(values["process_max_fds"]),
			TailcatProcessFileLimitStartFailures: int(values[`tnl_tailcat_failures_total{operation="start",reason="process_file_limit"}`]),
			TailcatSystemFileLimitStartFailures:  int(values[`tnl_tailcat_failures_total{operation="start",reason="system_file_limit"}`]),
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
	workers, err := sampleWorkers(ctx, flags.MetricsURLs)
	if err != nil {
		evidence.WorkerError = err.Error()
	} else {
		evidence.Workers = workers
	}
	if flags.EdgeMetricsURL != "" {
		values, err := sampleMetrics(ctx, flags.EdgeMetricsURL)
		if err != nil {
			evidence.EdgeError = err.Error()
		} else {
			evidence.Edge = make(map[string]float64)
			for name, value := range values {
				if strings.HasPrefix(name, "tnl_") || name == "process_open_fds" || name == "process_max_fds" {
					evidence.Edge[name] = value
				}
			}
		}
	}
	if err := json.NewEncoder(os.Stderr).Encode(evidence); err != nil {
		fmt.Fprintf(os.Stderr, "tnlbench: encode failure evidence: %v\n", err)
	}
}

func benchmarkHostnameSuffix(capabilities serverv1.Capabilities, configured string) (string, error) {
	localClaim := false
	for _, authorization := range capabilities.HostnameAuthorization {
		localClaim = localClaim || authorization == serverv1.LocalHostnames
	}
	if !localClaim || capabilities.LocalHostnames == nil || capabilities.LocalHostnames.Suffix == "" {
		return "", errors.New("server does not advertise local hostnames")
	}
	suffix, err := naming.CanonicalizeHostname(capabilities.LocalHostnames.Suffix)
	if err != nil || suffix != capabilities.LocalHostnames.Suffix {
		return "", errors.New("server advertises an invalid local hostname suffix")
	}
	if suffix != configured {
		return "", fmt.Errorf("server local hostname suffix %q does not match configured suffix %q", suffix, configured)
	}
	return suffix, nil
}

func benchmarkRouteLabel(driverIndex, routeIndex int) string {
	return fmt.Sprintf("tnlbench-d%d-r%d", driverIndex, routeIndex)
}

func benchmarkHostname(driverIndex, routeIndex int, suffix string) string {
	return benchmarkRouteLabel(driverIndex, routeIndex) + "." + suffix
}

func benchmarkHostnameRequestKey(driverIndex, routeIndex int) string {
	return "hostname_" + benchmarkRouteLabel(driverIndex, routeIndex)
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

func summarize(samples []time.Duration) timingSummary {
	if len(samples) == 0 {
		return timingSummary{}
	}
	ordered := append([]time.Duration(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	return timingSummary{
		P50Milliseconds: milliseconds(ordered[percentileIndex(len(ordered), 50)]),
		P95Milliseconds: milliseconds(ordered[percentileIndex(len(ordered), 95)]),
		MaxMilliseconds: milliseconds(ordered[len(ordered)-1]),
	}
}

func percentileIndex(length, percentile int) int {
	// Use nearest-rank percentiles so every result is an observed sample.
	index := (length*percentile + 99) / 100
	if index <= 0 {
		return 0
	}
	return index - 1
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}
