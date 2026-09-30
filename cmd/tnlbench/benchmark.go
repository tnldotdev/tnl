package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/tunnel"
)

type workloadOptions struct {
	Suite                       string        `name:"suite" env:"BENCH_SUITE" default:"smoke" enum:"smoke,target" help:"Small smoke or an explicit target workload."`
	Server                      string        `name:"server" env:"BENCH_SERVER" required:"" help:"HTTPS control URL of the approved tnl server."`
	Transport                   string        `name:"transport" env:"BENCH_TRANSPORT" default:"mixed" enum:"mixed,quic,tcp,auto" help:"Forced cohorts or normal QUIC/TLS-TCP selection."`
	QUICDisablePathMTUDiscovery bool          `name:"quic-disable-path-mtu-discovery" env:"BENCH_QUIC_DISABLE_PATH_MTU_DISCOVERY" help:"Disable publisher QUIC path-MTU discovery for a diagnostic run."`
	QUICQlog                    bool          `name:"quic-qlog" env:"BENCH_QUIC_QLOG" help:"Record publisher QUIC qlogs in the benchmark result directory."`
	QUICKeepAlive               time.Duration `name:"quic-keepalive" env:"BENCH_QUIC_KEEPALIVE" help:"Publisher QUIC keepalive period override for a diagnostic run."`
	VisitorNetwork              string        `name:"visitor-network" env:"BENCH_VISITOR_NETWORK" default:"tcp" enum:"tcp,tcp4,tcp6" help:"Network used by public visitor TCP sockets."`
	VisitorInterface            string        `name:"visitor-interface" env:"BENCH_VISITOR_INTERFACE" help:"Local interface whose IPv4 address is used by public visitors only."`
	PublicURLs                  int           `name:"public-urls" env:"BENCH_PUBLIC_URLS" default:"4" help:"Public URLs to publish."`
	FreshRate                   int           `name:"fresh-connections-per-second" env:"BENCH_FRESH_CONNECTIONS_PER_SECOND" default:"16" help:"Offered visitor requests per second."`
	HeldStreams                 int           `name:"held-streams" env:"BENCH_HELD_STREAMS" default:"4" help:"Held visitor streams."`
	Concurrency                 int           `name:"concurrency" env:"BENCH_CONCURRENCY" default:"128" help:"Concurrent visitor request workers."`
	QueueSlots                  int           `name:"queue-slots" env:"BENCH_QUEUE_SLOTS" default:"8" help:"Waiting visitor request slots."`
	PayloadBytes                int           `name:"payload-bytes" env:"BENCH_PAYLOAD_BYTES" default:"32768" help:"Verified response bytes."`
	Repetitions                 int           `name:"repetitions" env:"BENCH_REPETITIONS" default:"1" help:"Measurement windows."`
	Warmup                      time.Duration `name:"warmup" env:"BENCH_WARMUP" default:"5s" help:"Time before measuring."`
	Duration                    time.Duration `name:"duration" env:"BENCH_DURATION" default:"10s" help:"Length of each measurement window."`
	StateDir                    string        `name:"state-dir" env:"BENCH_STATE_DIR" type:"path" help:"Client state with an existing login for the selected server."`
	ResultsRoot                 string        `name:"results-root" env:"BENCH_RESULTS_ROOT" default:"bench-results" type:"path" help:"Result directory."`
}

type benchmarkPlan struct {
	SchemaVersion int             `json:"schema_version"`
	ReadOnly      bool            `json:"read_only"`
	Server        string          `json:"server"`
	Workload      workloadSummary `json:"workload"`
}

type workloadSummary struct {
	Suite                       string        `json:"suite"`
	Transport                   string        `json:"transport"`
	QUICDisablePathMTUDiscovery bool          `json:"quic_disable_path_mtu_discovery,omitempty"`
	QUICQlog                    bool          `json:"quic_qlog,omitempty"`
	QUICKeepAlive               time.Duration `json:"quic_keepalive,omitempty"`
	VisitorNetwork              string        `json:"visitor_network"`
	VisitorInterface            string        `json:"visitor_interface,omitempty"`
	PublicURLs                  int           `json:"public_urls"`
	FreshRate                   int           `json:"fresh_connections_per_second"`
	HeldStreams                 int           `json:"held_streams"`
	Concurrency                 int           `json:"concurrency"`
	QueueSlots                  int           `json:"queue_slots"`
	PayloadBytes                int           `json:"payload_bytes"`
	Repetitions                 int           `json:"repetitions"`
	Warmup                      time.Duration `json:"warmup"`
	Duration                    time.Duration `json:"duration"`
}

func (c workloadOptions) plan() (benchmarkPlan, error) {
	if c.Server == "" {
		return benchmarkPlan{}, errors.New("benchmark requires --server or BENCH_SERVER")
	}
	server, err := clientstate.CanonicalServer(c.Server)
	if err != nil {
		return benchmarkPlan{}, err
	}
	if c.Suite != "smoke" && c.Suite != "target" {
		return benchmarkPlan{}, errors.New("suite must be smoke or target")
	}
	if c.Transport != "mixed" && c.Transport != "quic" && c.Transport != "tcp" && c.Transport != "auto" {
		return benchmarkPlan{}, errors.New("transport must be mixed, quic, tcp, or auto")
	}
	if c.VisitorNetwork != "tcp" && c.VisitorNetwork != "tcp4" && c.VisitorNetwork != "tcp6" {
		return benchmarkPlan{}, errors.New("visitor network must be tcp, tcp4, or tcp6")
	}
	if c.QUICKeepAlive < 0 || c.QUICKeepAlive > 0 && (c.QUICKeepAlive < time.Second || c.QUICKeepAlive > time.Minute) {
		return benchmarkPlan{}, errors.New("QUIC keepalive must be zero or between 1s and 1m")
	}
	if c.VisitorInterface != "" {
		if c.VisitorNetwork == "tcp6" {
			return benchmarkPlan{}, errors.New("a selected visitor interface requires IPv4 visitor sockets")
		}
		if _, err := visitorSourceAddress(c.VisitorInterface); err != nil {
			return benchmarkPlan{}, err
		}
	}
	if c.PublicURLs < 1 || c.PublicURLs > 10_000 || c.FreshRate < 1 || c.FreshRate > 10_000 || c.HeldStreams < 0 || c.HeldStreams > 100_000 || c.Concurrency < 1 || c.Concurrency > 100_000 || c.QueueSlots < 0 || c.QueueSlots > 10_000 || c.PayloadBytes < 1 || c.PayloadBytes > 16<<20 || c.Repetitions < 1 || c.Repetitions > 10 || c.Warmup < 0 || c.Warmup > 5*time.Minute || c.Duration < time.Second || c.Duration > time.Hour {
		return benchmarkPlan{}, errors.New("invalid workload shape or duration")
	}
	if c.Suite == "smoke" && (c.Transport != "mixed" || c.PublicURLs > 4 || c.FreshRate > 16 ||
		c.HeldStreams > 4 || c.Concurrency > 128 || c.QueueSlots > 8 || c.PayloadBytes > 32<<10 ||
		c.Repetitions != 1 || c.Warmup > 5*time.Second || c.Duration > 30*time.Second) {
		return benchmarkPlan{}, errors.New("larger workloads require suite target")
	}
	return benchmarkPlan{SchemaVersion: 2, ReadOnly: true, Server: server,
		Workload: workloadSummary{Suite: c.Suite, Transport: c.Transport, QUICDisablePathMTUDiscovery: c.QUICDisablePathMTUDiscovery, QUICQlog: c.QUICQlog, QUICKeepAlive: c.QUICKeepAlive, VisitorNetwork: c.VisitorNetwork, VisitorInterface: c.VisitorInterface, PublicURLs: c.PublicURLs, FreshRate: c.FreshRate,
			HeldStreams: c.HeldStreams, Concurrency: c.Concurrency, QueueSlots: c.QueueSlots,
			PayloadBytes: c.PayloadBytes, Repetitions: c.Repetitions, Warmup: c.Warmup, Duration: c.Duration}}, nil
}

type planCommand struct {
	workloadOptions
	Format string `name:"format" default:"human" enum:"human,json" help:"Plan output format."`
}

func (c planCommand) run(stdout io.Writer) error {
	plan, err := c.plan()
	if err != nil {
		return err
	}
	if c.Format == "json" {
		return json.NewEncoder(stdout).Encode(plan)
	}
	fmt.Fprintf(stdout, "Benchmark plan (READ ONLY)\nServer: %s\nGenerators: local publisher and visitor\n", plan.Server)
	fmt.Fprintf(stdout, "Publisher transport: %s\n", c.Transport)
	if c.QUICDisablePathMTUDiscovery {
		fmt.Fprintln(stdout, "Publisher QUIC path-MTU discovery: disabled")
	}
	if c.QUICQlog {
		fmt.Fprintln(stdout, "Publisher QUIC qlog: enabled")
	}
	if c.QUICKeepAlive > 0 {
		fmt.Fprintf(stdout, "Publisher QUIC keepalive: %s\n", c.QUICKeepAlive)
	}
	fmt.Fprintf(stdout, "Visitor network: %s", c.VisitorNetwork)
	if c.VisitorInterface != "" {
		fmt.Fprintf(stdout, " via %s", c.VisitorInterface)
	}
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "Workload: %d public URLs, %d fresh/s, %d held, %d bytes\n", c.PublicURLs, c.FreshRate, c.HeldStreams, c.PayloadBytes)
	fmt.Fprintf(stdout, "Windows: %d x %s; warmup %s; local direct baseline %s\n", c.Repetitions, c.Duration, c.Warmup, c.Duration)
	_, err = fmt.Fprintln(stdout, "Execution requires an explicit BENCH_SUITE and BENCH_APPROVED=1.")
	return err
}

type runCommand struct {
	workloadOptions
	Approved string `name:"approved" env:"BENCH_APPROVED" help:"Explicit approval for this server and workload; must be 1."`
}

func (c runCommand) validate() (benchmarkPlan, error) {
	plan, err := c.plan()
	if err != nil {
		return plan, err
	}
	if c.Approved != "1" {
		return plan, errors.New("BENCH_APPROVED must be exactly 1; planning does not grant execution approval")
	}
	if value, found := os.LookupEnv("BENCH_SUITE"); !found || value == "" || value != c.Suite {
		return plan, errors.New("execution requires an explicit BENCH_SUITE environment variable")
	}
	return plan, nil
}

type benchmarkResult struct {
	SchemaVersion int                             `json:"schema_version"`
	RunID         string                          `json:"run_id"`
	Plan          benchmarkPlan                   `json:"plan"`
	StartedAt     time.Time                       `json:"started_at"`
	FinishedAt    time.Time                       `json:"finished_at"`
	Status        string                          `json:"status"`
	Error         string                          `json:"error,omitempty"`
	PublicURLs    []string                        `json:"public_urls,omitempty"`
	PublicURLInfo []benchmarkPublicURL            `json:"public_url_info,omitempty"`
	Fallbacks     []benchmarkTransportFallback    `json:"transport_fallbacks,omitempty"`
	Observations  []benchmarkPublisherObservation `json:"publisher_observations,omitempty"`
	Dropped       int                             `json:"publisher_observations_dropped,omitempty"`
	Direct        benchworkload.VisitorResult     `json:"direct_baseline"`
	Steady        []benchworkload.VisitorResult   `json:"steady"`
	SteadyByURL   []map[string]*urlVisitorResult  `json:"steady_by_public_url,omitempty"`
	CleanupExact  bool                            `json:"cleanup_exact"`
	CleanupStatus string                          `json:"cleanup_status"`
	Generator     generatorResult                 `json:"generator"`
}

type benchmarkPublicURL struct {
	Index       int           `json:"index"`
	PublicURL   string        `json:"public_url"`
	PublicURLID string        `json:"public_url_id"`
	Transport   string        `json:"transport"`
	Activation  time.Duration `json:"activation"`
}

type benchmarkPublisherObservation struct {
	Index       int       `json:"index"`
	PublicURLID string    `json:"public_url_id,omitempty"`
	At          time.Time `json:"at"`
	Kind        string    `json:"kind"`
	Detail      string    `json:"detail,omitempty"`
}

const maxPublisherObservations = 64

type publisherObservationRecorder struct {
	mu      sync.Mutex
	events  []benchmarkPublisherObservation
	dropped int
}

func (r *publisherObservationRecorder) add(event benchmarkPublisherObservation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) == maxPublisherObservations {
		oldest := 0
		for index, previous := range r.events {
			if previous.Kind == "error" {
				oldest = index
				break
			}
		}
		copy(r.events[oldest:], r.events[oldest+1:])
		r.events[len(r.events)-1] = event
		r.dropped++
		return
	}
	r.events = append(r.events, event)
}

func (r *publisherObservationRecorder) Observe(index int, event publisher.Event) error {
	r.add(benchmarkPublisherObservation{Index: index, PublicURLID: event.PublicURLID, At: time.Now().UTC(), Kind: string(event.Type)})
	return nil
}

func (r *publisherObservationRecorder) Report(index int, err error) {
	r.add(benchmarkPublisherObservation{Index: index, At: time.Now().UTC(), Kind: "error", Detail: err.Error()})
}

func (r *publisherObservationRecorder) Snapshot() ([]benchmarkPublisherObservation, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]benchmarkPublisherObservation(nil), r.events...), r.dropped
}

type benchmarkTransportFallback struct {
	PublicURLID string    `json:"public_url_id"`
	At          time.Time `json:"at"`
}

type transportFallbackRecorder struct {
	mu     sync.Mutex
	events []benchmarkTransportFallback
}

func (r *transportFallbackRecorder) Observe(_ int, event publisher.Event) error {
	if event.Type == publisher.EventTransportFallback {
		r.mu.Lock()
		r.events = append(r.events, benchmarkTransportFallback{PublicURLID: event.PublicURLID, At: time.Now().UTC()})
		r.mu.Unlock()
	}
	return nil
}

func (r *transportFallbackRecorder) Snapshot() []benchmarkTransportFallback {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]benchmarkTransportFallback(nil), r.events...)
}

type urlVisitorResult struct {
	Scheduled    int                          `json:"scheduled"`
	Started      int                          `json:"started"`
	Successes    int                          `json:"successes"`
	Failures     int                          `json:"failures"`
	Timeouts     int                          `json:"timeouts"`
	Missed       int                          `json:"missed"`
	QueueExpired int                          `json:"queue_expired"`
	FirstFailure *benchworkload.RequestResult `json:"first_failure,omitempty"`
}

type generatorResult struct {
	Goroutines int           `json:"goroutines"`
	HeapBytes  uint64        `json:"heap_bytes"`
	Elapsed    time.Duration `json:"elapsed"`
}

func (c runCommand) run(ctx context.Context, stdout, progress io.Writer) error {
	plan, err := c.validate()
	if err != nil {
		return err
	}
	stateDir := c.StateDir
	if stateDir == "" {
		stateDir, err = clientstate.DefaultDir()
		if err != nil {
			return err
		}
	}
	if err := os.MkdirAll(c.ResultsRoot, 0o700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(c.ResultsRoot, "run-")
	if err != nil {
		return err
	}
	resultPath := filepath.Join(dir, "result.json")
	if c.QUICQlog {
		qlogDir := filepath.Join(dir, "quic")
		if err := os.Mkdir(qlogDir, 0o700); err != nil {
			return err
		}
		previous, found := os.LookupEnv("QLOGDIR")
		if err := os.Setenv("QLOGDIR", qlogDir); err != nil {
			return err
		}
		defer func() {
			if found {
				_ = os.Setenv("QLOGDIR", previous)
			} else {
				_ = os.Unsetenv("QLOGDIR")
			}
		}()
	}
	initial := benchmarkResult{SchemaVersion: 2, RunID: filepath.Base(dir), Plan: plan,
		StartedAt: time.Now().UTC(), Status: "running", CleanupStatus: "not_needed"}
	if err := writeJSON(resultPath, initial); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "Results: %s\n", resultPath); err != nil {
		return err
	}
	result, runErr := c.measure(ctx, plan, stateDir, initial.RunID, progress, func(snapshot benchmarkResult) error {
		return writeJSON(resultPath, snapshot)
	})
	result.FinishedAt = time.Now().UTC()
	result.Status = "passed"
	if runErr != nil {
		result.Status, result.Error = "failed", runErr.Error()
		if ctx.Err() != nil {
			result.Status = "interrupted"
		}
	}
	if err := writeJSON(resultPath, result); err != nil {
		return errors.Join(runErr, err)
	}
	if err := printResult(stdout, result); err != nil {
		return errors.Join(runErr, err)
	}
	return runErr
}

func (c runCommand) measure(parent context.Context, plan benchmarkPlan, stateDir, runID string, progress io.Writer, checkpoint func(benchmarkResult) error) (result benchmarkResult, retErr error) {
	result = benchmarkResult{SchemaVersion: 2, RunID: runID, Plan: plan, StartedAt: time.Now().UTC(),
		Status: "running", CleanupStatus: "not_needed"}
	defer func() {
		var memory runtime.MemStats
		runtime.ReadMemStats(&memory)
		result.Generator = generatorResult{Goroutines: runtime.NumGoroutine(), HeapBytes: memory.HeapAlloc, Elapsed: time.Since(result.StartedAt)}
	}()
	source, err := visitorSourceAddress(c.VisitorInterface)
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration((c.PublicURLs+3)/4)*5*time.Minute+c.Warmup+time.Duration(c.Repetitions+1)*c.Duration+3*time.Minute)
	defer cancel()
	origin := httptest.NewServer(benchworkload.Origin(c.PayloadBytes))
	defer origin.Close()
	direct := httptest.NewTLSServer(benchworkload.Origin(c.PayloadBytes))
	defer direct.Close()
	roots := x509.NewCertPool()
	roots.AddCert(direct.Certificate())
	baseline := benchworkload.Visitor{Roots: roots, PayloadBytes: c.PayloadBytes}
	retErr = reportPhase(progress, "local baseline", c.Duration, func() error {
		var err error
		result.Direct, err = baseline.Run(ctx, benchworkload.VisitorConfig{
			Rate: c.FreshRate, Workers: c.Concurrency, QueueSlots: c.QueueSlots, Duration: c.Duration,
		}, []string{direct.URL})
		return err
	})
	if retErr != nil {
		return result, fmt.Errorf("local generator baseline: %w", retErr)
	}
	if err := result.Direct.Err(); err != nil {
		return result, fmt.Errorf("local generator baseline: %w", err)
	}
	fmt.Fprintf(progress, "tnlbench: connecting to %s\n", plan.Server)
	fallbacks := &transportFallbackRecorder{}
	defer func() { result.Fallbacks = fallbacks.Snapshot() }()
	observations := &publisherObservationRecorder{}
	defer func() { result.Observations, result.Dropped = observations.Snapshot() }()
	group, err := benchworkload.OpenPublishers(ctx, benchworkload.PublisherConfig{
		Server: plan.Server, StateRoot: stateDir, Target: origin.URL,
		HostnamePrefix: "tnlbench" + strings.TrimPrefix(runID, "run-"), Ephemeral: true,
		Transport: c.Transport, QUICDisablePathMTUDiscovery: c.QUICDisablePathMTUDiscovery, QUICQlog: c.QUICQlog, QUICKeepAlive: c.QUICKeepAlive,
		RelayTLS: &tls.Config{MinVersion: tls.VersionTLS13},
		Observe: func(index int, event publisher.Event) error {
			if err := fallbacks.Observe(index, event); err != nil {
				return err
			}
			return observations.Observe(index, event)
		},
		Report:   observations.Report,
		Parallel: 4, StartParallel: 4,
		ReadyTimeout: 5 * time.Minute, StopTimeout: 10 * time.Second,
	})
	if err != nil {
		return result, err
	}
	result.CleanupStatus = "pending"
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Minute)
		defer stop()
		var shutdown benchworkload.ShutdownResult
		err := reportPhase(progress, "publisher cleanup", 2*time.Minute, func() error {
			var err error
			shutdown, err = group.Close(cleanup)
			return err
		})
		if group.Started() == 0 {
			result.CleanupStatus = "not_needed"
		} else {
			result.CleanupExact = err == nil && shutdown.Failures == 0 && shutdown.Attempts == group.Started()
			result.CleanupStatus = "failed"
			if result.CleanupExact {
				result.CleanupStatus = "succeeded"
			}
		}
		fmt.Fprintf(progress, "tnlbench: cleanup %s (%d/%d publisher processes)\n", result.CleanupStatus, shutdown.Successes, group.Started())
		retErr = errors.Join(retErr, err)
	}()
	if err := checkpoint(result); err != nil {
		return result, err
	}
	indexes := make([]int, c.PublicURLs)
	for i := range indexes {
		indexes[i] = i
	}
	var publicURLs []benchworkload.PublishedPublicURL
	err = reportPhase(progress, fmt.Sprintf("activating %d public URLs", c.PublicURLs), 0, func() error {
		var err error
		publicURLs, err = group.Start(ctx, indexes)
		return err
	})
	urls := recordReadyPublicURLs(&result, publicURLs, c.Transport, c.PublicURLs)
	if checkpointErr := checkpoint(result); checkpointErr != nil {
		return result, errors.Join(err, checkpointErr)
	}
	if err != nil {
		return result, err
	}
	for _, publicURL := range urls {
		if publicURL == "" {
			return result, errors.New("missing public URL after activation")
		}
	}
	if err := reportPhase(progress, "public URL DNS", 2*time.Minute, func() error {
		return waitForPublicURLDNS(ctx, urls, net.DefaultResolver.LookupIPAddr)
	}); err != nil {
		return result, err
	}
	visitor := benchworkload.Visitor{PayloadBytes: c.PayloadBytes, Network: c.VisitorNetwork, SourceAddress: source}
	fmt.Fprintln(progress, "tnlbench: verifying each public URL")
	for _, url := range urls {
		if check := visitor.Request(ctx, url, time.Now()); check.Error != "" {
			return result, fmt.Errorf("visitor correctness %s: %s", url, check.Error)
		}
	}
	var held []*benchworkload.HeldStream
	defer func() {
		for _, stream := range held {
			retErr = errors.Join(retErr, stream.Close())
		}
	}()
	for i := range c.HeldStreams {
		stream, err := visitor.Hold(ctx, urls[i%len(urls)])
		if err != nil {
			return result, err
		}
		held = append(held, stream)
	}
	fmt.Fprintf(progress, "tnlbench: %d held visitor streams open\n", len(held))
	if err := reportPhase(progress, "warmup", c.Warmup, func() error {
		return wait(ctx, c.Warmup)
	}); err != nil {
		return result, err
	}
	for index := range c.Repetitions {
		var phase benchworkload.VisitorResult
		byURL, observe := newURLVisitorResults(urls)
		err := reportPhase(progress, fmt.Sprintf("server window %d/%d", index+1, c.Repetitions), c.Duration, func() error {
			var err error
			phase, err = visitor.Run(ctx, benchworkload.VisitorConfig{
				Rate: c.FreshRate, Workers: c.Concurrency, QueueSlots: c.QueueSlots, Duration: c.Duration,
				OnResult: observe,
			}, urls)
			return err
		})
		result.Steady = append(result.Steady, phase)
		result.SteadyByURL = append(result.SteadyByURL, byURL)
		if summaryErr := completeURLVisitorResults(urls, phase.Scheduled, byURL); summaryErr != nil {
			return result, errors.Join(err, summaryErr)
		}
		if err != nil {
			return result, err
		}
		if err := visitorWindowError(phase, held); err != nil {
			return result, fmt.Errorf("server visitor window %d: %w", index+1, err)
		}
	}
	return result, nil
}

func recordReadyPublicURLs(result *benchmarkResult, ready []benchworkload.PublishedPublicURL, transport string, count int) []string {
	urls := make([]string, count)
	for _, publicURL := range ready {
		urls[publicURL.Index] = publicURL.Ready.PublicURL
		selected := transport
		if selected == "tcp" || selected == "mixed" && publicURL.Index%2 != 0 {
			selected = string(tunnel.TransportTLSTCP)
		} else if selected == "quic" || selected == "mixed" {
			selected = string(tunnel.TransportQUIC)
		}
		result.PublicURLInfo = append(result.PublicURLInfo, benchmarkPublicURL{
			Index: publicURL.Index, PublicURL: publicURL.Ready.PublicURL, PublicURLID: publicURL.Ready.PublicURLID,
			Transport: selected, Activation: publicURL.Activation,
		})
	}
	slices.SortFunc(result.PublicURLInfo, func(a, b benchmarkPublicURL) int { return cmp.Compare(a.Index, b.Index) })
	for _, publicURL := range result.PublicURLInfo {
		result.PublicURLs = append(result.PublicURLs, publicURL.PublicURL)
	}
	return urls
}

func visitorWindowError(result benchworkload.VisitorResult, held []*benchworkload.HeldStream) error {
	err := result.Err()
	for index, stream := range held {
		if !stream.Alive() {
			err = errors.Join(err, fmt.Errorf("held visitor stream %d ended during steady traffic", index))
		}
	}
	return err
}

func visitorSourceAddress(name string) (*net.TCPAddr, error) {
	if name == "" {
		return nil, nil
	}
	interface_, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("visitor interface %q: %w", name, err)
	}
	addresses, err := interface_.Addrs()
	if err != nil {
		return nil, fmt.Errorf("visitor interface %q: %w", name, err)
	}
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok && network.IP.To4() != nil {
			return &net.TCPAddr{IP: network.IP.To4()}, nil
		}
	}
	return nil, fmt.Errorf("visitor interface %q has no IPv4 address", name)
}

func newURLVisitorResults(urls []string) (map[string]*urlVisitorResult, func(benchworkload.RequestResult)) {
	results := make(map[string]*urlVisitorResult, len(urls))
	for _, publicURL := range urls {
		results[publicURL] = new(urlVisitorResult)
	}
	// Visitor.Run serializes callbacks from its workers.
	observe := func(row benchworkload.RequestResult) {
		summary := results[row.URL]
		if row.QueueExpired {
			summary.QueueExpired++
		} else {
			summary.Started++
			if row.Error == "" {
				summary.Successes++
			} else {
				summary.Failures++
				if row.Timeout {
					summary.Timeouts++
				}
			}
		}
		if row.Error != "" && summary.FirstFailure == nil {
			summary.FirstFailure = &row
		}
	}
	return results, observe
}

func completeURLVisitorResults(urls []string, scheduled int, results map[string]*urlVisitorResult) error {
	perURL, remainder := scheduled/len(urls), scheduled%len(urls)
	for index, publicURL := range urls {
		summary := results[publicURL]
		summary.Scheduled = perURL
		if index < remainder {
			summary.Scheduled++
		}
		summary.Missed = summary.Scheduled - summary.Started - summary.QueueExpired
		if summary.Missed < 0 {
			return fmt.Errorf("public URL %s has more completed requests than scheduled", publicURL)
		}
	}
	return nil
}

func waitForPublicURLDNS(ctx context.Context, publicURLs []string, lookup func(context.Context, string) ([]net.IPAddr, error)) error {
	dnsCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for _, publicURL := range publicURLs {
		parsed, err := url.Parse(publicURL)
		if err != nil {
			return fmt.Errorf("invalid public URL %q: %w", publicURL, err)
		}
		if parsed.Hostname() == "" {
			return fmt.Errorf("public URL %q has no hostname", publicURL)
		}
		for {
			addresses, lookupErr := lookup(dnsCtx, parsed.Hostname())
			if lookupErr == nil && len(addresses) > 0 {
				break
			}
			if err := wait(dnsCtx, time.Second); err != nil {
				return fmt.Errorf("public URL DNS %s not ready: %w", parsed.Hostname(), errors.Join(err, lookupErr))
			}
		}
	}
	return nil
}

func reportPhase(progress io.Writer, name string, planned time.Duration, run func() error) error {
	return reportPhaseEvery(progress, name, planned, 30*time.Second, run)
}

func reportPhaseEvery(progress io.Writer, name string, planned, interval time.Duration, run func() error) error {
	started := time.Now()
	if planned > 0 {
		fmt.Fprintf(progress, "tnlbench: %s started (%s planned)\n", name, planned)
	} else {
		fmt.Fprintf(progress, "tnlbench: %s started\n", name)
	}
	done := make(chan struct{})
	var heartbeat sync.WaitGroup
	heartbeat.Go(func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				fmt.Fprintf(progress, "tnlbench: %s still running (%s elapsed)\n", name, time.Since(started).Truncate(time.Second))
			}
		}
	})
	err := run()
	close(done)
	heartbeat.Wait()
	status := "complete"
	if err != nil {
		status = "stopped"
	}
	fmt.Fprintf(progress, "tnlbench: %s %s after %s\n", name, status, time.Since(started).Truncate(time.Second))
	return err
}

func wait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type reportCommand struct {
	RunDirectory string `name:"run" env:"BENCH_RUN" type:"path" required:"" help:"Directory from an earlier run."`
}

func (c reportCommand) run(stdout io.Writer) error {
	data, err := os.ReadFile(filepath.Join(c.RunDirectory, "result.json"))
	if err != nil {
		return err
	}
	var result benchmarkResult
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	server, err := clientstate.CanonicalServer(result.Plan.Server)
	if result.SchemaVersion != 1 && result.SchemaVersion != 2 || err != nil || server != result.Plan.Server {
		return errors.New("invalid benchmark result")
	}
	return printResult(stdout, result)
}

func printResult(stdout io.Writer, result benchmarkResult) error {
	cleanup := result.CleanupStatus
	if cleanup == "" {
		cleanup = "unknown"
		if result.CleanupExact {
			cleanup = "succeeded"
		}
	}
	if _, err := fmt.Fprintf(stdout, "%s: %s (%d public URLs; cleanup: %s)\n", result.RunID, result.Status, len(result.PublicURLs), cleanup); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "direct: %d/%d successful; p95 %s\n", result.Direct.Successes, result.Direct.Scheduled, p95(&result.Direct)); err != nil {
		return err
	}
	for index, phase := range result.Steady {
		if _, err := fmt.Fprintf(stdout, "server %d: %d/%d successful; p95 %s\n", index+1, phase.Successes, phase.Scheduled, p95(&phase)); err != nil {
			return err
		}
		if index < len(result.SteadyByURL) {
			for _, publicURL := range result.PublicURLInfo {
				summary := result.SteadyByURL[index][publicURL.PublicURL]
				if summary == nil {
					continue
				}
				if _, err := fmt.Fprintf(stdout, "  %s %s %s: %d/%d successful; %d missed; %d timed out\n",
					publicURL.PublicURL, publicURL.PublicURLID, publicURL.Transport,
					summary.Successes, summary.Scheduled, summary.Missed, summary.Timeouts); err != nil {
					return err
				}
			}
		}
	}
	if result.Plan.Workload.Transport == "auto" {
		if _, err := fmt.Fprintf(stdout, "auto: %d TLS/TCP selection events\n", len(result.Fallbacks)); err != nil {
			return err
		}
	}
	if result.Error != "" {
		_, err := fmt.Fprintf(stdout, "failure: %s\n", result.Error)
		return err
	}
	return nil
}

func p95(result *benchworkload.VisitorResult) string {
	value := result.Total.Percentile(95)
	if value == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.1f ms", *value)
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".result-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		return errors.Join(err, temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}
