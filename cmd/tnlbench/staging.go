package main

import (
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
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/clientstate"
)

const stagingServer = "https://control.tnl.wtf"

type workloadOptions struct {
	Suite        string        `name:"suite" env:"BENCH_SUITE" default:"smoke" enum:"smoke,target" help:"Small smoke or an explicit target workload."`
	Server       string        `name:"server" env:"BENCH_SERVER" default:"https://control.tnl.wtf" help:"Staging control URL."`
	PublicURLs   int           `name:"public-urls" env:"BENCH_PUBLIC_URLS" default:"4" help:"Public URLs to publish."`
	FreshRate    int           `name:"fresh-connections-per-second" env:"BENCH_FRESH_CONNECTIONS_PER_SECOND" default:"16" help:"Offered visitor requests per second."`
	HeldStreams  int           `name:"held-streams" env:"BENCH_HELD_STREAMS" default:"4" help:"Held visitor streams."`
	Concurrency  int           `name:"concurrency" env:"BENCH_CONCURRENCY" default:"128" help:"Concurrent visitor request workers."`
	QueueSlots   int           `name:"queue-slots" env:"BENCH_QUEUE_SLOTS" default:"8" help:"Waiting visitor request slots."`
	PayloadBytes int           `name:"payload-bytes" env:"BENCH_PAYLOAD_BYTES" default:"32768" help:"Verified response bytes."`
	Repetitions  int           `name:"repetitions" env:"BENCH_REPETITIONS" default:"1" help:"Measurement windows."`
	Warmup       time.Duration `name:"warmup" env:"BENCH_WARMUP" default:"5s" help:"Time before measuring."`
	Duration     time.Duration `name:"duration" env:"BENCH_DURATION" default:"10s" help:"Length of each measurement window."`
	StateDir     string        `name:"state-dir" env:"BENCH_STATE_DIR" type:"path" help:"Client state with an existing staging login."`
	ResultsRoot  string        `name:"results-root" env:"BENCH_RESULTS_ROOT" default:"bench-results" type:"path" help:"Result directory."`
}

type benchmarkPlan struct {
	SchemaVersion int             `json:"schema_version"`
	ReadOnly      bool            `json:"read_only"`
	Environment   string          `json:"environment"`
	Server        string          `json:"server"`
	Workload      workloadSummary `json:"workload"`
}

type workloadSummary struct {
	Suite        string        `json:"suite"`
	PublicURLs   int           `json:"public_urls"`
	FreshRate    int           `json:"fresh_connections_per_second"`
	HeldStreams  int           `json:"held_streams"`
	Concurrency  int           `json:"concurrency"`
	QueueSlots   int           `json:"queue_slots"`
	PayloadBytes int           `json:"payload_bytes"`
	Repetitions  int           `json:"repetitions"`
	Warmup       time.Duration `json:"warmup"`
	Duration     time.Duration `json:"duration"`
}

func (c workloadOptions) plan() (benchmarkPlan, error) {
	if c.Server != stagingServer {
		return benchmarkPlan{}, fmt.Errorf("staging benchmarks require --server=%s", stagingServer)
	}
	if c.Suite != "smoke" && c.Suite != "target" {
		return benchmarkPlan{}, errors.New("suite must be smoke or target")
	}
	if c.PublicURLs < 1 || c.PublicURLs > 10_000 || c.FreshRate < 1 || c.FreshRate > 10_000 || c.HeldStreams < 0 || c.HeldStreams > 100_000 || c.Concurrency < 1 || c.Concurrency > 100_000 || c.QueueSlots < 0 || c.QueueSlots > 10_000 || c.PayloadBytes < 1 || c.PayloadBytes > 16<<20 || c.Repetitions < 1 || c.Repetitions > 10 || c.Warmup < 0 || c.Warmup > 5*time.Minute || c.Duration < time.Second || c.Duration > time.Hour {
		return benchmarkPlan{}, errors.New("invalid workload shape or duration")
	}
	if c.Suite == "smoke" && (c.PublicURLs > 4 || c.FreshRate > 16 || c.HeldStreams > 4 || c.Repetitions != 1 || c.Duration > 30*time.Second) {
		return benchmarkPlan{}, errors.New("larger workloads require suite target")
	}
	return benchmarkPlan{SchemaVersion: 1, ReadOnly: true, Environment: "staging", Server: c.Server,
		Workload: workloadSummary{Suite: c.Suite, PublicURLs: c.PublicURLs, FreshRate: c.FreshRate,
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
	fmt.Fprintf(stdout, "Staging benchmark plan (READ ONLY)\nServer: %s\nGenerators: local publisher and visitor\n", plan.Server)
	fmt.Fprintf(stdout, "Workload: %d public URLs, %d fresh/s, %d held, %d bytes\n", c.PublicURLs, c.FreshRate, c.HeldStreams, c.PayloadBytes)
	fmt.Fprintf(stdout, "Windows: %d x %s; warmup %s; local direct baseline %s\n", c.Repetitions, c.Duration, c.Warmup, c.Duration)
	_, err = fmt.Fprintln(stdout, "Execution requires an explicit BENCH_SUITE and BENCH_APPROVED=1.")
	return err
}

type runCommand struct {
	workloadOptions
	Approved string `name:"approved" env:"BENCH_APPROVED" help:"Explicit staging benchmark approval; must be 1."`
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
	SchemaVersion int                           `json:"schema_version"`
	RunID         string                        `json:"run_id"`
	Plan          benchmarkPlan                 `json:"plan"`
	StartedAt     time.Time                     `json:"started_at"`
	FinishedAt    time.Time                     `json:"finished_at"`
	Status        string                        `json:"status"`
	Error         string                        `json:"error,omitempty"`
	PublicURLs    []string                      `json:"public_urls,omitempty"`
	Direct        benchworkload.VisitorResult   `json:"direct_baseline"`
	Steady        []benchworkload.VisitorResult `json:"steady"`
	CleanupExact  bool                          `json:"cleanup_exact"`
	CleanupStatus string                        `json:"cleanup_status"`
	Generator     generatorResult               `json:"generator"`
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
	dir, err := os.MkdirTemp(c.ResultsRoot, "staging-")
	if err != nil {
		return err
	}
	resultPath := filepath.Join(dir, "result.json")
	initial := benchmarkResult{SchemaVersion: 1, RunID: filepath.Base(dir), Plan: plan,
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
	result = benchmarkResult{SchemaVersion: 1, RunID: runID, Plan: plan, StartedAt: time.Now().UTC(),
		Status: "running", CleanupStatus: "not_needed"}
	defer func() {
		var memory runtime.MemStats
		runtime.ReadMemStats(&memory)
		result.Generator = generatorResult{Goroutines: runtime.NumGoroutine(), HeapBytes: memory.HeapAlloc, Elapsed: time.Since(result.StartedAt)}
	}()
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
	fmt.Fprintln(progress, "tnlbench: connecting to staging control")
	group, err := benchworkload.OpenPublishers(ctx, benchworkload.PublisherConfig{
		Server: c.Server, Domain: "tnl.wtf", StateRoot: stateDir, Target: origin.URL,
		HostnamePrefix: "tnlbench" + strings.TrimPrefix(runID, "staging-"), Ephemeral: true,
		Transport: "mixed", RelayTLS: &tls.Config{MinVersion: tls.VersionTLS13},
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
	if err != nil {
		return result, err
	}
	urls := make([]string, c.PublicURLs)
	for _, publicURL := range publicURLs {
		urls[publicURL.Index] = publicURL.Ready.PublicURL
	}
	result.PublicURLs = urls
	if err := checkpoint(result); err != nil {
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
	visitor := benchworkload.Visitor{PayloadBytes: c.PayloadBytes}
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
		err := reportPhase(progress, fmt.Sprintf("staging window %d/%d", index+1, c.Repetitions), c.Duration, func() error {
			var err error
			phase, err = visitor.Run(ctx, benchworkload.VisitorConfig{
				Rate: c.FreshRate, Workers: c.Concurrency, QueueSlots: c.QueueSlots, Duration: c.Duration,
			}, urls)
			return err
		})
		result.Steady = append(result.Steady, phase)
		if err != nil {
			return result, err
		}
		for _, stream := range held {
			if !stream.Alive() {
				return result, errors.New("held visitor stream ended during steady traffic")
			}
		}
	}
	return result, nil
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
	if result.SchemaVersion != 1 || result.Plan.Server != stagingServer {
		return errors.New("invalid staging benchmark result")
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
		if _, err := fmt.Fprintf(stdout, "staging %d: %d/%d successful; p95 %s\n", index+1, phase.Successes, phase.Scheduled, p95(&phase)); err != nil {
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
