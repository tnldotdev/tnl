package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	Generator     generatorResult               `json:"generator"`
}

type generatorResult struct {
	Goroutines int           `json:"goroutines"`
	HeapBytes  uint64        `json:"heap_bytes"`
	Elapsed    time.Duration `json:"elapsed"`
}

func (c runCommand) run(ctx context.Context, stdout io.Writer) error {
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
	result, runErr := c.measure(ctx, plan, stateDir, filepath.Base(dir))
	result.FinishedAt = time.Now().UTC()
	result.Status = "passed"
	if runErr != nil {
		result.Status, result.Error = "failed", runErr.Error()
	}
	if err := writeJSON(filepath.Join(dir, "result.json"), result); err != nil {
		return errors.Join(runErr, err)
	}
	fmt.Fprintf(stdout, "Results: %s\n", filepath.Join(dir, "result.json"))
	if err := printResult(stdout, result); err != nil {
		return errors.Join(runErr, err)
	}
	return runErr
}

func (c runCommand) measure(parent context.Context, plan benchmarkPlan, stateDir, runID string) (result benchmarkResult, retErr error) {
	result = benchmarkResult{SchemaVersion: 1, RunID: runID, Plan: plan, StartedAt: time.Now().UTC()}
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
	result.Direct, retErr = baseline.Run(ctx, benchworkload.VisitorConfig{
		Rate: c.FreshRate, Workers: c.Concurrency, QueueSlots: c.QueueSlots, Duration: c.Duration,
	}, []string{direct.URL})
	if retErr != nil {
		return result, fmt.Errorf("local generator baseline: %w", retErr)
	}
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
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Minute)
		defer stop()
		shutdown, err := group.Close(cleanup)
		result.CleanupExact = err == nil && shutdown.Failures == 0 && shutdown.Attempts == group.Started()
		retErr = errors.Join(retErr, err)
	}()
	indexes := make([]int, c.PublicURLs)
	for i := range indexes {
		indexes[i] = i
	}
	publicURLs, err := group.Start(ctx, indexes)
	if err != nil {
		return result, err
	}
	urls := make([]string, c.PublicURLs)
	for _, publicURL := range publicURLs {
		urls[publicURL.Index] = publicURL.Ready.PublicURL
	}
	result.PublicURLs = urls
	visitor := benchworkload.Visitor{PayloadBytes: c.PayloadBytes}
	for _, url := range urls {
		if url == "" {
			return result, errors.New("missing public URL after activation")
		}
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
	if err := wait(ctx, c.Warmup); err != nil {
		return result, err
	}
	for range c.Repetitions {
		phase, err := visitor.Run(ctx, benchworkload.VisitorConfig{
			Rate: c.FreshRate, Workers: c.Concurrency, QueueSlots: c.QueueSlots, Duration: c.Duration,
		}, urls)
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
	if _, err := fmt.Fprintf(stdout, "%s: %s (%d public URLs; cleanup exact: %t)\n", result.RunID, result.Status, len(result.PublicURLs), result.CleanupExact); err != nil {
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
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
