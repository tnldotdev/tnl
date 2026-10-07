package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher"
)

func (c runCommand) run(ctx context.Context, stdout, progress io.Writer) error {
	plan, err := c.validate()
	if err != nil {
		return failure.Wrap("validate benchmark run", failure.BenchmarkInputInvalid, err)
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
	initial := benchmarkResult{SchemaVersion: 3, RunID: filepath.Base(dir), Plan: plan,
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
		result.Status, result.Error = "failed", failure.SafeMessage(runErr, failure.BenchmarkMeasurementFailed)
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
	defer func() {
		if _, classified := failure.ReasonOf(retErr); retErr != nil && !classified {
			retErr = failure.Wrap("measure benchmark workload", failure.BenchmarkMeasurementFailed, retErr)
		}
	}()
	result = benchmarkResult{SchemaVersion: 3, RunID: runID, Plan: plan, StartedAt: time.Now().UTC(),
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
	ctx, cancel := context.WithTimeout(parent, time.Duration((c.PublicURLs+c.StartParallel-1)/c.StartParallel)*5*time.Minute+2*c.Warmup+time.Duration(c.Repetitions+1)*c.Duration+5*time.Minute)
	defer cancel()
	origin := httptest.NewServer(benchworkload.Origin(c.PayloadBytes))
	defer origin.Close()
	direct := httptest.NewTLSServer(benchworkload.Origin(c.PayloadBytes))
	defer direct.Close()
	roots := x509.NewCertPool()
	roots.AddCert(direct.Certificate())
	baseline := benchworkload.Visitor{Roots: roots, PayloadBytes: c.PayloadBytes}
	directHeld, err := openHeldStreams(ctx, baseline, []string{direct.URL}, c.HeldStreams)
	if err != nil {
		return result, fmt.Errorf("local generator baseline: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, closeHeldStreams(directHeld)) }()
	result.DirectWarmupBandwidth, err = c.warmupPhase(ctx, baseline, []string{direct.URL}, progress, "local warmup")
	if err != nil {
		return result, fmt.Errorf("local generator baseline: %w", err)
	}
	directBefore := heldBytes(directHeld)
	retErr = reportPhase(progress, "local baseline", c.Duration, func() error {
		var err error
		result.Direct, result.DirectBandwidth, err = c.runWindow(ctx, baseline, []string{direct.URL}, c.Duration, nil, false)
		return err
	})
	if retErr != nil {
		return result, fmt.Errorf("local generator baseline: %w", retErr)
	}
	if c.Mode.fresh() {
		if err := result.Direct.Err(); err != nil {
			return result, fmt.Errorf("local generator baseline: %w", err)
		}
	}
	if c.HeldStreams > 0 {
		progress, err := checkHeldProgress(directHeld, directBefore)
		result.DirectHeld = &progress
		if err != nil {
			return result, fmt.Errorf("local generator baseline: %w", err)
		}
	}
	if err := closeHeldStreams(directHeld); err != nil {
		return result, fmt.Errorf("local generator baseline: %w", err)
	}
	directHeld = nil
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
		Parallel: c.StartParallel, StartParallel: c.StartParallel,
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
	activationStarted := time.Now()
	err = reportPhase(progress, fmt.Sprintf("activating %d public URLs", c.PublicURLs), 0, func() error {
		var err error
		publicURLs, err = group.Start(ctx, indexes)
		return err
	})
	result.Activation = time.Since(activationStarted)
	urls := recordReadyPublicURLs(&result, publicURLs, c.Transport, c.PublicURLs)
	if checkpointErr := checkpoint(result); checkpointErr != nil {
		return result, errors.Join(err, checkpointErr)
	}
	if err != nil {
		return result, err
	}
	if err := publisherFailure(group); err != nil {
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
	visitor := benchworkload.Visitor{PayloadBytes: c.PayloadBytes, Network: string(c.VisitorNetwork), SourceAddress: source}
	fmt.Fprintln(progress, "tnlbench: verifying each public URL")
	for _, url := range urls {
		if check := visitor.Request(ctx, url, time.Now()); check.Error != "" {
			return result, fmt.Errorf("visitor correctness %s: %s", url, check.Error)
		}
	}
	held, err := openHeldStreams(ctx, visitor, urls, c.HeldStreams)
	if err != nil {
		return result, err
	}
	defer func() { retErr = errors.Join(retErr, closeHeldStreams(held)) }()
	fmt.Fprintf(progress, "tnlbench: %d held visitor streams open\n", len(held))
	result.WarmupBandwidth, err = c.warmupPhase(ctx, visitor, urls, progress, "warmup")
	if err != nil {
		return result, err
	}
	for index := range c.Repetitions {
		var phase benchworkload.VisitorResult
		var bandwidth *benchworkload.BandwidthResult
		before := heldBytes(held)
		byURL, observe := newURLVisitorResults(urls)
		err := reportPhase(progress, fmt.Sprintf("server window %d/%d", index+1, c.Repetitions), c.Duration, func() error {
			var err error
			phase, bandwidth, err = c.runWindow(ctx, visitor, urls, c.Duration, observe, false)
			return err
		})
		if c.Mode.fresh() {
			result.Steady = append(result.Steady, phase)
			result.SteadyByURL = append(result.SteadyByURL, byURL)
			if summaryErr := completeURLVisitorResults(urls, phase.Scheduled, byURL); summaryErr != nil {
				return result, errors.Join(err, summaryErr)
			}
		}
		if bandwidth != nil {
			result.SteadyBandwidth = append(result.SteadyBandwidth, *bandwidth)
		}
		if c.HeldStreams > 0 {
			progress, heldErr := checkHeldProgress(held, before)
			result.SteadyHeld = append(result.SteadyHeld, progress)
			err = errors.Join(err, heldErr)
		}
		err = errors.Join(err, publisherFailure(group))
		if err != nil {
			return result, err
		}
		if c.Mode.fresh() {
			if err := visitorWindowError(phase, held); err != nil {
				return result, fmt.Errorf("server visitor window %d: %w", index+1, err)
			}
		}
	}
	return result, nil
}

func (c runCommand) runWindow(ctx context.Context, visitor benchworkload.Visitor, urls []string, duration time.Duration, observe func(benchworkload.RequestResult), allowLateBandwidth bool) (benchworkload.VisitorResult, *benchworkload.BandwidthResult, error) {
	var prepared *benchworkload.BandwidthSession
	if c.Mode.bandwidth() {
		var err error
		prepared, err = visitor.PrepareBandwidth(ctx, c.BandwidthDirection, c.BandwidthStreams, c.BandwidthMbits*1_000_000/8, urls)
		if err != nil {
			return benchworkload.VisitorResult{}, nil, fmt.Errorf("prepare bandwidth connections: %w", err)
		}
		defer prepared.Close()
	}
	start := time.Now().Add(time.Second)
	var fresh benchworkload.VisitorResult
	var bandwidth *benchworkload.BandwidthResult
	var freshErr, bandwidthErr error
	var group sync.WaitGroup
	if c.Mode.fresh() {
		group.Go(func() {
			fresh, freshErr = visitor.Run(ctx, benchworkload.VisitorConfig{Rate: c.FreshRate, Workers: c.Concurrency,
				QueueSlots: c.QueueSlots, Start: start, Duration: duration, OnResult: observe}, urls)
		})
	}
	if c.Mode.bandwidth() {
		group.Go(func() {
			value, err := prepared.Run(ctx, start, duration)
			if allowLateBandwidth && errors.Is(err, benchworkload.ErrBandwidthLate) {
				err = nil
			}
			bandwidth, bandwidthErr = &value, err
		})
	}
	if !c.Mode.fresh() && !c.Mode.bandwidth() {
		freshErr = benchworkload.WaitUntil(ctx, start.Add(duration))
	}
	group.Wait()
	return fresh, bandwidth, errors.Join(freshErr, bandwidthErr)
}

func (c runCommand) warmupPhase(ctx context.Context, visitor benchworkload.Visitor, urls []string, progress io.Writer, name string) (*benchworkload.BandwidthResult, error) {
	if c.Warmup == 0 {
		return nil, nil
	}
	var bandwidth *benchworkload.BandwidthResult
	err := reportPhase(progress, name, c.Warmup, func() error {
		fresh, measured, err := c.runWindow(ctx, visitor, urls, c.Warmup, nil, true)
		bandwidth = measured
		if measured != nil && errors.Is(measured.Err(), benchworkload.ErrBandwidthLate) {
			fmt.Fprintf(progress, "tnlbench: %s delivered all bytes %s after its window; measuring anyway\n", name, measured.Elapsed-measured.TargetDuration)
		}
		if c.Mode.fresh() {
			err = errors.Join(err, fresh.Err())
		}
		return err
	})
	return bandwidth, err
}

func openHeldStreams(ctx context.Context, visitor benchworkload.Visitor, urls []string, count int) ([]*benchworkload.HeldStream, error) {
	streams := make([]*benchworkload.HeldStream, count)
	if count == 0 {
		return streams, nil
	}
	jobs := make(chan int)
	failed := make(chan struct{})
	var firstErr error
	var once sync.Once
	var group sync.WaitGroup
	for range min(count, 64) {
		group.Go(func() {
			for index := range jobs {
				stream, err := visitor.Hold(ctx, urls[index%len(urls)])
				if err != nil {
					once.Do(func() { firstErr = err; close(failed) })
					return
				}
				streams[index] = stream
			}
		})
	}
send:
	for index := range count {
		select {
		case <-failed:
			break send
		case <-ctx.Done():
			break send
		case jobs <- index:
		}
	}
	close(jobs)
	group.Wait()
	if firstErr != nil || ctx.Err() != nil {
		return nil, errors.Join(firstErr, ctx.Err(), closeHeldStreams(streams))
	}
	return streams, nil
}

func closeHeldStreams(streams []*benchworkload.HeldStream) error {
	var err error
	for _, stream := range streams {
		if stream != nil {
			err = errors.Join(err, stream.Close())
		}
	}
	return err
}

func heldBytes(streams []*benchworkload.HeldStream) []int64 {
	before := make([]int64, len(streams))
	for i, stream := range streams {
		before[i] = stream.BytesReceived()
	}
	return before
}

func checkHeldProgress(streams []*benchworkload.HeldStream, before []int64) (heldProgress, error) {
	progress := heldProgress{Open: len(streams)}
	for i, stream := range streams {
		after := stream.BytesReceived()
		progress.Bytes += after - before[i]
		if stream.Alive() && after > before[i] {
			progress.Progressing++
		}
	}
	if progress.Progressing != progress.Open {
		return progress, fmt.Errorf("%d/%d held streams still delivering bytes", progress.Progressing, progress.Open)
	}
	return progress, nil
}

func publisherFailure(group *benchworkload.Publishers) error {
	select {
	case err := <-group.Failures():
		return err
	default:
		return nil
	}
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
