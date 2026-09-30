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
	"github.com/tnldotdev/tnl/internal/publisher"
)

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
