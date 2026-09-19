package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"
)

const (
	heldStreamOpenRate = 25
	recoveryTimeout    = 30 * time.Second
	recoveryInterval   = time.Second
)

type loadCommand struct {
	workerCommand
	Routes           int           `name:"routes" env:"TNL_BENCH_ROUTES" required:"" help:"Total route count in the cell."`
	PublicAddress    string        `name:"public-address" env:"TNL_BENCH_PUBLIC_ADDRESS" help:"Optional ingress host:port override; normal runs use public route DNS."`
	TotalFreshRate   int           `name:"total-fresh-connections-per-second" env:"TNL_BENCH_TOTAL_FRESH_CONNECTIONS_PER_SECOND" required:"" help:"Total fresh visitor connection rate for the cell."`
	TotalHeldStreams int           `name:"total-held-streams" env:"TNL_BENCH_TOTAL_HELD_STREAMS" help:"Total held-open streams for the cell."`
	LifecycleChurn   int           `name:"lifecycle-churn-per-second" env:"TNL_BENCH_LIFECYCLE_CHURN_PER_SECOND" help:"Total route-session lifecycle operations per second."`
	ResolverAddress  string        `name:"resolver-address" env:"TNL_BENCH_RESOLVER_ADDRESS" help:"Optional DNS server used for public route lookups."`
	FreshRate        int           `name:"fresh-connections-per-second" env:"TNL_BENCH_FRESH_CONNECTIONS_PER_SECOND" required:"" help:"Fresh visitor connection rate for this worker."`
	HeldStreams      int           `name:"held-streams" env:"TNL_BENCH_HELD_STREAMS" help:"Held-open streams for this worker."`
	Warmup           time.Duration `name:"warmup" env:"TNL_BENCH_WARMUP" required:"" help:"Warmup after held streams are ready."`
	Duration         time.Duration `name:"duration" env:"TNL_BENCH_DURATION" required:"" help:"Measured fresh-connection duration."`
	PayloadBytes     int           `name:"payload-bytes" env:"TNL_BENCH_PAYLOAD_BYTES" default:"16384" help:"Expected fresh-response payload size."`
	MetricsURLs      []string      `name:"metrics-url" env:"TNL_BENCH_METRICS_URLS" help:"Private process metrics URL; repeat for each process."`
	DiagnosticURLs   []string      `name:"database-diagnostics-url" env:"TNL_BENCH_DATABASE_DIAGNOSTICS_URLS" help:"Private control database diagnostics URL; repeat for each control process."`
	Timeout          time.Duration `name:"timeout" env:"TNL_BENCH_TIMEOUT" default:"30m" help:"Worker deadline."`
	onFailure        func()
}

func (c loadCommand) Validate() error {
	if err := c.workerCommand.validate(); err != nil {
		return err
	}
	if c.Routes <= 0 || c.TotalFreshRate <= 0 || c.TotalHeldStreams < 0 || c.LifecycleChurn < 0 ||
		c.FreshRate < 0 || c.FreshRate >= 40 ||
		c.FreshRate > c.TotalFreshRate || c.HeldStreams < 0 || c.HeldStreams > c.TotalHeldStreams || c.Warmup < 0 || c.Duration <= 0 {
		return errors.New("load shape is invalid or could exercise the ingress source limiter")
	}
	if c.PayloadBytes <= 0 || c.PayloadBytes > 16<<20 || c.Timeout <= 0 {
		return errors.New("load payload or timeout is invalid")
	}
	if c.PublicAddress != "" {
		if _, _, err := net.SplitHostPort(c.PublicAddress); err != nil {
			return fmt.Errorf("public address: %w", err)
		}
	}
	if c.ResolverAddress != "" {
		if _, _, err := net.SplitHostPort(c.ResolverAddress); err != nil {
			return fmt.Errorf("resolver address: %w", err)
		}
	}
	return nil
}

type visitorTiming struct {
	dns, connect, tls, firstByte, total time.Duration
}

type visitorResult struct {
	timing visitorTiming
	bytes  int64
	err    error
}

func (c loadCommand) run(parent context.Context) error {
	started := time.Now().UTC()
	ctx, cancel := context.WithTimeout(parent, c.Timeout)
	defer cancel()
	coordinator, err := newCoordinatorClient(c.CoordinatorURL, c.CoordinatorToken)
	if err != nil {
		return err
	}
	worker := resultWorker{Kind: "load", Index: c.WorkerIndex, Count: c.WorkerCount}
	configuration := resultConfiguration{
		Axis: c.Axis, Sequence: c.Sequence, Routes: c.Routes,
		FreshConnectionsPerSecond: c.TotalFreshRate, HeldStreams: c.TotalHeldStreams,
		LifecycleChurnPerSecond: c.LifecycleChurn,
		AssignedFreshRate:       c.FreshRate, AssignedHeldStreams: c.HeldStreams,
		WarmupSeconds: int(c.Warmup.Seconds()), DurationSeconds: int(c.Duration.Seconds()), PayloadBytes: c.PayloadBytes,
	}
	failureMetricsURLs := c.MetricsURLs
	c.MetricsURLs = nil // The publisher owns routine metrics sampling.
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
	result.DatabaseDiagnostics = failure.diagnostics
	result.Resources = append(result.Resources, failure.resources...)
	postCtx, postCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer postCancel()
	if err := coordinator.postResult(postCtx, result); err != nil {
		return errors.Join(runErr, fmt.Errorf("post load result: %w", err))
	}
	return runErr
}

func (c loadCommand) execute(ctx context.Context, worker resultWorker, configuration resultConfiguration) (benchmarkResult, error) {
	coordinator, _ := newCoordinatorClient(c.CoordinatorURL, c.CoordinatorToken)
	if err := coordinator.waitPublishers(ctx); err != nil {
		return benchmarkResult{}, err
	}
	hostnames, err := coordinator.routes(ctx)
	if err != nil {
		return benchmarkResult{}, err
	}
	if len(hostnames) != c.Routes {
		return benchmarkResult{}, fmt.Errorf("coordinator returned %d routes, want %d", len(hostnames), c.Routes)
	}
	resources := sampleResources(ctx, c.MetricsURLs, "ready")
	var setupPhases []phaseResult
	if c.PublicAddress == "" {
		var assignedHostnames []string
		for index := c.WorkerIndex; index < len(hostnames); index += c.WorkerCount {
			assignedHostnames = append(assignedHostnames, hostnames[index])
		}
		dnsCtx, cancelDNS := context.WithTimeout(ctx, benchmarkDNSPropagationTimeout)
		dnsPhase, err := waitForBenchmarkDNS(dnsCtx, assignedHostnames, visitorDNSResolver(c.ResolverAddress).LookupHost, 250*time.Millisecond)
		cancelDNS()
		setupPhases = append(setupPhases, dnsPhase)
		if err != nil {
			if c.onFailure != nil {
				c.onFailure()
			}
			return benchmarkResult{Phases: setupPhases}, err
		}
	}
	correctnessStarted := time.Now().UTC()
	correctness := make([]visitorResult, 0, divideRoundUp(c.Routes, c.WorkerCount))
	for index := c.WorkerIndex; index < len(hostnames); index += c.WorkerCount {
		correctness = append(correctness, c.request(ctx, hostnames[index], "/bench", false))
	}
	correctnessPhase := phaseFromVisitorResults("correctness", correctnessStarted, time.Since(correctnessStarted), correctness, 0)
	if err := visitorResultsError("correctness", correctness); err != nil {
		return benchmarkResult{Phases: append(setupPhases, correctnessPhase)}, err
	}

	heldStarted := time.Now().UTC()
	held, heldResults, err := c.openHeldStreams(ctx, hostnames)
	if err != nil {
		closeHeldStreams(held)
		heldPhase := phaseFromVisitorResults("held", heldStarted, time.Since(heldStarted), heldResults, len(held))
		recovery, recoveryErr := c.runRecovery(ctx, hostnames)
		resources = append(resources, sampleResources(ctx, c.MetricsURLs, "loaded")...)
		message := err.Error()
		if recoveryErr != nil {
			message += "; " + recoveryErr.Error()
		}
		result := benchmarkResult{
			SchemaVersion: benchmarkResultSchemaVersion, CellID: c.CellID, Status: "failed", Suite: c.Suite,
			Repetition: c.Repetition, Worker: worker, Configuration: configuration,
			Phases: append(setupPhases, correctnessPhase, heldPhase, recovery), Resources: resources,
			Cleanup: resultCleanup{Exact: true}, Failure: &resultFailure{Message: message, Stage: "measurement"},
		}
		return result, errors.New(message)
	}
	heldClosed := false
	defer func() {
		if !heldClosed {
			closeHeldStreams(held)
		}
	}()
	heldPhase := phaseFromVisitorResults("held", heldStarted, time.Since(heldStarted), heldResults, c.HeldStreams)
	if err := sleepContext(ctx, c.Warmup); err != nil {
		return benchmarkResult{Phases: append(setupPhases, correctnessPhase, heldPhase)}, err
	}
	freshStarted := time.Now().UTC()
	fresh := c.runFreshConnections(ctx, hostnames)
	freshElapsed := time.Since(freshStarted)
	freshPhase := phaseFromVisitorResults("fresh", freshStarted, freshElapsed, fresh, c.HeldStreams)
	freshPhase.AchievedRate = float64(freshPhase.Successes) / freshElapsed.Seconds()
	closeHeldStreams(held)
	heldClosed = true
	saturated := freshPhase.Errors != 0 || (c.FreshRate > 0 && freshPhase.AchievedRate < 0.95*float64(c.FreshRate))
	var recoveryPhase *phaseResult
	var recoveryErr error
	if saturated || c.LifecycleChurn > 0 {
		recovery, err := c.runRecovery(ctx, hostnames)
		recoveryPhase, recoveryErr = &recovery, err
	}
	resources = append(resources, sampleResources(ctx, c.MetricsURLs, "loaded")...)
	phases := append(setupPhases, correctnessPhase, heldPhase, freshPhase)
	if recoveryPhase != nil {
		phases = append(phases, *recoveryPhase)
	}
	result := benchmarkResult{
		SchemaVersion: benchmarkResultSchemaVersion, CellID: c.CellID, Status: "passed", Suite: c.Suite,
		Repetition: c.Repetition, Worker: worker, Configuration: configuration,
		Phases: phases, Resources: resources,
		Cleanup: resultCleanup{Exact: true},
	}
	if freshPhase.Errors != 0 {
		result.Status = "failed"
		message := fmt.Sprintf("%d of %d fresh visitor connections failed", freshPhase.Errors, freshPhase.Attempts)
		if recoveryErr != nil {
			message += "; " + recoveryErr.Error()
		}
		result.Failure = &resultFailure{Message: message, Stage: "measurement"}
		return result, errors.New(result.Failure.Message)
	}
	if c.FreshRate > 0 && freshPhase.AchievedRate < 0.95*float64(c.FreshRate) {
		result.Status = "failed"
		message := fmt.Sprintf(
			"fresh visitor rate %.2f/s was below 95%% of the %.2f/s target", freshPhase.AchievedRate, float64(c.FreshRate),
		)
		if recoveryErr != nil {
			message += "; " + recoveryErr.Error()
		}
		result.Failure = &resultFailure{Message: message, Stage: "measurement"}
		return result, errors.New(result.Failure.Message)
	}
	if recoveryErr != nil {
		result.Status = "failed"
		result.Failure = &resultFailure{Message: recoveryErr.Error(), Stage: "measurement"}
		return result, recoveryErr
	}
	return result, nil
}

func (c loadCommand) request(ctx context.Context, hostname, path string, hold bool) (result visitorResult) {
	defer func() {
		var held *heldResponse
		if result.err != nil && !errors.As(result.err, &held) && c.onFailure != nil {
			c.onFailure()
		}
	}()
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		DisableKeepAlives: true, ForceAttemptHTTP2: false, DisableCompression: true,
	}
	if c.PublicAddress != "" {
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, "tcp", c.PublicAddress)
		}
	} else if c.ResolverAddress != "" {
		dialer := &net.Dialer{Resolver: visitorDNSResolver(c.ResolverAddress)}
		transport.DialContext = dialer.DialContext
	}
	started := time.Now()
	var timing visitorTiming
	var dnsStarted, connectStarted, tlsStarted time.Time
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { dnsStarted = time.Now() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			if !dnsStarted.IsZero() {
				timing.dns = time.Since(dnsStarted)
			}
		},
		ConnectStart: func(_, _ string) { connectStarted = time.Now() },
		ConnectDone: func(_, _ string, _ error) {
			if !connectStarted.IsZero() {
				timing.connect = time.Since(connectStarted)
			}
		},
		TLSHandshakeStart: func() { tlsStarted = time.Now() },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			if !tlsStarted.IsZero() {
				timing.tls = time.Since(tlsStarted)
			}
		},
		GotFirstResponseByte: func() { timing.firstByte = time.Since(started) },
	}
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, "https://"+hostname+path, nil)
	if err != nil {
		return visitorResult{err: err}
	}
	client := &http.Client{Transport: transport}
	if !hold {
		client.Timeout = 30 * time.Second
	}
	response, err := client.Do(request)
	if err != nil {
		transport.CloseIdleConnections()
		return visitorResult{timing: timing, err: err}
	}
	if hold {
		one := []byte{0}
		_, err = io.ReadFull(response.Body, one)
		timing.total = time.Since(started)
		if err != nil || response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			transport.CloseIdleConnections()
			if err == nil {
				err = fmt.Errorf("HTTP %d", response.StatusCode)
			}
			return visitorResult{timing: timing, err: err}
		}
		return visitorResult{timing: timing, bytes: 1, err: &heldResponse{response: response, transport: transport}}
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, int64(c.PayloadBytes+1)))
	closeErr := response.Body.Close()
	transport.CloseIdleConnections()
	err = errors.Join(readErr, closeErr)
	if err == nil && response.StatusCode != http.StatusOK {
		err = fmt.Errorf("HTTP %d", response.StatusCode)
	}
	if err == nil && response.Header.Get("X-TNL-Bench-Host") != hostname {
		err = errors.New("origin observed wrong host")
	}
	want := make([]byte, c.PayloadBytes)
	for index := range want {
		want[index] = byte(index)
	}
	if err == nil && !bytes.Equal(body, want) {
		err = errors.New("response payload mismatch")
	}
	timing.total = time.Since(started)
	return visitorResult{timing: timing, bytes: int64(len(body)), err: err}
}

type heldResponse struct {
	response  *http.Response
	transport *http.Transport
}

func (h *heldResponse) Error() string { return "held stream" }

func (h *heldResponse) close() {
	_ = h.response.Body.Close()
	h.transport.CloseIdleConnections()
}

func (c loadCommand) openHeldStreams(ctx context.Context, hostnames []string) ([]*heldResponse, []visitorResult, error) {
	held := make([]*heldResponse, 0, c.HeldStreams)
	results := make([]visitorResult, 0, c.HeldStreams)
	interval := time.Second / heldStreamOpenRate
	for index := 0; index < c.HeldStreams; index++ {
		if index != 0 {
			if err := sleepContext(ctx, interval); err != nil {
				return held, results, err
			}
		}
		result := c.request(ctx, hostnames[(c.WorkerIndex+index*c.WorkerCount)%len(hostnames)], "/hold", true)
		var response *heldResponse
		if !errors.As(result.err, &response) {
			results = append(results, result)
			return held, results, fmt.Errorf("open held stream %d: %w", index, result.err)
		}
		result.err = nil
		held = append(held, response)
		results = append(results, result)
	}
	return held, results, nil
}

func closeHeldStreams(held []*heldResponse) {
	for _, response := range held {
		response.close()
	}
}

func (c loadCommand) runFreshConnections(ctx context.Context, hostnames []string) []visitorResult {
	if c.FreshRate == 0 {
		return nil
	}
	attempts := c.FreshRate * int(c.Duration/time.Second)
	results := make(chan visitorResult, attempts)
	semaphore := make(chan struct{}, 256)
	interval := time.Second / time.Duration(c.FreshRate)
	next := time.Now()
	var launched atomic.Int64
	var workers sync.WaitGroup
launch:
	for index := 0; index < attempts; index++ {
		if err := sleepUntil(ctx, next); err != nil {
			break
		}
		next = next.Add(interval)
		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			break launch
		}
		launched.Add(1)
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			defer func() { <-semaphore }()
			hostname := hostnames[(c.WorkerIndex+index*c.WorkerCount)%len(hostnames)]
			results <- c.request(ctx, hostname, "/bench", false)
		}(index)
	}
	workers.Wait()
	close(results)
	collected := make([]visitorResult, 0, launched.Load())
	for result := range results {
		collected = append(collected, result)
	}
	return collected
}

func (c loadCommand) runRecovery(ctx context.Context, hostnames []string) (phaseResult, error) {
	started := time.Now().UTC()
	probeCtx, cancel := context.WithTimeout(ctx, recoveryTimeout)
	defer cancel()
	var results []visitorResult
	for {
		hostname := hostnames[(c.WorkerIndex+len(results)*c.WorkerCount)%len(hostnames)]
		result := c.request(probeCtx, hostname, "/bench", false)
		results = append(results, result)
		if result.err == nil {
			return phaseFromVisitorResults("recovery", started, time.Since(started), results, 0), nil
		}
		if err := sleepContext(probeCtx, recoveryInterval); err != nil {
			phase := phaseFromVisitorResults("recovery", started, time.Since(started), results, 0)
			return phase, fmt.Errorf("visitor traffic did not recover within %s", recoveryTimeout)
		}
	}
}

func phaseFromVisitorResults(name string, started time.Time, elapsed time.Duration, results []visitorResult, concurrency int) phaseResult {
	phase := phaseResult{
		Name: name, StartedAt: started, DurationMilliseconds: milliseconds(elapsed), Attempts: len(results), Concurrency: concurrency,
	}
	var dns, connect, handshake, firstByte, total []time.Duration
	for _, result := range results {
		if result.err != nil {
			phase.Errors++
			continue
		}
		phase.Successes++
		phase.Bytes += result.bytes
		if result.timing.dns != 0 {
			dns = append(dns, result.timing.dns)
		}
		connect = append(connect, result.timing.connect)
		handshake = append(handshake, result.timing.tls)
		firstByte = append(firstByte, result.timing.firstByte)
		total = append(total, result.timing.total)
	}
	phase.DNS = newDurationHistogram(dns)
	phase.Connect = newDurationHistogram(connect)
	phase.TLS = newDurationHistogram(handshake)
	phase.FirstByte = newDurationHistogram(firstByte)
	phase.Total = newDurationHistogram(total)
	return phase
}

func visitorResultsError(name string, results []visitorResult) error {
	for index, result := range results {
		if result.err != nil {
			return fmt.Errorf("%s request %d: %w", name, index, result.err)
		}
	}
	return nil
}

func sleepUntil(ctx context.Context, deadline time.Time) error {
	delay := time.Until(deadline)
	if delay <= 0 {
		return nil
	}
	return sleepContext(ctx, delay)
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
