package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
)

type publisherCommand struct {
	workerCommand
	ServerURL      string   `name:"server" env:"TNL_BENCH_SERVER" required:"" help:"Control URL."`
	LoginToken     string   `name:"login-token" env:"TNL_BENCH_LOGIN_TOKEN" required:"" help:"Built-in authority login token."`
	ControlCAFile  string   `name:"control-ca-file" env:"TNL_BENCH_CONTROL_CA_FILE" type:"path" help:"Optional control and relay trust roots."`
	HostnameSuffix string   `name:"hostname-suffix" env:"TNL_BENCH_HOSTNAME_SUFFIX" required:"" help:"Managed deployment domain."`
	Routes         int      `name:"routes" env:"TNL_BENCH_ROUTES" required:"" help:"Total published routes."`
	StateRoot      string   `name:"state-root" env:"TNL_BENCH_STATE_ROOT" default:"/state" type:"path" help:"Run-local client state."`
	Parallel       int      `name:"parallel" env:"TNL_BENCH_PARALLEL" default:"4" help:"Concurrent route operations."`
	PayloadBytes   int      `name:"payload-bytes" env:"TNL_BENCH_PAYLOAD_BYTES" default:"32768" help:"Origin response bytes."`
	MetricsURLs    []string `name:"metrics-url" env:"TNL_BENCH_METRICS_URLS" help:"Private process metrics endpoints."`
	DiagnosticURLs []string `name:"database-diagnostics-url" env:"TNL_BENCH_DATABASE_DIAGNOSTICS_URLS" help:"Private database diagnostics endpoints."`
}

func (c publisherCommand) Validate() error {
	if err := c.workerCommand.validate(); err != nil {
		return err
	}
	if c.Routes < c.WorkerCount || c.Routes > 10_000 || c.Parallel < 1 || c.Parallel > 256 || c.PayloadBytes < 1 || c.PayloadBytes > 16<<20 {
		return errors.New("invalid publisher assignment or limits")
	}
	return nil
}

func (c publisherCommand) run(parent context.Context) (retErr error) {
	ctx, cancel := context.WithTimeout(parent, c.Timeout)
	defer cancel()
	coordination, err := benchworkload.NewCoordination(c.CoordinatorURL, c.CoordinatorToken)
	if err != nil {
		return err
	}
	ctx, stopFailures := coordination.WorkloadContext(ctx)
	defer stopFailures()
	result := benchmarkResult{SchemaVersion: benchmarkResultSchemaVersion, CellID: c.CellID, Status: "passed", Worker: resultWorker{Kind: "publisher", Index: c.WorkerIndex, Count: c.WorkerCount}, Cleanup: resultCleanup{}}
	failure := &failureCapture{ctx: ctx, metricsURLs: c.MetricsURLs, diagnosticURLs: c.DiagnosticURLs}
	stage := "setup"
	defer func() {
		if retErr != nil {
			failure.capture()
			result.Status = "failed"
			result.Failure = &resultFailure{Message: retErr.Error(), Stage: stage}
		}
		result.Resources = append(result.Resources, failure.resources...)
		result.DatabaseDiagnostics = failure.diagnostics
		post, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		retErr = errors.Join(retErr, coordination.Put(post, fmt.Sprintf("result.publisher-%d", c.WorkerIndex), result))
		if retErr != nil {
			_ = coordination.Put(post, "failure", boundedFailure(retErr.Error()))
		}
	}()
	roots, err := loadCertPool(c.ControlCAFile)
	if err != nil {
		return err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	origin := httptest.NewServer(benchworkload.Origin(c.PayloadBytes))
	defer origin.Close()
	group, err := benchworkload.OpenPublishers(ctx, benchworkload.PublisherConfig{
		Server: c.ServerURL, LoginToken: c.LoginToken, Domain: c.HostnameSuffix, StateRoot: c.StateRoot,
		Target: origin.URL, HTTPClient: &http.Client{Transport: transport, Timeout: 30 * time.Second},
		RelayTLS: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, Transport: "mixed",
		Parallel: c.Parallel, ReadyTimeout: 30 * time.Second, StopTimeout: 10 * time.Second, OnFailure: failure.capture,
	})
	if err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Minute)
		defer stop()
		shutdown, err := group.Close(cleanup)
		phase := phaseResult{Name: "deactivation", StartedAt: shutdown.StartedAt, DurationMilliseconds: milliseconds(shutdown.Duration), Attempts: shutdown.Attempts, Successes: shutdown.Successes, Errors: shutdown.Failures, Total: newDurationHistogram(shutdown.Timings)}
		if err == nil {
			result.Cleanup.Exact = true
		} else {
			stage = "shutdown"
		}
		result.Phases = append(result.Phases, phase)
		retErr = errors.Join(retErr, err)
	}()
	started := time.Now()
	routes, err := group.Start(ctx, benchworkload.RouteIndexes(c.Routes, c.WorkerCount, c.WorkerIndex))
	var durations []time.Duration
	for _, route := range routes {
		durations = append(durations, route.Activation)
	}
	phase := phaseResult{Name: "activation", StartedAt: started, DurationMilliseconds: milliseconds(time.Since(started)), Attempts: group.Started(), Successes: len(routes), Total: newDurationHistogram(durations)}
	if err != nil {
		phase.Errors = 1
	}
	result.Phases = append(result.Phases, phase)
	if err != nil {
		return err
	}
	if err := coordination.Put(ctx, fmt.Sprintf("publisher-%d.ready", c.WorkerIndex), routes); err != nil {
		return err
	}
	stage = "workload"
	waitCtx, stopWait := context.WithCancel(ctx)
	defer stopWait()
	stopped := make(chan error, 1)
	go func() { stopped <- coordination.Wait(waitCtx, "publish.stop", nil) }()
	select {
	case err := <-group.Failures():
		stopWait()
		<-stopped
		return err
	case err := <-stopped:
		return err
	}
}
