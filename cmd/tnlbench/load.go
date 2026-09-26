package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
)

type loadCommand struct {
	workerCommand
	PublicURLs      int      `name:"public-urls" env:"TNL_BENCH_PUBLIC_URLS" required:"" help:"Total public URLs."`
	PublicAddress   string   `name:"public-address" env:"TNL_BENCH_PUBLIC_ADDRESS" help:"Optional ingress host:port override."`
	ResolverAddress string   `name:"resolver-address" env:"TNL_BENCH_RESOLVER_ADDRESS" help:"Optional DNS server."`
	FreshRate       int      `name:"fresh-connections-per-second" env:"TNL_BENCH_FRESH_CONNECTIONS_PER_SECOND" required:"" help:"Assigned fresh requests/sec."`
	HeldStreams     int      `name:"held-streams" env:"TNL_BENCH_HELD_STREAMS" help:"Assigned held streams."`
	Concurrency     int      `name:"concurrency" env:"TNL_BENCH_CONCURRENCY" required:"" help:"Assigned visitor concurrency."`
	QueueSlots      int      `name:"queue-slots" env:"TNL_BENCH_QUEUE_SLOTS" help:"Assigned queue slots."`
	PayloadBytes    int      `name:"payload-bytes" env:"TNL_BENCH_PAYLOAD_BYTES" default:"32768" help:"Expected response bytes."`
	MetricsURLs     []string `name:"metrics-url" env:"TNL_BENCH_METRICS_URLS" help:"Private process metrics endpoints."`
	DiagnosticURLs  []string `name:"database-diagnostics-url" env:"TNL_BENCH_DATABASE_DIAGNOSTICS_URLS" help:"Database diagnostics endpoints."`
}

func (c loadCommand) Validate() error {
	if err := c.workerCommand.validate(); err != nil {
		return err
	}
	if c.PublicURLs <= 0 || c.FreshRate < 0 || c.FreshRate >= 40 || c.HeldStreams < 0 || c.Concurrency < 1 || c.QueueSlots < 0 || c.PayloadBytes < 1 || c.PayloadBytes > 16<<20 {
		return errors.New("invalid visitor limits or unsafe source rate")
	}
	for _, address := range []string{c.PublicAddress, c.ResolverAddress} {
		if address != "" {
			if _, _, err := net.SplitHostPort(address); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c loadCommand) run(parent context.Context) (retErr error) {
	ctx, cancel := context.WithTimeout(parent, c.Timeout)
	defer cancel()
	coordination, err := benchworkload.NewCoordination(c.CoordinatorURL, c.CoordinatorToken)
	if err != nil {
		return err
	}
	ctx, stopFailures := coordination.WorkloadContext(ctx)
	defer stopFailures()
	result := benchmarkResult{SchemaVersion: benchmarkResultSchemaVersion, CellID: c.CellID, Status: "passed", Worker: resultWorker{Kind: "load", Index: c.WorkerIndex, Count: c.WorkerCount}, Cleanup: resultCleanup{Exact: true}}
	failure := &failureCapture{ctx: ctx, metricsURLs: c.MetricsURLs, diagnosticURLs: c.DiagnosticURLs}
	stage := "setup"
	defer func() {
		if retErr != nil {
			failure.capture()
			result.Status = "failed"
			result.Failure = &resultFailure{Message: retErr.Error(), Stage: stage}
		}
		result.Resources = failure.resources
		result.DatabaseDiagnostics = failure.diagnostics
		post, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		retErr = errors.Join(retErr, coordination.Put(post, fmt.Sprintf("result.load-%d", c.WorkerIndex), result))
		if retErr != nil {
			_ = coordination.Put(post, "failure", boundedFailure(retErr.Error()))
		}
	}()
	var urls []string
	if err := coordination.Wait(ctx, "public_urls", &urls); err != nil {
		return err
	}
	if len(urls) != c.PublicURLs {
		return errors.New("coordinator public URL count mismatch")
	}
	if c.PublicAddress == "" {
		var hostnames []string
		for i := c.WorkerIndex; i < len(urls); i += c.WorkerCount {
			hostnames = append(hostnames, strings.TrimPrefix(urls[i], "https://"))
		}
		dnsCtx, stop := context.WithTimeout(ctx, benchmarkDNSPropagationTimeout)
		phase, err := waitForBenchmarkDNS(dnsCtx, hostnames, visitorDNSResolver(c.ResolverAddress).LookupHost, 250*time.Millisecond)
		stop()
		result.Phases = append(result.Phases, phase)
		if err != nil {
			return err
		}
	}
	visitor := benchworkload.Visitor{Address: c.PublicAddress, Resolver: visitorDNSResolver(c.ResolverAddress), PayloadBytes: c.PayloadBytes}
	var held []*benchworkload.HeldStream
	defer func() {
		for _, stream := range held {
			retErr = errors.Join(retErr, stream.Close())
		}
	}()
	for i := 0; i < c.HeldStreams; i++ {
		if err := sleepContext(ctx, time.Second/25); err != nil {
			return err
		}
		stream, err := visitor.Hold(ctx, urls[(c.WorkerIndex+i*c.WorkerCount)%len(urls)])
		if err != nil {
			return err
		}
		held = append(held, stream)
	}
	if err := coordination.Put(ctx, fmt.Sprintf("load-%d.ready", c.WorkerIndex), true); err != nil {
		return err
	}
	for sequence := 0; ; sequence++ {
		var phase benchworkload.Phase
		if err := coordination.Wait(ctx, fmt.Sprintf("phase-%d", sequence), &phase); err != nil {
			return err
		}
		if phase.Done {
			return nil
		}
		stage = phase.Name
		measured := phaseResult{Name: phase.Name, StartedAt: time.Now()}
		var phaseErr error
		if phase.Duration == 0 {
			var durations []time.Duration
			for i := c.WorkerIndex; i < len(phase.URLs); i += c.WorkerCount {
				row := visitor.Request(ctx, phase.URLs[i], time.Now())
				measured.Attempts++
				if row.Error != "" {
					failure.capture()
					measured.Errors++
					phaseErr = errors.Join(phaseErr, errors.New(row.Error))
				} else {
					measured.Successes++
					durations = append(durations, row.Duration)
				}
			}
			measured.Total = newDurationHistogram(durations)
		} else {
			value, err := visitor.Run(ctx, benchworkload.VisitorConfig{Rate: c.FreshRate, Workers: c.Concurrency, QueueSlots: c.QueueSlots, Start: phase.Start, Duration: phase.Duration, OnResult: func(row benchworkload.RequestResult) {
				if row.Error != "" {
					failure.capture()
				}
			}}, phase.URLs)
			measured.Visitor = &value
			measured.Attempts = value.Scheduled
			measured.Successes = value.Successes
			measured.Errors = value.Failures + value.Missed + value.QueueExpired
			phaseErr = errors.Join(err, value.Err())
			for _, stream := range held {
				if !stream.Alive() {
					phaseErr = errors.Join(phaseErr, errors.New("held stream ended during steady traffic"))
				}
			}
		}
		measured.DurationMilliseconds = milliseconds(time.Since(measured.StartedAt))
		result.Phases = append(result.Phases, measured)
		if err := coordination.Put(ctx, fmt.Sprintf("%s.load-%d", phase.Name, c.WorkerIndex), measured); err != nil {
			return err
		}
		if phaseErr != nil {
			return phaseErr
		}
	}
}

func sleepUntil(ctx context.Context, at time.Time) error { return benchworkload.WaitUntil(ctx, at) }
func sleepContext(ctx context.Context, delay time.Duration) error {
	return sleepUntil(ctx, time.Now().Add(delay))
}
