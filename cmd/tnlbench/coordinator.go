package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/naming"
)

type coordinatorCommand struct {
	Listen           string        `name:"listen" env:"TNL_BENCH_COORDINATOR_LISTEN" default:":8080" help:"Coordinator listen address."`
	Token            string        `name:"token" env:"TNL_BENCH_COORDINATOR_TOKEN" required:"" help:"Run bearer token."`
	CellID           string        `name:"cell-id" env:"TNL_BENCH_CELL_ID" required:"" help:"Workload identity."`
	PublisherWorkers int           `name:"publisher-workers" env:"TNL_BENCH_PUBLISHER_WORKERS" required:"" help:"Publisher processes."`
	LoadWorkers      int           `name:"load-workers" env:"TNL_BENCH_LOAD_WORKERS" required:"" help:"Visitor processes."`
	PublicURLs       int           `name:"public-urls" env:"TNL_BENCH_PUBLIC_URLS" required:"" help:"Expected public URL count."`
	Repetitions      int           `name:"repetitions" env:"TNL_BENCH_REPETITIONS" default:"1" help:"Steady measurement windows."`
	Warmup           time.Duration `name:"warmup" env:"TNL_BENCH_WARMUP" default:"5s" help:"Warmup."`
	Duration         time.Duration `name:"duration" env:"TNL_BENCH_DURATION" default:"10s" help:"Offer window duration."`
	Timeout          time.Duration `name:"timeout" env:"TNL_BENCH_TIMEOUT" default:"30m" help:"Run deadline."`
	MetricsURLs      []string      `name:"metrics-url" env:"TNL_BENCH_METRICS_URLS" help:"Private metrics endpoints."`
}

func (c coordinatorCommand) Validate() error {
	if c.PublisherWorkers < 1 || c.LoadWorkers < 1 || c.PublicURLs < 1 || c.Repetitions < 1 || c.Repetitions > 10 || c.Duration <= 0 || c.Timeout <= 0 || c.Warmup < 0 {
		return errors.New("invalid coordinator workload")
	}
	return nil
}

func (c coordinatorCommand) run(parent context.Context) error {
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: benchworkload.NewCoordinator().Handler(c.Token), ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() { _ = server.Close(); <-done }()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	client, err := benchworkload.NewCoordination("http://127.0.0.1:"+port, c.Token)
	if err != nil {
		return err
	}
	if err := client.Put(parent, "coordinator.ready", true); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, c.Timeout)
	defer cancel()
	results, runErr := c.execute(ctx, client)
	post, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	if err := client.Put(post, "results", results); err != nil {
		return errors.Join(runErr, err)
	}
	status := "passed"
	if runErr != nil {
		status = "failed"
		_ = client.Put(post, "failure", boundedFailure(runErr.Error()))
	}
	if err := client.Put(post, "complete", status); err != nil {
		return errors.Join(runErr, err)
	}
	// Collection ownership belongs to the host runner. Keep artifacts available
	// until teardown, bounded even if the runner is interrupted.
	select {
	case <-parent.Done():
	case <-time.After(time.Hour):
	}
	return nil
}

func (c coordinatorCommand) execute(ctx context.Context, client *benchworkload.Coordination) (results []benchmarkResult, retErr error) {
	var resources []resourceSample
	sampler := startResourceSampler(context.WithoutCancel(ctx), c.MetricsURLs, 5*time.Second)
	defer func() {
		resources = append(resources, sampler.Stop()...)
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Minute)
		defer stop()
		if retErr != nil {
			_ = client.Put(cleanup, "failure", boundedFailure(retErr.Error()))
		}
		_ = client.Put(cleanup, "publish.stop", true)
		// Failed participants may have already recorded results. Get (rather than
		// Wait) collects remaining cleanup evidence after an abort event.
		for _, kind := range []string{"publisher", "load"} {
			count := c.PublisherWorkers
			if kind == "load" {
				count = c.LoadWorkers
			}
			for i := range count {
				var result benchmarkResult
				for {
					found, err := client.Get(cleanup, fmt.Sprintf("result.%s-%d", kind, i), &result)
					if err != nil {
						retErr = errors.Join(retErr, err)
						break
					}
					if found {
						results = append(results, result)
						if result.Status != "passed" {
							retErr = errors.Join(retErr, fmt.Errorf("%s-%d failed", kind, i))
						}
						break
					}
					if err := sleepContext(cleanup, 100*time.Millisecond); err != nil {
						retErr = errors.Join(retErr, fmt.Errorf("missing %s-%d result: %w", kind, i, err))
						break
					}
				}
			}
		}
		if len(results) > 0 {
			results[0].Resources = append(results[0].Resources, resources...)
			results[0].DroppedResourceSamples = sampler.dropped
		}
	}()
	resources = append(resources, sampleBoundaryResources(ctx, c.MetricsURLs, "activation-before")...)
	urls := make([]string, c.PublicURLs)
	seenHostnames := make(map[string]bool)
	for i := range c.PublisherWorkers {
		var publicURLs []benchworkload.PublishedPublicURL
		if err := client.Wait(ctx, fmt.Sprintf("publisher-%d.ready", i), &publicURLs); err != nil {
			return nil, err
		}
		for _, route := range publicURLs {
			u, err := url.Parse(route.Ready.PublicURL)
			if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
				return nil, errors.New("invalid publisher route URL")
			}
			hostname, err := naming.CanonicalizeHostname(u.Hostname())
			if err != nil || hostname != u.Host || seenHostnames[hostname] || route.Index < 0 || route.Index >= len(urls) || urls[route.Index] != "" {
				return nil, errors.New("invalid or duplicate publisher route registration")
			}
			seenHostnames[hostname] = true
			urls[route.Index] = route.Ready.PublicURL
		}
	}
	for _, url := range urls {
		if url == "" {
			return nil, errors.New("missing publisher route")
		}
	}
	resources = append(resources, sampleBoundaryResources(ctx, c.MetricsURLs, "activation-after")...)
	if err := client.Put(ctx, "public_urls", urls); err != nil {
		return nil, err
	}
	for i := range c.LoadWorkers {
		if err := client.Wait(ctx, fmt.Sprintf("load-%d.ready", i), nil); err != nil {
			return nil, err
		}
	}
	if err := sleepContext(ctx, c.Warmup); err != nil {
		return nil, err
	}
	sequence := 0
	phase := func(name string, duration time.Duration) error {
		start := time.Now().Add(time.Second)
		if err := client.Put(ctx, fmt.Sprintf("phase-%d", sequence), benchworkload.Phase{Name: name, Start: start, Duration: duration, URLs: urls}); err != nil {
			return err
		}
		sequence++
		for i := range c.LoadWorkers {
			var result phaseResult
			if err := client.Wait(ctx, fmt.Sprintf("%s.load-%d", name, i), &result); err != nil {
				return err
			}
			if result.Errors != 0 {
				return fmt.Errorf("visitor %d failed in %s", i, name)
			}
		}
		return nil
	}
	if err := phase("correctness", 0); err != nil {
		return nil, err
	}
	for repetition := 1; repetition <= c.Repetitions; repetition++ {
		name := fmt.Sprintf("steady-%d", repetition)
		resources = append(resources, sampleBoundaryResources(ctx, c.MetricsURLs, name+"-before")...)
		if err := phase(name, c.Duration); err != nil {
			return nil, err
		}
		resources = append(resources, sampleBoundaryResources(ctx, c.MetricsURLs, name+"-after")...)
	}
	if err := client.Put(ctx, fmt.Sprintf("phase-%d", sequence), benchworkload.Phase{Done: true}); err != nil {
		return nil, err
	}
	return results, nil
}

func boundedFailure(message string) string {
	if len(message) <= 4096 {
		return message
	}
	limit := 4096
	for !utf8.ValidString(message[:limit]) {
		limit--
	}
	return message[:limit]
}
