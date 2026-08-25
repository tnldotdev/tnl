package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

func visitorDNSResolver(address string) *net.Resolver {
	if address == "" {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, "tcp", address)
		},
	}
}

// DNS propagation is setup work with its own bounded, recorded duration. Every
// correctness and measured visitor request still performs its normal lookup.
func waitForBenchmarkDNS(ctx context.Context, hostnames []string, lookup func(context.Context, string) ([]string, error), retryInterval time.Duration) (phaseResult, error) {
	started := time.Now().UTC()
	results := make([]visitorResult, len(hostnames))
	concurrency := min(8, len(hostnames))
	var workers sync.WaitGroup
	for worker := range concurrency {
		workers.Go(func() {
			for index := worker; index < len(hostnames); index += concurrency {
				began := time.Now()
				var err error
				for {
					if err = ctx.Err(); err != nil {
						break
					}
					addresses, lookupErr := lookup(ctx, hostnames[index])
					if lookupErr == nil && len(addresses) > 0 && ctx.Err() == nil {
						break
					}
					if err = sleepContext(ctx, retryInterval); err != nil {
						break
					}
				}
				elapsed := time.Since(began)
				results[index] = visitorResult{timing: visitorTiming{dns: elapsed, total: elapsed}, err: err}
			}
		})
	}
	workers.Wait()
	phase := phaseFromVisitorResults("dns_readiness", started, time.Since(started), results, concurrency)
	for index, result := range results {
		if result.err != nil {
			return phase, fmt.Errorf("DNS readiness for %s: %w", hostnames[index], result.err)
		}
	}
	return phase, nil
}
