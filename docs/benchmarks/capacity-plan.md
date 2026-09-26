# capacity testing plan

## goal

Find four safe limits for the smallest highly available tnl server deployment:

1. Active route sessions.
2. Fresh visitor connections per second.
3. Open visitor streams.
4. Bandwidth in each direction.

Then verify those limits while one failure boundary is unavailable.

This plan measures what one deployment can supply. Forecast demand comes later.

## test deployment

Use this minimum topology:

- Two control processes.
- Two ingress processes.
- Two relay services with one relay process each.
- The smallest suitable dedicated-CPU machine for each `tnld` process.
- A highly available PostgreSQL service.
- One region, with copies placed on separate hosts or zones when possible.

Publisher and visitor generators are not part of the capacity result. Give them
enough resources to exceed the load offered to the tnl server.

## first tests

| Test              | Keep steady                              | Increase                                      |
| ----------------- | ---------------------------------------- | --------------------------------------------- |
| Route sessions    | 10 connections/sec with 4KiB responses   | Start at 100 active route sessions and double |
| Fresh connections | A modest route count with 4KiB responses | Start at 100 connections/sec and double       |
| Open streams      | Low connection churn and a low byte rate | Start at 100 streams and double               |
| Bandwidth         | About 64 long-lived visitor streams      | Start at 100Mbit/sec and double               |

Test downstream and upstream bandwidth separately. Test both directions together
after their separate limits are clear.

These starting values are not capacity targets. If the first step fails, halve it
until it passes.

## how to run each test

1. Measure the same path without tnl.
2. Measure the unloaded tnl path.
3. Warm up for two minutes.
4. Measure for five minutes.
5. Double only the value under test.
6. Stop after the first failed or saturated step.
7. Test between the last pass and first failure.
8. Repeat the best passing step three times.

The direct-path test checks that the generators and network can carry more load
than the tnl server.

## when a test fails

A step fails when:

- A visitor connection is missed, rejected, timed out, or corrupted.
- Scheduled work does not start and finish within its request budget.
- A queue keeps growing.
- A process crashes, restarts, or runs out of memory.
- Memory keeps growing instead of leveling off.
- CPU, network, file descriptors, PostgreSQL, or another bounded resource fills.
- A limit rejects traffic outside a test that is meant to check that limit.
- Latency rises sharply and stays high.
- PublicURL, publisher connection, visitor stream, byte, or usage totals do not match.

Record queue, connection, TLS, first-body-byte, and total time for every step. Use
the resulting curves to find the latency knee instead of choosing a latency target
in advance.

When CPU saturates, capture an on-demand Go CPU profile from the affected `tnld`
process's private observability listener (`GET /debug/pprof/profile?seconds=30`;
1–30 seconds allowed). For a Fly.io Machine, configure that listener on its
private metrics port and use `fly proxy 9091:9090 -a APP --select` to select the
Machine. From another terminal, save the profile with
`curl --fail --max-time 40 -o relay.cpu.pprof
'http://127.0.0.1:9091/debug/pprof/profile?seconds=30'`, then inspect it with
`go tool pprof -http=127.0.0.1:0 relay.cpu.pprof`. The listener must not be a
public Fly service. Fly retains searchable app logs for seven days and managed
metrics for approximately 15 days; neither stores historical CPU profiles.
Save profiles only for diagnostic runs and compare ordinary capacity results
without profiling enabled.

## combined test

After the first tests:

1. Start at 25% of each measured limit.
2. Run route sessions, fresh connections, streams, and bandwidth together.
3. Raise the combined load in small steps.
4. Stop at the first shared resource or latency limit.
5. Repeat the highest clean step three times.

This test finds limits that do not appear when each kind of work runs alone.

## failure tests

Start at half of the lowest repeated combined limit. Test each failure separately:

1. Remove relay service A and keep traffic on relay service B.
2. Restore relay service A, then remove relay service B.
3. Remove one ingress process.
4. Remove one control process while route operations continue.
5. Test PostgreSQL failover separately.

For each failure:

- Record the exact failure time.
- Require every fresh visitor that starts after the failure to succeed.
- Do not replay visitor bytes already sent before the failure.
- Allow streams on the failed relay service to end.
- Require streams on the surviving relay service to keep receiving bytes.
- Keep serving the full offered fresh workload.
- Measure the first successful visitor and full publisher connection repair
  separately.
- Verify every active route after recovery.

After these tests pass, run the final combined workload for at least one hour.

## first production limits

Start with a conservative rule:

```text
operating limit = 50% of the lowest repeated degraded-state knee
```

Test the proposed route, connection, stream, and bandwidth limits together before
using them in production. If that test fails, lower the value that caused the
failure and test again.

The 50% margin is a starting policy. Production measurements can justify changing
it later.

## outputs

Publish:

- Direct-path and unloaded tnl baselines.
- Healthy and degraded curves for all four limits.
- The first limiting resource in each test.
- Per-route memory, file descriptor, goroutine, and PostgreSQL usage.
- Latency and queue curves.
- Recovery timing and results for every failure.
- Generator measurements that prove the generators did not limit the test.
- The combined safe operating envelope.
- Untested cases and remaining uncertainty.

## work order

1. Add and test direct-path measurements.
2. Add separate upstream, downstream, and bidirectional workloads.
3. Add relay-service, ingress-process, and control-process fault injection.
4. Check generator headroom and resource measurements locally.
5. Produce read-only infrastructure plans.
6. Get approval before creating billable benchmark infrastructure.
7. Run the four separate capacity tests.
8. Run the combined test.
9. Run failure and endurance tests.
10. Publish the measured limits and production recommendation.

Demand forecasts, multi-region failure, and maximum architecture scale are not
part of this first campaign.
