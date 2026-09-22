# Capacity Testing Working Log

This is a **temporary working log**, not production sizing guidance. At the end
of the capacity-testing campaign, **delete this file** and replace it with
`docs/benchmarks/capacity.md`: a fully written account of the findings, measured
operating envelope, recommended production resources, failure headroom, and
remaining uncertainty. Preserve useful evidence links in that final document.

## Scope And Measurement Rules

- Measure ready-route scaling, fresh-connection throughput, bandwidth, held
  streams, failure capacity, and endurance using the shared workload and local
  separated topology. Cold-activation optimization has a separate owner.
- Keep the 64-route, 160-request/sec, 32KiB reference reproducible. Record setup
  separately and declare admission/resource overrides before each experiment.
- Preserve the five-second visitor budget, offered traffic, failed artifacts,
  route/assignment correctness, no-replay boundary, and final usage reconciliation.
- Record generator limits separately from server limits. Recommendations require
  repeated measurements and capacity during failure, not extrapolation from a
  successful smoke run.
- Local validation is authorized; Fly execution requires separate approval.

## 2026-09-21 — Admission-Limit Setup

Starting baseline revision: `e8ab242`. The admission-limit validation ran after
the independent TypeScript tooling migration at `d6a278e`, with admission-limit
and cold-activation instrumentation in the tested tree. Production source-limit
configuration landed in `d16df04`; the independent runtime admission profile and
fixture plumbing landed in `07a2d26`. Task/Compose, coordinator, and
role-applicable artifact plumbing shared files with cold-activation work and
landed in `5ef4eae` after combined validation.

Setup:

- Exposed production source-connection rate/burst configuration (defaults 50/sec
  and 200), scoped to each ingress process and source IPv4 address or IPv6 /64.
- Passed explicit source, visitor, per-route, publisher, relay-stream, and QUIC
  admission limits through Task/Compose into the existing production settings.
- Saved requested and role-applicable component configuration with benchmark
  artifacts; do not describe unexercised limits as behaviorally validated.
- Validated configuration parsing, enforcement, and a small overridden runtime
  profile before starting capacity ramps.

Validation evidence:

- Production configuration/rate enforcement: focused race tests and vet passed
  for `internal/tnldconfig`, `internal/config`, `internal/ingress`,
  `internal/sourcelimiter`, and `cmd/tnld`.
- Default race-enabled runtime smoke: 160/160 steady, 640/640 relay-restart,
  and 160/160 shutdown requests succeeded. No failures, timeouts, missed offers,
  queue expiry, source-limit rejections, or final accounting mismatches.
- Override runtime: source rate 400/sec, burst 80, visitor limit 12,000,
  route limit 750, publisher limit 64, relay stream capacity 512, and QUIC stream
  limit 128. Ingress and both relays reported matching role-applicable process
  configuration. The source-rate override was behaviorally exercised; the other
  values require their later capacity-boundary experiments to prove enforcement.
- The override offered 240 fresh connections/sec across four sources for
  30/40/30-second windows: 7,200/9,600/7,200 successful requests, with no
  failures, timeouts, missed offers, queue expiry, or source-limit rejections.
  This exceeds the old sustained 50/sec/source limit for long enough that its
  200-token burst would have been exhausted.
- Both runs ended with exact usage reconciliation and zero active sessions,
  publisher connections, or reservations. All owned containers exited zero and
  the isolated Compose project left no containers, networks, or volumes.

Retained local evidence:

- `bench-results/capacity-admission-default.log`
- `bench-results/capacity-admission-default/`
- `bench-results/capacity-admission-override.log`
- `bench-results/capacity-admission-override/`

These runs validate configuration and harness propagation, not maximum capacity.
No new production-sizing conclusion has been established yet.

## 2026-09-21 — Route Scaling At 160 Requests/Sec

The first route-overhead points ran from committed revision `dead311` with an
uncommitted test-harness-only change in `separated_load_test.go`; production
runtime files matched the commit at preflight. Both used four visitor sources,
128 workers, eight waiting slots, 32KiB responses, default admission/resource
limits, four-way activation, and 60-second steady/restart/shutdown windows.

Results:

| Routes | Successful scheduled requests | Steady p95/max | Restart p95/max | Shutdown p95/max |
| -----: | ----------------------------: | -------------: | --------------: | ---------------: |
|     64 |                 28,800/28,800 | 4.904/13.985ms |  4.936/10.243ms |   4.909/11.479ms |
|    128 |                 28,800/28,800 |  4.843/8.771ms |   4.858/8.172ms |   4.865/12.036ms |

- Every window had zero failures, timeouts, missed offers, queue expiry,
  source-limit rejections, routing backlog, routing update failures, or OOMs.
- Both relay restarts preserved all fresh requests. All publisher connections
  repaired in 26.81s at 64 routes and 26.77s at 128 routes; every-route probes
  returned 64/64 and 128/128 bodies. Preexisting held streams were disrupted as
  expected and were not replayed.
- Four-way activation took 2m59.55s and 5m55.68s. Per-publisher p95 readiness was
  11.25s and 11.30s, so total setup was constrained by configured activation
  parallelism/certificate workflow rather than worsening per-route readiness.
- At steady state, publisher memory was 56.4MiB for 64 routes and 79.1MiB for
  128; active-relay memory was 30.4MiB and 36.4MiB; PostgreSQL was 119.3MiB and
  146.7MiB. Control and ingress memory remained approximately flat. These two
  points are insufficient to assume a linear slope through 1,000 routes.
- Steady ingress CPU was 8.57s/60s and 7.15s/60s; active-relay CPU was
  9.89s/60s and 8.30s/60s. No application process throttled. PostgreSQL had
  minor activation/recovery throttling under its one-CPU quota without visitor
  or state impact.
- Final usage was exact: 28,968/28,968 and 29,128/29,128 successful persisted
  streams, including probes/held streams. Both runs ended with zero active route
  sessions, publisher connections, and reservations, and all containers exited
  zero with no owned Docker resources left behind.

Retained local evidence:

- `bench-results/capacity-routes-64-160rps-1.log`
- `bench-results/capacity-routes-64-160rps-1/`
- `bench-results/capacity-routes-128-160rps-1.log`
- `bench-results/capacity-routes-128-160rps-1/`

Classification: neither point reached a server, admission, generator, database,
origin, publisher, or host capacity limit. They establish ready-route overhead
and fault correctness at fixed traffic, not maximum capacity.
