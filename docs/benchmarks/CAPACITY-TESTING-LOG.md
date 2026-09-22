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

## 2026-09-22 — Certificate Validation Shares The Visitor Source Bucket

The original 256-route attempt on clean `9b769d9` failed before visitor traffic.
Unlike the four-at-a-time 64/128 runs, it launched all 256 publishers concurrently.
Pebble validates each certificate three times from the same IP. Ingress applied
its 50/sec, burst-200 source bucket before inspecting the ClientHello, so it
rejected ACME checks as well as ordinary visitors.

An identical diagnostic reproduction and two single-variable experiments used
`ROUTES=256 START_PARALLEL=256 READY_TIMEOUT=5m RPS=160 DURATION=60s`. The code
remained `9b769d9` plus failure diagnostics; resource quotas, four certificate
workers, visitor deadlines, source count, worker count, and queue size were fixed.

| Source rate / burst | Accepted checks | Source rejections | Invalid orders | Total orders | Outcome                                            |
| ------------------- | --------------: | ----------------: | -------------: | -----------: | -------------------------------------------------- |
| 50 / 200            |             525 |               741 |            260 |          422 | Publisher certificate issuance failed              |
| 400 / 200           |             799 |                95 |             42 |          298 | All publishers ready; extra-order invariant failed |
| 50 / 1024           |             768 |                 0 |              0 |          256 | Complete workload passed                           |

Every row reconciles exactly: accepted plus source-rejected checks equals three
times the CA order count. Increasing **only burst** eliminated invalid orders
and replacement issuance at the original sustained rate. CPU throttling in
PostgreSQL/Pebble persisted in the passing run, so it did not require a resource
increase. This establishes source-budget coupling as the cause for this workload;
it does not characterize public-CA source distribution or maximum server capacity.

The passing burst-only run verified activation in 19.189s and completed
28,800/28,800 visitor requests (9,600 each in steady, restart, and shutdown),
with zero failures, timeouts, missed offers, queue expiry, or source rejections.
Exact raw-sample p95/max latencies were 3.861/12.763ms, 4.029/8.575ms, and
3.959/9.999ms respectively. Recovery took 16.713s; final accounting reconciled
29,448 successful streams including probes/held streams, and zero active
sessions, publisher connections, or reservations remained. All owned containers
exited zero and were removed. This is an explicitly overridden admission profile.

Evidence retained under `bench-results/` (each prefix has a log and directory):

- `capacity-routes-256-160rps-1`: original failure, no post-activation metrics.
- `capacity-routes-256-diagnostic-1`: identical reproduction with failure counters.
- `capacity-routes-256-source400-1`: rate-only comparison, still failed.
- `capacity-routes-256-burst1024-1`: burst-only comparison, passed.

The temporary ACME authorization-response recorder produced no error details:
the worker stops on an invalid order before fetching authorization again. It is
not retained as permanent tooling. Failure-time local actor metric/resource
capture and persisted order errors are retained. No individual failed
authorization was correlated with a specific rejected socket.

Follow-up: separate visitor, active route-challenge, and standalone service
admission budgets, retain bounded ClientHello inspection, and repeat the original
256-start workload at default source rate/burst. Preserve all failed runs above.

## 2026-09-22 — Independent Admission Fix At 256 Routes

Commit `51e1f6c` separated the bounded ClientHello inspection stage, ordinary
visitor source/concurrency limits, active route-challenge concurrency, and
standalone service handoff capacity. Deterministic tests cover fake/stale
challenge rejection, global and per-hostname challenge bounds, challenge
deadlines, inspection timeout cleanup, service capacity ownership through close,
and forced drain. The full formatting, lint, routine, race, PostgreSQL integration,
generation, and build sequence passed before the capacity rerun.

The original failed profile was then repeated without admission or workload
overrides: `ROUTES=256 START_PARALLEL=256 READY_TIMEOUT=5m RPS=160 DURATION=60s`.
The retained process configuration reports the production defaults: ClientHello
limit 1,024, challenge limit 1,024, per-hostname challenge limit eight, visitor
source rate 50/sec, and visitor burst 200.

- Activation installed 256 certificates from exactly 256 CA orders in 19.166s.
  Publisher readiness p95/max was 17.048/17.067s. There were no invalid or
  replacement orders, visitor source rejections, or capacity rejections.
- All 28,800 scheduled visitor requests succeeded: 9,600 in each steady,
  relay-restart, and shutdown window. There were zero failures, timeouts, missed
  offers, or queue expiry. Raw-sample p95/max latencies were 4.857/7.368ms,
  4.900/13.845ms, and 4.856/10.418ms respectively.
- Relay restart preserved every fresh request. All publisher connections repaired
  in 16.703s; every-route correctness probes passed. Preexisting held streams
  were disrupted as expected and were not replayed.
- Final accounting reconciled 29,448/29,448 successful streams including probes
  and held streams, with zero active route sessions, publisher connections, or
  reservations. Every component exited zero; the Compose project left no owned
  containers, networks, or volumes.
- Activation throttling remained confined to PostgreSQL/Pebble without affecting
  certificate correctness or timing. No application process throttled during
  steady traffic, and no process recorded an OOM kill.

Evidence retained in `bench-results/capacity-routes-256-default-fixed-1.log` and
`bench-results/capacity-routes-256-default-fixed-1/`. This validates the production
admission-policy correction for this workload; it does not yet establish the
maximum route count or throughput envelope.
