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
- At steady state, publisher client-generator memory was 56.4MiB for 64 routes
  and 79.1MiB for 128; active-relay memory was 30.4MiB and 36.4MiB; PostgreSQL
  was 119.3MiB and 146.7MiB. Control and ingress memory remained approximately
  flat. These two points are insufficient to assume a linear slope through 1,000
  routes.
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

## 2026-09-22 — Route Scaling At 512 Routes

The next point used committed revision `ece297a` and the same default-admission
profile, with only `ROUTES` and `START_PARALLEL` raised from 256 to 512. Activation
installed 512 certificates from exactly 512 CA orders in 32.312s; publisher
readiness p95/max was 31.896/32.007s. Source and capacity rejections remained zero.

- All 28,800 scheduled requests succeeded with zero failures, timeouts, missed
  offers, or queue expiry. Steady, relay-restart, and shutdown p95/max latencies
  were 4.859/9.286ms, 4.929/11.427ms, and 4.864/10.766ms.
- Relay restart preserved fresh traffic and repaired all publisher connections in
  26.737s. Every-route correctness probes passed; held-stream disruption retained
  the expected no-replay behavior.
- Final accounting reconciled 30,088/30,088 successful streams, with zero active
  sessions, publisher connections, or reservations. Every component exited zero
  and all owned Docker resources were removed.
- Peak publisher client-generator memory was 266.9MiB of 512MiB. Peak PostgreSQL
  memory was 271.4MiB of 512MiB. Relay-a's cgroup peak reached 141.4MiB of
  256MiB after its graceful restart; later clean-process attribution established
  that this retained sequential relay incarnations and is not a single-relay
  footprint. No process recorded an OOM kill. Application processes did not
  materially throttle; PostgreSQL throttled during activation and recovery while
  correctness and visitor timing remained intact.

Evidence retained in `bench-results/capacity-routes-512-160rps-1.log` and
`bench-results/capacity-routes-512-160rps-1/`. At the time, the retained cgroup
peak appeared to place 1,000 routes near the 256MiB relay limit, so the campaign
inserted a 768-route point before attempting 1,000. Later attribution below
supersedes that interpretation.

## 2026-09-22 — Route Scaling At 768 Routes

The inserted 768-route point used committed revision `29e0618`, default admission
and resource limits, 768-way activation, and the same 160 RPS/60-second windows.
Activation installed 768 certificates from exactly 768 CA orders in 64.732s;
publisher readiness p95/max was 61.511/61.632s. Source and capacity rejections
remained zero.

- All 28,800 scheduled requests succeeded with zero failures, timeouts, missed
  offers, or queue expiry. Steady, relay-restart, and shutdown p95/max latencies
  were 4.863/10.730ms, 4.969/19.693ms, and 4.865/9.112ms.
- Relay restart preserved fresh traffic and repaired all publisher connections in
  27.059s. Every-route probes passed and no visitor bytes were replayed.
- Final accounting reconciled 30,728/30,728 successful streams with zero active
  sessions, publisher connections, or reservations. Every component exited zero
  and all owned Docker resources were removed.
- Relay-a's retained cgroup peak reached 220.1MiB of 256MiB after graceful
  restart; this combines sequential relay incarnations rather than measuring one
  live relay. The publisher client generator reached 393.5MiB of 512MiB (77%),
  PostgreSQL 338.4MiB of 512MiB, and control 175.2MiB of 512MiB. There were no
  OOM kills.
- PostgreSQL used 0.948 CPU during activation and accumulated 232.0 CPU-seconds of
  quota throttling under its one-CPU limit. Activation approximately doubled from
  the 512-route point while application processes retained substantial CPU
  headroom during visitor phases.

Evidence retained in `bench-results/capacity-routes-768-160rps-1.log` and
`bench-results/capacity-routes-768-160rps-1/`. This is a passing point but not a
production recommendation with failure headroom. The then-apparent relay warning
threshold motivated a 1,000-route default run; later clean-process evidence below
shows that graceful-restart peak was not a valid relay memory boundary.

## 2026-09-22 - Route Scaling At 1,000 Routes

The first 1,000-route attempt used committed revision `7611dc0`, default admission
and resource limits, 1,000-way activation, and the same 160 RPS/60-second windows.
All 1,000 publishers became ready, all 28,800 scheduled requests succeeded, and
final accounting reconciled. The test nevertheless failed because each of the
four visitor sources sent its 250-route correctness share immediately after a
traffic window. That synthetic burst exceeded the default per-source burst of
200: the steady correctness sweep had 69 EOFs and the relay-restart sweep had 76,
matching cumulative source-limit counters of 69 and 145. The 500-route shutdown
sweep passed. This retained failure is a harness-induced admission event, not a
server route-capacity failure.

Commit `61cbe9f` paced only zero-duration correctness probes at the configured
per-source rate. It did not change the 160 RPS measured traffic, visitor deadline,
route coverage, admission settings, or resource limits. A four-route separated
runtime smoke passed before the same 1,000-route profile was repeated.

- Activation installed 1,000 certificates from exactly 1,000 CA orders in
  2m6.876s. Publisher readiness p50/p95/max was
  1m59.163s/2m3.037s/2m3.667s.
- All 28,800 scheduled requests succeeded with zero failures, timeouts, missed
  offers, or queue expiry. Steady, relay-restart, and shutdown p95/max latencies
  were 4.876/11.255ms, 4.998/18.785ms, and 4.865/11.451ms.
- All 2,500 live-route correctness requests succeeded. Each full 1,000-route
  sweep took 4.98s, consistent with four sources paced at 50 requests/sec. Source
  and capacity rejections remained zero.
- Relay restart preserved every fresh request. The first successful body arrived
  9.113ms after process exit, and all publisher connections repaired in 23.734s.
  Preexisting held streams were disrupted as expected and were not replayed.
- Final accounting reconciled 31,308/31,308 successful streams, with zero active
  route sessions, publisher connections, or reservations. Every component exited
  zero, and the Compose project left no containers, networks, or volumes.
- Both relays held exactly 1,000 ready publisher connections before traffic, which
  exactly consumed the then-current default per-process publisher connection
  limit. Before graceful restart, relay-a used 180.6MiB with a 181.3MiB cgroup
  peak and relay-b used 167.5MiB. Relay-a's later 256MiB cgroup peak retained
  sequential relay incarnations and is not single-process usage. The publisher
  client generator reached 508.2/512MiB, PostgreSQL 498.3/512MiB, and control
  298.4/512MiB.
- PostgreSQL accumulated 546.2 CPU-seconds of quota throttling, including 505.7
  during activation under its one-CPU quota. No application process materially
  throttled, and no process recorded an OOM kill.

Evidence is retained in `bench-results/capacity-routes-1000-default-1.log`,
`bench-results/capacity-routes-1000-default-1/`, and
`bench-results/capacity-routes-1000-default-paced-1/`. The tested revision can
complete the 1,000-route workload and reached its configured publisher-connection
boundary, but the raw cgroup peaks did not establish relay or PostgreSQL memory
exhaustion. The publisher figure belongs to the client generator, not the tnl
server. Do not treat 1,000 routes as a production operating point; production
guidance still requires repeated failure-headroom measurements.

## 2026-09-22 — Resource Attribution And Abrupt Relay Loss At 1,000 Routes

Resource attribution was added on base revision `9929963`. It records cgroup v2
memory categories and pressure/OOM events at every phase boundary, and records
PostgreSQL shared-memory allocation, shared buffers, backends, block activity,
and temporary bytes. The following values are post-steady-window
`memory.current` measurements from the passing 256, 512, 768, and 1,000-route
runs. The final row is an ordinary least-squares fit across those four points,
not an extrapolated capacity claim.

|    Routes |  Relay-a |  Relay-b | Publisher generator | PostgreSQL |
| --------: | -------: | -------: | ------------------: | ---------: |
|       256 |  58.6MiB |  44.7MiB |            147.0MiB |   152.1MiB |
|       512 |  90.5MiB |  78.8MiB |            253.9MiB |   205.2MiB |
|       768 | 136.2MiB | 117.1MiB |            389.7MiB |   241.0MiB |
|     1,000 | 180.6MiB | 167.5MiB |            504.2MiB |   299.7MiB |
| KiB/route |    169.2 |    166.9 |               496.6 |      196.6 |

- Relay process RSS fits were 155.8 and 162.3KiB/route. Each relay also added
  approximately four goroutines and 0.5 file descriptors per route. The two
  relay fits and their different intercepts are a useful range, not one exact
  per-route allocation constant.
- The publisher column measures the client generator, not the tnl server. Its
  approximately 497KiB/route slope determines local harness memory needs only.
- PostgreSQL's cgroup slope is not an anonymous resident-set slope. In the final
  attribution run it used 477.4MiB with a 501.7MiB peak, but only 43.7MiB was
  anonymous memory; 414.7MiB was file-backed, including 100.7MiB shared memory.
  PostgreSQL reported 143.0MiB allocated shared memory and 128MiB shared buffers.
  There were no cgroup pressure or OOM events.

Two abrupt relay-loss runs then used the same 1,000-route, 160-request/sec,
32KiB-response profile with four visitor sources, 128 total workers, eight total
waiting slots, and a diagnostic 768MiB publisher-generator limit. The first run
used ingress's original one-second preferred-relay attempt budget:

- The full workload scheduled 32,000 requests. It started 31,973, succeeded on
  31,972, returned one EOF, and missed 27 offers. In the 12,800-request fault
  window, maximum request latency was 1,025.088ms and maximum queue delay was
  214.959ms.
- The missed offers came from the bounded visitor worker/queue configuration,
  not visitor CPU saturation or server admission. The one EOF was already in
  flight when the relay process exited and was not replayed, preserving the
  retry-boundary invariant.
- The first successful response arrived 920.727ms after process exit. The
  replacement relay was restored 31.220s after exit and every route was verified
  repaired 51.597s after exit. All 2,500 post-recovery correctness requests
  succeeded.

Ingress's preferred-relay attempt budget was then reduced to 250ms. The default
per-relay publisher connection limit was independently raised from 1,000 to
4,000 so route-count experiments no longer stop at the old arbitrary admission
boundary. The repeated full workload produced:

- All 32,000 scheduled requests started and succeeded, with zero failures,
  timeouts, missed offers, queue expiry, or source-limit rejections. The fault
  window's maximum request latency was 257.479ms and maximum queue delay was
  4.032ms. All 3,656 failed preferred-relay backend attempts fell within the
  250ms duration histogram bucket.
- The first successful response arrived 159.126ms after relay process exit. The
  replacement was restored 31.225s after exit and every route was verified
  repaired 51.582s after exit. The shorter visitor fallback therefore fixes the
  request-level interruption without changing full route-session repair time.
- Before the fault, relay-a used 173.4MiB with a 174.6MiB cgroup peak and relay-b
  used 166.7MiB with a 167.8MiB peak. After repair, the clean replacement used
  146.1MiB with a 147.5MiB peak; the surviving relay used 210.6MiB with a
  212.3MiB peak after carrying failover traffic. The survivor reached 83% of its
  256MiB limit but recorded no memory-pressure or OOM event.
- Both relays again held 1,000 ready publisher connections. All 2,500 correctness
  requests succeeded, final usage reconciled 34,508/34,508 successful streams,
  every component exited zero, and cleanup left no owned Docker resources.

The 250ms attempt budget removed the observed harness backpressure while retaining
the no-replay boundary, but a request that has crossed that boundary can still
fail if its connected relay dies. The 4,000 publisher-connection default was
propagated and admitted this 1,000-route run; it does not establish 4,000-route
capacity. One passing abrupt-loss run is also insufficient production guidance,
especially with the surviving relay at 83% of its memory limit.

Evidence is retained in:

- `bench-results/resource-attribution-routes-1000-relay-kill-1/`
- `bench-results/resource-attribution-routes-1000-relay-kill-fallback250-1/`
