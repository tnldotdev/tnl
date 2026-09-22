# Contributing

## Development

Run commands from the repository root with the toolchain pinned in `mise.toml`:

```console
mise trust
mise install
mise exec -- pnpm install --frozen-lockfile
```

The full local sequence is:

```console
mise exec -- task generate
mise exec -- task format
mise exec -- task generate-check
mise exec -- task format-check
mise exec -- task lint
mise exec -- task test
mise exec -- task go:test:race
mise exec -- task go:test:integration
mise exec -- task build
```

Prepare the integration prerequisites below before running that tier.
`generate-check` regenerates files and compares committed generated paths to
`HEAD`; intentional uncommitted generated changes also appear as drift.
`format-check` is read-only. `format` applies Goimports and Oxfmt.

### Test Tiers

| Tier               | Command after `mise exec --`      | Prerequisites and scope                                                                    |
| ------------------ | --------------------------------- | ------------------------------------------------------------------------------------------ |
| Routine            | `task test`                       | Installed JavaScript dependencies; includes a package build                                |
| Race               | `task go:test:race`               | Go race detector; PostgreSQL-backed tiers remain opt-in                                    |
| Integration        | `task go:test:integration`        | Docker; Pebble from `mise install`; Task manages disposable PostgreSQL                     |
| Binary integration | `task go:test:integration:binary` | Integration prerequisites plus disposable Linux with local DNS/HTTPS ports available       |
| DNS integration    | `task go:test:integration:dns`    | Docker Compose; runs the authoritative DNS test with isolated Linux port 53 and PostgreSQL |
| Database load      | `task go:test:load:database`      | Docker; Task manages disposable PostgreSQL                                                 |
| Runtime load       | `task go:test:load:runtime`       | Docker Compose; constrained real publishers and visitor traffic                            |
| Go fuzzing         | `task go:test:fuzz`               | Runs every maintained Go fuzz target                                                       |
| Package checks     | `pnpm run pack`                   | Checks JavaScript exports and tarball contents                                             |
| Release snapshot   | `task package`                    | Builds native archives and npm packages, then verifies installations; does not publish     |

PostgreSQL-backed tasks start an isolated, digest-pinned PostgreSQL container,
wait for it to become healthy, and remove it after the test command. Focus a tier
with `RUN`, for example `task go:test:integration RUN='^TestIntegrationRouteRecovery$'`.

Binary tests change subprocess trust and configuration and bind privileged
ports. They run only on Linux; use the
[integration workflow](.github/workflows/integration.yml) as the setup
reference. The DNS integration task uses a dedicated Compose topology without
exposing its ports on the host. This lets the test DNS server use port 53 inside
its Linux container on any Docker host. The fixed Compose project name and
pre-run cleanup recover resources left by an interrupted prior invocation.

Task supplies `GOFLAGS=-tags=ts_omit_ssh`. Preserve it for direct Go commands:

```console
mise exec -- env GOFLAGS=-tags=ts_omit_ssh go test ./internal/tunnel
```

### Local Load Tests

Run database load tests with `mise exec -- task go:test:load:database`. Task
creates and removes their PostgreSQL container; CI uses the same command.

PR CI passes `ROUTES=32` for the database smoke. Scheduled and manually selected
load runs use the full 1,000-route workload, followed by the runtime reference and
fault scenarios. Routine Go and JavaScript stages run sequentially so package
build cleanup cannot race Go's repository traversal.

The default is 1,000 routes, with 64 workflows and two eight-connection request
pools. `ROUTES=<positive count>` changes only the route count; `RUN=<Go test regex>`
selects scenarios (default `^TestLoad`). For example:

```console
mise exec -- task go:test:load:database ROUTES=32 RUN='^TestLoadSteadyState$'
```

- `TestLoadPlacement` creates route sessions and claims their two publisher
  connections across four relay process records.
- `TestLoadPlacementWithHostnameLookup` adds a real authenticated hostname-lookup
  handler call before each session, preserving the same startup workflow.
- `TestLoadSteadyState` prepares ready sessions serially through production state
  methods and local signed-certificate fixtures, without injected SQL delay, and
  reports setup duration separately. Its timed mix runs three heartbeats per
  route, two serial usage streams (one per ingress, pages of 16), and concurrent
  ingress renewal plus routing event/snapshot reads through the same request
  pools. Each usage stream sends two cumulative revisions and replays every page
  once. Checks cover unchanged ready session/assignment identities, exact
  per-route bucket totals, ordered and complete routing revisions, and final
  snapshots containing every live route.
- `TestLoadRelayRecovery` restarts one relay process's database lease while 32
  recovery workflows, 32 healthy workflows, two serial usage writers, and two
  snapshot/ingress-renewal readers share the same pools. Readers sample initially,
  wait one second between completed cycles, and sample after all writers finish.
  Checks cover replacement assignments, stale-claim rejection, surviving
  connections, complete recovery, and exact final usage. It needs at least two
  routes and reports readiness time separately from final checks.

`HISTORY=<positive count>` sets the initial routing events per route for steady
state and recovery (default `1`). For example, `ROUTES=1000 HISTORY=1000` seeds
one million events before the timed workload. The fixture copies genuine ready
projections, advances their entry/global revisions, and analyzes the event table;
it logs setup time and relation size separately. Readers begin at the seeded
snapshot and validate subsequent live updates. This tests accumulated routing
data rather than elapsed days of operation. Placement tests ignore `HISTORY`;
the query profile retains its fixed 4/10/100-event-per-route stages.

Select `RUN='^TestLoadCadence$' DURATION=10m` for the separate paced workload.
`DURATION` opts it in and accepts whole minutes from 2m through 10m; routine load
runs skip it. It keeps 64 heartbeat workers and two eight-connection pools, but
schedules staggered heartbeats every 15 seconds with a ten-second deadline that
includes scheduler waiting. Sessions use 45-second leases; ingress and relay
leases last 30 seconds and renew every ten seconds. Setup holds its logical clock
fixed, then time advances at wall-clock speed throughout the workload.

The cadence case uses production ingress controllers and the standalone ingress
API adapter for initial snapshots, incremental updates, renewal, and a forced
resnapshot around a relay restart. It stops one relay's renewals halfway through,
waits for its real lease duration to expire, and registers a new process run.
Publisher connection replacement uses production state methods with 30-second
control-call deadlines. Visitor traffic is modeled as one accounted connection
per route per minute, split across two ingresses and six reporting checkpoints.
Checkpoints use 16-report pages, replay the first nonempty page once, and must
finish before the next ten-second checkpoint. This is an explicit baseline
activity model, not a high-bandwidth or held-stream test.

For example:

```console
mise exec -- task go:test:load:database ROUTES=1000 DURATION=10m RUN='^TestLoadCadence$'
mise exec -- task go:test:load:database ROUTES=10000 HISTORY=100 DURATION=10m RUN='^TestLoadCadence$'
```

Cadence output includes scheduled/completed work, overdue work, scheduler delay,
periodic backlog/freshness observations, recovery time from lease expiration,
production histograms, and final routing/usage/reservation verification. Database
sizes are sampled before/after rather than queried by the Prometheus collector.
Normal controller shutdown may record canceled long polls; those are separate
from a workload failure. A ten-minute case uses a further minute to stop and
verify actors, within the existing twenty-minute outer binary timeout.

These scenarios exercise database state without real tunnels, visitor traffic,
DNS resolution, or ACME network calls. The steady-state fixture signs test
certificates locally. The accelerated placement, steady-state, and recovery
cases use one-hour logical session and process leases; their repetitions are
not a lease-cadence or soak benchmark.

Use `DELAY=5ms` or `DELAY=20ms` to add client-side delay after successful SQL
commands. This is a latency-sensitivity model, not measured network latency.
The accelerated cases give each operation twenty seconds and each workload,
including final checks, five minutes. The test binary has a twenty-minute outer
timeout for all cases plus setup and cleanup. Actors are stopped and joined
on completion or failure; failures retain counts and timings in ordinary test
output. CI runs 0ms on PRs/main and 5ms nightly or manually.
Use 20ms for local experiments. Ordinary and integration test tasks skip these
load tests.

For cadence runs, `RETENTION=1m` enables two cleanup actors, one per control,
using the runtime's 1,000-candidate batches, 100ms inter-batch yield, 30-second
floor checks, and two-second call deadlines. The test window must be at least
30 seconds and less than half `DURATION`; production uses ten minutes. For example:

```console
mise exec -- task go:test:load:database ROUTES=1000 DELAY=5ms DURATION=10m RETENTION=1m RUN='^TestLoadCadence$'
```

This forces ingress to replay an old cursor through the real resnapshot boundary,
checks exact final event counts and routing state, and logs relation size,
estimated dead tuples, autovacuum counts, and cluster-wide WAL deltas. WAL includes
all concurrent database activity. Short test windows exercise repeated cleanup;
they do not establish production-window or multi-day storage requirements.

For isolated query-plan investigation, select `RUN='^TestProfile'` with
`DELAY=0ms`. These opt-in tests
log the actual generated queries' `EXPLAIN (ANALYZE, BUFFERS, SETTINGS)` plans:
placement counts at up to 1,000, 2,500, and `ROUTES` sessions, and routing reads
with 4, 10, and 100 events per live route. For example, `ROUTES=10000
RUN='^TestProfileRoutingHistory$'` profiles 40,000 through one million events.
History is bulk-copied from genuine ready-route projections; setup is untimed,
and three serial snapshots/plans per size measure read amplification without
concurrent writers. These profiles do not measure sustained heartbeat cadence,
history ingestion throughput, or mixed-workload recovery.

`RUN='^TestProfileRoutingRetention$'` profiles the actual retention SQL against
the same accumulated-history fixture, including an empty eligible range and a
full retention floor. Destructive EXPLAIN statements run inside rolled-back
transactions, and the test verifies the event count afterward.

`ROUTES=16 DELAY=10ms RUN='^TestProfileIngressUsage$'` isolates a 16-report usage
page, its replay, and a cumulative update with the same two eight-connection
pools. It logs production query/guard/operation histograms and verifies final
accounting. Use it to separate sequential round-trip cost from the competing
pool users and recovery burst in the cadence workload.

### Bounded Shutdown Load

`RUN='^TestLoadShutdown$'` closes half the ready sessions with 16 workers while
48 workers heartbeat the other half, two ingress sources send cumulative usage
pages and exact replays, and two readers consume routing events and renew leases.
It uses the same two eight-connection pools. Each close has ten seconds starting
when its worker takes the route; queued routes do not share an already-running
close deadline. It then finishes accounting and closes the remaining sessions.

Checks cover healthy-route survival, ordered tombstones, exact per-route usage,
zero remaining active sessions/connections/reservations, and idempotent closure.
Logs distinguish the overlapping shutdown phase, individual close duration, and
the full workload including accounting completion and verification. This is an
accelerated finite database workload with one-hour logical leases, not a soak or
an end-to-end publisher test. For example:

```console
mise exec -- task go:test:load:database ROUTES=1000 DELAY=5ms RUN='^TestLoadShutdown$'
```

### Runtime Load

`task go:test:load:runtime` runs one separated topology: control, ingress, two
relays, a publisher group, four visitor containers, a local service, Pebble/DNS,
PostgreSQL, and a coordinator. Publishers, visitors, histograms, and authenticated
HTTP coordination are shared with Fly through `internal/benchworkload`.
Production `publisher.Run` and `clientauth` own publishing and session refresh.

The default smoke has four routes, both QUIC and TLS/TCP, 16 fresh requests/sec,
ten-second steady/shutdown windows, **128 visitor workers**, and **eight waiting
slots** across the four visitor containers. Every request uses fresh verified
HTTP/1.1 TLS and validates the origin-observed hostname and 32KiB response.
Its five-second budget includes queue waiting; requests are never retried.

```console
mise exec -- task go:test:load:runtime RACE=1 RESULTS=bench-results/runtime-smoke
mise exec -- task go:test:load:runtime ROUTES=64 RPS=160 DURATION=30s RESULTS=bench-results/runtime-reference
mise exec -- env PUBLISHER_CPUS=0.25 task go:test:load:runtime ROUTES=64 RPS=160 DURATION=30s RESULTS=bench-results/runtime-publisher-025
mise exec -- task go:test:load:runtime SCENARIO=relay-kill RESULTS=bench-results/runtime-kill
mise exec -- task go:test:load:runtime SCENARIO=forwarding-blackhole RESULTS=bench-results/runtime-blackhole
mise exec -- task go:test:load:runtime SCENARIO=publisher-blackhole RESULTS=bench-results/runtime-publisher-blackhole
mise exec -- task go:test:load:runtime SCENARIO=udp-fallback RESULTS=bench-results/runtime-udp-fallback
mise exec -- task go:test:load:runtime SCENARIO=latency NETWORK_PATH=forwarding RTT=100ms RESULTS=bench-results/runtime-forwarding-rtt100
mise exec -- task go:test:load:runtime SCENARIO=packet-loss NETWORK_PATH=publisher LOSS=1 RESULTS=bench-results/runtime-publisher-loss1
```

`WORKERS` and `QUEUE` independently set total visitor concurrency and waiting
slots. Fixed offer windows count scheduled, started, completed, failed, timed-out,
missed, and queue-expired work. Offering and drain durations are separate. Successful
request histograms use production buckets and merge counts across generators.
First-byte timing means the first response **body** byte.

One coordinator supplies the phase sequence. Every route receives correctness
probes after each traffic window. Held streams must survive steady traffic;
restart windows retain all disruptions and require successful post-recovery traffic.
Missed offers fail every window. Four real source IPs preserve the normal
50-new-connections/sec source limit; concurrency does not create more source IPs.

`SCENARIO=relay-restart` is the default graceful restart. `relay-kill` uses Docker
SIGKILL, leaves the relay down longer than its 30-second lease, and requires a new
process run ID after restart. `forwarding-blackhole` drops only ingress-to-relay-a
TCP port 8443. `publisher-blackhole` drops publisher-to-relay-a TCP and UDP port
443 and measures detection using the existing transport timers. Control and
relay-b remain reachable. Blackholes stay installed through the entire traffic
window and every-route correctness probes; each installed rule must drop packets.
Fresh requests must have zero failures, timeouts, missed offers, and queue expiry
while the fault is active. Healthy-path held streams opened under the fault must
keep receiving bytes. Pre-existing held-stream disruption is recorded separately.
Fault windows last at least 40 seconds for graceful restart, 80 seconds for kill
and publisher blackhole, and 50 seconds for forwarding blackhole.

`udp-fallback` blocks both relay UDP addresses before publishing, uses automatic
transport selection, and requires a fallback event for each publisher and two ready
connections per route. The runner verifies that abandoned QUIC attempts leave no
publisher UDP sockets. Traffic and held streams use TLS/TCP through restoration.

Latency and loss experiments are explicit opt-in runs. `NETWORK_PATH=forwarding`
targets internal forwarding; `NETWORK_PATH=publisher` targets publisher connections.
`SCENARIO=latency` accepts `RTT=20ms`, `50ms`, or `100ms`, split equally between
both directions. `SCENARIO=packet-loss` accepts `LOSS=0.1` or `1` percent in each
direction. These impairments start before publishing, so activation and the
steady/scenario windows include the impairment; restoration precedes final probes
and shutdown traffic. They retain failures rather than adjusting workload budgets.
`SEED=<positive uint32>` requests a reproducible netem seed when the installed
kernel/iproute2 supports it; the default `0` records an unseeded experiment.

The runner retains targeted filters, qdisc packet/drop counters, and TCP RTT
observations. Counters must demonstrate both directions of an exercised path;
an unused alternate may have zero packets. Visitor artifacts include separate
QUIC/TCP cohort summaries. Scheduling and durations use a local monotonic epoch;
cross-process wall timestamps are correlation evidence, not precise elapsed clocks.
The authenticated phase barriers establish whether requests occurred under a fault.
All owned rules/qdiscs are restored on failure, including watchdog expiry, with
cleanup failures retained. Scheduled/manual CI runs the fault smokes; latency/loss
sweeps remain opt-in.

`TRACE=1` retains certificate HTTP metadata and persisted challenge/order sampling
for provisioning diagnosis. It adds inspection work; reference measurements leave
it disabled. Activation retains a 30-second per-publisher deadline, with four
concurrent starts and a ten-second per-publisher shutdown deadline.

| Component     | CPU quota | Memory limit | Overrides                            |
| ------------- | --------: | -----------: | ------------------------------------ |
| Control       |         1 |       512MiB | `CONTROL_CPUS`, `CONTROL_MEMORY`     |
| Ingress       |         1 |       256MiB | `INGRESS_CPUS`, `INGRESS_MEMORY`     |
| Each relay    |         1 |       256MiB | `RELAY_A_*`, `RELAY_B_*`             |
| Publishers    |         2 |       512MiB | `PUBLISHER_CPUS`, `PUBLISHER_MEMORY` |
| Each visitor  |         1 |       128MiB | `VISITOR_CPUS`, `VISITOR_MEMORY`     |
| Local service |         1 |       128MiB | `APP_CPUS`, `APP_MEMORY`             |
| Pebble/DNS    |         1 |       128MiB | `PEBBLE_CPUS`, `PEBBLE_MEMORY`       |
| PostgreSQL    |         1 |       512MiB | `DATABASE_CPUS`, `DATABASE_MEMORY`   |
| Coordinator   |       0.5 |       128MiB | Fixed                                |

Append `_CPUS` or `_MEMORY` to a prefix and pass it through `mise exec -- env`.
Swap is disabled. Publisher targets remain loopback-only: the local service has
its own cgroup but shares the publisher network namespace. Their network counters
are therefore marked shared and must not be summed. CPU and memory remain separate.

The result directory contains per-phase cgroup CPU, throttling, memory/current/peak,
OOM, and network-counter JSON, raw production `.prom` scrapes, visitor results,
and container exit evidence. Shared visitor summaries retain the merged histogram
counts and separate offering/drain durations. Gauge samples at one-second intervals appear in the
console log; redirect it to retain those samples. PostgreSQL's own resource files
are read through its disposable superuser connection, without a metrics sidecar.
Resource intervals include coordination/collection overhead and record their actual
duration; cgroup memory includes charged page cache. Quota and peak figures describe
the whole container, including its test wrapper.

Checks retain provisioning deadlines, one CA order per route, route versions,
recovery, healthy-route traffic during shutdown, and zero final active sessions,
connections, and reservations. Ingress stops while control/PostgreSQL remain up,
flushing its final usage checkpoints; latest per-route/bucket reports must match
stored connection and byte totals. The runner fails if any component exits early
and cleans its containers, networks, temporary keys/state, and volumes. Use a fresh
`RESULTS` path per experiment to preserve earlier evidence. Only the selected relay
SIGKILL is an expected early exit. Go build/module caches persist in dedicated
Docker volumes; databases, keys, publisher state, and coordination are fresh per
run. The origin has a separate cgroup locally; Fly embeds it in each publisher
process, so publisher resource costs include the origin there.

### JavaScript Package

`pnpm test` and `pnpm typecheck` build explicitly. Their `:run` variants and
direct Vitest runs do not. Build once before focused tests:

```console
mise exec -- pnpm --filter @tnldotdev/tnl build
mise exec -- pnpm exec vitest run packages/tnl/vite.test.ts
```

Keep the root package safe to run in a browser. Keep Node-only discovery and
framework code internal. `packages/tnl/package.json` defines the public exports;
the private development socket is not an extension API. The
[compatibility matrix](.github/workflows/checks.yml) tests supported framework
versions.

`packages/tnl/lib/native-targets.mjs` lists the native npm targets. When adding a
target, also add its native package template, GoReleaser artifact, launcher test
expectations, and package checks. Preserve checks for archive equality, license
files, public exports, and publishing native packages before the launcher.

### Generated Sources

Edit source contracts, then run `task generate` and `task format` through mise.
Do not hand-edit generated output.

| Source                                                                                                          | Committed output                                                                         |
| --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Five HTTP OpenAPI sources under `api/*/v1`                                                                      | Models, clients, and server interfaces under `pkg/api/*`                                 |
| `internal/controlstate/migrations` and `queries`                                                                | `internal/controlstate/controlstatedb`                                                   |
| `internal/clientstate/migrations` and `queries`                                                                 | `internal/clientstate/clientstatedb`                                                     |
| `internal/config` and its generator, `internal/projectconfig` key mappings, `scripts/generate-config-types.mjs` | `schema/v1.json`, `internal/projectconfig/keys.gen.json`, `packages/tnl/lib/config.d.ts` |

`packages/tnl/src` is handwritten; `packages/tnl/dist` is disposable build
output. Project-local `.tnl/project.json` and `.tnl/project.d.ts` are generated
by the CLI, not repository code generation. Their user workflow belongs in the
[package guide](packages/tnl/README.md).

## Local Stack

The local stack builds this checkout and runs PostgreSQL, Pebble, and standalone
`tnld`. It uses `127.0.0.1.nip.io` for public route namespaces and publishes ports
only on localhost. With Docker running:

```console
mise exec -- task local:up
mise exec -- task local:trust
mise exec -- task local:login
mise exec -- task local:tnl -- team current
```

`local:trust` modifies the macOS login keychain to trust the local certificate
roots. `mise exec -- task local:down` preserves PostgreSQL state;
`mise exec -- task local:reset` removes trust, containers, volumes, and `.local`.

Fly benchmarks are separate from local validation. Execution requires explicit
approval and the [benchmark gates](docs/benchmarks/README.md).

## Engineering Rules

- Follow [Architecture](docs/ARCHITECTURE.md) for package and API ownership and
  [AGENTS.md](AGENTS.md) for canonical terminology and CLI presentation rules.
- Prefer the smallest design that completes the current phase.
- Reuse the service that already owns a behavior, along with generated
  contracts, schema-derived types, and shared fixtures. Do not create a second
  implementation of the same rule.
- Use a maintained library instead of hand-rolling a capability. Ask before
  introducing a custom implementation when the tradeoff is unclear.
- Keep portable server packages independent of hosted protocol and domain types.
- Add tests for behavior, boundaries, and regressions. Do not add tautological
  tests solely to increase test counts.
- Keep release approval and publishing procedures in the
  [release guide](docs/RELEASES.md), not local development recipes.

## Dependencies And Notices

Every dependency must have a compatible license and a clear purpose. Direct
runtime dependencies that require attribution must add their notices to
`NOTICE`; generated release archives and native npm packages must include
`LICENSE`, `NOTICE`, and `THIRD_PARTY_LICENSES.txt`.
