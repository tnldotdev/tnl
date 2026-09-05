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
mise exec -- task go:test-race
mise exec -- task go:test-integration
mise exec -- task build
```

Prepare the integration prerequisites below before running that tier.
`generate-check` regenerates files and compares committed generated paths to
`HEAD`; intentional uncommitted generated changes also appear as drift.
`format-check` is read-only. `format` applies Goimports and Oxfmt.

### Test Tiers

| Tier               | Command after `mise exec --`                                 | Prerequisites and scope                                                                     |
| ------------------ | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| Routine            | `task test`                                                  | Installed JavaScript dependencies; includes a package build                                 |
| Race               | `task go:test-race`                                          | Go race detector; integration tests remain opt-in                                           |
| Integration        | `task go:test-integration`                                   | Disposable PostgreSQL, Pebble from `mise install`, installed dependencies, and `pnpm build` |
| Binary integration | `env TNL_TEST_BINARY_INTEGRATION=1 task go:test-integration` | Integration prerequisites plus disposable Linux with local DNS/HTTPS ports available        |
| DNS integration    | `task go:test-integration-dns-linux`                         | Docker Compose; runs the authoritative DNS test with isolated Linux port 53 and PostgreSQL  |
| Local load         | `task go:test-load`                                          | Disposable PostgreSQL, using the same URL prerequisite as integration tests                 |
| Package checks     | `pnpm run pack`                                              | Checks JavaScript exports and tarball contents                                              |
| Release snapshot   | `task package`                                               | Builds native archives and npm packages, then verifies installations; does not publish      |

Integration tests require `TNL_TEST_POSTGRES_URL`. It must point to a disposable
PostgreSQL server whose user can create databases. The fixtures create and
forcibly drop databases, so never use a production server.

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

Set `TNL_TEST_POSTGRES_URL` to a disposable PostgreSQL server, using the same
requirements as integration tests, then run `mise exec -- task go:test-load`.
CI supplies the database through the load workflow's PostgreSQL service.

The default is 1,000 routes, with 64 workflows and two eight-connection request
pools. `ROUTES=<positive count>` changes only the route count; `RUN=<Go test regex>`
selects scenarios (default `^TestLoad`). For example:

```console
TNL_TEST_POSTGRES_URL='postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable' \
  mise exec -- task go:test-load ROUTES=32 RUN='^TestLoadSteadyState$'
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

For example, with the disposable PostgreSQL URL configured:

```console
mise exec -- task go:test-load ROUTES=1000 DURATION=10m RUN='^TestLoadCadence$'
mise exec -- task go:test-load ROUTES=10000 HISTORY=100 DURATION=10m RUN='^TestLoadCadence$'
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

For isolated query-plan investigation, select `RUN='^TestProfile'` with
`DELAY=0ms` and the same disposable PostgreSQL prerequisite. These opt-in tests
log the actual generated queries' `EXPLAIN (ANALYZE, BUFFERS, SETTINGS)` plans:
placement counts at up to 1,000, 2,500, and `ROUTES` sessions, and routing reads
with 4, 10, and 100 events per live route. For example, `ROUTES=10000
RUN='^TestProfileRoutingHistory$'` profiles 40,000 through one million events.
History is bulk-copied from genuine ready-route projections; setup is untimed,
and three serial snapshots/plans per size measure read amplification without
concurrent writers. These profiles do not measure sustained heartbeat cadence,
history ingestion throughput, or mixed-workload recovery.

### JavaScript Package

`pnpm test` and `pnpm typecheck` build through lifecycle hooks. Their `:ci`
variants and direct Vitest runs do not. Build once before focused tests:

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
