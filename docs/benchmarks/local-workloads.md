# local workloads

Start with [routine checks](../../contributing.md#check-your-change). Local
load workloads are opt-in. Run them from the repo root with `mise exec --`.
They do not create deployed infrastructure.

## database load

Docker must be running. Task creates, waits for, and removes a disposable
PostgreSQL container. The default run has 1,000 public URLs:

```console
mise exec -- task go:test:load:database
```

Use `PUBLIC_URLS` to change the count and `RUN` to select a test. For a small
steady-state run:

```console
mise exec -- task go:test:load:database PUBLIC_URLS=32 RUN='^TestLoadSteadyState$'
```

The tests cover placement, routing reads, relay recovery, and bounded
shutdown. `HISTORY` seeds routing events per public URL for steady-state and
recovery runs; it defaults to one. `DELAY=5ms` or `20ms` adds a synthetic delay
after successful SQL commands. It models sensitivity to round trips, not
measured network latency.

Longer cadence, retention, and query-plan investigations are separate runs:

```console
mise exec -- task go:test:load:database PUBLIC_URLS=1000 DURATION=10m RUN='^TestLoadCadence$'
mise exec -- task go:test:load:database PUBLIC_URLS=1000 DURATION=10m RETENTION=1m RUN='^TestLoadCadence$'
mise exec -- task go:test:load:database RUN='^TestProfile' DELAY=0ms
```

`DURATION` opts in to the paced cadence test (2m–10m); `RETENTION` adds
routing-history cleanup to that run. Database tests do not send real visitor
traffic or make ACME network calls. See the test cases in
`internal/control/state` for their exact checks.

## runtime load

This Task target uses Testcontainers for Go to run a disposable Docker Compose
topology: separate control, ingress, and relay processes with real publishers
and visitors, Pebble, and PostgreSQL. Go drives faults and captures container
exit evidence; the workload and measurements run in the Go test binary. The
default is a four-public-URL smoke with both QUIC and TLS/TCP:

```console
mise exec -- task go:test:load:runtime RESULTS=bench-results/runtime-smoke
```

Use a fresh `RESULTS` directory for each run. `PUBLIC_URLS`, `RPS`, and
`DURATION` set the main workload; `WORKERS` and `QUEUE` bound visitor work.
`HELD_STREAMS` adds concurrent held visitor streams. To compare the same local
service with and without tnl, use `DIRECT_PATH=1`:

```console
mise exec -- task go:test:load:runtime PUBLIC_URLS=64 START_PARALLEL=64 RPS=160 DURATION=30s DIRECT_PATH=1 RESULTS=bench-results/runtime-reference
```

To investigate a fault, select one `SCENARIO` at a time. Available cases
include `relay-kill`, `control-restart`, `forwarding-blackhole`,
`publisher-blackhole`, `udp-fallback`, `latency`, and `packet-loss`. For example:

```console
mise exec -- task go:test:load:runtime SCENARIO=relay-kill RPS=160 RESULTS=bench-results/runtime-kill
```

Capacity-only runs can measure held streams or paced bandwidth alongside a
direct baseline. Keep generator resources separate from server-role limits:

```console
mise exec -- task go:test:load:runtime CAPACITY_ONLY=1 DIRECT_PATH=1 HELD_STREAMS=400 DURATION=30s RESULTS=bench-results/runtime-streams
mise exec -- task go:test:load:runtime CAPACITY_ONLY=1 DIRECT_PATH=1 BANDWIDTH_DIRECTION=bidirectional BANDWIDTH_MBITS_PER_SECOND=100 RESULTS=bench-results/runtime-bandwidth
```

Bandwidth workers establish one visitor TLS connection each before their
measurement window and send one paced transfer for windows up to one hour.
Results record `setup_duration` separately from measured transfer time. Fresh
visitor requests still use a new connection for every request.

Record applied admission limits from `admission-limits.json`, and compare
direct and tunneled results from the same run. The result directory keeps
visitor summaries, resource measurements, raw metrics, and component-exit
evidence. A local Docker profile is not a production capacity limit. See the
[local capacity results](local-capacity.md) for measured comparisons and the
[capacity plan](capacity-plan.md) for how to qualify a limit.

## native connector load

Measure the `tnl connect` path with the same disposable separated topology:

```console
mise exec -- task go:test:load:connect RESULTS=bench-results/connect-smoke
mise exec -- task go:test:load:connect SCENARIO=latency NETWORK_PATH=publisher RTT=50ms RESULTS=bench-results/connect-publisher-latency
mise exec -- task go:test:load:connect SCENARIO=latency NETWORK_PATH=connector RTT=50ms RESULTS=bench-results/connect-connector-latency
```

The default starts four private TCP services, each with two publisher connections,
and four built `tnl connect` processes, each with two authenticated ingress paths.
Publisher services alternate forced QUIC and TLS/TCP; connectors use the normal
transport race. The test uses production device enrollment, run selection, stream
authorization, and verified service TLS. Sign-in is seeded locally; no browser
approval or deployed server is involved.

Each of four ten-second windows offers four verified echo requests/second with a
256-byte payload: direct fresh TCP, fresh TCP through the connector, direct reused
TCP, and reused TCP through the connector. The direct path reaches the same target
without tnl or TLS, so it is a lower bound rather than an equivalent encrypted path.
The fresh connector measurement includes remote setup after the loopback socket
opens. Its `connect` timing measures only that loopback dial. Reused sockets are
opened and verified before their measurement window; failed sockets are never
silently replaced. This measures opaque TCP, not PostgreSQL/MySQL login or browser
HTTP behavior.

Use a fresh `RESULTS` directory. `SERVICES=4..64`, `RPS=4..256`,
`WORKERS=4..64`, `QUEUE=0..4096`, `DURATION=10s..1m`, and
`PAYLOAD_BYTES=8..1048576` bound the workload. Each phase gets the selected
duration. Connector visitors default to 512 MiB per container, including the CLI
children and their race instrumentation. Larger service counts may need higher `VISITOR_MEMORY`, since each
visitor container owns several real CLI processes. The smoke rate leaves headroom
for per-connection authorization on the one-CPU PostgreSQL profile; increase `RPS`
explicitly when measuring its saturation point. The runtime resource overrides
also apply to this target.

`SCENARIO=latency` supports `RTT=20ms`, `50ms`, or `100ms`.
`NETWORK_PATH=connector` delays connector-to-ingress traffic, `forwarding` delays
ingress-to-relay traffic, and `publisher` delays relay-to-publisher traffic.
`SCENARIO=packet-loss LOSS=0.1` or `1` uses the same paths. Impairments apply before
startup and remain active through all traffic windows; qdisc/filter evidence records
both directions. Direct traffic and control API traffic are outside those filters.

Results include `connect-startup.json`, per-phase `*-setup.json`, raw request
samples, publisher-transport cohorts, process resources, server metrics, and
`connect-cleanup.json`. `*-latency.json` reports exact mean/p50/p95/p99 from request
start separately from scheduled-slot latency, so generator delay remains visible.
Failures, missed offers, queue expiry, resource rejection, and retained connector
assignments fail the run. CI runs the race-enabled smoke and adds latency runs to
the scheduled workload; timings are measurements, not machine-dependent pass limits.
