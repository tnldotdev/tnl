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

The tests cover placement, routing reads, usage, relay recovery, and bounded
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
`internal/controlstate` for their exact checks.

## runtime load

This Task target uses Docker Compose to run separate control, ingress, and
relay processes with real publishers and visitors, Pebble, and PostgreSQL. The
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
