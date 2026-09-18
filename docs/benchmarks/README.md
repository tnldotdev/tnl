# Fly Route-Path Benchmark

`tnlbench` provisions an isolated, production-shaped tnl server on Fly and
measures the complete route path: ingress, internal forwarding to a connected
relay, the publisher, and its local service. It does not use or modify a
production tnl deployment.

The production profile uses:

- Two control processes sharing one transient Fly Managed Postgres cluster.
- Two ingress processes behind one public ingress address.
- Fly PROXY v2 metadata preserving each visitor source address at ingress.
- Two relay services, each with two relay processes behind one relay address.
- Automatic control, relay transport, and route certificate issuance. A
  benchmark-local authoritative resolver avoids stale recursive DNS during
  validation and load; capacity suites use private Pebble ACME, while the small
  compatibility suite uses Let's Encrypt.
- A transient server-domain Route 53 zone and a nested managed deployment
  domain zone.

Publisher generators share the built-in authority's permanent administrator
identity and personal team. The runner assigns routes in stable 250-route bands
and starts only the generators needed by a cell. Four encrypted 1 GiB Fly
volumes retain publisher state and reusable route certificates between cells.
The profile keeps every load worker below 40 fresh visitor connections per
second so the ingress source limiter does not become the measured boundary.

## Plan

Planning is read-only. It does not call Fly, Route 53, or ACME. Always inspect
the topology, worker counts, duration, and estimated spend before approving
execution.

```console
BENCH_SUITE=smoke mise exec -- task go:bench-fly:plan
BENCH_SUITE=scout mise exec -- task go:bench-fly:plan
BENCH_SUITE=confirm \
  BENCH_ROUTES=500 \
  BENCH_FRESH_CONNECTIONS_PER_SECOND=30 \
  BENCH_HELD_STREAMS=1000 \
  BENCH_LIFECYCLE_CHURN_PER_SECOND=5 \
  BENCH_PAYLOAD_BYTES=262144 \
  mise exec -- task go:bench-fly:plan
```

Set `BENCH_PLAN_FORMAT=json` for machine-readable output. Pricing is a dated
estimate. The maximum includes one full month of the configured Managed
Postgres cluster and publisher volumes plus two Route 53 hosted-zone charges in
case cleanup fails. Resources retained longer than one month can exceed that
estimate. The estimate excludes backups, DNS queries, image builds, public
egress, and failed retries.

The suites are:

- `smoke`: one small cell that validates provisioning and the full data path.
- `scout`: independent active-route, route-session lifecycle-churn,
  fresh-connection, held-stream, and bandwidth ramps.
- `confirm`: three repetitions of one explicitly supplied target.
- `compatibility`: one minimal cell against Let's Encrypt for public-CA
  compatibility, not capacity discovery.

## Prerequisites

Execution requires:

- `flyctl` authenticated to the organization selected by `BENCH_FLY_ORG`, with
  access to Fly Managed Postgres in the profile region. Set
  `BENCH_FLY_BINARY` if it is not on `PATH`.
- AWS credentials in the standard environment variables with permission to
  create and delete Route 53 hosted zones and update the parent zone.
- An existing public Route 53 parent zone and its bare hosted-zone ID.
- An ACME account email. Capacity suites use it with private Pebble, while the
  compatibility suite submits it to Let's Encrypt.

The benchmark tasks load `.env.bench` automatically. Create the ignored local
file with owner-only permissions, then fill in the benchmark settings and AWS
credentials:

```console
install -m 0600 .env.bench.example .env.bench
```

The runner copies the active AWS credentials into encrypted Fly secrets on the
control app because control manages benchmark DNS and certificates. It creates
a built-in login token for publisher authentication and never writes generated
credentials or AWS credentials to the run manifest. Keep `.env.bench` at mode
`0600`, use dedicated least-privilege credentials, and do not add
`BENCH_APPROVED` to the file.

Validate Fly access, Managed Postgres access, AWS credentials, the parent
hosted zone, domain, and ACME email without creating resources:

```console
mise exec -- task go:bench-fly:preflight
```

## Execute

Execution creates paid Fly and AWS resources. A plan is not approval. Set both
`BENCH_SUITE` and `BENCH_APPROVED=1` on the execution command after reviewing
that exact suite's plan. Review and approve again if the suite, overrides,
resources, or estimated cost ceiling changes.

```console
BENCH_APPROVED=1 mise exec -- task go:bench-fly:run
```

The runner creates `bench-results/<run-id>/` before provisioning and records
each resource in `manifest.json` as soon as creation starts. It provisions Fly
Managed Postgres, builds one benchmark-only image, migrates with the direct
database URL, and serves through the pooled database URL. It waits for every
Route 53 authoritative name server to publish each delegated zone and server
address, starts and probes every process, executes cells sequentially, writes
results and reports, then removes all recorded resources. The first control
process establishes the public control endpoint before the other control
process starts, avoiding concurrent initial certificate issuance.

A workload saturation result does not stop later cells, so every scout ramp can
establish its own observed boundary. Provisioning, instrumentation, and cleanup
errors stop the campaign and trigger cleanup.

For `smoke`, `scout`, and `confirm`, the runner starts a private Pebble Machine
without a public Fly port. Pebble performs normal DNS-01 and TLS-ALPN-01
validation. Pebble and load workers use a loopback resolver that sends benchmark
lookups directly to the Route 53 authoritative name servers and waits for
records to appear. This avoids stale recursive caches without bypassing DNS or
challenge checks. The runner combines the static Pebble API root with Pebble's
dynamic issuance root, installs that bundle only in benchmark Machines, and uses
it for host-side readiness checks without modifying the operator trust store.
`compatibility` omits Pebble and uses Let's Encrypt, so keep that suite small to
avoid public CA rate limits.

Each publisher exchanges the same built-in login token, resolves the same
personal member namespace, and uses its own persistent client-state volume.
Routes remain enabled between cells while route sessions stop, allowing later
cells to reuse route state and certificates. Lifecycle churn uses deterministic
prewarmed routes instead of creating identities or certificates during the
measured phase. Each active route has an independent churn route so generator
concurrency does not impose the measured lifecycle-rate boundary.

Managed Postgres credentials remain only in runner memory and encrypted Fly
secrets. The manifest records the generated cluster identity and configuration,
publisher volume IDs, and cleanup progress, but never a connection URL or
password.

The run directory contains:

- `manifest.json`: non-secret resource identities and cleanup progress.
- `plan.json`: the exact expanded plan used by the run.
- `results.jsonl`: one schema-version-6 row per publisher or load worker.
- `report.json` and `report.md`: schema-version-3 capacity, recovery,
  bottleneck-evidence, monthly-cost, and capacity-per-dollar summaries.
- `diagnostics/<role>.txt`: redacted Fly Machine status and logs when a server
  or workload worker fails to start.

The manifest remains after successful cleanup as an audit record. A successful
run ends with manifest status `cleaned`.

## Recover

The runner attempts cleanup with a separate timeout after an error or interrupt.
If the process is killed, the network is unavailable, or cleanup reports an
error, rerun cleanup from the repository root with the same Fly and AWS access:

```console
BENCH_RUN=bench-results/<run-id> mise exec -- task go:bench-fly:cleanup
```

Cleanup is resumable. It acts only on exact app names, publisher volume IDs,
the generated Managed Postgres cluster, and hosted-zone identities recorded for
the run. It verifies live ownership before mutation and polls until Fly confirms
the database is absent. Control Machines are removed before the database. Do
not hand-edit a manifest to target unrelated resources.

To regenerate reports from collected rows without provisioning anything:

```console
BENCH_RUN=bench-results/<run-id> mise exec -- task go:bench-fly:report
```

## Interpret Results

Each worker records activation, deactivation, lifecycle-churn, or visitor
phases, correctness failures, fixed latency histograms, retained route counts,
and process metrics sampled before, every five seconds during, and after load.
Fresh-connection and lifecycle-churn cells pass only when they complete without
operation errors and sustain at least 95 percent of the assigned target rate.
Lifecycle-churn routes are created and brought to readiness before load, so the
measured phase covers route-session start/stop work rather than first-use route
or certificate setup. Stored routes are removed with transient Managed Postgres
after the campaign. Reports merge histogram buckets rather than averaging
worker percentiles.

After a load worker observes visitor errors or misses its target rate, it first
releases held streams and then sends one low-rate visitor probe at a time for up
to 30 seconds. The report records how many saturated workers recovered and the
slowest observed time until a successful response. This measures post-load
service recovery; it is not a relay-failure or existing-stream survival test.

The report identifies the last passing target, last target that passed every
repetition, and first failing target independently for each axis. It records
direct capacity-rejection counter changes and peak sampled process CPU as
bottleneck evidence, and reports axis capacity divided by estimated monthly
topology cost. These boundaries describe this benchmark profile and run only;
they are not an availability SLO or general production capacity guarantee.
