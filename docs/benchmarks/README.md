# Fly Route-Path Benchmark

`tnlbench` provisions an isolated, production-shaped tnl server on Fly and
measures the complete route path: ingress, internal forwarding to a connected
relay, the publisher, and its local service. It does not use or modify a
production tnl deployment.

The fixed server topology is:

- Two control processes sharing one transient Fly Managed Postgres cluster.
- Two ingress processes behind one public ingress address.
- Fly PROXY v2 metadata preserving each visitor source address at ingress.
- Two relay services, each with two relay processes behind one relay address.
- Automatic control, relay transport, and route certificate issuance.
- A transient server-domain Route 53 zone and a nested managed deployment
  domain zone.

Publisher and load workers are added for each cell. The profile keeps every
load worker below 40 fresh visitor connections per second so the ingress source
limiter does not become the measured boundary.

## Plan

Planning is read-only. It does not call Fly, Route 53, Managed Postgres, or ACME.
Always inspect the topology, worker counts, duration, and estimated spend before
approving execution.

```console
BENCH_SUITE=smoke mise exec -- task go:bench-fly:plan
BENCH_SUITE=scout mise exec -- task go:bench-fly:plan
BENCH_SUITE=confirm \
  BENCH_ROUTES=500 \
  BENCH_FRESH_CONNECTIONS_PER_SECOND=30 \
  BENCH_HELD_STREAMS=1000 \
  mise exec -- task go:bench-fly:plan
```

Set `BENCH_PLAN_FORMAT=json` for machine-readable output. Pricing is a dated
estimate. The maximum includes one full month of the configured Managed
Postgres plan and storage plus two Route 53 hosted-zone charges in case cleanup
fails. Resources retained longer than one month can exceed that estimate. The
estimate also excludes DNS queries, image builds, public egress, and failed
retries.

The suites are:

- `smoke`: one small cell that validates provisioning and the full data path.
- `scout`: increasing route, fresh-connection, and held-stream targets for
  locating a saturation boundary.
- `confirm`: three repetitions of one explicitly supplied target.

## Prerequisites

Execution requires:

- `flyctl` authenticated to the organization selected by `BENCH_FLY_ORG`. Set
  `BENCH_FLY_BINARY` if it is not on `PATH`.
- Fly Managed Postgres access in the profile's region. The production profile
  uses the Basic plan with PostgreSQL 17 and 10 GB of storage in `sjc`.
- AWS credentials in the standard environment variables with permission to
  create and delete Route 53 hosted zones and update the parent zone.
- An existing public Route 53 parent zone and its bare hosted-zone ID.
- An email address accepted for the configured public ACME directory.

The benchmark tasks load `.env.bench` automatically. Create the ignored local
file with owner-only permissions, then fill in the benchmark settings and AWS
credentials:

```console
install -m 0600 .env.bench.example .env.bench
```

The runner copies the active AWS credentials into encrypted Fly secrets on the
control app because control manages benchmark DNS and certificates. It never
writes generated credentials or AWS credentials to the run manifest. Keep
`.env.bench` at mode `0600`, use dedicated least-privilege credentials, and do
not add `BENCH_APPROVED` to the file.

After filling in the file, validate the Fly identity, organization, Managed
Postgres list access, AWS credentials, parent hosted zone, domain, and ACME
email without creating any resources:

```console
mise exec -- task go:bench-fly:preflight
```

## Execute

Execution creates paid Fly and AWS resources. A plan is not approval. Set both
`BENCH_SUITE` and `BENCH_APPROVED=1` on the execution command after reviewing
that exact suite's plan.

```console
BENCH_APPROVED=1 mise exec -- task go:bench-fly:run
```

The runner creates `bench-results/<run-id>/` before provisioning and records
each resource in `manifest.json` as soon as it is created. It first provisions
Managed Postgres, builds one benchmark-only image containing `tnld` and
`tnlbench`, migrates with the direct database URL, runs control with the pooled
URL, starts the server topology, executes cells sequentially, writes result
rows, generates reports, and removes all recorded resources.

Managed Postgres credentials remain only in runner memory and encrypted Fly
secrets. The manifest records the cluster ID, generated name, region, plan,
PostgreSQL major version, storage size, and cleanup progress, but never a
connection URL or password.

The run directory contains:

- `manifest.json`: non-secret resource identities and cleanup progress.
- `plan.json`: the exact expanded plan used by the run.
- `results.jsonl`: one schema-version-5 row per publisher or load worker.
- `report.json` and `report.md`: merged cell and capacity summaries.

The manifest remains after successful cleanup as an audit record. A successful
run ends with manifest status `cleaned`.

## Recover

The runner attempts cleanup with a separate timeout after an error or interrupt.
If the process is killed, the network is unavailable, or cleanup reports an
error, rerun cleanup from the repository root with the same Fly and AWS access:

```console
BENCH_RUN=bench-results/<run-id> mise exec -- task go:bench-fly:cleanup
```

Cleanup is resumable. It acts only on exact app names, the exact generated
Managed Postgres identity, and hosted-zone identities recorded for the run. It
verifies the live Managed Postgres organization, name, region, plan, and storage
and the live Route 53 zone names before mutation. If creation was interrupted
before the cluster ID was saved, cleanup recovers it by the exact generated
name. Control Machines are removed before the database. Do not hand-edit a
manifest to target unrelated resources.

To regenerate reports from collected rows without provisioning anything:

```console
BENCH_RUN=bench-results/<run-id> mise exec -- task go:bench-fly:report
```

## Interpret Results

Each worker records activation or visitor phases, correctness failures, fixed
latency histograms, exact route cleanup, and process metrics sampled before and
during load. Reports merge histogram buckets rather than averaging worker
percentiles.

The report identifies the highest passing target, highest target that passed
every repetition, and first observed saturation. Those labels describe this
benchmark profile and run only; they are not an availability SLO or general
production capacity guarantee. Relay loss may reset existing visitor streams,
so recovery is measured by whether new visitor connections resume through the
other ready publisher connection.
