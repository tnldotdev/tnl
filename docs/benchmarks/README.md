# Benchmarks

Local runtime workloads and Fly use `internal/benchworkload` for publishers,
visitors, origin responses, scheduling, duration histograms, and authenticated
coordination. Runners own deployment, fault injection, resource collection, and
infrastructure cleanup. The [assertion inventory](assertions.md) records the checks
retained from the retired aggregate workload.

## Local workloads

See [Contributing](../../CONTRIBUTING.md#runtime-load) for the canonical
`go:test:load:runtime` task, resource limits, and smoke/reference/fault commands.
Routine tests need no external infrastructure. Focused integration tests validate
individual boundaries; larger load and fault runs are explicit opt-ins.

The smoke defaults to four routes, 16 fresh HTTPS requests/sec, 128 concurrent
request workers, eight waiting slots, both publisher transports, and a 32KiB
response. The reference uses 64 routes and 160 requests/sec with the same worker
and queue budgets. Historical eight-worker results describe a different generator.

## Fly plan and execution

Fly runs **one explicit target** per deployment. Repetitions are measurement
windows using the same running publishers and cached certificates. Setup,
measurement, publisher shutdown, and infrastructure cleanup are reported
separately. A cold-start measurement uses a new invocation.

`benchmarks/fly.json` contains infrastructure only: region, replicated server
topology, machine sizes, Managed PostgreSQL, and generator limits. Both `plan` and
`run` use the same workload options. There is no automatic scouting, inferred
capacity ranking, pricing, or capacity-per-dollar calculation.

```console
mise exec -- task go:bench-fly:plan
mise exec -- env BENCH_SUITE=target BENCH_ROUTES=64 BENCH_FRESH_CONNECTIONS_PER_SECOND=160 BENCH_DURATION=30s BENCH_REPETITIONS=3 task go:bench-fly:plan
```

The plan is read-only. It prints the target, resource counts and sizes, generator
budgets, and execution bounds. Review that plan before approving execution.

Execution requires explicit `BENCH_SUITE` and `BENCH_APPROVED=1`, plus:

- Fly CLI access to `BENCH_FLY_ORG` and Managed PostgreSQL in the selected region.
- AWS credentials with Route 53 access.
- `BENCH_PARENT_DOMAIN` and bare `BENCH_PARENT_ZONE_ID` for an existing public zone.
- `BENCH_ACME_EMAIL` for certificate issuance.

Task loads local infrastructure settings from `.env.bench`. Credentials are passed
through platform secrets and excluded from the ownership manifest. Access checks
run inside `run` before resources are created.

After explicit approval of the smoke plan:

```console
mise exec -- env BENCH_SUITE=smoke BENCH_APPROVED=1 task go:bench-fly:run
```

To check public certificate issuance, plan a smoke with
`BENCH_CERTIFICATE_AUTHORITY=letsencrypt` and obtain approval for that plan. Other
runs use private Pebble with real DNS validation. Public-CA checks remain small.

## Workload options

| Setting                              | Default | Meaning                                                    |
| ------------------------------------ | ------: | ---------------------------------------------------------- |
| `BENCH_SUITE`                        |   smoke | `smoke` or `target`; execution requires explicit selection |
| `BENCH_ROUTES`                       |       4 | Published routes                                           |
| `BENCH_FRESH_CONNECTIONS_PER_SECOND` |      16 | Total offered fresh requests/sec                           |
| `BENCH_HELD_STREAMS`                 |       4 | Held visitor streams                                       |
| `BENCH_CONCURRENCY`                  |     128 | Total fresh-request concurrency                            |
| `BENCH_QUEUE_SLOTS`                  |       8 | Total waiting slots, independently distributed             |
| `BENCH_PAYLOAD_BYTES`                |   32768 | Verified response payload                                  |
| `BENCH_WARMUP`                       |      5s | Setup settling time                                        |
| `BENCH_DURATION`                     |     10s | Fixed offering window                                      |
| `BENCH_REPETITIONS`                  |       1 | Measurement windows in the same deployment                 |
| `BENCH_CERTIFICATE_AUTHORITY`        |  pebble | `pebble` or small `letsencrypt` smoke                      |

Fly distributes visitors before reaching the per-source connection limit. The
infrastructure profile permits 30 fresh requests/sec per generator; 160/sec needs
six visitor Machines, with the 128 concurrent workers and eight waiting slots
distributed across them. The request budget is five seconds including queue delay.
Held-stream opening has its own five-second deadline, separate from stream lifetime.

The coordinator owns phase barriers and waits for every participant before
measuring. Publishers stay alive across windows and abort the run on unexpected
exit. Client state is private run-local storage; no publisher Fly volumes are
created. Each publisher process embeds the shared origin handler, so its resource
observations include the origin.

## Results

Artifacts are written beneath `bench-results/<run-id>/`:

- `plan.json`: exact infrastructure and target.
- `manifest.json`: owned resources, progress, and cleanup outcome.
- `results.jsonl`: participant results, shared visitor measurements, and metrics.
- `report.json` and `report.md`: merged window summaries and per-process metrics.
- `diagnostics/`: bounded, redacted snapshots on failure.

Scheduled, started, completed, successful, failed, timed-out, missed, and
queue-expired requests are distinct. Queue delay, DNS, connect, TLS, first body
byte, and total duration are measured. Histograms merge bucket counts, never
worker percentiles. Offering and drain durations remain separate. Normal windows
require zero failures, missed offers, and expired queued requests.

Local fault artifacts additionally retain request timestamps, fault boundaries,
drop counters, cgroup CPU/throttling/memory/network observations, raw `.prom`
scrapes, usage reconciliation, and container exit evidence. Blackhole disruptions
are reported even when subsequent recovery and final verification pass.

Result and configuration formats are replaced directly; old campaign results
remain historical artifacts rather than inputs to this reporter.

## Cleanup and reporting

The runner records ownership durably and cleans up after success or failure.
Interrupted cleanup is resumable and verifies exact resource ownership before
mutation. Control must be removed before deleting its PostgreSQL cluster.

```console
mise exec -- env BENCH_RUN=bench-results/<run-id> task go:bench-fly:cleanup
mise exec -- env BENCH_RUN=bench-results/<run-id> task go:bench-fly:report
```

Cleanup failures remain failures and retain resource identities in the manifest.
