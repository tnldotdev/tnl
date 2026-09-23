# benchmarks

Local and deployed benchmarks use `internal/benchworkload` for publishers,
visitors, origin responses, scheduling, measurements, and coordination. Each
runner owns setup, fault injection, resource collection, and cleanup.

The [assertion inventory](assertions.md) lists the behavior each workload checks.

## local workloads

See [Contributing](../../contributing.md#runtime-load) for the canonical
`go:test:load:runtime` task and its smoke, reference, and fault workloads.

Routine tests need no external infrastructure. Large load and fault tests are
explicit opt-in runs.

The smoke workload uses four routes, 16 fresh visitor connections per second,
128 request workers, eight waiting slots, eight held streams, both publisher
transports, and a 32KiB response. Optional local capacity phases use the same
visitor and origin code for a direct TLS baseline and paced upstream, downstream,
or bidirectional transfers. The reference workload uses 64 routes and 160 fresh
visitor connections per second with the same worker and queue limits.

## deployed workloads

A deployed run measures one explicit workload. Repetitions reuse the same running
publishers and cached certificates. Setup, measurement, publisher shutdown, and
infrastructure cleanup are reported separately.

An infrastructure profile defines the region, server topology, process sizes,
PostgreSQL configuration, and generator limits. Planning and execution use the
same workload settings.

Planning is read-only. Execution creates billable infrastructure and DNS records,
so it requires an explicit suite and approval with `BENCH_SUITE` and
`BENCH_APPROVED=1`.

Credentials are passed through the deployment platform and are not written to
the ownership manifest. Access checks run before resources are created.

Public certificate checks must use a small smoke workload. Other runs use a
private certificate authority with real DNS validation.

## workload settings

| Setting                              | Default | Meaning                                                    |
| ------------------------------------ | ------: | ---------------------------------------------------------- |
| `BENCH_SUITE`                        |   smoke | `smoke` or `target`; execution requires explicit selection |
| `BENCH_ROUTES`                       |       4 | Active route sessions                                      |
| `BENCH_FRESH_CONNECTIONS_PER_SECOND` |      16 | Total offered fresh visitor connections per second         |
| `BENCH_HELD_STREAMS`                 |       4 | Held visitor streams                                       |
| `BENCH_CONCURRENCY`                  |     128 | Total fresh visitor request workers                        |
| `BENCH_QUEUE_SLOTS`                  |       8 | Total waiting slots                                        |
| `BENCH_PAYLOAD_BYTES`                |   32768 | Verified response payload                                  |
| `BENCH_WARMUP`                       |      5s | Setup settling time                                        |
| `BENCH_DURATION`                     |     10s | Fixed offer window                                         |
| `BENCH_REPETITIONS`                  |       1 | Measurement windows in one deployment                      |
| `BENCH_CERTIFICATE_AUTHORITY`        |  pebble | `pebble` or a small public-certificate smoke               |

The runner uses enough visitor generators to keep each source below the source
connection limit. The five-second request budget includes queue delay. Opening a
held stream has its own five-second deadline.

The coordinator waits for every participant before starting a phase. Publishers
stay alive across measurement windows and fail the run if they exit early. Each
publisher process includes its origin handler, so publisher resource measurements
also include the origin.

## results

Artifacts are written under `bench-results/<run-id>/`:

- `plan.json` records the infrastructure and workload.
- `manifest.json` records owned resources, progress, and cleanup.
- `results.jsonl` records participant results and measurements.
- `report.json` and `report.md` contain merged summaries.
- `diagnostics/` contains bounded and redacted failure data.

The results keep scheduled, started, completed, successful, failed, timed-out,
missed, and queue-expired visitor work separate. They also keep queue, DNS,
connect, TLS, first-body-byte, and total durations separate. Normal measurement
windows require zero failures, missed offers, and expired queued work.

Local fault results also record request timestamps, fault boundaries, dropped
work, process resources, raw metrics, usage reconciliation, and process exits.

## cleanup

The runner records resource ownership before creating infrastructure. It cleans up
after both successful and failed runs. Interrupted cleanup can resume and checks
ownership before deleting anything.

Cleanup failures fail the benchmark and leave the resource identities in the
manifest for a later cleanup attempt.
