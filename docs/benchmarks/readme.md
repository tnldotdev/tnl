# benchmarks

Local runtime load and staging benchmarks share `internal/benchworkload` for
publishers, local service responses, visitors, scheduling, TLS verification,
and measurements. See [local workloads](local-workloads.md) for the Docker
topology and fault workloads. Staging benchmarks exercise the real, persistent
staging tnl server from this machine, like a developer publishing a local
service and visiting its public URL.

## staging workload

Log in to staging once, then preview a small workload without touching staging:

```console
mise exec -- tnl login --server=https://control.tnl.wtf
mise exec -- task go:bench:plan
```

The benchmark requires an existing staging control session. It uses a
run-specific member namespace, creates ephemeral public URLs, and removes
them when the publisher stops. It does not create Fly apps, databases, Route 53
zones, or a separate certificate service. The staging control service uses its
normal publicly trusted certificate issuer. Successful runs and failures write
`bench-results/staging-*/result.json` with the selected workload, direct local
TLS baseline, verified staging visitor measurements, generator measurements,
and public URL cleanup status. An interrupted process can leave ephemeral
public URLs until their publish runs expire; inspect the run's URLs before
removing only those benchmark-owned URLs.

Execution requires a separately approved workload, with an explicit suite and
`BENCH_APPROVED=1`. For example, after approving a smoke run:

```console
BENCH_SUITE=smoke BENCH_APPROVED=1 mise exec -- task go:bench:run
mise exec -- task go:bench:report BENCH_RUN=bench-results/staging-<run-id>
```

The default smoke publishes four public URLs and verifies both publisher
transports, four held streams, and 16 fresh visitor requests per second for 10
seconds. `BENCH_PUBLIC_URLS`, `BENCH_FRESH_CONNECTIONS_PER_SECOND`,
`BENCH_HELD_STREAMS`, `BENCH_CONCURRENCY`, `BENCH_QUEUE_SLOTS`,
`BENCH_PAYLOAD_BYTES`, `BENCH_WARMUP`, `BENCH_DURATION`, and
`BENCH_REPETITIONS` select the workload; larger values require
`BENCH_SUITE=target`. Record the location and network conditions of the local
machine alongside results. The direct loopback baseline tests generator
headroom, while the staging measurement includes the public network and
local publisher path. Large capacity and fault sweeps remain explicit opt-in
local Docker workloads, described in [local workloads](local-workloads.md).
