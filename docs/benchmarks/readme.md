# benchmarks

Local runtime load and deployed benchmarks share `internal/benchworkload` for
publishers, local service responses, visitors, scheduling, TLS verification,
and measurements. See [local workloads](local-workloads.md) for the Docker
topology and fault workloads. A deployed benchmark exercises one explicitly
selected tnl server from this machine, like a developer publishing a local
service and visiting its public URL.

## deployed workload

Log in to the selected server once, then preview a small workload without
changing the server. For example, against staging:

```console
mise exec -- go run ./cmd/tnl login --server=https://control.tnl.wtf
BENCH_SERVER=https://control.tnl.wtf mise exec -- task go:bench:plan
```

The benchmark requires an existing login for the selected control URL. It uses a
run-specific member namespace, creates ephemeral public URLs, and removes
them when the publisher stops. It does not create Fly apps, databases, Route 53
zones, or a separate certificate service. The selected server uses its normal
publicly trusted certificate issuer. Successful runs and failures write
`bench-results/run-*/result.json` with the selected workload, direct local
TLS baseline, verified visitor measurements, generator measurements,
and public URL cleanup status. An interrupted process can leave ephemeral
public URLs until their publish runs expire; inspect the run's URLs before
removing only those benchmark-owned URLs.

Execution requires separate approval for the exact control URL and workload,
with an explicit `BENCH_SERVER`, `BENCH_SUITE`, and `BENCH_APPROVED=1`.
The Task targets do not load an old `.env.bench`; pass the selected values on
each invocation.
For example, after approving a staging smoke run:

```console
BENCH_SERVER=https://control.tnl.wtf BENCH_SUITE=smoke BENCH_APPROVED=1 mise exec -- task go:bench:run
mise exec -- task go:bench:report BENCH_RUN=bench-results/run-<run-id>
```

The default smoke publishes four public URLs and verifies both publisher
transports, four held streams, and 16 fresh visitor requests per second for 10
seconds. `BENCH_PUBLIC_URLS`, `BENCH_FRESH_CONNECTIONS_PER_SECOND`,
`BENCH_HELD_STREAMS`, `BENCH_CONCURRENCY`, `BENCH_QUEUE_SLOTS`,
`BENCH_PAYLOAD_BYTES`, `BENCH_WARMUP`, `BENCH_DURATION`, and
`BENCH_REPETITIONS` select the workload. `BENCH_TRANSPORT` defaults to `mixed`;
`quic` and `tcp` isolate one publisher transport, while `mixed` alternates
forced QUIC and TLS/TCP public URLs. `auto` uses the normal publisher connection
race and records when TLS/TCP is selected for any connection; it does not move
existing visitor streams if QUIC later stalls. Larger workloads or a transport
other than `mixed` require `BENCH_SUITE=target` and separate approval. Results
include public URL IDs, transports, and per-URL visitor counts so server logs
can be correlated with failures. Record the location and network conditions
of the local machine alongside results. The direct loopback baseline tests
generator headroom, while the selected server measurement includes the public
network and local publisher path. Large capacity and fault sweeps remain
explicit opt-in local Docker workloads, described in
[local workloads](local-workloads.md).

`BENCH_VISITOR_NETWORK=tcp4` limits public visitor connections to IPv4.
`BENCH_VISITOR_INTERFACE` optionally binds only those visitor sockets to the
IPv4 address of a named local interface. The publisher connections and direct
loopback baseline retain their normal paths. Selecting a different network or
interface changes the approved workload.
