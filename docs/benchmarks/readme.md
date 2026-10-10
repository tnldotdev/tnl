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
mise exec -- go run ./cmd/tnl auth login --server=https://control.tnl.wtf
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
seconds. `BENCH_MODE=fresh-held` selects this mix; `fresh`, `held`, `bandwidth`,
and `combined` select separate capacity workloads with `BENCH_SUITE=target`.
Set `BENCH_FRESH_CONNECTIONS_PER_SECOND=0` for held or bandwidth mode, and
`BENCH_HELD_STREAMS=0` for fresh or bandwidth mode. Combined mode requires both
to be positive and also requires bandwidth settings. The workload has a matched
direct local TLS baseline before the server windows; held streams must continue
delivering bytes throughout the window. Warmup sends the selected workload
rather than waiting idle.

`BENCH_BANDWIDTH_DIRECTION` selects `downstream`, `upstream`, or
`bidirectional`; `BENCH_BANDWIDTH_MBITS_PER_SECOND` is decimal Mbit/s **per
direction** and `BENCH_BANDWIDTH_STREAMS` counts streams per direction. For a
read-only plan of one downstream step:

```console
BENCH_SERVER=https://control.tnl.wtf BENCH_SUITE=target BENCH_MODE=bandwidth \
  BENCH_FRESH_CONNECTIONS_PER_SECOND=0 BENCH_HELD_STREAMS=0 \
  BENCH_BANDWIDTH_DIRECTION=downstream BENCH_BANDWIDTH_MBITS_PER_SECOND=100 \
  BENCH_BANDWIDTH_STREAMS=64 BENCH_PAYLOAD_BYTES=4096 \
  BENCH_WARMUP=2m BENCH_DURATION=5m \
  mise exec -- task go:bench:plan
```

Bandwidth setup verifies one TLS connection per stream before timing starts.
Each stream sends one paced transfer for a measurement window of up to one hour,
so repeated request setup cannot consume the transfer's one-second completion
allowance. Results record connection setup time separately from delivered bytes
and measured elapsed time. A warmup that verifies every byte but finishes late
is recorded and the server measurement continues; missing bytes, transfer errors,
and late measurement windows still fail. The JSON result includes each stream's
public URL and first and last verified byte times, plus aggregate verified
upload and download bytes per second. Public URL details identify each
publisher's transport. Fresh visitor requests still use new connections.

`BENCH_PUBLIC_URLS`, `BENCH_START_PARALLEL`, `BENCH_FRESH_CONNECTIONS_PER_SECOND`,
`BENCH_HELD_STREAMS`, `BENCH_CONCURRENCY`, `BENCH_QUEUE_SLOTS`,
`BENCH_PAYLOAD_BYTES`, `BENCH_WARMUP`, `BENCH_DURATION`, and
`BENCH_REPETITIONS` select the workload. `BENCH_TRANSPORT` defaults to `mixed`;
`quic` and `tcp` isolate one publisher transport, while `mixed` alternates
forced QUIC and TLS/TCP public URLs. `auto` uses the normal publisher connection
race and records when TLS/TCP is selected for a publisher connection. After an
established QUIC connection fails, its replacement assignment tries TLS/TCP
first; existing visitor streams do not move or replay. Larger workloads or a
transport other than `mixed` require `BENCH_SUITE=target` and separate
approval. Results include public URL IDs, transports, and per-URL visitor
counts so server logs can be correlated with failures. Bandwidth results record
offered and delivered bytes, achieved rates, per-public-URL timing, and completion
time. Warmup
bandwidth failures retain up to eight transfer errors in `result.json`; the
report shows the first error so a setup failure can be distinguished from a
measured limit. Held-stream results record how many continued delivering bytes.
`BENCH_START_PARALLEL`
bounds concurrent publisher activation and shutdown (four by default).
Activation failures retain any ready public URLs and a bounded set of publisher
events and connection errors; the result counts omitted observations. Record the location
and network conditions of the local machine alongside results. The direct
loopback baseline tests generator headroom, while the selected server
measurement includes the public network and local publisher path. Large
capacity and fault sweeps remain explicit opt-in local Docker workloads,
described in [local workloads](local-workloads.md).

For a staging capacity campaign, use the [capacity testing plan](capacity-plan.md):
keep the other dimensions steady, measure the direct baseline and staging path,
then raise only the selected dimension. Stop at the first failed or saturated
step, test between the last pass and first failure, and repeat the best passing
step. Use [process metrics](../maintainers/metrics.md) to distinguish admission
limits and resource saturation from generator or network limits. The local direct
baseline does not include the public network. Plan each bounded step before
execution and obtain approval for its exact server and workload; changing a
workload setting needs new approval.

`BENCH_VISITOR_NETWORK=tcp4` limits public visitor connections to IPv4.
`BENCH_VISITOR_INTERFACE` optionally binds only those visitor sockets to the
IPv4 address of a named local interface. The publisher connections and direct
loopback baseline retain their normal paths. Selecting a different network or
interface changes the approved workload.

`BENCH_QUIC_DISABLE_PATH_MTU_DISCOVERY=true` is a publisher-side diagnostic
override for comparing QUIC behavior on a constrained UDP path. It does not
change the ordinary `tnl` publisher transport policy; include it in the exact
approved workload when using it.

`BENCH_QUIC_QLOG=true` saves publisher QUIC packet and timer traces in the
run-specific `quic/` result directory. Use it only for a small diagnostic run;
the normal visitor aggregates remain in `result.json`.
`BENCH_QUIC_KEEPALIVE=5s` optionally changes the publisher's keepalive period
for an otherwise matched diagnostic run; it does not change ordinary `tnl`.
