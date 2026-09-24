# local capacity checkpoints

This log records useful local capacity evidence while keeping it separate from
production sizing. The [capacity testing plan](capacity-plan.md) defines the
longer, repeated, highly available, and degraded-state work required before tnl
can publish safe operating limits.

## 2026-09-23 bandwidth

The separated local topology sustained 800 Mbit/sec upstream and 800 Mbit/sec
downstream simultaneously through one active relay path. The direct path achieved
799.078 Mbit/sec in each direction and the tunneled path achieved 798.686
Mbit/sec in each direction. Each path transferred exactly 3,000,000,000 bytes in
each direction with zero transfer failures.

This is a demonstrated local passing point, not a capacity limit. The highest
step still had CPU and memory headroom, so the experiment did not find a
throughput knee or first limiting resource.

### profile

- Four active route sessions and four low-rate fresh requests per second.
- No held streams during the bandwidth phases.
- Thirty-second measurement windows with 64 streams per active direction.
- One control process, one ingress process, and two relay processes belonging to
  separate relay services.
- One-CPU quotas and 256 MiB memory limits for ingress and each relay.
- Four visitor containers and a separately constrained local service.
- Docker Desktop VM exposing 14 CPUs and 8,318,976,000 bytes of memory.

Ingress selected `relay-a` for the measured visitor traffic. `relay-b` retained
publisher connections but remained effectively idle. The result therefore
describes one active relay path, not aggregate two-relay throughput.

### rates

Rates are achieved decimal Mbit/sec per active direction. Bidirectional rows
carried the displayed rate upstream and downstream simultaneously.

| Target | Direction     |  Direct | Tunneled | Bytes per active direction |
| -----: | ------------- | ------: | -------: | -------------------------: |
|    100 | Downstream    |  99.930 |   99.830 |                375,000,000 |
|    100 | Upstream      |  99.880 |   99.900 |                375,000,000 |
|    100 | Bidirectional |  99.864 |   99.810 |                375,000,000 |
|    200 | Downstream    | 199.799 |  199.691 |                750,000,000 |
|    200 | Upstream      | 199.802 |  199.829 |                750,000,000 |
|    200 | Bidirectional | 199.680 |  199.602 |                750,000,000 |
|    400 | Downstream    | 399.448 |  399.432 |              1,500,000,000 |
|    400 | Upstream      | 399.552 |  399.608 |              1,500,000,000 |
|    400 | Bidirectional | 399.439 |  399.151 |              1,500,000,000 |
|    800 | Bidirectional | 799.078 |  798.686 |              3,000,000,000 |

Every row transferred exactly its expected application bytes with zero failures.
The 800 Mbit/sec summaries completed in 30.035 seconds direct and 30.049 seconds
tunneled.

### server resources

Mean CPU values below cover each bidirectional tunneled phase. Resource intervals
include coordination and collection overhead and record their actual elapsed
time.

| Target per direction | Ingress mean cores | Active relay mean cores |
| -------------------: | -----------------: | ----------------------: |
|         100 Mbit/sec |             0.3160 |                  0.3700 |
|         200 Mbit/sec |             0.3877 |                  0.4690 |
|         400 Mbit/sec |             0.4421 |                  0.5329 |
|         800 Mbit/sec |             0.4567 |                  0.6263 |

At 800 Mbit/sec per direction, ingress used about 34.3 MiB current and
36.6 MiB peak charged memory. The active relay used about 43.2 MiB current and
45.4 MiB peak. Neither component throttled or recorded memory-pressure or OOM
events. The direct phase met the same offered rate with the same visitor and
origin containers, demonstrating generator headroom at the tested point.

### provenance and evidence

The runs used base commit `f446e681bf5e70f9170b082aea9518681cddf532` plus
the uncommitted precursor to `162af12`. That commit landed the direct-path and
bandwidth harness and added an explicit one-second completion grace. Every
retained run completed within that final budget.

Raw summaries, cgroup snapshots, production metrics, admission settings, and
container-exit evidence remain local under these ignored paths:

- `bench-results/capacity-local-{downstream,upstream,bidirectional}-{100,200,400}/`
- `bench-results/capacity-local-bidirectional-800/`
- `bench-results/capacity-local-bandwidth-20260923/findings.md`

One preliminary 200 Mbit/sec attempt is excluded. It used `BENCH_DURATION` and
`BENCH_ARTIFACT_DIR`, which are not inputs to the local Task target, so the target
selected its default duration and result path. The retained trials use the
documented `DURATION` and `RESULTS` Task variables.

### qualifications

- Each point is one 30-second trial rather than a five-minute measurement or a
  repeated boundary result.
- The highest point passed with headroom and does not identify a bandwidth limit.
- The topology had one ingress process and one active relay path; it was not the
  smallest highly available deployment from the capacity testing plan.
- No bandwidth phase ran with a relay, ingress process, control process, or
  PostgreSQL boundary unavailable.
- These measurements do not establish production hardware sizing, network cost,
  WAN behavior, endurance, or a safe operating limit.

### next workload

Open visitor streams are the next isolated dimension. The harness must first
retain opening duration, requested/opened/surviving counts, progress after
opening, and before/after resources. The local staircase can then increase held
streams while fresh traffic and byte rate stay low. Fresh visitor connections
and route sessions follow; combined and degraded tests wait until all four
dimensions have repeated passing points.
