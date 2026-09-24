# local capacity checkpoints

This log records useful local capacity evidence while keeping it separate from
production sizing. The [capacity testing plan](capacity-plan.md) defines the
longer, repeated, highly available, and degraded-state work required before tnl
can publish safe operating limits.

## 2026-09-23 bandwidth

| Result                  | Observation                                                                                               |
| ----------------------- | --------------------------------------------------------------------------------------------------------- |
| Strongest passing point | 800 Mbit/sec upstream and downstream simultaneously through one active relay path                         |
| Direct path             | 799.078 Mbit/sec per direction                                                                            |
| Tunneled path           | 798.686 Mbit/sec per direction                                                                            |
| Exact transfer          | 3,000,000,000 bytes in each direction on each path                                                        |
| Correctness             | Zero transfer failures, incomplete payloads, or byte mismatches                                           |
| Limiting resource       | None found; the highest step retained CPU and memory headroom                                             |
| Interpretation          | Demonstrated local passing point, not a capacity limit, throughput knee, or production operating envelope |

### profile

| Dimension               | Value                                                                                   |
| ----------------------- | --------------------------------------------------------------------------------------- |
| Active route sessions   | 4                                                                                       |
| Background fresh rate   | 4 requests/sec                                                                          |
| Held streams            | 0 during bandwidth phases                                                               |
| Measurement window      | 30 seconds                                                                              |
| Bandwidth streams       | 64 per active direction                                                                 |
| Server topology         | 1 control process, 1 ingress process, 2 relay processes in separate relay services      |
| Active visitor path     | Ingress through `relay-a`; `relay-b` retained publisher connections but was mostly idle |
| Ingress resources       | 1 CPU, 256 MiB memory                                                                   |
| Per-relay resources     | 1 CPU, 256 MiB memory                                                                   |
| Traffic generators      | 4 visitor containers and a separately constrained local service                         |
| Docker Desktop VM       | 14 CPUs, 8,318,976,000 bytes of memory                                                  |
| Topology interpretation | One active relay path, not aggregate two-relay or highly available throughput           |

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

| Completion check at 800 Mbit/sec |  Direct | Tunneled |
| -------------------------------- | ------: | -------: |
| Elapsed                          | 30.035s |  30.049s |
| Bytes per direction              |    3 GB |     3 GB |
| Failures                         |       0 |        0 |

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

| 800 Mbit/sec component | CPU quota | Mean cores | Current memory | Peak memory | Throttling | Memory pressure / OOM |
| ---------------------- | --------: | ---------: | -------------: | ----------: | ---------- | --------------------- |
| Ingress                |         1 |     0.4567 |       34.3 MiB |    36.6 MiB | None       | None                  |
| Active relay           |         1 |     0.6263 |       43.2 MiB |    45.4 MiB | None       | None                  |

| Generator check | Observation                                                                                        |
| --------------- | -------------------------------------------------------------------------------------------------- |
| Direct baseline | The same visitor and origin containers met the 800 Mbit/sec-per-direction target without failures. |

### provenance and evidence

| Item                  | Value                                                                                                                                                                                        |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Base source           | `f446e681bf5e70f9170b082aea9518681cddf532`                                                                                                                                                   |
| Workload source       | Uncommitted precursor to `162af12`                                                                                                                                                           |
| Landed harness        | `162af12`; added the direct path, bandwidth workload, and explicit one-second completion grace                                                                                               |
| Completion budget     | Every retained run completed within the final harness budget                                                                                                                                 |
| 100-400 evidence      | `bench-results/capacity-local-{downstream,upstream,bidirectional}-{100,200,400}/`                                                                                                            |
| 800 evidence          | `bench-results/capacity-local-bidirectional-800/`                                                                                                                                            |
| Detailed local report | `bench-results/capacity-local-bandwidth-20260923/findings.md`                                                                                                                                |
| Retained artifacts    | Exact summaries, cgroup snapshots, production metrics, admission settings, and container-exit evidence                                                                                       |
| Excluded trial        | One preliminary 200 Mbit/sec attempt used `BENCH_DURATION` and `BENCH_ARTIFACT_DIR`, which are not local Task inputs; retained trials use the documented `DURATION` and `RESULTS` variables. |

### qualifications

| Area                 | Qualification                                                                                        |
| -------------------- | ---------------------------------------------------------------------------------------------------- |
| Duration             | One 30-second trial per point, not a five-minute measurement                                         |
| Repetition           | No repeated boundary result                                                                          |
| Bandwidth boundary   | Highest point passed with headroom; no limit was identified                                          |
| Topology             | One ingress process and one active relay path, not the smallest highly available deployment          |
| Degraded operation   | No bandwidth phase ran with a relay, ingress, control, or PostgreSQL boundary unavailable            |
| Production relevance | Does not establish hardware sizing, network cost, WAN behavior, endurance, or a safe operating limit |

### next workload

| Order | Dimension                 | Next action                                                                                                          |
| ----: | ------------------------- | -------------------------------------------------------------------------------------------------------------------- |
|     1 | Open visitor streams      | Retain opening duration, requested/opened/surviving counts, byte progress, and before/after resources; run staircase |
|     2 | Fresh visitor connections | Search with held streams and bandwidth disabled                                                                      |
|     3 | Active route sessions     | Revisit the existing local route boundary on the landed harness                                                      |
|     4 | Combined and degraded     | Wait until all four isolated dimensions have repeated passing points                                                 |
