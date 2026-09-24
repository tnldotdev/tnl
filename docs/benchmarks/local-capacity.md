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

## 2026-09-24 local 1 cpu / 2 gib server-role screens

Control, ingress, and each relay had a one-CPU quota and a 2 GiB cgroup limit.
The separated local topology had one ingress process and two relay services,
but traffic used mostly `relay-a`. Docker Desktop had 14 CPUs and 8,318,976,000
bytes of memory. All points below are local screens, not repeatable operating
limits for a highly available deployment. Each run retained its own direct
baseline, admission settings, component resources, metrics, and exit evidence.
Generator and PostgreSQL overrides varied by dimension and are listed below.

| Dimension                                       | Observed point                                                                    | Result                                                                                                                    | Boundary or qualification                                                                                                                                |
| ----------------------------------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Open visitor streams                            | 4,000 with default 4,096 relay-stream and 500-per-route publisher request limits  | 10-second steady screen passed                                                                                            | Configured relay-stream limit is near this point.                                                                                                        |
| Open visitor streams                            | 6,400 with relay-stream limit 8,192 and default 500 publisher requests per route  | 10-second steady screen passed                                                                                            | No resource boundary established.                                                                                                                        |
| Open visitor streams                            | 6,400 with relay-stream limit 16,384 and per-route ingress/publisher limits 1,000 | Three full runs passed two-minute direct/tunneled warmups, five-minute direct/tunneled measurements, and final accounting | All 6,400 streams survived and progressed in each run; this is a repeated local passing point.                                                           |
| Open visitor streams                            | 8,000 with relay-stream limit 16,384 and per-route ingress/publisher limits 1,000 | 10-second screen passed; five-minute tunneled steady phase had 8,000 surviving and progressing streams                    | The long run failed the final 10-second zero-active-state cleanup check; it is **not** a complete passing run.                                           |
| Open visitor streams                            | 9,600 with the same raised limits                                                 | Failed during tunneled opening/steady traffic                                                                             | The direct baseline passed; tunneled opening took up to 2m09s and only 485 streams survived to the first steady result.                                  |
| Fresh visitor connections                       | 400, 800, 1,600, 2,000 per second                                                 | Each 30-second direct and tunneled screen passed with zero failed, timed-out, or missed offers                            | At 2,000 the active relay was close to its one-CPU quota; no failed traffic point was found.                                                             |
| Active route sessions                           | 1,000, 2,000, 3,000, 4,000                                                        | 30-second direct and tunneled screens and final accounting passed at each point                                           | At 4,000 both relay processes held 4,000 ready publisher connections, exactly their configured per-process limit; no server-role memory limit was found. |
| Bandwidth, simultaneous upstream and downstream | 1,600, 2,000, 2,200 Mbit/sec **per direction**                                    | Exact bytes passed in 30-second direct and tunneled screens; 2,200 passed three times                                     | 2,200 is the highest repeated short-window local point, not a long-duration operating limit.                                                             |
| Bandwidth, simultaneous upstream and downstream | 2,400 Mbit/sec **per direction**                                                  | Passed once; failed on repeat                                                                                             | Tunneled transfers finished in 30.963s and 31.012s against a 31-second budget, while the direct path passed both times.                                  |
| Bandwidth, simultaneous upstream and downstream | 2,600 Mbit/sec **per direction**                                                  | Direct path passed; tunneled path failed the completion budget                                                            | Exact 9.75 GB in each direction took 34.193s through the tunnel, past the 31-second budget. The active relay was CPU-throttled.                          |

### stream profile and resource boundary

| Item                                                      | Observation                                                                                                                                                                                                                                                                                                    |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Workload                                                  | 16 routes, four visitor sources, 4 fresh requests/sec, 32 KiB forwarding buffers, direct TLS baseline; short screens used 10-second windows.                                                                                                                                                                   |
| Longer 8,000-stream run                                   | Two-minute warmup and five-minute measurement on each direct and tunneled path; all 8,000 tunneled streams survived and received more bytes over the measurement.                                                                                                                                              |
| Longer 6,400-stream runs                                  | Three identical full runs: the same direct/tunneled windows, 1,200/1,200 successful tunneled fresh requests per measurement, 6,400/6,400 surviving and progressing streams, clean close and final usage reconciliation each time.                                                                              |
| Active relay during five-minute 6,400-stream steady phase | Sampled maxima 1,098-1,103 MB; 0.862-0.874 mean CPU cores, negligible throttling. Final memory was within 3.3 MB of the last-minute mean in all three runs.                                                                                                                                                    |
| Ingress during the same 6,400-stream phase                | Sampled maxima 689-703 MB; 0.969-0.981 mean CPU cores, negligible throttling.                                                                                                                                                                                                                                  |
| Active relay during five-minute 8,000-stream steady phase | Sampled maximum 1,378 MB; 0.989 mean CPU cores and 49 seconds of quota throttling.                                                                                                                                                                                                                             |
| Ingress during the same phase                             | Sampled maximum 872 MB; 0.998 mean CPU cores and 357 seconds of quota throttling.                                                                                                                                                                                                                              |
| Resource correctness                                      | No cgroup memory-limit events or OOM kills in the long 8,000-stream measurement. CPU, not the 2 GiB process memory limit, was saturated in this traffic pattern.                                                                                                                                               |
| Configured limits                                         | At 8,000 streams with the publisher's default 500 concurrent requests per route, held streams progressed but fresh requests received HTTP 503. Raising that explicit request limit to 1,000 eliminated those 503s in the short screen. This is a configured publisher limit, not a measured server-role limit. |
| Generators                                                | Stream screens used 512 MiB to 1 GiB per visitor, 512 MiB to 1 GiB for the local service, and 2 to 3 GiB for publishers; these are separate from the 1 CPU / 2 GiB server-role profile.                                                                                                                        |

### fresh traffic, routes, and bandwidth details

| Workload                     | Direct result                                | Tunneled result                                               | Resource or method detail                                                                                                                                                                                                                                |
| ---------------------------- | -------------------------------------------- | ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2,000 fresh connections/sec  | 60,000/60,000 successful in 30s, p95 2.444ms | 60,000/60,000 successful in 30s, p95 8.967ms                  | Ingress 0.895 mean cores; active relay 0.963, with 2.65s of quota throttling. Source rate/burst were explicitly raised to 1,000/4,000 per source; visitor workers and queue were 512 each.                                                               |
| 1,000 active route sessions  | 120/120 successful in 30s                    | 120/120 successful in 30s, plus 1,000/1,000 live-route probes | Activation verified in 32.794s with 1,000 certificate orders. PostgreSQL had 2 CPUs / 2 GiB, publisher generator 2 CPUs / 3 GiB, and source rate/burst 500/2,000.                                                                                        |
| 4,000 active route sessions  | 120/120 successful in 30s                    | 120/120 successful in 30s, plus 4,000/4,000 live-route probes | Activation verified in 2m16.019s with 4,000 certificate orders (four 1,000-publisher waves). Control used 0.837 mean CPU cores during activation; PostgreSQL had 4 CPUs / 2 GiB and its activation CPU throttled. Both relays remained well below 2 GiB. |
| 1,600 Mbit/sec bidirectional | 6 GB per direction in 30.044s                | 6 GB per direction in 30.057s                                 | Active relay 0.964 mean cores, 1.09s quota throttling.                                                                                                                                                                                                   |
| 2,000 Mbit/sec bidirectional | 7.5 GB per direction in 30.032s              | 7.5 GB per direction in 30.060s                               | Active relay 0.968 mean cores, 19.98s quota throttling.                                                                                                                                                                                                  |
| 2,200 Mbit/sec bidirectional | 8.25 GB per direction in 30.032-30.039s      | 8.25 GB per direction in 30.066-30.092s                       | Three clean identical 30-second runs; active relay used about 0.968 mean cores and accumulated 24-26s quota throttling in each run.                                                                                                                      |
| 2,400 Mbit/sec bidirectional | 9 GB per direction in 30.042s both times     | 9 GB per direction in 30.963s / 31.012s                       | Active relay about 0.954 mean cores with over 33s quota throttling; the second run failed the completion budget by 0.012s.                                                                                                                               |
| 2,600 Mbit/sec bidirectional | 9.75 GB per direction in 30.037s             | 9.75 GB per direction in 34.193s                              | Active relay 0.929 mean cores over the longer interval, 34.37s quota throttling. This fails the exact-byte completion budget despite zero byte mismatches.                                                                                               |

Bandwidth runs used four routes, 64 streams per direction, no held streams,
4 background fresh requests/sec, and separately constrained local-service,
publisher, and visitor generators (4, 4, and 2 CPUs respectively). The
original 800 Mbit/sec measurement above used the earlier 256 MiB ingress/relay
profile; do not merge its resource numbers with these runs. The initial
1,600-requests/sec fresh trial OOM-killed only the 128 MiB test coordinator
while collecting direct-path results. Its rerun with a separately expanded
512 MiB coordinator passed; the server-role resources did not change.

| Evidence                                  | Ignored local artifact directory                                                                                                                                |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Stream screens and longer phases          | `bench-results/capacity-profile-1cpu-2g-streams-{4000-screen,6400-screen,6400-full-1,6400-full-2,6400-full-3,8000-tuned-screen,9600-tuned-screen,8000-full-1}/` |
| Fresh connection screens                  | `bench-results/capacity-profile-1cpu-2g-fresh-{400-screen,800-screen,1600-coordinator512,2000-screen}/`                                                         |
| Route session screens                     | `bench-results/capacity-profile-1cpu-2g-routes-{1000-screen,2000-screen,3000-screen,4000-screen}/`                                                              |
| Bandwidth screens and first late transfer | `bench-results/capacity-profile-1cpu-2g-bandwidth-{1600-bidi,2000-bidi,2200-bidi-1,2200-bidi-2,2200-bidi-3,2400-bidi,2400-bidi-repeat-2,2600-bidi}/`            |

### remaining validation

| Dimension         | Required before reporting a repeatable local point                                                                                                                                       |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Streams           | The 6,400-stream point passed three full runs with leveling memory. The higher 8,000-stream trial saturated ingress/relay CPU and failed cleanup; do not infer a safe operating limit.   |
| Fresh connections | Repeat the strongest clean point and measure for five minutes; the existing runtime fresh-window limit is two minutes.                                                                   |
| Route sessions    | Repeat the 4,000-route point, then raise its configured 4,000-publisher-connections-per-relay ceiling explicitly before testing higher counts. Verify PostgreSQL and generator headroom. |
| Bandwidth         | 2,200 Mbit/sec per direction passed three 30-second trials; 2,400 missed its deadline on repeat. Run longer direct/tunneled transfers before using either as an operating point.         |
| Combined/degraded | Only after the isolated boundaries are repeated; this local topology does not establish production limits.                                                                               |
