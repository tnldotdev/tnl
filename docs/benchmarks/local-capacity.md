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
| Fresh visitor connections                       | 2,000 per second over five-minute phases                                          | Two complete runs passed direct, steady tunneled, and partial-shutdown tunneled traffic; 600,000 successes per phase      | The active relay was CPU-throttled in both runs; this is a repeated local passing point, not an operating limit.                                         |
| Active route sessions                           | 1,000, 2,000, 3,000, 4,000                                                        | 30-second direct and tunneled screens and final accounting passed at each point                                           | At 4,000 both relay processes held 4,000 ready publisher connections, exactly their configured per-process limit; no server-role memory limit was found. |
| Active route sessions                           | 5,000 and 6,000 with relay connection capacity raised to 8,000                    | 5,000 passed once; 6,000 passed twice with the production 30-second ingress drain profile                                 | The five-second fixture had failed final usage flush at 5,500 and 6,000. With production drain timing, all 6,000 routes and usage reconciled.            |
| Active route sessions                           | 7,000 and 8,000 with separate publisher/Pebble headroom                           | 7,000 passed once; 8,000 passed twice with live-route probes and final accounting                                         | At 8,000 each relay reached its then-configured 8,000 publisher connections and the former harness cap; no server-role memory limit was found.           |
| Active route sessions                           | 9,000 and 10,000 with relay capacity raised to 10,000                             | 9,000 passed once; 10,000 completed five times, with one additional run failing publisher readiness                       | The 10,000-route runs reached the new harness and configured relay-connection ceilings; the intermittent activation failure is unresolved.               |
| Bandwidth, simultaneous upstream and downstream | 1,600, 2,000, 2,200 Mbit/sec **per direction**                                    | Exact bytes passed in 30-second direct and tunneled screens; 2,200 passed three times                                     | 2,200 is the highest repeated short-window local point, not a long-duration operating limit.                                                             |
| Bandwidth, simultaneous upstream and downstream | 2,200 Mbit/sec **per direction**, five minutes                                    | Two complete runs passed direct/tunneled exact bytes and final accounting                                                 | The active relay ran near its CPU quota and was heavily throttled in both runs; this is a repeated local passing point, not an operating limit.          |
| Bandwidth, simultaneous upstream and downstream | 2,400 Mbit/sec **per direction**                                                  | Passed once; failed on repeat                                                                                             | Tunneled transfers finished in 30.963s and 31.012s against a 31-second budget, while the direct path passed both times.                                  |
| Bandwidth, simultaneous upstream and downstream | 2,400 Mbit/sec **per direction**, five minutes                                    | Direct path passed; tunneled path failed the completion budget                                                            | All 90 GB per direction arrived without mismatches, but tunneled completion took 319.313s against the 301s deadline. The active relay was CPU-throttled. |
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

| Workload                                   | Direct result                                         | Tunneled result                                                                                         | Resource or method detail                                                                                                                                                                                                                                                                                                                      |
| ------------------------------------------ | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2,000 fresh connections/sec                | 60,000/60,000 successful in 30s, p95 2.444ms          | 60,000/60,000 successful in 30s, p95 8.967ms                                                            | Ingress 0.895 mean cores; active relay 0.963, with 2.65s of quota throttling. Source rate/burst were explicitly raised to 1,000/4,000 per source; visitor workers and queue were 512 each.                                                                                                                                                     |
| 2,000 fresh connections/sec, five minutes  | 600,000/600,000 successful per run, p95 2.441-2.442ms | 600,000/600,000 successful in both steady and partial-shutdown phases per run; steady p95 9.829-9.921ms | Two complete identical runs, with zero failed, timed-out, missed, or queue-expired requests and exact final usage accounting. Ingress used 0.920-0.922 mean cores during steady traffic; the active relay used 0.991-0.992 and accumulated 32.27-33.49s of quota throttling. The separate coordinator had 2 CPUs / 3 GiB for request evidence. |
| 1,000 active route sessions                | 120/120 successful in 30s                             | 120/120 successful in 30s, plus 1,000/1,000 live-route probes                                           | Activation verified in 32.794s with 1,000 certificate orders. PostgreSQL had 2 CPUs / 2 GiB, publisher generator 2 CPUs / 3 GiB, and source rate/burst 500/2,000.                                                                                                                                                                              |
| 4,000 active route sessions                | 120/120 successful in 30s                             | 120/120 successful in 30s, plus 4,000/4,000 live-route probes                                           | Activation verified in 2m16.019s with 4,000 certificate orders (four 1,000-publisher waves). Control used 0.837 mean CPU cores during activation; PostgreSQL had 4 CPUs / 2 GiB and its activation CPU throttled. Both relays remained well below 2 GiB.                                                                                       |
| 6,000 active route sessions                | 120/120 successful in 30s in each repeat              | 120/120 successful in 30s and 6,000/6,000 live-route probes per repeat                                  | Two clean runs: activation verified in 3m24s-3m26s with 6,000 certificate orders; final usage and zero active sessions/connections reconciled. PostgreSQL had 6 CPUs / 2 GiB; the generator publisher had 2 CPUs / 4 GiB. Both relays stayed below 570 MB during steady traffic.                                                               |
| 7,000 active route sessions                | 120/120 successful in 30s                             | 120/120 successful in 30s and 7,000/7,000 live-route probes                                             | One complete run: activation verified in 3m52.686s with 7,000 certificate orders; final usage and zero active sessions/connections reconciled. Both relays stayed below 640 MB in steady traffic. Publisher readiness used 2m and Pebble had 512 MiB, independently of the server-role profile.                                                |
| 8,000 active route sessions                | 120/120 successful in 30s per repeat                  | 120/120 successful in 30s and 8,000/8,000 live-route probes per repeat                                  | Two complete runs: activation verified in 4m44.683s-4m54.981s with 8,000 certificate orders each, followed by exact accounting and clean shutdown. Both relays stayed below 756 MB, while each held exactly 8,000 ready publisher connections, matching its configured capacity.                                                               |
| 9,000 active route sessions                | 120/120 successful in 30s                             | 120/120 successful in 30s and 9,000/9,000 live-route probes                                             | One complete run: activation verified in 5m56.739s with 9,000 certificate orders, exact final usage and zero active sessions/connections. Both relays stayed below 813 MB; the publisher generator peaked at 3.27 GB against its separate 4 GiB limit.                                                                                         |
| 10,000 active route sessions               | 120/120 successful in 30s per complete run            | 120/120 successful in 30s and 10,000/10,000 live-route probes per complete run                          | Five complete runs: activation verified in 6m57.455s-7m18.382s, 10,000 certificate orders each, clean shutdown and exact accounting. One intervening run stopped during activation when a publisher exceeded a 2m readiness deadline. Both relays stayed below 900 MB in the complete runs; publisher generator peaked at 3.63 GB.             |
| 1,600 Mbit/sec bidirectional               | 6 GB per direction in 30.044s                         | 6 GB per direction in 30.057s                                                                           | Active relay 0.964 mean cores, 1.09s quota throttling.                                                                                                                                                                                                                                                                                         |
| 2,000 Mbit/sec bidirectional               | 7.5 GB per direction in 30.032s                       | 7.5 GB per direction in 30.060s                                                                         | Active relay 0.968 mean cores, 19.98s quota throttling.                                                                                                                                                                                                                                                                                        |
| 2,200 Mbit/sec bidirectional               | 8.25 GB per direction in 30.032-30.039s               | 8.25 GB per direction in 30.066-30.092s                                                                 | Three clean identical 30-second runs; active relay used about 0.968 mean cores and accumulated 24-26s quota throttling in each run.                                                                                                                                                                                                            |
| 2,200 Mbit/sec bidirectional, five minutes | 82.5 GB per direction in 300.066-300.071s             | 82.5 GB per direction in 300.601-300.624s                                                               | Two complete identical runs with zero transfer failures or byte mismatches. The active relay used 0.996 mean cores and accumulated 252.78-254.35s quota throttling; ingress used 0.831-0.849 mean cores. Separate origin/publisher generators had 4 CPUs each and each visitor had 2 CPUs.                                                     |
| 2,400 Mbit/sec bidirectional               | 9 GB per direction in 30.042s both times              | 9 GB per direction in 30.963s / 31.012s                                                                 | Active relay about 0.954 mean cores with over 33s quota throttling; the second run failed the completion budget by 0.012s.                                                                                                                                                                                                                     |
| 2,400 Mbit/sec bidirectional, five minutes | 90 GB per direction in 300.022s                       | 90 GB per direction in 319.313s                                                                         | Exact bytes and final usage reconciled, but the tunneled phase missed the 301s completion budget by 18.313s. The active relay accumulated 334.58s of quota throttling; the direct path and generators had headroom.                                                                                                                            |
| 2,600 Mbit/sec bidirectional               | 9.75 GB per direction in 30.037s                      | 9.75 GB per direction in 34.193s                                                                        | Active relay 0.929 mean cores over the longer interval, 34.37s quota throttling. This fails the exact-byte completion budget despite zero byte mismatches.                                                                                                                                                                                     |

Bandwidth runs used four routes, 64 streams per direction, no held streams,
4 background fresh requests/sec, and separately constrained local-service,
publisher, and visitor generators (4, 4, and 2 CPUs respectively). The
original 800 Mbit/sec measurement above used the earlier 256 MiB ingress/relay
profile; do not merge its resource numbers with these runs. The initial
1,600-requests/sec fresh trial OOM-killed only the 128 MiB test coordinator
while collecting direct-path results. Its rerun with a separately expanded
512 MiB coordinator passed; the server-role resources did not change.
The first five-minute 2,000/sec attempt completed direct offers but could not
submit per-request events through the coordinator's 16 MiB request limit; it
is not a passing run. The passing repeats write each visitor's request rows to
JSONL in the ignored results directory and reads them back for the same
assertions. This fixture boundary does not measure a server-role limit. The
five-minute bandwidth run used `BANDWIDTH_MEASURE=5m` and `DURATION=30s`, so
the long direct/tunneled transfers did not extend the fresh phases. Both
passing 2,200 Mbit/sec runs reconciled exact final usage and cleanly shut down.
The 2,400 Mbit/sec five-minute run also reconciled usage and shut down but
failed the tunneled completion deadline, not byte integrity.

### high-route finalization boundary

| Route sessions | Test ingress drain / final-routing wait | Result                                                                                                                            |
| -------------: | --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
|          5,000 | 5s / 10s                                | Complete short run passed with the original fixture.                                                                              |
|          5,500 | 5s / 10s                                | Visitor phases and publisher shutdown passed; ingress's final usage report to control exceeded its request context.               |
|          6,000 | 5s / 10s                                | Same final usage-report failure.                                                                                                  |
|          6,000 | 30s / 10s                               | Final routing acknowledgment exceeded the test's fixed 10-second wait, before the usage flush could be checked.                   |
|          6,000 | 30s / 30s                               | Two complete runs passed, including final ingress usage completion and exact accounting; one measured ingress shutdown at 2.816s. |

The separated fixture's old five-second ingress drain included both visitor
draining and every page of final usage reporting, whereas the production
`tnld` default is 30 seconds. Capacity-only runs now exercise that production
deadline and allow the final ingress routing revision the same bounded wait.
The production usage reporter, its 16-report transaction pages, and the
shorter fault-test profile were not changed. These local observations establish
that 6,000 completes under the production drain profile; they do not establish
a safe route-session operating limit.

The initial 7,000-route trial stopped when a publisher exceeded the fixture's
30-second readiness deadline; its second attempt lost Pebble while the test
CA was still limited to 128 MiB. The passing higher-route screens used 512 MiB
for Pebble, PostgreSQL at 6 CPUs / 2 GiB, publishers at 2 CPUs / 4 GiB, and a
two-minute per-publisher readiness deadline unless noted. These generator and
fixture changes do not alter the control, ingress, or per-relay 1 CPU / 2 GiB
profile. The 8,000-route screens reached the former harness cap and 8,000
publisher connections per relay; subsequent 9,000/10,000-route runs explicitly
raised those ceilings to 10,000.

At 10,000 routes, the first complete run passed with `READY_TIMEOUT=2m`;
the identical next run exceeded that deadline for publisher 5,793 while
certificate work was still active and never reached visitor traffic. Two
further complete runs passed with `READY_TIMEOUT=5m` and two later 2m
diagnostic runs passed; the slowest individual publisher in these passing
runs took about 1m03s-1m06s. They do not establish whether the earlier
straggler would have recovered within five minutes. This is **five complete
passes and one incomplete activation run**, not an unqualified repeatable
operating limit. Ten thousand is the current harness cap and configured
publisher-connection capacity per relay, not an observed server resource
limit. The route screens offered just 4 fresh requests/sec plus correctness
probes and ran for 30 seconds per traffic phase; route endurance and combined
traffic at this count remain untested.

Failure-time diagnostics now capture a single publisher's non-secret route,
certificate-order/authorization, connected-relay, and ingress revision state
before group cancellation. A deliberately short 30s-readiness run verified
the artifact: its selected route had an installed certificate and two ready
publisher connections, but its route session was still `starting`. That
forced deadline is not a reproduction or explanation of the earlier 2m stall.

| Evidence                               | Ignored local artifact directory                                                                                                                                                                                                                                                                                                                                                                                                               |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Stream screens and longer phases       | `bench-results/capacity-profile-1cpu-2g-streams-{4000-screen,6400-screen,6400-full-1,6400-full-2,6400-full-3,8000-tuned-screen,9600-tuned-screen,8000-full-1}/`                                                                                                                                                                                                                                                                                |
| Fresh connection screens and long runs | `bench-results/capacity-profile-1cpu-2g-fresh-{400-screen,800-screen,1600-coordinator512,2000-screen,2000-long-1,2000-long-2,2000-long-3}/`                                                                                                                                                                                                                                                                                                    |
| Route session screens                  | `bench-results/capacity-profile-1cpu-2g-routes-{1000-screen,2000-screen,3000-screen,4000-screen,5000-tuned-screen,5500-tuned-screen,6000-tuned-screen,6000-prod-drain,6000-prod-drain-routing,6000-prod-drain-repeat,7000-screen,7000-ready2m,7000-pebble512,8000-ceiling-1,8000-ceiling-2,9000-ceiling10000-1,10000-ceiling-1,10000-ceiling-2,10000-ready5m-1,10000-ready5m-2,10000-diagnostic-1,10000-diagnostic-2,10000-snapshot-focused}/` |
| Bandwidth screens and longer transfers | `bench-results/capacity-profile-1cpu-2g-bandwidth-{1600-bidi,2000-bidi,2200-bidi-1,2200-bidi-2,2200-bidi-3,2200-bidi-long-1,2200-bidi-long-2,2400-bidi,2400-bidi-repeat-2,2400-bidi-long-1,2600-bidi}/`                                                                                                                                                                                                                                        |

### simultaneous local work

The combined workload holds routes and streams while offering fresh connections
and paced upstream/downstream bandwidth **at the same time**. The direct local
TLS path and tunneled path each had a two-minute fresh-request warmup and
five-minute combined measurement. All three trials passed exact-byte checks,
held-stream progress, offered fresh work, clean close, and final usage
reconciliation; the shared resource boundary appeared before correctness failed.

| Routes | Fresh/sec | Held streams | Mbit/sec per direction | Direct/tunneled fresh p95                                   | Active relay CPU and throttling      |
| -----: | --------: | -----------: | ---------------------: | ----------------------------------------------------------- | ------------------------------------ |
|    500 |       125 |          400 |                    140 | 2.440ms / 4.878ms; 37,500/37,500 successful on each path    | 0.811 mean cores, 0.09s throttling   |
|  1,000 |       250 |          800 |                    275 | 2.438ms / 5.597ms; 75,000/75,000 successful on each path    | 0.990 mean cores, 20.17s throttling  |
|  2,000 |       500 |        1,600 |                    550 | 2.436ms / 70.639ms; 150,000/150,000 successful on each path | 0.997 mean cores, 181.01s throttling |

All held streams survived and progressed. At the 2,000-route point, bandwidth
completed at 549.223 Mbit/sec per direction tunneled against 549.888 direct;
at 500 routes it completed at 139.940 against 139.979. The ingress used
0.652-0.846 mean cores across these tunneled measurements, with no OOM events.
The 1,000-route step showed relay CPU pressure and the 2,000-route step showed
a sustained latency knee, despite both passing correctness. The 500-route
point was measured only once, so it is a promising lower screen, not a
repeatable operating limit. Ignored local evidence is in
`bench-results/capacity-profile-1cpu-2g-combined-{25pct-1,12pct-1,6pct-1}/`.

### replicated-process local comparison

Two matched runs at the 500-route combined point used two control processes,
two ingress processes, and two relay services with one relay process each.
Control, ingress, and each relay still had 1 CPU / 2 GiB per process; separate
generator and database resources matched the single-control/ingress run.
Shared Docker DNS names distributed traffic; each process had its own resource
and metrics address. Over five minutes both ingresses served visitor traffic:
19,771/19,649 successful backend attempts in the first run and 19,636/19,784
in the second. Each run completed all 37,500 tunneled fresh requests, kept all
400 held streams progressing, transferred exact bytes at 140 Mbit/sec per
direction, reconciled final usage, and reached zero active state. Tunneled
fresh-request p95 was 4.881ms and 4.886ms (2.440ms direct in the first run),
versus 4.878ms tunneled in the matched single-ingress run. Ingresses averaged
0.446/0.437 and 0.451/0.470 CPU cores; the active relay averaged 0.823 and
0.856 cores, versus 0.811 in the single-ingress run. Evidence:
`bench-results/capacity-profile-1cpu-2g-combined-ha-6pct-{1,2}/`.

This verifies a replicated control/ingress process boundary with real
publisher and visitor traffic, not a highly available deployment: PostgreSQL
is one disposable process, Docker DNS is not a health-aware ingress address,
and the local processes share one Docker host. Both runs still concentrated
visitor traffic on the first relay. A third trial was interrupted during
activation, before it offered visitor traffic; its incomplete snapshot is not
a failed five-minute capacity measurement. These runs do not establish a
deployed combined capacity limit.

### balanced replicated-process combined profile

The next local combined profile spread visitor work across two ingress
processes and both relay services, with two control processes sharing one
disposable PostgreSQL instance. Each server-role process had a one-CPU quota
and 2 GiB memory limit. The separate database had 4 CPUs / 2 GiB;
publishers had 2 CPUs / 3 GiB; the local service had 4 CPUs / 1 GiB; each
visitor had 2 CPUs / 512 MiB; Pebble had 512 MiB; and the coordinator had
2 CPUs / 1 GiB. Activation used 1,000 concurrent starts, eight certificate
workers per control process, and a five-minute publisher readiness timeout.
The same four visitor sources used a 1,000/sec source rate and 4,000 burst.

The initial balanced combined runs offered 406 fresh requests/sec while keeping
1,300 held streams progressing and carrying 447 Mbit/sec **in each direction**
over 64 bandwidth streams per direction. Direct and tunneled paths each used
two-minute held-stream warmups and five-minute measurements. The 1,625-route
point had three complete clean trials (one before and two after the challenge
projection fix):

| 1,625-route trial    | Direct fresh p95 | Tunneled fresh p95 | Tunneled bandwidth per direction |
| -------------------- | ---------------: | -----------------: | -------------------------------: |
| Earlier complete run |          2.443ms |            9.327ms |                 446.542 Mbit/sec |
| Projection-fix run 1 |          2.467ms |           16.481ms |                 446.510 Mbit/sec |
| Projection-fix run 2 |          2.469ms |           12.342ms |                 446.438 Mbit/sec |

Each of these runs completed 121,800/121,800 successful direct and tunneled
steady fresh requests, with no failures, timeouts, missed offers, or queue
expiry. All 1,300 held streams survived and progressed. Each transfer delivered
exactly 16,762,500,000 bytes in each direction, and each run installed one
certificate per route without replacement orders. Post-fix activation verified
in 43.698s and 38.961s respectively. Usage reconciled and the final state
contained no active route sessions, publisher connections, or reservations.
In the two post-fix tunneled steady phases the relays averaged
0.778–0.794 CPU cores each, with under 0.4 seconds of quota throttling each;
the two ingresses averaged 0.619–0.645 cores. The generators and database
retained CPU and memory headroom in these measurements.

The initial variable-scaled 1,750- and 2,000-route trials reported histogram
p95 of 44.110ms and 104.919ms. The former trial's retained request samples
give exact p95 of 42.712ms, but a **route-count knee is not repeatable**:

| Routes | Fresh/sec |  Held | Mbit/sec per direction | Five-minute tunneled histogram p95 | Result |
| -----: | --------: | ----: | ---------------------: | ---------------------------------: | ------ |
|  1,625 |       438 | 1,400 |                    481 |                            9.949ms | Clean  |
|  1,750 |       406 | 1,300 |                    447 |                            9.701ms | Clean  |
|  1,750 |       438 | 1,400 |                    481 |                           16.837ms | Clean  |

All three matched trials completed every offered fresh request, exact
bandwidth bytes, held-stream progress, usage reconciliation, and clean
shutdown. At 2,000 routes, isolating fresh traffic, fresh plus held streams,
fresh plus bandwidth, or held streams plus bandwidth kept exact p95 below
5ms in separate two-minute measurements (the last offered only 4 fresh/sec).
With all three kinds of traffic at once, the shorter measurements showed:

| Mbit/sec per direction | Exact fresh p95 | Exact fresh p99 | Fresh successes | Result |
| ---------------------: | --------------: | --------------: | --------------: | ------ |
|                    300 |        16.523ms |       199.882ms |   52,560/52,560 | Clean  |
|                    400 |        13.317ms |       190.432ms |   52,560/52,560 | Clean  |
|                    481 |        42.020ms |       223.634ms |   52,560/52,560 | Clean  |

These points are not a monotonic bandwidth curve: 400 measured below 300 in
these single short runs. The two-minute 481 Mbit/sec run included relay CPU
profiling, so its latency is diagnostic evidence rather than a matched
unprofiled repeat. A five-minute 400 Mbit/sec run also passed: 131,400/131,400
fresh successes, 1,400 held streams progressing, 399.292 Mbit/sec in each
direction with exact bytes, reconciled usage, and clean shutdown. Its exact
fresh p95 was 33.515ms (p99 212.434ms), with per-minute p95 varying from
20.535ms to 61.637ms rather than steadily increasing.

An earlier five-minute 481 Mbit/sec run on the preceding source had exact p95
81.096ms, 126 failed fresh requests and 128 bandwidth failures; pooled
ingress-to-relay sessions closed together late in the measurement. Its first
two minutes had already reached exact p95 53.801ms, before the session
failures. Two subsequent matched five-minute runs on the source including
`554e8ea` completed all 131,400 fresh requests, kept all 1,400 held streams
progressing, delivered exact bandwidth bytes (480.308 and 479.854 Mbit/sec
per direction), reconciled usage, and shut down cleanly. Their exact fresh
p95 was 52.740ms and 34.813ms (p99 224.971ms and 211.988ms); neither lost
a pooled forwarding session during traffic. In both, per-minute p95 varied
sharply, and much of the slow period was TLS/first-byte time, while DNS and
TCP connect times stayed low. The previous session-closure trigger remains
unproven. Relays averaged roughly 0.8 CPU cores each with little quota
throttling; relay CPU quota alone does not explain the tail.

### publisher-generator headroom

Matched five-minute trials kept the 438 fresh/sec, 1,400 held-stream, and
481 Mbit/sec-per-direction workload fixed. The only change in each comparison
was the **separately constrained publisher generator's CPU quota**; server-role
quotas stayed at 1 CPU / 2 GiB per process and publisher memory stayed at
3 GiB. The two-CPU generator ran at 1.3–1.4 mean cores with little throttling,
but its mean did not capture the scheduler and burst headroom needed under
simultaneous traffic:

| Routes | Publisher CPUs | Exact tunneled fresh p95 |            Exact p99 | Result      |
| -----: | -------------: | -----------------------: | -------------------: | ----------- |
|  1,875 |              2 |                 46.726ms |            210.682ms | Clean       |
|  1,875 |              4 |                  5.326ms |             10.740ms | Clean       |
|  2,000 |              2 |       52.740ms, 34.813ms | 224.971ms, 211.988ms | Clean twice |
|  2,000 |              4 |                  5.198ms |             10.197ms | Clean       |

Each offered fresh request succeeded, all held streams progressed, transfer
bytes were exact, usage reconciled, and shutdown completed. One 1,750-route
two-CPU comparison passed at 12.015ms p95, but the apparent 1,750–2,000
latency knee vanishes at the higher generator quota. This is strong evidence
that **publisher-generator headroom**, not a measured tnl server-role limit,
caused most of the old local latency tail. The two later 2,000-route two-CPU
runs did not reproduce the earlier simultaneous pooled-session closures;
their original trigger remains unknown. The four-CPU profile is only one
complete run per route count, not a repeated production operating limit.

Two earlier attempts, one at 1,625 routes and one at 1,750, stopped during
activation after Pebble invalidated TLS-ALPN authorizations; replacement orders
later succeeded, but these are not clean capacity trials. A subsequent
reproduction showed an ingress applied revision 3635 when the missing
hostname's challenge upsert was revision 3637. The ACME work-claim check can
precede a publisher's challenge-ready transition, so control now rechecks the
latest live projection and every live ingress acknowledgment just before
asking the CA to validate. Three subsequent 1,625-route activation smokes
issued exactly one CA order per route; the read-and-accept sequence is not
atomic, and these trials do not rule out further activation races.

The runtime harness now defaults to the two-control/two-ingress process
topology, with consistently named `control-a`/`control-b` and
`ingress-a`/`ingress-b` processes; `control` and `ingress` remain shared Docker
DNS names. On this replicated process topology, a four-route abrupt relay-a
loss check completed 12,800/12,800 successful fresh requests at 160/sec during
an 80-second fault/recovery phase, including 31 seconds with relay-a stopped.
A forwarding blackhole on relay-a from **both** ingress processes completed
800/800 requests and kept all four healthy-path held streams progressing.
These small fault checks verify fallback correctness, **not** the combined
1,625-route workload under degradation: the current fault harness does not
combine the five-minute held/bandwidth workload with faults, and it does not
inject loss of one ingress process. Docker DNS is not a health-aware ingress
address, and PostgreSQL and the Docker host are single failure boundaries.

Ignored local evidence: `bench-results/capacity-profile-balanced-relays-1625-full-{1,2}/`,
`bench-results/capacity-profile-balanced-relays-1750-full-{1,2}/`,
`bench-results/capacity-profile-balanced-relays-1625-projection-fix-{1,2}/`,
`bench-results/capacity-profile-balanced-relays-{1625-scaled-traffic,1750-fixed-traffic,1750-scaled-traffic}-post-check-1/`,
`bench-results/capacity-profile-balanced-relays-2000-{fresh-only,held-fresh,bandwidth-fresh,held-bandwidth,bw300,bw400,bw400-long,cpu-diagnostic,fixed-traffic-post-check}-1/`,
`bench-results/capacity-profile-balanced-relays-2000-main-session-diagnostic-{1,2}/`,
`bench-results/capacity-profile-balanced-relays-{1750-main-matched,1875-main-matched,1875-publisher4,2000-publisher4}-1/`,
`bench-results/runtime-ha-names-{relay-kill,forwarding-blackhole}-20260925/`.
The `1625-full-2` and `1750-full-1` directories contain failed activation
attempts. Earlier evidence was copied out of its temporary benchmark worktree
into the main checkout's ignored `bench-results/` directory; the post-check
and 2,000-route evidence is in the isolated benchmark worktree's ignored
`bench-results/` directory. The two later 481 Mbit/sec runs are in the ignored
`bench-results/` directory of the separate current-main worktree; the matched
generator comparisons are there as well. One earlier diagnostic attempt in
the benchmark worktree ended during direct traffic because Docker Desktop
shifted every process's Prometheus start-time gauge by one second; the
test processes' own run IDs and cgroup counters stayed continuous. The
runtime harness now checks those run IDs for restart detection.

### remaining validation

| Dimension         | Next boundary or qualification                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Streams           | The 6,400-stream point passed three full runs with leveling memory. The higher 8,000-stream trial saturated ingress/relay CPU and failed cleanup; do not infer a safe operating limit.                                                                                                                                                                                                                                                                                                                                                             |
| Fresh connections | 2,000/sec passed two complete five-minute direct and tunneled runs with a near-saturated active relay. Find a genuine failure point and assess headroom before setting any operating limit.                                                                                                                                                                                                                                                                                                                                                        |
| Route sessions    | 10,000 completed five times but one identical 2m-readiness attempt failed during activation. Diagnose the straggler, test route endurance and mixed traffic, and reassess the 10,000-route harness/relay ceilings before setting any operating limit.                                                                                                                                                                                                                                                                                              |
| Bandwidth         | 2,200 Mbit/sec per direction passed three 30-second trials and two five-minute direct/tunneled runs. The single five-minute 2,400 Mbit/sec trial missed its tunneled deadline. Assess headroom before setting an operating point.                                                                                                                                                                                                                                                                                                                  |
| Combined/degraded | The apparent local route-count knee was primarily publisher-generator headroom: at the matched 1,875- and 2,000-route combined workload, raising only its CPU quota from two to four cut tunneled p95 to about 5ms. An earlier two-CPU 481 Mbit/sec run failed after pooled sessions closed, but later runs did not reproduce that loss. Repeat four-CPU candidate measurements and find a server-role boundary, then test under degradation with a health-aware ingress address and highly available PostgreSQL before setting production limits. |

The isolated local staircase is sufficient to identify relay CPU pressure in
the fresh-connection and bandwidth profiles and to choose the high-route
certificate-readiness straggler for investigation. It has not found a server
resource limit for active route sessions: the highest tested count reached
configured harness and relay limits. It does not establish safe production
limits or a highly available deployment's behavior. The combined local
screens exposed a generator headroom limit and a nonrepeatable session loss;
they have not established a server-role, degraded-state, or production
operating limit.
Further isolated short screens alone would not close those gaps.
