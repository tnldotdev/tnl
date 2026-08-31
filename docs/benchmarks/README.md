# Route-Path Benchmark

The Fly benchmark exercises the complete tnl route path, from publication and
public TLS ingress through Tailcat and the application origin. Tailcat is forced
through one DERP region so direct peer connectivity cannot affect the result.

It supports two topologies:

- `single-node`: one standalone `tnld` Machine.
- `ha`: one edge and a fixed worker pool.

`ha` provides worker redundancy only. The edge and its SQLite database remain a
single point of failure.

## Run

The benchmark requires `fly`, `jq`, `curl`, and `openssl`, plus access to the
configured Fly organization. Run the default matrix with:

```console
mise exec -- task go:bench-fly
```

The proven 10,000-route profile is:

```console
MODES=ha HA_ROUTES=10000 WORKERS=4 WORKER_CAPACITY=5000 \
  EDGE_SIZE=performance-2x WORKER_SIZE=performance-16x \
  DRIVERS=8 DRIVER_SIZE=performance-16x PARALLEL=4 \
  TIMEOUT=30m DRIVER_WAIT_SECONDS=2100 ATTEMPTS=1 \
  mise exec -- task go:bench-fly
```

## Capacity Results

Both forced-DERP runs transferred and validated a 64 KiB response through every
route, deleted every route, and returned all workers to zero:

| Metric | 5,125 routes | 10,000 routes |
| --- | --- | --- |
| Workers | 2 | 4 |
| Drivers | 4 | 8 |
| Routes per worker | 2,562 / 2,563 | 2,500 each |
| Activation p95 | 1.15-1.26 s | 0.89-10.08 s |
| Request p95 | 104-110 ms | 147-260 ms |
| Teardown p95 | 39.1-39.4 s | 104.8-108.2 s |
| Ready worker RSS | 2.37 / 2.41 GB | 2.09-2.10 GB |
| Worker goroutines | about 233,000 | about 227,500 |
| Open worker FDs | 10,261 / 10,265 | 10,011-10,021 |
| Routes after cleanup | 0 / 0 | 0 / 0 / 0 / 0 |

The 10,000-route run emitted all eight valid result rows. Its local failure
bundle came from the benchmark process losing stdout after writing the results,
not from a route, worker, or cleanup failure.

## Lessons

- The route path scales horizontally when route density stays near 2,500 per
  large worker.
- Worker resource use remained stable, but activation tails and teardown time
  increased. The serialized SQLite edge is now the main scaling constraint.
- Each active route uses about four file descriptors. The benchmark raises the
  limit to 65,536; the released image retains Fly's lower default limit.
- Limiting SQLite to one open connection prevents writer contention from
  amplifying retries and failures.
- The large benchmark Machines prove capacity but are not the recommended
  cost-efficient deployment shape.

## Fly Scaling

For a cost-first deployment, start with the historical forced-DERP small-worker
density:

| Setting | Value |
| --- | --- |
| Edge | 1 fixed `performance-2x` Machine |
| Worker size | `performance-2x` |
| Scheduling target | 400 routes per worker |
| `TNLD_WORKER_CAPACITY` | 500 routes |
| Minimum workers | 1 |
| Maximum workers | 10 |
| Scale-in cooldown | 15 minutes |

The complete route path has not yet been rerun with 10 small workers.

Calculate the desired pool from authoritative edge state:

```text
demand = active routes + provisioning routes
desired workers = clamp(ceil(demand / 400), 1, 10)
```

Scale out immediately. Scale in after demand remains below the next threshold
for 15 minutes, stopping at most one worker every 30 seconds. At full scale this
uses 20 performance CPUs and 40 GB of memory, compared with 64 CPUs and 128 GB
for the four large benchmark workers. At idle, only one 2-CPU, 4 GB worker runs.

Fly's request-based autoscaler cannot observe route demand because workers
connect outbound to the edge. Keep Fly request autoscaling and edge auto-stop
disabled, and use an external metrics scaler. Automatic scale-in remains
experimental until graceful worker drain and lease reacquisition are qualified
under continuous traffic.

## Results

Each run creates a temporary Fly app and destroys its Machines on exit. Results
are written as JSON Lines under `bench-results/`, with one row per driver shard
and ready and post-cleanup worker state.

The benchmark image raises its file-descriptor limit to 65,536 before dropping
to its non-root user. The released tnl image is unchanged.
