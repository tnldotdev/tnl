# Route-Path Benchmark

The Fly benchmark measures the complete TNL path rather than Tailcat in
isolation:

```text
tnlbench publisher/load
  -> public TLS ingress
  -> standalone worker or edge WSS/yamux worker pool
  -> Tailcat over forced DERP
  -> application TLS
  -> loopback HTTP origin
```

It compares two modes:

- `single-node`: one `tnld --mode=standalone` Machine.
- `ha`: one edge and a fixed pool of workers, two by default.

The `ha` name refers to worker redundancy. The SQLite edge remains a single
point of failure, so this is not an edge or state failover benchmark.

## Run

The benchmark requires `fly`, `jq`, `curl`, and `openssl`, plus access to the
configured Fly organization. It creates one temporary app and always destroys
the app and its Machines on exit.

```console
mise exec -- task go:bench-fly
```

Useful overrides:

```console
MODES=single-node SINGLE_ROUTES=1,100 mise exec -- task go:bench-fly
MODES=ha WORKERS=2 HA_ROUTES=1,500,1000 mise exec -- task go:bench-fly
MODES=ha DRIVERS=4 HA_ROUTES=2000,3000 mise exec -- task go:bench-fly
```

The main settings are `ORG`, `REGION`, `MODES`, `SINGLE_ROUTES`, `HA_ROUTES`,
`WORKERS`, `DRIVERS`, `PARALLEL`, `PAYLOAD_BYTES`, `WORKER_CAPACITY`, `SINGLE_SIZE`,
`EDGE_SIZE`, `WORKER_SIZE`, `DRIVER_SIZE`, `TIMEOUT`, `ATTEMPTS`, and
`DRIVER_WAIT_SECONDS`.

The default standalone and worker Machines use `performance-6x`; the edge uses
`performance-2x`, and the load driver uses `performance-8x`. The route path is
memory-bound at the larger tiers, so smaller Machines may restart before the
configured route capacity is reached. Setup, load, and cleanup concurrency
defaults to eight for both topologies.

Results are written as JSON Lines under `bench-results/`. Each tier reports:

- route activation p50, p95, and maximum
- first-byte and request latency p50, p95, and maximum
- route teardown p50, p95, and maximum
- aggregate payload throughput
- worker route count, capacity, RSS, goroutines, and open file descriptors
- post-cleanup worker state

Each route transfers one validated 64 KiB response by default. Every run uses a
fresh benchmark hostname suffix. Every tier starts fresh topology Machines,
explicitly deletes its routes, and waits for worker route counts to return to
zero. A failed tier is retried up to three times with fresh Machines and is only
recorded after full validation. The harness destroys all Machines between tiers
and finally destroys the temporary Fly app.

`DRIVERS` defaults to one. With multiple drivers, the harness divides a tier's
routes evenly across driver Machines. Each driver waits for the aggregate worker
route count before sending load, owns and cleans up only its shard, and waits for
the aggregate count to return to zero. A tier is recorded only if every driver
succeeds. Results remain per-driver rows and include `total_routes`,
`driver_index`, and `driver_count`; latency percentiles are not merged across
shards.
