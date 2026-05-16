# Tailcat Benchmarks

These opt-in benchmarks measure Tailcat route capacity and lifecycle behavior.

## Run

```console
# Local capacity: 1, 10, and 100 routes
mise exec -- task go:bench-tailcat-capacity

# Local lifecycle: 10,000 create/start/close cycles
mise exec -- task go:bench-tailcat-churn CYCLES=10000x

# Fly capacity and autoscaling: up to 5,000 routes
mise exec -- task go:bench-tailcat-fly-autoscale
```

The Fly run requires an authenticated `fly` CLI with access to the `tnl`
organization. It uses private Machines in `sjc`, public DERP region 302, and
forced DERP traffic.

## Results

Baseline: 2026-08-29. Each route transferred 64 KiB through one stream.

| Topology | Routes | Result |
| --- | ---: | --- |
| One `performance-8x`, 16 GiB worker | 1,500 | Pass; 1.98 MiB/s and zero forced closes. |
| One `performance-8x`, 16 GiB worker | 2,000 | Failed near 15.3 GiB RSS during creation. |
| Thirteen `performance-2x`, 4 GiB workers | 5,000 | Pass; 51.54 MiB/s and zero forced closes. |

The 5,000-route run transferred 312.5 MiB. Maximum worker-only RSS was
271.3 MiB. Startup, first-byte, and shutdown p95 were 269, 130, and 73 ms.

The 10,000-cycle local run completed in 146.5 seconds without descriptor or
goroutine leaks.

## Autoscaling

Workers have a 400-route target, 500-route limit, and `GOMEMLIMIT=3GiB`. The
benchmark scaled through `1,2,3,5,8,10,13` workers and returned to one.

It does not scale to zero. Both created and running worker counts have a minimum
of one. Zero running workers would require keeping one stopped seed Machine and
setting only the running-worker minimum to zero; that configuration is not
implemented or tested.

The benchmark colocates a client shard with each worker for the final load. It
does not test the planned production edge-to-worker routing protocol.

## Costs

Estimated monthly `sjc` costs before bandwidth:

| State | Cost |
| --- | ---: |
| Current one-worker floor | $82.20 |
| Thirteen running workers | $969.24 |
| Hypothetical zero-running floor | $8.43 |

The zero-running estimate includes one stopped seed Machine and is not the
current benchmark configuration. Recheck [Fly pricing](https://fly.io/docs/about/pricing/)
before budgeting.
