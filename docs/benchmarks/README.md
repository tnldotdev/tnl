# Tailcat Benchmarks

These opt-in benchmarks test one Tailcat server and one reusable client per
lease. They are separate from normal tests because larger route counts consume
substantial time and resources.

## Run Locally

The default capacity task runs the development-safe `1,10,100` route tiers:

```console
mise exec -- task go:bench-tailcat-capacity
```

Select tiers and require an observed path when needed:

```console
mise exec -- task go:bench-tailcat-capacity ROUTES=1,10 PATH_MODE=direct
TS_DEBUG_NEVER_DIRECT_UDP=1 mise exec -- task go:bench-tailcat-capacity ROUTES=1,10 PATH_MODE=derp
```

Lifecycle churn defaults to 100 cycles. The acceptance run uses 10,000:

```console
mise exec -- task go:bench-tailcat-churn
mise exec -- task go:bench-tailcat-churn CYCLES=10000x
```

## Results

Baseline date: 2026-08-29. Clients ran on an Apple M5 Pro Mac with 24 GiB memory;
the agent ran on a `performance-8x` Fly Machine in `sjc`. Both used public
DERP/STUN region 302. Each route transferred 64 KiB through one stream with eight
concurrent lifecycle operations.

| Forced-DERP routes | Result | Notes |
| --- | --- | --- |
| 250 | Pass, three runs | Zero forced closes; agent shutdown 221-226 ms. |
| 500 | Pass | Zero forced closes. |
| 1,000 | Pass | Zero forced closes; agent shutdown 796 ms. |
| 1,500 | Pass | Zero forced closes; agent shutdown 1.24 s and client shutdown p95 71 ms. |
| 2,000 | Fail | Agent was OOM-killed during route creation at about 15.3 GiB RSS. |

The observed capacity of this topology is 1,500 routes. The 2,000-route boundary
is agent memory, not DERP traffic or stream teardown: all 1,500 routes started,
transferred data at 1.98 MiB/s aggregate, and cleaned up within budget.

The local 10,000-cycle lifecycle run completed in 146.5 seconds, retained about
1.6 MiB of Go heap, and leaked no descriptors or goroutines. Direct-path
convergence is tracked separately because routes remain available over DERP.

## Budgets

- No startup, stream, transfer, or close failures.
- Startup p95 at most 15 seconds.
- First-byte p95 at most 2 seconds.
- Shutdown p95 at most 5 seconds.
- Idle Go heap at most 8 MiB per route for tiers of 10 or more.
- Churn residuals at most 32 MiB heap, 16 descriptors, and 16 goroutines.
- Capacity residual heap at most 32 MiB plus 512 KiB per created route.

The benchmark reports Go heap and runtime reservations, goroutines, file
descriptors, latency percentiles, throughput, path, and cleanup residuals. Linux
runs also report current RSS. Absolute production budgets remain provisional
until ingress, agents, and DERP run in separate processes or hosts.

DERP reachability is the availability baseline. Direct-path convergence is
reported separately and does not fail a Fly run. Agent drain timeouts fall back
to a bounded forced close and are reported as `agent_forced_closes`.

## Fly Runs

The Fly task runs Tailcat clients on the Mac against Tailcat servers on a
temporary private Fly Machine. Both sides use public DERP/STUN region 302; the
control API is reached through `fly proxy` and is not exposed publicly.

Prerequisites are an authenticated `fly` CLI with access to the `tnl`
organization, the repository Go toolchain, and outbound access to public
DERP/STUN:

```console
mise exec -- task go:bench-tailcat-fly
```

Defaults are organization `tnl`, region `sjc`, Machine size `performance-8x`,
eight concurrent operations, direct then forced-DERP modes, and route tiers
`1,10,100,250,500,1000,1500`. Override them through the task environment:

```console
ORG=tnl REGION=sjc AGENT_SIZE=performance-4x ROUTES=1,10 MODES=direct PARALLEL=4 LOCAL_PORT=18081 mise exec -- task go:bench-tailcat-fly
```

Each mode gets a fresh Machine. The benchmark stops at the first failed tier,
and the script's exit trap destroys the Machine and temporary Fly app on
success, failure, or interruption. Output separates client shutdown percentiles
from agent shutdown time and reports client and agent resource residuals
independently. Use `ROUTES=2000 MODES=derp` to reproduce the memory boundary.
