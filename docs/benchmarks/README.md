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

## Development Baseline

Baseline date: 2026-08-28. The machine was an Apple M5 Pro with 15 logical
cores, 24 GiB memory, macOS 26.6.1, and Go 1.27.0. Each route transferred 64 KiB
through one active stream. Lifecycle concurrency was eight.

| Workload | Result | Notes |
| --- | --- | --- |
| Direct, 1 and 10 routes | Pass | Direct path observed; no residual descriptors or goroutines. |
| Direct, 100 routes | Unstable | One run passed; another stream open exceeded 30 seconds. |
| Direct, 500 routes | Fail | All routes started, but 7 did not establish a direct path within 10 seconds. |
| Direct, 1,000 routes | Incomplete | Multiple stream opens timed out before direct-path diagnostics were added. |
| Forced DERP, 1, 10, and 500 routes | Pass | No stream, transfer, or cleanup failures. |
| Forced DERP, 1,000 routes | Budget fail | All traffic passed; retained heap was 590.8 MB against a 557.8 MB budget. |
| 10,000 lifecycle cycles | Pass | Completed in 146.5 seconds with eight concurrent cycles. |

The 10,000-cycle run retained about 1.6 MiB of Go heap and no file descriptors
or goroutines. Startup p95 was 5.3 ms, with roughly one percent of starts taking
Tailcat's 10-second readiness retry. Shutdown p95 was 1.7 ms.

At 500 direct routes, DERP held all expected 1,000 connections without queue or
write-error drops. Direct-path preparation caused connection churn and transient
unknown-destination packets. The forced-DERP control then passed all 500 routes,
isolating the failure to direct-path discovery in the single-host topology.

The machine handled the 1,000-route forced-DERP workload without a functional
failure or descriptor/goroutine leak. A 100-route successful run used about 1.3
MiB idle Go heap per route and 2.3 MiB with one active stream per route.

## Budgets

- No startup, path, stream, transfer, drain, or close failures.
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

## Fly Runs

The same Task targets are suitable for a temporary Fly Machine. A small runner
can create a machine at a selected size, check out an exact commit, run one
benchmark command, save stdout with the machine metadata, and always destroy the
machine. Keep that orchestration separate from the benchmark so local and Fly
runs exercise identical code.
