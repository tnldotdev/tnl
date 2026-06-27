# Fly Benchmark Progress

This is a temporary implementation handoff for the Fly benchmark effort. Delete
it after the current control/ingress/relay benchmark runner, approved runs, reports,
and resulting capacity decisions are complete.

## Objective

Answer three questions with repeatable evidence:

1. What publisher-connection density is safe for a `performance-1x` relay?
2. Do independently scaled ingress and relay services behave predictably behind
   a fixed `performance-2x` control?
3. Can relay drain and publisher-connection replenishment support conservative
   automatic scale-in without interrupting new visitor connections?

## Decisions

- Use one fixed `performance-2x` control with independently sized ingress and
  `performance-1x` relay processes.
- Keep at least two relay services because each route session maintains two
  publisher connections assigned to distinct services.
- Model route density as publisher-connection assignments per relay. A route
  consumes two assignments.
- Exercise `auto` transport selection. Do not label an `auto` run as QUIC-only
  without observed transport evidence.
- Existing streams may reset during relay loss. Recovery applies to new
  connections through the other ready publisher connection.
- Label workload inputs as assumed until privacy-preserving aggregate observed
  data replaces them.
- Do not select customer pricing from benchmark results.
- Do not create Fly, DNS, PostgreSQL, or certificate resources without explicit
  user approval.
- Do not run a Fly benchmark without both `BENCH_SUITE` and
  `BENCH_APPROVED=1`.

## Completed

- `tnlbench plan` strictly decodes profile files, validates cross-profile
  references, expands deterministic matrices, and estimates duration and spend
  without creating resources.
- Suite and workload profiles use schema version 3 with current control,
  ingress, relay, publisher connection, and transport terminology.
- The smoke plan uses one control, ingress, two relay services,
  25 routes, and one driver.
- The `scale` input converts aggregate relay publisher-connection
  capacity to route count using the two-connection invariant.
- The driver emits result schema version 4 with relay readiness and publisher
  connection resource fields.
- `tnlbench report` validates schema-v4 rows and shard identities, merges fixed
  histogram buckets, and writes `report.json` and `report.md`.
- The obsolete paid-resource launcher was removed because it could not launch
  the PostgreSQL control/ingress/relay architecture safely.
- Historical benchmark evidence predates the destructive architecture cutover
  and does not qualify current capacity.

## Current State

- Read-only planning and offline report generation are available.
- Fly execution is intentionally unavailable.
- The PostgreSQL-backed control API does not yet implement the route and
  route-session operations required by the benchmark driver.
- A persistent Fly benchmark app and dedicated IPv4 may still exist outside
  this repository. No command in this repository currently creates or modifies
  them.
- Static certificate files are not substitutes for service enrollment or
  control-managed relay transport identities.

## Next Steps

1. Complete and test control API route and route-session lifecycles.
2. Build a new approved-run launcher that provisions PostgreSQL, automatic
   public control TLS, scoped enrollment tokens, ingress, and two relay services.
3. Run one explicitly approved smoke cell and preserve failures without retrying
   to obtain a preferred result.
4. Qualify ingress and relay density, then run an explicitly selected replica
   matrix across at least two relay services.
5. Add drain coordination and sustained traffic before making scale-in claims.

## Safe Commands

```console
mise exec -- env GOFLAGS=-tags=ts_omit_ssh go test ./cmd/tnlbench
BENCH_SUITE=smoke mise exec -- task go:bench-fly:plan
BENCH_SUITE=smoke BENCH_PLAN_FORMAT=json mise exec -- task go:bench-fly:plan
BENCH_RUN=bench-results/<run-id> mise exec -- task go:bench-fly:report
```

## Key Files

- `cmd/tnlbench/main.go`: benchmark driver and cleanup lifecycle.
- `cmd/tnlbench/plan.go`: profile decoding, validation, expansion, and pricing.
- `cmd/tnlbench/barrier.go`: driver-shard coordination.
- `cmd/tnlbench/result.go`: result schema version 4.
- `cmd/tnlbench/report.go`: result validation and merged reports.
- `benchmarks/suites/p1-horizontal.json`: control, ingress, and relay-service
  capacity matrix.
- `benchmarks/workloads/agent-worktrees-assumed-v1.json`: assumed workload.
- `docs/benchmarks/README.md`: operator-facing benchmark contract and safety
  boundary.
